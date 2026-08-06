use std::{
    collections::VecDeque,
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

const TASK_POOL_MIN_THREADS: usize = 8;
// 每个 DNS worker 在并发转发模式下会同时提交多个上游任务（最多
// MAX_PARALLEL_UPSTREAMS_PER_QUERY 个），突发时允许扩到 worker 数 × 单查询并行度；
// 空闲后收回额外线程，避免日常低负载也永久承担峰值线程数。
const TASK_POOL_MAX_THREADS: usize = 128;
const TASK_POOL_MAX_THREADS_PER_CORE: usize = 4;
const TASK_POOL_QUEUE_CAPACITY: usize = 4096;
const COORDINATION_POOL_THREADS: usize = 4;
const COORDINATION_POOL_QUEUE_CAPACITY: usize = 256;
const TASK_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const TASK_POOL_THREAD_STACK_SIZE: usize = 1024 * 1024;

type Task = Box<dyn FnOnce() + Send + 'static>;

/// 弹性上游 I/O 任务线程池，替代并发转发和 IP 拨测时的临时 thread::spawn。
struct TaskPool {
    shared: Arc<TaskPoolShared>,
}

struct TaskPoolShared {
    state: Mutex<TaskPoolState>,
    ready: Condvar,
    worker_count: AtomicUsize,
    idle_workers: AtomicUsize,
    min_threads: usize,
    max_threads: usize,
    queue_capacity: usize,
    idle_timeout: Duration,
}

#[derive(Default)]
struct TaskPoolState {
    queue: VecDeque<Task>,
}

static TASK_POOL: OnceLock<TaskPool> = OnceLock::new();
static COORDINATION_POOL: OnceLock<TaskPool> = OnceLock::new();

fn task_pool() -> &'static TaskPool {
    TASK_POOL.get_or_init(|| {
        let cores = thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(TASK_POOL_MIN_THREADS)
            .max(1);
        let min_threads = cores.clamp(TASK_POOL_MIN_THREADS, 32);
        let max_threads = cores
            .saturating_mul(TASK_POOL_MAX_THREADS_PER_CORE)
            .clamp(min_threads, TASK_POOL_MAX_THREADS);
        TaskPool::new(
            min_threads,
            max_threads,
            TASK_POOL_QUEUE_CAPACITY,
            TASK_POOL_IDLE_TIMEOUT,
        )
    })
}

/// 协调任务可能继续向上游 I/O 池提交子任务并等待结果，必须与 I/O 池隔离，
/// 否则协调任务占满全部线程后会形成线程池饥饿。
fn coordination_pool() -> &'static TaskPool {
    COORDINATION_POOL.get_or_init(|| {
        TaskPool::new(
            COORDINATION_POOL_THREADS,
            COORDINATION_POOL_THREADS,
            COORDINATION_POOL_QUEUE_CAPACITY,
            TASK_POOL_IDLE_TIMEOUT,
        )
    })
}

impl TaskPool {
    fn new(
        min_threads: usize,
        max_threads: usize,
        queue_capacity: usize,
        idle_timeout: Duration,
    ) -> Self {
        let min_threads = min_threads.max(1);
        let max_threads = max_threads.max(min_threads);
        let shared = Arc::new(TaskPoolShared {
            state: Mutex::new(TaskPoolState::default()),
            ready: Condvar::new(),
            worker_count: AtomicUsize::new(0),
            idle_workers: AtomicUsize::new(0),
            min_threads,
            max_threads,
            queue_capacity: queue_capacity.max(1),
            idle_timeout,
        });
        for _ in 0..min_threads {
            spawn_worker(&shared);
        }
        Self { shared }
    }

    fn try_spawn(&self, task: Task) -> bool {
        let queued = {
            let Ok(mut state) = self.shared.state.lock() else {
                return false;
            };
            if state.queue.len() >= self.shared.queue_capacity {
                return false;
            }
            state.queue.push_back(task);
            state.queue.len()
        };
        self.shared.ready.notify_one();

        // 基础线程足够日常负载；只有排队任务超过当前空闲 worker 时才按需扩容。
        // 每次提交最多补一个，连续突发会自然扩到上限而不会一次性创建 128 个线程。
        if queued > self.shared.idle_workers.load(Ordering::Acquire)
            && self.shared.worker_count.load(Ordering::Acquire) < self.shared.max_threads
        {
            spawn_worker(&self.shared);
        }
        true
    }

    #[cfg(test)]
    fn worker_count(&self) -> usize {
        self.shared.worker_count.load(Ordering::Acquire)
    }
}

fn spawn_worker(shared: &Arc<TaskPoolShared>) {
    let mut current = shared.worker_count.load(Ordering::Acquire);
    loop {
        if current >= shared.max_threads {
            return;
        }
        match shared.worker_count.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }

    let worker_shared = Arc::clone(shared);
    if thread::Builder::new()
        .name("dns-upstream-io".to_string())
        .stack_size(TASK_POOL_THREAD_STACK_SIZE)
        .spawn(move || worker_loop(worker_shared))
        .is_err()
    {
        shared.worker_count.fetch_sub(1, Ordering::AcqRel);
    }
}

fn worker_loop(shared: Arc<TaskPoolShared>) {
    loop {
        let task = {
            let Ok(mut state) = shared.state.lock() else {
                shared.worker_count.fetch_sub(1, Ordering::AcqRel);
                return;
            };
            loop {
                if let Some(task) = state.queue.pop_front() {
                    break task;
                }

                shared.idle_workers.fetch_add(1, Ordering::AcqRel);
                let waited = shared.ready.wait_timeout(state, shared.idle_timeout);
                shared.idle_workers.fetch_sub(1, Ordering::AcqRel);
                let Ok((next_state, timeout)) = waited else {
                    shared.worker_count.fetch_sub(1, Ordering::AcqRel);
                    return;
                };
                state = next_state;
                if timeout.timed_out() && state.queue.is_empty() && try_retire_worker(&shared) {
                    return;
                }
            }
        };
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)).is_err() {
            eprintln!("DNS 上游任务异常退出，线程池继续处理后续任务");
        }
    }
}

fn try_retire_worker(shared: &TaskPoolShared) -> bool {
    let mut current = shared.worker_count.load(Ordering::Acquire);
    loop {
        if current <= shared.min_threads {
            return false;
        }
        match shared.worker_count.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

pub(crate) fn spawn_task<F>(task: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    task_pool().try_spawn(Box::new(task))
}

pub(crate) fn spawn_coordination_task<F>(task: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    coordination_pool().try_spawn(Box::new(task))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use super::{TaskPool, spawn_task};

    #[test]
    fn runs_tasks_concurrently_and_completely() {
        let counter = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = mpsc::channel();

        for _ in 0..64 {
            let counter = Arc::clone(&counter);
            let sender = sender.clone();
            assert!(spawn_task(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = sender.send(());
            }));
        }
        drop(sender);

        for _ in 0..64 {
            receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("task should complete");
        }
        assert_eq!(counter.load(Ordering::SeqCst), 64);
    }

    #[test]
    fn rejects_tasks_when_queue_is_full() {
        let pool = TaskPool::new(1, 1, 1, Duration::from_secs(1));
        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();

        assert!(pool.try_spawn(Box::new(move || {
            let _ = started_sender.send(());
            let _ = release_receiver.recv();
        })));
        started_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("first task should start");

        assert!(pool.try_spawn(Box::new(|| {})));
        assert!(!pool.try_spawn(Box::new(|| {})));
        let _ = release_sender.send(());
    }

    #[test]
    fn separate_coordination_pool_can_wait_for_io_pool() {
        let io_pool = Arc::new(TaskPool::new(1, 1, 1, Duration::from_secs(1)));
        let coordination_pool = TaskPool::new(1, 1, 1, Duration::from_secs(1));
        let (completed_sender, completed_receiver) = mpsc::channel();
        let io_pool_for_task = Arc::clone(&io_pool);

        assert!(coordination_pool.try_spawn(Box::new(move || {
            let (io_sender, io_receiver) = mpsc::channel();
            assert!(io_pool_for_task.try_spawn(Box::new(move || {
                let _ = io_sender.send(());
            })));
            io_receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("io task should not be starved by its coordinator");
            let _ = completed_sender.send(());
        })));

        completed_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("coordination task should complete");
    }

    #[test]
    fn worker_survives_a_panicking_task() {
        let pool = TaskPool::new(1, 1, 4, Duration::from_secs(1));
        let (completed_tx, completed_rx) = mpsc::channel();
        assert!(pool.try_spawn(Box::new(|| panic!("expected test panic"))));
        assert!(pool.try_spawn(Box::new(move || {
            let _ = completed_tx.send(());
        })));
        completed_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("panic 后的任务仍应执行");
    }

    #[test]
    fn elastic_pool_grows_for_a_burst_and_retires_to_minimum() {
        let pool = TaskPool::new(1, 4, 16, Duration::from_millis(20));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));

        for _ in 0..4 {
            let started_tx = started_tx.clone();
            let release_rx = Arc::clone(&release_rx);
            assert!(pool.try_spawn(Box::new(move || {
                let _ = started_tx.send(());
                let _ = release_rx.lock().expect("release lock").recv();
            })));
        }
        for _ in 0..4 {
            started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("突发任务应并行启动");
        }
        assert_eq!(pool.worker_count(), 4);
        for _ in 0..4 {
            release_tx.send(()).expect("任务应可释放");
        }

        let deadline = Instant::now() + Duration::from_secs(1);
        while pool.worker_count() != 1 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(pool.worker_count(), 1, "空闲 worker 应回收到基础规模");
    }
}
