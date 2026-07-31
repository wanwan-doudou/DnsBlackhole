use std::{
    sync::{Arc, Mutex, OnceLock, mpsc},
    thread,
};

const TASK_POOL_MIN_THREADS: usize = 8;
const TASK_POOL_MAX_THREADS: usize = 32;
const TASK_POOL_QUEUE_CAPACITY: usize = 4096;
const COORDINATION_POOL_THREADS: usize = 4;
const COORDINATION_POOL_QUEUE_CAPACITY: usize = 256;

type Task = Box<dyn FnOnce() + Send + 'static>;

/// 常驻上游 I/O 任务线程池，替代并发转发和 IP 拨测时的临时 thread::spawn，
/// 避免高 QPS 下每次查询都创建/销毁 OS 线程。
struct TaskPool {
    sender: Mutex<mpsc::SyncSender<Task>>,
}

static TASK_POOL: OnceLock<TaskPool> = OnceLock::new();
static COORDINATION_POOL: OnceLock<TaskPool> = OnceLock::new();

fn task_pool() -> &'static TaskPool {
    TASK_POOL.get_or_init(|| {
        let thread_count = thread::available_parallelism()
            .map(|count| count.get().saturating_mul(4))
            .unwrap_or(TASK_POOL_MIN_THREADS)
            .clamp(TASK_POOL_MIN_THREADS, TASK_POOL_MAX_THREADS);
        TaskPool::new(thread_count, TASK_POOL_QUEUE_CAPACITY)
    })
}

/// 协调任务可能继续向上游 I/O 池提交子任务并等待结果，必须与 I/O 池隔离，
/// 否则协调任务占满全部线程后会形成线程池饥饿。
fn coordination_pool() -> &'static TaskPool {
    COORDINATION_POOL
        .get_or_init(|| TaskPool::new(COORDINATION_POOL_THREADS, COORDINATION_POOL_QUEUE_CAPACITY))
}

impl TaskPool {
    fn new(thread_count: usize, queue_capacity: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<Task>(queue_capacity.max(1));
        let receiver = Arc::new(Mutex::new(receiver));

        for _ in 0..thread_count.max(1) {
            let receiver = Arc::clone(&receiver);
            thread::spawn(move || {
                loop {
                    let task = {
                        let Ok(receiver) = receiver.lock() else {
                            return;
                        };
                        receiver.recv()
                    };
                    match task {
                        Ok(task) => task(),
                        Err(_) => return,
                    }
                }
            });
        }

        Self {
            sender: Mutex::new(sender),
        }
    }

    fn try_spawn(&self, task: Task) -> bool {
        let Ok(sender) = self.sender.lock() else {
            return false;
        };
        sender.try_send(task).is_ok()
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
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
        let pool = TaskPool::new(1, 1);
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
        let io_pool = Arc::new(TaskPool::new(1, 1));
        let coordination_pool = TaskPool::new(1, 1);
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
}
