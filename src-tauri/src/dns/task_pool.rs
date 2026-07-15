use std::{
    sync::{Arc, Mutex, OnceLock, mpsc},
    thread,
};

const TASK_POOL_MIN_THREADS: usize = 8;
const TASK_POOL_MAX_THREADS: usize = 32;

type Task = Box<dyn FnOnce() + Send + 'static>;

/// 常驻任务线程池，替代上游并发转发、IP 拨测和乐观缓存刷新时的临时 thread::spawn，
/// 避免高 QPS 下每次查询都创建/销毁 OS 线程。
struct TaskPool {
    sender: Mutex<mpsc::Sender<Task>>,
}

static TASK_POOL: OnceLock<TaskPool> = OnceLock::new();

fn task_pool() -> &'static TaskPool {
    TASK_POOL.get_or_init(|| {
        let thread_count = thread::available_parallelism()
            .map(|count| count.get().saturating_mul(4))
            .unwrap_or(TASK_POOL_MIN_THREADS)
            .clamp(TASK_POOL_MIN_THREADS, TASK_POOL_MAX_THREADS);
        let (sender, receiver) = mpsc::channel::<Task>();
        let receiver = Arc::new(Mutex::new(receiver));

        for _ in 0..thread_count {
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

        TaskPool {
            sender: Mutex::new(sender),
        }
    })
}

pub(crate) fn spawn_task<F>(task: F)
where
    F: FnOnce() + Send + 'static,
{
    let task: Task = Box::new(task);
    let task = match task_pool().sender.lock() {
        Ok(sender) => match sender.send(task) {
            Ok(()) => return,
            Err(mpsc::SendError(task)) => task,
        },
        Err(_) => return,
    };

    // 池不可用属于异常情况，退回临时线程保证任务不丢
    thread::spawn(task);
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    use super::spawn_task;

    #[test]
    fn runs_tasks_concurrently_and_completely() {
        let counter = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = mpsc::channel();

        for _ in 0..64 {
            let counter = Arc::clone(&counter);
            let sender = sender.clone();
            spawn_task(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = sender.send(());
            });
        }
        drop(sender);

        for _ in 0..64 {
            receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("task should complete");
        }
        assert_eq!(counter.load(Ordering::SeqCst), 64);
    }
}
