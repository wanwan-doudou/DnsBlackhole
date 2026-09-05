use std::{
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::database::Database;

use super::stats::{DnsStats, SecurityEvent};

const QUEUE_CAPACITY: usize = 4096;
const BATCH_SIZE: usize = 256;
const BATCH_WAIT: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub(crate) enum SecurityEventMessage {
    Event(SecurityEvent),
    Flush(mpsc::Sender<Result<(), String>>),
    Stop,
}

pub(crate) struct SecurityEventWriter {
    stats: Arc<Mutex<DnsStats>>,
    thread: JoinHandle<()>,
}

impl SecurityEventWriter {
    pub(crate) fn start(stats: Arc<Mutex<DnsStats>>, database: Arc<Database>) -> Self {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        stats
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .security_event_sender = Some(sender);
        let thread = thread::spawn(move || {
            if let Err(error) = write_events(&database, receiver) {
                eprintln!("安全事件写入线程已停止：{error}");
            }
        });
        Self { stats, thread }
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.thread.is_finished()
    }

    pub(crate) fn stop(self) {
        if let Some(sender) = self
            .stats
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .security_event_sender
            .take()
        {
            let _ = sender.send(SecurityEventMessage::Stop);
        }
        let _ = self.thread.join();
    }
}

/// 调用方持有 stats 锁，等待此前事件全部提交后再清除/裁剪数据。
/// 写线程不访问 stats，因此队列满时背压和此屏障均不会形成锁循环。
pub(crate) fn flush_security_events(stats: &DnsStats) -> Result<(), String> {
    if let Some(sender) = &stats.security_event_sender {
        let (reply, result) = mpsc::channel();
        sender
            .send(SecurityEventMessage::Flush(reply))
            .map_err(|_| "安全事件写入队列已关闭".to_string())?;
        result
            .recv()
            .map_err(|_| "安全事件写入线程已退出".to_string())??;
    }
    Ok(())
}

fn write_events(
    database: &Database,
    receiver: mpsc::Receiver<SecurityEventMessage>,
) -> Result<(), String> {
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut deadline = Instant::now() + BATCH_WAIT;
    loop {
        let message = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        match message {
            Ok(SecurityEventMessage::Event(event)) => {
                batch.push(event);
                if batch.len() < BATCH_SIZE {
                    continue;
                }
            }
            Ok(SecurityEventMessage::Flush(reply)) => {
                let result = database.append_security_events(&batch);
                let _ = reply.send(result.clone());
                result?;
                batch.clear();
                deadline = Instant::now() + BATCH_WAIT;
                continue;
            }
            Ok(SecurityEventMessage::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                return database.append_security_events(&batch);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        database.append_security_events(&batch)?;
        batch.clear();
        deadline = Instant::now() + BATCH_WAIT;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{
        DnsTransport,
        stats::{SECURITY_EVENT_CAPACITY, record_access_denied},
    };

    #[test]
    fn all_events_persist_even_when_recent_view_is_full() {
        let database = Arc::new(Database::open_in_memory().unwrap());
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        let writer = SecurityEventWriter::start(Arc::clone(&stats), Arc::clone(&database));
        for index in 0..5_000 {
            record_access_denied(
                &stats,
                "192.0.2.1".parse().unwrap(),
                DnsTransport::Udp,
                format!("reason-{index}"),
            );
        }
        assert_eq!(
            stats.lock().unwrap().security_events.len(),
            SECURITY_EVENT_CAPACITY
        );
        writer.stop();
        assert_eq!(
            database.recent_security_events(10_000).unwrap().len(),
            5_000
        );
    }

    #[test]
    fn restored_aggregates_only_persist_new_increments() {
        let database = Arc::new(Database::open_in_memory().unwrap());
        let stats = Arc::new(Mutex::new(DnsStats::default()));
        let writer = SecurityEventWriter::start(Arc::clone(&stats), Arc::clone(&database));
        for _ in 0..3 {
            record_access_denied(
                &stats,
                "192.0.2.1".parse().unwrap(),
                DnsTransport::Udp,
                "denied".into(),
            );
        }
        writer.stop();
        super::super::stats::restore_security_events(
            &stats,
            database.recent_security_events(200).unwrap(),
        );
        let writer = SecurityEventWriter::start(Arc::clone(&stats), Arc::clone(&database));
        record_access_denied(
            &stats,
            "192.0.2.1".parse().unwrap(),
            DnsTransport::Udp,
            "denied".into(),
        );
        writer.stop();
        assert_eq!(
            database
                .recent_security_events(200)
                .unwrap()
                .iter()
                .map(|event| event.count)
                .sum::<u64>(),
            4
        );
    }
}
