use std::{
    net::{Shutdown, SocketAddr},
    os::unix::net::UnixStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::dns::{
    server::{DispatchDnsWorkError, dispatch_dns_work},
    stats::{DnsStats, record_error},
    worker::{DnsResponseTarget, DnsWorkItem},
};

use super::{
    BRIDGE_PROTOCOL_VERSION, BRIDGE_SOCKET_PATH, BridgeTransport, ClientMessage, ServiceMessage,
    read_message, write_message,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct PrivilegedBridge {
    writer: Arc<Mutex<UnixStream>>,
    reader_thread: Option<JoinHandle<()>>,
}

impl PrivilegedBridge {
    pub(crate) fn start(
        listen_addrs: Vec<SocketAddr>,
        work_senders: Vec<mpsc::SyncSender<DnsWorkItem>>,
        stats: Arc<Mutex<DnsStats>>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        let stream = UnixStream::connect(BRIDGE_SOCKET_PATH).map_err(|error| {
            format!("连接 macOS DNS 后台服务失败：{error}。请先在设置中安装并授权后台服务")
        })?;
        stream
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| format!("设置后台服务读取超时失败：{error}"))?;
        stream
            .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| format!("设置后台服务写入超时失败：{error}"))?;

        let mut reader = stream
            .try_clone()
            .map_err(|error| format!("复制后台服务连接失败：{error}"))?;
        let mut writer = stream;

        write_message(
            &mut writer,
            &ClientMessage::Hello {
                protocol_version: BRIDGE_PROTOCOL_VERSION,
                app_version: env!("CARGO_PKG_VERSION").to_string(),
            },
        )?;
        match read_message::<_, ServiceMessage>(&mut reader)? {
            ServiceMessage::Hello {
                protocol_version,
                service_version,
            } if protocol_version == BRIDGE_PROTOCOL_VERSION => {
                if service_version != env!("CARGO_PKG_VERSION") {
                    return Err(format!(
                        "macOS DNS 后台服务版本不一致：应用 {}，服务 {service_version}。请修复或重新安装后台服务",
                        env!("CARGO_PKG_VERSION")
                    ));
                }
            }
            ServiceMessage::Hello {
                protocol_version, ..
            } => {
                return Err(format!(
                    "macOS DNS 后台服务协议版本不兼容：应用 {}，服务 {protocol_version}",
                    BRIDGE_PROTOCOL_VERSION
                ));
            }
            message => return Err(format!("macOS DNS 后台服务握手响应无效：{message:?}")),
        }

        const CONFIGURE_REQUEST_ID: u64 = 1;
        write_message(
            &mut writer,
            &ClientMessage::Configure {
                request_id: CONFIGURE_REQUEST_ID,
                listen_addrs,
            },
        )?;
        match read_message::<_, ServiceMessage>(&mut reader)? {
            ServiceMessage::Result {
                request_id: CONFIGURE_REQUEST_ID,
                error: None,
            } => {}
            ServiceMessage::Result {
                request_id: CONFIGURE_REQUEST_ID,
                error: Some(error),
            } => return Err(error),
            message => return Err(format!("macOS DNS 后台服务配置响应无效：{message:?}")),
        }

        // 握手完成后改为阻塞读，stop() 通过 shutdown 唤醒；
        // 带超时的 read_exact 部分读取会破坏帧边界，不能用超时轮询
        reader
            .set_read_timeout(None)
            .map_err(|error| format!("设置后台服务阻塞读取失败：{error}"))?;

        let writer = Arc::new(Mutex::new(writer));
        let reader_writer = Arc::clone(&writer);
        let reader_thread = thread::spawn(move || {
            bridge_reader_loop(&mut reader, reader_writer, work_senders, stats, stop);
        });

        Ok(Self {
            writer,
            reader_thread: Some(reader_thread),
        })
    }

    // 桥接读线程退出即代表 IPC 已断开，交由运行时看门狗按线程异常处理并重启恢复
    pub(crate) fn is_finished(&self) -> bool {
        self.reader_thread
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
    }

    pub(crate) fn stop(mut self) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = write_message(&mut *writer, &ClientMessage::Stop { request_id: 2 });
            let _ = writer.shutdown(Shutdown::Both);
        }
        if let Some(thread) = self.reader_thread.take() {
            let _ = thread.join();
        }
    }
}

// 由 DNS worker 直接把响应写回后台服务，避免每个查询占用一个等待线程
pub(crate) struct BridgeResponder {
    writer: Arc<Mutex<UnixStream>>,
    request_id: u64,
    responded: std::cell::Cell<bool>,
}

impl BridgeResponder {
    fn new(writer: Arc<Mutex<UnixStream>>, request_id: u64) -> Self {
        Self {
            writer,
            request_id,
            responded: std::cell::Cell::new(false),
        }
    }

    pub(crate) fn respond(&self, response: Option<Vec<u8>>) -> Result<(), String> {
        self.responded.set(true);
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| "后台服务 IPC 写入锁已损坏".to_string())?;
        let message = ClientMessage::Response {
            request_id: self.request_id,
            response,
        };
        if let Err(error) = write_message(&mut *writer, &message) {
            // 写失败后帧边界已不可信，关闭连接让读线程退出并触发自恢复
            let _ = writer.shutdown(Shutdown::Both);
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for BridgeResponder {
    // 任何处理路径遗漏回复时兜底发送空响应，让后台服务及时清理等待记录
    fn drop(&mut self) {
        if !self.responded.get() {
            let _ = self.respond(None);
        }
    }
}

fn bridge_reader_loop(
    reader: &mut UnixStream,
    writer: Arc<Mutex<UnixStream>>,
    work_senders: Vec<mpsc::SyncSender<DnsWorkItem>>,
    stats: Arc<Mutex<DnsStats>>,
    stop: Arc<AtomicBool>,
) {
    let mut next_worker = 0_usize;
    while !stop.load(Ordering::Relaxed) {
        let message = match read_message::<_, ServiceMessage>(reader) {
            Ok(message) => message,
            Err(error) => {
                if !stop.load(Ordering::Relaxed) {
                    record_error(&stats, format!("macOS DNS 后台服务连接中断：{error}"));
                }
                break;
            }
        };

        let ServiceMessage::Query {
            request_id,
            transport,
            client_addr,
            query,
        } = message
        else {
            continue;
        };

        let responder = BridgeResponder::new(Arc::clone(&writer), request_id);
        let response_target = match transport {
            BridgeTransport::Udp => DnsResponseTarget::BridgeUdp(responder),
            BridgeTransport::Tcp => DnsResponseTarget::BridgeTcp(responder),
        };
        let work_item = DnsWorkItem {
            query,
            client_addr,
            response_target,
        };

        // 分发失败时 work_item 被丢弃，BridgeResponder 的 Drop 兜底会回复空响应
        match dispatch_dns_work(&work_senders, work_item, &mut next_worker) {
            Ok(()) => {}
            Err(DispatchDnsWorkError::Full) => {
                record_error(
                    &stats,
                    "DNS 请求队列已满，已丢弃 macOS 后台请求".to_string(),
                );
            }
            Err(DispatchDnsWorkError::Disconnected) => break,
        }
    }
}
