use std::{
    io::{Read, Write},
    net::SocketAddr,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[cfg(target_os = "macos")]
mod client;
#[cfg(target_os = "macos")]
mod daemon;
#[cfg(target_os = "macos")]
mod service_management;

#[cfg(target_os = "macos")]
pub(crate) use client::{BridgeResponder, PrivilegedBridge};
#[cfg(target_os = "macos")]
pub use daemon::run_daemon;
#[cfg(target_os = "macos")]
pub(crate) use service_management::{
    macos_service_install, macos_service_open_settings, macos_service_status,
    macos_service_uninstall,
};

pub const BRIDGE_PROTOCOL_VERSION: u16 = 1;
pub const BRIDGE_SOCKET_PATH: &str = "/var/run/dnsblackhole/service.sock";
// DNS 报文最大 64KB，serde_json 将字节编码为数字数组最坏膨胀约 4 倍，再留出消息结构开销
const MAX_FRAME_SIZE: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosServiceStatus {
    pub state: MacosServiceState,
    pub enabled: bool,
    pub requires_approval: bool,
    pub expected_version: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosServiceState {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Hello {
        protocol_version: u16,
        app_version: String,
    },
    Configure {
        request_id: u64,
        listen_addrs: Vec<SocketAddr>,
    },
    Stop {
        request_id: u64,
    },
    Response {
        request_id: u64,
        response: Option<Vec<u8>>,
    },
    Ping {
        request_id: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServiceMessage {
    Hello {
        protocol_version: u16,
        service_version: String,
    },
    Result {
        request_id: u64,
        error: Option<String>,
    },
    Query {
        request_id: u64,
        transport: BridgeTransport,
        client_addr: SocketAddr,
        query: Vec<u8>,
    },
}

pub fn write_message<W: Write, T: Serialize>(writer: &mut W, message: &T) -> Result<(), String> {
    let payload =
        serde_json::to_vec(message).map_err(|error| format!("序列化后台服务消息失败：{error}"))?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(format!("后台服务消息超过大小限制：{} 字节", payload.len()));
    }
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| "后台服务消息长度超出范围".to_string())?;
    writer
        .write_all(&payload_len.to_be_bytes())
        .and_then(|_| writer.write_all(&payload))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("写入后台服务消息失败：{error}"))
}

pub fn read_message<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, String> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|error| format!("读取后台服务消息长度失败：{error}"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_SIZE {
        return Err(format!("后台服务消息长度无效：{length}"));
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| format!("读取后台服务消息失败：{error}"))?;
    serde_json::from_slice(&payload).map_err(|error| format!("解析后台服务消息失败：{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_message_round_trip() {
        let message = ClientMessage::Configure {
            request_id: 7,
            listen_addrs: vec!["127.0.0.1:53".parse().unwrap()],
        };
        let mut encoded = Vec::new();
        write_message(&mut encoded, &message).expect("消息应可编码");
        let decoded: ClientMessage = read_message(&mut encoded.as_slice()).expect("消息应可解码");
        match decoded {
            ClientMessage::Configure {
                request_id,
                listen_addrs,
            } => {
                assert_eq!(request_id, 7);
                assert_eq!(listen_addrs, vec!["127.0.0.1:53".parse().unwrap()]);
            }
            _ => panic!("消息类型错误"),
        }
    }
}
