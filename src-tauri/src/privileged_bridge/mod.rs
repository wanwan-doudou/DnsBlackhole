use std::io::{Read, Write};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[cfg(any(target_os = "macos", windows))]
mod client;
#[cfg(target_os = "macos")]
mod daemon;
#[cfg(any(target_os = "macos", windows))]
mod rpc_server;
#[cfg(target_os = "macos")]
mod service_management;
#[cfg(windows)]
mod windows_pipe;
#[cfg(windows)]
mod windows_service;
#[cfg(windows)]
mod windows_service_management;
#[cfg(windows)]
mod windows_system_dns;

#[cfg(any(target_os = "macos", windows))]
pub(crate) use client::ServiceClient;
#[cfg(target_os = "macos")]
pub use daemon::run_daemon;
#[cfg(target_os = "macos")]
pub(crate) use service_management::{
    ensure_macos_service_current, macos_service_install, macos_service_open_settings,
    macos_service_uninstall,
};
#[cfg(windows)]
pub use windows_service::run_service_dispatcher as run_windows_service;

#[cfg(windows)]
pub(crate) fn write_windows_service_performance_log(message: &str) {
    if std::env::args_os().any(|argument| argument == "--windows-service") {
        windows_service::write_service_log(message);
    }
}
#[cfg(windows)]
pub(crate) use windows_service_management::{
    WindowsServiceStatus, ensure_windows_service_current, install_windows_service,
    uninstall_windows_service, windows_service_status,
};
#[cfg(windows)]
pub(crate) use windows_system_dns::WindowsSystemDnsStatus;
#[cfg(windows)]
pub fn handle_windows_service_command() -> Option<Result<(), String>> {
    use std::path::PathBuf;

    let mut arguments = std::env::args_os().skip(1);
    let command = arguments.next()?;
    if command == "--windows-service" {
        return Some(run_windows_service());
    }
    if command == "--windows-service-uninstall" {
        return Some(windows_service_management::uninstall_windows_service_elevated());
    }
    if command == "--windows-service-uninstall-request" {
        return Some(windows_service_management::uninstall_windows_service().map(|_| ()));
    }
    if command != "--windows-service-install" && command != "--windows-service-install-request" {
        return None;
    }

    let mut legacy_data_dir: Option<PathBuf> = None;
    while let Some(argument) = arguments.next() {
        if argument == "--legacy-data-dir" {
            let Some(path) = arguments.next() else {
                return Some(Err("--legacy-data-dir 缺少路径参数".to_string()));
            };
            legacy_data_dir = Some(PathBuf::from(path));
        }
    }
    let source_executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return Some(Err(format!("读取当前程序路径失败：{error}"))),
    };
    if command == "--windows-service-install-request" {
        return Some(
            windows_service_management::install_windows_service(legacy_data_dir.as_deref())
                .map(|_| ()),
        );
    }
    Some(
        windows_service_management::install_windows_service_elevated(
            &source_executable,
            legacy_data_dir.as_deref(),
        ),
    )
}

// 协议 5：控制面 RPC，并由 Windows 服务负责系统 DNS 的接管、恢复与外部 DNS 选择。
// GUI 只通过本协议做配置、状态查询和日志读取，不再转发 DNS 查询。
pub const BRIDGE_PROTOCOL_VERSION: u16 = 5;
pub const BRIDGE_SOCKET_PATH: &str = "/var/run/dnsblackhole/service.sock";
// 单帧上限：查询日志分页（最多 200 条记录）与统计快照都远小于该值
const MAX_FRAME_SIZE: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosServiceStatus {
    pub state: MacosServiceState,
    pub enabled: bool,
    pub requires_approval: bool,
    pub expected_version: String,
    pub service_version: Option<String>,
    pub needs_repair: bool,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse {
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HelloParams {
    pub protocol_version: u16,
    pub app_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloResult {
    pub protocol_version: u16,
    pub service_version: String,
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
    fn rpc_message_round_trip() {
        let request = RpcRequest {
            id: 7,
            method: "get_status".to_string(),
            params: serde_json::json!({ "force": true }),
        };
        let mut encoded = Vec::new();
        write_message(&mut encoded, &request).expect("请求应可编码");
        let decoded: RpcRequest = read_message(&mut encoded.as_slice()).expect("请求应可解码");
        assert_eq!(decoded.id, 7);
        assert_eq!(decoded.method, "get_status");
        assert_eq!(decoded.params["force"], true);

        let response = RpcResponse {
            id: 7,
            result: Some(serde_json::json!({ "running": true })),
            error: None,
        };
        let mut encoded = Vec::new();
        write_message(&mut encoded, &response).expect("响应应可编码");
        let decoded: RpcResponse = read_message(&mut encoded.as_slice()).expect("响应应可解码");
        assert_eq!(decoded.id, 7);
        assert!(decoded.error.is_none());
        assert_eq!(decoded.result.expect("应有结果")["running"], true);
    }
}
