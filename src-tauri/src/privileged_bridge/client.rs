#[cfg(target_os = "macos")]
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use serde::{Serialize, de::DeserializeOwned};

#[cfg(target_os = "macos")]
use super::BRIDGE_SOCKET_PATH;
#[cfg(windows)]
use super::windows_pipe::WindowsPipeStream;
use super::{
    BRIDGE_PROTOCOL_VERSION, HelloParams, HelloResult, RpcRequest, RpcResponse, read_message,
    write_message,
};

#[cfg(target_os = "macos")]
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const EXPECTED_SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(target_os = "macos")]
type ServiceStream = UnixStream;
#[cfg(windows)]
type ServiceStream = WindowsPipeStream;

pub(crate) struct ServiceClient;

impl ServiceClient {
    #[cfg(target_os = "macos")]
    pub(crate) fn probe() -> Result<HelloResult, String> {
        let (mut stream, hello) = connect_and_hello()?;
        verify_connection_alive(&mut stream)?;
        Ok(hello)
    }

    #[cfg(windows)]
    pub(crate) fn probe_with_timeout(timeout: Duration) -> Result<HelloResult, String> {
        let started = Instant::now();
        let timeout_ms = timeout.as_millis().min(u128::from(u32::MAX)) as u32;
        let result = (|| {
            let (mut stream, hello) = connect_and_hello_with_timeout(timeout_ms)?;
            verify_connection_alive(&mut stream)?;
            Ok(hello)
        })();
        crate::performance::log("IPC 客户端", "服务就绪探测", started);
        result
    }

    pub(crate) fn call<P, R>(method: &str, params: &P) -> Result<R, String>
    where
        P: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        Self::call_with_version_policy(method, params, true)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn request_restart() -> Result<(), String> {
        Self::call_with_version_policy("restart_service", &serde_json::json!({}), false)
    }

    fn call_with_version_policy<P, R>(
        method: &str,
        params: &P,
        require_current_version: bool,
    ) -> Result<R, String>
    where
        P: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let total_started = Instant::now();
        let connect_started = Instant::now();
        let connection = connect_and_hello();
        crate::performance::log(
            "IPC 客户端",
            &format!("{method} 连接与握手"),
            connect_started,
        );
        let (mut stream, hello) = connection?;
        if require_current_version && hello.service_version != EXPECTED_SERVICE_VERSION {
            crate::performance::log("IPC 客户端", &format!("{method} 总计"), total_started);
            return Err(format!(
                "DNS 后台服务版本不一致：应用 {}，服务 {}。请安装或修复后台服务",
                EXPECTED_SERVICE_VERSION, hello.service_version
            ));
        }

        let request = RpcRequest {
            id: 2,
            method: method.to_string(),
            params: serde_json::to_value(params)
                .map_err(|error| format!("构造后台服务请求失败：{error}"))?,
        };
        let request_started = Instant::now();
        let result = write_message(&mut stream, &request).and_then(|_| read_result(&mut stream, 2));
        crate::performance::log(
            "IPC 客户端",
            &format!("{method} 请求与响应"),
            request_started,
        );
        crate::performance::log("IPC 客户端", &format!("{method} 总计"), total_started);
        result
    }
}

/// 握手后的连接存活性检查：旧版服务不认识 ping 会返回错误响应，
/// 但能收到完整响应就说明连接在握手后仍可用、服务只是版本旧；
/// 只有写入失败、连接被关闭或超时等传输层错误才判定为断管。
fn verify_connection_alive(stream: &mut ServiceStream) -> Result<(), String> {
    let request = RpcRequest {
        id: 2,
        method: "ping".to_string(),
        params: serde_json::Value::Null,
    };
    write_message(stream, &request)?;
    let response: RpcResponse = read_message(stream)?;
    if response.id != request.id {
        return Err(format!(
            "后台服务响应编号不匹配：期望 {}，收到 {}",
            request.id, response.id
        ));
    }
    Ok(())
}

fn connect_and_hello() -> Result<(ServiceStream, HelloResult), String> {
    #[cfg(target_os = "macos")]
    let stream = UnixStream::connect(BRIDGE_SOCKET_PATH).map_err(|error| {
        // 区分“服务根本没在运行”（socket 不存在或无人监听）与其他连接故障，
        // 前者最常见的原因是服务尚未安装、等待系统设置批准或正在启动。
        let hint = match error.kind() {
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound => {
                "后台服务未在运行。若已安装，请在“系统设置 → 通用 → 登录项与扩展”中\
                批准 DnsBlackhole 后稍候重试；若未安装，请在设置中点击“安装或修复”"
            }
            _ => "请先在设置中安装或修复后台服务",
        };
        format!("无法连接 macOS DNS 后台服务，{hint}：{error}")
    })?;
    #[cfg(windows)]
    let stream = WindowsPipeStream::connect()?;
    finish_hello(stream)
}

#[cfg(windows)]
fn connect_and_hello_with_timeout(timeout_ms: u32) -> Result<(ServiceStream, HelloResult), String> {
    let stream = WindowsPipeStream::connect_with_timeout(timeout_ms)?;
    finish_hello(stream)
}

fn finish_hello(mut stream: ServiceStream) -> Result<(ServiceStream, HelloResult), String> {
    #[cfg(target_os = "macos")]
    stream
        .set_read_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("设置后台服务读取超时失败：{error}"))?;
    #[cfg(target_os = "macos")]
    stream
        .set_write_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("设置后台服务写入超时失败：{error}"))?;

    let request = RpcRequest {
        id: 1,
        method: "hello".to_string(),
        params: serde_json::to_value(HelloParams {
            protocol_version: BRIDGE_PROTOCOL_VERSION,
            app_version: EXPECTED_SERVICE_VERSION.to_string(),
        })
        .map_err(|error| format!("构造后台服务握手失败：{error}"))?,
    };
    write_message(&mut stream, &request)?;
    let hello: HelloResult = read_result(&mut stream, 1)?;
    if hello.protocol_version != BRIDGE_PROTOCOL_VERSION {
        return Err(format!(
            "DNS 后台服务协议版本不兼容：应用 {}，服务 {}。请安装或修复后台服务",
            BRIDGE_PROTOCOL_VERSION, hello.protocol_version
        ));
    }
    Ok((stream, hello))
}

fn read_result<R: DeserializeOwned>(
    stream: &mut ServiceStream,
    expected_id: u64,
) -> Result<R, String> {
    let response: RpcResponse = read_message(stream)?;
    if response.id != expected_id {
        return Err(format!(
            "后台服务响应编号不匹配：期望 {expected_id}，收到 {}",
            response.id
        ));
    }
    if let Some(error) = response.error {
        return Err(error);
    }
    let result = response
        .result
        .ok_or_else(|| "后台服务响应缺少结果".to_string())?;
    serde_json::from_value(result).map_err(|error| format!("解析后台服务响应失败：{error}"))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::thread;

    use super::*;

    fn stream_pair() -> (UnixStream, UnixStream) {
        let (client, server) = UnixStream::pair().expect("应能创建 Unix socket 对");
        client
            .set_read_timeout(Some(RPC_TIMEOUT))
            .expect("应能设置客户端读取超时");
        client
            .set_write_timeout(Some(RPC_TIMEOUT))
            .expect("应能设置客户端写入超时");
        (client, server)
    }

    #[test]
    fn connection_check_tolerates_error_response_from_old_service() {
        let (mut client, mut server) = stream_pair();

        let server_thread = thread::spawn(move || -> Result<(), String> {
            let request: RpcRequest = read_message(&mut server)?;
            write_message(
                &mut server,
                &RpcResponse {
                    id: request.id,
                    result: None,
                    error: Some(format!("未知的后台服务方法：{}", request.method)),
                },
            )
        });

        verify_connection_alive(&mut client).expect("旧服务的错误响应应视为连接存活");
        server_thread
            .join()
            .expect("服务端测试线程不应 panic")
            .expect("服务端应能读取请求并应答");
    }

    #[test]
    fn connection_check_fails_when_peer_closed_after_handshake() {
        let (mut client, server) = stream_pair();
        drop(server);

        assert!(verify_connection_alive(&mut client).is_err());
    }
}
