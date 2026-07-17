use std::{os::unix::net::UnixStream, time::Duration};

use serde::{Serialize, de::DeserializeOwned};

use super::{
    BRIDGE_PROTOCOL_VERSION, BRIDGE_SOCKET_PATH, HelloParams, HelloResult, RpcRequest, RpcResponse,
    read_message, write_message,
};

const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const EXPECTED_SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) struct ServiceClient;

impl ServiceClient {
    pub(crate) fn probe() -> Result<HelloResult, String> {
        let (mut stream, hello) = connect_and_hello()?;
        let request = RpcRequest {
            id: 2,
            method: "ping".to_string(),
            params: serde_json::Value::Null,
        };
        write_message(&mut stream, &request)?;
        let _: serde_json::Value = read_result(&mut stream, 2)?;
        Ok(hello)
    }

    pub(crate) fn call<P, R>(method: &str, params: &P) -> Result<R, String>
    where
        P: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        Self::call_with_version_policy(method, params, true)
    }

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
        let (mut stream, hello) = connect_and_hello()?;
        if require_current_version && hello.service_version != EXPECTED_SERVICE_VERSION {
            return Err(format!(
                "macOS 后台服务版本不一致：应用 {}，服务 {}。应用将自动修复后台服务",
                EXPECTED_SERVICE_VERSION, hello.service_version
            ));
        }

        let request = RpcRequest {
            id: 2,
            method: method.to_string(),
            params: serde_json::to_value(params)
                .map_err(|error| format!("构造后台服务请求失败：{error}"))?,
        };
        write_message(&mut stream, &request)?;
        read_result(&mut stream, 2)
    }
}

fn connect_and_hello() -> Result<(UnixStream, HelloResult), String> {
    let mut stream = UnixStream::connect(BRIDGE_SOCKET_PATH).map_err(|error| {
        format!("无法连接 macOS DNS 后台服务，请先在设置中安装或修复后台服务：{error}")
    })?;
    stream
        .set_read_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("设置后台服务读取超时失败：{error}"))?;
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
            "macOS 后台服务协议版本不兼容：应用 {}，服务 {}。应用将自动修复后台服务",
            BRIDGE_PROTOCOL_VERSION, hello.protocol_version
        ));
    }
    Ok((stream, hello))
}

fn read_result<R: DeserializeOwned>(
    stream: &mut UnixStream,
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
