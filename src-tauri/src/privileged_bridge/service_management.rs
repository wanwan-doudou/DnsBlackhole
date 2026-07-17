use std::{thread, time::Duration};

use objc2_foundation::{NSError, NSString};
use objc2_service_management::{SMAppService, SMAppServiceStatus};

use super::{HelloResult, MacosServiceState, MacosServiceStatus, ServiceClient};

const SERVICE_PLIST_NAME: &str = "com.dnsblackhole.app.service.plist";
const EXPECTED_SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROBE_INTERVAL: Duration = Duration::from_millis(250);
const INITIAL_PROBE_ATTEMPTS: usize = 4;
const RESTART_PROBE_ATTEMPTS: usize = 20;
const SERVICE_TRANSITION_ATTEMPTS: usize = 20;
const REGISTER_ATTEMPTS: usize = 6;
// 注销后系统的后台任务管理（BTM）传播新状态可能需要数秒，重试间隔要比探测间隔更宽。
const REGISTER_RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// 已获批启用的旧版服务在应用升级后被请求自行退出，由 KeepAlive 用当前 bundle 重新拉起。
/// SMAppService 的注册与批准是持久状态、跨应用更新有效，本函数只做只读探测与温和重启，
/// 绝不注销重装（注销会连同批准状态一起销毁，且重新注册可能被系统拒绝）；
/// 温和修复失败时通过 needs_repair 引导用户点击“安装或修复”执行重装。
pub fn ensure_macos_service_current() -> Result<MacosServiceStatus, String> {
    ensure_macos_service_with(INITIAL_PROBE_ATTEMPTS)
}

fn ensure_macos_service_with(probe_attempts: usize) -> Result<MacosServiceStatus, String> {
    let raw = current_raw_status();
    if raw != SMAppServiceStatus::Enabled {
        return Ok(status_from_raw(raw));
    }

    match probe_service(probe_attempts) {
        Ok(hello) if service_is_current(&hello) => Ok(status_with_runtime(raw, Some(hello))),
        Ok(stale) => {
            // 同协议的旧服务可自行退出，由 KeepAlive 使用更新后的 bundle 重新拉起。
            let _ = ServiceClient::request_restart();
            match wait_for_current_service(RESTART_PROBE_ATTEMPTS) {
                Ok(hello) => Ok(status_with_runtime(current_raw_status(), Some(hello))),
                Err(_) => Ok(status_with_runtime(current_raw_status(), Some(stale))),
            }
        }
        Err(_) => Ok(status_with_runtime(raw, None)),
    }
}

pub fn macos_service_install(force: bool) -> Result<MacosServiceStatus, String> {
    register_service(force)?;
    // 刚注册的服务由 launchd 首次拉起：AMFI 校验双架构二进制、初始化数据目录与
    // 数据库都需要时间，用重启级探测窗口等待就绪，避免把启动中的服务误判为异常、
    // 引导用户反复点击“安装或修复”。
    ensure_macos_service_with(RESTART_PROBE_ATTEMPTS)
}

pub fn macos_service_uninstall() -> Result<MacosServiceStatus, String> {
    let service = daemon_service();
    let current = unsafe { service.status() };
    if current != SMAppServiceStatus::NotRegistered && current != SMAppServiceStatus::NotFound {
        unsafe { service.unregisterAndReturnError() }
            .map_err(|error| service_error("卸载 macOS DNS 后台服务失败", &error))?;
    }
    let current = wait_for_service_stopped(&service);
    if current == SMAppServiceStatus::Enabled {
        return Err("卸载 macOS DNS 后台服务超时，服务仍处于启用状态".to_string());
    }
    Ok(status_from_raw(current))
}

pub fn macos_service_open_settings() {
    unsafe { SMAppService::openSystemSettingsLoginItems() };
}

fn register_service(force: bool) -> Result<(), String> {
    let service = daemon_service();
    let current = unsafe { service.status() };
    if current == SMAppServiceStatus::RequiresApproval {
        return Ok(());
    }
    if current == SMAppServiceStatus::Enabled && !force {
        return Ok(());
    }
    // 即便强制修复也绝不先注销：macOS 26 的 unregister 会连同用户在系统设置中的
    // 批准状态一起销毁，重新注册后服务回到待批准、daemon 被停掉（实机日志证实）。
    // 对已有注册直接 register 会原地刷新 BTM 记录并保留批准；
    // “已注册”类报错在下方按最终状态判定成功即可。

    let mut last_error = "注册 macOS DNS 后台服务失败".to_string();
    for attempt in 0..REGISTER_ATTEMPTS {
        match unsafe { service.registerAndReturnError() } {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = service_error("注册 macOS DNS 后台服务失败", &error);
                let current = unsafe { service.status() };
                if current == SMAppServiceStatus::Enabled
                    || current == SMAppServiceStatus::RequiresApproval
                {
                    return Ok(());
                }
            }
        }
        if attempt + 1 < REGISTER_ATTEMPTS {
            thread::sleep(REGISTER_RETRY_INTERVAL);
        }
    }
    // 走到这里说明注册既没成功也没进入待批准状态，即注册请求本身被系统拒绝，
    // 常见于后台任务管理数据库状态异常，重试无法自愈，只能引导用户手动恢复。
    Err(format!(
        "{last_error}。注册未进入待批准状态，系统可能拒绝了本应用的注册资格：\
        请重启 Mac 后再点击“安装或修复”；若仍失败，在终端执行 sudo sfltool resetbtm \
        并重启后重新安装（该命令会重置所有应用的后台项批准状态）"
    ))
}

fn wait_for_service_stopped(service: &SMAppService) -> SMAppServiceStatus {
    for attempt in 0..SERVICE_TRANSITION_ATTEMPTS {
        let current = unsafe { service.status() };
        if current != SMAppServiceStatus::Enabled {
            return current;
        }
        if attempt + 1 < SERVICE_TRANSITION_ATTEMPTS {
            thread::sleep(PROBE_INTERVAL);
        }
    }
    unsafe { service.status() }
}

fn probe_service(attempts: usize) -> Result<HelloResult, String> {
    let mut last_error = "后台服务尚未响应".to_string();
    for attempt in 0..attempts.max(1) {
        match ServiceClient::probe() {
            Ok(hello) => return Ok(hello),
            Err(error) => last_error = error,
        }
        if attempt + 1 < attempts {
            thread::sleep(PROBE_INTERVAL);
        }
    }
    Err(last_error)
}

fn wait_for_current_service(attempts: usize) -> Result<HelloResult, String> {
    let mut last_error = "后台服务尚未响应".to_string();
    for attempt in 0..attempts.max(1) {
        match ServiceClient::probe() {
            Ok(hello) if service_is_current(&hello) => return Ok(hello),
            Ok(hello) => {
                last_error = format!(
                    "后台服务仍为旧版本 {}，期望 {}",
                    hello.service_version, EXPECTED_SERVICE_VERSION
                );
            }
            Err(error) => last_error = error,
        }
        if attempt + 1 < attempts {
            thread::sleep(PROBE_INTERVAL);
        }
    }
    Err(last_error)
}

fn service_is_current(hello: &HelloResult) -> bool {
    hello.service_version == EXPECTED_SERVICE_VERSION
}

fn current_raw_status() -> SMAppServiceStatus {
    let service = daemon_service();
    unsafe { service.status() }
}

fn daemon_service() -> objc2::rc::Retained<SMAppService> {
    let plist_name = NSString::from_str(SERVICE_PLIST_NAME);
    unsafe { SMAppService::daemonServiceWithPlistName(&plist_name) }
}

fn status_with_runtime(
    status: SMAppServiceStatus,
    hello: Option<HelloResult>,
) -> MacosServiceStatus {
    let service_version = hello.as_ref().map(|hello| hello.service_version.clone());
    let needs_repair = status == SMAppServiceStatus::Enabled
        && hello
            .as_ref()
            .is_none_or(|hello| !service_is_current(hello));
    let mut result = status_from_raw(status);
    result.service_version = service_version;
    result.needs_repair = needs_repair;
    result
}

fn status_from_raw(status: SMAppServiceStatus) -> MacosServiceStatus {
    let state = if status == SMAppServiceStatus::NotRegistered {
        MacosServiceState::NotRegistered
    } else if status == SMAppServiceStatus::Enabled {
        MacosServiceState::Enabled
    } else if status == SMAppServiceStatus::RequiresApproval {
        MacosServiceState::RequiresApproval
    } else if status == SMAppServiceStatus::NotFound {
        MacosServiceState::NotFound
    } else {
        MacosServiceState::Unknown
    };
    MacosServiceStatus {
        state,
        enabled: status == SMAppServiceStatus::Enabled,
        requires_approval: status == SMAppServiceStatus::RequiresApproval,
        expected_version: EXPECTED_SERVICE_VERSION.to_string(),
        service_version: None,
        needs_repair: false,
    }
}

fn service_error(prefix: &str, error: &NSError) -> String {
    format!("{prefix}：{}", error.localizedDescription())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privileged_bridge::BRIDGE_PROTOCOL_VERSION;

    #[test]
    fn recognizes_current_service_version() {
        let hello = HelloResult {
            protocol_version: BRIDGE_PROTOCOL_VERSION,
            service_version: EXPECTED_SERVICE_VERSION.to_string(),
        };
        assert!(service_is_current(&hello));
    }

    #[test]
    fn rejects_old_service_version() {
        let hello = HelloResult {
            protocol_version: BRIDGE_PROTOCOL_VERSION,
            service_version: "0.0.0-old".to_string(),
        };
        assert!(!service_is_current(&hello));
    }
}
