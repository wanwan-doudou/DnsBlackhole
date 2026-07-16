use std::{thread, time::Duration};

use objc2_foundation::{NSError, NSString};
use objc2_service_management::{SMAppService, SMAppServiceStatus};

use super::{HelloResult, MacosServiceState, MacosServiceStatus, ServiceClient};

const SERVICE_PLIST_NAME: &str = "com.dnsblackhole.app.service.plist";
const EXPECTED_SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROBE_INTERVAL: Duration = Duration::from_millis(250);
const INITIAL_PROBE_ATTEMPTS: usize = 4;
const RESTART_PROBE_ATTEMPTS: usize = 20;

/// 已获批启用的服务在应用升级后自动切换到当前 bundle 内的 helper。
/// 尚未安装或等待系统批准时不主动注册，避免应用启动时擅自触发授权流程。
pub fn ensure_macos_service_current() -> Result<MacosServiceStatus, String> {
    let raw = current_raw_status();
    if raw != SMAppServiceStatus::Enabled {
        return Ok(status_from_raw(raw));
    }

    match probe_hello(INITIAL_PROBE_ATTEMPTS) {
        Ok(hello) if service_is_current(&hello) => {
            return Ok(status_with_runtime(raw, Some(hello)));
        }
        Ok(_) => {
            // 同协议的旧服务可自行退出，由 KeepAlive 使用更新后的 bundle 重新拉起。
            let _ = ServiceClient::request_restart();
            if let Ok(hello) = wait_for_current_service(RESTART_PROBE_ATTEMPTS) {
                return Ok(status_with_runtime(current_raw_status(), Some(hello)));
            }
        }
        Err(_) => {}
    }

    // 协议不兼容、旧服务不支持自重启或 socket 损坏时，重新注册 LaunchDaemon。
    register_service(true)?;
    let raw = current_raw_status();
    if raw != SMAppServiceStatus::Enabled {
        return Ok(status_from_raw(raw));
    }
    let hello = wait_for_current_service(RESTART_PROBE_ATTEMPTS)
        .map_err(|error| format!("自动修复 macOS DNS 后台服务后仍无法连接：{error}"))?;
    Ok(status_with_runtime(raw, Some(hello)))
}

pub fn macos_service_install(force: bool) -> Result<MacosServiceStatus, String> {
    register_service(force)?;
    ensure_macos_service_current()
}

pub fn macos_service_uninstall() -> Result<MacosServiceStatus, String> {
    let service = daemon_service();
    let current = unsafe { service.status() };
    if current != SMAppServiceStatus::NotRegistered && current != SMAppServiceStatus::NotFound {
        unsafe { service.unregisterAndReturnError() }
            .map_err(|error| service_error("卸载 macOS DNS 后台服务失败", &error))?;
    }
    Ok(status_from_raw(unsafe { service.status() }))
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
    if current == SMAppServiceStatus::Enabled {
        unsafe { service.unregisterAndReturnError() }
            .map_err(|error| service_error("移除旧版 macOS DNS 后台服务失败", &error))?;
    }

    unsafe { service.registerAndReturnError() }
        .map_err(|error| service_error("注册 macOS DNS 后台服务失败", &error))
}

fn probe_hello(attempts: usize) -> Result<HelloResult, String> {
    let mut last_error = "后台服务尚未响应".to_string();
    for attempt in 0..attempts.max(1) {
        match ServiceClient::hello() {
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
        match ServiceClient::hello() {
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
