use objc2_foundation::{NSError, NSString};
use objc2_service_management::{SMAppService, SMAppServiceStatus};

use super::{MacosServiceState, MacosServiceStatus};

const SERVICE_PLIST_NAME: &str = "com.dnsblackhole.app.service.plist";

pub fn macos_service_status() -> Result<MacosServiceStatus, String> {
    let service = daemon_service();
    Ok(status_from_raw(unsafe { service.status() }))
}

pub fn macos_service_install(force: bool) -> Result<MacosServiceStatus, String> {
    let service = daemon_service();
    let current = unsafe { service.status() };
    if current == SMAppServiceStatus::RequiresApproval {
        return Ok(status_from_raw(current));
    }
    if current == SMAppServiceStatus::Enabled && !force {
        return Ok(status_from_raw(current));
    }
    if current == SMAppServiceStatus::Enabled {
        unsafe { service.unregisterAndReturnError() }
            .map_err(|error| service_error("移除旧版 macOS DNS 后台服务失败", &error))?;
    }

    unsafe { service.registerAndReturnError() }
        .map_err(|error| service_error("注册 macOS DNS 后台服务失败", &error))?;
    Ok(status_from_raw(unsafe { service.status() }))
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

fn daemon_service() -> objc2::rc::Retained<SMAppService> {
    let plist_name = NSString::from_str(SERVICE_PLIST_NAME);
    unsafe { SMAppService::daemonServiceWithPlistName(&plist_name) }
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
        expected_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

fn service_error(prefix: &str, error: &NSError) -> String {
    format!("{prefix}：{}", error.localizedDescription())
}
