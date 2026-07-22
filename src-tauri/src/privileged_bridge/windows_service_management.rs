use std::{
    ffi::{OsStr, OsString},
    fs,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr, thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use windows_service::{
    Error,
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceDependency, ServiceErrorControl,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, WAIT_OBJECT_0},
    System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject},
    UI::{
        Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
        WindowsAndMessaging::SW_HIDE,
    },
};

use crate::storage;

use super::{ServiceClient, windows_system_dns};

pub(crate) const WINDOWS_SERVICE_NAME: &str = "DnsBlackholeService";
const WINDOWS_SERVICE_DISPLAY_NAME: &str = "DnsBlackhole DNS Service";
const SERVICE_BINARY_NAME: &str = "dnsblackhole-service.exe";
const SERVICE_TRANSITION_ATTEMPTS: usize = 240;
const SERVICE_TRANSITION_INTERVAL: Duration = Duration::from_millis(250);
const SERVICE_STATUS_PROBE_TIMEOUT: Duration = Duration::from_millis(300);
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsServiceStatus {
    pub state: WindowsServiceState,
    pub installed: bool,
    pub running: bool,
    pub ready: bool,
    pub ipc_ready: bool,
    pub expected_version: String,
    pub service_version: Option<String>,
    pub needs_repair: bool,
    pub diagnostic: Option<String>,
}

pub(crate) fn ensure_windows_service_current() -> Result<WindowsServiceStatus, String> {
    windows_service_status()
}

pub(crate) fn windows_service_status() -> Result<WindowsServiceStatus, String> {
    let total_started = Instant::now();
    let scm_started = Instant::now();
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| service_error("连接 Windows 服务管理器失败", error))?;
    let service = match manager.open_service(WINDOWS_SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(error) if is_missing_service(&error) => {
            crate::performance::log("Windows 服务状态", "SCM 查询", scm_started);
            crate::performance::log("Windows 服务状态", "总计（未安装）", total_started);
            return Ok(not_installed_status());
        }
        Err(error) => return Err(service_error("读取 Windows DNS 服务失败", error)),
    };
    let status = service
        .query_status()
        .map_err(|error| service_error("读取 Windows DNS 服务状态失败", error))?;
    let state = map_service_state(status.current_state);
    let running = status.current_state == ServiceState::Running;
    crate::performance::log("Windows 服务状态", "SCM 查询", scm_started);
    let expected_version = env!("CARGO_PKG_VERSION").to_string();
    let probe = running.then(|| {
        let started = Instant::now();
        let result = ServiceClient::probe_with_timeout(SERVICE_STATUS_PROBE_TIMEOUT);
        crate::performance::log("Windows 服务状态", "IPC 就绪探测", started);
        result
    });
    let result = status_from_probe(state, expected_version, probe);
    eprintln!(
        "[Windows 服务状态] state={:?}, ready={}, ipc_ready={}, needs_repair={}, diagnostic={}",
        result.state,
        result.ready,
        result.ipc_ready,
        result.needs_repair,
        result.diagnostic.as_deref().unwrap_or("无")
    );
    crate::performance::log("Windows 服务状态", "总计", total_started);
    Ok(result)
}

pub(crate) fn install_windows_service(
    legacy_default_dir: Option<&Path>,
) -> Result<WindowsServiceStatus, String> {
    run_elevated_service_command("--windows-service-install", legacy_default_dir)?;
    wait_for_service_ready()
}

pub(crate) fn uninstall_windows_service() -> Result<WindowsServiceStatus, String> {
    run_elevated_service_command("--windows-service-uninstall", None)?;
    windows_service_status()
}

pub fn install_windows_service_elevated(
    source_executable: &Path,
    legacy_default_dir: Option<&Path>,
) -> Result<(), String> {
    storage::prepare_windows_service_storage(legacy_default_dir)?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|error| service_error("连接 Windows 服务管理器失败，请确认已授予管理员权限", error))?;

    remove_existing_service(&manager)?;
    let service_binary = install_service_binary(source_executable)?;
    let service_info = ServiceInfo {
        name: OsString::from(WINDOWS_SERVICE_NAME),
        display_name: OsString::from(WINDOWS_SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary,
        launch_arguments: vec![OsString::from("--windows-service")],
        dependencies: vec![ServiceDependency::Service(OsString::from("Tcpip"))],
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::DELETE
        | ServiceAccess::CHANGE_CONFIG;
    let service = manager
        .create_service(&service_info, access)
        .map_err(|error| service_error("创建 Windows DNS 服务失败", error))?;
    service
        .set_description("在系统启动阶段提供本机 DNS 黑名单解析，不依赖 GUI 登录启动。")
        .map_err(|error| service_error("设置 Windows DNS 服务说明失败", error))?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                restart_action(Duration::from_secs(5)),
                restart_action(Duration::from_secs(15)),
                restart_action(Duration::from_secs(60)),
            ]),
        })
        .map_err(|error| service_error("设置 Windows DNS 服务恢复策略失败", error))?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|error| service_error("启用 Windows DNS 服务失败恢复策略失败", error))?;
    service
        .start::<OsString>(&[])
        .map_err(|error| service_error("启动 Windows DNS 服务失败", error))?;
    wait_for_state(&service, ServiceState::Running)
}

pub fn uninstall_windows_service_elevated() -> Result<(), String> {
    let default_data_dir = storage::windows_service_default_dir()?;
    windows_system_dns::restore_system_dns_if_managed(&default_data_dir)
        .map_err(|error| format!("卸载系统服务前恢复原 DNS 失败：{error}"))?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| service_error("连接 Windows 服务管理器失败", error))?;
    remove_existing_service(&manager)?;
    let service_dir = service_install_dir()?;
    if service_dir.exists() {
        fs::remove_dir_all(&service_dir).map_err(|error| {
            format!(
                "删除 Windows DNS 服务程序失败（{}）：{error}",
                service_dir.display()
            )
        })?;
    }
    Ok(())
}

fn remove_existing_service(manager: &ServiceManager) -> Result<(), String> {
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = match manager.open_service(WINDOWS_SERVICE_NAME, access) {
        Ok(service) => service,
        Err(error) if is_missing_service(&error) => return Ok(()),
        Err(error) => return Err(service_error("打开现有 Windows DNS 服务失败", error)),
    };
    stop_existing_service(&service)?;
    service
        .delete()
        .map_err(|error| service_error("删除现有 Windows DNS 服务注册失败", error))?;
    drop(service);

    for attempt in 0..SERVICE_TRANSITION_ATTEMPTS {
        match manager.open_service(WINDOWS_SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Err(error) if is_missing_service(&error) => return Ok(()),
            Err(error) => {
                return Err(service_error("确认 Windows DNS 服务删除状态失败", error));
            }
            Ok(service) => drop(service),
        }
        if attempt + 1 < SERVICE_TRANSITION_ATTEMPTS {
            thread::sleep(SERVICE_TRANSITION_INTERVAL);
        }
    }
    Err("等待现有 Windows DNS 服务删除超时".to_string())
}

fn stop_existing_service(service: &windows_service::service::Service) -> Result<(), String> {
    let mut stop_sent = false;
    for attempt in 0..SERVICE_TRANSITION_ATTEMPTS {
        let status = service
            .query_status()
            .map_err(|error| service_error("读取现有 Windows DNS 服务状态失败", error))?;
        match status.current_state {
            ServiceState::Stopped => return Ok(()),
            ServiceState::Running | ServiceState::Paused if !stop_sent => {
                service
                    .stop()
                    .map_err(|error| service_error("停止现有 Windows DNS 服务失败", error))?;
                stop_sent = true;
            }
            _ => {}
        }
        if attempt + 1 < SERVICE_TRANSITION_ATTEMPTS {
            thread::sleep(SERVICE_TRANSITION_INTERVAL);
        }
    }
    Err("等待现有 Windows DNS 服务停止超时".to_string())
}

fn install_service_binary(source_executable: &Path) -> Result<PathBuf, String> {
    let service_dir = service_install_dir()?;
    fs::create_dir_all(&service_dir).map_err(|error| {
        format!(
            "创建 Windows DNS 服务程序目录失败（{}）：{error}",
            service_dir.display()
        )
    })?;
    let target = service_dir.join(SERVICE_BINARY_NAME);
    let temporary = service_dir.join(format!("{SERVICE_BINARY_NAME}.new"));
    fs::copy(source_executable, &temporary).map_err(|error| {
        format!(
            "复制 Windows DNS 服务程序失败（{} → {}）：{error}",
            source_executable.display(),
            temporary.display()
        )
    })?;
    if target.exists() {
        fs::remove_file(&target)
            .map_err(|error| format!("替换旧 Windows DNS 服务程序失败：{error}"))?;
    }
    fs::rename(&temporary, &target)
        .map_err(|error| format!("启用新的 Windows DNS 服务程序失败：{error}"))?;
    Ok(target)
}

fn service_install_dir() -> Result<PathBuf, String> {
    let program_data = std::env::var_os("ProgramData")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "无法获取 Windows ProgramData 目录".to_string())?;
    Ok(PathBuf::from(program_data)
        .join("DnsBlackhole")
        .join("Service"))
}

fn wait_for_state(
    service: &windows_service::service::Service,
    expected: ServiceState,
) -> Result<(), String> {
    for attempt in 0..SERVICE_TRANSITION_ATTEMPTS {
        let status = service
            .query_status()
            .map_err(|error| service_error("读取 Windows DNS 服务状态失败", error))?;
        if status.current_state == expected {
            return Ok(());
        }
        if attempt + 1 < SERVICE_TRANSITION_ATTEMPTS {
            thread::sleep(SERVICE_TRANSITION_INTERVAL);
        }
    }
    Err(format!("等待 Windows DNS 服务进入 {expected:?} 状态超时"))
}

fn wait_for_service_ready() -> Result<WindowsServiceStatus, String> {
    let mut last = windows_service_status()?;
    for attempt in 0..SERVICE_TRANSITION_ATTEMPTS {
        if last.ready {
            return Ok(last);
        }
        if attempt + 1 < SERVICE_TRANSITION_ATTEMPTS {
            thread::sleep(SERVICE_TRANSITION_INTERVAL);
            last = windows_service_status()?;
        }
    }
    Ok(last)
}

fn run_elevated_service_command(
    command: &str,
    legacy_default_dir: Option<&Path>,
) -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("读取当前程序路径失败：{error}"))?;
    let mut arguments = vec![quote_windows_argument(OsStr::new(command))];
    if let Some(path) = legacy_default_dir {
        arguments.push(quote_windows_argument(OsStr::new("--legacy-data-dir")));
        arguments.push(quote_windows_argument(path.as_os_str()));
    }
    let verb = wide(OsStr::new("runas"));
    let executable = wide(executable.as_os_str());
    let parameters = wide(OsStr::new(&arguments.join(" ")));
    let mut execute_info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: ptr::null_mut(),
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: ptr::null(),
        nShow: SW_HIDE,
        ..Default::default()
    };
    if unsafe { ShellExecuteExW(&mut execute_info) } == 0 {
        return Err(format!(
            "请求 Windows 管理员权限失败，可能取消了授权：{}",
            std::io::Error::last_os_error()
        ));
    }
    if execute_info.hProcess.is_null() {
        return Err("Windows 未返回服务管理进程句柄".to_string());
    }
    let wait_result = unsafe { WaitForSingleObject(execute_info.hProcess, INFINITE) };
    if wait_result != WAIT_OBJECT_0 {
        unsafe {
            CloseHandle(execute_info.hProcess);
        }
        return Err(format!("等待 Windows 服务管理操作失败：{wait_result}"));
    }
    let mut exit_code = 1_u32;
    let exit_code_result = unsafe { GetExitCodeProcess(execute_info.hProcess, &mut exit_code) };
    unsafe {
        CloseHandle(execute_info.hProcess);
    }
    if exit_code_result == 0 {
        return Err(format!(
            "读取 Windows 服务管理操作结果失败：{}",
            std::io::Error::last_os_error()
        ));
    }
    if exit_code != 0 {
        return Err(format!(
            "Windows DNS 服务管理操作未完成（退出码 {exit_code}）"
        ));
    }
    Ok(())
}

fn quote_windows_argument(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    let mut backslashes = 0;
    for character in value.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                quoted.push(character);
                backslashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn restart_action(delay: Duration) -> ServiceAction {
    ServiceAction {
        action_type: ServiceActionType::Restart,
        delay,
    }
}

fn map_service_state(state: ServiceState) -> WindowsServiceState {
    match state {
        ServiceState::Stopped => WindowsServiceState::Stopped,
        ServiceState::StartPending => WindowsServiceState::StartPending,
        ServiceState::StopPending => WindowsServiceState::StopPending,
        ServiceState::Running => WindowsServiceState::Running,
        ServiceState::ContinuePending => WindowsServiceState::ContinuePending,
        ServiceState::PausePending => WindowsServiceState::PausePending,
        ServiceState::Paused => WindowsServiceState::Paused,
    }
}

fn not_installed_status() -> WindowsServiceStatus {
    WindowsServiceStatus {
        state: WindowsServiceState::NotInstalled,
        installed: false,
        running: false,
        ready: false,
        ipc_ready: false,
        expected_version: env!("CARGO_PKG_VERSION").to_string(),
        service_version: None,
        needs_repair: true,
        diagnostic: None,
    }
}

fn status_from_probe(
    state: WindowsServiceState,
    expected_version: String,
    probe: Option<Result<super::HelloResult, String>>,
) -> WindowsServiceStatus {
    let running = state == WindowsServiceState::Running;
    let (service_version, diagnostic) = match probe {
        Some(Ok(hello)) => (Some(hello.service_version), None),
        Some(Err(error)) => (None, Some(error)),
        None => (None, None),
    };
    let ipc_ready = running && service_version.is_some();
    let ready = ipc_ready && service_version.as_deref() == Some(expected_version.as_str());
    let confirmed_incompatible = diagnostic
        .as_deref()
        .is_some_and(|error| error.contains("协议版本不兼容"));
    let needs_repair = match state {
        WindowsServiceState::NotInstalled
        | WindowsServiceState::Stopped
        | WindowsServiceState::Paused => true,
        WindowsServiceState::Running => (ipc_ready && !ready) || confirmed_incompatible,
        WindowsServiceState::StartPending
        | WindowsServiceState::StopPending
        | WindowsServiceState::ContinuePending
        | WindowsServiceState::PausePending => false,
    };
    WindowsServiceStatus {
        state,
        installed: state != WindowsServiceState::NotInstalled,
        running,
        ready,
        ipc_ready,
        expected_version,
        service_version,
        needs_repair,
        diagnostic,
    }
}

fn is_missing_service(error: &Error) -> bool {
    matches!(
        error,
        Error::Winapi(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST)
    )
}

fn service_error(context: &str, error: Error) -> String {
    match error {
        Error::Winapi(error) => format!("{context}：{error}"),
        error => format!("{context}：{error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{WindowsServiceState, quote_windows_argument, status_from_probe};
    use crate::privileged_bridge::{BRIDGE_PROTOCOL_VERSION, HelloResult};
    use std::ffi::OsStr;

    #[test]
    fn quotes_windows_arguments_with_spaces_and_trailing_backslashes() {
        assert_eq!(
            quote_windows_argument(OsStr::new(r"C:\Program Files\DnsBlackhole")),
            r#""C:\Program Files\DnsBlackhole""#
        );
        assert_eq!(
            quote_windows_argument(OsStr::new(r"C:\DnsBlackhole\")),
            r#""C:\DnsBlackhole\\""#
        );
    }

    #[test]
    fn running_service_without_ipc_is_starting_not_broken() {
        let status = status_from_probe(
            WindowsServiceState::Running,
            "1.2.3".to_string(),
            Some(Err("管道尚未就绪".to_string())),
        );

        assert!(status.running);
        assert!(!status.ready);
        assert!(!status.ipc_ready);
        assert!(!status.needs_repair);
    }

    #[test]
    fn running_service_with_old_version_requires_repair() {
        let status = status_from_probe(
            WindowsServiceState::Running,
            "1.2.3".to_string(),
            Some(Ok(HelloResult {
                protocol_version: BRIDGE_PROTOCOL_VERSION,
                service_version: "1.2.2".to_string(),
            })),
        );

        assert!(status.ipc_ready);
        assert!(!status.ready);
        assert!(status.needs_repair);
    }
}
