use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use crate::{service_core::initialize_runtime_blocking, storage};

use super::{
    rpc_server::{handle_client, initialize_state, start_maintenance_tasks},
    windows_pipe::{WindowsPipeListener, WindowsPipeStream},
    windows_service_management::WINDOWS_SERVICE_NAME,
};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

pub fn run_service_dispatcher() -> Result<(), String> {
    service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main)
        .map_err(|error| format!("启动 Windows 服务调度器失败：{error}"))
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        write_service_log(&error);
    }
}

fn run_service() -> Result<(), String> {
    write_service_log("服务进程开始初始化");
    let stop_requested = Arc::new(AtomicBool::new(false));
    let handler_stop = Arc::clone(&stop_requested);
    let event_handler = move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            handler_stop.store(true, Ordering::Release);
            thread::spawn(WindowsPipeStream::wake_server);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(WINDOWS_SERVICE_NAME, event_handler)
        .map_err(|error| format!("注册 Windows 服务控制处理器失败：{error}"))?;

    let result = run_service_body(&stop_requested, &status_handle);
    let exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::Win32(1)
    };
    let status_result = status_handle.set_service_status(service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        Duration::default(),
    ));
    result?;
    status_result.map_err(|error| format!("报告 Windows 服务停止状态失败：{error}"))
}

fn run_service_body(
    stop_requested: &Arc<AtomicBool>,
    status_handle: &service_control_handler::ServiceStatusHandle,
) -> Result<(), String> {
    let startup_started = Instant::now();
    status_handle
        .set_service_status(service_status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(0),
            Duration::from_secs(10),
        ))
        .map_err(|error| format!("报告 Windows 服务启动状态失败：{error}"))?;

    let storage_started = Instant::now();
    let service_default_dir = storage::prepare_windows_service_storage(None)?;
    write_service_log(&format!(
        "存储定位完成，耗时 {} ms",
        storage_started.elapsed().as_millis()
    ));
    let state_started = Instant::now();
    let state = initialize_state(service_default_dir)?;
    write_service_log(&format!(
        "数据库与配置初始化完成，耗时 {} ms",
        state_started.elapsed().as_millis()
    ));
    let runtime_started = Instant::now();
    let rule_source = initialize_dns_runtime(&state, stop_requested, status_handle)?;
    write_service_log(&format!(
        "规则加载与 DNS 监听初始化完成，耗时 {} ms，规则来源：{}",
        runtime_started.elapsed().as_millis(),
        match rule_source {
            Some(crate::dns::RuleLoadSource::Cache) => "编译缓存",
            Some(crate::dns::RuleLoadSource::Compiled) => "重新编译",
            None => "未启用",
        }
    ));
    if stop_requested.load(Ordering::Acquire) {
        state.shutdown();
        return Ok(());
    }
    start_maintenance_tasks(&state);
    // IPC 监听器必须先于 Running 状态就绪，避免 GUI 在两步之间误判服务损坏。
    let listener = WindowsPipeListener::bind()?;
    status_handle
        .set_service_status(service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::Win32(0),
            Duration::default(),
        ))
        .map_err(|error| format!("报告 Windows 服务运行状态失败：{error}"))?;
    write_service_log(&format!(
        "服务已进入运行状态，总耗时 {} ms",
        startup_started.elapsed().as_millis()
    ));

    run_service_loop(stop_requested, state, listener)
}

fn initialize_dns_runtime(
    state: &Arc<crate::service_core::AppState>,
    stop_requested: &Arc<AtomicBool>,
    status_handle: &service_control_handler::ServiceStatusHandle,
) -> Result<Option<crate::dns::RuleLoadSource>, String> {
    let (finished_tx, finished_rx) = mpsc::channel();
    let initial_state = Arc::clone(state);
    thread::spawn(move || {
        let source = initialize_runtime_blocking(&initial_state);
        let _ = finished_tx.send(source);
    });

    let mut checkpoint = 1_u32;
    loop {
        match finished_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(source) => {
                let config = state.current_config()?;
                let status = state.status_with_log_stats(false, false);
                if config.enabled && !status.running {
                    return Err(status
                        .error
                        .unwrap_or_else(|| "DNS 初始化完成但监听线程未运行".to_string()));
                }
                return Ok(source);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if stop_requested.load(Ordering::Acquire) {
                    return Ok(None);
                }
                checkpoint = checkpoint.saturating_add(1);
                let mut status = service_status(
                    ServiceState::StartPending,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::Win32(0),
                    Duration::from_secs(10),
                );
                status.checkpoint = checkpoint;
                status_handle
                    .set_service_status(status)
                    .map_err(|error| format!("更新 Windows 服务启动进度失败：{error}"))?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("Windows DNS 初始化线程异常退出".to_string());
            }
        }
    }
}

fn run_service_loop(
    stop_requested: &Arc<AtomicBool>,
    state: Arc<crate::service_core::AppState>,
    mut listener: WindowsPipeListener,
) -> Result<(), String> {
    let restart_requested = Arc::new(AtomicBool::new(false));

    while !stop_requested.load(Ordering::Acquire) && !restart_requested.load(Ordering::Acquire) {
        let stream = listener.accept()?;
        if stop_requested.load(Ordering::Acquire) || restart_requested.load(Ordering::Acquire) {
            break;
        }

        // 在处理当前连接前创建下一实例，缩短并发客户端等待新管道的窗口。
        listener = WindowsPipeListener::bind()?;

        let state = Arc::clone(&state);
        let restart_requested = Arc::clone(&restart_requested);
        thread::spawn(move || match handle_client(stream, state) {
            Ok(true) => {
                restart_requested.store(true, Ordering::Release);
                WindowsPipeStream::wake_server();
            }
            Ok(false) => {}
            Err(error) => write_service_log(&error),
        });
    }
    state.shutdown();
    if restart_requested.load(Ordering::Acquire) {
        Err("Windows DNS 服务收到重新加载请求，将由服务控制管理器重新启动".to_string())
    } else {
        Ok(())
    }
}

fn service_status(
    state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted,
        exit_code,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    }
}

pub(super) fn write_service_log(message: &str) {
    let Ok(data_dir) = storage::windows_service_default_dir() else {
        return;
    };
    let _ = std::fs::create_dir_all(&data_dir);
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("service.log"))
    {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        let _ = writeln!(file, "[{timestamp}] {message}");
    }
}
