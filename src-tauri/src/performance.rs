use std::time::Instant;

pub(crate) fn log(scope: &str, module: &str, started: Instant) {
    eprintln!(
        "[加载耗时][{scope}] {module}：{} ms",
        started.elapsed().as_millis()
    );
}

pub(crate) fn log_service(scope: &str, module: &str, started: Instant) {
    let message = format!(
        "[加载耗时][{scope}] {module}：{} ms",
        started.elapsed().as_millis()
    );
    eprintln!("{message}");

    #[cfg(windows)]
    crate::privileged_bridge::write_windows_service_performance_log(&message);
}
