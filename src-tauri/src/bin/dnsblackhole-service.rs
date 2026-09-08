fn main() {
    let result = run();
    if let Err(error) = result {
        eprintln!("DnsBlackhole 后台服务退出：{error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn run() -> Result<(), String> {
    dnsblackhole_lib::privileged_bridge::run_daemon()
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    dnsblackhole_lib::headless::run(std::env::args_os())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn run() -> Result<(), String> {
    Err("dnsblackhole-service 的独立入口仅支持 macOS 与 Linux".to_string())
}
