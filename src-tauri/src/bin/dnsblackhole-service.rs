#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = dnsblackhole_lib::privileged_bridge::run_daemon() {
        eprintln!("DnsBlackhole 后台服务退出：{error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("dnsblackhole-service 仅用于 macOS");
    std::process::exit(1);
}
