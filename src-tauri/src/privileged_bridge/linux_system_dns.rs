use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, MutexGuard, mpsc},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::AppConfig,
    service_core::{AppState, apply_listen_port_blocking, start_dns_blocking, stop_dns_blocking},
};

use super::{ServiceClient, linux_daemon::is_confirmed_container};

const STATE_FILE: &str = "system-dns-state.json";
const RESOLV_CONF: &str = "/etc/resolv.conf";
const RESOLVED_DROP_IN: &str = "/etc/systemd/resolved.conf.d/dnsblackhole.conf";
const RESOLVED_RESOLV_CONF: &str = "/run/systemd/resolve/resolv.conf";
const RESOLVED_STUB_RESOLV_CONF: &str = "/run/systemd/resolve/stub-resolv.conf";
/// systemd-resolved 的 stub 监听地址。新版本除 127.0.0.53 外还会监听 127.0.0.54。
const RESOLVED_STUB_ADDRESSES: [&str; 2] = ["127.0.0.53", "127.0.0.54"];
const DNS_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const RESOLVER_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MANAGED_DROP_IN: &str = "# Managed by DnsBlackhole. Do not edit while system DNS is managed.\n\
[Resolve]\n\
DNS=127.0.0.1\n\
FallbackDNS=\n\
Domains=~.\n\
DNSStubListener=no\n";

/// 所有读取或改变系统 DNS 的路径共用这把全局锁，避免快照、`desired` 状态与实际系统状态
/// 在并发的接管、恢复、启动核对和配置保存之间交错。
static SYSTEM_DNS_OPERATION_LOCK: Mutex<()> = Mutex::new(());

/// 持有它表示调用方已进入系统 DNS 全局串行区。持有期间只能调用 `*_unlocked` 内部函数，
/// 不能再次进入带锁的公开入口，否则会自锁。
pub(crate) struct SystemDnsGuard {
    _guard: MutexGuard<'static, ()>,
}

/// daemon 启动时的接管意图核对结果：`desired` 表示状态文件仍要求接管，
/// `error` 是本次自动重新接管失败的原因。
pub(crate) struct StartupReconciliation {
    pub desired: bool,
    pub error: Option<String>,
}

/// 供跨模块的“先校验再操作”场景使用：调用方取锁后在同一临界区内完成校验与动作。
pub(crate) fn lock_operations() -> Result<SystemDnsGuard, String> {
    SYSTEM_DNS_OPERATION_LOCK
        .lock()
        .map(|guard| SystemDnsGuard { _guard: guard })
        .map_err(|_| "系统 DNS 操作锁已损坏".to_string())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinuxSystemDnsStatus {
    pub supported: bool,
    pub desired: bool,
    pub effective: bool,
    pub pending: bool,
    pub conflict: bool,
    pub message: String,
    pub resolv_conf_target: Option<String>,
    pub resolved_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemDnsState {
    version: u32,
    desired: bool,
    effective: bool,
    pending: bool,
    original_resolv_conf: FileSnapshot,
    original_drop_in: FileSnapshot,
    managed_drop_in_sha256: String,
    managed_resolv_conf_target: String,
    #[serde(default)]
    last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FileSnapshot {
    Missing,
    Regular { content_base64: String, mode: u32 },
    Symlink { target: String },
}

pub(crate) fn system_dns_status(data_dir: &Path) -> Result<LinuxSystemDnsStatus, String> {
    let _guard = lock_operations()?;
    system_dns_status_unlocked(data_dir)
}

fn system_dns_status_unlocked(data_dir: &Path) -> Result<LinuxSystemDnsStatus, String> {
    if is_confirmed_container() {
        return Ok(LinuxSystemDnsStatus {
            supported: false,
            desired: false,
            effective: false,
            pending: false,
            conflict: false,
            message: "容器不能接管宿主机系统 DNS".to_string(),
            resolv_conf_target: current_symlink_target(Path::new(RESOLV_CONF)),
            resolved_active: false,
        });
    }

    let environment = inspect_environment();
    let state = read_state(data_dir)?;
    let (desired, effective, pending, conflict, last_error) = if let Some(state) = state {
        let owned = managed_files_match(&state);
        (
            state.desired,
            state.effective && owned,
            state.pending,
            state.effective && !owned,
            state.last_error,
        )
    } else {
        (false, false, false, false, None)
    };
    let message = if conflict {
        "接管后系统 DNS 文件被其它程序修改，已停止自动覆盖".to_string()
    } else if effective {
        "系统 DNS 正由 DnsBlackhole 接管".to_string()
    } else if pending {
        "上次系统 DNS 事务未完成，需要恢复或重新接管".to_string()
    } else if let Some(error) = last_error {
        error
    } else {
        environment
            .as_ref()
            .map(|_| "系统 DNS 未接管".to_string())
            .unwrap_or_else(|error| error.clone())
    };

    Ok(LinuxSystemDnsStatus {
        supported: environment.is_ok(),
        desired,
        effective,
        pending,
        conflict,
        message,
        resolv_conf_target: current_symlink_target(Path::new(RESOLV_CONF)),
        resolved_active: systemctl_is_active("systemd-resolved"),
    })
}

pub(crate) fn take_over_system_dns(state: Arc<AppState>) -> Result<LinuxSystemDnsStatus, String> {
    let _guard = lock_operations()?;
    take_over_system_dns_unlocked(state)
}

fn take_over_system_dns_unlocked(state: Arc<AppState>) -> Result<LinuxSystemDnsStatus, String> {
    if is_confirmed_container() {
        return Err("容器不能接管宿主机系统 DNS，请在宿主侧配置 DNS 指向容器".to_string());
    }
    require_root()?;
    inspect_environment()?;
    let config = state.current_config()?;
    validate_takeover_config(&config)?;

    if let Some(existing) = read_state(&state.default_data_dir)? {
        // 被中断的事务（崩溃、关机、加固配置不当导致的失败）如果相关文件仍属本项目——
        // 内容要么是受管版本、要么还是原始快照——就先恢复到干净基线再继续接管，
        // 不必让用户先手工点一次恢复。只有文件被外部改过才拒绝，交人工处理。
        if existing.pending {
            if !transition_files_are_owned(&existing) {
                return Err(
                    "上次系统 DNS 事务未完成且相关文件已被外部修改，请先人工检查".to_string(),
                );
            }
            restore_system_dns_unlocked(&state, true)?;
        } else if existing.effective {
            if !managed_files_match(&existing) {
                return Err("系统 DNS 接管状态发生冲突，拒绝覆盖外部修改，请先人工检查".to_string());
            }
            start_dns_blocking(Arc::clone(&state))?;
            return system_dns_status_unlocked(&state.default_data_dir);
        }
    }
    if Path::new(RESOLVED_DROP_IN).exists() && read_state(&state.default_data_dir)?.is_none() {
        return Err(format!(
            "发现没有事务状态的现有文件 {RESOLVED_DROP_IN}，拒绝覆盖"
        ));
    }
    ensure_resolved_is_only_port_53_owner()?;

    let mut transaction = SystemDnsState {
        version: 1,
        desired: true,
        effective: false,
        pending: true,
        original_resolv_conf: capture_file(Path::new(RESOLV_CONF))?,
        original_drop_in: capture_file(Path::new(RESOLVED_DROP_IN))?,
        managed_drop_in_sha256: sha256_hex(MANAGED_DROP_IN.as_bytes()),
        managed_resolv_conf_target: RESOLVED_RESOLV_CONF.to_string(),
        last_error: None,
    };
    write_state(&state.default_data_dir, &transaction)?;

    // 端口回滚状态记在事务闭包外面：接管失败时要连端口一起退回去。
    let mut restored_listen_port = None;
    let result = (|| {
        stop_dns_blocking(Arc::clone(&state))?;
        ensure_resolved_drop_in_dir()?;
        write_atomic(
            Path::new(RESOLVED_DROP_IN),
            MANAGED_DROP_IN.as_bytes(),
            0o644,
        )?;
        replace_symlink_atomic(Path::new(RESOLV_CONF), Path::new(RESOLVED_RESOLV_CONF))?;
        restart_resolved()?;
        ensure_port_53_is_free()?;
        // stub 已经让开，这时才绑得上通配 53
        let previous_port = apply_listen_port_blocking(Arc::clone(&state), 53)?;
        if previous_port != 53 {
            restored_listen_port = Some(previous_port);
        }
        start_dns_blocking(Arc::clone(&state))?;
        verify_dns_runtime(&config)?;
        verify_system_resolver()?;
        Ok::<(), String>(())
    })();

    match result {
        Ok(()) => {
            transaction.effective = true;
            transaction.pending = false;
            transaction.last_error = None;
            write_state(&state.default_data_dir, &transaction)?;
            system_dns_status_unlocked(&state.default_data_dir)
        }
        Err(error) => {
            if let Some(previous_port) = restored_listen_port {
                let _ = apply_listen_port_blocking(Arc::clone(&state), previous_port);
            }
            let rollback_error = rollback(&state, &transaction).err();
            transaction.desired = false;
            transaction.effective = false;
            transaction.pending = rollback_error.is_some();
            transaction.last_error = Some(match rollback_error {
                Some(rollback) => format!("接管失败：{error}；回滚失败：{rollback}"),
                None => format!("接管失败，已恢复原系统 DNS：{error}"),
            });
            let _ = write_state(&state.default_data_dir, &transaction);
            Err(transaction.last_error.clone().unwrap_or(error))
        }
    }
}

pub(crate) fn restore_system_dns(
    state: Arc<AppState>,
    preserve_desired: bool,
) -> Result<LinuxSystemDnsStatus, String> {
    let _guard = lock_operations()?;
    restore_system_dns_unlocked(&state, preserve_desired)
}

fn restore_system_dns_unlocked(
    state: &Arc<AppState>,
    preserve_desired: bool,
) -> Result<LinuxSystemDnsStatus, String> {
    if is_confirmed_container() {
        return Err("容器不能恢复宿主机系统 DNS".to_string());
    }
    require_root()?;
    let data_dir = state.default_data_dir.as_path();
    let Some(mut transaction) = read_state(data_dir)? else {
        return system_dns_status_unlocked(data_dir);
    };
    if (transaction.effective || transaction.pending) && !transition_files_are_owned(&transaction) {
        return Err("系统 DNS 文件在接管后被外部修改，拒绝静默覆盖，请先人工检查".to_string());
    }

    begin_restore(&mut transaction, preserve_desired);
    write_state(data_dir, &transaction)?;
    stop_dns_blocking(Arc::clone(state))?;
    restore_files(&transaction)?;
    finish_restore(&mut transaction);
    write_state(data_dir, &transaction)?;

    if let Err(error) = reload_and_verify_resolver() {
        transaction.last_error = Some(format!("原系统 DNS 文件已恢复，但{error}"));
        write_state(data_dir, &transaction)?;
    }
    system_dns_status_unlocked(data_dir)
}

/// daemon 不可用时的受控离线恢复：只做 root 本地文件恢复，不启动 DNS runtime、不重新接管，
/// 仍复用既有快照与所有权校验，冲突或 DnsBlackhole 仍占用 53 端口时拒绝覆盖。
/// 升级停止传入 `preserve_desired`，卸载与人工恢复必须清除 `desired`。
pub(crate) fn restore_system_dns_offline(
    data_dir: &Path,
    preserve_desired: bool,
) -> Result<LinuxSystemDnsStatus, String> {
    let _guard = lock_operations()?;
    if is_confirmed_container() {
        return Err("容器不能恢复宿主机系统 DNS".to_string());
    }
    require_root()?;
    // 服务仍可管理时必须走同一套在线事务，避免离线路径与运行中的 daemon 各写一次状态。
    if ServiceClient::probe().is_ok() {
        return Err(
            "后台服务仍可连接，请使用 dnsblackhole-service system-dns restore 通过服务恢复"
                .to_string(),
        );
    }
    let Some(mut transaction) = read_state(data_dir)? else {
        return system_dns_status_unlocked(data_dir);
    };
    if !transaction.desired && !transaction.effective && !transaction.pending {
        return system_dns_status_unlocked(data_dir);
    }
    if (transaction.effective || transaction.pending) && !transition_files_are_owned(&transaction) {
        return Err("系统 DNS 文件在接管后被外部修改，拒绝静默覆盖，请先人工检查".to_string());
    }
    ensure_port_53_released_for_resolved()?;

    begin_restore(&mut transaction, preserve_desired);
    write_state(data_dir, &transaction)?;
    restore_files(&transaction)?;
    finish_restore(&mut transaction);
    write_state(data_dir, &transaction)?;

    if let Err(error) = reload_and_verify_resolver() {
        transaction.last_error = Some(format!("原系统 DNS 文件已恢复，但{error}"));
        write_state(data_dir, &transaction)?;
    }
    system_dns_status_unlocked(data_dir)
}

pub(crate) fn restore_before_shutdown(state: Arc<AppState>) -> Result<(), String> {
    let _guard = lock_operations()?;
    let Some(transaction) = read_state(&state.default_data_dir)? else {
        return Ok(());
    };
    if transaction.effective {
        // 升级或 systemd stop 只恢复实际状态，`desired` 保留给下次启动重新接管。
        restore_system_dns_unlocked(&state, true).map(|_| ())
    } else {
        Ok(())
    }
}

/// 启动时在同一个临界区内读取 `desired` 并尝试重新接管，避免与并发的接管/恢复交错。
pub(crate) fn reconcile_desired_on_start(
    state: &Arc<AppState>,
) -> Result<StartupReconciliation, String> {
    let _guard = lock_operations()?;
    let Some(existing) = read_state(&state.default_data_dir)? else {
        return Ok(StartupReconciliation {
            desired: false,
            error: None,
        });
    };
    if !existing.desired {
        return Ok(StartupReconciliation {
            desired: false,
            error: None,
        });
    }

    // 未完成事务的自愈由 take_over_system_dns_unlocked 统一处理，这里不再重复一遍
    let error = take_over_system_dns_unlocked(Arc::clone(state)).err();
    Ok(StartupReconciliation {
        desired: true,
        error,
    })
}

pub(crate) fn ensure_system_dns_not_managed(
    _guard: &SystemDnsGuard,
    data_dir: &Path,
) -> Result<(), String> {
    let Some(state) = read_state(data_dir)? else {
        return Ok(());
    };
    if state.desired || state.effective || state.pending {
        Err("系统 DNS 正由 DnsBlackhole 管理，请先执行 system-dns restore".to_string())
    } else {
        Ok(())
    }
}

pub(crate) fn validate_managed_config(
    _guard: &SystemDnsGuard,
    data_dir: &Path,
    config: &AppConfig,
) -> Result<(), String> {
    let Some(state) = read_state(data_dir)? else {
        return Ok(());
    };
    if !(state.desired || state.effective || state.pending) {
        return Ok(());
    }
    // 已接管时不允许关闭自动运行或把端口改离 53，规则与 Windows 侧对齐；
    // 这两条只属于受管校验，不属于接管前置条件——接管事务会自己把它们调整到位。
    if !config.enabled {
        return Err("系统 DNS 正由 DnsBlackhole 管理，请先恢复原 DNS，再关闭自动运行".to_string());
    }
    if config.listen_port != 53 {
        return Err("系统 DNS 正由 DnsBlackhole 管理，请先恢复原 DNS，再修改监听端口".to_string());
    }
    validate_takeover_config(config)
        .map_err(|error| format!("系统 DNS 正由 DnsBlackhole 管理，请先恢复原 DNS。{error}"))
}

fn rollback(state: &Arc<AppState>, transaction: &SystemDnsState) -> Result<(), String> {
    let _ = stop_dns_blocking(Arc::clone(state));
    restore_files(transaction)?;
    reload_and_verify_resolver()
}

/// 恢复事务开始：先落盘 `pending`，保证中途崩溃后仍能被识别为未完成事务。
fn begin_restore(transaction: &mut SystemDnsState, preserve_desired: bool) {
    transaction.pending = true;
    if !preserve_desired {
        transaction.desired = false;
    }
}

fn finish_restore(transaction: &mut SystemDnsState) {
    transaction.effective = false;
    transaction.pending = false;
    transaction.last_error = None;
}

/// 接管回滚、在线恢复和离线恢复共用同一套文件恢复顺序，避免三处各写一遍。
/// 这一步是安全底线：只要它成功，系统文件就不再指向 DnsBlackhole，失败必须向上传播。
fn restore_files(transaction: &SystemDnsState) -> Result<(), String> {
    restore_snapshot(Path::new(RESOLVED_DROP_IN), &transaction.original_drop_in)?;
    restore_snapshot(Path::new(RESOLV_CONF), &transaction.original_resolv_conf)?;
    Ok(())
}

/// 让 resolved 重新读取恢复后的配置并确认解析可用。
///
/// 恢复路径把它降级成告警：系统关机时 systemd 正在拆各种单元，重启 resolved 和解析验证
/// 本来就可能失败。若因此让状态文件继续声称 `effective`，下次启动就会把"文件其实已经还原"
/// 误判成冲突或未完成事务，反而永久挡住自动重新接管。接管回滚仍按失败处理。
fn reload_and_verify_resolver() -> Result<(), String> {
    restart_resolved()?;
    verify_system_resolver()
}

/// 离线恢复前的保护：53 端口还被别人占着时，恢复后的 resolved stub 就绑不上。
/// 最常见的情况是 DnsBlackhole 自己还在监听通配 53（服务没停干净）。
/// 判断同样以地址为准，不依赖 `ss -p` 的进程名，理由见 `port_53_is_free_or_resolved_stub_only`。
fn ensure_port_53_released_for_resolved() -> Result<(), String> {
    let output = port_53_listeners()?;
    if port_53_is_free_or_resolved_stub_only(&output) {
        return Ok(());
    }
    Err(format!(
        "53 端口仍被占用，离线恢复后 systemd-resolved 无法重新监听 stub。\
若占用者是 DnsBlackhole，请先执行 systemctl stop dnsblackhole：\n{output}"
    ))
}

fn inspect_environment() -> Result<(), String> {
    let init = fs::read_to_string("/proc/1/comm")
        .map_err(|error| format!("读取 PID 1 信息失败：{error}"))?;
    if init.trim() != "systemd" {
        return Err("仅支持以 systemd 作为 PID 1 的 Linux 宿主".to_string());
    }
    if !systemctl_is_active("systemd-resolved") {
        return Err("systemd-resolved 未运行，不能自动接管系统 DNS".to_string());
    }
    let target = resolved_symlink_target(Path::new(RESOLV_CONF)).ok_or_else(|| {
        "/etc/resolv.conf 不是可识别的 systemd-resolved 符号链接，拒绝自动修改".to_string()
    })?;
    if target != RESOLVED_STUB_RESOLV_CONF && target != RESOLVED_RESOLV_CONF {
        return Err(format!(
            "/etc/resolv.conf 指向未识别的目标 {target}，拒绝自动修改"
        ));
    }
    Ok(())
}

/// 接管前置校验：只检查监听地址和上游回环，不检查 `enabled` 与监听端口。
///
/// `enabled` 和端口都由接管事务自己在 resolved stub 释放之后落实，那是唯一能成功绑定通配 53
/// 的时机。把它们当成前置条件会让几条必须成立的路径永远失败：优雅停止时的恢复会把 `enabled`
/// 置为 false，下次启动按 `desired` 自动重新接管就再也过不了校验；而配置保存的监听预检不允许在
/// resolved 占着 53 时保存"端口 53 且已启用"的配置，用户手工也补不上，端口一旦改离 53 就回不去。
///
/// 监听地址仍然是前置条件：改成覆盖回环会顺带决定 DNS 是否暴露到局域网，属于安全相关的选择，
/// 不能替用户做。上游回环检查同理，必须在动系统配置之前拦住解析闭环。
fn validate_takeover_config(config: &AppConfig) -> Result<(), String> {
    let listen_ipv4 = config
        .listen_host
        .parse::<Ipv4Addr>()
        .map_err(|_| "接管系统 DNS 前 IPv4 监听地址必须是 0.0.0.0 或 127.0.0.1".to_string())?;
    if listen_ipv4 != Ipv4Addr::UNSPECIFIED && listen_ipv4 != Ipv4Addr::LOCALHOST {
        return Err("接管系统 DNS 前 IPv4 监听地址必须覆盖 127.0.0.1".to_string());
    }
    if config.listen_ipv6 {
        let listen_ipv6 = config
            .listen_ipv6_host
            .parse::<Ipv6Addr>()
            .map_err(|_| "接管系统 DNS 前 IPv6 监听地址必须是 :: 或 ::1".to_string())?;
        if listen_ipv6 != Ipv6Addr::UNSPECIFIED && listen_ipv6 != Ipv6Addr::LOCALHOST {
            return Err("接管系统 DNS 前 IPv6 监听地址必须覆盖 ::1".to_string());
        }
    }

    for (name, value) in [
        ("主上游", config.upstream_dns.as_str()),
        ("备用上游", config.fallback_dns.as_str()),
        ("Bootstrap", config.bootstrap_dns.as_str()),
        ("域名分流", config.domain_upstream_rules.as_str()),
        ("客户端分流", config.client_upstream_rules.as_str()),
    ] {
        if contains_loopback_target(value) {
            return Err(format!("{name}包含本机回环 DNS 目标，会形成解析循环"));
        }
    }
    Ok(())
}

fn contains_loopback_target(value: &str) -> bool {
    value.lines().any(|line| {
        let normalized = line.trim().to_ascii_lowercase();
        if normalized.contains("localhost") || normalized.contains("[::1]") {
            return true;
        }
        normalized
            .split(|character: char| {
                character.is_whitespace()
                    || matches!(character, '/' | ':' | '@' | '#' | '?' | '[' | ']' | ',')
            })
            .filter_map(|token| token.parse::<Ipv4Addr>().ok())
            .any(|address| address.is_loopback())
    })
}

fn ensure_resolved_is_only_port_53_owner() -> Result<(), String> {
    let output = port_53_listeners()?;
    if port_53_is_free_or_resolved_stub_only(&output) {
        Ok(())
    } else {
        Err(format!(
            "53 端口存在 systemd-resolved stub 之外的占用者，拒绝自动腾端口：\n{output}"
        ))
    }
}

/// 判断 53 端口是否只被 systemd-resolved 的 stub 占用（或完全空闲）。
///
/// 这里刻意**不**依赖 `ss -p` 给出的进程名。服务跑在加固后的 systemd unit 里时，
/// `CapabilityBoundingSet` 不含 `CAP_DAC_READ_SEARCH`，`ss` 读不到其它进程的
/// `/proc/<pid>/fd`，`users:(...)` 整列会是空的；按进程名判断就会把 resolved 自己
/// 误判成陌生占用者，接管在正式安装环境下永远失败（已在 Ubuntu 26.04 实测）。
///
/// 真正要确认的是"即将被释放的监听地址"，所以以地址为准：stub 固定用 127.0.0.53/54，
/// dnsmasq、bind、unbound 这些不会用这两个地址。端口空闲也算通过——没有要腾的东西。
fn port_53_is_free_or_resolved_stub_only(listeners: &str) -> bool {
    listeners
        .lines()
        .filter(|line| !line.trim().is_empty())
        .all(|line| {
            listener_local_address(line)
                .is_some_and(|address| RESOLVED_STUB_ADDRESSES.contains(&address))
        })
}

/// 从 `ss -H -lntup` 的一行里取出本地监听地址。
/// 列序为 Netid State Recv-Q Send-Q Local:Port Peer:Port [Process]，
/// 地址可能带接口后缀（`127.0.0.53%lo:53`），IPv6 则形如 `[::]:53`。
fn listener_local_address(line: &str) -> Option<&str> {
    let field = line.split_whitespace().nth(4)?;
    let (address, _) = field.rsplit_once(':')?;
    Some(address.split('%').next().unwrap_or(address))
}

fn ensure_port_53_is_free() -> Result<(), String> {
    let output = port_53_listeners()?;
    if output.trim().is_empty() {
        Ok(())
    } else {
        Err(format!("关闭 resolved stub 后 53 端口仍被占用：\n{output}"))
    }
}

fn port_53_listeners() -> Result<String, String> {
    let output = Command::new("ss")
        .args(["-H", "-lntup", "sport = :53"])
        .output()
        .map_err(|error| format!("执行 ss 检查 53 端口失败：{error}"))?;
    if !output.status.success() {
        return Err(format!(
            "ss 检查 53 端口失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| format!("ss 输出不是 UTF-8：{error}"))
}

/// 显式把 resolved 的 drop-in 目录建成 0755，不依赖 umask。
///
/// systemd-resolved 以 `systemd-resolve` 用户运行，进不了 root 的 0700 目录。而服务 unit 设了
/// `UMask=0077`，`create_dir_all` 建出来的目录就是 0700：drop-in 确实写进去了，resolved 却读不到，
/// 于是 stub 不会关闭，接管最终失败在"关闭 resolved stub 后 53 端口仍被占用"。
/// Ubuntu 26.04 默认不带这个目录，所以每一次全新安装都会踩到（已实测）。
/// 0755 也是各发行版自带该目录时的标准权限。
fn ensure_resolved_drop_in_dir() -> Result<(), String> {
    let directory = Path::new(RESOLVED_DROP_IN)
        .parent()
        .ok_or_else(|| format!("{RESOLVED_DROP_IN} 缺少父目录"))?;
    fs::create_dir_all(directory)
        .map_err(|error| format!("创建目录 {} 失败：{error}", directory.display()))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("设置目录 {} 权限失败：{error}", directory.display()))
}

fn restart_resolved() -> Result<(), String> {
    run_systemctl(&["restart", "systemd-resolved"])
}

fn systemctl_is_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn run_systemctl(arguments: &[&str]) -> Result<(), String> {
    let output = Command::new("systemctl")
        .args(arguments)
        .output()
        .map_err(|error| format!("执行 systemctl 失败：{error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl {} 失败：{}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn verify_dns_runtime(config: &AppConfig) -> Result<(), String> {
    verify_dns_udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 53)))?;
    verify_dns_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 53)))?;
    if config.listen_ipv6 {
        verify_dns_udp(SocketAddr::from((Ipv6Addr::LOCALHOST, 53)))?;
        verify_dns_tcp(SocketAddr::from((Ipv6Addr::LOCALHOST, 53)))?;
    }
    Ok(())
}

fn dns_probe_query() -> Vec<u8> {
    vec![
        0x44, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]
}

fn validate_dns_probe_response(response: &[u8]) -> Result<(), String> {
    if response.len() < 12 || response[0..2] != [0x44, 0x42] || response[2] & 0x80 == 0 {
        return Err("DNS 探测收到无效响应".to_string());
    }
    Ok(())
}

fn verify_dns_udp(address: SocketAddr) -> Result<(), String> {
    let bind_address = match address {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_address)
        .map_err(|error| format!("创建 UDP DNS 探测 socket 失败：{error}"))?;
    socket
        .set_read_timeout(Some(DNS_PROBE_TIMEOUT))
        .map_err(|error| format!("设置 UDP DNS 探测超时失败：{error}"))?;
    socket
        .send_to(&dns_probe_query(), address)
        .map_err(|error| format!("发送 UDP DNS 探测失败（{address}）：{error}"))?;
    let mut response = [0_u8; 4096];
    let (length, _) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("接收 UDP DNS 探测失败（{address}）：{error}"))?;
    validate_dns_probe_response(&response[..length])
}

fn verify_dns_tcp(address: SocketAddr) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&address, DNS_PROBE_TIMEOUT)
        .map_err(|error| format!("连接 TCP DNS 失败（{address}）：{error}"))?;
    stream
        .set_read_timeout(Some(DNS_PROBE_TIMEOUT))
        .map_err(|error| format!("设置 TCP DNS 读取超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(DNS_PROBE_TIMEOUT))
        .map_err(|error| format!("设置 TCP DNS 写入超时失败：{error}"))?;
    let query = dns_probe_query();
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .and_then(|_| stream.write_all(&query))
        .map_err(|error| format!("发送 TCP DNS 探测失败（{address}）：{error}"))?;
    let mut length = [0_u8; 2];
    stream
        .read_exact(&mut length)
        .map_err(|error| format!("读取 TCP DNS 响应长度失败（{address}）：{error}"))?;
    let mut response = vec![0_u8; u16::from_be_bytes(length) as usize];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("读取 TCP DNS 响应失败（{address}）：{error}"))?;
    validate_dns_probe_response(&response)
}

/// 清掉 systemd-resolved 的缓存。命中缓存会让"上游其实已经不可用"的接管看起来健康，
/// 验证也就失去意义；规划要求系统 resolver 验证是一次无缓存测试。清缓存本身失败不算致命。
fn flush_resolved_caches() {
    let _ = Command::new("resolvectl").arg("flush-caches").status();
}

fn verify_system_resolver() -> Result<(), String> {
    flush_resolved_caches();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = ("example.com", 80)
            .to_socket_addrs()
            .map(|mut addresses| addresses.next().is_some())
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(RESOLVER_PROBE_TIMEOUT) {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => Err("系统 resolver 未返回任何地址".to_string()),
        Ok(Err(error)) => Err(format!("系统 resolver 验证失败：{error}")),
        Err(_) => Err("系统 resolver 验证超时".to_string()),
    }
}

fn managed_files_match(state: &SystemDnsState) -> bool {
    let drop_in_matches = fs::read(RESOLVED_DROP_IN)
        .map(|content| sha256_hex(&content) == state.managed_drop_in_sha256)
        .unwrap_or(false);
    let resolv_conf_matches = current_symlink_target(Path::new(RESOLV_CONF))
        .is_some_and(|target| target == state.managed_resolv_conf_target);
    drop_in_matches && resolv_conf_matches
}

fn transition_files_are_owned(state: &SystemDnsState) -> bool {
    let drop_in_safe = fs::read(RESOLVED_DROP_IN)
        .map(|content| sha256_hex(&content) == state.managed_drop_in_sha256)
        .unwrap_or(matches!(&state.original_drop_in, FileSnapshot::Missing))
        || snapshot_matches_current(Path::new(RESOLVED_DROP_IN), &state.original_drop_in);
    let resolv_safe = current_symlink_target(Path::new(RESOLV_CONF))
        .is_some_and(|target| target == state.managed_resolv_conf_target)
        || snapshot_matches_current(Path::new(RESOLV_CONF), &state.original_resolv_conf);
    drop_in_safe && resolv_safe
}

fn snapshot_matches_current(path: &Path, snapshot: &FileSnapshot) -> bool {
    match snapshot {
        FileSnapshot::Missing => fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        FileSnapshot::Regular {
            content_base64,
            mode,
        } => {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return false;
            };
            if !metadata.is_file() || metadata.permissions().mode() & 0o7777 != *mode {
                return false;
            }
            BASE64
                .decode(content_base64)
                .is_ok_and(|expected| fs::read(path).is_ok_and(|current| current == expected))
        }
        FileSnapshot::Symlink { target } => {
            current_symlink_target(path).is_some_and(|current| current == target.as_str())
        }
    }
}

fn current_symlink_target(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_symlink() {
        return None;
    }
    fs::read_link(path)
        .ok()
        .map(|target| target.to_string_lossy().into_owned())
}

fn resolved_symlink_target(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_symlink() {
        return None;
    }
    fs::canonicalize(path)
        .ok()
        .map(|target| target.to_string_lossy().into_owned())
}

fn capture_file(path: &Path) -> Result<FileSnapshot, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileSnapshot::Missing);
        }
        Err(error) => return Err(format!("读取 {} 元数据失败：{error}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)
            .map_err(|error| format!("读取 {} 符号链接失败：{error}", path.display()))?;
        return Ok(FileSnapshot::Symlink {
            target: target.to_string_lossy().into_owned(),
        });
    }
    if metadata.is_file() {
        let content =
            fs::read(path).map_err(|error| format!("读取 {} 内容失败：{error}", path.display()))?;
        return Ok(FileSnapshot::Regular {
            content_base64: BASE64.encode(content),
            mode: metadata.permissions().mode() & 0o7777,
        });
    }
    Err(format!("{} 既不是普通文件也不是符号链接", path.display()))
}

fn restore_snapshot(path: &Path, snapshot: &FileSnapshot) -> Result<(), String> {
    match snapshot {
        FileSnapshot::Missing => remove_file_if_present(path),
        FileSnapshot::Regular {
            content_base64,
            mode,
        } => {
            let content = BASE64
                .decode(content_base64)
                .map_err(|error| format!("解码 {} 备份失败：{error}", path.display()))?;
            write_atomic(path, &content, *mode)
        }
        FileSnapshot::Symlink { target } => replace_symlink_atomic(path, Path::new(target)),
    }
}

fn remove_file_if_present(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(path)
                .map_err(|error| format!("删除 {} 失败：{error}", path.display()))?;
            sync_parent(path)
        }
        Ok(_) => Err(format!("拒绝删除不是文件的路径：{}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("检查 {} 失败：{error}", path.display())),
    }
}

fn write_state(data_dir: &Path, state: &SystemDnsState) -> Result<(), String> {
    let content = serde_json::to_vec_pretty(state)
        .map_err(|error| format!("序列化系统 DNS 事务状态失败：{error}"))?;
    write_atomic(&data_dir.join(STATE_FILE), &content, 0o600)
}

fn read_state(data_dir: &Path) -> Result<Option<SystemDnsState>, String> {
    let path = data_dir.join(STATE_FILE);
    let content = match fs::read(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("读取系统 DNS 事务状态失败：{error}")),
    };
    serde_json::from_slice(&content)
        .map(Some)
        .map_err(|error| format!("系统 DNS 事务状态损坏，拒绝继续修改：{error}"))
}

fn write_atomic(path: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} 缺少父目录", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("创建目录 {} 失败：{error}", parent.display()))?;
    let temporary = temporary_sibling(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("创建临时文件 {} 失败：{error}", temporary.display()))?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| format!("设置临时文件权限失败：{error}"))?;
        file.write_all(content)
            .map_err(|error| format!("写入临时文件失败：{error}"))?;
        file.sync_all()
            .map_err(|error| format!("同步临时文件失败：{error}"))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("原子替换 {} 失败：{error}", path.display()))?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn replace_symlink_atomic(path: &Path, target: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} 缺少父目录", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("创建目录 {} 失败：{error}", parent.display()))?;
    let temporary = temporary_sibling(path);
    let result = (|| {
        std::os::unix::fs::symlink(target, &temporary)
            .map_err(|error| format!("创建临时符号链接失败：{error}"))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("原子替换 {} 符号链接失败：{error}", path.display()))?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn temporary_sibling(path: &Path) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("dnsblackhole");
    path.with_file_name(format!(".{name}.tmp-{}-{unique}", std::process::id()))
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} 缺少父目录", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("同步目录 {} 失败：{error}", parent.display()))
}

fn sha256_hex(content: &[u8]) -> String {
    Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn require_root() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err("系统 DNS 操作必须由 root 服务执行".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系统时间应有效")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dnsblackhole-system-dns-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("应能创建测试目录");
        path
    }

    #[test]
    fn file_snapshots_restore_regular_symlink_and_missing_states() {
        let directory = temporary_directory("snapshot");
        let regular = directory.join("regular");
        fs::write(&regular, b"before").expect("应能写入普通文件");
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o640)).expect("应能设置权限");
        let snapshot = capture_file(&regular).expect("应能备份普通文件");
        fs::write(&regular, b"after").expect("应能修改普通文件");
        restore_snapshot(&regular, &snapshot).expect("应能恢复普通文件");
        assert_eq!(fs::read(&regular).expect("应能读取普通文件"), b"before");
        assert_eq!(
            fs::metadata(&regular)
                .expect("应能读取权限")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );

        let link = directory.join("link");
        std::os::unix::fs::symlink("regular", &link).expect("应能创建链接");
        let snapshot = capture_file(&link).expect("应能备份链接");
        replace_symlink_atomic(&link, Path::new("other")).expect("应能替换链接");
        restore_snapshot(&link, &snapshot).expect("应能恢复链接");
        assert_eq!(
            fs::read_link(&link).expect("应能读取链接"),
            Path::new("regular")
        );

        let missing = directory.join("missing");
        let snapshot = capture_file(&missing).expect("应能记录缺失状态");
        fs::write(&missing, b"created").expect("应能创建文件");
        restore_snapshot(&missing, &snapshot).expect("应能恢复缺失状态");
        assert!(!missing.exists());
        fs::remove_dir_all(directory).expect("应能清理测试目录");
    }

    #[test]
    fn loopback_targets_are_rejected_without_false_positive_for_remote_ports() {
        assert!(contains_loopback_target("127.0.0.1:5353"));
        assert!(contains_loopback_target("https://localhost/dns-query"));
        assert!(contains_loopback_target("tls://[::1]:853"));
        assert!(!contains_loopback_target("https://1.1.1.1/dns-query"));
        assert!(!contains_loopback_target(
            "https://dns.alidns.com/dns-query"
        ));
    }

    #[test]
    fn managed_drop_in_hash_is_stable() {
        assert_eq!(sha256_hex(MANAGED_DROP_IN.as_bytes()).len(), 64);
        assert_eq!(
            sha256_hex(MANAGED_DROP_IN.as_bytes()),
            sha256_hex(MANAGED_DROP_IN.as_bytes())
        );
    }

    fn managed_state() -> SystemDnsState {
        SystemDnsState {
            version: 1,
            desired: true,
            effective: true,
            pending: false,
            original_resolv_conf: FileSnapshot::Symlink {
                target: RESOLVED_STUB_RESOLV_CONF.to_string(),
            },
            original_drop_in: FileSnapshot::Missing,
            managed_drop_in_sha256: sha256_hex(MANAGED_DROP_IN.as_bytes()),
            managed_resolv_conf_target: RESOLVED_RESOLV_CONF.to_string(),
            last_error: None,
        }
    }

    #[test]
    fn global_lock_serializes_concurrent_system_dns_operations() {
        use std::{
            sync::atomic::{AtomicBool, AtomicUsize, Ordering},
            thread,
        };

        static ACTIVE: AtomicUsize = AtomicUsize::new(0);
        static OVERLAPPED: AtomicBool = AtomicBool::new(false);

        let handles = (0..8)
            .map(|_| {
                thread::spawn(|| {
                    let _guard = lock_operations().expect("应能取得系统 DNS 操作锁");
                    if ACTIVE.fetch_add(1, Ordering::SeqCst) != 0 {
                        OVERLAPPED.store(true, Ordering::SeqCst);
                    }
                    thread::sleep(Duration::from_millis(5));
                    ACTIVE.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().expect("并发线程应正常结束");
        }

        assert!(
            !OVERLAPPED.load(Ordering::SeqCst),
            "系统 DNS 操作不应并发进入临界区"
        );
        assert_eq!(ACTIVE.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn upgrade_restore_preserves_desired_while_uninstall_clears_it() {
        let mut upgrade = managed_state();
        begin_restore(&mut upgrade, true);
        assert!(upgrade.pending, "恢复开始必须先落盘 pending");
        assert!(upgrade.desired, "升级停止必须保留接管意图");
        finish_restore(&mut upgrade);
        assert!(!upgrade.pending);
        assert!(!upgrade.effective);
        assert!(upgrade.desired);

        let mut uninstall = managed_state();
        begin_restore(&mut uninstall, false);
        assert!(!uninstall.desired, "卸载与人工恢复必须清除接管意图");
        finish_restore(&mut uninstall);
        assert!(!uninstall.pending);
        assert!(!uninstall.effective);
        assert!(!uninstall.desired);
    }

    #[test]
    fn state_file_round_trip_keeps_transaction_fields_and_permissions() {
        let directory = temporary_directory("state");
        assert!(
            read_state(&directory)
                .expect("空目录应能读取状态")
                .is_none()
        );

        let mut state = managed_state();
        begin_restore(&mut state, true);
        write_state(&directory, &state).expect("应能写入事务状态");
        let restored = read_state(&directory)
            .expect("应能读取事务状态")
            .expect("事务状态应存在");
        assert!(restored.desired);
        assert!(restored.pending);
        assert!(restored.effective);
        assert_eq!(
            restored.managed_drop_in_sha256,
            sha256_hex(MANAGED_DROP_IN.as_bytes())
        );
        assert_eq!(restored.managed_resolv_conf_target, RESOLVED_RESOLV_CONF);
        assert_eq!(
            fs::metadata(directory.join(STATE_FILE))
                .expect("应能读取状态文件权限")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        fs::write(directory.join(STATE_FILE), b"not json").expect("应能写入损坏状态");
        assert!(
            read_state(&directory).is_err(),
            "损坏的事务状态必须报错而不是当作未接管"
        );
        fs::remove_dir_all(directory).expect("应能清理测试目录");
    }

    #[test]
    fn takeover_validation_ignores_enabled_and_port_but_guards_listen_host() {
        // 优雅停止后的状态是 enabled=false，端口也可能被改离 53，两者都由接管事务自己补齐
        let stopped = AppConfig {
            listen_port: 5399,
            listen_host: "0.0.0.0".to_string(),
            enabled: false,
            ..AppConfig::default()
        };
        validate_takeover_config(&stopped).expect("接管校验不应要求 enabled 或端口已是 53");

        // 监听地址是否覆盖回环会决定 DNS 是否暴露到局域网，必须由用户自己改
        let narrow = AppConfig {
            listen_host: "192.168.1.10".to_string(),
            ..stopped.clone()
        };
        let error = validate_takeover_config(&narrow).expect_err("监听地址不覆盖回环必须被拒绝");
        assert!(error.contains("127.0.0.1"), "{error}");

        let looping = AppConfig {
            upstream_dns: "127.0.0.1".to_string(),
            ..stopped
        };
        let error = validate_takeover_config(&looping).expect_err("上游指回本机必须被拒绝");
        assert!(error.contains("回环"), "{error}");
    }

    #[test]
    fn managed_validation_rejects_disabling_auto_start_and_moving_port() {
        let directory = temporary_directory("managed-validate");
        let guard = lock_operations().expect("应能取得系统 DNS 操作锁");
        let managed = AppConfig {
            listen_port: 53,
            listen_host: "0.0.0.0".to_string(),
            enabled: true,
            ..AppConfig::default()
        };
        let disabled = AppConfig {
            enabled: false,
            ..managed.clone()
        };

        // 没有事务状态时不做受管校验
        validate_managed_config(&guard, &directory, &disabled).expect("未接管时应放行");

        write_state(&directory, &managed_state()).expect("应能写入事务状态");
        let error = validate_managed_config(&guard, &directory, &disabled)
            .expect_err("受管状态下关闭自动运行必须被拒绝");
        assert!(error.contains("关闭自动运行"), "{error}");

        let moved = AppConfig {
            listen_port: 5399,
            ..managed.clone()
        };
        let error = validate_managed_config(&guard, &directory, &moved)
            .expect_err("受管状态下改端口必须被拒绝");
        assert!(error.contains("监听端口"), "{error}");

        validate_managed_config(&guard, &directory, &managed).expect("受管状态下合法配置应放行");

        drop(guard);
        fs::remove_dir_all(directory).expect("应能清理测试目录");
    }

    #[test]
    fn port_53_ownership_is_decided_by_address_not_process_name() {
        // 加固后的 unit 里 ss 读不到其它进程，users:(...) 整列为空，判断必须照样成立
        let stub_without_process = "udp   UNCONN 0      0      127.0.0.53:53 0.0.0.0:*\n\
tcp   LISTEN 0      0      127.0.0.54:53 0.0.0.0:*";
        assert!(port_53_is_free_or_resolved_stub_only(stub_without_process));

        let stub_with_process = "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* \
users:((\"systemd-resolve\",pid=701,fd=13))";
        assert!(port_53_is_free_or_resolved_stub_only(stub_with_process));

        // 端口空闲也算通过：没有要腾的东西
        assert!(port_53_is_free_or_resolved_stub_only(""));
        assert!(port_53_is_free_or_resolved_stub_only("\n  \n"));

        // DnsBlackhole 自己占着通配 53（离线恢复必须拦住）
        let wildcard = "udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* \
users:((\"dnsblackhole-se\",pid=812,fd=9))";
        assert!(!port_53_is_free_or_resolved_stub_only(wildcard));
        assert!(!port_53_is_free_or_resolved_stub_only(&format!(
            "{stub_with_process}\n{wildcard}"
        )));

        // 第三方解析器：地址不是 stub 的两个，即使读不到进程名也要拒绝
        let dnsmasq = "udp   UNCONN 0      0      127.0.0.1:53 0.0.0.0:*";
        assert!(!port_53_is_free_or_resolved_stub_only(dnsmasq));
        let ipv6_wildcard = "udp   UNCONN 0      0      [::]:53 [::]:*";
        assert!(!port_53_is_free_or_resolved_stub_only(ipv6_wildcard));
    }

    #[test]
    fn listener_local_address_strips_port_and_interface_suffix() {
        assert_eq!(
            listener_local_address("udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*"),
            Some("127.0.0.53")
        );
        assert_eq!(
            listener_local_address("tcp LISTEN 0 4096 0.0.0.0:53 0.0.0.0:*"),
            Some("0.0.0.0")
        );
        assert_eq!(
            listener_local_address("udp UNCONN 0 0 [::]:53 [::]:*"),
            Some("[::]")
        );
        assert_eq!(listener_local_address("列数不足"), None);
    }
}
