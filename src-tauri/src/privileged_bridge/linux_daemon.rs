use std::{
    fs, mem,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use signal_hook::consts::signal::{SIGINT, SIGTERM};

use super::{
    BRIDGE_SOCKET_PATH, linux_system_dns,
    rpc_server::{
        handle_requests, initialize_state, perform_handshake, start_background_tasks,
        start_maintenance_tasks,
    },
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const REJECT_DELAY: Duration = Duration::from_millis(100);

pub fn run_daemon(
    data_dir: PathBuf,
    bootstrap_config: Option<PathBuf>,
    web_listen: Option<String>,
) -> Result<(), String> {
    ensure_execution_identity()?;
    fs::create_dir_all(&data_dir)
        .map_err(|error| format!("创建服务数据目录失败（{}）：{error}", data_dir.display()))?;
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("设置服务数据目录权限失败：{error}"))?;

    let state = initialize_state(data_dir, bootstrap_config.as_deref())?;
    // 读取 desired 与重新接管必须在同一个系统 DNS 临界区内完成，否则会与并发的接管/恢复交错。
    let reconciliation = linux_system_dns::reconcile_desired_on_start(&state)?;
    if let Some(error) = reconciliation.error {
        eprintln!("恢复系统 DNS 接管意图失败：{error}");
    }
    if reconciliation.desired {
        start_maintenance_tasks(&state);
    } else {
        start_background_tasks(&state);
    }

    let socket_path = Path::new(BRIDGE_SOCKET_PATH);
    let socket_dir = socket_path
        .parent()
        .ok_or_else(|| "后台服务 IPC 路径缺少父目录".to_string())?;
    fs::create_dir_all(socket_dir)
        .map_err(|error| format!("创建后台服务 IPC 目录失败：{error}"))?;
    fs::set_permissions(socket_dir, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("设置后台服务 IPC 目录权限失败：{error}"))?;
    remove_stale_socket(socket_path)?;

    let listener = UnixListener::bind(socket_path)
        .map_err(|error| format!("创建后台服务 IPC 失败：{error}"))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666))
        .map_err(|error| format!("设置后台服务 IPC 权限失败：{error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("设置后台服务 IPC 非阻塞失败：{error}"))?;

    let shutdown_requested = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGTERM, Arc::clone(&shutdown_requested))
        .map_err(|error| format!("注册 SIGTERM 处理失败：{error}"))?;
    signal_hook::flag::register(SIGINT, Arc::clone(&shutdown_requested))
        .map_err(|error| format!("注册 SIGINT 处理失败：{error}"))?;

    #[cfg(feature = "web-admin")]
    let web_admin = web_listen
        .as_deref()
        .map(|listen| {
            crate::web_admin::start(Arc::clone(&state), listen, Arc::clone(&shutdown_requested))
        })
        .transpose()?;
    #[cfg(not(feature = "web-admin"))]
    {
        if web_listen.is_some() {
            return Err("当前构建未启用 Web 管理后台".to_string());
        }
    }

    while !shutdown_requested.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let stream = match prepare_accepted_stream(stream) {
                    Ok(stream) => stream,
                    Err(error) => {
                        eprintln!("{error}");
                        continue;
                    }
                };
                let state = Arc::clone(&state);
                let shutdown_requested = Arc::clone(&shutdown_requested);
                thread::spawn(move || match handle_linux_client(stream, state) {
                    Ok(true) => shutdown_requested.store(true, Ordering::Release),
                    Ok(false) => {}
                    Err(error) => eprintln!("{error}"),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) => {
                shutdown_requested.store(true, Ordering::Release);
                if let Err(restore_error) =
                    linux_system_dns::restore_before_shutdown(Arc::clone(&state))
                {
                    eprintln!("服务异常退出前恢复系统 DNS 失败：{restore_error}");
                }
                state.shutdown();
                let _ = fs::remove_file(socket_path);
                #[cfg(feature = "web-admin")]
                if let Some(web_admin) = web_admin {
                    web_admin.join();
                }
                return Err(format!("接受后台服务 IPC 连接失败：{error}"));
            }
        }
    }

    if let Err(error) = linux_system_dns::restore_before_shutdown(Arc::clone(&state)) {
        eprintln!("服务停止前恢复系统 DNS 失败：{error}");
    }
    state.shutdown();
    drop(listener);
    let _ = fs::remove_file(socket_path);
    #[cfg(feature = "web-admin")]
    if let Some(web_admin) = web_admin {
        web_admin.join();
    }
    Ok(())
}

fn ensure_execution_identity() -> Result<(), String> {
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid == 0 || is_confirmed_container() {
        return Ok(());
    }
    Err("Linux 宿主服务必须以 root 身份运行；容器内可使用固定非 root 用户".to_string())
}

pub(crate) fn is_confirmed_container() -> bool {
    if std::env::var_os("DNSBLACKHOLE_CONTAINER").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return false;
    }
    if Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists() {
        return true;
    }
    fs::read_to_string("/proc/1/cgroup")
        .map(|content| {
            ["docker", "containerd", "kubepods", "podman", "lxc"]
                .iter()
                .any(|marker| content.contains(marker))
        })
        .unwrap_or(false)
}

fn remove_stale_socket(socket_path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(socket_path).map_err(|error| format!("清理旧 IPC socket 失败：{error}"))
        }
        Ok(_) => Err(format!(
            "拒绝覆盖不是 Unix socket 的 IPC 路径：{}",
            socket_path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("检查 IPC 路径失败：{error}")),
    }
}

fn prepare_accepted_stream(stream: UnixStream) -> Result<UnixStream, String> {
    stream
        .set_nonblocking(false)
        .map_err(|error| format!("设置后台服务 IPC 客户端阻塞模式失败：{error}"))?;
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("设置后台服务握手读取超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("设置后台服务握手写入超时失败：{error}"))?;
    Ok(stream)
}

fn handle_linux_client(
    mut stream: UnixStream,
    state: Arc<crate::service_core::AppState>,
) -> Result<bool, String> {
    if let Err(error) = verify_peer(&stream) {
        thread::sleep(REJECT_DELAY);
        return Err(error);
    }
    if !perform_handshake(&mut stream)? {
        return Ok(false);
    }
    stream
        .set_read_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("设置后台服务请求读取超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("设置后台服务请求写入超时失败：{error}"))?;
    handle_requests(stream, state)
}

fn verify_peer(stream: &UnixStream) -> Result<(), String> {
    let credential = peer_credential(stream)?;
    let service_uid = unsafe { libc::geteuid() };
    if credential.uid == 0 || credential.uid == service_uid {
        return Ok(());
    }
    if active_seat0_uid() == Some(credential.uid) {
        return Ok(());
    }
    Err(format!(
        "拒绝未授权的本机 IPC 客户端：pid={} uid={} gid={}",
        credential.pid, credential.uid, credential.gid
    ))
}

fn peer_credential(stream: &UnixStream) -> Result<libc::ucred, String> {
    let mut credential = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credential).cast(),
            &raw mut length,
        )
    };
    if result != 0 || length as usize != mem::size_of::<libc::ucred>() {
        return Err(format!(
            "读取 IPC 客户端身份失败：{}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(credential)
}

fn active_seat0_uid() -> Option<u32> {
    let session = command_value(&["show-seat", "seat0", "--property=ActiveSession", "--value"])?;
    if session.is_empty() {
        return None;
    }
    command_value(&[
        "show-session",
        session.as_str(),
        "--property=User",
        "--value",
    ])?
    .parse()
    .ok()
}

fn command_value(arguments: &[&str]) -> Option<String> {
    let output = Command::new("loginctl").args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_credential_matches_current_process() {
        let (client, server) = UnixStream::pair().expect("应能创建 Unix socket 对");
        let credential = peer_credential(&server).expect("应能读取对端身份");
        assert_eq!(credential.pid, std::process::id() as i32);
        assert_eq!(credential.uid, unsafe { libc::geteuid() });
        drop(client);
    }
}
