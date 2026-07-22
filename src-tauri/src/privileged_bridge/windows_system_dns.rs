use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use windows_sys::{
    Win32::{
        NetworkManagement::{
            IpHelper::{
                DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6,
                DNS_SETTING_NAMESERVER, DNS_SETTING_PROFILE_NAMESERVER, FreeMibTable, GetIfTable2,
                IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, MIB_IF_TABLE2,
            },
            Ndis::IfOperStatusUp,
        },
        System::LibraryLoader::{GetProcAddress, LoadLibraryW},
    },
    core::GUID,
};

const BACKUP_VERSION: u32 = 1;
const BACKUP_FILE: &str = "system-dns-backup.json";
const IPV4_LOCAL_DNS: &str = "127.0.0.1";
const IPV6_LOCAL_DNS: &str = "::1";
const DNS114_IPV4: [&str; 2] = ["114.114.114.114", "114.114.115.115"];
const GOOGLE_IPV4: [&str; 2] = ["8.8.8.8", "8.8.4.4"];
const GOOGLE_IPV6: [&str; 2] = ["2001:4860:4860::8888", "2001:4860:4860::8844"];
const HARDWARE_INTERFACE_FLAG: u8 = 1;
const MAX_DNS_SETTINGS_CHARS: usize = 64 * 1024;

static SYSTEM_DNS_OPERATION_LOCK: Mutex<()> = Mutex::new(());
static DNS_INTERFACE_API: OnceLock<Result<DnsInterfaceApi, String>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WindowsSystemDnsStatus {
    pub managed: bool,
    pub in_effect: bool,
    pub adapters: Vec<String>,
    pub restore_ipv4_automatic: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) enum WindowsSystemDnsFallback {
    #[serde(rename = "automatic")]
    Automatic,
    #[serde(rename = "dns114")]
    Dns114,
    #[serde(rename = "google")]
    Google,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemDnsBackup {
    version: u32,
    adapters: Vec<AdapterDnsBackup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdapterDnsBackup {
    interface_guid: String,
    interface_name: String,
    ipv4_servers: Option<Vec<String>>,
    #[serde(default)]
    ipv4_profile_servers: Option<Vec<String>>,
    ipv6_servers: Option<Vec<String>>,
    #[serde(default)]
    ipv6_profile_servers: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DnsFamilySettings {
    name_servers: Option<Vec<String>>,
    profile_name_servers: Option<Vec<String>>,
}

#[derive(Clone)]
struct NetworkAdapter {
    guid: GUID,
    guid_text: String,
    name: String,
}

#[derive(Debug, Clone, Copy)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

struct AppliedChange {
    guid: GUID,
    name: String,
    family: AddressFamily,
    original_settings: DnsFamilySettings,
}

#[derive(Clone, Copy)]
struct DnsInterfaceApi {
    get: unsafe extern "system" fn(GUID, *mut DNS_INTERFACE_SETTINGS) -> u32,
    set: unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS) -> u32,
    free: unsafe extern "system" fn(*mut DNS_INTERFACE_SETTINGS),
}

pub(crate) fn system_dns_status(default_data_dir: &Path) -> Result<WindowsSystemDnsStatus, String> {
    let _guard = SYSTEM_DNS_OPERATION_LOCK
        .lock()
        .map_err(|_| "系统 DNS 操作锁已损坏".to_string())?;
    system_dns_status_unlocked(default_data_dir)
}

pub(crate) fn system_dns_is_managed(default_data_dir: &Path) -> bool {
    backup_path(default_data_dir).exists()
}

pub(crate) fn take_over_system_dns(
    default_data_dir: &Path,
) -> Result<WindowsSystemDnsStatus, String> {
    let _guard = SYSTEM_DNS_OPERATION_LOCK
        .lock()
        .map_err(|_| "系统 DNS 操作锁已损坏".to_string())?;
    let backup_path = backup_path(default_data_dir);
    if backup_path.exists() {
        return Err("系统 DNS 已由 DnsBlackhole 接管，请先恢复原 DNS".to_string());
    }

    let adapters = active_physical_adapters()?;
    if adapters.is_empty() {
        return Err("未找到已连接的物理网卡，无法接管系统 DNS".to_string());
    }
    let backup = SystemDnsBackup {
        version: BACKUP_VERSION,
        adapters: adapters
            .iter()
            .map(snapshot_adapter)
            .collect::<Result<Vec<_>, _>>()?,
    };
    if let Some(adapter) = backup
        .adapters
        .iter()
        .find(|adapter| adapter_backup_contains_local_dns(adapter))
    {
        return Err(format!(
            "网卡“{}”已经指向 127.0.0.1 或 ::1，但 DnsBlackhole 没有原 DNS 备份。请先在 Windows 中恢复希望保留的 DNS，再执行接管",
            adapter.interface_name
        ));
    }
    write_backup(default_data_dir, &backup)?;

    let mut changes = Vec::new();
    let result: Result<(), String> = (|| {
        for (adapter, original) in adapters.iter().zip(&backup.adapters) {
            set_dns_settings(
                adapter.guid,
                AddressFamily::Ipv4,
                &local_dns_settings(AddressFamily::Ipv4),
            )
            .map_err(|error| format!("设置网卡“{}”的 IPv4 DNS 失败：{error}", adapter.name))?;
            changes.push(AppliedChange {
                guid: adapter.guid,
                name: adapter.name.clone(),
                family: AddressFamily::Ipv4,
                original_settings: backup_family_settings(original, AddressFamily::Ipv4),
            });

            set_dns_settings(
                adapter.guid,
                AddressFamily::Ipv6,
                &local_dns_settings(AddressFamily::Ipv6),
            )
            .map_err(|error| format!("设置网卡“{}”的 IPv6 DNS 失败：{error}", adapter.name))?;
            changes.push(AppliedChange {
                guid: adapter.guid,
                name: adapter.name.clone(),
                family: AddressFamily::Ipv6,
                original_settings: backup_family_settings(original, AddressFamily::Ipv6),
            });
        }
        Ok(())
    })();

    if let Err(error) = result {
        let rollback_errors = rollback_changes(&changes);
        if rollback_errors.is_empty() {
            if let Err(remove_error) = fs::remove_file(&backup_path) {
                return Err(format!(
                    "{error}。已恢复已修改的网卡，但删除 DNS 备份失败：{remove_error}"
                ));
            }
            return Err(format!("{error}。已自动恢复原 DNS"));
        }
        return Err(format!(
            "{error}。自动恢复未全部完成，请点击“恢复原 DNS”：{}",
            rollback_errors.join("；")
        ));
    }

    Ok(WindowsSystemDnsStatus {
        managed: true,
        in_effect: true,
        adapters: adapters.into_iter().map(|adapter| adapter.name).collect(),
        restore_ipv4_automatic: backup_restores_ipv4_automatically(&backup),
    })
}

pub(crate) fn restore_system_dns(
    default_data_dir: &Path,
) -> Result<WindowsSystemDnsStatus, String> {
    let _guard = SYSTEM_DNS_OPERATION_LOCK
        .lock()
        .map_err(|_| "系统 DNS 操作锁已损坏".to_string())?;
    restore_system_dns_unlocked(default_data_dir)
}

pub(crate) fn replace_unmanaged_local_dns(
    default_data_dir: &Path,
    preset: WindowsSystemDnsFallback,
) -> Result<WindowsSystemDnsStatus, String> {
    let _guard = SYSTEM_DNS_OPERATION_LOCK
        .lock()
        .map_err(|_| "系统 DNS 操作锁已损坏".to_string())?;
    if backup_path(default_data_dir).exists() {
        return Err("已经存在原 DNS 备份，请直接恢复原 DNS".to_string());
    }

    let adapters = active_physical_adapters()?;
    if adapters.is_empty() {
        return Err("未找到已连接的物理网卡，无法解除本机 DNS".to_string());
    }
    let snapshots = adapters
        .iter()
        .map(snapshot_adapter)
        .collect::<Result<Vec<_>, _>>()?;
    let mut changes = Vec::new();
    let result: Result<(), String> = (|| {
        for (adapter, snapshot) in adapters.iter().zip(&snapshots) {
            let ipv4 = backup_family_settings(snapshot, AddressFamily::Ipv4);
            if ipv4.contains(IPV4_LOCAL_DNS) {
                set_dns_settings(
                    adapter.guid,
                    AddressFamily::Ipv4,
                    &fallback_dns_settings(preset, AddressFamily::Ipv4),
                )
                .map_err(|error| format!("设置网卡“{}”的 IPv4 DNS 失败：{error}", adapter.name))?;
                changes.push(AppliedChange {
                    guid: adapter.guid,
                    name: adapter.name.clone(),
                    family: AddressFamily::Ipv4,
                    original_settings: ipv4,
                });
            }

            let ipv6 = backup_family_settings(snapshot, AddressFamily::Ipv6);
            if ipv6.contains(IPV6_LOCAL_DNS) {
                set_dns_settings(
                    adapter.guid,
                    AddressFamily::Ipv6,
                    &fallback_dns_settings(preset, AddressFamily::Ipv6),
                )
                .map_err(|error| format!("设置网卡“{}”的 IPv6 DNS 失败：{error}", adapter.name))?;
                changes.push(AppliedChange {
                    guid: adapter.guid,
                    name: adapter.name.clone(),
                    family: AddressFamily::Ipv6,
                    original_settings: ipv6,
                });
            }
        }
        if changes.is_empty() {
            return Err("当前已连接的物理网卡没有使用 127.0.0.1 或 ::1".to_string());
        }
        Ok(())
    })();

    if let Err(error) = result {
        let rollback_errors = rollback_changes(&changes);
        if rollback_errors.is_empty() {
            return Err(format!("{error}。已自动恢复本次修改"));
        }
        return Err(format!(
            "{error}。自动恢复未全部完成：{}",
            rollback_errors.join("；")
        ));
    }

    system_dns_status_unlocked(default_data_dir)
}

pub(crate) fn restore_system_dns_with_fallback(
    default_data_dir: &Path,
    preset: WindowsSystemDnsFallback,
) -> Result<WindowsSystemDnsStatus, String> {
    let _guard = SYSTEM_DNS_OPERATION_LOCK
        .lock()
        .map_err(|_| "系统 DNS 操作锁已损坏".to_string())?;
    let path = backup_path(default_data_dir);
    if !path.exists() {
        return Err("没有可替换的系统 DNS 备份".to_string());
    }
    let backup = read_backup(&path)?;
    let mut changes = Vec::new();
    let result: Result<(), String> = (|| {
        for adapter in &backup.adapters {
            let guid = parse_guid(&adapter.interface_guid)?;
            for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
                let current = read_interface_dns_settings(guid, family)?;
                set_dns_settings(guid, family, &fallback_dns_settings(preset, family)).map_err(
                    |error| {
                        format!(
                            "设置网卡“{}”的 {} DNS 失败：{error}",
                            adapter.interface_name,
                            family_name(family)
                        )
                    },
                )?;
                changes.push(AppliedChange {
                    guid,
                    name: adapter.interface_name.clone(),
                    family,
                    original_settings: current,
                });
            }
        }
        Ok(())
    })();

    if let Err(error) = result {
        let rollback_errors = rollback_changes(&changes);
        if rollback_errors.is_empty() {
            return Err(format!("{error}。已自动恢复本次修改"));
        }
        return Err(format!(
            "{error}。自动恢复未全部完成，原备份仍已保留：{}",
            rollback_errors.join("；")
        ));
    }

    fs::remove_file(&path)
        .map_err(|error| format!("外部 DNS 已设置，但删除原 DNS 备份失败，可稍后重试：{error}"))?;
    Ok(WindowsSystemDnsStatus {
        managed: false,
        in_effect: false,
        adapters: backup
            .adapters
            .into_iter()
            .map(|adapter| adapter.interface_name)
            .collect(),
        restore_ipv4_automatic: false,
    })
}

pub(crate) fn restore_system_dns_if_managed(default_data_dir: &Path) -> Result<(), String> {
    let _guard = SYSTEM_DNS_OPERATION_LOCK
        .lock()
        .map_err(|_| "系统 DNS 操作锁已损坏".to_string())?;
    if backup_path(default_data_dir).exists() {
        restore_system_dns_unlocked(default_data_dir)?;
    }
    Ok(())
}

fn restore_system_dns_unlocked(default_data_dir: &Path) -> Result<WindowsSystemDnsStatus, String> {
    let path = backup_path(default_data_dir);
    if !path.exists() {
        return Err("没有可恢复的系统 DNS 备份".to_string());
    }
    let backup = read_backup(&path)?;
    let mut errors = Vec::new();
    for adapter in &backup.adapters {
        let guid = parse_guid(&adapter.interface_guid)?;
        if let Err(error) = set_dns_settings(
            guid,
            AddressFamily::Ipv4,
            &backup_family_settings(adapter, AddressFamily::Ipv4),
        ) {
            errors.push(format!(
                "网卡“{}”的 IPv4 DNS：{error}",
                adapter.interface_name
            ));
        }
        if let Err(error) = set_dns_settings(
            guid,
            AddressFamily::Ipv6,
            &backup_family_settings(adapter, AddressFamily::Ipv6),
        ) {
            errors.push(format!(
                "网卡“{}”的 IPv6 DNS：{error}",
                adapter.interface_name
            ));
        }
    }
    if !errors.is_empty() {
        return Err(format!(
            "部分系统 DNS 未能恢复，备份已保留，可稍后重试：{}",
            errors.join("；")
        ));
    }
    fs::remove_file(&path).map_err(|error| format!("删除已恢复的系统 DNS 备份失败：{error}"))?;
    Ok(WindowsSystemDnsStatus {
        managed: false,
        in_effect: false,
        adapters: backup
            .adapters
            .into_iter()
            .map(|adapter| adapter.interface_name)
            .collect(),
        restore_ipv4_automatic: false,
    })
}

fn system_dns_status_unlocked(default_data_dir: &Path) -> Result<WindowsSystemDnsStatus, String> {
    let path = backup_path(default_data_dir);
    if !path.exists() {
        let active_adapters = active_physical_adapters()?;
        let in_effect = active_adapters
            .iter()
            .map(snapshot_adapter)
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(adapter_backup_contains_local_dns);
        let adapters = active_adapters
            .into_iter()
            .map(|adapter| adapter.name)
            .collect();
        return Ok(WindowsSystemDnsStatus {
            managed: false,
            in_effect,
            adapters,
            restore_ipv4_automatic: false,
        });
    }

    let backup = read_backup(&path)?;
    let in_effect = backup
        .adapters
        .iter()
        .all(|adapter| adapter_dns_in_effect(adapter).unwrap_or(false));
    let restore_ipv4_automatic = backup_restores_ipv4_automatically(&backup);
    Ok(WindowsSystemDnsStatus {
        managed: true,
        in_effect,
        adapters: backup
            .adapters
            .into_iter()
            .map(|adapter| adapter.interface_name)
            .collect(),
        restore_ipv4_automatic,
    })
}

fn snapshot_adapter(adapter: &NetworkAdapter) -> Result<AdapterDnsBackup, String> {
    let ipv4 = read_interface_dns_settings(adapter.guid, AddressFamily::Ipv4)?;
    let ipv6 = read_interface_dns_settings(adapter.guid, AddressFamily::Ipv6)?;
    Ok(AdapterDnsBackup {
        interface_guid: adapter.guid_text.clone(),
        interface_name: adapter.name.clone(),
        ipv4_servers: ipv4.name_servers,
        ipv4_profile_servers: ipv4.profile_name_servers,
        ipv6_servers: ipv6.name_servers,
        ipv6_profile_servers: ipv6.profile_name_servers,
    })
}

fn backup_family_settings(adapter: &AdapterDnsBackup, family: AddressFamily) -> DnsFamilySettings {
    match family {
        AddressFamily::Ipv4 => DnsFamilySettings {
            name_servers: adapter.ipv4_servers.clone(),
            profile_name_servers: adapter.ipv4_profile_servers.clone(),
        },
        AddressFamily::Ipv6 => DnsFamilySettings {
            name_servers: adapter.ipv6_servers.clone(),
            profile_name_servers: adapter.ipv6_profile_servers.clone(),
        },
    }
}

fn backup_restores_ipv4_automatically(backup: &SystemDnsBackup) -> bool {
    backup
        .adapters
        .iter()
        .any(|adapter| adapter.ipv4_servers.is_none() && adapter.ipv4_profile_servers.is_none())
}

fn local_dns_settings(family: AddressFamily) -> DnsFamilySettings {
    DnsFamilySettings {
        name_servers: Some(vec![
            match family {
                AddressFamily::Ipv4 => IPV4_LOCAL_DNS,
                AddressFamily::Ipv6 => IPV6_LOCAL_DNS,
            }
            .to_string(),
        ]),
        profile_name_servers: None,
    }
}

fn fallback_dns_settings(
    preset: WindowsSystemDnsFallback,
    family: AddressFamily,
) -> DnsFamilySettings {
    let servers = match (preset, family) {
        (WindowsSystemDnsFallback::Automatic, _) => None,
        (WindowsSystemDnsFallback::Dns114, AddressFamily::Ipv4) => Some(&DNS114_IPV4[..]),
        (WindowsSystemDnsFallback::Dns114, AddressFamily::Ipv6) => None,
        (WindowsSystemDnsFallback::Google, AddressFamily::Ipv4) => Some(&GOOGLE_IPV4[..]),
        (WindowsSystemDnsFallback::Google, AddressFamily::Ipv6) => Some(&GOOGLE_IPV6[..]),
    };
    DnsFamilySettings {
        name_servers: servers
            .map(|servers| servers.iter().map(|server| (*server).to_string()).collect()),
        profile_name_servers: None,
    }
}

fn adapter_backup_contains_local_dns(adapter: &AdapterDnsBackup) -> bool {
    backup_family_settings(adapter, AddressFamily::Ipv4).contains(IPV4_LOCAL_DNS)
        || backup_family_settings(adapter, AddressFamily::Ipv6).contains(IPV6_LOCAL_DNS)
}

fn adapter_dns_in_effect(adapter: &AdapterDnsBackup) -> Result<bool, String> {
    let guid = parse_guid(&adapter.interface_guid)?;
    Ok(read_interface_dns_settings(guid, AddressFamily::Ipv4)?
        == local_dns_settings(AddressFamily::Ipv4)
        && read_interface_dns_settings(guid, AddressFamily::Ipv6)?
            == local_dns_settings(AddressFamily::Ipv6))
}

impl DnsFamilySettings {
    fn contains(&self, server: &str) -> bool {
        self.name_servers
            .as_deref()
            .into_iter()
            .flatten()
            .chain(self.profile_name_servers.as_deref().into_iter().flatten())
            .any(|candidate| candidate == server)
    }
}

fn rollback_changes(changes: &[AppliedChange]) -> Vec<String> {
    let mut errors = Vec::new();
    for change in changes.iter().rev() {
        if let Err(error) = set_dns_settings(change.guid, change.family, &change.original_settings)
        {
            errors.push(format!(
                "网卡“{}”的 {} DNS：{error}",
                change.name,
                family_name(change.family)
            ));
        }
    }
    errors
}

fn active_physical_adapters() -> Result<Vec<NetworkAdapter>, String> {
    let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
    let result = unsafe { GetIfTable2(&mut table) };
    if result != 0 {
        return Err(win32_error("枚举 Windows 网卡失败", result));
    }
    if table.is_null() {
        return Err("Windows 返回了空的网卡列表".to_string());
    }

    let adapters = unsafe {
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        rows.iter()
            .filter(|row| {
                row.OperStatus == IfOperStatusUp
                    && row.InterfaceAndOperStatusFlags._bitfield & HARDWARE_INTERFACE_FLAG != 0
                    && row.Type != IF_TYPE_SOFTWARE_LOOPBACK
                    && row.Type != IF_TYPE_TUNNEL
            })
            .map(|row| NetworkAdapter {
                guid: row.InterfaceGuid,
                guid_text: format_guid(row.InterfaceGuid),
                name: wide_array_to_string(&row.Alias),
            })
            .collect::<Vec<_>>()
    };
    unsafe {
        FreeMibTable(table.cast());
    }

    let mut seen = HashSet::new();
    let mut adapters = adapters
        .into_iter()
        .filter(|adapter| seen.insert(adapter.guid_text.clone()))
        .collect::<Vec<_>>();
    adapters.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(adapters)
}

fn read_interface_dns_settings(
    guid: GUID,
    family: AddressFamily,
) -> Result<DnsFamilySettings, String> {
    let api = load_dns_interface_api()?;
    let mut raw = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        // Windows 对 IPv6 使用同一读取接口，并通过此标志选择地址族。
        Flags: if matches!(family, AddressFamily::Ipv6) {
            u64::from(DNS_SETTING_IPV6)
        } else {
            0
        },
        ..Default::default()
    };
    let result = unsafe { (api.get)(guid, &mut raw) };
    if result != 0 {
        return Err(win32_error(
            &format!("读取 Windows {} DNS 设置失败", family_name(family)),
            result,
        ));
    }

    let settings = (|| {
        Ok(DnsFamilySettings {
            name_servers: parse_nameservers(&read_wide_string(raw.NameServer)?, family)?,
            profile_name_servers: parse_nameservers(
                &read_wide_string(raw.ProfileNameServer)?,
                family,
            )?,
        })
    })();
    unsafe {
        (api.free)(&mut raw);
    }
    settings
}

fn read_wide_string(value: *const u16) -> Result<String, String> {
    if value.is_null() {
        return Ok(String::new());
    }
    let mut length = 0;
    while length < MAX_DNS_SETTINGS_CHARS && unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    if length == MAX_DNS_SETTINGS_CHARS {
        return Err("Windows 返回的 DNS 设置字符串过长".to_string());
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .map_err(|_| "Windows 返回的 DNS 设置包含无效字符".to_string())
}

fn parse_nameservers(raw: &str, family: AddressFamily) -> Result<Option<Vec<String>>, String> {
    let servers = raw
        .split(|character: char| character == ',' || character == ';' || character.is_whitespace())
        .filter(|server| !server.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if servers.is_empty() {
        return Ok(None);
    }
    for server in &servers {
        let address = server
            .split_once('%')
            .map(|(address, _)| address)
            .unwrap_or(server)
            .parse::<IpAddr>()
            .map_err(|_| format!("DNS 服务器地址无效：{server}"))?;
        let valid_family = matches!(
            (family, address),
            (AddressFamily::Ipv4, IpAddr::V4(_)) | (AddressFamily::Ipv6, IpAddr::V6(_))
        );
        if !valid_family {
            return Err(format!(
                "{} DNS 中包含其他地址族：{server}",
                family_name(family)
            ));
        }
    }
    Ok(Some(servers))
}

fn set_dns_settings(
    guid: GUID,
    family: AddressFamily,
    desired: &DnsFamilySettings,
) -> Result<(), String> {
    let mut name_servers = wide(join_nameservers(desired.name_servers.as_deref()));
    let mut profile_name_servers = wide(join_nameservers(desired.profile_name_servers.as_deref()));
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(
            DNS_SETTING_NAMESERVER
                | DNS_SETTING_PROFILE_NAMESERVER
                | if matches!(family, AddressFamily::Ipv6) {
                    DNS_SETTING_IPV6
                } else {
                    0
                },
        ),
        // 空字符串会清除对应静态设置；两者同时为空时恢复自动获取 DNS。
        NameServer: name_servers.as_mut_ptr(),
        ProfileNameServer: profile_name_servers.as_mut_ptr(),
        ..Default::default()
    };

    let api = load_dns_interface_api()?;
    let result = unsafe { (api.set)(guid, &settings) };
    if result == 0 {
        Ok(())
    } else {
        Err(win32_error(
            &format!("调用 Windows {} DNS 接口失败", family_name(family)),
            result,
        ))
    }
}

fn join_nameservers(servers: Option<&[String]>) -> String {
    servers.map(|servers| servers.join(",")).unwrap_or_default()
}

fn load_dns_interface_api() -> Result<DnsInterfaceApi, String> {
    match DNS_INTERFACE_API.get_or_init(resolve_dns_interface_api) {
        Ok(api) => Ok(*api),
        Err(error) => Err(error.clone()),
    }
}

fn resolve_dns_interface_api() -> Result<DnsInterfaceApi, String> {
    let module_name = wide("iphlpapi.dll");
    // 该系统 DLL 保持加载到进程结束，确保缓存的函数指针始终有效。
    let module = unsafe { LoadLibraryW(module_name.as_ptr()) };
    if module.is_null() {
        return Err(format!(
            "加载 Windows DNS 配置组件失败：{}",
            std::io::Error::last_os_error()
        ));
    }
    let get = unsafe { GetProcAddress(module, c"GetInterfaceDnsSettings".as_ptr().cast()) }
        .ok_or_else(unsupported_windows_version_error)?;
    let set = unsafe { GetProcAddress(module, c"SetInterfaceDnsSettings".as_ptr().cast()) }
        .ok_or_else(unsupported_windows_version_error)?;
    let free = unsafe { GetProcAddress(module, c"FreeInterfaceDnsSettings".as_ptr().cast()) }
        .ok_or_else(unsupported_windows_version_error)?;
    Ok(DnsInterfaceApi {
        get: unsafe {
            std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(GUID, *mut DNS_INTERFACE_SETTINGS) -> u32,
            >(get)
        },
        set: unsafe {
            std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS) -> u32,
            >(set)
        },
        free: unsafe {
            std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(*mut DNS_INTERFACE_SETTINGS),
            >(free)
        },
    })
}

fn unsupported_windows_version_error() -> String {
    "当前 Windows 版本过低，系统 DNS 接管需要 Windows 10 2004 或更高版本".to_string()
}

fn read_backup(path: &Path) -> Result<SystemDnsBackup, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("读取系统 DNS 备份失败（{}）：{error}", path.display()))?;
    let backup: SystemDnsBackup = serde_json::from_str(&raw)
        .map_err(|error| format!("解析系统 DNS 备份失败（{}）：{error}", path.display()))?;
    validate_backup(backup)
}

fn validate_backup(backup: SystemDnsBackup) -> Result<SystemDnsBackup, String> {
    if backup.version != BACKUP_VERSION {
        return Err(format!("不支持的系统 DNS 备份版本：{}", backup.version));
    }
    if backup.adapters.is_empty() {
        return Err("系统 DNS 备份中没有网卡".to_string());
    }
    let mut guids = HashSet::new();
    for adapter in &backup.adapters {
        parse_guid(&adapter.interface_guid)?;
        if !guids.insert(adapter.interface_guid.to_ascii_uppercase()) {
            return Err(format!(
                "系统 DNS 备份中存在重复网卡：{}",
                adapter.interface_name
            ));
        }
        validate_saved_nameservers(adapter.ipv4_servers.as_deref(), AddressFamily::Ipv4)?;
        validate_saved_nameservers(adapter.ipv4_profile_servers.as_deref(), AddressFamily::Ipv4)?;
        validate_saved_nameservers(adapter.ipv6_servers.as_deref(), AddressFamily::Ipv6)?;
        validate_saved_nameservers(adapter.ipv6_profile_servers.as_deref(), AddressFamily::Ipv6)?;
    }
    Ok(backup)
}

fn validate_saved_nameservers(
    servers: Option<&[String]>,
    family: AddressFamily,
) -> Result<(), String> {
    let Some(servers) = servers else {
        return Ok(());
    };
    if servers.is_empty() {
        return Err(format!("{} DNS 备份为空", family_name(family)));
    }
    parse_nameservers(&servers.join(","), family).map(|_| ())
}

fn write_backup(default_data_dir: &Path, backup: &SystemDnsBackup) -> Result<(), String> {
    fs::create_dir_all(default_data_dir).map_err(|error| {
        format!(
            "创建系统 DNS 备份目录失败（{}）：{error}",
            default_data_dir.display()
        )
    })?;
    let path = backup_path(default_data_dir);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary =
        default_data_dir.join(format!("{BACKUP_FILE}.{}.{nonce}.tmp", std::process::id()));
    let raw = serde_json::to_vec_pretty(backup)
        .map_err(|error| format!("序列化系统 DNS 备份失败：{error}"))?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("创建系统 DNS 临时备份失败：{error}"))?;
        file.write_all(&raw)
            .map_err(|error| format!("写入系统 DNS 临时备份失败：{error}"))?;
        file.sync_all()
            .map_err(|error| format!("同步系统 DNS 临时备份失败：{error}"))?;
        drop(file);
        fs::rename(&temporary, &path).map_err(|error| format!("启用系统 DNS 备份失败：{error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn backup_path(default_data_dir: &Path) -> PathBuf {
    default_data_dir.join(BACKUP_FILE)
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_array_to_string(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

fn format_guid(guid: GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    )
}

fn parse_guid(value: &str) -> Result<GUID, String> {
    let compact = value
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .replace('-', "");
    if compact.len() != 32 {
        return Err(format!("系统 DNS 备份中的网卡 GUID 无效：{value}"));
    }
    let raw = u128::from_str_radix(&compact, 16)
        .map_err(|_| format!("系统 DNS 备份中的网卡 GUID 无效：{value}"))?;
    Ok(GUID::from_u128(raw))
}

fn family_name(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::Ipv4 => "IPv4",
        AddressFamily::Ipv6 => "IPv6",
    }
}

fn win32_error(context: &str, code: u32) -> String {
    format!(
        "{context}（错误码 {code}）：{}",
        std::io::Error::from_raw_os_error(code as i32)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_round_trip_matches_windows_registry_format() {
        let guid = GUID::from_u128(0x12345678_9abc_def0_1234_56789abcdef0);
        let formatted = format_guid(guid);
        assert_eq!(formatted, "{12345678-9ABC-DEF0-1234-56789ABCDEF0}");
        assert_eq!(format_guid(parse_guid(&formatted).unwrap()), formatted);
    }

    #[test]
    fn parses_static_and_automatic_dns_values() {
        assert_eq!(
            parse_nameservers("1.1.1.1, 8.8.8.8", AddressFamily::Ipv4).unwrap(),
            Some(vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()])
        );
        assert_eq!(
            parse_nameservers("fe80::1%12 ::1", AddressFamily::Ipv6).unwrap(),
            Some(vec!["fe80::1%12".to_string(), "::1".to_string()])
        );
        assert_eq!(parse_nameservers("  ", AddressFamily::Ipv4).unwrap(), None);
        assert!(parse_nameservers("::1", AddressFamily::Ipv4).is_err());
    }

    #[test]
    fn detects_local_dns_in_regular_or_profile_settings() {
        let regular = DnsFamilySettings {
            name_servers: Some(vec![IPV4_LOCAL_DNS.to_string()]),
            profile_name_servers: None,
        };
        let profile = DnsFamilySettings {
            name_servers: None,
            profile_name_servers: Some(vec![IPV6_LOCAL_DNS.to_string()]),
        };
        assert!(regular.contains(IPV4_LOCAL_DNS));
        assert!(profile.contains(IPV6_LOCAL_DNS));
        assert!(!profile.contains(IPV4_LOCAL_DNS));
    }

    #[test]
    fn validates_profile_dns_from_backup() {
        let backup = SystemDnsBackup {
            version: BACKUP_VERSION,
            adapters: vec![AdapterDnsBackup {
                interface_guid: "{12345678-9ABC-DEF0-1234-56789ABCDEF0}".to_string(),
                interface_name: "WLAN".to_string(),
                ipv4_servers: None,
                ipv4_profile_servers: Some(vec!["114.114.114.114".to_string()]),
                ipv6_servers: None,
                ipv6_profile_servers: Some(vec!["::1".to_string()]),
            }],
        };
        assert!(validate_backup(backup).is_ok());
    }

    #[test]
    fn builds_automatic_and_public_dns_fallbacks() {
        assert_eq!(
            fallback_dns_settings(WindowsSystemDnsFallback::Automatic, AddressFamily::Ipv4),
            DnsFamilySettings::default()
        );
        assert_eq!(
            fallback_dns_settings(WindowsSystemDnsFallback::Dns114, AddressFamily::Ipv4)
                .name_servers,
            Some(DNS114_IPV4.map(str::to_string).to_vec())
        );
        assert_eq!(
            fallback_dns_settings(WindowsSystemDnsFallback::Dns114, AddressFamily::Ipv6),
            DnsFamilySettings::default()
        );
        assert_eq!(
            fallback_dns_settings(WindowsSystemDnsFallback::Google, AddressFamily::Ipv6)
                .name_servers,
            Some(GOOGLE_IPV6.map(str::to_string).to_vec())
        );
    }
}
