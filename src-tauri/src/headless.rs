use std::{
    ffi::OsString,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use serde_json::{Value, json};

use crate::{
    config::AppConfig,
    config_transfer,
    privileged_bridge::{ServiceClient, linux_system_dns, run_linux_daemon},
};

const DEFAULT_DATA_DIR: &str = "/var/lib/dnsblackhole";
const SYSTEM_DNS_USAGE: &str = "用法：dnsblackhole-service system-dns <status|takeover>\n\
      dnsblackhole-service system-dns restore [--offline [--keep-desired] [--data-dir <路径>]]";

pub fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), String> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "serve".to_string());
    let remaining = arguments.collect::<Vec<_>>();

    match command.as_str() {
        "serve" => serve(&remaining),
        "status" => status(&remaining),
        "healthcheck" => healthcheck(&remaining),
        "start" => call_without_params("start_dns", &remaining),
        "stop" => call_without_params("stop_dns", &remaining),
        "filters" => filters(&remaining),
        "config" => config(&remaining),
        "system-dns" => system_dns(&remaining),
        "--help" | "-h" | "help" => {
            print_help();
            Ok(())
        }
        "--version" | "-V" => {
            println!("dnsblackhole-service {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(format!("未知命令：{command}\n\n{}", help_text())),
    }
}

fn serve(arguments: &[OsString]) -> Result<(), String> {
    let mut data_dir = PathBuf::from(DEFAULT_DATA_DIR);
    let mut bootstrap_config = None;
    #[cfg(feature = "web-admin")]
    let mut web_listen = Some("0.0.0.0:3000".to_string());
    #[cfg(not(feature = "web-admin"))]
    let web_listen: Option<String> = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--data-dir") => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| "--data-dir 缺少路径参数".to_string())?;
                data_dir = PathBuf::from(value);
            }
            Some("--bootstrap-config") => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| "--bootstrap-config 缺少路径参数".to_string())?;
                bootstrap_config = Some(PathBuf::from(value));
            }
            Some("--web-listen") => {
                index += 1;
                let value = arguments
                    .get(index)
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| "--web-listen 缺少地址参数".to_string())?;
                #[cfg(feature = "web-admin")]
                {
                    web_listen = Some(value.to_string());
                }
                #[cfg(not(feature = "web-admin"))]
                {
                    let _ = value;
                    return Err("当前构建未启用 web-admin feature".to_string());
                }
            }
            Some(argument) => return Err(format!("serve 不支持参数：{argument}")),
            None => return Err("serve 参数必须是有效文本".to_string()),
        }
        index += 1;
    }
    run_linux_daemon(data_dir, bootstrap_config, web_listen)
}

fn status(arguments: &[OsString]) -> Result<(), String> {
    let json_output = match arguments {
        [] => false,
        [argument] if argument == "--json" => true,
        _ => return Err("用法：dnsblackhole-service status [--json]".to_string()),
    };
    let status: Value = ServiceClient::call(
        "get_status",
        &json!({
            "forceLogStats": false,
            "includeLogStats": false,
            "statisticsHours": null
        }),
    )?;
    let config: Value = ServiceClient::call("get_config", &json!({}))?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&status)
                .map_err(|error| format!("序列化状态失败：{error}"))?
        );
    } else {
        let running = status
            .get("running")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let enabled = config
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        println!("服务：已连接");
        println!("DNS：{}", if running { "运行中" } else { "已停止" });
        println!("自动运行：{}", if enabled { "启用" } else { "关闭" });
        if let Some(error) = status.get("error").and_then(Value::as_str)
            && !error.is_empty()
        {
            println!("最近错误：{error}");
        }
    }
    Ok(())
}

fn healthcheck(arguments: &[OsString]) -> Result<(), String> {
    ensure_no_arguments("healthcheck", arguments)?;
    let status: Value = ServiceClient::call(
        "get_status",
        &json!({
            "forceLogStats": false,
            "includeLogStats": false,
            "statisticsHours": null
        }),
    )?;
    if status.get("running").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err("DNS runtime 未运行".to_string())
    }
}

fn call_without_params(method: &str, arguments: &[OsString]) -> Result<(), String> {
    ensure_no_arguments(method, arguments)?;
    let result: Value = ServiceClient::call(method, &json!({}))?;
    print_json(&result)
}

fn filters(arguments: &[OsString]) -> Result<(), String> {
    if arguments.len() != 1 || arguments[0] != "update" {
        return Err("用法：dnsblackhole-service filters update".to_string());
    }
    let config: Value = ServiceClient::call("get_config", &json!({}))?;
    let result: Value = ServiceClient::call("update_filters", &json!({ "config": config }))?;
    print_json(&result)
}

fn config(arguments: &[OsString]) -> Result<(), String> {
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        return Err("用法：dnsblackhole-service config <validate|export|apply> ...".to_string());
    };
    match (command, arguments.get(1), arguments.len()) {
        ("validate", Some(path), 2) => {
            read_and_validate_config(Path::new(path))?;
            println!("配置有效");
            Ok(())
        }
        ("export", Some(path), 2) => export_config(Path::new(path)),
        ("apply", Some(path), 2) => {
            let config = read_and_validate_config(Path::new(path))?;
            let result: Value = ServiceClient::call("save_config", &json!({ "config": config }))?;
            print_json(&result)
        }
        _ => Err("用法：dnsblackhole-service config <validate|export|apply> <文件|->".to_string()),
    }
}

fn read_and_validate_config(path: &Path) -> Result<AppConfig, String> {
    if path == Path::new("-") {
        return Err("首版暂不从 stdin 导入配置，请传入本地 JSON 文件".to_string());
    }
    config_transfer::read_imported_config_file(path)
}

fn export_config(path: &Path) -> Result<(), String> {
    let config: Value = ServiceClient::call("get_config", &json!({}))?;
    let content =
        serde_json::to_vec_pretty(&config).map_err(|error| format!("序列化配置失败：{error}"))?;
    if path == Path::new("-") {
        io::stdout()
            .write_all(&content)
            .and_then(|_| io::stdout().write_all(b"\n"))
            .map_err(|error| format!("写入标准输出失败：{error}"))
    } else {
        fs::write(path, content).map_err(|error| format!("写入配置文件失败：{error}"))
    }
}

fn system_dns(arguments: &[OsString]) -> Result<(), String> {
    let operation = arguments
        .first()
        .and_then(|value| value.to_str())
        .ok_or_else(|| SYSTEM_DNS_USAGE.to_string())?;
    match operation {
        "status" if arguments.len() == 1 => {
            let result: Value = ServiceClient::call("get_linux_system_dns_status", &json!({}))?;
            print_json(&result)
        }
        "takeover" if arguments.len() == 1 => {
            let result: Value = ServiceClient::call("take_over_linux_system_dns", &json!({}))?;
            print_json(&result)
        }
        "restore" => system_dns_restore(&arguments[1..]),
        _ => Err(SYSTEM_DNS_USAGE.to_string()),
    }
}

/// 恢复分两条路径：默认经运行中的服务执行在线事务；`--offline` 是 daemon 不可用时的
/// root 本地救援路径，供维护脚本和人工恢复使用，仍复用同一套快照与所有权校验。
/// 升级停止用 `--keep-desired` 保留接管意图，卸载与人工恢复必须清除它。
fn system_dns_restore(arguments: &[OsString]) -> Result<(), String> {
    let mut offline = false;
    let mut keep_desired = false;
    let mut data_dir: Option<PathBuf> = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--offline") => offline = true,
            Some("--keep-desired") => keep_desired = true,
            Some("--data-dir") => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| "--data-dir 缺少路径参数".to_string())?;
                data_dir = Some(PathBuf::from(value));
            }
            Some(argument) => {
                return Err(format!("system-dns restore 不支持参数：{argument}"));
            }
            None => return Err("system-dns restore 参数必须是有效文本".to_string()),
        }
        index += 1;
    }

    if !offline {
        if keep_desired {
            return Err("--keep-desired 只能与 --offline 一起使用".to_string());
        }
        if data_dir.is_some() {
            return Err(
                "--data-dir 只能与 --offline 一起使用；在线恢复由运行中的服务决定数据目录"
                    .to_string(),
            );
        }
        let result: Value = ServiceClient::call("restore_linux_system_dns", &json!({}))?;
        return print_json(&result);
    }

    let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
    let status = linux_system_dns::restore_system_dns_offline(&data_dir, keep_desired)?;
    let result = serde_json::to_value(status)
        .map_err(|error| format!("序列化系统 DNS 状态失败：{error}"))?;
    print_json(&result)
}

fn ensure_no_arguments(command: &str, arguments: &[OsString]) -> Result<(), String> {
    if arguments.is_empty() {
        Ok(())
    } else {
        Err(format!("{command} 不接受额外参数"))
    }
}

fn print_json(value: &Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| format!("序列化结果失败：{error}"))?
    );
    Ok(())
}

fn print_help() {
    print!("{}", help_text());
}

fn help_text() -> &'static str {
    "DnsBlackhole headless 服务与本机管理 CLI\n\n\
用法：\n  dnsblackhole-service serve [--data-dir <路径>] [--bootstrap-config <文件>] [--web-listen <地址:端口>]\n  dnsblackhole-service status [--json]\n  dnsblackhole-service healthcheck\n  dnsblackhole-service config <validate|export|apply> <文件|->\n  dnsblackhole-service start|stop\n  dnsblackhole-service filters update\n  dnsblackhole-service system-dns <status|takeover>\n  dnsblackhole-service system-dns restore [--offline [--keep-desired] [--data-dir <路径>]]\n\n\
注意：system-dns restore --offline 仅在后台服务无法连接时使用，需要 root 且要求 DnsBlackhole 已释放 53 端口。\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn validates_config_without_writing_database() {
        let path = std::env::temp_dir().join(format!(
            "dnsblackhole-headless-config-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("系统时间应有效")
                .as_nanos()
        ));
        fs::write(
            &path,
            serde_json::to_vec(&AppConfig::default()).expect("默认配置应可序列化"),
        )
        .expect("应能写入临时配置");
        read_and_validate_config(&path).expect("默认配置应通过校验");
        fs::remove_file(path).expect("应能清理临时配置");
    }

    #[test]
    fn rejects_oversized_config_before_reading_content() {
        let path = std::env::temp_dir().join(format!(
            "dnsblackhole-headless-large-{}.json",
            std::process::id()
        ));
        let file = fs::File::create(&path).expect("应能创建临时配置");
        file.set_len(config_transfer::MAX_IMPORT_BYTES + 1)
            .expect("应能扩展临时配置");
        let error = read_and_validate_config(&path).expect_err("超大配置应被拒绝");
        assert!(error.contains("4 MiB"));
        fs::remove_file(path).expect("应能清理临时配置");
    }
}
