import { open, save } from "@tauri-apps/plugin-dialog";

import { exportConfigFile, exportDiagnosticFile, importConfigFile } from "./api";
import type { AppConfig, RuntimeStatus } from "./types";

function dateStamp(): string {
  const now = new Date();
  return [now.getFullYear(), now.getMonth() + 1, now.getDate()]
    .map((value, index) => String(value).padStart(index === 0 ? 4 : 2, "0"))
    .join("");
}

export async function exportConfigBackup(config: AppConfig): Promise<boolean> {
  const path = await save({
    title: "导出 DnsBlackhole 配置",
    defaultPath: `DnsBlackhole-config-${dateStamp()}.json`,
    filters: [{ name: "JSON 配置", extensions: ["json"] }],
  });
  if (!path) {
    return false;
  }
  await exportConfigFile(path, config);
  return true;
}

export async function chooseConfigBackup(): Promise<AppConfig | null> {
  const path = await open({
    title: "选择 DnsBlackhole 配置备份",
    multiple: false,
    directory: false,
    filters: [{ name: "JSON 配置", extensions: ["json"] }],
  });
  if (!path || Array.isArray(path)) {
    return null;
  }
  return importConfigFile(path);
}

export async function exportSanitizedDiagnostics(
  config: AppConfig,
  status: RuntimeStatus | null,
): Promise<boolean> {
  const path = await save({
    title: "导出脱敏诊断信息",
    defaultPath: `DnsBlackhole-diagnostic-${dateStamp()}.json`,
    filters: [{ name: "JSON 诊断信息", extensions: ["json"] }],
  });
  if (!path) {
    return false;
  }
  await exportDiagnosticFile(path, config, status);
  return true;
}
