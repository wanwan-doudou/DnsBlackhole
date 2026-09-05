import { exportConfigFile, exportDiagnosticFile, importConfigFile } from "./api";
import type { AppConfig, RuntimeStatus } from "./types";
import { t } from "./i18n";

function dateStamp(): string {
  const now = new Date();
  return [now.getFullYear(), now.getMonth() + 1, now.getDate()]
    .map((value, index) => String(value).padStart(index === 0 ? 4 : 2, "0"))
    .join("");
}

export async function exportConfigBackup(config: AppConfig): Promise<boolean> {
  const { save } = await import("@tauri-apps/plugin-dialog");
  const path = await save({
    title: t("导出 DnsBlackhole 配置"),
    defaultPath: `DnsBlackhole-config-${dateStamp()}.json`,
    filters: [{ name: t("JSON 配置"), extensions: ["json"] }],
  });
  if (!path) {
    return false;
  }
  await exportConfigFile(path, config);
  return true;
}

export async function chooseConfigBackup(): Promise<AppConfig | null> {
  const { open } = await import("@tauri-apps/plugin-dialog");
  const path = await open({
    title: t("选择 DnsBlackhole 配置备份"),
    multiple: false,
    directory: false,
    filters: [{ name: t("JSON 配置"), extensions: ["json"] }],
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
  const { save } = await import("@tauri-apps/plugin-dialog");
  const path = await save({
    title: t("导出脱敏诊断信息"),
    defaultPath: `DnsBlackhole-diagnostic-${dateStamp()}.json`,
    filters: [{ name: t("JSON 诊断信息"), extensions: ["json"] }],
  });
  if (!path) {
    return false;
  }
  await exportDiagnosticFile(path, config, status);
  return true;
}
