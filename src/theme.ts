import { getCurrentWindow } from "@tauri-apps/api/window";

export type ThemePreference = "system" | "light" | "dark";

const STORAGE_KEY = "dnsblackhole.theme";
const THEME_VALUES: ThemePreference[] = ["system", "light", "dark"];

/** 系统深色媒体查询。构造一次复用，避免每次切换都新建监听源。 */
const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");

let current: ThemePreference = readStoredPreference();

function readStoredPreference(): ThemePreference {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored && (THEME_VALUES as string[]).includes(stored)) {
      return stored as ThemePreference;
    }
  } catch (error) {
    // 隐私模式或站点数据被禁用时读取会抛错，跟随系统即可。
    console.warn("读取主题偏好失败，改为跟随系统", error);
  }
  return "system";
}

export function getThemePreference(): ThemePreference {
  return current;
}

/** 当前实际生效的明暗，供需要按主题取值的地方使用。 */
export function resolvedTheme(): "light" | "dark" {
  if (current !== "system") {
    return current;
  }
  return darkQuery.matches ? "dark" : "light";
}

/**
 * 应用主题。
 *
 * 跟随系统时不写 `data-theme`，交给 CSS 的 `prefers-color-scheme` 分支处理；
 * 显式选择时写上属性，优先级高于系统偏好。
 */
export function applyTheme(preference: ThemePreference = current): void {
  current = preference;
  const root = document.documentElement;
  if (preference === "system") {
    root.removeAttribute("data-theme");
  } else {
    root.dataset.theme = preference;
  }
  syncWindowTheme();
}

export function setThemePreference(preference: ThemePreference): void {
  applyTheme(preference);
  try {
    window.localStorage.setItem(STORAGE_KEY, preference);
  } catch (error) {
    // 存不下也不影响本次会话的显示效果。
    console.warn("保存主题偏好失败", error);
  }
}

/**
 * 同步 Tauri 窗口主题，让标题栏、右键菜单和滚动条跟随应用配色。
 * 传 null 表示交还给系统。
 */
function syncWindowTheme(): void {
  const target = current === "system" ? null : current;
  try {
    void getCurrentWindow()
      .setTheme(target)
      .catch((error: unknown) => {
        console.warn("同步窗口主题失败", error);
      });
  } catch (error) {
    // 在纯浏览器里（本地调试样式）没有 Tauri 运行时，跳过窗口同步即可。
    console.warn("当前环境没有 Tauri 窗口，跳过主题同步", error);
  }
}

/** 跟随系统时，系统配色变化要立刻反映到窗口主题上。 */
export function watchSystemTheme(onChange?: () => void): void {
  darkQuery.addEventListener("change", () => {
    if (current !== "system") {
      return;
    }
    syncWindowTheme();
    onChange?.();
  });
}
