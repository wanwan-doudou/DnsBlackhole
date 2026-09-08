import { enUS } from "./en-US";

export type Locale = "zh-CN" | "en-US";
export type LocalePreference = Locale | "system";

const STORAGE_KEY = "dnsblackhole.locale";
const SUPPORTED: Locale[] = ["zh-CN", "en-US"];

/**
 * 字典以中文原文为键（gettext 风格）。
 *
 * 这样中文不需要字典、也永远不会漏词；只有英文需要维护一份映射。
 * 代价是改动中文文案时要同步改英文字典的键——比维护上千个人造 key 更不容易出错。
 */
const DICTIONARIES: Record<Locale, Record<string, string>> = {
  "zh-CN": {},
  "en-US": enUS,
};

function detectSystemLocale(): Locale {
  const languages = navigator.languages?.length ? navigator.languages : [navigator.language];
  for (const tag of languages) {
    const lower = (tag || "").toLowerCase();
    if (lower.startsWith("zh")) {
      return "zh-CN";
    }
    if (lower.startsWith("en")) {
      return "en-US";
    }
  }
  // 既不是中文也不是英文的系统，用英文比用中文更可能被看懂。
  return "en-US";
}

function readStoredPreference(): LocalePreference {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "system" || (SUPPORTED as string[]).includes(stored ?? "")) {
      return stored as LocalePreference;
    }
  } catch (error) {
    console.warn("读取语言偏好失败，改为跟随系统", error);
  }
  return "system";
}

let preference: LocalePreference = readStoredPreference();
let active: Locale = preference === "system" ? detectSystemLocale() : preference;
if (typeof document !== "undefined") {
  document.documentElement.lang = active;
}

export function getLocalePreference(): LocalePreference {
  return preference;
}

export function getLocale(): Locale {
  return active;
}

/** 供日期、数字格式化使用的 BCP 47 标签。 */
export function getIntlLocale(): string {
  return active;
}

/**
 * 翻译。`params` 用 `{name}` 占位符替换。
 *
 * 找不到译文时回退到原文（也就是中文），保证界面不会出现空白或 key。
 */
export function t(text: string, params?: Record<string, string | number>): string {
  const dictionary = DICTIONARIES[active];
  let result = dictionary[text] ?? text;
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      result = result.split(`{${key}}`).join(String(value));
    }
  }
  return result;
}

/**
 * 切换语言。
 *
 * 模板是启动时一次性渲染并绑定事件的，没有可靠的整体重渲染入口，
 * 因此换语言直接重载页面——配置都在后端，重载不会丢数据。
 *
 * 但实际语种没变时不重载：例如跟随系统本来就解析成中文，用户又手动选了简体中文，
 * 界面文案一个字都不会变，重载只会白闪一下。
 *
 * `beforeReload` 只在确实要重载时调用，供调用方暂存需要跨重载保留的状态。
 */
export function setLocalePreference(next: LocalePreference, beforeReload?: () => void): void {
  const nextActive = next === "system" ? detectSystemLocale() : next;
  const localeChanged = nextActive !== active;
  preference = next;
  active = nextActive;
  try {
    window.localStorage.setItem(STORAGE_KEY, next);
  } catch (error) {
    console.warn("保存语言偏好失败", error);
  }
  if (!localeChanged) {
    return;
  }
  beforeReload?.();
  window.location.reload();
}

export function localeLabel(locale: Locale): string {
  return locale === "zh-CN" ? "简体中文" : "English";
}
