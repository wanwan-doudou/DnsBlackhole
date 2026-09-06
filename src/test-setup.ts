// 测试环境把界面语言钉死为简体中文。
//
// i18n 在模块加载时就解析出当前语种：没有存储偏好时按 navigator 推断系统语言，
// 于是断言中文原文的用例在英文 runner 上会拿到英文译文。这里在任何被测模块
// 导入之前写好偏好，让断言只取决于代码，而不是跑测试那台机器的系统语言。
const LOCALE_STORAGE_KEY = "dnsblackhole.locale";

const localeStorage: Storage = {
  length: 1,
  key: (index) => (index === 0 ? LOCALE_STORAGE_KEY : null),
  getItem: (key) => (key === LOCALE_STORAGE_KEY ? "zh-CN" : null),
  setItem: () => {},
  removeItem: () => {},
  clear: () => {},
};

globalThis.window = { localStorage: localeStorage } as unknown as Window & typeof globalThis;
