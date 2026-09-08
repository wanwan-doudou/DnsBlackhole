import { describe, expect, it } from "vitest";
import { mapBackendConfigError, validateConfigDraft } from "./config-validation";
import type { AppConfig } from "./types";

const validConfig = {
  listen_host: "0.0.0.0",
  listen_port: 53,
  listen_ipv6: true,
  listen_ipv6_host: "::",
  rate_limit_per_second: 2000,
  dns_cache_enabled: true,
  dns_cache_size: 4 * 1024 * 1024,
  dns_cache_min_ttl: 0,
  dns_cache_max_ttl: 86400,
  dns_cache_optimistic_max_stale_seconds: 3600,
  dns_cache_prefetch_hit_threshold: 10,
  runtime_watchdog_interval_seconds: 30,
  blocking_response_ttl: 60,
  monitoring_api_enabled: false,
  monitoring_api_listen_host: "127.0.0.1",
  monitoring_api_port: 8080,
} as AppConfig;

describe("validateConfigDraft", () => {
  it("接受常规 IPv4/IPv6 双监听配置", () => {
    expect(validateConfigDraft(validConfig)).toEqual([]);
  });

  it("定位地址、端口和缓存范围错误", () => {
    const issues = validateConfigDraft({
      ...validConfig,
      listen_host: "localhost",
      listen_port: 0,
      listen_ipv6_host: "127.0.0.1",
      dns_cache_min_ttl: 100,
      dns_cache_max_ttl: 20,
    });
    expect(issues.map((issue) => issue.fieldId)).toEqual([
      "listen_host",
      "listen_port",
      "listen_ipv6_host",
      "dns_cache_min_ttl",
    ]);
  });

  it("识别监控端口与 DNS 端口冲突", () => {
    const issues = validateConfigDraft({
      ...validConfig,
      monitoring_api_enabled: true,
      monitoring_api_port: 53,
    });
    expect(issues).toContainEqual({
      fieldId: "monitoring_api_port",
      view: "settings",
      code: "monitoring_port_conflict",
    });
  });
});

describe("mapBackendConfigError", () => {
  it("把后端策略错误映射到高级策略编辑器", () => {
    expect(mapBackendConfigError("客户端过滤策略第 2 行引用错误")).toEqual({
      fieldId: "client_filtering_rules",
      view: "security",
    });
  });

  it("把 Windows IPv6 监听失败映射到 IPv6 地址字段", () => {
    expect(
      mapBackendConfigError(
        "新配置应用失败：监听 UDP [2001:db8::1]:53 失败：在其上下文中，该请求的地址无效。 (os error 10049)；已恢复原配置及服务状态",
      ),
    ).toEqual({ fieldId: "listen_ipv6_host", view: "dns" });
  });

  it("区分 IPv4 地址不可用和端口占用", () => {
    expect(
      mapBackendConfigError(
        "监听 TCP 192.0.2.1:53 失败：在其上下文中，该请求的地址无效。 (os error 10049)",
      ),
    ).toEqual({ fieldId: "listen_host", view: "dns" });
    expect(
      mapBackendConfigError(
        "监听 UDP 0.0.0.0:53 失败：通常每个套接字地址只允许使用一次。 (os error 10048)",
      ),
    ).toEqual({ fieldId: "listen_port", view: "dns" });
  });
});
