import { describe, expect, it } from "vitest";
import {
  findClientPolicyGroup,
  findEffectiveClientPolicyRule,
  findClientPolicyRule,
  expandPolicyWeekdays,
  resolveEffectiveClientPolicy,
  selectedWeekdaysValue,
  upsertClientPolicyGroup,
  upsertClientPolicyRule,
  validateIpOrCidr,
} from "./client-policy-form";

describe("client policy form helpers", () => {
  it("validates IPv4, IPv6 and CIDR selectors", () => {
    expect(validateIpOrCidr("192.168.1.23")).toBe(true);
    expect(validateIpOrCidr("192.168.1.0/24")).toBe(true);
    expect(validateIpOrCidr("fd00::1/64")).toBe(true);
    expect(validateIpOrCidr("192.168.1.999")).toBe(false);
    expect(validateIpOrCidr("fd00::1/129")).toBe(false);
  });

  it("upserts rules without removing comments or advanced entries", () => {
    const original = "# 客厅\n192.168.1.10 => filter\n10.0.0.0/8 => bypass";
    const next = upsertClientPolicyRule(original, {
      network: "192.168.1.10",
      profile: "family",
      schedule: { days: "mon,tue,wed,thu,fri", start: "20:00", end: "07:00" },
    });
    expect(next).toContain("# 客厅");
    expect(next).toContain("192.168.1.10 => family @ mon,tue,wed,thu,fri 20:00-07:00");
    expect(next).toContain("10.0.0.0/8 => bypass");
    expect(findClientPolicyRule(next, "192.168.1.10")?.profile).toBe("family");
  });

  it("builds searchable custom service groups", () => {
    const next = upsertClientPolicyGroup("work => bypass", {
      name: "study",
      mode: "filter",
      safeSearch: true,
      services: ["youtube", "tiktok"],
    });
    expect(next).toContain("study => filter, safe_search, block:tiktok|youtube");
    expect(findClientPolicyGroup(next, "study")).toEqual({
      name: "study",
      mode: "filter",
      safeSearch: true,
      services: ["tiktok", "youtube"],
    });
  });

  it("resolves longest prefixes and overnight schedules", () => {
    const rules = [
      "192.168.1.0/24 => bypass",
      "192.168.1.20 => family @ mon-fri 20:00-07:00",
    ].join("\n");
    expect(resolveEffectiveClientPolicy("192.168.1.20", rules, new Date(2026, 8, 7, 21))).toMatchObject({
      profile: "family",
      source: "192.168.1.20",
      scheduled: true,
    });
    expect(resolveEffectiveClientPolicy("192.168.1.20", rules, new Date(2026, 8, 8, 6))).toMatchObject({
      profile: "family",
    });
    expect(resolveEffectiveClientPolicy("192.168.1.20", rules, new Date(2026, 8, 8, 12))).toMatchObject({
      profile: "bypass",
      source: "192.168.1.0/24",
    });
    expect(findEffectiveClientPolicyRule(
      rules,
      "192.168.1.20",
      new Date(2026, 8, 8, 12),
    )?.network).toBe("192.168.1.0/24");
  });

  it("uses daily shorthand and rejects empty schedules", () => {
    expect(selectedWeekdaysValue(["mon", "tue", "wed", "thu", "fri", "sat", "sun"])).toBe("daily");
    expect(expandPolicyWeekdays("mon-fri")).toEqual(["mon", "tue", "wed", "thu", "fri"]);
    expect(expandPolicyWeekdays("fri-mon")).toEqual(["mon", "fri", "sat", "sun"]);
    expect(() => selectedWeekdaysValue([])).toThrow("至少需要选择一天");
  });
});
