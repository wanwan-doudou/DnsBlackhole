export const CLIENT_POLICY_SERVICE_KEYS = [
  "youtube",
  "tiktok",
  "instagram",
  "facebook",
  "x",
  "reddit",
  "twitch",
  "discord",
  "steam",
  "epic",
  "roblox",
] as const;

export const CLIENT_POLICY_WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;

export type ClientPolicyService = (typeof CLIENT_POLICY_SERVICE_KEYS)[number];
export type ClientPolicyWeekday = (typeof CLIENT_POLICY_WEEKDAYS)[number];

export type ClientPolicySchedule = {
  days: string;
  start: string;
  end: string;
};

export type ClientPolicyRule = {
  network: string;
  profile: string;
  schedule: ClientPolicySchedule | null;
};

export type ClientPolicyGroup = {
  name: string;
  mode: "filter" | "bypass";
  safeSearch: boolean;
  services: ClientPolicyService[];
};

export type EffectiveClientPolicy = {
  profile: string;
  source: string | null;
  scheduled: boolean;
};

type ParsedIp = {
  family: 4 | 6;
  value: bigint;
  bits: 32 | 128;
};

type ParsedNetwork = ParsedIp & {
  prefix: number;
};

export function validateIpOrCidr(value: string): boolean {
  return parseNetwork(value.trim()) !== null;
}

export function validateIpAddress(value: string): boolean {
  const normalized = value.trim();
  return !normalized.includes("/") && parseIp(normalized) !== null;
}

export function validateIpv4Address(value: string): boolean {
  return parseIpv4(value.trim()) !== null;
}

export function validateIpv6Address(value: string): boolean {
  return parseIpv6(value.trim()) !== null;
}

export function validatePolicyName(value: string): boolean {
  return /^[a-z0-9_-]{1,32}$/i.test(value.trim());
}

export function parseClientPolicyRules(value: string): ClientPolicyRule[] {
  return value
    .split("\n")
    .map((line) => parseClientPolicyRuleLine(line))
    .filter((rule): rule is ClientPolicyRule => rule !== null);
}

export function parseClientPolicyGroups(value: string): ClientPolicyGroup[] {
  const groups: ClientPolicyGroup[] = [];
  for (const line of value.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("!")) {
      continue;
    }
    const pair = trimmed.split("=>");
    if (pair.length !== 2) {
      continue;
    }
    const name = pair[0].trim().toLowerCase();
    if (!validatePolicyName(name)) {
      continue;
    }
    let mode: "filter" | "bypass" = "filter";
    let safeSearch = false;
    const services = new Set<ClientPolicyService>();
    for (const rawOption of pair[1].split(",")) {
      const option = rawOption.trim().toLowerCase();
      if (option === "bypass") {
        mode = "bypass";
      } else if (option === "safe_search") {
        safeSearch = true;
      } else if (option.startsWith("block:")) {
        for (const service of option.slice(6).split("|")) {
          if (isClientPolicyService(service)) {
            services.add(service);
          }
        }
      }
    }
    groups.push({ name, mode, safeSearch, services: [...services].sort() });
  }
  return groups;
}

export function findClientPolicyRule(value: string, network: string): ClientPolicyRule | null {
  const normalized = network.trim().toLowerCase();
  const rules = parseClientPolicyRules(value);
  for (let index = rules.length - 1; index >= 0; index -= 1) {
    if (rules[index].network.toLowerCase() === normalized) {
      return rules[index];
    }
  }
  return null;
}

export function findClientPolicyGroup(value: string, name: string): ClientPolicyGroup | null {
  const normalized = name.trim().toLowerCase();
  const groups = parseClientPolicyGroups(value);
  for (let index = groups.length - 1; index >= 0; index -= 1) {
    if (groups[index].name === normalized) {
      return groups[index];
    }
  }
  return null;
}

export function upsertClientPolicyRule(
  value: string,
  rule: ClientPolicyRule,
): string {
  if (!validateIpOrCidr(rule.network)) {
    throw new Error("客户端或网段必须是有效的 IP 或 CIDR");
  }
  if (!validatePolicyName(rule.profile)) {
    throw new Error("策略组名称只能包含字母、数字、短横线或下划线，且不超过 32 个字符");
  }
  if (rule.schedule) {
    validateSchedule(rule.schedule);
  }
  const normalizedNetwork = rule.network.trim();
  const normalizedProfile = rule.profile.trim().toLowerCase();
  const schedule = rule.schedule
    ? ` @ ${rule.schedule.days} ${rule.schedule.start}-${rule.schedule.end}`
    : "";
  const nextLine = `${normalizedNetwork} => ${normalizedProfile}${schedule}`;
  return upsertLine(value, nextLine, (line) => {
    const parsed = parseClientPolicyRuleLine(line);
    return parsed?.network.toLowerCase() === normalizedNetwork.toLowerCase();
  });
}

export function upsertClientPolicyGroup(value: string, group: ClientPolicyGroup): string {
  const name = group.name.trim().toLowerCase();
  if (!validatePolicyName(name) || ["filter", "bypass", "family"].includes(name)) {
    throw new Error("自定义策略组名称无效或使用了保留名称");
  }
  const options: string[] = [group.mode];
  if (group.safeSearch) {
    options.push("safe_search");
  }
  const services = [...new Set(group.services)].filter(isClientPolicyService).sort();
  if (services.length > 0) {
    options.push(`block:${services.join("|")}`);
  }
  const nextLine = `${name} => ${options.join(", ")}`;
  return upsertLine(value, nextLine, (line) => {
    const pair = line.split("=>");
    return pair.length === 2 && pair[0].trim().toLowerCase() === name;
  });
}

export function selectedWeekdaysValue(days: readonly ClientPolicyWeekday[]): string {
  const selected = CLIENT_POLICY_WEEKDAYS.filter((day) => days.includes(day));
  if (selected.length === CLIENT_POLICY_WEEKDAYS.length) {
    return "daily";
  }
  if (selected.length === 0) {
    throw new Error("计划至少需要选择一天");
  }
  return selected.join(",");
}

export function resolveEffectiveClientPolicy(
  client: string,
  rulesValue: string,
  now = new Date(),
): EffectiveClientPolicy {
  const address = parseIp(client.trim());
  if (!address) {
    return { profile: "filter", source: null, scheduled: false };
  }
  const weekday = (now.getDay() + 6) % 7;
  const minute = now.getHours() * 60 + now.getMinutes();
  let matched: { rule: ClientPolicyRule; prefix: number } | null = null;
  for (const rule of parseClientPolicyRules(rulesValue)) {
    const network = parseNetwork(rule.network);
    if (
      !network ||
      !networkContains(network, address) ||
      (rule.schedule && !scheduleIsActive(rule.schedule, weekday, minute))
    ) {
      continue;
    }
    if (!matched || network.prefix >= matched.prefix) {
      matched = { rule, prefix: network.prefix };
    }
  }
  return matched
    ? {
        profile: matched.rule.profile,
        source: matched.rule.network,
        scheduled: matched.rule.schedule !== null,
      }
    : { profile: "filter", source: null, scheduled: false };
}

export function findEffectiveClientPolicyRule(
  value: string,
  client: string,
  now = new Date(),
): ClientPolicyRule | null {
  const effective = resolveEffectiveClientPolicy(client, value, now);
  return effective.source ? findClientPolicyRule(value, effective.source) : null;
}

function parseClientPolicyRuleLine(line: string): ClientPolicyRule | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("!")) {
    return null;
  }
  const pair = trimmed.split("=>");
  if (pair.length !== 2) {
    return null;
  }
  const network = pair[0].trim();
  const policySchedule = pair[1].split("@");
  if (
    policySchedule.length > 2 ||
    !validateIpOrCidr(network) ||
    !validatePolicyName(policySchedule[0].trim())
  ) {
    return null;
  }
  const schedule = policySchedule.length === 2 ? parseSchedule(policySchedule[1]) : null;
  if (policySchedule.length === 2 && !schedule) {
    return null;
  }
  return {
    network,
    profile: policySchedule[0].trim().toLowerCase(),
    schedule,
  };
}

function parseSchedule(value: string): ClientPolicySchedule | null {
  const parts = value.trim().split(/\s+/);
  if (parts.length !== 2) {
    return null;
  }
  const time = parts[1].split("-");
  if (time.length !== 2) {
    return null;
  }
  const schedule = { days: parts[0].toLowerCase(), start: time[0], end: time[1] };
  try {
    validateSchedule(schedule);
    return schedule;
  } catch {
    return null;
  }
}

function validateSchedule(schedule: ClientPolicySchedule): void {
  parseWeekdays(schedule.days);
  if (parseTime(schedule.start) === null || parseTime(schedule.end) === null) {
    throw new Error("计划时间必须在 00:00 到 23:59 之间");
  }
}

function scheduleIsActive(
  schedule: ClientPolicySchedule,
  weekday: number,
  minute: number,
): boolean {
  const weekdays = parseWeekdays(schedule.days);
  const start = parseTime(schedule.start);
  const end = parseTime(schedule.end);
  if (start === null || end === null) {
    return false;
  }
  if (start === end) {
    return weekdays[weekday];
  }
  if (start < end) {
    return weekdays[weekday] && minute >= start && minute < end;
  }
  return minute >= start ? weekdays[weekday] : minute < end && weekdays[(weekday + 6) % 7];
}

export function expandPolicyWeekdays(value: string): ClientPolicyWeekday[] {
  const active = parseWeekdays(value);
  return CLIENT_POLICY_WEEKDAYS.filter((_, index) => active[index]);
}

function parseWeekdays(value: string): boolean[] {
  if (value.toLowerCase() === "daily") {
    return Array.from({ length: 7 }, () => true);
  }
  const weekdays = Array.from({ length: 7 }, () => false);
  for (const item of value.toLowerCase().split(",")) {
    const [startValue, endValue = startValue] = item.split("-");
    const start = CLIENT_POLICY_WEEKDAYS.indexOf(startValue as ClientPolicyWeekday);
    const end = CLIENT_POLICY_WEEKDAYS.indexOf(endValue as ClientPolicyWeekday);
    if (start < 0 || end < 0) {
      throw new Error(`未知星期：${item}`);
    }
    let current = start;
    while (true) {
      weekdays[current] = true;
      if (current === end) {
        break;
      }
      current = (current + 1) % 7;
    }
  }
  if (!weekdays.some(Boolean)) {
    throw new Error("计划至少需要选择一天");
  }
  return weekdays;
}

function parseTime(value: string): number | null {
  const match = /^(\d{2}):(\d{2})$/.exec(value);
  if (!match) {
    return null;
  }
  const hour = Number(match[1]);
  const minute = Number(match[2]);
  return hour <= 23 && minute <= 59 ? hour * 60 + minute : null;
}

function upsertLine(value: string, nextLine: string, matches: (line: string) => boolean): string {
  const lines = value.split("\n");
  const result: string[] = [];
  let replaced = false;
  for (const line of lines) {
    if (!matches(line)) {
      result.push(line);
      continue;
    }
    if (!replaced) {
      result.push(nextLine);
      replaced = true;
    }
  }
  if (!replaced) {
    while (result.length > 0 && result[result.length - 1].trim() === "") {
      result.pop();
    }
    result.push(nextLine);
  }
  return result.join("\n").trimEnd();
}

function parseNetwork(value: string): ParsedNetwork | null {
  const parts = value.split("/");
  if (parts.length > 2) {
    return null;
  }
  const ip = parseIp(parts[0]);
  if (!ip) {
    return null;
  }
  const prefix = parts.length === 1 ? ip.bits : Number(parts[1]);
  if (!/^\d{1,3}$/.test(parts[1] ?? String(prefix)) || prefix < 0 || prefix > ip.bits) {
    return null;
  }
  return { ...ip, prefix };
}

function parseIp(value: string): ParsedIp | null {
  const ipv4 = parseIpv4(value);
  if (ipv4 !== null) {
    return { family: 4, value: ipv4, bits: 32 };
  }
  const ipv6 = parseIpv6(value);
  return ipv6 === null ? null : { family: 6, value: ipv6, bits: 128 };
}

function parseIpv4(value: string): bigint | null {
  const parts = value.split(".");
  if (
    parts.length !== 4 ||
    parts.some((part) => !/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255)
  ) {
    return null;
  }
  return parts.reduce((result, part) => (result << 8n) | BigInt(Number(part)), 0n);
}

function parseIpv6(value: string): bigint | null {
  if (!value || value.includes("%") || value.split("::").length > 2) {
    return null;
  }
  const hasCompression = value.includes("::");
  const [leftRaw, rightRaw = ""] = value.split("::");
  const left = parseIpv6Side(leftRaw);
  const right = parseIpv6Side(rightRaw);
  if (!left || !right) {
    return null;
  }
  const missing = 8 - left.length - right.length;
  if ((!hasCompression && missing !== 0) || (hasCompression && missing < 1)) {
    return null;
  }
  const groups = [...left, ...Array.from({ length: missing }, () => 0), ...right];
  if (groups.length !== 8) {
    return null;
  }
  return groups.reduce((result, group) => (result << 16n) | BigInt(group), 0n);
}

function parseIpv6Side(value: string): number[] | null {
  if (!value) {
    return [];
  }
  const tokens = value.split(":");
  const groups: number[] = [];
  for (const [index, token] of tokens.entries()) {
    const ipv4 = parseIpv4(token);
    if (ipv4 !== null) {
      if (index !== tokens.length - 1) {
        return null;
      }
      groups.push(Number((ipv4 >> 16n) & 0xffffn), Number(ipv4 & 0xffffn));
      continue;
    }
    if (!/^[0-9a-f]{1,4}$/i.test(token)) {
      return null;
    }
    groups.push(Number.parseInt(token, 16));
  }
  return groups;
}

function networkContains(network: ParsedNetwork, address: ParsedIp): boolean {
  if (network.family !== address.family) {
    return false;
  }
  const shift = BigInt(network.bits - network.prefix);
  return network.value >> shift === address.value >> shift;
}

function isClientPolicyService(value: string): value is ClientPolicyService {
  return CLIENT_POLICY_SERVICE_KEYS.includes(value as ClientPolicyService);
}
