export type ConfigDraftGuard = {
  loaded: boolean;
  force: boolean;
  dirty: boolean;
  savedAtStart: string;
  savedNow: string;
  draftAtStart: string | null;
  draftNow: string | null;
};

export function shouldPreserveConfigDraft(state: ConfigDraftGuard): boolean {
  return state.loaded && (
    (!state.force && state.dirty) ||
    state.savedNow !== state.savedAtStart ||
    state.draftNow !== state.draftAtStart
  );
}

export function configSaveCompletion(
  submittedFingerprint: string,
  currentFingerprint: string,
): { savedFingerprint: string; dirty: boolean } {
  return {
    savedFingerprint: submittedFingerprint,
    dirty: currentFingerprint !== submittedFingerprint,
  };
}

export function rebaseConfigFingerprint(
  fingerprint: string,
  authoritativeFields: Record<string, unknown>,
): string {
  if (!fingerprint) {
    return fingerprint;
  }
  const parsed: unknown = JSON.parse(fingerprint);
  if (!isRecord(parsed)) {
    throw new Error("配置指纹格式无效");
  }
  for (const [key, value] of Object.entries(authoritativeFields)) {
    if (Object.prototype.hasOwnProperty.call(parsed, key)) {
      parsed[key] = value;
    }
  }
  return JSON.stringify(parsed);
}

export type QueryLogRuleDraft = {
  blacklist: string;
  dnsRewrites: string;
};

export function mergeQueryLogRuleIntoDraft(
  draft: QueryLogRuleDraft,
  authoritative: QueryLogRuleDraft,
  action: "block" | "allow" | "rewrite",
): QueryLogRuleDraft {
  const intendedLine = lastConfigLine(
    action === "rewrite" ? authoritative.dnsRewrites : authoritative.blacklist,
  );
  const domain = action === "rewrite"
    ? intendedLine.split(/\s+/)[0]
    : intendedLine.replace(/^@@/, "").replace(/^\|\|/, "").replace(/\^$/, "");
  if (!domain) {
    throw new Error("服务端未返回可合并的查询日志规则");
  }

  const next: QueryLogRuleDraft = {
    blacklist: removeExactDomainRules(draft.blacklist, domain),
    dnsRewrites: removeExactDnsRewrites(draft.dnsRewrites, domain),
  };
  if (action === "rewrite") {
    next.dnsRewrites = appendConfigLine(next.dnsRewrites, intendedLine);
  } else {
    next.blacklist = appendConfigLine(next.blacklist, intendedLine);
  }
  return next;
}

function lastConfigLine(value: string): string {
  const lines = value.split(/\r?\n/);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index].trim();
    if (line) {
      return line;
    }
  }
  return "";
}

function removeExactDomainRules(value: string, domain: string): string {
  const block = `||${domain}^`.toLocaleLowerCase();
  const allow = `@@||${domain}^`.toLocaleLowerCase();
  return value
    .split(/\r?\n/)
    .filter((line) => {
      const normalized = line.trim().toLocaleLowerCase();
      return normalized !== block && normalized !== allow;
    })
    .join("\n");
}

function removeExactDnsRewrites(value: string, domain: string): string {
  const normalizedDomain = domain.toLocaleLowerCase();
  return value
    .split(/\r?\n/)
    .filter((line) => (line.trim().split(/\s+/)[0] ?? "").toLocaleLowerCase() !== normalizedDomain)
    .join("\n");
}

function appendConfigLine(value: string, line: string): string {
  return value && !value.endsWith("\n") ? `${value}\n${line}` : `${value}${line}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
