import { escapeHtml, formatCount, formatElapsedMs, formatLogDate, formatLogTime } from "./format";
import type { QueryLogRecord } from "./types";
import { t } from "./i18n";

type QueryLogRenderOptions = {
  clientDisplayName: (ip: string | null) => string | null;
  formatClientLabel: (ip: string | null) => string;
};

export function renderQueryLogRow(
  record: QueryLogRecord,
  options: QueryLogRenderOptions,
): string {
  const status = queryLogStatus(record);
  const rowClass = record.failed ? " failed" : record.blocked ? " blocked" : "";
  const detail = escapeHtml(queryLogResponseDetail(record));
  const measuredDuration = record.processing_duration_ms ?? record.upstream_duration_ms;
  const duration = measuredDuration !== null ? formatElapsedMs(measuredDuration) : "";
  const requestMeta = [
    dnsQueryTypeLabel(record.query_type),
    record.transport?.toUpperCase() ?? t("协议未记录"),
  ];
  if (record.query_class !== null && record.query_class !== 1) {
    requestMeta.push(dnsQueryClassLabel(record.query_class));
  }
  const requestDetailPopover = renderQueryLogRequestDetail(record, options.formatClientLabel);
  const responseDetailPopover = renderQueryLogResponseDetail(record, status.label);

  return `
    <div class="query-log-row${rowClass}" role="row">
      <div class="log-time" role="cell">
        <strong>${escapeHtml(formatLogTime(record.timestamp))}</strong>
        <span>${escapeHtml(formatLogDate(record.timestamp))}</span>
      </div>
      <div class="log-request" role="cell">
        <div class="log-detail-anchor">
          <button class="log-detail-trigger" type="button" aria-label="${t("查看请求详情")}">
            ${renderLogEyeIcon(status.className)}
          </button>
          ${requestDetailPopover}
        </div>
        <div class="log-request-content">
          <strong title="${escapeHtml(record.domain)}">${escapeHtml(record.domain)}</strong>
          <div class="log-request-meta">
            <span>${escapeHtml(requestMeta.join(" · "))}</span>
            <div class="log-rule-actions">
              <button data-log-rule-action="${record.blocked ? "allow" : "block"}" data-domain="${escapeHtml(record.domain)}" type="button">${record.blocked ? t("放行") : t("拦截")}</button>
              <button data-log-rule-action="rewrite" data-domain="${escapeHtml(record.domain)}" type="button">${t("重写")}</button>
            </div>
          </div>
        </div>
      </div>
      <div class="log-response" role="cell">
        <div class="log-response-layout">
          <div class="log-detail-anchor log-response-detail-anchor">
            <button class="log-detail-trigger" type="button" aria-label="${t("查看响应详情")}">
              ${renderLogQuestionIcon()}
            </button>
            ${responseDetailPopover}
          </div>
          <div class="log-response-summary">
            <strong class="${status.className}">${status.label}</strong>
            <span title="${detail}">${detail}</span>
            ${duration ? `<small>${duration}</small>` : ""}
          </div>
        </div>
      </div>
      <div class="log-client" role="cell">
        <strong>${escapeHtml(options.clientDisplayName(record.client_ip) ?? record.client_ip ?? "-")}</strong>
        <span>${escapeHtml(record.client_ip || t("未知客户端"))}</span>
      </div>
    </div>
  `;
}

function renderLogEyeIcon(className: string): string {
  return `
    <svg class="log-eye-icon ${className}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d="M2.75 12c1.95-3.25 5.2-5.25 9.25-5.25s7.3 2 9.25 5.25c-1.95 3.25-5.2 5.25-9.25 5.25S4.7 15.25 2.75 12Z"></path>
      <circle cx="12" cy="12" r="2.75"></circle>
      <path d="M4.75 19.25 19.25 4.75"></path>
    </svg>
  `;
}

function renderLogQuestionIcon(): string {
  return `
    <svg class="log-question-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <circle cx="12" cy="12" r="8.75"></circle>
      <path d="M9.7 9.35a2.45 2.45 0 0 1 4.7.95c0 1.9-2.4 2.1-2.4 3.65"></path>
      <path d="M12 17.25h.01"></path>
    </svg>
  `;
}

function renderQueryLogRequestDetail(
  record: QueryLogRecord,
  formatClientLabel: (ip: string | null) => string,
): string {
  return renderLogDetailPopover(t("请求详情"), [
    [t("时间"), formatLogTime(record.timestamp)],
    [t("日期"), formatLogDate(record.timestamp)],
    [t("域名"), record.domain],
    [t("查询类型"), dnsQueryTypeDetail(record.query_type)],
    [t("查询类别"), dnsQueryClassLabel(record.query_class)],
    [t("传输协议"), record.transport?.toUpperCase() ?? t("旧日志未记录")],
    [t("客户端"), formatClientLabel(record.client_ip)],
  ]);
}

function renderQueryLogResponseDetail(record: QueryLogRecord, statusLabel: string): string {
  const rows = [
    [t("状态"), statusLabel],
    [t("响应来源"), queryLogResponseSourceLabel(record)],
  ];
  const response = record.response;
  if (response) {
    rows.push(
      [t("响应代码"), dnsResponseCodeLabel(response.code)],
      [t("响应记录"), t("{p0} 条", { p0: formatCount(response.answer_count) })],
    );
  } else {
    rows.push([t("响应代码"), record.failed ? t("无响应") : t("旧日志未记录")]);
  }
  if (record.upstream_server) {
    rows.push([t("上游服务器"), record.upstream_server]);
  }
  if (record.upstream_duration_ms !== null) {
    rows.push([t("上游耗时"), formatElapsedMs(record.upstream_duration_ms)]);
  }
  if (record.processing_duration_ms !== null) {
    rows.push([t("总处理耗时"), formatElapsedMs(record.processing_duration_ms)]);
  }
  if (response?.truncated) {
    rows.push([t("截断响应"), t("是（TC 标志）")]);
  }
  if (record.error) {
    rows.push([record.failed ? t("错误") : t("说明"), record.error]);
  }
  if (record.blocked) {
    rows.push(
      [t("命中规则"), record.matched_rule ?? t("旧日志未记录")],
      [t("来源清单"), record.rule_source ?? t("旧日志未记录")],
      [t("规则类型"), record.rule_type ?? t("旧日志未记录")],
      [t("important 覆盖"), record.important_overrode ? t("是") : t("否")],
      ["allowlist", record.allowlist_rule ?? t("无")],
    );
  }
  return renderLogDetailPopover(t("响应详情"), rows, renderQueryLogResponseAnswers(record));
}

function renderLogDetailPopover(title: string, rows: string[][], extraContent = ""): string {
  return `
    <div class="log-detail-popover${extraContent ? " log-response-popover" : ""}" role="tooltip">
      <strong>${escapeHtml(title)}</strong>
      <dl>
        ${rows.map(([label, value]) => `
          <div>
            <dt>${escapeHtml(label)}</dt>
            <dd title="${escapeHtml(value)}">${escapeHtml(value)}</dd>
          </div>
        `).join("")}
      </dl>
      ${extraContent}
    </div>
  `;
}

function renderQueryLogResponseAnswers(record: QueryLogRecord): string {
  const response = record.response;
  if (!response || response.answer_count === 0) {
    return "";
  }
  const omitted = Math.max(0, response.answer_count - response.answers.length);
  const records = response.answers.map((answer) => `
    <div class="log-response-answer">
      <span>${escapeHtml(dnsQueryTypeLabel(answer.record_type))}</span>
      <code title="${escapeHtml(answer.value)}">${escapeHtml(answer.value)}</code>
      <small>${t("TTL {p0} 秒", { p0: formatCount(answer.ttl) })}</small>
    </div>
  `).join("");
  return `
    <section class="log-response-answers">
      <strong>${t("响应记录")}</strong>
      <div class="log-response-answer-list">
        ${records || `<p>${t("响应记录内容无法解析")}</p>`}
      </div>
      ${omitted > 0 ? `<p>${t("另有 {p0} 条记录未写入日志摘要", { p0: formatCount(omitted) })}</p>` : ""}
    </section>
  `;
}

function dnsResponseCodeLabel(code: number): string {
  const labels: Record<number, string> = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
  };
  return t("{p0}（{p1}）", { p0: labels[code] ?? "RCODE", p1: code });
}

function queryLogStatus(record: QueryLogRecord): { label: string; className: string } {
  if (record.failed) return { label: t("失败"), className: "failed" };
  if (record.blocked) return { label: t("已拦截"), className: "blocked" };
  if (queryLogResponseSource(record) === "refused") {
    return { label: t("已拒绝"), className: "refused" };
  }
  return { label: t("已处理"), className: "processed" };
}

type ResolvedQueryResponseSource =
  | "upstream"
  | "cache"
  | "rewrite"
  | "blocked"
  | "refused"
  | "local";

function queryLogResponseSource(record: QueryLogRecord): ResolvedQueryResponseSource {
  if (record.response_source) return record.response_source;
  if (record.blocked) return "blocked";
  if (record.error?.includes("ANY 查询")) return "refused";
  if (record.upstream_server) return "upstream";
  if (record.upstream_duration_ms === 0) return "cache";
  return "local";
}

function queryLogResponseSourceLabel(record: QueryLogRecord): string {
  switch (queryLogResponseSource(record)) {
    case "upstream": return t("上游 DNS");
    case "cache": return t("DNS 缓存");
    case "rewrite": return t("本地 DNS 重写");
    case "blocked": return t("过滤器");
    case "refused": return t("本地拒绝");
    default: return t("本地响应（旧日志未记录来源）");
  }
}

function queryLogResponseDetail(record: QueryLogRecord): string {
  if (record.failed && record.error) return record.error;
  switch (queryLogResponseSource(record)) {
    case "upstream":
      return record.upstream_server ? t("上游：{p0}", { p0: record.upstream_server }) : t("上游 DNS 解析");
    case "cache": return t("DNS 缓存命中");
    case "rewrite": return t("本地 DNS 重写");
    case "blocked": return record.rule_source ? t("过滤器：{p0}", { p0: record.rule_source }) : t("过滤器拦截");
    case "refused": return record.error ?? t("本地拒绝响应");
    default: return t("本地响应（旧日志）");
  }
}

export function dnsQueryTypeLabel(queryType: number | null): string {
  if (queryType === null) return t("类型未记录");
  return DNS_QUERY_TYPE_LABELS[queryType] ?? `TYPE${queryType}`;
}

function dnsQueryTypeDetail(queryType: number | null): string {
  return queryType === null ? t("旧日志未记录") : `${dnsQueryTypeLabel(queryType)}（${queryType}）`;
}

function dnsQueryClassLabel(queryClass: number | null): string {
  if (queryClass === null) return t("旧日志未记录");
  const labels: Record<number, string> = {
    1: t("IN（互联网）"),
    3: t("CH（Chaos）"),
    4: t("HS（Hesiod）"),
    255: t("ANY（任意类别）"),
  };
  return labels[queryClass] ?? `CLASS${queryClass}`;
}

const DNS_QUERY_TYPE_LABELS: Record<number, string> = {
  1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
  28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC",
  48: "DNSKEY", 52: "TLSA", 64: "SVCB", 65: "HTTPS", 255: "ANY",
};
