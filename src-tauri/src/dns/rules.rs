use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSummary {
    pub block_rules: usize,
    pub allow_rules: usize,
    pub ignored_rules: usize,
    pub ignored_comment_rules: usize,
    pub ignored_regex_rules: usize,
    pub ignored_unsupported_rules: usize,
    pub ignored_invalid_rules: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleAnalysis {
    pub summary: RuleSummary,
    pub disabled_rules: usize,
    pub diagnostics: Vec<RuleLineDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleLineDiagnostic {
    pub line: usize,
    pub severity: String,
    pub reason: String,
    pub message: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CompiledRules {
    blocks: RuleSet,
    allows: RuleSet,
    /// 清单名称表：规则条目里只存索引，避免几百万条规则各克隆一份清单名
    sources: Vec<Box<str>>,
    summary: RuleSummary,
    /// 本次编译收集到的 badfilter 禁用目标。增量合并自定义规则时要继续尊重它，
    /// 否则被清单 badfilter 禁掉的规则会从自定义规则那边重新生效。
    disabled: HashSet<Box<str>>,
    /// 自定义规则只保存很小的增量层，并共享只读的远程清单索引。
    /// 纯清单缓存落盘时该字段始终为空，不改变 postcard 格式。
    #[serde(skip)]
    base: Option<Arc<CompiledRules>>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct RuleSet {
    exact: HashMap<Box<str>, RuleEntry>,
    suffix: HashMap<Box<str>, RuleEntry>,
}

/// 绝大多数规则是无修饰符的规范写法（如 `||domain^`），原文可以在命中时由域名重建，
/// 压缩成 4 字节的 Simple；带修饰符、非规范写法或同域名多条规则时才升级为完整形态。
#[derive(Clone, Serialize, Deserialize)]
enum RuleEntry {
    Simple(SimpleRule),
    Complex(Box<[ComplexRule]>),
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct SimpleRule {
    source_id: u16,
    kind: SimpleKind,
}

/// 能够由域名逐字节重建规则原文的规范形态
#[derive(Clone, Copy, Serialize, Deserialize)]
enum SimpleKind {
    /// `||domain^`（允许规则为 `@@||domain^`）
    Suffix,
    /// `domain`（允许规则为 `@@domain`）
    ExactPlain,
    /// `0.0.0.0 domain`
    HostsZero4,
    /// `127.0.0.1 domain`
    HostsLocal4,
    /// `:: domain`
    HostsZero6,
    /// `::1 domain`
    HostsLocal6,
}

#[derive(Clone, Serialize, Deserialize)]
struct ComplexRule {
    raw: Box<str>,
    source_id: u16,
    rule_type: RuleType,
    important: bool,
    query_types: QueryTypes,
    denyallow: Box<[Box<str>]>,
}

#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
enum QueryTypes {
    #[default]
    Any,
    Include(Box<[u16]>),
    Exclude(Box<[u16]>),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum RuleType {
    Exact,
    Suffix,
    Hosts,
}

#[derive(Debug, Clone)]
pub(crate) struct BlockMatch {
    pub(crate) rule: String,
    pub(crate) source: String,
    pub(crate) rule_type: String,
    pub(crate) important_overrode: bool,
    pub(crate) allowlist_rule: Option<String>,
}

/// 命中结果的只读视图：只有真正命中时才把规则原文物化成 String
struct MatchedRule<'a> {
    domain: &'a str,
    source_id: u16,
    rule_type: RuleType,
    raw: MatchedRaw<'a>,
}

enum MatchedRaw<'a> {
    Stored(&'a str),
    Canonical(SimpleKind),
}

impl MatchedRule<'_> {
    fn raw_text(&self, is_allow: bool) -> String {
        match self.raw {
            MatchedRaw::Stored(raw) => raw.to_string(),
            MatchedRaw::Canonical(kind) => canonical_rule_text(kind, self.domain, is_allow),
        }
    }
}

const SOURCE_MARKER_PREFIX: &str = "! dnsblackhole-source:";
const DEFAULT_SOURCE: &str = "自定义规则";

/// 逐行扫描规则文本，统一处理来源标记与 badfilter 禁用行，
/// 保证 summarize 与 compile 对每一行的判定完全一致。
fn scan_rules<'a>(raw: &'a str, handle: impl FnMut(ScanEvent<'a>)) {
    let empty = HashSet::new();
    scan_rules_with_disabled(raw, &empty, handle);
}

/// extra_disabled 承载另一段规则里的 badfilter 目标，用于把自定义规则增量合并进
/// 已编译的清单结果时仍然尊重清单的禁用。返回本段自己收集到的禁用目标。
fn scan_rules_with_disabled<'a>(
    raw: &'a str,
    extra_disabled: &HashSet<Box<str>>,
    mut handle: impl FnMut(ScanEvent<'a>),
) -> HashSet<String> {
    let disabled = raw
        .lines()
        .filter_map(badfilter_target)
        .collect::<HashSet<_>>();

    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(encoded) = trimmed.strip_prefix(SOURCE_MARKER_PREFIX) {
            if let Ok(value) = serde_json::from_str::<String>(encoded) {
                handle(ScanEvent::Source(value));
            }
            continue;
        }
        if disabled.contains(trimmed) || extra_disabled.contains(trimmed) {
            continue;
        }
        if let Some((kind, domains)) = parse_hosts_rules(trimmed) {
            let single_domain = domains.len() == 1;
            for domain in domains {
                match domain {
                    Some(domain) => {
                        let canonical = (single_domain
                            && is_canonical_rule_text(trimmed, kind, &domain, false))
                        .then_some(kind);
                        handle(ScanEvent::Rule(ParsedRule::Block(RuleData {
                            domain,
                            include_subdomains: false,
                            raw: trimmed,
                            rule_type: RuleType::Hosts,
                            important: false,
                            query_types: QueryTypes::Any,
                            denyallow: Vec::new(),
                            canonical,
                        })));
                    }
                    None => handle(ScanEvent::Rule(ParsedRule::Ignored(
                        IgnoredRuleReason::Invalid,
                    ))),
                }
            }
            continue;
        }
        handle(ScanEvent::Rule(parse_rule(line)));
    }
    disabled
}

enum ScanEvent<'a> {
    Source(String),
    Rule(ParsedRule<'a>),
}

/// 只解析计数，不构建索引结构，避免为了统计条数把几 GB 的规则索引建了又丢
pub fn summarize_rules(raw: &str) -> RuleSummary {
    let mut summary = RuleSummary::default();
    scan_rules(raw, |event| {
        if let ScanEvent::Rule(parsed) = event {
            count_rule(&mut summary, &parsed);
        }
    });
    summary
}

/// 为编辑器提供逐行反馈。诊断复用生产解析器，避免前端校验和实际生效结果不一致。
pub fn analyze_rules(raw: &str) -> RuleAnalysis {
    let mut analysis = RuleAnalysis {
        summary: summarize_rules(raw),
        disabled_rules: raw
            .lines()
            .filter(|line| badfilter_target(line).is_some())
            .count(),
        diagnostics: Vec::new(),
    };
    for (index, line) in raw.lines().enumerate() {
        let summary = summarize_rules(line);
        let diagnostic = if summary.ignored_regex_rules > 0 {
            Some(("warning", "regex", "暂不支持正则表达式规则，该行不会生效"))
        } else if summary.ignored_unsupported_rules > 0 {
            Some(("warning", "unsupported", "包含不支持的修饰符，该行不会生效"))
        } else if summary.ignored_invalid_rules > 0 {
            Some(("error", "invalid", "规则格式或域名无效，该行不会生效"))
        } else {
            None
        };
        if let Some((severity, reason, message)) = diagnostic {
            analysis.diagnostics.push(RuleLineDiagnostic {
                line: index + 1,
                severity: severity.to_string(),
                reason: reason.to_string(),
                message: message.to_string(),
            });
        }
    }
    analysis
}

pub fn compile_rules(raw: &str) -> CompiledRules {
    compile_rules_with_disabled(raw, &HashSet::new())
}

fn compile_rules_with_disabled(raw: &str, extra_disabled: &HashSet<Box<str>>) -> CompiledRules {
    let capacities = estimate_rule_capacities(raw);
    let mut blocks = RuleSet::with_capacities(capacities.block_exact, capacities.block_suffix);
    let mut allows = RuleSet::with_capacities(capacities.allow_exact, capacities.allow_suffix);
    let mut summary = RuleSummary::default();
    let mut sources: Vec<Box<str>> = vec![DEFAULT_SOURCE.into()];
    let mut source_id: u16 = 0;

    let own_disabled = scan_rules_with_disabled(raw, extra_disabled, |event| match event {
        ScanEvent::Source(name) => source_id = intern_source(&mut sources, &name),
        ScanEvent::Rule(parsed) => {
            count_rule(&mut summary, &parsed);
            match parsed {
                ParsedRule::Block(rule) => blocks.insert(rule, source_id, false),
                ParsedRule::Allow(rule) => allows.insert(rule, source_id, true),
                ParsedRule::Ignored(_) | ParsedRule::Disable => {}
            }
        }
    });

    let mut disabled = extra_disabled.clone();
    disabled.extend(own_disabled.into_iter().map(String::into_boxed_str));
    CompiledRules {
        blocks,
        allows,
        sources,
        summary,
        disabled,
        base: None,
    }
}

/// 自定义规则里的 badfilter 需要回溯禁用清单里已编译的规则，增量合并做不到，
/// 命中时必须退回整体编译。
pub(crate) fn custom_rules_have_badfilter(raw: &str) -> bool {
    raw.lines().any(|line| badfilter_target(line).is_some())
}

#[derive(Default)]
struct RuleCapacities {
    block_exact: usize,
    block_suffix: usize,
    allow_exact: usize,
    allow_suffix: usize,
}

/// 预估四个索引的容量，避免数百万条规则启动时反复扩容和搬迁哈希表。
fn estimate_rule_capacities(raw: &str) -> RuleCapacities {
    let mut capacities = RuleCapacities::default();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with('!')
            || trimmed.contains("$badfilter")
        {
            continue;
        }
        let (is_allow, rule) = trimmed
            .strip_prefix("@@")
            .map_or((false, trimmed), |rule| (true, rule));
        let pattern = rule.split_once('$').map_or(rule, |(pattern, _)| pattern);
        let mut parts = pattern.split_whitespace();
        let host_prefix = parts
            .next()
            .is_some_and(|value| matches!(value, "0.0.0.0" | "127.0.0.1" | "::" | "::1"));
        let exact_count = if host_prefix {
            parts
                .take_while(|token| !token.starts_with('#') && !token.starts_with('!'))
                .count()
                .max(1)
        } else {
            1
        };
        let suffix = pattern.starts_with("||") || pattern.starts_with("*.");
        let capacity = match (is_allow, suffix) {
            (false, false) => &mut capacities.block_exact,
            (false, true) => &mut capacities.block_suffix,
            (true, false) => &mut capacities.allow_exact,
            (true, true) => &mut capacities.allow_suffix,
        };
        *capacity = capacity.saturating_add(exact_count);
    }
    capacities
}

fn count_rule(summary: &mut RuleSummary, parsed: &ParsedRule<'_>) {
    match parsed {
        ParsedRule::Block(_) => summary.block_rules += 1,
        ParsedRule::Allow(_) => summary.allow_rules += 1,
        ParsedRule::Ignored(reason) => {
            summary.ignored_rules += 1;
            match reason {
                IgnoredRuleReason::Comment => summary.ignored_comment_rules += 1,
                IgnoredRuleReason::Regex => summary.ignored_regex_rules += 1,
                IgnoredRuleReason::Unsupported => summary.ignored_unsupported_rules += 1,
                IgnoredRuleReason::Invalid => summary.ignored_invalid_rules += 1,
            }
        }
        ParsedRule::Disable => {}
    }
}

fn intern_source(sources: &mut Vec<Box<str>>, name: &str) -> u16 {
    if let Some(index) = sources
        .iter()
        .position(|existing| existing.as_ref() == name)
    {
        return index as u16;
    }
    if sources.len() > usize::from(u16::MAX) {
        return 0;
    }
    sources.push(name.into());
    (sources.len() - 1) as u16
}

impl CompiledRules {
    pub(crate) fn summary(&self) -> RuleSummary {
        self.summary.clone()
    }

    /// 在已编译的清单结果上原地追加自定义规则。插入顺序与整体编译一致（清单先、
    /// 自定义后），因此与清单重复的规则仍然保留清单里的那一条。
    /// 调用前需用 [`custom_rules_have_badfilter`] 排除自定义 badfilter。
    #[cfg(test)]
    pub(crate) fn merge_custom_rules(&mut self, custom: &str) {
        let Self {
            blocks,
            allows,
            sources,
            summary,
            disabled,
            base: _,
        } = self;
        let default_id = intern_source(sources, DEFAULT_SOURCE);
        let mut source_id = default_id;
        scan_rules_with_disabled(custom, &*disabled, |event| match event {
            ScanEvent::Source(name) => source_id = intern_source(sources, &name),
            ScanEvent::Rule(parsed) => {
                count_rule(summary, &parsed);
                match parsed {
                    ParsedRule::Block(rule) => blocks.insert(rule, source_id, false),
                    ParsedRule::Allow(rule) => allows.insert(rule, source_id, true),
                    ParsedRule::Ignored(_) | ParsedRule::Disable => {}
                }
            }
        });
    }

    /// 只编译自定义规则这一小层，并共享远程清单的数百万条索引。
    /// 查询时按原有的域名优先级跨层匹配，效果与原地合入保持一致。
    pub(crate) fn with_custom_layer(base: Arc<Self>, custom: &str) -> Self {
        let mut overlay = compile_rules_with_disabled(custom, &base.disabled);
        overlay.summary = combined_summary(&base.summary, &overlay.summary);
        overlay.base = Some(base);
        overlay
    }

    #[cfg(test)]
    pub(crate) fn is_blocked(&self, domain: &str, qtype: u16) -> bool {
        self.blocking_match(domain, qtype).is_some()
    }

    pub(crate) fn blocking_match(&self, domain: &str, qtype: u16) -> Option<BlockMatch> {
        if let Some(base) = self.base.as_deref() {
            blocking_match_layers(&[base, self], domain, qtype)
        } else {
            blocking_match_layers(&[self], domain, qtype)
        }
    }

    fn source_name(&self, source_id: u16) -> String {
        self.sources
            .get(usize::from(source_id))
            .map(|name| name.to_string())
            .unwrap_or_else(|| DEFAULT_SOURCE.to_string())
    }
}

fn combined_summary(base: &RuleSummary, overlay: &RuleSummary) -> RuleSummary {
    RuleSummary {
        block_rules: base.block_rules + overlay.block_rules,
        allow_rules: base.allow_rules + overlay.allow_rules,
        ignored_rules: base.ignored_rules + overlay.ignored_rules,
        ignored_comment_rules: base.ignored_comment_rules + overlay.ignored_comment_rules,
        ignored_regex_rules: base.ignored_regex_rules + overlay.ignored_regex_rules,
        ignored_unsupported_rules: base.ignored_unsupported_rules
            + overlay.ignored_unsupported_rules,
        ignored_invalid_rules: base.ignored_invalid_rules + overlay.ignored_invalid_rules,
    }
}

struct RuleCandidate {
    raw: String,
    source: String,
    rule_type: RuleType,
}

fn blocking_match_layers(
    layers: &[&CompiledRules],
    domain: &str,
    qtype: u16,
) -> Option<BlockMatch> {
    if find_layered_match(layers, domain, qtype, true, true).is_some() {
        return None;
    }
    if let Some(block) = find_layered_match(layers, domain, qtype, true, false) {
        let allow = find_layered_match(layers, domain, qtype, false, true);
        let important_overrode = allow.is_some();
        return Some(build_block_match(block, allow, important_overrode));
    }
    if find_layered_match(layers, domain, qtype, false, true).is_some() {
        return None;
    }
    find_layered_match(layers, domain, qtype, false, false)
        .map(|block| build_block_match(block, None, false))
}

fn find_layered_match(
    layers: &[&CompiledRules],
    domain: &str,
    qtype: u16,
    important: bool,
    allow: bool,
) -> Option<RuleCandidate> {
    if let Some(found) = lookup_layers(layers, domain, domain, qtype, important, allow, true) {
        return Some(found);
    }
    if let Some(found) = lookup_layers(layers, domain, domain, qtype, important, allow, false) {
        return Some(found);
    }

    let mut offset = 0;
    while let Some(dot_index) = domain[offset..].find('.') {
        offset += dot_index + 1;
        if let Some(found) = lookup_layers(
            layers,
            &domain[offset..],
            domain,
            qtype,
            important,
            allow,
            false,
        ) {
            return Some(found);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn lookup_layers(
    layers: &[&CompiledRules],
    lookup: &str,
    query_domain: &str,
    qtype: u16,
    important: bool,
    allow: bool,
    exact: bool,
) -> Option<RuleCandidate> {
    for rules in layers {
        let rule_set = if allow { &rules.allows } else { &rules.blocks };
        let entries = if exact {
            &rule_set.exact
        } else {
            &rule_set.suffix
        };
        if let Some(matched) = lookup_entry(entries, lookup, query_domain, qtype, important) {
            return Some(RuleCandidate {
                raw: matched.raw_text(allow),
                source: rules.source_name(matched.source_id),
                rule_type: matched.rule_type,
            });
        }
    }
    None
}

fn build_block_match(
    block: RuleCandidate,
    allow: Option<RuleCandidate>,
    important_overrode: bool,
) -> BlockMatch {
    BlockMatch {
        rule: block.raw,
        source: block.source,
        rule_type: format!("{} block", block.rule_type.as_str()),
        important_overrode,
        allowlist_rule: allow.map(|rule| rule.raw),
    }
}

impl RuleSet {
    fn with_capacities(exact: usize, suffix: usize) -> Self {
        Self {
            exact: HashMap::with_capacity(exact),
            suffix: HashMap::with_capacity(suffix),
        }
    }

    fn insert(&mut self, rule: RuleData<'_>, source_id: u16, is_allow: bool) {
        let RuleData {
            domain,
            include_subdomains,
            raw,
            rule_type,
            important,
            query_types,
            denyallow,
            canonical,
        } = rule;
        let map = if include_subdomains {
            &mut self.suffix
        } else {
            &mut self.exact
        };

        if let Some(entry) = map.get_mut(domain.as_ref()) {
            // 匹配条件完全相同的规则永远只会命中先插入的一条（find 只取第一条），
            // 多个清单间的重复规则在这里直接去重
            if entry.covers_semantics(important, &query_types, &denyallow) {
                return;
            }
            entry.push(
                domain.as_ref(),
                is_allow,
                ComplexRule {
                    raw: raw.into(),
                    source_id,
                    rule_type,
                    important,
                    query_types,
                    denyallow: denyallow.into_boxed_slice(),
                },
            );
            return;
        }

        let value = match canonical {
            Some(kind) => RuleEntry::Simple(SimpleRule { source_id, kind }),
            None => RuleEntry::Complex(Box::new([ComplexRule {
                raw: raw.into(),
                source_id,
                rule_type,
                important,
                query_types,
                denyallow: denyallow.into_boxed_slice(),
            }])),
        };
        map.insert(domain.into_owned().into_boxed_str(), value);
    }
}

fn lookup_entry<'a>(
    map: &'a HashMap<Box<str>, RuleEntry>,
    key: &str,
    query_domain: &str,
    qtype: u16,
    important: bool,
) -> Option<MatchedRule<'a>> {
    let (stored_key, entry) = map.get_key_value(key)?;
    match entry {
        RuleEntry::Simple(rule) => (!important).then(|| MatchedRule {
            domain: stored_key,
            source_id: rule.source_id,
            rule_type: rule.kind.rule_type(),
            raw: MatchedRaw::Canonical(rule.kind),
        }),
        RuleEntry::Complex(rules) => rules
            .iter()
            .find(|rule| rule.matches(query_domain, qtype, important))
            .map(|rule| MatchedRule {
                domain: stored_key,
                source_id: rule.source_id,
                rule_type: rule.rule_type,
                raw: MatchedRaw::Stored(&rule.raw),
            }),
    }
}

impl RuleEntry {
    /// 已有条目中是否存在匹配条件完全相同的规则；有则后续同语义规则永远不可能命中
    fn covers_semantics(
        &self,
        important: bool,
        query_types: &QueryTypes,
        denyallow: &[Box<str>],
    ) -> bool {
        match self {
            Self::Simple(_) => {
                !important && *query_types == QueryTypes::Any && denyallow.is_empty()
            }
            Self::Complex(rules) => rules.iter().any(|rule| {
                rule.important == important
                    && rule.query_types == *query_types
                    && rule.denyallow.as_ref() == denyallow
            }),
        }
    }

    fn push(&mut self, domain: &str, is_allow: bool, rule: ComplexRule) {
        match self {
            Self::Simple(simple) => {
                let first = simple.to_complex(domain, is_allow);
                *self = Self::Complex(Box::new([first, rule]));
            }
            Self::Complex(rules) => {
                let mut list = std::mem::take(rules).into_vec();
                list.push(rule);
                *rules = list.into_boxed_slice();
            }
        }
    }
}

impl SimpleRule {
    fn to_complex(self, domain: &str, is_allow: bool) -> ComplexRule {
        ComplexRule {
            raw: canonical_rule_text(self.kind, domain, is_allow).into_boxed_str(),
            source_id: self.source_id,
            rule_type: self.kind.rule_type(),
            important: false,
            query_types: QueryTypes::Any,
            denyallow: Box::default(),
        }
    }
}

impl SimpleKind {
    fn rule_type(self) -> RuleType {
        match self {
            Self::Suffix => RuleType::Suffix,
            Self::ExactPlain => RuleType::Exact,
            Self::HostsZero4 | Self::HostsLocal4 | Self::HostsZero6 | Self::HostsLocal6 => {
                RuleType::Hosts
            }
        }
    }
}

fn canonical_rule_text(kind: SimpleKind, domain: &str, is_allow: bool) -> String {
    let allow_prefix = if is_allow { "@@" } else { "" };
    match kind {
        SimpleKind::Suffix => format!("{allow_prefix}||{domain}^"),
        SimpleKind::ExactPlain => format!("{allow_prefix}{domain}"),
        SimpleKind::HostsZero4 => format!("0.0.0.0 {domain}"),
        SimpleKind::HostsLocal4 => format!("127.0.0.1 {domain}"),
        SimpleKind::HostsZero6 => format!(":: {domain}"),
        SimpleKind::HostsLocal6 => format!("::1 {domain}"),
    }
}

/// 整行原文是否恰好等于该形态的规范写法（是则无需保存原文，命中时重建）
fn is_canonical_rule_text(line: &str, kind: SimpleKind, domain: &str, is_allow: bool) -> bool {
    let rest = if is_allow {
        match line.strip_prefix("@@") {
            Some(rest) => rest,
            None => return false,
        }
    } else {
        line
    };
    match kind {
        SimpleKind::Suffix => {
            rest.strip_prefix("||")
                .and_then(|value| value.strip_suffix('^'))
                == Some(domain)
        }
        SimpleKind::ExactPlain => rest == domain,
        SimpleKind::HostsZero4 => rest.strip_prefix("0.0.0.0 ") == Some(domain),
        SimpleKind::HostsLocal4 => rest.strip_prefix("127.0.0.1 ") == Some(domain),
        SimpleKind::HostsZero6 => rest.strip_prefix(":: ") == Some(domain),
        SimpleKind::HostsLocal6 => rest.strip_prefix("::1 ") == Some(domain),
    }
}

impl ComplexRule {
    fn matches(&self, domain: &str, qtype: u16, important: bool) -> bool {
        self.important == important
            && self.query_types.matches(qtype)
            && !self
                .denyallow
                .iter()
                .any(|excluded| domain_matches(domain, excluded))
    }
}

impl RuleType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Suffix => "suffix",
            Self::Hosts => "hosts",
        }
    }
}

impl QueryTypes {
    fn matches(&self, qtype: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Include(types) => types.contains(&qtype),
            Self::Exclude(types) => !types.contains(&qtype),
        }
    }
}

/// 简单域名集合：命中域名本身或其任意父域名即算匹配，用于日志忽略等场景。
#[derive(Clone, Default)]
pub(crate) struct DomainSet {
    domains: HashSet<String>,
}

impl DomainSet {
    pub(crate) fn contains(&self, domain: &str) -> bool {
        if self.domains.is_empty() {
            return false;
        }
        if self.domains.contains(domain) {
            return true;
        }

        let mut offset = 0;
        while let Some(dot_index) = domain[offset..].find('.') {
            offset += dot_index + 1;
            if self.domains.contains(&domain[offset..]) {
                return true;
            }
        }

        false
    }
}

pub(crate) fn compile_domain_set(raw: &str) -> DomainSet {
    let mut domains = HashSet::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }

        let pattern = trimmed.strip_prefix("*.").unwrap_or(trimmed);
        if let Some(domain) = normalize_domain(pattern) {
            domains.insert(domain.into_owned());
        }
    }
    DomainSet { domains }
}

/// 解析出的单条规则：域名尽量借用原文本，只有插入索引时才转为独立分配
struct RuleData<'a> {
    domain: Cow<'a, str>,
    include_subdomains: bool,
    raw: &'a str,
    rule_type: RuleType,
    important: bool,
    query_types: QueryTypes,
    denyallow: Vec<Box<str>>,
    canonical: Option<SimpleKind>,
}

enum ParsedRule<'a> {
    Block(RuleData<'a>),
    Allow(RuleData<'a>),
    Ignored(IgnoredRuleReason),
    Disable,
}

enum IgnoredRuleReason {
    Comment,
    Regex,
    Unsupported,
    Invalid,
}

fn parse_rule(line: &str) -> ParsedRule<'_> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return ParsedRule::Ignored(IgnoredRuleReason::Comment);
    }

    parse_filter_rule(trimmed)
}

fn parse_hosts_rules(line: &str) -> Option<(SimpleKind, Vec<Option<Cow<'_, str>>>)> {
    let mut parts = line.split_whitespace();
    let ip = parts.next()?;
    let kind = match ip {
        "0.0.0.0" => SimpleKind::HostsZero4,
        "127.0.0.1" => SimpleKind::HostsLocal4,
        "::" => SimpleKind::HostsZero6,
        "::1" => SimpleKind::HostsLocal6,
        _ => return None,
    };
    let domains = parts
        .take_while(|token| !token.starts_with('#') && !token.starts_with('!'))
        .map(normalize_domain)
        .collect::<Vec<_>>();
    if domains.is_empty() {
        return Some((kind, vec![None]));
    }
    Some((kind, domains))
}

fn parse_filter_rule(line: &str) -> ParsedRule<'_> {
    let (is_allow, rest) = if let Some(value) = line.strip_prefix("@@") {
        (true, value)
    } else {
        (false, line)
    };

    let (pattern, modifiers) = rest.split_once('$').unwrap_or((rest, ""));
    let Ok(modifiers) = parse_modifiers(modifiers) else {
        return ParsedRule::Ignored(IgnoredRuleReason::Unsupported);
    };
    if modifiers.badfilter {
        return ParsedRule::Disable;
    }

    let Some(mut rule) = parse_pattern(pattern.trim()) else {
        return ParsedRule::Ignored(ignored_pattern_reason(pattern.trim()));
    };
    rule.raw = line;
    rule.important = modifiers.important;
    rule.query_types = modifiers.query_types;
    rule.denyallow = modifiers.denyallow;

    if !rule.important && rule.query_types == QueryTypes::Any && rule.denyallow.is_empty() {
        let kind = match rule.rule_type {
            RuleType::Suffix => SimpleKind::Suffix,
            RuleType::Exact | RuleType::Hosts => SimpleKind::ExactPlain,
        };
        rule.canonical = is_canonical_rule_text(line, kind, &rule.domain, is_allow).then_some(kind);
    }

    if is_allow {
        ParsedRule::Allow(rule)
    } else {
        ParsedRule::Block(rule)
    }
}

fn parse_pattern(pattern: &str) -> Option<RuleData<'_>> {
    if pattern.starts_with('/') && pattern.ends_with('/') {
        return None;
    }

    if let Some(rest) = pattern.strip_prefix("||") {
        let domain = rest.trim_end_matches('^').trim_end_matches('|');
        return normalize_domain(domain).map(|domain| RuleData {
            domain,
            include_subdomains: true,
            raw: "",
            rule_type: RuleType::Suffix,
            important: false,
            query_types: QueryTypes::Any,
            denyallow: Vec::new(),
            canonical: None,
        });
    }

    let stripped = pattern.trim_matches('|').trim_end_matches('^');
    let include_subdomains = pattern.starts_with("*.");
    let domain = stripped.strip_prefix("*.").unwrap_or(stripped);

    normalize_domain(domain).map(|domain| RuleData {
        domain,
        include_subdomains,
        raw: "",
        rule_type: if include_subdomains {
            RuleType::Suffix
        } else {
            RuleType::Exact
        },
        important: false,
        query_types: QueryTypes::Any,
        denyallow: Vec::new(),
        canonical: None,
    })
}

#[derive(Default)]
struct Modifiers {
    important: bool,
    badfilter: bool,
    query_types: QueryTypes,
    denyallow: Vec<Box<str>>,
}

fn parse_modifiers(raw: &str) -> Result<Modifiers, ()> {
    let mut parsed = Modifiers::default();
    if raw.is_empty() {
        return Ok(parsed);
    }
    for modifier in raw.split(',') {
        let lower = modifier.to_ascii_lowercase();
        if lower == "important" {
            parsed.important = true;
        } else if lower == "badfilter" {
            parsed.badfilter = true;
        } else if let Some(value) = lower.strip_prefix("dnstype=") {
            parsed.query_types = parse_query_types(value)?;
        } else if let Some(value) = lower.strip_prefix("denyallow=") {
            parsed.denyallow = value
                .split('|')
                .map(|part| {
                    normalize_domain(part).map(|domain| domain.into_owned().into_boxed_str())
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(())?;
            if parsed.denyallow.is_empty() {
                return Err(());
            }
        } else {
            return Err(());
        }
    }
    Ok(parsed)
}

fn parse_query_types(raw: &str) -> Result<QueryTypes, ()> {
    let values = raw.split('|').collect::<Vec<_>>();
    if values.is_empty() {
        return Err(());
    }
    let excluded = values[0].starts_with('~');
    let mut types = Vec::with_capacity(values.len());
    for value in values {
        if value.starts_with('~') != excluded {
            return Err(());
        }
        types.push(query_type_number(value.trim_start_matches('~')).ok_or(())?);
    }
    Ok(if excluded {
        QueryTypes::Exclude(types.into_boxed_slice())
    } else {
        QueryTypes::Include(types.into_boxed_slice())
    })
}

fn query_type_number(value: &str) -> Option<u16> {
    match value.to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        "NAPTR" => Some(35),
        "DS" => Some(43),
        "RRSIG" => Some(46),
        "NSEC" => Some(47),
        "DNSKEY" => Some(48),
        "TLSA" => Some(52),
        "SVCB" => Some(64),
        "HTTPS" => Some(65),
        "CAA" => Some(257),
        "ANY" => Some(255),
        value => value.parse().ok().filter(|value| *value > 0),
    }
}

fn badfilter_target(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let (pattern, modifiers) = trimmed.split_once('$')?;
    let remaining = modifiers
        .split(',')
        .filter(|modifier| !modifier.eq_ignore_ascii_case("badfilter"))
        .collect::<Vec<_>>();
    if remaining.len() == modifiers.split(',').count() {
        return None;
    }
    if remaining.is_empty() {
        Some(pattern.to_string())
    } else {
        Some(format!("{pattern}${}", remaining.join(",")))
    }
}

fn domain_matches(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || domain
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn ignored_pattern_reason(pattern: &str) -> IgnoredRuleReason {
    if pattern.starts_with('/') && pattern.ends_with('/') {
        IgnoredRuleReason::Regex
    } else {
        IgnoredRuleReason::Invalid
    }
}

fn normalize_domain(value: &str) -> Option<Cow<'_, str>> {
    let domain = value.trim().trim_end_matches('.');

    if domain.is_empty() {
        return None;
    }
    if domain.contains('/') || domain.contains('*') || domain.contains(' ') {
        return None;
    }
    if !domain
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return None;
    }

    if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Some(Cow::Owned(domain.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(domain))
    }
}
