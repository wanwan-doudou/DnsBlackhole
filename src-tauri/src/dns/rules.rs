use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct RuleSummary {
    pub block_rules: usize,
    pub allow_rules: usize,
    pub ignored_rules: usize,
    pub ignored_comment_rules: usize,
    pub ignored_regex_rules: usize,
    pub ignored_unsupported_rules: usize,
    pub ignored_invalid_rules: usize,
}

#[derive(Clone)]
pub struct CompiledRules {
    blocks: RuleSet,
    allows: RuleSet,
    /// 清单名称表：规则条目里只存索引，避免几百万条规则各克隆一份清单名
    sources: Vec<Box<str>>,
    summary: RuleSummary,
}

#[derive(Clone, Default)]
struct RuleSet {
    exact: HashMap<Box<str>, RuleEntry>,
    suffix: HashMap<Box<str>, RuleEntry>,
}

/// 绝大多数规则是无修饰符的规范写法（如 `||domain^`），原文可以在命中时由域名重建，
/// 压缩成 4 字节的 Simple；带修饰符、非规范写法或同域名多条规则时才升级为完整形态。
#[derive(Clone)]
enum RuleEntry {
    Simple(SimpleRule),
    Complex(Box<[ComplexRule]>),
}

#[derive(Clone, Copy)]
struct SimpleRule {
    source_id: u16,
    kind: SimpleKind,
}

/// 能够由域名逐字节重建规则原文的规范形态
#[derive(Clone, Copy)]
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

#[derive(Clone)]
struct ComplexRule {
    raw: Box<str>,
    source_id: u16,
    rule_type: RuleType,
    important: bool,
    query_types: QueryTypes,
    denyallow: Box<[Box<str>]>,
}

#[derive(Clone, Default, PartialEq)]
enum QueryTypes {
    #[default]
    Any,
    Include(Box<[u16]>),
    Exclude(Box<[u16]>),
}

#[derive(Debug, Clone, Copy)]
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
fn scan_rules<'a>(raw: &'a str, mut handle: impl FnMut(ScanEvent<'a>)) {
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
        if disabled.contains(trimmed) {
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

pub fn compile_rules(raw: &str) -> CompiledRules {
    let mut blocks = RuleSet::default();
    let mut allows = RuleSet::default();
    let mut summary = RuleSummary::default();
    let mut sources: Vec<Box<str>> = vec![DEFAULT_SOURCE.into()];
    let mut source_id: u16 = 0;

    scan_rules(raw, |event| match event {
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

    CompiledRules {
        blocks,
        allows,
        sources,
        summary,
    }
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

    #[cfg(test)]
    pub(crate) fn is_blocked(&self, domain: &str, qtype: u16) -> bool {
        self.blocking_match(domain, qtype).is_some()
    }

    pub(crate) fn blocking_match(&self, domain: &str, qtype: u16) -> Option<BlockMatch> {
        let important_allow = self.allows.find_match(domain, qtype, true);
        if important_allow.is_some() {
            return None;
        }
        if let Some(block) = self.blocks.find_match(domain, qtype, true) {
            let allow = self.allows.find_match(domain, qtype, false);
            let important_overrode = allow.is_some();
            return Some(self.build_block_match(block, allow, important_overrode));
        }
        if self.allows.find_match(domain, qtype, false).is_some() {
            return None;
        }
        self.blocks
            .find_match(domain, qtype, false)
            .map(|block| self.build_block_match(block, None, false))
    }

    fn build_block_match(
        &self,
        block: MatchedRule<'_>,
        allow: Option<MatchedRule<'_>>,
        important_overrode: bool,
    ) -> BlockMatch {
        BlockMatch {
            rule: block.raw_text(false),
            source: self.source_name(block.source_id),
            rule_type: format!("{} block", block.rule_type.as_str()),
            important_overrode,
            allowlist_rule: allow.map(|rule| rule.raw_text(true)),
        }
    }

    fn source_name(&self, source_id: u16) -> String {
        self.sources
            .get(usize::from(source_id))
            .map(|name| name.to_string())
            .unwrap_or_else(|| DEFAULT_SOURCE.to_string())
    }
}

impl RuleSet {
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

    fn find_match(&self, domain: &str, qtype: u16, important: bool) -> Option<MatchedRule<'_>> {
        if let Some(found) = lookup_entry(&self.exact, domain, domain, qtype, important) {
            return Some(found);
        }
        if let Some(found) = lookup_entry(&self.suffix, domain, domain, qtype, important) {
            return Some(found);
        }

        let mut offset = 0;
        while let Some(dot_index) = domain[offset..].find('.') {
            offset += dot_index + 1;
            if let Some(found) =
                lookup_entry(&self.suffix, &domain[offset..], domain, qtype, important)
            {
                return Some(found);
            }
        }

        None
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
