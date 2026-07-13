use std::collections::{HashMap, HashSet};

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
    summary: RuleSummary,
}

#[derive(Clone)]
struct Rule {
    domain: String,
    include_subdomains: bool,
    raw: String,
    source: String,
    rule_type: RuleType,
    important: bool,
    query_types: QueryTypes,
    denyallow: Vec<String>,
}

#[derive(Clone, Default)]
struct RuleSet {
    exact: HashMap<String, Vec<RuleOptions>>,
    suffix: HashMap<String, Vec<RuleOptions>>,
}

#[derive(Clone)]
struct RuleOptions {
    raw: String,
    source: String,
    rule_type: RuleType,
    important: bool,
    query_types: QueryTypes,
    denyallow: Vec<String>,
}

#[derive(Clone, Default)]
enum QueryTypes {
    #[default]
    Any,
    Include(Vec<u16>),
    Exclude(Vec<u16>),
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

const SOURCE_MARKER_PREFIX: &str = "! dnsblackhole-source:";

pub fn summarize_rules(raw: &str) -> RuleSummary {
    compile_rules(raw).summary
}

pub fn compile_rules(raw: &str) -> CompiledRules {
    let mut blocks = RuleSet::default();
    let mut allows = RuleSet::default();
    let mut summary = RuleSummary::default();

    let disabled = raw
        .lines()
        .filter_map(badfilter_target)
        .collect::<HashSet<_>>();

    let mut source = "自定义规则".to_string();
    for line in raw.lines() {
        if let Some(encoded) = line.trim().strip_prefix(SOURCE_MARKER_PREFIX) {
            if let Ok(value) = serde_json::from_str::<String>(encoded) {
                source = value;
            }
            continue;
        }
        if disabled.contains(line.trim()) {
            continue;
        }
        match parse_rule(line) {
            ParsedRule::Block(mut rule) => {
                rule.source.clone_from(&source);
                summary.block_rules += 1;
                blocks.insert(rule);
            }
            ParsedRule::Allow(mut rule) => {
                rule.source.clone_from(&source);
                summary.allow_rules += 1;
                allows.insert(rule);
            }
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

    CompiledRules {
        blocks,
        allows,
        summary,
    }
}

impl CompiledRules {
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
            return Some(block.to_block_match(allow, important_overrode));
        }
        if self.allows.find_match(domain, qtype, false).is_some() {
            return None;
        }
        self.blocks
            .find_match(domain, qtype, false)
            .map(|block| block.to_block_match(None, false))
    }
}

impl RuleSet {
    fn insert(&mut self, rule: Rule) {
        let options = RuleOptions {
            raw: rule.raw,
            source: rule.source,
            rule_type: rule.rule_type,
            important: rule.important,
            query_types: rule.query_types,
            denyallow: rule.denyallow,
        };
        if rule.include_subdomains {
            self.suffix.entry(rule.domain).or_default().push(options);
        } else {
            self.exact.entry(rule.domain).or_default().push(options);
        }
    }

    fn find_match(&self, domain: &str, qtype: u16, important: bool) -> Option<&RuleOptions> {
        if let Some(rule) = self.exact.get(domain).and_then(|rules| {
            rules
                .iter()
                .find(|rule| rule.matches(domain, qtype, important))
        }) {
            return Some(rule);
        }
        if let Some(rule) = self.suffix.get(domain).and_then(|rules| {
            rules
                .iter()
                .find(|rule| rule.matches(domain, qtype, important))
        }) {
            return Some(rule);
        }

        let mut offset = 0;
        while let Some(dot_index) = domain[offset..].find('.') {
            offset += dot_index + 1;
            if let Some(rule) = self.suffix.get(&domain[offset..]).and_then(|rules| {
                rules
                    .iter()
                    .find(|rule| rule.matches(domain, qtype, important))
            }) {
                return Some(rule);
            }
        }

        None
    }
}

impl RuleOptions {
    fn matches(&self, domain: &str, qtype: u16, important: bool) -> bool {
        self.important == important
            && self.query_types.matches(qtype)
            && !self
                .denyallow
                .iter()
                .any(|excluded| domain_matches(domain, excluded))
    }

    fn to_block_match(&self, allow: Option<&RuleOptions>, important_overrode: bool) -> BlockMatch {
        BlockMatch {
            rule: self.raw.clone(),
            source: self.source.clone(),
            rule_type: format!("{} block", self.rule_type.as_str()),
            important_overrode,
            allowlist_rule: allow.map(|rule| rule.raw.clone()),
        }
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
            domains.insert(domain);
        }
    }
    DomainSet { domains }
}

enum ParsedRule {
    Block(Rule),
    Allow(Rule),
    Ignored(IgnoredRuleReason),
    Disable,
}

enum IgnoredRuleReason {
    Comment,
    Regex,
    Unsupported,
    Invalid,
}

fn parse_rule(line: &str) -> ParsedRule {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return ParsedRule::Ignored(IgnoredRuleReason::Comment);
    }

    if let Some(rule) = parse_hosts_rule(trimmed) {
        return ParsedRule::Block(rule);
    }

    parse_filter_rule(trimmed)
}

fn parse_hosts_rule(line: &str) -> Option<Rule> {
    let mut parts = line.split_whitespace();
    let ip = parts.next()?;
    let domain = parts.next()?;
    let is_block_ip = matches!(ip, "0.0.0.0" | "127.0.0.1" | "::" | "::1");
    if !is_block_ip {
        return None;
    }

    normalize_domain(domain).map(|domain| Rule {
        domain,
        include_subdomains: false,
        raw: line.to_string(),
        source: String::new(),
        rule_type: RuleType::Hosts,
        important: false,
        query_types: QueryTypes::Any,
        denyallow: Vec::new(),
    })
}

fn parse_filter_rule(line: &str) -> ParsedRule {
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
    rule.raw = line.to_string();
    rule.important = modifiers.important;
    rule.query_types = modifiers.query_types;
    rule.denyallow = modifiers.denyallow;

    if is_allow {
        ParsedRule::Allow(rule)
    } else {
        ParsedRule::Block(rule)
    }
}

fn parse_pattern(pattern: &str) -> Option<Rule> {
    if pattern.starts_with('/') && pattern.ends_with('/') {
        return None;
    }

    if let Some(rest) = pattern.strip_prefix("||") {
        let domain = rest.trim_end_matches('^').trim_end_matches('|');
        return normalize_domain(domain).map(|domain| Rule {
            domain,
            include_subdomains: true,
            raw: String::new(),
            source: String::new(),
            rule_type: RuleType::Suffix,
            important: false,
            query_types: QueryTypes::Any,
            denyallow: Vec::new(),
        });
    }

    let domain = pattern
        .trim_matches('|')
        .trim_end_matches('^')
        .strip_prefix("*.")
        .unwrap_or_else(|| pattern.trim_matches('|').trim_end_matches('^'));
    let include_subdomains = pattern.starts_with("*.");

    normalize_domain(domain).map(|domain| Rule {
        domain,
        include_subdomains,
        raw: String::new(),
        source: String::new(),
        rule_type: if include_subdomains {
            RuleType::Suffix
        } else {
            RuleType::Exact
        },
        important: false,
        query_types: QueryTypes::Any,
        denyallow: Vec::new(),
    })
}

#[derive(Default)]
struct Modifiers {
    important: bool,
    badfilter: bool,
    query_types: QueryTypes,
    denyallow: Vec<String>,
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
                .map(normalize_domain)
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
        QueryTypes::Exclude(types)
    } else {
        QueryTypes::Include(types)
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
    let mut remaining = modifiers
        .split(',')
        .filter(|modifier| !modifier.eq_ignore_ascii_case("badfilter"))
        .collect::<Vec<_>>();
    if remaining.len() == modifiers.split(',').count() {
        return None;
    }
    if remaining.is_empty() {
        Some(pattern.to_string())
    } else {
        Some(format!(
            "{pattern}${}",
            remaining.drain(..).collect::<Vec<_>>().join(",")
        ))
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

fn normalize_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();

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

    Some(domain)
}
