use std::collections::HashSet;

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct RuleSummary {
    pub block_rules: usize,
    pub allow_rules: usize,
    pub ignored_rules: usize,
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
}

#[derive(Clone, Default)]
struct RuleSet {
    exact: HashSet<String>,
    suffix: HashSet<String>,
}

pub fn summarize_rules(raw: &str) -> RuleSummary {
    compile_rules(raw).summary
}

pub fn compile_rules(raw: &str) -> CompiledRules {
    let mut blocks = RuleSet::default();
    let mut allows = RuleSet::default();
    let mut summary = RuleSummary::default();

    for line in raw.lines() {
        match parse_rule(line) {
            ParsedRule::Block(rule) => {
                summary.block_rules += 1;
                blocks.insert(rule);
            }
            ParsedRule::Allow(rule) => {
                summary.allow_rules += 1;
                allows.insert(rule);
            }
            ParsedRule::Ignored => summary.ignored_rules += 1,
        }
    }

    CompiledRules {
        blocks,
        allows,
        summary,
    }
}

impl CompiledRules {
    pub(crate) fn is_blocked(&self, domain: &str) -> bool {
        if self.allows.contains(domain) {
            return false;
        }
        self.blocks.contains(domain)
    }
}

impl RuleSet {
    fn insert(&mut self, rule: Rule) {
        if rule.include_subdomains {
            self.suffix.insert(rule.domain);
        } else {
            self.exact.insert(rule.domain);
        }
    }

    fn contains(&self, domain: &str) -> bool {
        if self.exact.contains(domain) || self.suffix.contains(domain) {
            return true;
        }

        let mut offset = 0;
        while let Some(dot_index) = domain[offset..].find('.') {
            offset += dot_index + 1;
            if self.suffix.contains(&domain[offset..]) {
                return true;
            }
        }

        false
    }
}

enum ParsedRule {
    Block(Rule),
    Allow(Rule),
    Ignored,
}

fn parse_rule(line: &str) -> ParsedRule {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return ParsedRule::Ignored;
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
    })
}

fn parse_filter_rule(line: &str) -> ParsedRule {
    let (is_allow, rest) = if let Some(value) = line.strip_prefix("@@") {
        (true, value)
    } else {
        (false, line)
    };

    let pattern = rest.split('$').next().unwrap_or(rest).trim();
    let Some(rule) = parse_pattern(pattern) else {
        return ParsedRule::Ignored;
    };

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
    })
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
