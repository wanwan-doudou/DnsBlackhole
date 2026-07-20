use std::sync::{Arc, RwLock};

use crate::config::AppConfig;

use super::{
    protocol::BlockingPolicy,
    rewrites::{CompiledRewrites, compile_rewrites},
    rules::{CompiledRules, DomainSet, compile_domain_set},
};

#[cfg(test)]
use super::rules::compile_rules;

/// 一次查询会用到的全部过滤状态。整体只读共享，更新时整包替换，
/// 让规则/清单/重写变更不需要重启 DNS 服务、不清空缓存。
pub(crate) struct FilterRuntime {
    pub(crate) rules: Arc<CompiledRules>,
    pub(crate) rewrites: CompiledRewrites,
    pub(crate) blocking: BlockingPolicy,
    pub(crate) log_ignore: DomainSet,
}

impl FilterRuntime {
    pub(crate) fn summary(&self) -> super::rules::RuleSummary {
        self.rules.summary()
    }
}

pub(crate) type SharedFilterRuntime = Arc<RwLock<Arc<FilterRuntime>>>;

#[cfg(test)]
pub(crate) fn build_filter_runtime(config: &AppConfig, rules_text: &str) -> FilterRuntime {
    build_filter_runtime_with_rules(config, Arc::new(compile_rules(rules_text)))
}

pub(crate) fn build_filter_runtime_with_rules(
    config: &AppConfig,
    rules: Arc<CompiledRules>,
) -> FilterRuntime {
    FilterRuntime {
        rules,
        rewrites: compile_rewrites(&config.dns_rewrites),
        blocking: BlockingPolicy::from_config(config),
        log_ignore: compile_domain_set(&config.query_log_ignored_domains),
    }
}

pub(crate) fn share_filter_runtime(runtime: FilterRuntime) -> SharedFilterRuntime {
    Arc::new(RwLock::new(Arc::new(runtime)))
}

pub(crate) fn current_filter_runtime(shared: &SharedFilterRuntime) -> Arc<FilterRuntime> {
    match shared.read() {
        Ok(guard) => Arc::clone(&guard),
        Err(poisoned) => Arc::clone(&poisoned.into_inner()),
    }
}

pub(crate) fn replace_filter_runtime(shared: &SharedFilterRuntime, runtime: FilterRuntime) {
    match shared.write() {
        Ok(mut guard) => *guard = Arc::new(runtime),
        Err(poisoned) => *poisoned.into_inner() = Arc::new(runtime),
    }
}
