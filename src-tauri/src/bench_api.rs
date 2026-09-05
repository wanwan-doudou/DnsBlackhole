//! 基准测试用的公开门面。
//!
//! DNS 热路径的类型都是 `pub(crate)`，criterion 基准作为独立 crate 无法直接访问。
//! 这里只在 `bench` feature 下暴露一层极薄的包装，不改变任何运行时行为，
//! 也不会进入正式构建产物。

use crate::{
    config::AppConfig,
    dns::bench_support::{self, BenchCache, BenchRules},
};

/// 编译规则文本，返回可重复匹配的规则集。
pub fn compile_rules(raw: &str) -> BenchRules {
    bench_support::compile_rules(raw)
}

/// 判断域名是否命中拦截规则，等价于 DNS worker 的过滤判定入口。
pub fn is_blocked(rules: &BenchRules, domain: &str, qtype: u16) -> bool {
    bench_support::is_blocked(rules, domain, qtype)
}

/// 构造一个标准 A 查询报文。
pub fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
    bench_support::build_query(domain, qtype)
}

/// 解析查询报文并返回 question 段长度，覆盖收包后的第一步开销。
pub fn parse_query_len(packet: &[u8]) -> Option<usize> {
    bench_support::parse_query_len(packet)
}

/// 按默认拦截方式构造拦截应答。
pub fn build_block_response(packet: &[u8]) -> Option<Vec<u8>> {
    bench_support::build_block_response(packet)
}

/// 建一个用于基准的 DNS 缓存实例。
pub fn build_cache(config: &AppConfig) -> Option<BenchCache> {
    bench_support::build_cache(config)
}

/// 向缓存写入一条应答。
pub fn cache_insert(cache: &BenchCache, packet: &[u8], response: Vec<u8>) {
    bench_support::cache_insert(cache, packet, response);
}

/// 查询缓存，返回是否命中。
pub fn cache_lookup(cache: &BenchCache, packet: &[u8]) -> bool {
    bench_support::cache_lookup(cache, packet)
}

/// 默认配置，供基准构造缓存等运行时组件。
pub fn default_config() -> AppConfig {
    AppConfig::default()
}
