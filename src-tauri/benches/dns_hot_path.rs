//! DNS 热路径基准。
//!
//! 覆盖每条查询都会走到的四段开销：规则编译（启动）、规则匹配、报文解析与
//! 拦截应答构造、缓存读写。跑法见 README 的「性能基准」一节。

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use dnsblackhole_lib::bench_api;

/// 构造一份接近真实清单规模的规则文本：
/// 以 `||domain^` 为主，混入 hosts 行、allowlist、带修饰符规则和注释。
fn synthetic_rules(count: usize) -> String {
    let mut rules = String::with_capacity(count * 32);
    rules.push_str("! dnsblackhole-source:基准清单\n");
    for index in 0..count {
        match index % 16 {
            0 => rules.push_str(&format!("0.0.0.0 hosts-{index}.example.com\n")),
            7 => rules.push_str(&format!("@@||allow-{index}.example.com^\n")),
            11 => rules.push_str(&format!("||typed-{index}.example.com^$dnstype=A\n")),
            13 => rules.push_str(&format!("! 注释行 {index}\n")),
            _ => rules.push_str(&format!("||ads-{index}.tracker-{index}.example.com^\n")),
        }
    }
    rules
}

fn bench_rule_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_compile");
    // 编译只在启动和规则热替换时发生，样本量小一些即可。
    group.sample_size(10);
    for count in [10_000_usize, 100_000] {
        let raw = synthetic_rules(count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &raw, |b, raw| {
            b.iter(|| black_box(bench_api::compile_rules(black_box(raw))));
        });
    }
    group.finish();
}

fn bench_rule_match(c: &mut Criterion) {
    let rules = bench_api::compile_rules(&synthetic_rules(100_000));
    let mut group = c.benchmark_group("rule_match");
    group.throughput(Throughput::Elements(1));

    // 直接命中：域名就是规则本身。
    group.bench_function("hit_exact", |b| {
        b.iter(|| {
            black_box(bench_api::is_blocked(
                &rules,
                black_box("ads-500.tracker-500.example.com"),
                1,
            ))
        });
    });

    // 子域命中：需要沿标签逐级回退，是最坏的命中路径。
    group.bench_function("hit_subdomain", |b| {
        b.iter(|| {
            black_box(bench_api::is_blocked(
                &rules,
                black_box("a.b.c.ads-500.tracker-500.example.com"),
                1,
            ))
        });
    });

    // 未命中：必须走完全部后缀回退才能确认放行，是最常见的开销。
    group.bench_function("miss", |b| {
        b.iter(|| {
            black_box(bench_api::is_blocked(
                &rules,
                black_box("www.some-unlisted-domain.example.net"),
                1,
            ))
        });
    });
    group.finish();
}

fn bench_packet_path(c: &mut Criterion) {
    let query = bench_api::build_query("www.example.com", 1);
    let mut group = c.benchmark_group("packet");
    group.throughput(Throughput::Elements(1));

    group.bench_function("parse_query", |b| {
        b.iter(|| black_box(bench_api::parse_query_len(black_box(&query))));
    });

    group.bench_function("build_block_response", |b| {
        b.iter(|| black_box(bench_api::build_block_response(black_box(&query))));
    });
    group.finish();
}

fn bench_cache(c: &mut Criterion) {
    let config = bench_api::default_config();
    let Some(cache) = bench_api::build_cache(&config) else {
        return;
    };

    // 预热若干条目，让查找面对的是有真实规模的分片表。
    let queries = (0..1_000)
        .map(|index| bench_api::build_query(&format!("cached-{index}.example.com"), 1))
        .collect::<Vec<_>>();
    for query in &queries {
        let Some(response) = cached_response(query) else {
            continue;
        };
        bench_api::cache_insert(&cache, query, response);
    }

    let mut group = c.benchmark_group("cache");
    group.throughput(Throughput::Elements(1));
    group.bench_function("lookup_hit", |b| {
        b.iter(|| black_box(bench_api::cache_lookup(&cache, black_box(&queries[500]))));
    });

    let missing = bench_api::build_query("not-cached.example.com", 1);
    group.bench_function("lookup_miss", |b| {
        b.iter(|| black_box(bench_api::cache_lookup(&cache, black_box(&missing))));
    });
    group.finish();
}

/// 造一条带 300 秒 TTL 的 A 应答，供缓存基准写入。
fn cached_response(query: &[u8]) -> Option<Vec<u8>> {
    let question_end = bench_api::parse_query_len(query)?;
    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[0..2]);
    response.push(0x81);
    response.push(0x80);
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&300_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&[93, 184, 216, 34]);
    Some(response)
}

criterion_group!(
    benches,
    bench_rule_compile,
    bench_rule_match,
    bench_packet_path,
    bench_cache
);
criterion_main!(benches);
