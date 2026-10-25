use std::time::Instant;

use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

use crate::engine::aggregate::{eval_single_line, AggregateQuery, AggregateSummary};
use crate::engine::kmp_seam::{build_kmp_table, kmp_count};
use crate::engine::regex_compile::GrepMode;
use crate::grammar::GrammarDag;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationBench {
    pub operation: String,
    pub buttlick_us: u64,
    pub raw_scan_us: u64,
    pub speedup_x: f64,
    pub verified_result: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BenchReport {
    pub uncompressed_bytes: u64,
    pub archive_bytes: u64,
    pub num_rules: usize,
    pub dag_height: u16,
    pub compression_ratio: f64,
    pub compress_ms: f64,
    pub benchmarks: Vec<OperationBench>,
}

/// Generates a realistic repetitive structured server log dataset of `target_bytes` bytes.
pub fn generate_synthetic_log_dataset(target_bytes: usize) -> Vec<u8> {
    let mut base_cluster = Vec::with_capacity(64 * 1024);
    for i in 0..500 {
        let line = if i % 25 == 0 {
            format!(
                "2026-10-24T19:00:{:02}Z ERROR service=checkout status=500 latency={}\n",
                i % 60,
                250 + (i % 40)
            )
        } else if i % 10 == 0 {
            format!(
                "2026-10-24T19:00:{:02}Z WARN service=auth status=429 latency={}\n",
                i % 60,
                80 + (i % 20)
            )
        } else {
            format!(
                "2026-10-24T19:00:{:02}Z INFO service=api status=200 latency={}\n",
                i % 60,
                15 + (i % 15)
            )
        };
        base_cluster.extend_from_slice(line.as_bytes());
    }

    let mut out = Vec::with_capacity(target_bytes + base_cluster.len());
    while out.len() < target_bytes {
        let remaining = target_bytes - out.len();
        if remaining >= base_cluster.len() {
            out.extend_from_slice(&base_cluster);
        } else {
            // Cut cleanly at a newline boundary if possible
            let slice = &base_cluster[..remaining];
            out.extend_from_slice(slice);
            break;
        }
    }
    out
}

/// Runs the built-in benchmark suite comparing Buttlick zero-decompression compute against
/// raw uncompressed scans and asserting 100% bit-exact agreement on every query.
pub fn run_benchmarks(size_mb: usize) -> BenchReport {
    let target_bytes = size_mb.max(1) * 1024 * 1024;
    let raw_data = generate_synthetic_log_dataset(target_bytes);

    let t_comp = Instant::now();
    let dag = GrammarDag::from_bytes(&raw_data);
    let compress_ms = t_comp.elapsed().as_secs_f64() * 1000.0;

    let inspect = dag.inspect_report(None);
    let mut benchmarks = Vec::new();

    // 1. Exact Pattern Count ("ERROR")
    let pattern = b"ERROR";
    let t0 = Instant::now();
    let bt_count = dag.count_literal(None, pattern).unwrap();
    let bt_count_us = t0.elapsed().as_micros() as u64;

    let t1 = Instant::now();
    let pi = build_kmp_table(pattern);
    let raw_count = kmp_count(&raw_data, pattern, &pi);
    let raw_count_us = t1.elapsed().as_micros() as u64;
    assert_eq!(bt_count, raw_count);

    benchmarks.push(OperationBench {
        operation: "Exact Substring Count ('ERROR')".to_string(),
        buttlick_us: bt_count_us.max(1),
        raw_scan_us: raw_count_us.max(1),
        speedup_x: (raw_count_us.max(1) as f64) / (bt_count_us.max(1) as f64),
        verified_result: format!("count={bt_count}"),
    });

    // 2. O(log N) Substring Equality over two distinct 500+ MB spans
    // Choose `period` = length of one 500-line cluster so `[0..span]` and `[period..period+span]`
    // are at distinct memory addresses but contain identical byte sequences.
    let mut period = 0usize;
    let mut nl_seen = 0usize;
    for (idx, &b) in raw_data.iter().enumerate() {
        if b == b'\n' {
            nl_seen += 1;
            if nl_seen == 500 {
                period = idx + 1;
                break;
            }
        }
    }
    let pos2 = if period > 0 && period * 2 < raw_data.len() {
        period as u64
    } else {
        0
    };
    let span = (raw_data.len() as u64 - pos2) / 2;

    let t0 = Instant::now();
    let bt_eq = std::hint::black_box(dag.substring_eq(None, 0, pos2, span).unwrap());
    let bt_eq_us = t0.elapsed().as_micros() as u64;

    let t1 = Instant::now();
    let slice_a = std::hint::black_box(&raw_data[0..span as usize]);
    let slice_b = std::hint::black_box(&raw_data[pos2 as usize..(pos2 + span) as usize]);
    let raw_eq = std::hint::black_box(slice_a == slice_b);
    let raw_eq_us = t1.elapsed().as_micros() as u64;
    assert_eq!(bt_eq, raw_eq);

    benchmarks.push(OperationBench {
        operation: format!(
            "O(log N) Substring Equality ({} MB span)",
            (span / (1024 * 1024)).max(1)
        ),
        buttlick_us: bt_eq_us.max(1),
        raw_scan_us: raw_eq_us.max(1),
        speedup_x: (raw_eq_us.max(1) as f64) / (bt_eq_us.max(1) as f64),
        verified_result: format!("equal={bt_eq}"),
    });

    // 3. Zero-Decompression Regex Line Grep ("status=500.*latency=[0-9]+")
    let regex_pat = "status=500.*latency=[0-9]+";
    let t0 = Instant::now();
    let bt_grep = dag.grep(None, regex_pat, GrepMode::LineCount).unwrap();
    let bt_grep_us = t0.elapsed().as_micros() as u64;

    let t1 = Instant::now();
    let re = Regex::new(regex_pat).unwrap();
    let raw_slice = if raw_data.last() == Some(&b'\n') {
        &raw_data[..raw_data.len() - 1]
    } else {
        &raw_data[..]
    };
    let raw_grep = raw_slice
        .split(|&b| b == b'\n')
        .filter(|line| re.is_match(line))
        .count() as u64;
    let raw_grep_us = t1.elapsed().as_micros() as u64;
    assert_eq!(bt_grep, raw_grep);

    benchmarks.push(OperationBench {
        operation: "Regex Line Grep ('status=500.*latency=[0-9]+')".to_string(),
        buttlick_us: bt_grep_us.max(1),
        raw_scan_us: raw_grep_us.max(1),
        speedup_x: (raw_grep_us.max(1) as f64) / (bt_grep_us.max(1) as f64),
        verified_result: format!("lines={bt_grep}"),
    });

    // 4. Zero-Decompression Structured Analytics (SUM/MIN/MAX/COUNT where status=200)
    let agg_query = AggregateQuery {
        delimiter: b' ',
        target_col: 4,
        filter: Some((3, b"200".to_vec())),
    };
    let t0 = Instant::now();
    let bt_agg = dag.aggregate_query(None, &agg_query).unwrap();
    let bt_agg_us = t0.elapsed().as_micros() as u64;

    let t1 = Instant::now();
    let mut raw_agg = AggregateSummary::empty();
    for line in raw_slice.split(|&b| b == b'\n') {
        raw_agg = raw_agg.combine(eval_single_line(line, &agg_query));
    }
    let raw_agg_us = t1.elapsed().as_micros() as u64;
    assert_eq!(bt_agg, raw_agg);

    benchmarks.push(OperationBench {
        operation: "Structured Analytics (SUM/MIN/MAX WHERE status=200)".to_string(),
        buttlick_us: bt_agg_us.max(1),
        raw_scan_us: raw_agg_us.max(1),
        speedup_x: (raw_agg_us.max(1) as f64) / (bt_agg_us.max(1) as f64),
        verified_result: format!("count={}, sum={}", bt_agg.count, bt_agg.sum),
    });

    BenchReport {
        uncompressed_bytes: inspect.total_uncompressed_bytes,
        archive_bytes: inspect.archive_bytes,
        num_rules: inspect.num_rules,
        dag_height: inspect.max_height,
        compression_ratio: inspect.compression_ratio,
        compress_ms,
        benchmarks,
    }
}
