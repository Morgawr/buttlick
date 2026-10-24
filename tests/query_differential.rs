use buttlick::engine::aggregate::{eval_single_line, AggregateQuery, AggregateSummary};
use buttlick::engine::regex_compile::GrepMode;
use buttlick::grammar::GrammarDag;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use regex::bytes::{Regex, RegexBuilder};

fn oracle_find_all_offsets(haystack: &[u8], needle: &[u8]) -> Vec<u64> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(i, w)| if w == needle { Some(i as u64) } else { None })
        .collect()
}

#[test]
fn test_differential_kmp_exact_search_and_offsets_500_cases() {
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE);

    for case in 0..500 {
        // Generate highly repetitive, periodic, and random inputs over small alphabets
        let alphabet_size = match case % 4 {
            0 => 1, // Pure runs ('A'...)
            1 => 2, // Binary periodic ('A', 'B')
            2 => 4, // DNA-like ('A', 'B', 'C', 'D')
            _ => 8,
        };
        let mut data = Vec::new();
        let num_blocks = rng.gen_range(1..=30);
        for _ in 0..num_blocks {
            let unit_len = rng.gen_range(1..=6);
            let unit: Vec<u8> = (0..unit_len)
                .map(|_| b'A' + rng.gen_range(0..alphabet_size))
                .collect();
            let repeat = rng.gen_range(1..=25);
            for _ in 0..repeat {
                data.extend_from_slice(&unit);
            }
        }

        let dag = GrammarDag::from_bytes(&data);
        dag.validate_invariants().unwrap();

        // Pick 3 patterns per input (including short, long, overlapping, and non-occurring)
        for _ in 0..3 {
            let pat_len = rng.gen_range(1..=12);
            let pat: Vec<u8> = if rng.gen_bool(0.7) && data.len() >= pat_len {
                let start = rng.gen_range(0..=data.len() - pat_len);
                data[start..start + pat_len].to_vec()
            } else {
                (0..pat_len)
                    .map(|_| b'A' + rng.gen_range(0..alphabet_size))
                    .collect()
            };

            let expected_offsets = oracle_find_all_offsets(&data, &pat);
            let expected_count = expected_offsets.len() as u64;

            let got_count = dag.count_literal(None, &pat).unwrap();
            assert_eq!(
                got_count, expected_count,
                "Count mismatch on case {case}, pat={:?}",
                String::from_utf8_lossy(&pat)
            );

            let (got_count2, got_offsets) = dag.locate_literal(None, &pat, usize::MAX).unwrap();
            assert_eq!(got_count2, expected_count);
            assert_eq!(
                got_offsets, expected_offsets,
                "Offsets mismatch on case {case}, pat={:?}",
                String::from_utf8_lossy(&pat)
            );

            // Also test limited top-K offset extraction
            let limit = rng.gen_range(1..=10);
            let (_, got_top_k) = dag.locate_literal(None, &pat, limit).unwrap();
            let expected_top_k: Vec<u64> = expected_offsets.into_iter().take(limit).collect();
            assert_eq!(got_top_k, expected_top_k);
        }
    }
}

#[test]
fn test_differential_regex_grep_and_structured_analytics() {
    let mut rng = StdRng::seed_from_u64(0x1234_5678);
    let services = ["auth", "api", "payment", "search"];
    let statuses = ["200", "201", "400", "404", "500"];

    for trial in 0..30 {
        let mut raw = Vec::new();
        let num_clusters = rng.gen_range(5..=25);
        for _ in 0..num_clusters {
            let svc = services[rng.gen_range(0..services.len())];
            let status = statuses[rng.gen_range(0..statuses.len())];
            let latency: i64 = rng.gen_range(-500..=5000);
            let line = format!("2026-10-24,{svc},{status},{latency}\n");
            let repeat = rng.gen_range(1..=40);
            for _ in 0..repeat {
                raw.extend_from_slice(line.as_bytes());
            }
        }
        // Randomly drop the trailing '\n' on odd trials (Pitfall 6)
        if trial % 2 == 1 && raw.last() == Some(&b'\n') {
            raw.pop();
        }

        let dag = GrammarDag::from_bytes(&raw);
        dag.validate_invariants().unwrap();

        let line_slice = if raw.last() == Some(&b'\n') {
            &raw[..raw.len() - 1]
        } else {
            &raw[..]
        };

        // 1. Differential Regex LineCount & MatchCount
        for pat in [
            ",500,",
            "^(2026-10-24),(auth|payment),",
            ",-[0-9]+$",
            ",(200|201),[0-9]{3,4}$",
        ] {
            let re_line = Regex::new(pat).unwrap();
            let expected_lines = if raw.is_empty() {
                0
            } else {
                line_slice
                    .split(|&b| b == b'\n')
                    .filter(|l| re_line.is_match(l))
                    .count() as u64
            };
            let got_lines = dag.grep(None, pat, GrepMode::LineCount).unwrap();
            assert_eq!(got_lines, expected_lines, "LineCount mismatch on trial {trial}, pat={pat}");

            let re_multi = RegexBuilder::new(pat).multi_line(true).build().unwrap();
            let expected_matches = re_multi.find_iter(&raw).count() as u64;
            let got_matches = dag.grep(None, pat, GrepMode::MatchCount).unwrap();
            assert_eq!(
                got_matches, expected_matches,
                "MatchCount mismatch on trial {trial}, pat={pat}"
            );
        }

        // 2. Differential Structured Analytics
        for filter in [
            None,
            Some((1usize, b"auth".to_vec())),
            Some((2usize, b"500".to_vec())),
            Some((2usize, b"200".to_vec())),
        ] {
            let q = AggregateQuery {
                delimiter: b',',
                target_col: 3,
                filter,
            };
            let got_agg = dag.aggregate_query(None, &q).unwrap();

            let mut expected_agg = AggregateSummary::empty();
            if !raw.is_empty() {
                for line in line_slice.split(|&b| b == b'\n') {
                    expected_agg = expected_agg.combine(eval_single_line(line, &q));
                }
            }
            assert_eq!(got_agg, expected_agg, "Aggregate mismatch on trial {trial}");
        }
    }
}
