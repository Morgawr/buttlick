//! Differential tests: zero-copy `MappedArchive` evaluators vs the fully decoded `GrammarDag`
//! (and vs brute-force oracles on the raw bytes).

use buttlick::engine::regex_compile::GrepMode;
use buttlick::format::MappedArchive;
use buttlick::grammar::GrammarDag;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tempfile::NamedTempFile;

fn sample_docs() -> Vec<(String, Vec<u8>)> {
    let mut rng = StdRng::seed_from_u64(0x5EED_CAFE);
    let words: [&[u8]; 10] = [
        b"spin_lock(&rq->lock);",
        b"mutex_lock(&m);",
        b"  kfree_rcu(p, rcu);",
        b"abcabcabcab",
        b"aaaaaaaaaaaaaaaa",
        b"\t\treturn -EINVAL;",
        b"struct task_struct *p;",
        b"x",
        b"",
        b"/* \xe3\x81\x82\xe3\x81\x84 */",
    ];
    let mut docs = Vec::new();
    for d in 0..6 {
        let mut doc = Vec::new();
        let lines = rng.gen_range(0..400);
        for _ in 0..lines {
            let n = rng.gen_range(1..4);
            for _ in 0..n {
                doc.extend_from_slice(words[rng.gen_range(0..words.len())]);
                if rng.gen_bool(0.3) {
                    doc.push(b' ');
                }
            }
            doc.push(b'\n');
        }
        if d % 2 == 1 {
            doc.extend_from_slice(b"trailing line without newline spin_lock(");
        }
        docs.push((format!("dir/doc{d}.c"), doc));
    }
    docs.push(("empty.txt".to_string(), Vec::new()));
    docs.push(("run.bin".to_string(), vec![b'a'; 100_000]));
    docs
}

fn build(docs: &[(String, Vec<u8>)]) -> (GrammarDag, NamedTempFile) {
    let mut dag = GrammarDag::new();
    for (name, bytes) in docs {
        dag.add_document(name.clone(), bytes);
    }
    let tmp = NamedTempFile::new().unwrap();
    dag.save_to_path(tmp.path()).unwrap();
    (dag, tmp)
}

fn oracle_line_count(data: &[u8], pattern: &str) -> u64 {
    if data.is_empty() {
        return 0;
    }
    let re = regex::bytes::Regex::new(pattern).unwrap();
    let slice = data.strip_suffix(b"\n").unwrap_or(data);
    slice
        .split(|&b| b == b'\n')
        .filter(|l| re.is_match(l))
        .count() as u64
}

fn oracle_lines(data: &[u8], pattern: &str) -> Vec<String> {
    if data.is_empty() {
        return Vec::new();
    }
    let re = regex::bytes::Regex::new(pattern).unwrap();
    let slice = data.strip_suffix(b"\n").unwrap_or(data);
    slice
        .split(|&b| b == b'\n')
        .filter(|l| re.is_match(l))
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect()
}

#[test]
fn test_mapped_grep_matches_oracle_including_many_state_patterns() {
    let docs = sample_docs();
    let (_dag, tmp) = build(&docs);
    let archive = MappedArchive::open(tmp.path()).unwrap();

    // The last two patterns compile to far more than 128 DFA states, which used to overflow the
    // 7-bit packed state of the fast evaluators and silently produce wrong counts.
    for pat in [
        "spin_lock",
        "lock\\(&",
        "^\\t\\treturn",
        "\\(p, rcu\\);$",
        "\\w+_lock\\(",
        "a.{6}b",
        "(a|b|c|d|e).{8}z",
    ] {
        let all = archive.grep_all_docs(pat, GrepMode::LineCount).unwrap();
        let all_lines = archive.grep_lines_all_docs(pat, usize::MAX).unwrap();
        for (i, (name, bytes)) in docs.iter().enumerate() {
            assert_eq!(all[i].0, *name);
            assert_eq!(
                all[i].1,
                oracle_line_count(bytes, pat),
                "pattern {pat} doc {name}"
            );
            assert_eq!(
                archive.grep(Some(name), pat, GrepMode::LineCount).unwrap(),
                oracle_line_count(bytes, pat)
            );
            let expected_lines = oracle_lines(bytes, pat);
            assert_eq!(
                archive.grep_lines(Some(name), pat, usize::MAX).unwrap(),
                expected_lines,
                "pattern {pat} doc {name}"
            );
            let got_all = all_lines
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, l)| l.clone())
                .unwrap_or_default();
            assert_eq!(got_all, expected_lines);

            let re = regex::bytes::RegexBuilder::new(pat)
                .multi_line(true)
                .build()
                .unwrap();
            assert_eq!(
                archive.grep(Some(name), pat, GrepMode::MatchCount).unwrap(),
                re.find_iter(bytes).count() as u64,
                "match count pattern {pat} doc {name}"
            );
        }
    }
}

#[test]
fn test_mapped_count_literal_matches_kmp_index() {
    let docs = sample_docs();
    let (dag, tmp) = build(&docs);
    let archive = MappedArchive::open(tmp.path()).unwrap();
    for pat in [
        &b"a"[..],
        b"aa",
        b"abcab",
        b"lock",
        b" mutex_lock(",
        b"\n",
        b"\n\t\t",
        b"\xe3\x81\x82",
        b"never-present",
    ] {
        let expected = dag.count_literal_all_docs(pat).unwrap();
        assert_eq!(archive.count_literal_all_docs(pat).unwrap(), expected);
        for (name, bytes) in &docs {
            let brute = if bytes.len() < pat.len() {
                0
            } else {
                bytes.windows(pat.len()).filter(|w| *w == pat).count() as u64
            };
            assert_eq!(archive.count_literal(Some(name), pat).unwrap(), brute);
        }
    }
}

#[test]
fn test_mapped_navigation_matches_raw_bytes() {
    let docs = sample_docs();
    let (dag, tmp) = build(&docs);
    let archive = MappedArchive::open(tmp.path()).unwrap();
    archive.verify_checksum().unwrap();
    let mut rng = StdRng::seed_from_u64(7);

    for (name, bytes) in &docs {
        assert_eq!(archive.decompress(Some(name)).unwrap(), *bytes);
        let n = bytes.len();
        for _ in 0..300 {
            let start = rng.gen_range(0..=n);
            let len = rng.gen_range(0..=(n - start).min(700));
            assert_eq!(
                archive
                    .extract_slice(Some(name), start as u64, len as u64)
                    .unwrap(),
                &bytes[start..start + len]
            );
            let pos2 = if rng.gen_bool(0.3) {
                start
            } else {
                rng.gen_range(0..=n - len)
            };
            assert_eq!(
                archive
                    .substring_eq(Some(name), start as u64, pos2 as u64, len as u64)
                    .unwrap(),
                bytes[start..start + len] == bytes[pos2..pos2 + len]
            );
        }
        assert!(archive.extract_slice(Some(name), n as u64, 1).is_err());
    }

    let a = archive.inspect_report(42).unwrap();
    let b = dag.inspect_report(Some(42));
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn test_mapped_locate_literal_matches_kmp_index() {
    let docs = sample_docs();
    let (dag, tmp) = build(&docs);
    let archive = MappedArchive::open(tmp.path()).unwrap();
    for pat in [
        &b"a"[..],
        b"aa",
        b"abcab",
        b"lock(",
        b"\n\t\t",
        b"never-present",
    ] {
        for (name, _) in &docs {
            for limit in [0usize, 1, 7, usize::MAX] {
                assert_eq!(
                    archive.locate_literal(Some(name), pat, limit).unwrap(),
                    dag.locate_literal(Some(name), pat, limit).unwrap(),
                    "pattern {:?} doc {name} limit {limit}",
                    String::from_utf8_lossy(pat)
                );
            }
        }
    }
}

#[test]
fn test_run_counts_beyond_u32_survive_serialization() {
    // A run longer than the on-disk u32 count must be split into nested runs instead of being
    // silently truncated when saved.
    let mut dag = GrammarDag::new();
    let a = buttlick::SymbolId::from_byte(b'a');
    let b = buttlick::SymbolId::from_byte(b'b');
    let huge = 5_000_000_123u64;
    let run = dag.intern_run(a, huge);
    let root = dag.intern_pair(run, b);
    assert_eq!(dag.sym_len(root), huge + 1);
    // Concatenating two capped runs of the same byte must not overflow either.
    let doubled = dag.concat_symbols(Some(run), Some(run)).unwrap();
    assert_eq!(dag.sym_len(doubled), 2 * huge);
    dag.roots.push(buttlick::RootEntry {
        name: "huge".into(),
        root_symbol: Some(root),
        byte_len: huge + 1,
        kr_hash: dag.sym_hash(root),
    });
    dag.validate_invariants().unwrap();

    let tmp = NamedTempFile::new().unwrap();
    dag.save_to_path(tmp.path()).unwrap();
    let loaded = GrammarDag::load_from_path(tmp.path()).unwrap();
    loaded.validate_invariants().unwrap();
    assert_eq!(
        loaded.sym_len(loaded.roots[0].root_symbol.unwrap()),
        huge + 1
    );
    assert_eq!(loaded.byte_at(Some("huge"), huge).unwrap(), b'b');
    assert_eq!(loaded.byte_at(Some("huge"), huge - 1).unwrap(), b'a');

    let archive = MappedArchive::open(tmp.path()).unwrap();
    assert_eq!(
        archive.extract_slice(Some("huge"), huge - 3, 4).unwrap(),
        b"aaab"
    );
    assert!(archive
        .substring_eq(Some("huge"), 0, 4_294_967_000, 1_000_000)
        .unwrap());
    assert_eq!(archive.count_literal(Some("huge"), b"ab").unwrap(), 1);
}

#[test]
fn test_mapped_rejects_corrupted_rule_table() {
    let docs = sample_docs();
    let (_dag, tmp) = build(&docs);
    let mut raw = std::fs::read(tmp.path()).unwrap();
    // Point the last rule at itself (a cycle / forward reference).
    let n = raw.len();
    let last_rule = n - 8 - 8;
    let num_rules = u64::from_le_bytes(raw[24..32].try_into().unwrap()) as u32;
    let self_sym = 256 + num_rules - 1;
    raw[last_rule..last_rule + 4].copy_from_slice(&self_sym.to_le_bytes());
    raw[last_rule + 4..last_rule + 8].copy_from_slice(&self_sym.to_le_bytes());
    let bad = NamedTempFile::new().unwrap();
    std::fs::write(bad.path(), &raw).unwrap();

    let archive = MappedArchive::open(bad.path()).unwrap();
    assert!(archive.verify_checksum().is_err());
    assert!(archive.grep_all_docs("lock", GrepMode::LineCount).is_err());
    assert!(archive.grep_lines_all_docs("lock", 10).is_err());
    assert!(archive.count_literal_all_docs(b"lock").is_err());
    assert!(GrammarDag::load_from_path(bad.path()).is_err());
}
