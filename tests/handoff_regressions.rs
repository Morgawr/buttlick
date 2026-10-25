use std::process::Command;

use buttlick::engine::regex_compile::GrepMode;
use buttlick::format::MappedArchive;
use buttlick::{GrammarDag, RootEntry, SymbolId};
use tempfile::{tempdir, NamedTempFile};

#[test]
fn parallel_batches_have_exact_hashes_and_consistent_upserts() {
    let docs: Vec<_> = (0..80)
        .map(|i| (format!("doc{i}"), format!("record {i}\n").into_bytes()))
        .chain(std::iter::once(("empty".into(), Vec::new())))
        .collect();
    let mut dag = GrammarDag::new();
    dag.add_documents_parallel(&docs);
    dag.validate_invariants().unwrap();
    dag.add_documents_parallel(&[
        ("doc3".into(), b"replacement\n".to_vec()),
        ("new".into(), b"first".to_vec()),
        ("new".into(), b"second".to_vec()),
    ]);
    assert_eq!(dag.roots.len(), 82);
    assert_eq!(dag.decompress(Some("doc3")).unwrap(), b"replacement\n");
    assert_eq!(dag.decompress(Some("new")).unwrap(), b"second");
    let loaded = GrammarDag::from_btlk_bytes(&dag.to_btlk_bytes()).unwrap();
    loaded.validate_invariants().unwrap();
    assert!(loaded.root_hashes_are_exact());
    for root in &loaded.roots {
        assert_eq!(
            root.kr_hash,
            root.root_symbol.map_or(0, |s| loaded.sym_hash(s))
        );
    }
}

#[test]
fn cli_rejects_colliding_names_before_writing_archive() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    for path in [&a, &b] {
        std::fs::write(path.join("same.txt"), path.as_os_str().as_encoded_bytes()).unwrap();
    }
    let archive = dir.path().join("out.btlk");
    for inputs in [
        vec![a.join("same.txt"), b.join("same.txt")],
        vec![a.clone(), a.clone()],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_buttlick"))
            .arg("compress")
            .args(inputs)
            .arg("-o")
            .arg(&archive)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("Duplicate archive document name"));
        assert!(!archive.exists());
    }
}

fn add_root(dag: &mut GrammarDag, name: &str, sym: SymbolId) {
    dag.roots.push(RootEntry {
        name: name.into(),
        root_symbol: Some(sym),
        byte_len: dag.sym_len(sym),
        kr_hash: dag.sym_hash(sym),
    });
}

#[test]
fn huge_periodic_runs_skip_cycles_and_preserve_offsets() {
    let mut dag = GrammarDag::new();
    let a = SymbolId::from_byte(b'a');
    let run = dag.intern_run(a, 3_000_000_001);
    let nested = dag.intern_run(run, 3_000_000_000);
    add_root(&mut dag, "run", run);
    add_root(&mut dag, "nested", nested);
    let nl = SymbolId::from_byte(b'\n');
    let first = dag.intern_pair(run, nl);
    let tail = dag.compress_bytes(b"b\nmatch\nlast").unwrap();
    let root = dag.intern_pair(first, tail);
    add_root(&mut dag, "lines", root);
    let tmp = NamedTempFile::new().unwrap();
    dag.save_to_path(tmp.path()).unwrap();
    let mapped = MappedArchive::open(tmp.path()).unwrap();
    for name in ["run", "nested"] {
        assert_eq!(
            mapped
                .grep(Some(name), "(aa)*b", GrepMode::LineCount)
                .unwrap(),
            0
        );
        assert_eq!(
            mapped
                .grep(Some(name), "(aa)*b", GrepMode::MatchCount)
                .unwrap(),
            0
        );
        assert!(mapped
            .grep_lines(Some(name), "(aa)*b", 5)
            .unwrap()
            .is_empty());
    }
    assert_eq!(
        mapped.grep_lines(Some("lines"), "b|match|last", 5).unwrap(),
        ["b", "match", "last"]
    );
    assert_eq!(
        mapped.locate_literal(Some("lines"), b"b", 10).unwrap(),
        (1, vec![3_000_000_002])
    );
    assert_eq!(
        mapped.locate_literal(Some("run"), b"aa", 5).unwrap(),
        (3_000_000_000, vec![0, 1, 2, 3, 4])
    );
    assert_eq!(
        dag.locate_literal(Some("run"), b"a", 3).unwrap(),
        (3_000_000_001, vec![0, 1, 2])
    );
}

#[test]
fn writer_rejects_unrepresentable_run_counts_and_tagged_symbols() {
    use buttlick::grammar::{RuleKind, RuleNode};
    for kind in [
        RuleKind::Run {
            child: SymbolId::from_byte(b'a'),
            count: u32::MAX as u64 + 1,
        },
        RuleKind::Run {
            child: SymbolId::from_byte(b'a'),
            count: 1,
        },
        RuleKind::Pair {
            left: SymbolId(1 << 31),
            right: SymbolId(0),
        },
    ] {
        let dag = GrammarDag::from_parts(
            vec![RuleNode {
                kind,
                byte_len: 2,
                height: 1,
                first_byte: b'a',
                last_byte: b'a',
            }],
            vec![],
        );
        let file = NamedTempFile::new().unwrap();
        let error = dag.save_to_path(file.path()).unwrap_err();
        assert!(matches!(error, buttlick::ButtlickError::Io(ref e)
            if e.kind() == std::io::ErrorKind::InvalidInput));
    }
}

#[test]
fn compaction_preserves_all_documents_and_future_edits() {
    let mut dag = GrammarDag::new();
    dag.add_document("edited", &b"old line that will be removed\n".repeat(200));
    dag.add_document("keep", b"shared content and a final line\n");
    let len = dag.find_root(Some("edited")).unwrap().byte_len;
    dag.delete(Some("edited"), 0, len).unwrap();
    dag.insert(Some("edited"), 0, b"new line\n").unwrap();
    let before = dag.to_btlk_bytes().len();
    assert!(dag.compact() > 0);
    assert!(dag.to_btlk_bytes().len() < before);
    assert_eq!(dag.compact(), 0);
    dag.validate_invariants().unwrap();
    assert_eq!(
        dag.decompress(Some("keep")).unwrap(),
        b"shared content and a final line\n"
    );
    let mut loaded = GrammarDag::from_btlk_bytes(&dag.to_btlk_bytes()).unwrap();
    assert_eq!(
        loaded
            .replace_all(Some("edited"), b"new", b"better")
            .unwrap(),
        1
    );
    loaded.compact();
    assert_eq!(loaded.decompress(Some("edited")).unwrap(), b"better line\n");
    loaded.validate_invariants().unwrap();
}

#[test]
fn interner_reuses_long_pairs_after_loading() {
    let mut dag = GrammarDag::new();
    let a = dag.intern_run(SymbolId::from_byte(b'a'), 50);
    let b = dag.intern_run(SymbolId::from_byte(b'b'), 50);
    let root = dag.intern_pair(a, b);
    add_root(&mut dag, "long", root);
    let mut loaded = GrammarDag::from_btlk_bytes(&dag.to_btlk_bytes()).unwrap();
    assert_eq!(loaded.intern_pair(a, b), root);
    assert_eq!(loaded.rules.len(), dag.rules.len());
}

#[test]
fn cli_validates_search_modes_and_edit_target_and_verifies_checksum() {
    let dir = tempdir().unwrap();
    let archive = dir.path().join("test.btlk");
    let output = dir.path().join("edit.btlk");
    let mut dag = GrammarDag::new();
    dag.add_document("one", b"one\n");
    dag.add_document("two", b"two\n");
    dag.save_to_path(&archive).unwrap();
    let exe = env!("CARGO_BIN_EXE_buttlick");
    let verified = Command::new(exe)
        .arg("verify")
        .arg(&archive)
        .output()
        .unwrap();
    assert!(verified.status.success());
    for args in [vec!["--all", "--offsets"], vec!["--all", "--doc", "one"]] {
        assert!(!Command::new(exe)
            .arg("count")
            .arg(&archive)
            .arg("o")
            .args(args)
            .output()
            .unwrap()
            .status
            .success());
    }
    assert!(!Command::new(exe)
        .arg("slurp")
        .arg(&archive)
        .arg("o")
        .args(["-c", "--match-count"])
        .output()
        .unwrap()
        .status
        .success());
    assert!(!Command::new(exe)
        .arg("edit")
        .arg(&archive)
        .arg("-o")
        .arg(&output)
        .args(["insert", "--offset", "0", "--text", "prefix"])
        .output()
        .unwrap()
        .status
        .success());
    assert!(!output.exists());
    let mut bytes = std::fs::read(&archive).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&archive, bytes).unwrap();
    assert!(!Command::new(exe)
        .arg("verify")
        .arg(&archive)
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn cli_json_aggregation_preserves_i128_sums() {
    for value in [i64::MIN, i64::MAX] {
        let raw = format!("{value}\n").repeat(3);
        let dag = GrammarDag::from_bytes(raw.as_bytes());
        let archive = NamedTempFile::new().unwrap();
        dag.save_to_path(archive.path()).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_buttlick"))
            .arg("query")
            .arg(archive.path())
            .args(["--col", "0", "--json"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let output = String::from_utf8(out.stdout).unwrap();
        assert!(output.contains(&format!("\"sum\": {}", value as i128 * 3)));
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["count"], 3);
    }
}

#[cfg(unix)]
#[test]
fn cli_follows_explicit_symlinks_but_skips_nested_links() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("real.txt"), b"real contents\n").unwrap();
    let link = source.join("link.txt");
    std::os::unix::fs::symlink("real.txt", &link).unwrap();
    let archive = dir.path().join("test.btlk");
    let exe = env!("CARGO_BIN_EXE_buttlick");
    for (input, expected_name) in [
        (link.as_path(), "link.txt"),
        (source.as_path(), "source/real.txt"),
    ] {
        let out = Command::new(exe)
            .arg("compress")
            .arg(input)
            .arg("-o")
            .arg(&archive)
            .arg("--stats")
            .output()
            .unwrap();
        assert!(out.status.success());
        let mapped = MappedArchive::open(&archive).unwrap();
        assert_eq!(mapped.roots.len(), 1);
        assert_eq!(mapped.roots[0].name, expected_name);
        assert_eq!(mapped.decompress(None).unwrap(), b"real contents\n");
    }
}

#[test]
fn aggregation_skips_huge_unused_fields_and_repeated_delimiters() {
    use buttlick::engine::aggregate::{AggregateQuery, AggregateSummary};
    let mut dag = GrammarDag::new();
    let start = dag.compress_bytes(b"tag,42,").unwrap();
    let tail = dag.intern_run(SymbolId::from_byte(b'x'), 3_000_000_000);
    let root = dag.intern_pair(start, tail);
    add_root(&mut dag, "unused-tail", root);
    let block = dag.compress_bytes(b",7").unwrap();
    let repeated = dag.intern_run(block, 3_000_000_000);
    add_root(&mut dag, "repeated-fields", repeated);
    let file = NamedTempFile::new().unwrap();
    dag.save_to_path(file.path()).unwrap();
    let mapped = MappedArchive::open(file.path()).unwrap();
    for (name, col, expected) in [("unused-tail", 1, 42), ("repeated-fields", 2, 7)] {
        let query = AggregateQuery {
            delimiter: b',',
            target_col: col,
            filter: None,
        };
        assert_eq!(
            dag.aggregate_query(Some(name), &query).unwrap(),
            AggregateSummary::single(expected)
        );
        assert_eq!(
            mapped.aggregate_query(Some(name), &query).unwrap(),
            AggregateSummary::single(expected)
        );
    }
}

#[test]
fn bounded_aggregation_matches_complete_records_for_delimiters_and_filters() {
    use buttlick::engine::aggregate::{eval_single_line, AggregateQuery, AggregateSummary};
    let tokens: [&[u8]; 9] = [
        b"42", b"key=-7", b"", b" 19 ", b"x", b"00042", b"+3", b"a=b=1", b"\r9\r",
    ];
    for delimiter in [b',', b' ', b'\t', b'\r', b'=', 0, b'\n'] {
        let mut data = Vec::new();
        for line in 0..200 {
            for col in 0..6 {
                if col > 0 {
                    data.push(delimiter);
                }
                data.extend_from_slice(tokens[(line * 7 + col * 3) % tokens.len()]);
            }
            if line % 3 == 0 {
                data.push(b'\r');
            }
            data.push(b'\n');
        }
        data.extend_from_slice(b"trailing=42");
        let dag = GrammarDag::from_bytes(&data);
        let file = NamedTempFile::new().unwrap();
        dag.save_to_path(file.path()).unwrap();
        let mapped = MappedArchive::open(file.path()).unwrap();
        for target_col in [0, 2, 5, 6] {
            for filter in [None, Some((1, b"42".to_vec())), Some((5, Vec::new()))] {
                let query = AggregateQuery {
                    delimiter,
                    target_col,
                    filter,
                };
                let expected = data
                    .split(|&b| b == b'\n')
                    .fold(AggregateSummary::empty(), |sum, line| {
                        sum.combine(eval_single_line(line, &query))
                    });
                assert_eq!(dag.aggregate_query(None, &query).unwrap(), expected);
                assert_eq!(mapped.aggregate_query(None, &query).unwrap(), expected);
            }
        }
    }
}

#[test]
fn parallel_ingestion_after_manual_interning_keeps_seed_ids_valid() {
    let mut dag = GrammarDag::new();
    dag.add_documents_parallel(&[("seed".to_string(), b"ab".to_vec())]);
    assert!(dag.interner.seed_rules_len > 0);
    let pair = dag.intern_pair(SymbolId::from_byte(b'Q'), SymbolId::from_byte(b'Z'));
    let run = dag.intern_run(SymbolId::from_byte(b'q'), 7);
    dag.add_documents_parallel(&[
        ("later".to_string(), b"QZ".to_vec()),
        ("run".to_string(), vec![b'q'; 7]),
    ]);
    assert_eq!(dag.decompress(Some("seed")).unwrap(), b"ab");
    assert_eq!(dag.decompress(Some("later")).unwrap(), b"QZ");
    assert_eq!(
        dag.find_root(Some("later")).unwrap().root_symbol,
        Some(pair)
    );
    assert_eq!(dag.find_root(Some("run")).unwrap().root_symbol, Some(run));
    dag.validate_invariants().unwrap();
}

#[test]
fn regex_match_count_respects_empty_greedy_and_context_matches() {
    let docs: &[&[u8]] = &[
        b"",
        b"aaa",
        b"ab ab",
        b"a!!",
        b"x\nx\n",
        b"\xff\x80a",
        "日本語".as_bytes(),
    ];
    let mut dag = GrammarDag::new();
    for (i, bytes) in docs.iter().enumerate() {
        dag.add_document(format!("doc{i}"), bytes);
    }
    let file = NamedTempFile::new().unwrap();
    dag.save_to_path(file.path()).unwrap();
    let mapped = MappedArchive::open(file.path()).unwrap();
    for pattern in [
        "", "a*", "a+", "a.*b", "\\Aaaa", "\\b!", "^x", "\n", "a|ab", "ab|a", "a{2,3}", "a{2,3}?",
        "b|", "(?-u:.)", "\\w", "\\w+",
    ] {
        let re = regex::bytes::RegexBuilder::new(pattern)
            .multi_line(true)
            .build()
            .unwrap();
        let expected: Vec<_> = docs
            .iter()
            .enumerate()
            .map(|(i, data)| (format!("doc{i}"), re.find_iter(data).count() as u64))
            .collect();
        assert_eq!(
            mapped.grep_all_docs(pattern, GrepMode::MatchCount).unwrap(),
            expected
        );
        assert_eq!(
            dag.grep_all_docs(pattern, GrepMode::MatchCount).unwrap(),
            expected
        );
        for (name, count) in expected {
            assert_eq!(
                mapped
                    .grep(Some(&name), pattern, GrepMode::MatchCount)
                    .unwrap(),
                count,
                "mapped {pattern:?} {name}"
            );
            assert_eq!(
                dag.grep(Some(&name), pattern, GrepMode::MatchCount)
                    .unwrap(),
                count,
                "decoded {pattern:?} {name}"
            );
        }
    }
    for mode in [GrepMode::MatchCount, GrepMode::LineCount] {
        assert!(dag.grep(Some("doc0"), "[", mode).is_err());
        assert!(mapped.grep(Some("doc0"), "[", mode).is_err());
    }
}

#[test]
fn empty_regex_counts_full_u64_length_without_expansion() {
    let mut dag = GrammarDag::new();
    let run = dag.intern_run(SymbolId::from_byte(b'a'), u64::MAX);
    add_root(&mut dag, "largest", run);
    let file = NamedTempFile::new().unwrap();
    dag.save_to_path(file.path()).unwrap();
    let mapped = MappedArchive::open(file.path()).unwrap();
    assert_eq!(dag.grep(None, "", GrepMode::MatchCount).unwrap(), u64::MAX);
    assert_eq!(
        mapped.grep(None, "", GrepMode::MatchCount).unwrap(),
        u64::MAX
    );
    for pattern in ["a+", "a*", "[a-z]+", "(?-u:[a-z])*", "(a)+"] {
        assert_eq!(dag.grep(None, pattern, GrepMode::MatchCount).unwrap(), 1);
        assert_eq!(mapped.grep(None, pattern, GrepMode::MatchCount).unwrap(), 1);
    }
    assert_eq!(
        mapped.grep(None, "aa", GrepMode::MatchCount).unwrap(),
        u64::MAX / 2
    );
}

#[test]
fn long_literal_windows_match_byte_oracle_including_mapped_fallback() {
    let data = b"0123456789abcdef0123456789abcdef\n".repeat(2000);
    let dag = GrammarDag::from_bytes(&data);
    let file = NamedTempFile::new().unwrap();
    dag.save_to_path(file.path()).unwrap();
    let mapped = MappedArchive::open(file.path()).unwrap();
    for len in [17, 33, 129, 33_000] {
        let pattern = &data[5..5 + len];
        let offsets: Vec<_> = data
            .windows(len)
            .enumerate()
            .filter_map(|(i, window)| (window == pattern).then_some(i as u64))
            .collect();
        let expected = (offsets.len() as u64, offsets.into_iter().take(10).collect());
        assert_eq!(dag.locate_literal(None, pattern, 10).unwrap(), expected);
        assert_eq!(mapped.locate_literal(None, pattern, 10).unwrap(), expected);
        assert_eq!(
            mapped.count_literal_all_docs(pattern).unwrap()[0].1,
            expected.0
        );
    }
    assert_eq!(
        mapped
            .count_literal_all_docs(&vec![b'x'; data.len() + 1])
            .unwrap()[0]
            .1,
        0
    );
}

#[test]
fn maximum_lengths_reject_overflowing_ranges_edits_and_archive_totals() {
    let mut dag = GrammarDag::new();
    let run = dag.intern_run(SymbolId::from_byte(b'a'), u64::MAX);
    add_root(&mut dag, "largest", run);
    let file = NamedTempFile::new().unwrap();
    dag.save_to_path(file.path()).unwrap();
    let mapped = MappedArchive::open(file.path()).unwrap();
    for (start, len) in [(u64::MAX, 1), (u64::MAX - 1, 2), (u64::MAX / 2, u64::MAX)] {
        assert!(dag.extract_slice(None, start, len).is_err());
        assert!(dag.range_hash(None, start, len).is_err());
        assert!(dag.substring_eq(None, start, start, len).is_err());
        assert!(mapped.extract_slice(None, start, len).is_err());
        assert!(mapped.substring_eq(None, start, start, len).is_err());
        assert!(dag.delete(None, start, len).is_err());
    }
    assert_eq!(dag.extract_slice(None, u64::MAX - 1, 1).unwrap(), b"a");
    assert_eq!(mapped.extract_slice(None, u64::MAX - 1, 1).unwrap(), b"a");
    assert!(dag.insert(None, u64::MAX, b"x").is_err());
    dag.add_document("one", b"x");
    assert!(dag.concat_documents("largest", "one", "too-large").is_err());
    assert_eq!(dag.total_uncompressed_bytes(), u64::MAX);
    let out = NamedTempFile::new().unwrap();
    assert!(dag.save_to_path(out.path()).is_err());

    let mut small = GrammarDag::new();
    small.add_document("one", b"a");
    small.add_document("two", b"b");
    let mut bytes = small.to_btlk_bytes();
    let header = buttlick::format::header::BtlkHeader::from_bytes(&bytes).unwrap();
    let mut cursor = header.roots_offset as usize;
    for _ in 0..2 {
        let len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        bytes[cursor + 16..cursor + 24].copy_from_slice(&u64::MAX.to_le_bytes());
        cursor += 32 + len;
    }
    let bad = NamedTempFile::new().unwrap();
    std::fs::write(bad.path(), bytes).unwrap();
    assert!(MappedArchive::open(bad.path()).is_err());
}
