use buttlick::error::ButtlickError;
use buttlick::grammar::GrammarDag;
use buttlick::hash::raw_slice_hash;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tempfile::NamedTempFile;

#[test]
fn test_exhaustive_small_and_repetitive_roundtrips() {
    let mut rng = StdRng::seed_from_u64(0xB077_11C4);

    // 1. Lengths 0..=128 with varying alphabet sizes
    for len in 0..=128 {
        for alpha in [1u8, 2, 3, 4, 16, 255] {
            let data: Vec<u8> = (0..len).map(|_| rng.gen_range(0..=alpha)).collect();
            let dag = GrammarDag::from_bytes(&data);
            dag.validate_invariants().unwrap();
            assert_eq!(dag.decompress(None).unwrap(), data);
            assert_eq!(dag.find_root(None).unwrap().kr_hash, raw_slice_hash(&data));
        }
    }

    // 2. Massive 100 MB pure run compresses to 1 single Run rule!
    let huge_len = 100_000_000usize;
    let huge_run = vec![b'X'; huge_len];
    let dag_huge = GrammarDag::from_bytes(&huge_run);
    dag_huge.validate_invariants().unwrap();
    assert_eq!(dag_huge.rules.len(), 1);
    assert_eq!(dag_huge.find_root(None).unwrap().byte_len, huge_len as u64);
    assert_eq!(
        dag_huge.extract_slice(None, 50_000_000, 1024).unwrap(),
        vec![b'X'; 1024]
    );
    assert!(dag_huge
        .substring_eq(None, 0, 12_345_678, 80_000_000)
        .unwrap());
}

#[test]
fn test_5000_random_navigation_slice_and_equality_queries() {
    let mut rng = StdRng::seed_from_u64(42);
    let mut raw = Vec::new();
    let phrases = [
        &b"alpha_block_12345\n"[..],
        &b"beta_block_67890\n"[..],
        &b"AAAAAAAAAAAAAAAAAAAA"[..],
        &b"2026-10-24 status=200 latency=42\n"[..],
    ];
    for _ in 0..2000 {
        let p = phrases[rng.gen_range(0..phrases.len())];
        let rep = rng.gen_range(1..=5);
        for _ in 0..rep {
            raw.extend_from_slice(p);
        }
    }

    let tmp = NamedTempFile::new().unwrap();
    let dag = GrammarDag::from_bytes(&raw);
    dag.save_to_path(tmp.path()).unwrap();

    // Reopen via zero-copy mmap
    let loaded = GrammarDag::load_from_path(tmp.path()).unwrap();
    loaded.validate_invariants().unwrap();
    let n = raw.len();

    for i in 0..5000 {
        // Test byte_at
        let pos = rng.gen_range(0..n);
        assert_eq!(loaded.byte_at(None, pos as u64).unwrap(), raw[pos]);

        // Test extract_slice (keep slice sizes reasonable so test finishes in < 0.2s)
        let max_len = (n - pos).min(512);
        let len = rng.gen_range(0..=max_len);
        let slice = loaded.extract_slice(None, pos as u64, len as u64).unwrap();
        assert_eq!(&slice[..], &raw[pos..pos + len]);

        // Test substring_eq (both random positions and deliberately equal periodic ranges)
        let pos2 = if i % 3 == 0 {
            pos
        } else {
            rng.gen_range(0..=n - len)
        };
        let eq_dag = loaded
            .substring_eq(None, pos as u64, pos2 as u64, len as u64)
            .unwrap();
        let eq_raw = raw[pos..pos + len] == raw[pos2..pos2 + len];
        assert_eq!(eq_dag, eq_raw);
    }

    // Out-of-bounds checks
    assert!(matches!(
        loaded.byte_at(None, n as u64),
        Err(ButtlickError::OutOfBounds { .. })
    ));
    assert!(matches!(
        loaded.extract_slice(None, (n - 5) as u64, 10),
        Err(ButtlickError::OutOfBounds { .. })
    ));
}

#[test]
fn test_all_10_cli_subcommands_end_to_end() {
    use std::fs;
    use std::process::Command;

    let bin = env!("CARGO_BIN_EXE_buttlick");
    let dir = tempfile::tempdir().unwrap();
    let in1 = dir.path().join("doc1.csv");
    let in2 = dir.path().join("doc2.csv");
    let btlk = dir.path().join("archive.btlk");
    let btlk_edited = dir.path().join("edited.btlk");
    let decomp_out = dir.path().join("decomp.csv");

    let csv1 = b"2026-10-24,200,100\n2026-10-24,500,250\n2026-10-24,200,300\n".repeat(20);
    let csv2 = b"2026-10-24,200,50\n".repeat(10);
    fs::write(&in1, &csv1).unwrap();
    fs::write(&in2, &csv2).unwrap();

    // 1. compress
    let st = Command::new(bin)
        .args([
            "compress",
            in1.to_str().unwrap(),
            in2.to_str().unwrap(),
            "-o",
            btlk.to_str().unwrap(),
            "--stats",
        ])
        .output()
        .unwrap();
    assert!(st.status.success());

    // 2. decompress
    let st = Command::new(bin)
        .args([
            "decompress",
            btlk.to_str().unwrap(),
            "-o",
            decomp_out.to_str().unwrap(),
            "--doc",
            "doc1.csv",
        ])
        .output()
        .unwrap();
    assert!(st.status.success());
    assert_eq!(fs::read(&decomp_out).unwrap(), csv1);

    // 3. inspect --json
    let out = Command::new(bin)
        .args(["inspect", btlk.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json_val["num_roots"], 2);

    // 4. slice
    let out = Command::new(bin)
        .args([
            "slice",
            btlk.to_str().unwrap(),
            "--start",
            "0",
            "--len",
            "19",
            "--doc",
            "doc1.csv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(&out.stdout[..], b"2026-10-24,200,100\n");

    // 5. eq
    let out = Command::new(bin)
        .args([
            "eq",
            btlk.to_str().unwrap(),
            "--pos1",
            "0",
            "--pos2",
            "57",
            "--len",
            "57",
            "--doc",
            "doc1.csv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true");

    // 6. count --offsets
    let out = Command::new(bin)
        .args([
            "count",
            btlk.to_str().unwrap(),
            ",500,",
            "--offsets",
            "--limit",
            "5",
            "--doc",
            "doc1.csv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let lines: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
    assert_eq!(lines[0], "20");
    assert_eq!(lines.len(), 6); // 1 count line + 5 offsets

    // 7. slurp --line-count
    let out = Command::new(bin)
        .args([
            "slurp",
            btlk.to_str().unwrap(),
            ",200,[0-9]+$",
            "--line-count",
            "--doc",
            "doc1.csv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "40");

    // 8. query --json
    let out = Command::new(bin)
        .args([
            "query",
            btlk.to_str().unwrap(),
            "--delimiter",
            ",",
            "--col",
            "2",
            "--where-col",
            "1",
            "--where-eq",
            "200",
            "--doc",
            "doc1.csv",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let q_json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(q_json["count"], 40);
    assert_eq!(q_json["sum"], 8000);
    assert_eq!(q_json["min"], 100);
    assert_eq!(q_json["max"], 300);

    // 9. edit (replace, insert, delete, concat)
    let st = Command::new(bin)
        .args([
            "edit",
            btlk.to_str().unwrap(),
            "-o",
            btlk_edited.to_str().unwrap(),
            "--doc",
            "doc1.csv",
            "replace",
            "--pattern",
            ",500,",
            "--with",
            ",200,",
        ])
        .output()
        .unwrap();
    assert!(st.status.success());

    let out = Command::new(bin)
        .args([
            "count",
            btlk_edited.to_str().unwrap(),
            ",500,",
            "--doc",
            "doc1.csv",
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0");

    // 10. bench
    let out = Command::new(bin)
        .args(["bench", "--size-mb", "2", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let b_json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(b_json["benchmarks"].as_array().unwrap().len(), 4);
}
