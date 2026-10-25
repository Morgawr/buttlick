use buttlick::engine::regex_compile::GrepMode;
use buttlick::grammar::GrammarDag;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn brute_replace_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> (Vec<u8>, u64) {
    let mut out = Vec::with_capacity(haystack.len());
    let mut count = 0u64;
    let mut i = 0;
    while i < haystack.len() {
        if i + needle.len() <= haystack.len() && &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            count += 1;
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    (out, count)
}

#[test]
fn test_100_sequential_random_dag_edits_vs_vec_oracle() {
    for multi_document in [false, true] {
        sequential_edits(multi_document);
    }
}

fn sequential_edits(multi_document: bool) {
    let mut rng = StdRng::seed_from_u64(0xED17_F00D);

    let mut raw: Vec<u8> = b"INIT_BLOCK_AAAABBBB\n".repeat(40);
    let mut dag = GrammarDag::from_bytes(&raw);
    let sentinel = b"INIT_BLOCK_AAAABBBB\nuntouched other document\n".repeat(10);
    if multi_document {
        dag.add_document("sentinel", &sentinel);
    }
    dag.validate_invariants().unwrap();

    let tokens = [
        &b"AAA"[..],
        &b"BBBB"[..],
        &b"INIT"[..],
        &b"PATCH_99"[..],
        &b"XYXYXY"[..],
        &b"\n"[..],
    ];
    let re = regex::bytes::Regex::new("INIT|PATCH").unwrap();

    for step in 0..100 {
        let op = rng.gen_range(0..4);
        match op {
            0 => {
                // INSERT at random offset
                let offset = rng.gen_range(0..=raw.len());
                let tok = tokens[rng.gen_range(0..tokens.len())];
                let rep = rng.gen_range(1..=10);
                let payload = tok.repeat(rep);

                dag.insert(None, offset as u64, &payload).unwrap();
                raw.splice(offset..offset, payload);
            }
            1 => {
                // DELETE random range
                if !raw.is_empty() {
                    let offset = rng.gen_range(0..raw.len());
                    let max_del = (raw.len() - offset).min(120);
                    let len = rng.gen_range(0..=max_del);

                    dag.delete(None, offset as u64, len as u64).unwrap();
                    raw.drain(offset..offset + len);
                }
            }
            2 => {
                // REPLACE_ALL with random token -> replacement
                let pat = tokens[rng.gen_range(0..tokens.len())];
                let repl = tokens[rng.gen_range(0..tokens.len())];

                let got_count = dag.replace_all(None, pat, repl).unwrap();
                let (new_raw, expected_count) = brute_replace_all(&raw, pat, repl);
                assert_eq!(
                    got_count, expected_count,
                    "replace_all count mismatch at step {step}"
                );
                raw = new_raw;
            }
            _ => {
                // SPLICED SELF-CONCAT of a slice
                if raw.len() >= 10 && raw.len() < 50_000 {
                    let start = rng.gen_range(0..raw.len() - 5);
                    let len = rng.gen_range(1..=50.min(raw.len() - start));
                    let sub = dag.extract_slice(None, start as u64, len as u64).unwrap();
                    assert_eq!(&sub[..], &raw[start..start + len]);

                    let ins_pos = rng.gen_range(0..=raw.len());
                    dag.insert(None, ins_pos as u64, &sub).unwrap();
                    raw.splice(ins_pos..ins_pos, sub);
                }
            }
        }

        // After EVERY single edit operation:
        if multi_document && step % 7 == 0 {
            dag.compact();
            dag = GrammarDag::from_btlk_bytes(&dag.to_btlk_bytes()).unwrap();
            assert_eq!(dag.decompress(Some("sentinel")).unwrap(), sentinel);
        }
        // 1. Structural and topological invariants must hold
        dag.validate_invariants().unwrap();

        // 2. Decompressed bytes must match the reference Vec<u8> bit-for-bit
        let decompressed = dag.decompress(None).unwrap();
        assert_eq!(
            decompressed, raw,
            "Decompression mismatch after edit step {step}"
        );

        // 3. Queries on the edited DAG must return 100% exact results
        for probe in [&b"AA"[..], &b"PATCH"[..], &b"XYXY"[..]] {
            let (count, offsets) = dag.locate_literal(None, probe, 20).unwrap();
            let expected_all: Vec<u64> = raw
                .windows(probe.len())
                .enumerate()
                .filter_map(|(i, w)| if w == probe { Some(i as u64) } else { None })
                .collect();
            assert_eq!(count, expected_all.len() as u64);
            let expected_top20: Vec<u64> = expected_all.into_iter().take(20).collect();
            assert_eq!(offsets, expected_top20);
        }

        if step % 10 == 0 && !raw.is_empty() {
            let got_lines = dag.grep(None, "INIT|PATCH", GrepMode::LineCount).unwrap();
            let slice = if raw.last() == Some(&b'\n') {
                &raw[..raw.len() - 1]
            } else {
                &raw[..]
            };
            let expected_lines = slice
                .split(|&b| b == b'\n')
                .filter(|l| re.is_match(l))
                .count() as u64;
            assert_eq!(got_lines, expected_lines);
        }
    }
}
