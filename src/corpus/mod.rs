use serde::{Deserialize, Serialize};

use crate::engine::kmp_seam::KmpDagIndex;
use crate::engine::regex_compile::{
    compile_line_grep_transducer, compile_match_count_transducer, GrepMode,
};
use crate::error::{ButtlickError, Result};
use crate::format::header::{PackedRuleNode, BTLK_HEADER_SIZE, PACKED_RULE_SIZE};
use crate::format::MappedArchive;
use crate::grammar::{GrammarDag, RootEntry, RuleKind, SymbolId};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RootReport {
    pub name: String,
    pub byte_len: u64,
    pub kr_hash_hex: String,
    pub height: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InspectReport {
    pub num_roots: usize,
    pub num_rules: usize,
    pub num_pair_rules: usize,
    pub num_run_rules: usize,
    pub max_height: u16,
    pub total_uncompressed_bytes: u64,
    pub archive_bytes: u64,
    pub compression_ratio: f64,
    pub roots: Vec<RootReport>,
}

fn build_inspect_report(
    roots: &[RootEntry],
    height_of: impl Fn(SymbolId) -> u16,
    num_rules: usize,
    num_pair_rules: usize,
    num_run_rules: usize,
    archive_bytes: u64,
) -> InspectReport {
    let roots_report: Vec<RootReport> = roots
        .iter()
        .map(|r| RootReport {
            name: r.name.clone(),
            byte_len: r.byte_len,
            kr_hash_hex: format!("0x{:016x}", r.kr_hash),
            height: r.root_symbol.map(&height_of).unwrap_or(0),
        })
        .collect();
    let total_uncompressed_bytes: u64 = roots.iter().map(|r| r.byte_len).sum();
    let compression_ratio = if archive_bytes > 0 {
        (total_uncompressed_bytes as f64) / (archive_bytes as f64)
    } else {
        1.0
    };
    InspectReport {
        num_roots: roots.len(),
        num_rules,
        num_pair_rules,
        num_run_rules,
        max_height: roots_report.iter().map(|r| r.height).max().unwrap_or(0),
        total_uncompressed_bytes,
        archive_bytes,
        compression_ratio,
        roots: roots_report,
    }
}

impl MappedArchive {
    /// Inspection report computed directly on the memory-mapped archive: verifies the footer
    /// checksum and derives rule heights in one sequential pass (2 bytes per rule) instead of
    /// decoding the whole `GrammarDag`.
    pub fn inspect_report(&self, archive_bytes: u64) -> Result<InspectReport> {
        self.verify_checksum()?;
        let mut heights = vec![0u16; self.num_rules];
        let mut num_pair_rules = 0usize;
        let mut num_run_rules = 0usize;
        let height = |sym: SymbolId, heights: &[u16]| -> u16 {
            if sym.is_terminal() {
                0
            } else {
                heights[sym.rule_index()]
            }
        };
        for (idx, chunk) in self
            .rules_bytes()
            .chunks_exact(PACKED_RULE_SIZE)
            .enumerate()
        {
            let p = PackedRuleNode::from_bytes(chunk.try_into().unwrap());
            let sym_id = SymbolId::from_rule_index(idx).0;
            heights[idx] = if p.is_run() {
                num_run_rules += 1;
                if p.first_sym().0 >= sym_id || p.word1 < 2 {
                    return Err(ButtlickError::CorruptedFormat(format!(
                        "Invalid Run rule at index {idx}"
                    )));
                }
                height(p.first_sym(), &heights).saturating_add(1)
            } else {
                num_pair_rules += 1;
                if p.word0 >= sym_id || p.word1 >= sym_id {
                    return Err(ButtlickError::CorruptedFormat(format!(
                        "Topological ordering violation at rule {idx}"
                    )));
                }
                height(SymbolId(p.word0), &heights)
                    .max(height(SymbolId(p.word1), &heights))
                    .saturating_add(1)
            };
        }
        Ok(build_inspect_report(
            &self.roots,
            |sym| height(sym, &heights),
            self.num_rules,
            num_pair_rules,
            num_run_rules,
            archive_bytes,
        ))
    }
}

impl GrammarDag {
    /// Generates a comprehensive structural and statistical inspection report of the DAG.
    pub fn inspect_report(&self, archive_bytes_override: Option<u64>) -> InspectReport {
        let mut num_pair_rules = 0usize;
        let mut num_run_rules = 0usize;
        for node in &self.rules {
            match node.kind {
                RuleKind::Pair { .. } => num_pair_rules += 1,
                RuleKind::Run { .. } => num_run_rules += 1,
            }
        }

        let estimated_roots_bytes: usize =
            self.roots.iter().map(|r| 32 + r.name.len()).sum::<usize>();
        let aligned_roots_bytes = (estimated_roots_bytes + 7) & !7;
        let archive_bytes = archive_bytes_override.unwrap_or(
            (BTLK_HEADER_SIZE + aligned_roots_bytes + self.rules.len() * PACKED_RULE_SIZE + 8)
                as u64,
        );

        build_inspect_report(
            &self.roots,
            |sym| self.sym_height(sym),
            self.rules.len(),
            num_pair_rules,
            num_run_rules,
            archive_bytes,
        )
    }

    /// Evaluates an exact substring count across ALL documents in the archive in a SINGLE
    /// bottom-up pass over the shared grammar rules ($O(n \cdot |P| + M)$ for $M$ documents).
    pub fn count_literal_all_docs(&self, pattern: &[u8]) -> Result<Vec<(String, u64)>> {
        if pattern.is_empty() {
            return Err(ButtlickError::EmptyPattern);
        }
        let index = KmpDagIndex::evaluate(self, pattern)?;
        let mut results = Vec::with_capacity(self.roots.len());
        for root in &self.roots {
            let count = match root.root_symbol {
                Some(sym) if root.byte_len >= pattern.len() as u64 => index.count_symbol(sym),
                _ => 0,
            };
            results.push((root.name.clone(), count));
        }
        Ok(results)
    }

    /// Evaluates a regular expression across ALL documents in the archive in a SINGLE
    /// bottom-up pass over the shared grammar rules ($O(n \cdot |Q| + M)$ for $M$ documents).
    pub fn grep_all_docs(&self, pattern: &str, mode: GrepMode) -> Result<Vec<(String, u64)>> {
        let transducer = match mode {
            GrepMode::LineCount => compile_line_grep_transducer(pattern)?,
            GrepMode::MatchCount => compile_match_count_transducer(pattern)?,
        };
        let eval = transducer.evaluate_dag(self);
        let mut results = Vec::with_capacity(self.roots.len());
        for root in &self.roots {
            let count = eval.query_root(root.root_symbol);
            results.push((root.name.clone(), count));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_document_shared_deduplication_and_batch_query() {
        let mut dag = GrammarDag::new();
        let base_block = b"2026-10-24 INFO [cluster] heartbeat=ok status=200\n".repeat(1000);

        for v in 0..10 {
            let mut doc = base_block.clone();
            for _ in 0..v {
                doc.extend_from_slice(b"2026-10-24 ERROR [cluster] node_down status=500\n");
            }
            dag.add_document(format!("v{v}.log"), &doc);
        }

        // All 10 versions share the exact same base rules!
        let report = dag.inspect_report(None);
        assert_eq!(report.num_roots, 10);
        assert!(
            report.compression_ratio > 100.0,
            "Expected >100x compression ratio across 10 versions, got {:.2}x",
            report.compression_ratio
        );

        // Single-pass query across all 10 documents
        let counts = dag.count_literal_all_docs(b"ERROR").unwrap();
        for (v, (name, count)) in counts.into_iter().enumerate() {
            assert_eq!(name, format!("v{v}.log"));
            assert_eq!(count, v as u64);
        }

        let grep_counts = dag
            .grep_all_docs("status=500$", GrepMode::LineCount)
            .unwrap();
        for (v, (_, count)) in grep_counts.into_iter().enumerate() {
            assert_eq!(count, v as u64);
        }
    }
}
