use serde::{Deserialize, Serialize};

use crate::engine::kmp_seam::KmpDagIndex;
use crate::engine::regex_compile::{
    compile_line_grep_transducer, compile_match_count_transducer, GrepMode,
};
use crate::error::{ButtlickError, Result};
use crate::format::header::{BTLK_HEADER_SIZE, PACKED_RULE_SIZE};
use crate::grammar::{GrammarDag, RuleKind};

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

        let roots: Vec<RootReport> = self
            .roots
            .iter()
            .map(|r| RootReport {
                name: r.name.clone(),
                byte_len: r.byte_len,
                kr_hash_hex: format!("0x{:016x}", r.kr_hash),
                height: r.root_symbol.map(|s| self.sym_height(s)).unwrap_or(0),
            })
            .collect();

        let total_uncompressed_bytes = self.total_uncompressed_bytes();
        let estimated_roots_bytes: usize =
            self.roots.iter().map(|r| 32 + r.name.len()).sum::<usize>();
        let aligned_roots_bytes = (estimated_roots_bytes + 7) & !7;
        let archive_bytes = archive_bytes_override.unwrap_or(
            (BTLK_HEADER_SIZE + aligned_roots_bytes + self.rules.len() * PACKED_RULE_SIZE + 8)
                as u64,
        );

        let compression_ratio = if archive_bytes > 0 {
            (total_uncompressed_bytes as f64) / (archive_bytes as f64)
        } else {
            1.0
        };

        InspectReport {
            num_roots: self.roots.len(),
            num_rules: self.rules.len(),
            num_pair_rules,
            num_run_rules,
            max_height: self.max_height(),
            total_uncompressed_bytes,
            archive_bytes,
            compression_ratio,
            roots,
        }
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

        let grep_counts = dag.grep_all_docs("status=500$", GrepMode::LineCount).unwrap();
        for (v, (_, count)) in grep_counts.into_iter().enumerate() {
            assert_eq!(count, v as u64);
        }
    }
}
