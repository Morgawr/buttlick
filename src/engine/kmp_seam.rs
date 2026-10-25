use crate::engine::transducer::MealyTransducer;
use crate::error::{ButtlickError, Result};
use crate::format::MappedArchive;
use crate::grammar::{GrammarDag, RuleKind, SymbolId};

/// Builds the Knuth-Morris-Pratt (KMP) prefix-function (failure) table for `pattern` in O(m) time.
pub fn build_kmp_table(pattern: &[u8]) -> Vec<usize> {
    let m = pattern.len();
    let mut pi = vec![0usize; m];
    let mut k = 0usize;
    for i in 1..m {
        while k > 0 && pattern[k] != pattern[i] {
            k = pi[k - 1];
        }
        if pattern[k] == pattern[i] {
            k += 1;
        }
        pi[i] = k;
    }
    pi
}

/// Counts all (potentially overlapping) occurrences of `pattern` in `haystack` using KMP in O(|haystack|) time.
#[inline]
pub fn kmp_count(haystack: &[u8], pattern: &[u8], pi: &[usize]) -> u64 {
    let m = pattern.len();
    if m == 0 || haystack.len() < m {
        return 0;
    }
    let mut count = 0u64;
    let mut q = 0usize;
    for &b in haystack {
        while q > 0 && pattern[q] != b {
            q = pi[q - 1];
        }
        if pattern[q] == b {
            q += 1;
            if q == m {
                count += 1;
                q = pi[q - 1];
            }
        }
    }
    count
}

/// Appends the starting byte index of every match of `pattern` in `haystack` (shifted by `base_offset`)
/// into `out`, stopping early if `out.len() >= limit`.
#[inline]
pub fn kmp_collect_offsets(
    haystack: &[u8],
    pattern: &[u8],
    pi: &[usize],
    base_offset: u64,
    limit: usize,
    out: &mut Vec<u64>,
) {
    let m = pattern.len();
    if m == 0 || haystack.len() < m || out.len() >= limit {
        return;
    }
    let mut q = 0usize;
    for (idx, &b) in haystack.iter().enumerate() {
        while q > 0 && pattern[q] != b {
            q = pi[q - 1];
        }
        if pattern[q] == b {
            q += 1;
            if q == m {
                let start_idx = (idx + 1 - m) as u64;
                out.push(base_offset + start_idx);
                if out.len() >= limit {
                    return;
                }
                q = pi[q - 1];
            }
        }
    }
}

/// Compact inline-or-heap byte buffer for KMP seam prefixes and suffixes.
/// Eliminates all per-rule heap allocations for patterns up to 16 bytes (`m - 1 <= 15`).
#[derive(Clone, Debug)]
pub enum SeamBytes {
    Inline { len: u8, buf: [u8; 15] },
    Heap(Vec<u8>),
}

impl SeamBytes {
    #[inline(always)]
    pub fn with_capacity(cap: usize) -> Self {
        if cap <= 15 {
            Self::Inline {
                len: 0,
                buf: [0u8; 15],
            }
        } else {
            Self::Heap(Vec::with_capacity(cap))
        }
    }

    #[inline(always)]
    pub fn from_single(b: u8, w: usize) -> Self {
        if w == 0 {
            Self::Inline {
                len: 0,
                buf: [0u8; 15],
            }
        } else {
            let mut buf = [0u8; 15];
            buf[0] = b;
            Self::Inline { len: 1, buf }
        }
    }

    #[inline(always)]
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        match self {
            Self::Inline { len, buf } => {
                let l = *len as usize;
                buf[l..l + slice.len()].copy_from_slice(slice);
                *len = (l + slice.len()) as u8;
            }
            Self::Heap(v) => v.extend_from_slice(slice),
        }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { len, buf } => &buf[..*len as usize],
            Self::Heap(v) => v.as_slice(),
        }
    }
}

impl std::ops::Deref for SeamBytes {
    type Target = [u8];
    #[inline(always)]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Monoid summary for a grammar symbol under the KMP Seam-Tracking Algebra.
#[derive(Clone, Debug)]
pub struct SeamSummary {
    pub byte_len: u64,
    pub match_count: u64,
    /// First `min(byte_len, m - 1)` bytes of the symbol's expansion.
    pub prefix: SeamBytes,
    /// Last `min(byte_len, m - 1)` bytes of the symbol's expansion.
    pub suffix: SeamBytes,
}

impl SeamSummary {
    #[inline]
    pub fn from_terminal(b: u8, m: usize) -> Self {
        let match_count = 0; // Only used when m >= 2
        let w = m - 1;
        let v = SeamBytes::from_single(b, w);
        Self {
            byte_len: 1,
            match_count,
            prefix: v.clone(),
            suffix: v,
        }
    }
}

/// Associative monoid operator combining two adjacent `SeamSummary` values `left` and `right`.
pub fn combine_seam(
    left: &SeamSummary,
    right: &SeamSummary,
    pattern: &[u8],
    pi: &[usize],
    seam_scratch: &mut Vec<u8>,
) -> SeamSummary {
    let w = pattern.len() - 1;

    seam_scratch.clear();
    seam_scratch.extend_from_slice(&left.suffix);
    seam_scratch.extend_from_slice(&right.prefix);
    let cross_matches = kmp_count(seam_scratch, pattern, pi);
    let match_count = left.match_count + right.match_count + cross_matches;

    let mut prefix = SeamBytes::with_capacity(w);
    prefix.extend_from_slice(&left.prefix);
    if prefix.len() < w {
        let needed = (w - prefix.len()).min(right.prefix.len());
        prefix.extend_from_slice(&right.prefix[..needed]);
    }

    let mut suffix = SeamBytes::with_capacity(w);
    if right.suffix.len() < w {
        let needed = (w - right.suffix.len()).min(left.suffix.len());
        let start = left.suffix.len() - needed;
        suffix.extend_from_slice(&left.suffix[start..]);
    }
    suffix.extend_from_slice(&right.suffix);

    SeamSummary {
        byte_len: left.byte_len + right.byte_len,
        match_count,
        prefix,
        suffix,
    }
}

/// Computes `base^k` in the KMP Seam-Tracking Monoid in O(m log k) time (or O(m) when `base.byte_len >= m - 1`).
pub fn power_seam(
    base: &SeamSummary,
    mut k: u64,
    pattern: &[u8],
    pi: &[usize],
    seam_scratch: &mut Vec<u8>,
) -> SeamSummary {
    debug_assert!(k >= 1);
    if k == 1 {
        return base.clone();
    }
    let w = pattern.len() - 1;
    // Fast path when a single copy of `base` already covers `m - 1` bytes:
    // Every seam between adjacent copies is identical, and no match can span >= 3 copies.
    if base.byte_len >= w as u64 {
        seam_scratch.clear();
        seam_scratch.extend_from_slice(&base.suffix);
        seam_scratch.extend_from_slice(&base.prefix);
        let seam_matches = kmp_count(seam_scratch, pattern, pi);
        return SeamSummary {
            byte_len: base.byte_len * k,
            match_count: k * base.match_count + (k - 1) * seam_matches,
            prefix: base.prefix.clone(),
            suffix: base.suffix.clone(),
        };
    }

    // General binary exponentiation for short periodic children (`base.byte_len < m - 1`)
    let mut acc: Option<SeamSummary> = None;
    let mut cur = base.clone();
    while k > 0 {
        if k & 1 == 1 {
            acc = Some(match acc {
                None => cur.clone(),
                Some(prev) => combine_seam(&prev, &cur, pattern, pi, seam_scratch),
            });
        }
        k >>= 1;
        if k > 0 {
            cur = combine_seam(&cur, &cur, pattern, pi, seam_scratch);
        }
    }
    acc.unwrap()
}

/// Precomputed exact-search state across all rules in a `GrammarDag` for a given pattern.
pub struct KmpDagIndex {
    pub pattern: Vec<u8>,
    pub pi: Vec<usize>,
    /// Used when pattern.len() == 1
    pub single_counts: Vec<u64>,
    /// Used when pattern.len() >= 2
    pub summaries: Vec<SeamSummary>,
}

impl KmpDagIndex {
    /// Evaluates the KMP Seam-Tracking Monoid bottom-up across all rules in `dag` in O(n * |P|) time.
    pub fn evaluate(dag: &GrammarDag, pattern: &[u8]) -> Result<Self> {
        if pattern.is_empty() {
            return Err(ButtlickError::EmptyPattern);
        }
        let m = pattern.len();
        let pi = build_kmp_table(pattern);

        if m == 1 {
            let target = pattern[0];
            let mut single_counts = vec![0u64; dag.rules.len()];
            let sym_count = |sym: SymbolId, counts: &[u64]| -> u64 {
                if let Some(b) = sym.as_byte() {
                    (b == target) as u64
                } else {
                    counts[sym.rule_index()]
                }
            };
            for (idx, node) in dag.rules.iter().enumerate() {
                single_counts[idx] = match node.kind {
                    RuleKind::Pair { left, right } => {
                        sym_count(left, &single_counts) + sym_count(right, &single_counts)
                    }
                    RuleKind::Run { child, count } => count * sym_count(child, &single_counts),
                };
            }
            return Ok(Self {
                pattern: pattern.to_vec(),
                pi,
                single_counts,
                summaries: Vec::new(),
            });
        }

        let mut summaries: Vec<SeamSummary> = Vec::with_capacity(dag.rules.len());
        let mut seam_scratch = Vec::with_capacity(2 * m);

        let get_summary = |sym: SymbolId, table: &[SeamSummary]| -> SeamSummary {
            if let Some(b) = sym.as_byte() {
                SeamSummary::from_terminal(b, m)
            } else {
                table[sym.rule_index()].clone()
            }
        };

        for node in &dag.rules {
            let sum = match node.kind {
                RuleKind::Pair { left, right } => {
                    match (left.as_byte(), right.as_byte()) {
                        (Some(lb), Some(rb)) => {
                            let ls = SeamSummary::from_terminal(lb, m);
                            let rs = SeamSummary::from_terminal(rb, m);
                            combine_seam(&ls, &rs, pattern, &pi, &mut seam_scratch)
                        }
                        (Some(lb), None) => {
                            let ls = SeamSummary::from_terminal(lb, m);
                            let rs = &summaries[right.rule_index()];
                            combine_seam(&ls, rs, pattern, &pi, &mut seam_scratch)
                        }
                        (None, Some(rb)) => {
                            let ls = &summaries[left.rule_index()];
                            let rs = SeamSummary::from_terminal(rb, m);
                            combine_seam(ls, &rs, pattern, &pi, &mut seam_scratch)
                        }
                        (None, None) => {
                            let ls = &summaries[left.rule_index()];
                            let rs = &summaries[right.rule_index()];
                            combine_seam(ls, rs, pattern, &pi, &mut seam_scratch)
                        }
                    }
                }
                RuleKind::Run { child, count } => {
                    let cs = get_summary(child, &summaries);
                    power_seam(&cs, count, pattern, &pi, &mut seam_scratch)
                }
            };
            summaries.push(sum);
        }

        Ok(Self {
            pattern: pattern.to_vec(),
            pi,
            single_counts: Vec::new(),
            summaries,
        })
    }

    /// Returns the total match count for `sym` in O(1) time.
    #[inline]
    pub fn count_symbol(&self, sym: SymbolId) -> u64 {
        if self.pattern.len() == 1 {
            if let Some(b) = sym.as_byte() {
                (b == self.pattern[0]) as u64
            } else {
                self.single_counts[sym.rule_index()]
            }
        } else if sym.is_terminal() {
            0
        } else {
            self.summaries[sym.rule_index()].match_count
        }
    }

    #[inline]
    fn summary_of(&self, sym: SymbolId) -> SeamSummary {
        if let Some(b) = sym.as_byte() {
            SeamSummary::from_terminal(b, self.pattern.len())
        } else {
            self.summaries[sym.rule_index()].clone()
        }
    }

    /// Extracts the first `limit` 64-bit byte offsets of matches inside `sym` in O(k log N) time.
    pub fn locate_symbol(
        &self,
        dag: &GrammarDag,
        sym: SymbolId,
        limit: usize,
        out: &mut Vec<u64>,
    ) {
        if limit == 0 || self.count_symbol(sym) == 0 {
            return;
        }
        if self.pattern.len() == 1 {
            self.collect_m1(dag, sym, 0, limit, out);
        } else {
            let mut scratch = Vec::with_capacity(2 * self.pattern.len());
            self.collect_m_general(dag, sym, 0, limit, out, &mut scratch);
        }
    }

    fn collect_m1(
        &self,
        dag: &GrammarDag,
        sym: SymbolId,
        base_offset: u64,
        limit: usize,
        out: &mut Vec<u64>,
    ) {
        if out.len() >= limit || self.count_symbol(sym) == 0 {
            return;
        }
        if sym.is_terminal() {
            out.push(base_offset);
            return;
        }
        let node = dag.rule(sym);
        match node.kind {
            RuleKind::Pair { left, right } => {
                self.collect_m1(dag, left, base_offset, limit, out);
                if out.len() < limit {
                    let left_len = dag.sym_len(left);
                    self.collect_m1(dag, right, base_offset + left_len, limit, out);
                }
            }
            RuleKind::Run { child, count } => {
                let c_len = dag.sym_len(child);
                for i in 0..count {
                    if out.len() >= limit {
                        break;
                    }
                    self.collect_m1(dag, child, base_offset + i * c_len, limit, out);
                }
            }
        }
    }

    fn collect_m_general(
        &self,
        dag: &GrammarDag,
        sym: SymbolId,
        base_offset: u64,
        limit: usize,
        out: &mut Vec<u64>,
        scratch: &mut Vec<u8>,
    ) {
        if out.len() >= limit || self.count_symbol(sym) == 0 {
            return;
        }
        let node = dag.rule(sym);
        match node.kind {
            RuleKind::Pair { left, right } => {
                self.collect_m_general(dag, left, base_offset, limit, out, scratch);
                if out.len() >= limit {
                    return;
                }
                let l_sum = self.summary_of(left);
                let r_sum = self.summary_of(right);

                scratch.clear();
                scratch.extend_from_slice(&l_sum.suffix);
                scratch.extend_from_slice(&r_sum.prefix);
                let seam_start = base_offset + l_sum.byte_len - (l_sum.suffix.len() as u64);
                kmp_collect_offsets(scratch, &self.pattern, &self.pi, seam_start, limit, out);
                if out.len() >= limit {
                    return;
                }

                self.collect_m_general(
                    dag,
                    right,
                    base_offset + l_sum.byte_len,
                    limit,
                    out,
                    scratch,
                );
            }
            RuleKind::Run { child, count } => {
                let child_sum = self.summary_of(child);
                let _ = self.collect_run_virtual(
                    dag,
                    child,
                    &child_sum,
                    count,
                    base_offset,
                    limit,
                    out,
                    scratch,
                );
            }
        }
    }

    /// Recursively decomposes `child^k` as a virtual balanced binary tree `child^(k/2) || child^(k - k/2)`
    /// to emit exact match offsets in strictly increasing order while pruning zero-match subtrees.
    #[allow(clippy::too_many_arguments)]
    fn collect_run_virtual(
        &self,
        dag: &GrammarDag,
        child: SymbolId,
        child_sum: &SeamSummary,
        k: u64,
        base_offset: u64,
        limit: usize,
        out: &mut Vec<u64>,
        scratch: &mut Vec<u8>,
    ) -> SeamSummary {
        if k == 1 {
            if out.len() < limit && child_sum.match_count > 0 {
                self.collect_m_general(dag, child, base_offset, limit, out, scratch);
            }
            return child_sum.clone();
        }

        // Fast check: if child^k has 0 matches overall or we already hit the limit,
        // compute summary without descending.
        let total_sum = power_seam(child_sum, k, &self.pattern, &self.pi, scratch);
        if total_sum.match_count == 0 || out.len() >= limit {
            return total_sum;
        }

        let k_left = k / 2;
        let k_right = k - k_left;

        let left_sum = self.collect_run_virtual(
            dag,
            child,
            child_sum,
            k_left,
            base_offset,
            limit,
            out,
            scratch,
        );
        if out.len() >= limit {
            return total_sum;
        }

        let right_sum = power_seam(child_sum, k_right, &self.pattern, &self.pi, scratch);

        scratch.clear();
        scratch.extend_from_slice(&left_sum.suffix);
        scratch.extend_from_slice(&right_sum.prefix);
        let seam_start = base_offset + left_sum.byte_len - (left_sum.suffix.len() as u64);
        kmp_collect_offsets(scratch, &self.pattern, &self.pi, seam_start, limit, out);
        if out.len() >= limit {
            return total_sum;
        }

        if right_sum.match_count > 0 {
            let _ = self.collect_run_virtual(
                dag,
                child,
                child_sum,
                k_right,
                base_offset + left_sum.byte_len,
                limit,
                out,
                scratch,
            );
        }

        total_sum
    }
}

/// Compiles `pattern` into a KMP-automaton `MealyTransducer` over states `0..m` (number of pattern
/// bytes currently matched) that emits `1` on every byte completing an occurrence. Overlapping
/// occurrences are included, so transducer-based evaluators count exactly what `kmp_count` counts.
pub fn compile_literal_transducer(pattern: &[u8]) -> Result<MealyTransducer> {
    if pattern.is_empty() {
        return Err(ButtlickError::EmptyPattern);
    }
    let m = pattern.len();
    if m > u16::MAX as usize {
        return Err(ButtlickError::InvalidQuery(format!(
            "literal pattern too long for a transducer ({m} bytes)"
        )));
    }
    let pi = build_kmp_table(pattern);
    let mut byte_next = vec![0u16; m * 256];
    let mut byte_emit = vec![0u64; m * 256];
    for q in 0..m {
        for b in 0..=255u8 {
            // Standard KMP automaton transition, built by dynamic programming over the failure
            // links: `pi[q - 1] < q`, so its transitions are already final (and never the
            // completing transition, which only exists for state `m - 1`).
            let k = if pattern[q] == b {
                q + 1
            } else if q == 0 {
                0
            } else {
                byte_next[pi[q - 1] * 256 + b as usize] as usize
            };
            let idx = q * 256 + b as usize;
            if k == m {
                byte_emit[idx] = 1;
                byte_next[idx] = pi[m - 1] as u16;
            } else {
                byte_next[idx] = k as u16;
            }
        }
    }
    Ok(MealyTransducer {
        num_states: m,
        start_state: 0,
        byte_next,
        byte_emit,
        eof_emit: vec![0u64; m],
    })
}

impl MappedArchive {
    /// Zero-copy exact substring count (overlapping occurrences) on a named document, evaluated
    /// directly on the memory-mapped rule table with 1–2 bytes of state per symbol.
    pub fn count_literal(&self, doc_name: Option<&str>, pattern: &[u8]) -> Result<u64> {
        let root = self.find_root(doc_name)?;
        if pattern.is_empty() {
            return Err(ButtlickError::EmptyPattern);
        }
        if root.root_symbol.is_none() || (pattern.len() as u64) > root.byte_len {
            return Ok(0);
        }
        Ok(self.count_literal_roots(pattern, &[root.root_symbol])?[0])
    }

    /// Zero-copy exact substring count across ALL documents in a single pass over the rule table.
    pub fn count_literal_all_docs(&self, pattern: &[u8]) -> Result<Vec<(String, u64)>> {
        if pattern.is_empty() {
            return Err(ButtlickError::EmptyPattern);
        }
        let roots: Vec<Option<SymbolId>> = self.roots.iter().map(|r| r.root_symbol).collect();
        let counts = self.count_literal_roots(pattern, &roots)?;
        Ok(self
            .roots
            .iter()
            .zip(counts)
            .map(|(r, c)| (r.name.clone(), c))
            .collect())
    }

    /// Zero-copy exact substring count plus the byte offsets of the first `limit` matches
    /// (in increasing order) on a named document.
    pub fn locate_literal(
        &self,
        doc_name: Option<&str>,
        pattern: &[u8],
        limit: usize,
    ) -> Result<(u64, Vec<u64>)> {
        let root = self.find_root(doc_name)?;
        if pattern.is_empty() {
            return Err(ButtlickError::EmptyPattern);
        }
        let Some(sym) = root.root_symbol else {
            return Ok((0, Vec::new()));
        };
        if (pattern.len() as u64) > root.byte_len {
            return Ok((0, Vec::new()));
        }
        if pattern.len() > MAX_MAPPED_LITERAL_LEN {
            return self.load_grammar_dag()?.locate_literal(doc_name, pattern, limit);
        }
        let transducer = compile_literal_transducer(pattern)?;
        let (count, match_ends) =
            self.locate_emissions(&transducer, sym, limit, &String::from_utf8_lossy(pattern))?;
        // The transducer emits on the last byte of each occurrence.
        let m = pattern.len() as u64;
        Ok((count, match_ends.into_iter().map(|end| end + 1 - m).collect()))
    }

    fn count_literal_roots(&self, pattern: &[u8], roots: &[Option<SymbolId>]) -> Result<Vec<u64>> {
        if pattern.len() > MAX_MAPPED_LITERAL_LEN {
            // Too many automaton states for the packed evaluators: fall back to the fully decoded
            // KMP seam-tracking evaluation.
            let dag = self.load_grammar_dag()?;
            let index = KmpDagIndex::evaluate(&dag, pattern)?;
            return Ok(roots
                .iter()
                .map(|r| r.map_or(0, |sym| index.count_symbol(sym)))
                .collect());
        }
        let transducer = compile_literal_transducer(pattern)?;
        self.count_emissions(&transducer, roots, &String::from_utf8_lossy(pattern))
    }
}

/// Longest literal handled by the packed mmap evaluators (one automaton state per pattern byte).
const MAX_MAPPED_LITERAL_LEN: usize = 0x8000;

impl GrammarDag {
    /// Zero-decompression exact substring count on a named document in O(n * |P|) time.
    pub fn count_literal(&self, doc_name: Option<&str>, pattern: &[u8]) -> Result<u64> {
        let root = self.find_root(doc_name)?;
        if pattern.is_empty() {
            return Err(ButtlickError::EmptyPattern);
        }
        let Some(sym) = root.root_symbol else {
            return Ok(0);
        };
        if (pattern.len() as u64) > root.byte_len {
            return Ok(0);
        }
        let index = KmpDagIndex::evaluate(self, pattern)?;
        Ok(index.count_symbol(sym))
    }

    /// Zero-decompression exact substring count AND lazy top-`limit` byte offset extraction
    /// in O(n * |P| + k log N) time.
    pub fn locate_literal(
        &self,
        doc_name: Option<&str>,
        pattern: &[u8],
        limit: usize,
    ) -> Result<(u64, Vec<u64>)> {
        let root = self.find_root(doc_name)?;
        if pattern.is_empty() {
            return Err(ButtlickError::EmptyPattern);
        }
        let Some(sym) = root.root_symbol else {
            return Ok((0, Vec::new()));
        };
        if (pattern.len() as u64) > root.byte_len {
            return Ok((0, Vec::new()));
        }
        let index = KmpDagIndex::evaluate(self, pattern)?;
        let total_count = index.count_symbol(sym);
        let mut offsets = Vec::with_capacity(limit.min(total_count as usize));
        if total_count > 0 && limit > 0 {
            index.locate_symbol(self, sym, limit, &mut offsets);
        }
        Ok((total_count, offsets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brute_force_offsets(haystack: &[u8], needle: &[u8]) -> Vec<u64> {
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
    fn test_kmp_seam_overlapping_and_periodic() {
        // Pitfall 2: Pattern longer than RLE child ("AAAAA" in 'A'^100)
        let data = vec![b'A'; 100];
        let dag = GrammarDag::from_bytes(&data);
        for pat_len in 1..=15 {
            let pat = vec![b'A'; pat_len];
            let (count, offsets) = dag.locate_literal(None, &pat, usize::MAX).unwrap();
            let expected = brute_force_offsets(&data, &pat);
            assert_eq!(count, expected.len() as u64);
            assert_eq!(offsets, expected);
        }

        // Periodic multi-byte child ("ABABAB" in ("AB")^50)
        let data2 = b"AB".repeat(50);
        let dag2 = GrammarDag::from_bytes(&data2);
        for pat in &[b"A".as_slice(), b"AB", b"BA", b"ABA", b"BAB", b"ABABAB", b"BABABA"] {
            let (count, offsets) = dag2.locate_literal(None, pat, usize::MAX).unwrap();
            let expected = brute_force_offsets(&data2, pat);
            assert_eq!(count, expected.len() as u64, "Failed count for {:?}", pat);
            assert_eq!(offsets, expected, "Failed offsets for {:?}", pat);
        }
    }
}
