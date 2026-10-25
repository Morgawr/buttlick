use rustc_hash::FxHashMap;

use crate::engine::kmp_seam::{build_kmp_table, KmpDagIndex};
use crate::error::{ButtlickError, Result};
use crate::grammar::{check_range, GrammarDag, RootEntry, RuleKind, SymbolId};

/// Finds the starting index of the FIRST match of `pattern` in `haystack` using KMP.
#[inline]
fn kmp_first_match(haystack: &[u8], pattern: &[u8], pi: &[usize]) -> Option<usize> {
    let m = pattern.len();
    if m == 0 || haystack.len() < m {
        return None;
    }
    let mut q = 0usize;
    for (idx, &b) in haystack.iter().enumerate() {
        while q > 0 && pattern[q] != b {
            q = pi[q - 1];
        }
        if pattern[q] == b {
            q += 1;
            if q == m {
                return Some(idx + 1 - m);
            }
        }
    }
    None
}

#[derive(Clone, Debug)]
struct RewriteChunk {
    orig_sym: Option<SymbolId>,
    rewritten_sym: Option<SymbolId>,
    replaced_count: u64,
    orig_prefix: Vec<u8>,
    unconsumed_suffix: Vec<u8>,
}

impl GrammarDag {
    fn prepare_edit_interner(&mut self, roots: impl IntoIterator<Item = SymbolId>) {
        if self.interner.len() != self.rules.len() {
            self.interner.clear_tables();
        }
        let indices = self.reachable_rules(roots);
        self.interner.index_selected(&self.rules, &indices);
    }

    /// Concatenates two optional symbols in $O(\log N)$ time while maintaining height balance
    /// and canonical hash-consing (automatically coalescing runs of identical symbols).
    pub fn concat_symbols(
        &mut self,
        sym_a: Option<SymbolId>,
        sym_b: Option<SymbolId>,
    ) -> Option<SymbolId> {
        match (sym_a, sym_b) {
            (None, None) => None,
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (Some(a), Some(b)) => Some(self.concat_non_empty(a, b)),
        }
    }

    fn concat_non_empty(&mut self, a: SymbolId, b: SymbolId) -> SymbolId {
        if a == b {
            return self.intern_run(a, 2);
        }
        let ha = self.sym_height(a);
        let hb = self.sym_height(b);

        if ha > hb + 2 {
            if let RuleKind::Pair {
                left: al,
                right: ar,
            } = self.rule(a).kind
            {
                let new_right = self.concat_non_empty(ar, b);
                if self.sym_height(new_right) > self.sym_height(al) + 2 {
                    if let RuleKind::Pair {
                        left: nrl,
                        right: nrr,
                    } = self.rule(new_right).kind
                    {
                        let new_left = self.intern_pair(al, nrl);
                        return self.intern_pair(new_left, nrr);
                    }
                }
                return self.intern_pair(al, new_right);
            }
        } else if hb > ha + 2 {
            if let RuleKind::Pair {
                left: bl,
                right: br,
            } = self.rule(b).kind
            {
                let new_left = self.concat_non_empty(a, bl);
                if self.sym_height(new_left) > self.sym_height(br) + 2 {
                    if let RuleKind::Pair {
                        left: nll,
                        right: nlr,
                    } = self.rule(new_left).kind
                    {
                        let new_right = self.intern_pair(nlr, br);
                        return self.intern_pair(nll, new_right);
                    }
                }
                return self.intern_pair(new_left, br);
            }
        }

        self.intern_pair(a, b)
    }

    /// Splits `sym` at byte `offset` (`0 <= offset <= sym_len(sym)`) into `(left, right)`
    /// in $O(\log N)$ time without decompressing the data.
    pub fn split_symbol(
        &mut self,
        sym: SymbolId,
        offset: u64,
    ) -> (Option<SymbolId>, Option<SymbolId>) {
        let total_len = self.sym_len(sym);
        assert!(
            offset <= total_len,
            "split offset {offset} > total_len {total_len}"
        );
        if offset == 0 {
            return (None, Some(sym));
        }
        if offset == total_len {
            return (Some(sym), None);
        }

        let kind = self.rule(sym).kind;
        match kind {
            RuleKind::Pair { left, right } => {
                let left_len = self.sym_len(left);
                if offset == left_len {
                    (Some(left), Some(right))
                } else if offset < left_len {
                    let (l1, l2) = self.split_symbol(left, offset);
                    let r_combined = self.concat_symbols(l2, Some(right));
                    (l1, r_combined)
                } else {
                    let (r1, r2) = self.split_symbol(right, offset - left_len);
                    let l_combined = self.concat_symbols(Some(left), r1);
                    (l_combined, r2)
                }
            }
            RuleKind::Run { child, count } => {
                let c_len = self.sym_len(child);
                let q = offset / c_len;
                let r = offset % c_len;

                let left_full = if q == 0 {
                    None
                } else {
                    Some(self.intern_run(child, q))
                };

                if r == 0 {
                    let right_full = Some(self.intern_run(child, count - q));
                    (left_full, right_full)
                } else {
                    let rem = count - q - 1;
                    let right_full = if rem == 0 {
                        None
                    } else {
                        Some(self.intern_run(child, rem))
                    };
                    let (c1, c2) = self.split_symbol(child, r);
                    let left_res = self.concat_symbols(left_full, c1);
                    let right_res = self.concat_symbols(c2, right_full);
                    (left_res, right_res)
                }
            }
        }
    }

    fn update_root_symbol(
        &mut self,
        doc_name: Option<&str>,
        new_sym: Option<SymbolId>,
    ) -> Result<()> {
        let (byte_len, kr_hash) = match new_sym {
            Some(s) => (self.sym_len(s), self.sym_hash_reachable(s)),
            None => (0, 0),
        };
        let root = self.find_root_mut(doc_name)?;
        root.root_symbol = new_sym;
        root.byte_len = byte_len;
        root.kr_hash = kr_hash;
        Ok(())
    }

    /// Inserts `bytes` at byte `offset` in a named document in $O(\log N + |\text{bytes}|)$ time.
    pub fn insert(&mut self, doc_name: Option<&str>, offset: u64, bytes: &[u8]) -> Result<()> {
        let root = self.find_root(doc_name)?;
        if offset > root.byte_len {
            return Err(ButtlickError::OutOfBounds {
                offset,
                len: 0,
                total: root.byte_len,
            });
        }
        if bytes.is_empty() {
            return Ok(());
        }
        root.byte_len
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| {
                ButtlickError::InvalidQuery("inserted document exceeds the u64 length limit".into())
            })?;
        let root_sym = root.root_symbol;
        self.prepare_edit_interner(root_sym);
        let mid_sym = self.compress_bytes(bytes);

        let new_root = match root_sym {
            None => mid_sym,
            Some(sym) => {
                let (left, right) = self.split_symbol(sym, offset);
                let left_mid = self.concat_symbols(left, mid_sym);
                self.concat_symbols(left_mid, right)
            }
        };
        self.update_root_symbol(doc_name, new_root)
    }

    /// Deletes the byte range `[offset, offset + len)` from a named document in $O(\log N)$ time.
    pub fn delete(&mut self, doc_name: Option<&str>, offset: u64, len: u64) -> Result<()> {
        let root = self.find_root(doc_name)?;
        check_range(root, offset, len)?;
        if len == 0 {
            return Ok(());
        }
        let sym = root.root_symbol.unwrap();
        self.prepare_edit_interner([sym]);
        let (left, rest) = self.split_symbol(sym, offset);
        let right = match rest {
            Some(r_sym) => self.split_symbol(r_sym, len).1,
            None => None,
        };
        let new_root = self.concat_symbols(left, right);
        self.update_root_symbol(doc_name, new_root)
    }

    /// Concatenates two existing documents `doc1` and `doc2` into `new_name` in $O(\log N)$ time.
    pub fn concat_documents(
        &mut self,
        doc1: &str,
        doc2: &str,
        new_name: impl Into<String>,
    ) -> Result<RootEntry> {
        self.find_root(Some(doc1))?
            .byte_len
            .checked_add(self.find_root(Some(doc2))?.byte_len)
            .ok_or_else(|| {
                ButtlickError::InvalidQuery(
                    "concatenated document exceeds the u64 length limit".into(),
                )
            })?;
        let sym1 = self.find_root(Some(doc1))?.root_symbol;
        let sym2 = self.find_root(Some(doc2))?.root_symbol;
        self.prepare_edit_interner(sym1.into_iter().chain(sym2));
        let new_sym = self.concat_symbols(sym1, sym2);
        let (byte_len, kr_hash) = match new_sym {
            Some(s) => (self.sym_len(s), self.sym_hash_reachable(s)),
            None => (0, 0),
        };
        let entry = RootEntry {
            name: new_name.into(),
            root_symbol: new_sym,
            byte_len,
            kr_hash,
        };
        self.upsert_root(entry.clone());
        Ok(entry)
    }

    /// Replaces all non-overlapping occurrences of `pattern` with `replacement` across a document
    /// in $O(n \cdot |P|)$ time directly on the compressed DAG, returning the number of replacements made.
    pub fn replace_all(
        &mut self,
        doc_name: Option<&str>,
        pattern: &[u8],
        replacement: &[u8],
    ) -> Result<u64> {
        if pattern.is_empty() {
            return Err(ButtlickError::EmptyPattern);
        }
        let root = self.find_root(doc_name)?;
        let Some(root_sym) = root.root_symbol else {
            return Ok(0);
        };
        if (pattern.len() as u64) > root.byte_len {
            return Ok(0);
        }

        let kmp_index = KmpDagIndex::evaluate_root(self, pattern, root_sym)?;
        if kmp_index.count_symbol(root_sym) == 0 {
            return Ok(0);
        }
        self.prepare_edit_interner([root_sym]);
        let repl_sym = self.compress_bytes(replacement);

        let m = pattern.len();
        if m == 1 {
            let target = pattern[0];
            let mut memo: FxHashMap<SymbolId, (Option<SymbolId>, u64)> = FxHashMap::default();
            let (new_root, count) =
                self.replace_m1_recursive(root_sym, target, repl_sym, &kmp_index, &mut memo);
            self.update_root_symbol(doc_name, new_root)?;
            return Ok(count);
        }

        let pi = build_kmp_table(pattern);
        let mut memo: FxHashMap<SymbolId, RewriteChunk> = FxHashMap::default();
        let root_chunk =
            self.rewrite_symbol_memo(root_sym, pattern, &pi, repl_sym, &kmp_index, &mut memo);
        self.update_root_symbol(doc_name, root_chunk.rewritten_sym)?;
        Ok(root_chunk.replaced_count)
    }

    fn replace_m1_recursive(
        &mut self,
        sym: SymbolId,
        target: u8,
        repl_sym: Option<SymbolId>,
        kmp_index: &KmpDagIndex,
        memo: &mut FxHashMap<SymbolId, (Option<SymbolId>, u64)>,
    ) -> (Option<SymbolId>, u64) {
        if let Some(&cached) = memo.get(&sym) {
            return cached;
        }
        if let Some(b) = sym.as_byte() {
            if b == target {
                return (repl_sym, 1);
            } else {
                return (Some(sym), 0);
            }
        }
        if kmp_index.contains(sym) && kmp_index.count_symbol(sym) == 0 {
            return (Some(sym), 0);
        }
        let kind = self.rule(sym).kind;
        let res = match kind {
            RuleKind::Pair { left, right } => {
                let (nl, cl) = self.replace_m1_recursive(left, target, repl_sym, kmp_index, memo);
                let (nr, cr) = self.replace_m1_recursive(right, target, repl_sym, kmp_index, memo);
                (self.concat_symbols(nl, nr), cl + cr)
            }
            RuleKind::Run { child, count } => {
                let (nc, cc) = self.replace_m1_recursive(child, target, repl_sym, kmp_index, memo);
                let repeated = nc.map(|s| self.intern_run(s, count));
                (repeated, cc * count)
            }
        };
        memo.insert(sym, res);
        res
    }

    fn rewrite_symbol_memo(
        &mut self,
        sym: SymbolId,
        pattern: &[u8],
        pi: &[usize],
        repl_sym: Option<SymbolId>,
        kmp_index: &KmpDagIndex,
        memo: &mut FxHashMap<SymbolId, RewriteChunk>,
    ) -> RewriteChunk {
        if let Some(cached) = memo.get(&sym) {
            return cached.clone();
        }
        let w = pattern.len() - 1;

        if let Some(b) = sym.as_byte() {
            return RewriteChunk {
                orig_sym: Some(sym),
                rewritten_sym: Some(sym),
                replaced_count: 0,
                orig_prefix: vec![b],
                unconsumed_suffix: vec![b],
            };
        }

        // Fast path for pre-existing DAG nodes that have 0 matches of `pattern`
        if let Some(sum) = kmp_index.summary(sym).filter(|s| s.match_count == 0) {
            let chunk = RewriteChunk {
                orig_sym: Some(sym),
                rewritten_sym: Some(sym),
                replaced_count: 0,
                orig_prefix: sum.prefix.to_vec(),
                unconsumed_suffix: sum.suffix.to_vec(),
            };
            memo.insert(sym, chunk.clone());
            return chunk;
        }

        // Also check if `sym` is shorter than `pattern.len()`
        let total_len = self.sym_len(sym);
        if total_len < pattern.len() as u64 {
            let mut bytes = Vec::with_capacity(total_len as usize);
            self.decompress_symbol_into(sym, &mut bytes);
            let chunk = RewriteChunk {
                orig_sym: Some(sym),
                rewritten_sym: Some(sym),
                replaced_count: 0,
                orig_prefix: bytes.clone(),
                unconsumed_suffix: bytes,
            };
            memo.insert(sym, chunk.clone());
            return chunk;
        }

        let kind = self.rule(sym).kind;
        let mut res = match kind {
            RuleKind::Pair { left, right } => {
                let lc = self.rewrite_symbol_memo(left, pattern, pi, repl_sym, kmp_index, memo);
                let rc = self.rewrite_symbol_memo(right, pattern, pi, repl_sym, kmp_index, memo);
                self.combine_rewrite_chunks(&lc, &rc, pattern, pi, repl_sym, kmp_index, memo)
            }
            RuleKind::Run { child, count } => {
                let cc = self.rewrite_symbol_memo(child, pattern, pi, repl_sym, kmp_index, memo);
                self.power_rewrite_chunk(&cc, count, pattern, pi, repl_sym, kmp_index, memo)
            }
        };
        res.orig_sym = Some(sym);
        if res.orig_prefix.len() > w {
            res.orig_prefix.truncate(w);
        }
        memo.insert(sym, res.clone());
        res
    }

    #[allow(clippy::too_many_arguments)]
    fn combine_rewrite_chunks(
        &mut self,
        left: &RewriteChunk,
        right: &RewriteChunk,
        pattern: &[u8],
        pi: &[usize],
        repl_sym: Option<SymbolId>,
        kmp_index: &KmpDagIndex,
        memo: &mut FxHashMap<SymbolId, RewriteChunk>,
    ) -> RewriteChunk {
        let m = pattern.len();
        let w = m - 1;

        let mut orig_prefix = Vec::with_capacity(w);
        orig_prefix.extend_from_slice(&left.orig_prefix);
        if orig_prefix.len() < w {
            let needed = (w - orig_prefix.len()).min(right.orig_prefix.len());
            orig_prefix.extend_from_slice(&right.orig_prefix[..needed]);
        }

        let mut seam = Vec::with_capacity(left.unconsumed_suffix.len() + right.orig_prefix.len());
        seam.extend_from_slice(&left.unconsumed_suffix);
        seam.extend_from_slice(&right.orig_prefix);

        let orig_sym = self.concat_symbols(left.orig_sym, right.orig_sym);

        if let Some(match_pos) = kmp_first_match(&seam, pattern, pi) {
            // A match of `pattern` crosses the seam between `left` and `right`!
            let a = left.unconsumed_suffix.len() - match_pos;
            let c = m - a;
            debug_assert!(a >= 1 && a <= w);
            debug_assert!(c >= 1 && c <= w);

            let l_rew_len = left.rewritten_sym.map(|s| self.sym_len(s)).unwrap_or(0);
            let l_trimmed = match left.rewritten_sym {
                Some(s) => self.split_symbol(s, l_rew_len - (a as u64)).0,
                None => None,
            };
            let left_plus_repl = self.concat_symbols(l_trimmed, repl_sym);

            let r_orig = right.orig_sym.unwrap();
            let (_, r_rem_opt) = self.split_symbol(r_orig, c as u64);

            match r_rem_opt {
                None => RewriteChunk {
                    orig_sym,
                    rewritten_sym: left_plus_repl,
                    replaced_count: left.replaced_count + 1,
                    orig_prefix,
                    unconsumed_suffix: Vec::new(),
                },
                Some(r_rem_sym) => {
                    let rem_chunk =
                        self.rewrite_symbol_memo(r_rem_sym, pattern, pi, repl_sym, kmp_index, memo);
                    let rewritten_sym =
                        self.concat_symbols(left_plus_repl, rem_chunk.rewritten_sym);
                    RewriteChunk {
                        orig_sym,
                        rewritten_sym,
                        replaced_count: left.replaced_count + 1 + rem_chunk.replaced_count,
                        orig_prefix,
                        unconsumed_suffix: rem_chunk.unconsumed_suffix,
                    }
                }
            }
        } else {
            // No match across the seam!
            let rewritten_sym = self.concat_symbols(left.rewritten_sym, right.rewritten_sym);
            let replaced_count = left.replaced_count + right.replaced_count;
            let unconsumed_suffix = if right.replaced_count > 0 {
                right.unconsumed_suffix.clone()
            } else {
                // Zero matches occurred inside `right`, so all of `right` is unconsumed.
                let mut suf = Vec::with_capacity(w);
                if right.unconsumed_suffix.len() < w {
                    let needed =
                        (w - right.unconsumed_suffix.len()).min(left.unconsumed_suffix.len());
                    let start = left.unconsumed_suffix.len() - needed;
                    suf.extend_from_slice(&left.unconsumed_suffix[start..]);
                }
                suf.extend_from_slice(&right.unconsumed_suffix);
                suf
            };
            RewriteChunk {
                orig_sym,
                rewritten_sym,
                replaced_count,
                orig_prefix,
                unconsumed_suffix,
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn power_rewrite_chunk(
        &mut self,
        base: &RewriteChunk,
        mut k: u64,
        pattern: &[u8],
        pi: &[usize],
        repl_sym: Option<SymbolId>,
        kmp_index: &KmpDagIndex,
        memo: &mut FxHashMap<SymbolId, RewriteChunk>,
    ) -> RewriteChunk {
        debug_assert!(k >= 1);
        if k == 1 {
            return base.clone();
        }
        let mut acc: Option<RewriteChunk> = None;
        let mut cur = base.clone();
        while k > 0 {
            if k & 1 == 1 {
                acc = Some(match acc {
                    None => cur.clone(),
                    Some(prev) => self.combine_rewrite_chunks(
                        &prev, &cur, pattern, pi, repl_sym, kmp_index, memo,
                    ),
                });
            }
            k >>= 1;
            if k > 0 {
                cur =
                    self.combine_rewrite_chunks(&cur, &cur, pattern, pi, repl_sym, kmp_index, memo);
            }
        }
        acc.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_edit_insert_delete_concat() {
        let orig = b"Hello, grammar-homomorphic world!".to_vec();
        let mut ref_vec = orig.clone();
        let mut dag = GrammarDag::from_bytes(&orig);

        // Insert
        dag.insert(None, 7, b"amazing ").unwrap();
        ref_vec.splice(7..7, b"amazing ".iter().copied());
        assert_eq!(dag.decompress(None).unwrap(), ref_vec);
        dag.validate_invariants().unwrap();

        // Delete
        dag.delete(None, 0, 7).unwrap();
        ref_vec.drain(0..7);
        assert_eq!(dag.decompress(None).unwrap(), ref_vec);
        dag.validate_invariants().unwrap();

        // Concat documents
        dag.add_document("doc2", b" --- appended suffix!");
        dag.concat_documents("default", "doc2", "combined").unwrap();
        let mut expected_combined = ref_vec.clone();
        expected_combined.extend_from_slice(b" --- appended suffix!");
        assert_eq!(dag.decompress(Some("combined")).unwrap(), expected_combined);
        dag.validate_invariants().unwrap();
    }

    #[test]
    fn test_replace_all_overlapping_and_rle() {
        // Pitfall 3: "AA" -> "B" in "AAAA", "AAAAA", etc.
        for len in 1..=25 {
            let raw = vec![b'A'; len];
            for pat_len in 1..=5 {
                let pat = vec![b'A'; pat_len];
                for repl in [b"".as_slice(), b"B", b"XYZ", b"AA"] {
                    let mut dag = GrammarDag::from_bytes(&raw);
                    let count = dag.replace_all(None, &pat, repl).unwrap();
                    let (expected_bytes, expected_count) = brute_replace_all(&raw, &pat, repl);
                    assert_eq!(count, expected_count);
                    assert_eq!(dag.decompress(None).unwrap(), expected_bytes);
                    dag.validate_invariants().unwrap();
                }
            }
        }

        // Periodic alternating "ABABABAB..." with "ABA" -> "X"
        let raw_alt = b"AB".repeat(40);
        for pat in [b"AB".as_slice(), b"BA", b"ABA", b"BAB", b"ABAB"] {
            let mut dag = GrammarDag::from_bytes(&raw_alt);
            let count = dag.replace_all(None, pat, b"[REPL]").unwrap();
            let (expected_bytes, expected_count) = brute_replace_all(&raw_alt, pat, b"[REPL]");
            assert_eq!(count, expected_count);
            assert_eq!(dag.decompress(None).unwrap(), expected_bytes);
            dag.validate_invariants().unwrap();
        }
    }
}
