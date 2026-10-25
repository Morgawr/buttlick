pub mod builder;
pub mod edit;
pub mod lcp;
pub mod navigate;

use std::sync::Mutex;

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::error::{ButtlickError, Result};
use crate::grammar::builder::RuleInterner;
use crate::hash::{byte_hash, combine_hashes, mod_mul, repeat_hash_and_pow, HASH_BASE};

/// A symbol in the RLSLP grammar.
/// IDs 0..=255 are literal terminal bytes (0x00..=0xFF).
/// IDs >= 256 are non-terminal rules stored at index (id - 256) in `GrammarDag::rules`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct SymbolId(pub u32);

impl SymbolId {
    pub const FIRST_NON_TERMINAL: u32 = 256;
    pub const MAX_RULES: usize = (1usize << 31) - Self::FIRST_NON_TERMINAL as usize;

    #[inline(always)]
    pub const fn from_byte(b: u8) -> Self {
        Self(b as u32)
    }

    #[inline(always)]
    pub const fn from_rule_index(idx: usize) -> Self {
        assert!(
            idx < Self::MAX_RULES,
            "rule index exceeds the .btlk 31-bit symbol limit"
        );
        Self((idx as u32) + Self::FIRST_NON_TERMINAL)
    }

    /// Exclusive symbol bound; unlike an allocated id this may equal the run-tag bit.
    pub(crate) const fn rule_watermark(len: usize) -> u32 {
        assert!(
            len <= Self::MAX_RULES,
            "rule table exceeds the .btlk 31-bit symbol limit"
        );
        len as u32 + Self::FIRST_NON_TERMINAL
    }

    #[inline(always)]
    pub const fn is_terminal(self) -> bool {
        self.0 < Self::FIRST_NON_TERMINAL
    }

    #[inline(always)]
    pub const fn as_byte(self) -> Option<u8> {
        if self.0 < Self::FIRST_NON_TERMINAL {
            Some(self.0 as u8)
        } else {
            None
        }
    }

    #[inline(always)]
    pub const fn rule_index(self) -> usize {
        debug_assert!(self.0 >= Self::FIRST_NON_TERMINAL);
        (self.0 - Self::FIRST_NON_TERMINAL) as usize
    }
}

/// Largest `Run` repetition count representable in the on-disk `.btlk` rule format
/// (`PackedRuleNode` stores it in a `u32`). Larger repetitions are built from nested runs.
pub const MAX_RUN_COUNT: u64 = u32::MAX as u64;

/// Canonical production rule for a non-terminal symbol.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleKind {
    /// Concatenation: X -> left right (where left != right)
    Pair { left: SymbolId, right: SymbolId },
    /// Run-Length Encoding: X -> child^count (where count >= 2)
    Run { child: SymbolId, count: u64 },
}

/// Complete metadata stored per non-terminal rule in the DAG.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleNode {
    pub kind: RuleKind,
    /// Total uncompressed byte length of this symbol's expansion.
    pub byte_len: u64,
    /// Subtree height (terminals have height 0).
    pub height: u16,
    /// First byte of expansion (fast-path for seam/navigation).
    pub first_byte: u8,
    /// Last byte of expansion (fast-path for seam/navigation).
    pub last_byte: u8,
}

/// Represents a top-level document or version inside a Buttlick archive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootEntry {
    pub name: String,
    /// `None` if and only if the document is 0 bytes (empty).
    pub root_symbol: Option<SymbolId>,
    pub byte_len: u64,
    pub kr_hash: u64,
}

/// Check a half-open document range without overflowing at the `u64::MAX` boundary.
pub(crate) fn check_range(root: &RootEntry, start: u64, len: u64) -> Result<()> {
    if start > root.byte_len || len > root.byte_len - start {
        return Err(ButtlickError::OutOfBounds {
            offset: start,
            len,
            total: root.byte_len,
        });
    }
    Ok(())
}

/// Given `out[start..]` holding one copy of a piece, appends copies until it holds `count` copies
/// in total, doubling the copied span each step.
#[inline]
pub(crate) fn repeat_tail(out: &mut Vec<u8>, start: usize, count: u64) {
    let piece_len = out.len() - start;
    if piece_len == 0 || count <= 1 {
        return;
    }
    out.reserve(piece_len.saturating_mul(count as usize - 1));
    let mut copied = 1u64;
    while copied < count {
        let to_copy = copied.min(count - copied);
        out.extend_from_within(start..start + (to_copy as usize) * piece_len);
        copied += to_copy;
    }
}

/// Index of the root named `doc_name`, or of the first root if `doc_name` is `None`.
pub(crate) fn find_root_index(roots: &[RootEntry], doc_name: Option<&str>) -> Result<usize> {
    match doc_name {
        Some(name) => roots
            .iter()
            .position(|r| r.name == name)
            .ok_or_else(|| ButtlickError::DocumentNotFound(name.to_string())),
        None if roots.is_empty() => Err(ButtlickError::DocumentNotFound(
            "<empty archive>".to_string(),
        )),
        None => Ok(0),
    }
}

/// Finds the root named `doc_name`, or the first root if `doc_name` is `None`.
#[inline]
pub(crate) fn find_root_in<'a>(
    roots: &'a [RootEntry],
    doc_name: Option<&str>,
) -> Result<&'a RootEntry> {
    find_root_index(roots, doc_name).map(|idx| &roots[idx])
}

/// Lazy append-only cache of `(kr_hash, kr_pow)` per rule in `GrammarDag::rules`.
/// Stays completely unallocated during `compress`, `decompress`, `count`, `grep`, `query`, and `slice`,
/// and populates on demand in a single topological pass when `eq` (`range_hash`) or `validate_invariants` runs.
#[derive(Debug, Default)]
pub struct KrCache {
    inner: Mutex<Vec<(u64, u64)>>,
}

impl Clone for KrCache {
    fn clone(&self) -> Self {
        let vec = self.inner.lock().unwrap().clone();
        Self {
            inner: Mutex::new(vec),
        }
    }
}

/// The complete Run-Length Straight-Line Program (RLSLP) DAG.
#[derive(Clone, Debug, Default)]
pub struct GrammarDag {
    pub rules: Vec<RuleNode>,
    pub roots: Vec<RootEntry>,
    pub interner: RuleInterner,
    pub kr_cache: KrCache,
    pub(crate) root_hashes_are_fingerprints: bool,
}

impl GrammarDag {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            roots: Vec::new(),
            interner: RuleInterner::new(),
            kr_cache: KrCache::default(),
            root_hashes_are_fingerprints: false,
        }
    }

    pub fn from_parts(rules: Vec<RuleNode>, roots: Vec<RootEntry>) -> Self {
        Self {
            rules,
            roots,
            interner: RuleInterner::new(),
            kr_cache: KrCache::default(),
            root_hashes_are_fingerprints: false,
        }
    }

    #[inline(always)]
    fn ensure_interner(&mut self) {
        if self.interner.len() != self.rules.len() {
            self.interner = RuleInterner::from_rules(&self.rules);
        }
    }

    #[inline(always)]
    pub fn rule(&self, sym: SymbolId) -> &RuleNode {
        &self.rules[sym.rule_index()]
    }

    #[inline(always)]
    pub fn sym_len(&self, sym: SymbolId) -> u64 {
        if sym.is_terminal() {
            1
        } else {
            self.rules[sym.rule_index()].byte_len
        }
    }

    /// Returns `(kr_hash, kr_pow)` for `sym` in O(1) amortized time by extending the lazy topological cache.
    #[inline]
    pub fn sym_hash_and_pow(&self, sym: SymbolId) -> (u64, u64) {
        if let Some(b) = sym.as_byte() {
            return (byte_hash(b), HASH_BASE);
        }
        let target_idx = sym.rule_index();
        let mut cache = self.kr_cache.inner.lock().unwrap();
        if cache.len() <= target_idx {
            let needed = self.rules.len() - cache.len();
            cache.reserve(needed);
            for idx in cache.len()..self.rules.len() {
                let node = &self.rules[idx];
                let entry = match node.kind {
                    RuleKind::Pair { left, right } => {
                        let (l_hash, l_pow) = if let Some(b) = left.as_byte() {
                            (byte_hash(b), HASH_BASE)
                        } else {
                            cache[left.rule_index()]
                        };
                        let (r_hash, r_pow) = if let Some(b) = right.as_byte() {
                            (byte_hash(b), HASH_BASE)
                        } else {
                            cache[right.rule_index()]
                        };
                        (combine_hashes(l_hash, r_hash, r_pow), mod_mul(l_pow, r_pow))
                    }
                    RuleKind::Run { child, count } => {
                        let (c_hash, c_pow) = if let Some(b) = child.as_byte() {
                            (byte_hash(b), HASH_BASE)
                        } else {
                            cache[child.rule_index()]
                        };
                        repeat_hash_and_pow(c_hash, c_pow, count)
                    }
                };
                cache.push(entry);
            }
        }
        cache[target_idx]
    }

    #[inline(always)]
    pub fn sym_hash(&self, sym: SymbolId) -> u64 {
        self.sym_hash_and_pow(sym).0
    }

    /// Hashes only the requested sub-DAG without populating the archive-wide `KrCache`.
    /// Suitable for edits to a small document in a large shared archive.
    pub(crate) fn sym_hash_reachable(&self, sym: SymbolId) -> u64 {
        fn visit(
            dag: &GrammarDag,
            sym: SymbolId,
            memo: &mut FxHashMap<SymbolId, (u64, u64)>,
        ) -> (u64, u64) {
            if let Some(b) = sym.as_byte() {
                return (byte_hash(b), HASH_BASE);
            }
            if let Some(&entry) = memo.get(&sym) {
                return entry;
            }
            let entry = match dag.rule(sym).kind {
                RuleKind::Pair { left, right } => {
                    let (lh, lp) = visit(dag, left, memo);
                    let (rh, rp) = visit(dag, right, memo);
                    (combine_hashes(lh, rh, rp), mod_mul(lp, rp))
                }
                RuleKind::Run { child, count } => {
                    let (h, p) = visit(dag, child, memo);
                    repeat_hash_and_pow(h, p, count)
                }
            };
            memo.insert(sym, entry);
            entry
        }
        visit(self, sym, &mut FxHashMap::default()).0
    }

    #[inline(always)]
    pub fn sym_pow(&self, sym: SymbolId) -> u64 {
        self.sym_hash_and_pow(sym).1
    }

    #[inline(always)]
    pub fn sym_height(&self, sym: SymbolId) -> u16 {
        if sym.is_terminal() {
            0
        } else {
            self.rules[sym.rule_index()].height
        }
    }

    #[inline(always)]
    pub fn sym_first_byte(&self, sym: SymbolId) -> u8 {
        if let Some(b) = sym.as_byte() {
            b
        } else {
            self.rules[sym.rule_index()].first_byte
        }
    }

    #[inline(always)]
    pub fn sym_last_byte(&self, sym: SymbolId) -> u8 {
        if let Some(b) = sym.as_byte() {
            b
        } else {
            self.rules[sym.rule_index()].last_byte
        }
    }

    #[inline]
    pub fn intern_pair(&mut self, left: SymbolId, right: SymbolId) -> SymbolId {
        self.ensure_interner();
        self.interner.intern_pair(&mut self.rules, left, right)
    }

    #[inline]
    pub fn intern_run(&mut self, child: SymbolId, count: u64) -> SymbolId {
        self.ensure_interner();
        self.interner.intern_run(&mut self.rules, child, count)
    }

    /// Finds a `RootEntry` by name, or returns the first root if `doc_name` is `None`.
    pub fn find_root(&self, doc_name: Option<&str>) -> Result<&RootEntry> {
        find_root_in(&self.roots, doc_name)
    }

    /// Whether all root hashes are guaranteed to be polynomial Karp-Rabin hashes.
    pub fn root_hashes_are_exact(&self) -> bool {
        !self.root_hashes_are_fingerprints
    }

    /// Finds a mutable `RootEntry` by name, or returns the first root if `doc_name` is `None`.
    pub fn find_root_mut(&mut self, doc_name: Option<&str>) -> Result<&mut RootEntry> {
        let idx = find_root_index(&self.roots, doc_name)?;
        Ok(&mut self.roots[idx])
    }

    /// Replaces the root named `entry.name` if present, otherwise appends `entry`.
    pub(crate) fn upsert_root(&mut self, entry: RootEntry) {
        if let Some(existing) = self.roots.iter_mut().find(|r| r.name == entry.name) {
            *existing = entry;
        } else {
            self.roots.push(entry);
        }
    }

    /// Total uncompressed bytes across all roots, capped at `u64::MAX` for in-memory
    /// DAGs exceeding the format's total-size limit. Serialization rejects such DAGs.
    pub fn total_uncompressed_bytes(&self) -> u64 {
        self.roots
            .iter()
            .fold(0, |sum: u64, root| sum.saturating_add(root.byte_len))
    }

    /// Maximum tree height across all roots in the archive.
    pub fn max_height(&self) -> u16 {
        self.roots
            .iter()
            .filter_map(|r| r.root_symbol.map(|s| self.sym_height(s)))
            .max()
            .unwrap_or(0)
    }

    /// Returns reachable rule indices in topological order.
    pub(crate) fn reachable_rules(&self, roots: impl IntoIterator<Item = SymbolId>) -> Vec<usize> {
        let mut bits = vec![0u64; self.rules.len().div_ceil(64)];
        let mut stack: Vec<_> = roots.into_iter().collect();
        let mut indices = Vec::new();
        while let Some(sym) = stack.pop() {
            if sym.is_terminal() {
                continue;
            }
            let idx = sym.rule_index();
            let bit = 1u64 << (idx % 64);
            if bits[idx / 64] & bit != 0 {
                continue;
            }
            bits[idx / 64] |= bit;
            indices.push(idx);
            match self.rules[idx].kind {
                RuleKind::Pair { left, right } => {
                    stack.push(right);
                    stack.push(left);
                }
                RuleKind::Run { child, .. } => stack.push(child),
            }
        }
        indices.sort_unstable();
        indices
    }

    /// Removes rules unreachable from every document and renumbers the survivors in place.
    /// Returns the number removed. All roots and expanded bytes remain unchanged.
    pub fn compact(&mut self) -> usize {
        let reachable = self.reachable_rules(self.roots.iter().filter_map(|r| r.root_symbol));
        if reachable.len() == self.rules.len() {
            return 0;
        }
        let removed = self.rules.len() - reachable.len();
        let mut remap = vec![SymbolId(0); self.rules.len()];
        for (new_idx, &old_idx) in reachable.iter().enumerate() {
            let map = |s: SymbolId| {
                if s.is_terminal() {
                    s
                } else {
                    remap[s.rule_index()]
                }
            };
            let mut node = self.rules[old_idx];
            node.kind = match node.kind {
                RuleKind::Pair { left, right } => RuleKind::Pair {
                    left: map(left),
                    right: map(right),
                },
                RuleKind::Run { child, count } => RuleKind::Run {
                    child: map(child),
                    count,
                },
            };
            self.rules[new_idx] = node;
            remap[old_idx] = SymbolId::from_rule_index(new_idx);
        }
        for root in &mut self.roots {
            if let Some(sym) = &mut root.root_symbol {
                if !sym.is_terminal() {
                    *sym = remap[sym.rule_index()];
                }
            }
        }
        self.rules.truncate(reachable.len());
        self.interner.clear_tables();
        self.kr_cache = KrCache::default();
        removed
    }

    /// Validates all structural, topological, length, and hash invariants of the DAG.
    pub fn validate_invariants(&self) -> Result<()> {
        for (idx, node) in self.rules.iter().enumerate() {
            let sym = SymbolId::from_rule_index(idx);
            match node.kind {
                RuleKind::Pair { left, right } => {
                    if left.0 >= sym.0 || right.0 >= sym.0 {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Topological invariant violated at rule {}: Pair({:?}, {:?})",
                            idx, left, right
                        )));
                    }
                    let expected_len = self
                        .sym_len(left)
                        .checked_add(self.sym_len(right))
                        .ok_or_else(|| {
                            ButtlickError::CorruptedFormat(format!(
                                "Byte length overflow at rule {idx}"
                            ))
                        })?;
                    if node.byte_len != expected_len {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Byte length mismatch at rule {}: expected {}, got {}",
                            idx, expected_len, node.byte_len
                        )));
                    }
                    if node.first_byte != self.sym_first_byte(left)
                        || node.last_byte != self.sym_last_byte(right)
                    {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Boundary byte mismatch at rule {}",
                            idx
                        )));
                    }
                }
                RuleKind::Run { child, count } => {
                    if child.0 >= sym.0 {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Topological invariant violated at rule {}: Run({:?}, {})",
                            idx, child, count
                        )));
                    }
                    if !(2..=MAX_RUN_COUNT).contains(&count) {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Invalid run count {} at rule {}",
                            count, idx
                        )));
                    }
                    let expected_len = self.sym_len(child).checked_mul(count).ok_or_else(|| {
                        ButtlickError::CorruptedFormat(format!(
                            "Byte length overflow at rule {idx}"
                        ))
                    })?;
                    if node.byte_len != expected_len {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Byte length mismatch at rule {}: expected {}, got {}",
                            idx, expected_len, node.byte_len
                        )));
                    }
                    if node.first_byte != self.sym_first_byte(child)
                        || node.last_byte != self.sym_last_byte(child)
                    {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Boundary byte mismatch at rule {}",
                            idx
                        )));
                    }
                }
            }
        }
        for root in &self.roots {
            match root.root_symbol {
                None => {
                    if root.byte_len != 0 || (self.root_hashes_are_exact() && root.kr_hash != 0) {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Empty root '{}' has non-zero len or hash",
                            root.name
                        )));
                    }
                }
                Some(sym) => {
                    let max_id = self.rules.len() as u64 + 256;
                    if sym.0 as u64 >= max_id {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Root '{}' references out-of-range symbol {}",
                            root.name, sym.0
                        )));
                    }
                    if root.byte_len != self.sym_len(sym)
                        || (self.root_hashes_are_exact() && root.kr_hash != self.sym_hash(sym))
                    {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Root '{}' metadata mismatch with root symbol",
                            root.name
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interner_deduplication_and_coalescing() {
        let mut dag = GrammarDag::new();
        let a = SymbolId::from_byte(b'a');
        let b = SymbolId::from_byte(b'b');

        // Interning identical pair twice yields the exact same SymbolId
        let ab1 = dag.intern_pair(a, b);
        let ab2 = dag.intern_pair(a, b);
        assert_eq!(ab1, ab2);
        assert_eq!(dag.rules.len(), 1);
        assert_eq!(dag.sym_len(ab1), 2);
        assert_eq!(dag.sym_first_byte(ab1), b'a');
        assert_eq!(dag.sym_last_byte(ab1), b'b');

        // Interning Pair(a, a) automatically coalesces into Run(a, 2)
        let aa1 = dag.intern_pair(a, a);
        let aa2 = dag.intern_run(a, 2);
        assert_eq!(aa1, aa2);
        assert_eq!(dag.rules.len(), 2);
        assert_eq!(dag.sym_len(aa1), 2);

        // Nested Run(Run(a, 2), 5) flattens to Run(a, 10)
        let a10_nested = dag.intern_run(aa1, 5);
        let a10_direct = dag.intern_run(a, 10);
        assert_eq!(a10_nested, a10_direct);
        assert_eq!(dag.sym_len(a10_nested), 10);

        dag.validate_invariants().unwrap();
    }
}
