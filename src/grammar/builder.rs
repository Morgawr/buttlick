use rustc_hash::FxHashMap;

use crate::grammar::{RuleKind, RuleNode, SymbolId};

/// Returns true if a `Pair` rule should be indexed in the global cross-chunk hash-consing table
/// during bulk streaming ingestion.
#[inline(always)]
pub const fn should_intern_pair_globally(node: &RuleNode) -> bool {
    node.byte_len <= 32
}

/// Canonical hash-consing table ensuring structural deduplication across the `GrammarDag`.
/// Uses compact 64-bit packed keys `((left.0 as u64) << 32) | (right.0 as u64)` for `Pair` rules.
#[derive(Clone, Debug, Default)]
pub struct RuleInterner {
    pair_map: FxHashMap<u64, SymbolId>,
    run_map: FxHashMap<(SymbolId, u64), SymbolId>,
    indexed_rules: usize,
}

impl RuleInterner {
    pub fn new() -> Self {
        Self {
            pair_map: FxHashMap::default(),
            run_map: FxHashMap::default(),
            indexed_rules: 0,
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        let mut pair_map = FxHashMap::default();
        pair_map.reserve(cap);
        Self {
            pair_map,
            run_map: FxHashMap::default(),
            indexed_rules: 0,
        }
    }

    #[inline(always)]
    pub const fn pack_pair_key(left: SymbolId, right: SymbolId) -> u64 {
        ((left.0 as u64) << 32) | (right.0 as u64)
    }

    /// Reconstructs the hash-consing table from an existing slice of `RuleNode`s.
    pub fn from_rules(rules: &[RuleNode]) -> Self {
        let mut interner = Self::with_capacity(rules.len().clamp(65_536, 7_500_000));
        for (idx, node) in rules.iter().enumerate() {
            let sym = SymbolId::from_rule_index(idx);
            match node.kind {
                RuleKind::Pair { left, right } => {
                    if should_intern_pair_globally(node) {
                        interner
                            .pair_map
                            .insert(Self::pack_pair_key(left, right), sym);
                    }
                }
                RuleKind::Run { child, count } => {
                    interner.run_map.insert((child, count), sym);
                }
            }
        }
        interner.indexed_rules = rules.len();
        interner
    }

    /// Resets `pair_map` in-place (retaining allocated bucket capacity so zero reallocations occur)
    /// when it exceeds the L3/RAM budget between streaming batches, re-seeding core UTF-8/token rules.
    pub fn trim_for_next_batch(&mut self, rules: &[RuleNode]) {
        if self.pair_map.len() > 7_500_000 {
            self.pair_map.clear();
            let seed_limit = rules.len().min(131_072);
            for (idx, node) in rules[..seed_limit].iter().enumerate() {
                if node.byte_len <= 12 {
                    if let RuleKind::Pair { left, right } = node.kind {
                        let sym = SymbolId::from_rule_index(idx);
                        self.pair_map.insert(Self::pack_pair_key(left, right), sym);
                    }
                }
            }
        }
        self.indexed_rules = rules.len();
    }

    pub fn set_indexed_rules(&mut self, len: usize) {
        self.indexed_rules = len;
    }

    #[inline(always)]
    fn sym_meta(rules: &[RuleNode], sym: SymbolId) -> (u64, u16, u8, u8) {
        if let Some(b) = sym.as_byte() {
            (1, 0, b, b)
        } else {
            let n = &rules[sym.rule_index()];
            (n.byte_len, n.height, n.first_byte, n.last_byte)
        }
    }

    #[inline(always)]
    fn as_run(rules: &[RuleNode], sym: SymbolId) -> (SymbolId, u64) {
        if !sym.is_terminal() {
            if let RuleKind::Run { child, count } = rules[sym.rule_index()].kind {
                return (child, count);
            }
        }
        (sym, 1)
    }

    /// Fast merge path for precomputed `RuleNode`s coming from a thread-local `LocalPartitionDag`.
    /// When `can_match_existing` is false (because `left` or `right` was newly allocated in this chunk),
    /// skips hash table lookup entirely!
    #[inline]
    pub fn merge_precomputed_pair(
        &mut self,
        rules: &mut Vec<RuleNode>,
        left: SymbolId,
        right: SymbolId,
        mut precomputed: RuleNode,
        can_match_existing: bool,
    ) -> SymbolId {
        if should_intern_pair_globally(&precomputed) {
            let key = Self::pack_pair_key(left, right);
            if can_match_existing {
                match self.pair_map.entry(key) {
                    std::collections::hash_map::Entry::Occupied(e) => return *e.get(),
                    std::collections::hash_map::Entry::Vacant(v) => {
                        let sym = SymbolId::from_rule_index(rules.len());
                        precomputed.kind = RuleKind::Pair { left, right };
                        rules.push(precomputed);
                        v.insert(sym);
                        self.indexed_rules = rules.len();
                        return sym;
                    }
                }
            }
            let sym = SymbolId::from_rule_index(rules.len());
            precomputed.kind = RuleKind::Pair { left, right };
            rules.push(precomputed);
            self.pair_map.insert(key, sym);
            self.indexed_rules = rules.len();
            sym
        } else {
            let sym = SymbolId::from_rule_index(rules.len());
            precomputed.kind = RuleKind::Pair { left, right };
            rules.push(precomputed);
            self.indexed_rules = rules.len();
            sym
        }
    }

    #[inline]
    pub fn merge_precomputed_run(
        &mut self,
        rules: &mut Vec<RuleNode>,
        child: SymbolId,
        count: u64,
        mut precomputed: RuleNode,
        can_match_existing: bool,
    ) -> SymbolId {
        if can_match_existing {
            if let Some(&existing) = self.run_map.get(&(child, count)) {
                return existing;
            }
        }
        let sym = SymbolId::from_rule_index(rules.len());
        precomputed.kind = RuleKind::Run { child, count };
        rules.push(precomputed);
        self.run_map.insert((child, count), sym);
        self.indexed_rules = rules.len();
        sym
    }

    /// Interns a run-length rule `X -> child^count`.
    pub fn intern_run(
        &mut self,
        rules: &mut Vec<RuleNode>,
        child: SymbolId,
        count: u64,
    ) -> SymbolId {
        assert!(count >= 1, "Run count must be at least 1");
        if count == 1 {
            return child;
        }
        let (base_child, base_count) = Self::as_run(rules, child);
        let total_count = base_count.checked_mul(count).expect("byte_len overflow");

        if let Some(&existing) = self.run_map.get(&(base_child, total_count)) {
            return existing;
        }

        let (c_len, c_height, first_byte, last_byte) = Self::sym_meta(rules, base_child);
        let byte_len = c_len.checked_mul(total_count).expect("byte_len overflow");
        let height = c_height.saturating_add(1);

        let kind = RuleKind::Run {
            child: base_child,
            count: total_count,
        };
        let sym = SymbolId::from_rule_index(rules.len());
        debug_assert!(base_child.0 < sym.0);
        rules.push(RuleNode {
            kind,
            byte_len,
            height,
            first_byte,
            last_byte,
        });
        self.run_map.insert((base_child, total_count), sym);
        self.indexed_rules = rules.len();
        sym
    }

    /// Interns a pair concatenation rule `X -> left right`.
    pub fn intern_pair(
        &mut self,
        rules: &mut Vec<RuleNode>,
        left: SymbolId,
        right: SymbolId,
    ) -> SymbolId {
        let (l_base, l_count) = Self::as_run(rules, left);
        let (r_base, r_count) = Self::as_run(rules, right);
        if l_base == r_base {
            return self.intern_run(rules, l_base, l_count + r_count);
        }

        let key = Self::pack_pair_key(left, right);
        if let Some(&existing) = self.pair_map.get(&key) {
            return existing;
        }

        let (l_len, l_height, first_byte, _) = Self::sym_meta(rules, left);
        let (r_len, r_height, _, last_byte) = Self::sym_meta(rules, right);

        let byte_len = l_len.checked_add(r_len).expect("byte_len overflow");
        let height = l_height.max(r_height).saturating_add(1);

        let kind = RuleKind::Pair { left, right };
        let sym = SymbolId::from_rule_index(rules.len());
        debug_assert!(left.0 < sym.0 && right.0 < sym.0);
        rules.push(RuleNode {
            kind,
            byte_len,
            height,
            first_byte,
            last_byte,
        });
        self.pair_map.insert(key, sym);
        self.indexed_rules = rules.len();
        sym
    }

    pub fn len(&self) -> usize {
        self.indexed_rules
    }

    pub fn is_empty(&self) -> bool {
        self.indexed_rules == 0
    }

    /// Drops the hash-consing lookup tables to reclaim memory once all documents have been ingested.
    pub fn clear_tables(&mut self) {
        self.pair_map = FxHashMap::default();
        self.run_map = FxHashMap::default();
        self.indexed_rules = 0;
    }
}
