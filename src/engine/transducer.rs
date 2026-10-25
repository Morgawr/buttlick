use crate::grammar::{GrammarDag, RuleKind, SymbolId};

/// Applies a deterministic state transition repeatedly, skipping complete cycles. Most runs
/// reach a fixed point immediately, so allocate the cycle table only after eight transitions.
pub(crate) fn advance_run(
    count: u64,
    q: u16,
    num_states: usize,
    mut step: impl FnMut(u16) -> (u16, u64),
) -> (u16, u64) {
    let (mut q, mut i, mut total) = (q, 0u64, 0u64);
    let mut seen = Vec::new();
    while i < count {
        if i == 8 {
            seen.resize(num_states, (u64::MAX, 0u64));
        }
        if !seen.is_empty() {
            let (prev_i, prev_total) = seen[q as usize];
            if prev_i != u64::MAX {
                let cycles = (count - i) / (i - prev_i);
                if cycles > 0 {
                    total = total.saturating_add((total - prev_total).saturating_mul(cycles));
                    i += cycles * (i - prev_i);
                    if i == count {
                        break;
                    }
                }
                // Only a partial cycle remains; no further cycle bookkeeping is necessary.
                seen.clear();
            } else {
                seen[q as usize] = (i, total);
            }
        }
        let (next, emitted) = step(q);
        if next == q {
            total = total.saturating_add(emitted.saturating_mul(count - i));
            break;
        }
        total = total.saturating_add(emitted);
        q = next;
        i += 1;
    }
    (q, total)
}

/// A Deterministic Finite-State Mealy Transducer over the byte alphabet `0..=255`.
/// Evaluates regular expressions and stateful stream queries homomorphically on the `GrammarDag`
/// via the Wreath-Product Monoid without decompressing the data.
/// Emission totals saturate at `u64::MAX`; ordinary unit-weight byte/regex counts
/// remain exact whenever the final total (including EOF) fits in `u64`.
#[derive(Clone, Debug)]
pub struct MealyTransducer {
    pub num_states: usize,
    pub start_state: u16,
    /// Flattened `[state * 256 + byte] -> next_state`
    pub byte_next: Vec<u16>,
    /// Flattened `[state * 256 + byte] -> emitted_weight`
    pub byte_emit: Vec<u64>,
    /// Weight emitted at end-of-file for each final state `q in 0..num_states`.
    pub eof_emit: Vec<u64>,
}

/// Wreath-product monoid summary $\mathcal{T}(X) = (\Delta_X, \Omega_X)$ for a single grammar node $X$.
#[derive(Clone, Debug)]
pub struct NodeTransducerSummary {
    /// For each entry state `q in 0..num_states`, the exit state after consuming all bytes of `X`.
    pub next_state: Vec<u16>,
    /// For each entry state `q in 0..num_states`, the total weight emitted while consuming `X`.
    pub emit_sum: Vec<u64>,
}

impl NodeTransducerSummary {
    #[inline]
    pub fn identity(num_states: usize) -> Self {
        assert!(
            num_states <= u16::MAX as usize + 1,
            "transducer exceeds u16 states"
        );
        Self {
            next_state: (0..num_states).map(|q| q as u16).collect(),
            emit_sum: vec![0u64; num_states],
        }
    }

    #[inline]
    pub fn empty(num_states: usize) -> Self {
        Self {
            next_state: vec![0u16; num_states],
            emit_sum: vec![0u64; num_states],
        }
    }
}

/// Associative composition $\mathcal{T}(L \mathbin{\Vert} R) = \mathcal{T}(L) \star \mathcal{T}(R)$
/// in $O(|Q|)$ time.
#[inline]
pub fn compose_summaries(
    left: &NodeTransducerSummary,
    right: &NodeTransducerSummary,
    out: &mut NodeTransducerSummary,
) {
    let s = left.next_state.len();
    debug_assert_eq!(right.next_state.len(), s);
    debug_assert_eq!(out.next_state.len(), s);
    for q in 0..s {
        let mid = left.next_state[q] as usize;
        out.next_state[q] = right.next_state[mid];
        out.emit_sum[q] = left.emit_sum[q].saturating_add(right.emit_sum[mid]);
    }
}

/// Computes $\mathcal{T}(A^k) = \mathcal{T}(A)^k$ in $O(|Q| \log k)$ time via binary exponentiation.
pub fn power_summary(base: &NodeTransducerSummary, mut k: u64) -> NodeTransducerSummary {
    let s = base.next_state.len();
    if k == 0 {
        return NodeTransducerSummary::identity(s);
    }
    if k == 1 {
        return base.clone();
    }
    let mut result = NodeTransducerSummary::identity(s);
    let mut cur = base.clone();
    let mut scratch = NodeTransducerSummary::empty(s);

    while k > 0 {
        if k & 1 == 1 {
            compose_summaries(&result, &cur, &mut scratch);
            std::mem::swap(&mut result, &mut scratch);
        }
        k >>= 1;
        if k > 0 {
            compose_summaries(&cur, &cur, &mut scratch);
            std::mem::swap(&mut cur, &mut scratch);
        }
    }
    result
}

impl MealyTransducer {
    /// Builds the `NodeTransducerSummary` for a single terminal byte `b` in $O(|Q|)$ time.
    #[inline]
    pub fn terminal_summary(&self, b: u8) -> NodeTransducerSummary {
        let s = self.num_states;
        let mut next_state = Vec::with_capacity(s);
        let mut emit_sum = Vec::with_capacity(s);
        let offset = b as usize;
        for q in 0..s {
            let idx = q * 256 + offset;
            next_state.push(self.byte_next[idx]);
            emit_sum.push(self.byte_emit[idx]);
        }
        NodeTransducerSummary {
            next_state,
            emit_sum,
        }
    }

    /// Evaluates this `MealyTransducer` bottom-up across all rules of `dag` in $O((256 + n) \cdot |Q|)$ time
    /// using a flat state table and sparse emission pool (zero per-rule heap allocations).
    #[allow(clippy::needless_range_loop)]
    pub fn evaluate_dag(&self, dag: &GrammarDag) -> TransducerDagEval {
        let s = self.num_states;
        let num_rules = dag.rules.len();
        let mut terminal_next = vec![0u16; 256 * s];
        let mut terminal_emit = vec![0u64; 256 * s];
        for b in 0..=255u8 {
            let b_idx = b as usize;
            for q in 0..s {
                let idx = q * 256 + b_idx;
                terminal_next[b_idx * s + q] = self.byte_next[idx];
                terminal_emit[b_idx * s + q] = self.byte_emit[idx];
            }
        }

        let mut rule_next = vec![0u16; num_rules * s];
        let mut rule_emit_offset = vec![u32::MAX; num_rules];
        let mut emit_pool: Vec<u64> = Vec::new();

        let mut scratch_a = NodeTransducerSummary::empty(s);
        let mut scratch_b = NodeTransducerSummary::empty(s);

        for (r_idx, node) in dag.rules.iter().enumerate() {
            let out_next_start = r_idx * s;
            match node.kind {
                RuleKind::Pair { left, right } => {
                    let l_has_emit = if let Some(b) = left.as_byte() {
                        let off = (b as usize) * s;
                        scratch_a
                            .next_state
                            .copy_from_slice(&terminal_next[off..off + s]);
                        let em = &terminal_emit[off..off + s];
                        let has = em.iter().any(|&v| v != 0);
                        if has {
                            scratch_a.emit_sum.copy_from_slice(em);
                        }
                        has
                    } else {
                        let li = left.rule_index();
                        let off = li * s;
                        scratch_a
                            .next_state
                            .copy_from_slice(&rule_next[off..off + s]);
                        let em_off = rule_emit_offset[li];
                        if em_off != u32::MAX {
                            let eo = (em_off as usize) * s;
                            scratch_a.emit_sum.copy_from_slice(&emit_pool[eo..eo + s]);
                            true
                        } else {
                            false
                        }
                    };

                    let r_has_emit = if let Some(b) = right.as_byte() {
                        let off = (b as usize) * s;
                        scratch_b
                            .next_state
                            .copy_from_slice(&terminal_next[off..off + s]);
                        let em = &terminal_emit[off..off + s];
                        let has = em.iter().any(|&v| v != 0);
                        if has {
                            scratch_b.emit_sum.copy_from_slice(em);
                        }
                        has
                    } else {
                        let ri = right.rule_index();
                        let off = ri * s;
                        scratch_b
                            .next_state
                            .copy_from_slice(&rule_next[off..off + s]);
                        let em_off = rule_emit_offset[ri];
                        if em_off != u32::MAX {
                            let eo = (em_off as usize) * s;
                            scratch_b.emit_sum.copy_from_slice(&emit_pool[eo..eo + s]);
                            true
                        } else {
                            false
                        }
                    };

                    let out_next = &mut rule_next[out_next_start..out_next_start + s];
                    for q in 0..s {
                        let mid = scratch_a.next_state[q] as usize;
                        out_next[q] = scratch_b.next_state[mid];
                    }

                    match (l_has_emit, r_has_emit) {
                        (false, false) => {}
                        (true, false) => {
                            if !left.is_terminal() {
                                rule_emit_offset[r_idx] = rule_emit_offset[left.rule_index()];
                            } else {
                                let pool_idx = (emit_pool.len() / s) as u32;
                                emit_pool.extend_from_slice(&scratch_a.emit_sum);
                                rule_emit_offset[r_idx] = pool_idx;
                            }
                        }
                        (false, true) => {
                            let mut any_non_zero = false;
                            for q in 0..s {
                                let mid = scratch_a.next_state[q] as usize;
                                let v = scratch_b.emit_sum[mid];
                                scratch_a.emit_sum[q] = v;
                                any_non_zero |= v != 0;
                            }
                            if any_non_zero {
                                let pool_idx = (emit_pool.len() / s) as u32;
                                emit_pool.extend_from_slice(&scratch_a.emit_sum);
                                rule_emit_offset[r_idx] = pool_idx;
                            }
                        }
                        (true, true) => {
                            for q in 0..s {
                                let mid = scratch_a.next_state[q] as usize;
                                scratch_a.emit_sum[q] =
                                    scratch_a.emit_sum[q].saturating_add(scratch_b.emit_sum[mid]);
                            }
                            let pool_idx = (emit_pool.len() / s) as u32;
                            emit_pool.extend_from_slice(&scratch_a.emit_sum);
                            rule_emit_offset[r_idx] = pool_idx;
                        }
                    }
                }
                RuleKind::Run { child, count } => {
                    if let Some(b) = child.as_byte() {
                        let off = (b as usize) * s;
                        scratch_a
                            .next_state
                            .copy_from_slice(&terminal_next[off..off + s]);
                        scratch_a
                            .emit_sum
                            .copy_from_slice(&terminal_emit[off..off + s]);
                    } else {
                        let ci = child.rule_index();
                        let off = ci * s;
                        scratch_a
                            .next_state
                            .copy_from_slice(&rule_next[off..off + s]);
                        let em_off = rule_emit_offset[ci];
                        if em_off == u32::MAX {
                            scratch_a.emit_sum.fill(0);
                        } else {
                            let eo = (em_off as usize) * s;
                            scratch_a.emit_sum.copy_from_slice(&emit_pool[eo..eo + s]);
                        }
                    }
                    let pow = power_summary(&scratch_a, count);
                    rule_next[out_next_start..out_next_start + s].copy_from_slice(&pow.next_state);
                    if pow.emit_sum.iter().any(|&v| v != 0) {
                        let pool_idx = (emit_pool.len() / s) as u32;
                        emit_pool.extend_from_slice(&pow.emit_sum);
                        rule_emit_offset[r_idx] = pool_idx;
                    }
                }
            }
        }

        TransducerDagEval {
            num_states: s,
            start_state: self.start_state,
            eof_emit: self.eof_emit.clone(),
            terminal_next,
            terminal_emit,
            rule_next,
            rule_emit_offset,
            emit_pool,
        }
    }
}

/// Holds the evaluated transducer summaries for all symbols in a `GrammarDag`,
/// allowing $O(1)$ readout for any document root in the archive and $O(k \log N)$ match offset extraction.
pub struct TransducerDagEval {
    pub num_states: usize,
    pub start_state: u16,
    pub eof_emit: Vec<u64>,
    pub terminal_next: Vec<u16>,
    pub terminal_emit: Vec<u64>,
    pub rule_next: Vec<u16>,
    pub rule_emit_offset: Vec<u32>,
    pub emit_pool: Vec<u64>,
}

impl TransducerDagEval {
    #[inline(always)]
    pub fn next_state_at(&self, sym: SymbolId, q: u16) -> u16 {
        let s = self.num_states;
        if let Some(b) = sym.as_byte() {
            self.terminal_next[(b as usize) * s + (q as usize)]
        } else {
            self.rule_next[sym.rule_index() * s + (q as usize)]
        }
    }

    #[inline(always)]
    pub fn emit_at(&self, sym: SymbolId, q: u16) -> u64 {
        let s = self.num_states;
        if let Some(b) = sym.as_byte() {
            self.terminal_emit[(b as usize) * s + (q as usize)]
        } else {
            let off = self.rule_emit_offset[sym.rule_index()];
            if off == u32::MAX {
                0
            } else {
                self.emit_pool[(off as usize) * s + (q as usize)]
            }
        }
    }

    /// Returns the total weight, including EOF. An empty document emits EOF from the start state.
    #[inline]
    pub fn query_root(&self, root_symbol: Option<SymbolId>) -> u64 {
        let Some(sym) = root_symbol else {
            return self.eof_emit[self.start_state as usize];
        };
        let q0 = self.start_state;
        let final_q = self.next_state_at(sym, q0) as usize;
        self.emit_at(sym, q0).saturating_add(self.eof_emit[final_q])
    }

    /// Collects the exact byte offsets where transitions emit weight `> 0` (e.g. terminating `\n`
    /// of matching lines in `GrepMode::LineCount`), skipping zero-emission subtrees in $O(1)$ time.
    pub fn collect_emitted_offsets(
        &self,
        dag: &GrammarDag,
        root_symbol: SymbolId,
        limit: usize,
        out: &mut Vec<u64>,
    ) {
        if limit == 0 || self.query_root(Some(root_symbol)) == 0 {
            return;
        }
        let final_q = self.walk_emitted_offsets(dag, root_symbol, self.start_state, 0, limit, out);
        if out.len() < limit && self.eof_emit[final_q as usize] > 0 {
            out.push(dag.sym_len(root_symbol));
        }
    }

    fn walk_emitted_offsets(
        &self,
        dag: &GrammarDag,
        sym: SymbolId,
        q: u16,
        base_offset: u64,
        limit: usize,
        out: &mut Vec<u64>,
    ) -> u16 {
        let q_out = self.next_state_at(sym, q);
        let emitted = self.emit_at(sym, q);
        if emitted == 0 || out.len() >= limit {
            return q_out;
        }
        if sym.is_terminal() {
            out.push(base_offset);
            return q_out;
        }
        let node = dag.rule(sym);
        match node.kind {
            RuleKind::Pair { left, right } => {
                let q_mid = self.walk_emitted_offsets(dag, left, q, base_offset, limit, out);
                if out.len() < limit {
                    let left_len = dag.sym_len(left);
                    let _ = self.walk_emitted_offsets(
                        dag,
                        right,
                        q_mid,
                        base_offset + left_len,
                        limit,
                        out,
                    );
                }
                q_out
            }
            RuleKind::Run { child, count } => {
                self.walk_run_offsets(dag, child, count, q, base_offset, limit, out);
                q_out
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_run_offsets(
        &self,
        dag: &GrammarDag,
        child: SymbolId,
        count: u64,
        q: u16,
        base: u64,
        limit: usize,
        out: &mut Vec<u64>,
    ) -> u16 {
        if count == 1 {
            return self.walk_emitted_offsets(dag, child, q, base, limit, out);
        }
        let (end, emitted) = advance_run(count, q, self.num_states, |state| {
            (self.next_state_at(child, state), self.emit_at(child, state))
        });
        if emitted > 0 && out.len() < limit {
            let left_count = count / 2;
            let mid = self.walk_run_offsets(dag, child, left_count, q, base, limit, out);
            if out.len() < limit {
                self.walk_run_offsets(
                    dag,
                    child,
                    count - left_count,
                    mid,
                    base + dag.sym_len(child) * left_count,
                    limit,
                    out,
                );
            }
        }
        end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycles_match_direct_evaluation() {
        for states in [2usize, 3, 13] {
            for count in [0, 1, 8, 9, 37, 1000] {
                let got = advance_run(count, 0, states, |q| {
                    (((q as usize + 1) % states) as u16, q as u64)
                });
                let mut expected = (0, 0);
                for _ in 0..count {
                    expected.1 += expected.0 as u64;
                    expected.0 = ((expected.0 as usize + 1) % states) as u16;
                }
                assert_eq!(got, expected);
            }
        }
    }

    #[test]
    fn identity_supports_all_u16_states() {
        let identity = NodeTransducerSummary::identity(65536);
        assert_eq!(identity.next_state.len(), 65536);
        assert_eq!(identity.next_state[65535], u16::MAX);
        assert!(identity.emit_sum.iter().all(|&n| n == 0));
    }

    #[test]
    fn large_weights_saturate_without_losing_emission_offsets() {
        let mut dag = GrammarDag::new();
        let run = dag.intern_run(SymbolId::from_byte(b'a'), 2);
        let root = dag.intern_pair(run, SymbolId::from_byte(b'b'));
        let transducer = MealyTransducer {
            num_states: 1,
            start_state: 0,
            byte_next: vec![0; 256],
            byte_emit: vec![u64::MAX; 256],
            eof_emit: vec![1],
        };
        let eval = transducer.evaluate_dag(&dag);
        assert_eq!(eval.query_root(None), 1);
        assert_eq!(eval.query_root(Some(root)), u64::MAX);
        let mut offsets = Vec::new();
        eval.collect_emitted_offsets(&dag, root, 10, &mut offsets);
        assert_eq!(offsets, [0, 1, 2, 3]);
    }

    #[test]
    fn offset_walk_skips_nonemitting_cycle_after_a_match() {
        let mut dag = GrammarDag::new();
        let root = dag.intern_run(SymbolId::from_byte(b'a'), 3_000_000_000);
        let mut transducer = MealyTransducer {
            num_states: 3,
            start_state: 0,
            byte_next: vec![0; 3 * 256],
            byte_emit: vec![0; 3 * 256],
            eof_emit: vec![0; 3],
        };
        transducer.byte_next[b'a' as usize] = 1;
        transducer.byte_emit[b'a' as usize] = 1;
        transducer.byte_next[256 + b'a' as usize] = 2;
        transducer.byte_next[512 + b'a' as usize] = 1;
        let eval = transducer.evaluate_dag(&dag);
        assert_eq!(eval.query_root(Some(root)), 1);
        let mut offsets = Vec::new();
        eval.collect_emitted_offsets(&dag, root, 10, &mut offsets);
        assert_eq!(offsets, [0]);
    }
}
