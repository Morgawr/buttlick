use regex_automata::dfa::{dense, Automaton, StartKind};
use regex_automata::util::primitives::StateID;
use regex_automata::util::syntax;
use regex_automata::{Anchored, Input, MatchKind};
use rustc_hash::FxHashMap;

use crate::engine::transducer::MealyTransducer;
use crate::error::{ButtlickError, Result};
use crate::format::header::{PackedRuleNode, PACKED_RULE_SIZE};
use crate::format::mapped::MappedMeta;
use crate::format::MappedArchive;
use crate::grammar::{GrammarDag, SymbolId};

/// Evaluation mode for regex queries over the compressed `GrammarDag`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GrepMode {
    /// Counts the number of lines matching the regular expression (`grep -E -c` semantics).
    LineCount,
    /// Counts total non-overlapping matches of the regular expression across the stream.
    MatchCount,
}

/// Transducer states are stored as `u16`; reject patterns whose DFA exceeds that
/// (state ids would otherwise silently wrap around during construction).
fn check_state_count(pattern: &str, num_states: usize) -> Result<()> {
    if num_states > u16::MAX as usize + 1 {
        return Err(ButtlickError::InvalidRegex {
            pattern: pattern.to_string(),
            message: format!("pattern compiles to too many DFA states ({num_states})"),
        });
    }
    Ok(())
}

/// Compiles a regular expression into a `MealyTransducer` for `GrepMode::LineCount` (`grep -E -c`).
pub fn compile_line_grep_transducer(pattern: &str) -> Result<MealyTransducer> {
    let dfa = dense::Builder::new()
        .configure(
            dense::Config::new()
                .match_kind(MatchKind::All)
                .start_kind(StartKind::Unanchored),
        )
        .syntax(
            syntax::Config::new()
                .multi_line(false)
                .dot_matches_new_line(false)
                .utf8(false),
        )
        .build(pattern)
        .map_err(|e| ButtlickError::InvalidRegex {
            pattern: pattern.to_string(),
            message: e.to_string(),
        })?;

    let q_dfa_start = dfa
        .start_state_forward(&Input::new(b"").anchored(Anchored::No))
        .map_err(|e| ButtlickError::InvalidRegex {
            pattern: pattern.to_string(),
            message: e.to_string(),
        })?;

    // State 0: IDLE_LINE_START (at start of file or immediately after '\n', 0 bytes on current line)
    // State 1: MATCHED_LINE (current line has >= 1 byte and has already matched `pattern`)
    // States 2..: Reachable non-matched DFA states on an active line
    const IDLE_LINE_START: u16 = 0;
    const MATCHED_LINE: u16 = 1;

    let empty_line_matches = dfa.is_match_state(dfa.next_eoi_state(q_dfa_start));

    let mut dfa_to_trans: FxHashMap<StateID, u16> = FxHashMap::default();
    let mut trans_to_dfa: Vec<StateID> = Vec::new();

    if !empty_line_matches && !dfa.is_match_state(q_dfa_start) {
        dfa_to_trans.insert(q_dfa_start, IDLE_LINE_START);
    }

    let map_active_state =
        |sid: StateID, map: &mut FxHashMap<StateID, u16>, vec: &mut Vec<StateID>| -> u16 {
            if dfa.is_match_state(sid) {
                return MATCHED_LINE;
            }
            if let Some(&existing) = map.get(&sid) {
                return existing;
            }
            let new_id = (vec.len() + 2) as u16;
            map.insert(sid, new_id);
            vec.push(sid);
            new_id
        };

    // Seed reachable active states from `q_dfa_start` on all non-'\n' bytes
    let mut start_non_nl_next = [0u16; 256];
    for b in 0..=255u8 {
        if b != b'\n' {
            let sid = dfa.next_state(q_dfa_start, b);
            start_non_nl_next[b as usize] =
                map_active_state(sid, &mut dfa_to_trans, &mut trans_to_dfa);
        }
    }

    // BFS over reachable active DFA states using `trans_to_dfa` as queue
    let mut cursor = 0usize;
    while cursor < trans_to_dfa.len() {
        let sid = trans_to_dfa[cursor];
        cursor += 1;
        for b in 0..=255u8 {
            if b != b'\n' {
                let next_sid = dfa.next_state(sid, b);
                let _ = map_active_state(next_sid, &mut dfa_to_trans, &mut trans_to_dfa);
            }
        }
    }

    let num_states = 2 + trans_to_dfa.len();
    check_state_count(pattern, num_states)?;
    let mut byte_next = vec![0u16; num_states * 256];
    let mut byte_emit = vec![0u64; num_states * 256];
    let mut eof_emit = vec![0u64; num_states];

    // 1. Transitions for State 0 (IDLE_LINE_START)
    for b in 0..=255u8 {
        let idx = (IDLE_LINE_START as usize) * 256 + (b as usize);
        if b == b'\n' {
            byte_next[idx] = IDLE_LINE_START;
            byte_emit[idx] = if empty_line_matches { 1 } else { 0 };
        } else {
            byte_next[idx] = start_non_nl_next[b as usize];
            byte_emit[idx] = 0;
        }
    }
    eof_emit[IDLE_LINE_START as usize] = 0;

    // 2. Transitions for State 1 (MATCHED_LINE)
    for b in 0..=255u8 {
        let idx = (MATCHED_LINE as usize) * 256 + (b as usize);
        if b == b'\n' {
            byte_next[idx] = IDLE_LINE_START;
            byte_emit[idx] = 1;
        } else {
            byte_next[idx] = MATCHED_LINE;
            byte_emit[idx] = 0;
        }
    }
    eof_emit[MATCHED_LINE as usize] = 1;

    // 3. Transitions for Active DFA States (2..num_states)
    for (i, &sid) in trans_to_dfa.iter().enumerate() {
        let q = i + 2;
        let matches_at_line_end = dfa.is_match_state(dfa.next_eoi_state(sid));
        eof_emit[q] = if matches_at_line_end { 1 } else { 0 };

        for b in 0..=255u8 {
            let idx = q * 256 + (b as usize);
            if b == b'\n' {
                byte_next[idx] = IDLE_LINE_START;
                byte_emit[idx] = if matches_at_line_end { 1 } else { 0 };
            } else {
                let next_sid = dfa.next_state(sid, b);
                byte_next[idx] = if dfa.is_match_state(next_sid) {
                    MATCHED_LINE
                } else {
                    dfa_to_trans[&next_sid]
                };
                byte_emit[idx] = 0;
            }
        }
    }

    Ok(MealyTransducer {
        num_states,
        start_state: IDLE_LINE_START,
        byte_next,
        byte_emit,
        eof_emit,
    })
}

/// Compiles a regular expression into a `MealyTransducer` for `GrepMode::MatchCount`
/// (counting non-overlapping matches across the stream).
pub fn compile_match_count_transducer(pattern: &str) -> Result<MealyTransducer> {
    let dfa = dense::Builder::new()
        .configure(
            dense::Config::new()
                .match_kind(MatchKind::LeftmostFirst)
                .start_kind(StartKind::Unanchored),
        )
        .syntax(
            syntax::Config::new()
                .multi_line(true)
                .dot_matches_new_line(false)
                .utf8(false),
        )
        .build(pattern)
        .map_err(|e| ButtlickError::InvalidRegex {
            pattern: pattern.to_string(),
            message: e.to_string(),
        })?;

    let q_start_bol = dfa
        .start_state_forward(&Input::new(b"\n").span(1..1).anchored(Anchored::No))
        .map_err(|e| ButtlickError::InvalidRegex {
            pattern: pattern.to_string(),
            message: e.to_string(),
        })?;
    let q_start_mid = dfa
        .start_state_forward(&Input::new(b"a").span(1..1).anchored(Anchored::No))
        .map_err(|e| ButtlickError::InvalidRegex {
            pattern: pattern.to_string(),
            message: e.to_string(),
        })?;

    let mut dfa_to_trans: FxHashMap<StateID, u16> = FxHashMap::default();
    let mut trans_to_dfa: Vec<StateID> = Vec::new();

    let intern_state =
        |sid: StateID, map: &mut FxHashMap<StateID, u16>, vec: &mut Vec<StateID>| -> u16 {
            if let Some(&id) = map.get(&sid) {
                return id;
            }
            let id = vec.len() as u16;
            map.insert(sid, id);
            vec.push(sid);
            id
        };

    let start_state = intern_state(q_start_bol, &mut dfa_to_trans, &mut trans_to_dfa);

    let restart_on_byte = |b: u8| -> StateID {
        if b == b'\n' {
            q_start_bol
        } else {
            dfa.next_state(q_start_mid, b)
        }
    };

    let mut cursor = 0usize;
    while cursor < trans_to_dfa.len() {
        let sid = trans_to_dfa[cursor];
        cursor += 1;
        for b in 0..=255u8 {
            let next_sid = dfa.next_state(sid, b);
            let target_sid = if dfa.is_match_state(next_sid) {
                // Match ended right before `b`; restart and consume `b`
                restart_on_byte(b)
            } else {
                next_sid
            };
            let _ = intern_state(target_sid, &mut dfa_to_trans, &mut trans_to_dfa);
        }
    }

    let num_states = trans_to_dfa.len();
    check_state_count(pattern, num_states)?;
    let mut byte_next = vec![0u16; num_states * 256];
    let mut byte_emit = vec![0u64; num_states * 256];
    let mut eof_emit = vec![0u64; num_states];

    for (q, &sid) in trans_to_dfa.iter().enumerate() {
        let eoi = dfa.next_eoi_state(sid);
        eof_emit[q] = if dfa.is_match_state(eoi) && sid != q_start_bol && sid != q_start_mid {
            1
        } else {
            0
        };

        for b in 0..=255u8 {
            let idx = q * 256 + (b as usize);
            let next_sid = dfa.next_state(sid, b);
            if dfa.is_match_state(next_sid) {
                let restarted_sid = restart_on_byte(b);
                byte_next[idx] = dfa_to_trans[&restarted_sid];
                byte_emit[idx] = 1;
            } else {
                byte_next[idx] = dfa_to_trans[&next_sid];
                byte_emit[idx] = 0;
            }
        }
    }

    Ok(MealyTransducer {
        num_states,
        start_state,
        byte_next,
        byte_emit,
        eof_emit,
    })
}

impl GrammarDag {
    /// Extracts the single line ending at `nl_offset` (exclusive of `\n`) directly from `root_sym`
    /// in $O(\log N + |\text{line}|)$ time without decompressing the document.
    pub fn extract_line_ending_at(&self, root_sym: SymbolId, nl_offset: u64) -> String {
        if nl_offset == 0 {
            return String::new();
        }
        let mut step = 512u64;
        loop {
            let win_start = nl_offset.saturating_sub(step);
            let win_len = nl_offset - win_start;
            let mut buf = Vec::with_capacity(win_len as usize);
            self.extract_slice_symbol(root_sym, win_start, win_len, &mut buf);
            if let Some(pos) = buf.iter().rposition(|&b| b == b'\n') {
                return String::from_utf8_lossy(&buf[pos + 1..]).into_owned();
            }
            if win_start == 0 {
                return String::from_utf8_lossy(&buf).into_owned();
            }
            step = step.saturating_mul(4);
        }
    }

    /// Zero-decompression regex evaluation (`LineCount` or `MatchCount`) on a named document
    /// in $O(n \cdot |Q|)$ time via the Wreath-Product Mealy Transducer Monoid.
    pub fn grep(&self, doc_name: Option<&str>, pattern: &str, mode: GrepMode) -> Result<u64> {
        let root = self.find_root(doc_name)?;
        let Some(sym) = root.root_symbol else {
            return Ok(0);
        };
        let transducer = match mode {
            GrepMode::LineCount => compile_line_grep_transducer(pattern)?,
            GrepMode::MatchCount => compile_match_count_transducer(pattern)?,
        };
        let eval = transducer.evaluate_dag(self);
        Ok(eval.query_root(Some(sym)))
    }

    /// Zero-decompression extraction of matching lines in a named document in $O(n \cdot |Q| + k \log N)$ time.
    pub fn grep_lines(
        &self,
        doc_name: Option<&str>,
        pattern: &str,
        limit: usize,
    ) -> Result<Vec<String>> {
        let root = self.find_root(doc_name)?;
        let Some(sym) = root.root_symbol else {
            return Ok(Vec::new());
        };
        let transducer = compile_line_grep_transducer(pattern)?;
        let eval = transducer.evaluate_dag(self);
        let mut nl_offsets = Vec::new();
        eval.collect_emitted_offsets(self, sym, limit, &mut nl_offsets);
        let lines = nl_offsets
            .into_iter()
            .map(|off| self.extract_line_ending_at(sym, off))
            .collect();
        Ok(lines)
    }

    /// Zero-decompression extraction of matching lines across ALL documents in a single shared-DAG pass!
    pub fn grep_lines_all_docs(
        &self,
        pattern: &str,
        limit: usize,
    ) -> Result<Vec<(String, Vec<String>)>> {
        let transducer = compile_line_grep_transducer(pattern)?;
        let eval = transducer.evaluate_dag(self);
        let mut results = Vec::new();
        let mut remaining = limit;
        let mut nl_offsets = Vec::new();

        for root in &self.roots {
            if remaining == 0 {
                break;
            }
            let Some(sym) = root.root_symbol else {
                continue;
            };
            if eval.query_root(Some(sym)) == 0 {
                continue;
            }
            nl_offsets.clear();
            eval.collect_emitted_offsets(self, sym, remaining, &mut nl_offsets);
            if !nl_offsets.is_empty() {
                remaining = remaining.saturating_sub(nl_offsets.len());
                let lines: Vec<String> = nl_offsets
                    .iter()
                    .map(|&off| self.extract_line_ending_at(sym, off))
                    .collect();
                results.push((root.name.clone(), lines));
            }
        }
        Ok(results)
    }
}

/// A packed `(transducer state, emitted)` cell used by the zero-copy mmap evaluators.
///
/// The most significant bit carries the "emitted at least once" flag and the remaining bits hold
/// the exit state, so the per-symbol table costs 1 byte (`u8`, up to 128 states) or 2 bytes
/// (`u16`, up to 32768 states) per symbol.
trait PackedCell:
    Copy + std::ops::BitOr<Output = Self> + std::ops::BitAnd<Output = Self> + Eq + 'static
{
    const ZERO: Self;
    const EMIT_FLAG: Self;
    const MAX_STATES: usize;
    fn from_state(q: u16) -> Self;
    fn state(self) -> u16;
    #[inline(always)]
    fn emitted(self) -> bool {
        (self & Self::EMIT_FLAG) != Self::ZERO
    }
    #[inline(always)]
    fn emit_bit(self) -> Self {
        self & Self::EMIT_FLAG
    }
}

impl PackedCell for u8 {
    const ZERO: Self = 0;
    const EMIT_FLAG: Self = 0x80;
    const MAX_STATES: usize = 0x80;
    #[inline(always)]
    fn from_state(q: u16) -> Self {
        q as u8
    }
    #[inline(always)]
    fn state(self) -> u16 {
        (self & 0x7F) as u16
    }
}

impl PackedCell for u16 {
    const ZERO: Self = 0;
    const EMIT_FLAG: Self = 0x8000;
    const MAX_STATES: usize = 0x8000;
    #[inline(always)]
    fn from_state(q: u16) -> Self {
        q
    }
    #[inline(always)]
    fn state(self) -> u16 {
        self & 0x7FFF
    }
}

#[cold]
fn topological_violation(rule_idx: usize) -> ButtlickError {
    ButtlickError::CorruptedFormat(format!("Topological ordering violation at rule {rule_idx}"))
}

/// Rejects rules that reference symbols at or above their own id (only possible in a corrupted
/// archive). This guarantees that every child lookup in the evaluators is in-bounds and refers to
/// an already-evaluated symbol.
#[inline(always)]
fn check_topological(rule_idx: usize, packed: PackedRuleNode) -> Result<()> {
    let sym_id = SymbolId::from_rule_index(rule_idx).0;
    let ok = if packed.is_run() {
        packed.first_sym().0 < sym_id
    } else {
        packed.word0 < sym_id && packed.word1 < sym_id
    };
    if ok {
        Ok(())
    } else {
        Err(topological_violation(rule_idx))
    }
}

/// Zero-copy evaluator of a `MealyTransducer` over the on-disk packed rule table.
struct PackedEval<'a, C: PackedCell> {
    rules_bytes: &'a [u8],
    /// `[q * 256 + b]` -> packed exit cell for terminal byte `b` entered in state `q`.
    terminal_packed: Vec<C>,
    /// `[sym]` -> packed exit cell for symbol `sym` entered in state 0.
    table: Vec<C>,
}

impl<'a, C: PackedCell> PackedEval<'a, C> {
    fn new(archive: &'a MappedArchive, transducer: &MealyTransducer) -> Self {
        debug_assert!(transducer.num_states <= C::MAX_STATES);
        let terminal_packed: Vec<C> = transducer
            .byte_next
            .iter()
            .zip(&transducer.byte_emit)
            .map(|(&nq, &em)| {
                let cell = C::from_state(nq);
                if em > 0 {
                    cell | C::EMIT_FLAG
                } else {
                    cell
                }
            })
            .collect();
        let mut table = vec![C::ZERO; 256 + archive.num_rules];
        table[0..256].copy_from_slice(&terminal_packed[0..256]);
        Self {
            rules_bytes: archive.rules_bytes(),
            terminal_packed,
            table,
        }
    }

    #[inline(always)]
    fn rule(&self, sym: SymbolId) -> PackedRuleNode {
        PackedRuleNode::read_at(self.rules_bytes, sym.rule_index())
    }

    /// Packed exit cell of `sym` entered in state 0.
    #[inline(always)]
    fn table_at(&self, sym: SymbolId) -> C {
        // SAFETY: `sym` is either a terminal (< 256) or a rule validated by `check_topological`
        // (or a root validated on open), so `sym.0 < 256 + num_rules == table.len()`.
        unsafe { *self.table.get_unchecked(sym.0 as usize) }
    }

    #[inline(always)]
    fn set_table(&mut self, rule_idx: usize, cell: C) {
        self.table[256 + rule_idx] = cell;
    }

    /// Builds `table` for the state-only evaluation used by line extraction.
    fn build_line_table(&mut self, memo: &mut FxHashMap<u64, C>) -> Result<()> {
        let rules_bytes = self.rules_bytes;
        for (idx, chunk) in rules_bytes.chunks_exact(PACKED_RULE_SIZE).enumerate() {
            let packed = PackedRuleNode::from_bytes(chunk.try_into().unwrap());
            check_topological(idx, packed)?;
            let cell = if !packed.is_run() {
                let l_val = self.table_at(SymbolId(packed.word0));
                if l_val.state() == 0 {
                    self.table_at(SymbolId(packed.word1)) | l_val
                } else {
                    let r_val = self.eval_sym_state(SymbolId(packed.word1), l_val.state(), memo);
                    r_val | l_val.emit_bit()
                }
            } else {
                self.eval_run_state(packed.first_sym(), packed.word1 as u64, 0, memo)
            };
            self.set_table(idx, cell);
        }
        Ok(())
    }

    fn eval_sym_state(&self, sym: SymbolId, q: u16, memo: &mut FxHashMap<u64, C>) -> C {
        if q == 0 {
            return self.table_at(sym);
        }
        if let Some(b) = sym.as_byte() {
            return self.terminal_packed[(q as usize) * 256 + (b as usize)];
        }
        let key = ((sym.0 as u64) << 16) | (q as u64);
        if let Some(&cached) = memo.get(&key) {
            return cached;
        }
        let packed = self.rule(sym);
        let res = if !packed.is_run() {
            let l_val = self.eval_sym_state(SymbolId(packed.word0), q, memo);
            let r_val = self.eval_sym_state(SymbolId(packed.word1), l_val.state(), memo);
            r_val | l_val.emit_bit()
        } else {
            self.eval_run_state(packed.first_sym(), packed.word1 as u64, q, memo)
        };
        memo.insert(key, res);
        res
    }

    fn eval_run_state(
        &self,
        child: SymbolId,
        count: u64,
        q: u16,
        memo: &mut FxHashMap<u64, C>,
    ) -> C {
        let mut cur_q = q;
        let mut emitted = C::ZERO;
        for _ in 0..count {
            let v = self.eval_sym_state(child, cur_q, memo);
            let next_q = v.state();
            emitted = emitted | v.emit_bit();
            if next_q == cur_q {
                break;
            }
            cur_q = next_q;
        }
        C::from_state(cur_q) | emitted
    }

    /// Number of emissions while consuming `sym` from state 0, given its packed cell `v`.
    #[inline(always)]
    fn emit0_count(sym: SymbolId, v: C, emit0_counts: &FxHashMap<u32, u64>) -> u64 {
        if !v.emitted() {
            0
        } else if sym.is_terminal() {
            1
        } else {
            emit0_counts[&sym.0]
        }
    }

    /// Builds `table` plus the exact emission counts (from state 0) of every emitting symbol.
    fn build_count_table(&mut self) -> Result<FxHashMap<u32, u64>> {
        let rules_bytes = self.rules_bytes;
        let mut emit0_counts: FxHashMap<u32, u64> = FxHashMap::default();
        let mut memo: FxHashMap<u64, (C, u64)> = FxHashMap::default();

        for (idx, chunk) in rules_bytes.chunks_exact(PACKED_RULE_SIZE).enumerate() {
            let packed = PackedRuleNode::from_bytes(chunk.try_into().unwrap());
            check_topological(idx, packed)?;
            let (cell, count) = if !packed.is_run() {
                let (left, right) = (SymbolId(packed.word0), SymbolId(packed.word1));
                let l_val = self.table_at(left);
                let lc = Self::emit0_count(left, l_val, &emit0_counts);
                if l_val.state() == 0 {
                    let r_val = self.table_at(right);
                    (
                        r_val | l_val,
                        lc + Self::emit0_count(right, r_val, &emit0_counts),
                    )
                } else {
                    let (r_val, rc) =
                        self.eval_sym_count_state(right, l_val.state(), &emit0_counts, &mut memo);
                    (r_val | l_val.emit_bit(), lc + rc)
                }
            } else {
                self.eval_run_count_state(
                    packed.first_sym(),
                    packed.word1 as u64,
                    0,
                    &emit0_counts,
                    &mut memo,
                )
            };
            self.set_table(idx, cell);
            if cell.emitted() {
                emit0_counts.insert(SymbolId::from_rule_index(idx).0, count);
            }
        }
        Ok(emit0_counts)
    }

    fn eval_sym_count_state(
        &self,
        sym: SymbolId,
        q: u16,
        emit0_counts: &FxHashMap<u32, u64>,
        memo: &mut FxHashMap<u64, (C, u64)>,
    ) -> (C, u64) {
        if q == 0 {
            let v = self.table_at(sym);
            return (v, Self::emit0_count(sym, v, emit0_counts));
        }
        if let Some(b) = sym.as_byte() {
            let v = self.terminal_packed[(q as usize) * 256 + (b as usize)];
            return (v, v.emitted() as u64);
        }
        let key = ((sym.0 as u64) << 16) | (q as u64);
        if let Some(&cached) = memo.get(&key) {
            return cached;
        }
        let packed = self.rule(sym);
        let res = if !packed.is_run() {
            let (l_val, lc) =
                self.eval_sym_count_state(SymbolId(packed.word0), q, emit0_counts, memo);
            let (r_val, rc) = self.eval_sym_count_state(
                SymbolId(packed.word1),
                l_val.state(),
                emit0_counts,
                memo,
            );
            (r_val | l_val.emit_bit(), lc + rc)
        } else {
            self.eval_run_count_state(
                packed.first_sym(),
                packed.word1 as u64,
                q,
                emit0_counts,
                memo,
            )
        };
        memo.insert(key, res);
        res
    }

    fn eval_run_count_state(
        &self,
        child: SymbolId,
        count: u64,
        q: u16,
        emit0_counts: &FxHashMap<u32, u64>,
        memo: &mut FxHashMap<u64, (C, u64)>,
    ) -> (C, u64) {
        let mut cur_q = q;
        let mut emitted = C::ZERO;
        let mut total_c = 0u64;
        for i in 0..count {
            let (v, c) = self.eval_sym_count_state(child, cur_q, emit0_counts, memo);
            let next_q = v.state();
            if next_q == cur_q {
                // Fixed point: every remaining repetition behaves identically.
                if c > 0 {
                    emitted = C::EMIT_FLAG;
                    total_c += (count - i) * c;
                }
                break;
            }
            emitted = emitted | v.emit_bit();
            total_c += c;
            cur_q = next_q;
        }
        (C::from_state(cur_q) | emitted, total_c)
    }

    /// Total emissions (stream + end-of-file) for a document root, after `build_count_table`.
    #[inline]
    fn root_count(
        &self,
        transducer: &MealyTransducer,
        sym: SymbolId,
        emit0_counts: &FxHashMap<u32, u64>,
    ) -> u64 {
        let root_val = self.table_at(sym);
        Self::emit0_count(sym, root_val, emit0_counts)
            + transducer.eof_emit[root_val.state() as usize]
    }

    /// Appends the document offsets of up to `walk.limit` emitting bytes inside `sym` (entered in
    /// state `q` at document offset `base`), in increasing order, after `build_count_table`.
    /// Returns the exit state.
    fn walk_emitted_offsets(
        &self,
        walk: &mut OffsetWalk<'_, C>,
        sym: SymbolId,
        q: u16,
        base: u64,
    ) -> Result<u16> {
        let (v, _) = self.eval_sym_count_state(sym, q, walk.emit0_counts, &mut walk.memo);
        if !v.emitted() || walk.out.len() >= walk.limit {
            return Ok(v.state());
        }
        if sym.is_terminal() {
            walk.out.push(base);
            return Ok(v.state());
        }
        let packed = self.rule(sym);
        if !packed.is_run() {
            let (left, right) = (SymbolId(packed.word0), SymbolId(packed.word1));
            let q_mid = self.walk_emitted_offsets(walk, left, q, base)?;
            if walk.out.len() < walk.limit {
                let l_len = walk.archive.sym_len(left, &mut walk.meta)?;
                self.walk_emitted_offsets(walk, right, q_mid, base + l_len)?;
            }
        } else {
            let child = packed.first_sym();
            let c_len = walk.archive.sym_len(child, &mut walk.meta)?;
            let mut cur_q = q;
            let mut cur_base = base;
            for _ in 0..packed.word1 {
                if walk.out.len() >= walk.limit {
                    break;
                }
                let (cv, _) =
                    self.eval_sym_count_state(child, cur_q, walk.emit0_counts, &mut walk.memo);
                if !cv.emitted() && cv.state() == cur_q {
                    // Every remaining repetition is identical and emits nothing.
                    break;
                }
                cur_q = self.walk_emitted_offsets(walk, child, cur_q, cur_base)?;
                cur_base += c_len;
            }
        }
        Ok(v.state())
    }

    /// Collects up to `limit` matching lines of the document rooted at `sym`,
    /// after `build_line_table`.
    fn collect_root_lines(
        &self,
        transducer: &MealyTransducer,
        sym: SymbolId,
        limit: usize,
        memo: &mut FxHashMap<u64, C>,
        left_siblings: &mut Vec<(SymbolId, u64)>,
    ) -> Vec<String> {
        let mut lines = Vec::new();
        let root_val = self.table_at(sym);
        if root_val.emitted() {
            left_siblings.clear();
            let _ = self.walk_emitted_lines(sym, 0, limit, memo, left_siblings, &mut lines);
        }
        if lines.len() < limit && transducer.eof_emit[root_val.state() as usize] > 0 {
            // The final line has no trailing '\n': it is the suffix of the whole document.
            let mut rev_buf = Vec::with_capacity(128);
            let _ = append_rev_until_nl(self.rules_bytes, sym, &mut rev_buf);
            rev_buf.reverse();
            lines.push(String::from_utf8_lossy(&rev_buf).into_owned());
        }
        lines
    }

    fn walk_emitted_lines(
        &self,
        sym: SymbolId,
        q: u16,
        limit: usize,
        memo: &mut FxHashMap<u64, C>,
        left_siblings: &mut Vec<(SymbolId, u64)>,
        out_lines: &mut Vec<String>,
    ) -> u16 {
        let v = self.eval_sym_state(sym, q, memo);
        let q_out = v.state();
        if !v.emitted() || out_lines.len() >= limit {
            return q_out;
        }
        if sym.is_terminal() {
            // `sym` is the emitting '\n': rebuild its line from the left siblings on the stack.
            let mut rev_buf = Vec::with_capacity(128);
            'siblings: for &(sib_sym, sib_count) in left_siblings.iter().rev() {
                for _ in 0..sib_count {
                    if append_rev_until_nl(self.rules_bytes, sib_sym, &mut rev_buf) {
                        break 'siblings;
                    }
                }
            }
            rev_buf.reverse();
            out_lines.push(String::from_utf8_lossy(&rev_buf).into_owned());
            return q_out;
        }

        let packed = self.rule(sym);
        if !packed.is_run() {
            let left = SymbolId(packed.word0);
            let right = SymbolId(packed.word1);
            let q_mid = self.walk_emitted_lines(left, q, limit, memo, left_siblings, out_lines);
            if out_lines.len() < limit {
                left_siblings.push((left, 1));
                let _ =
                    self.walk_emitted_lines(right, q_mid, limit, memo, left_siblings, out_lines);
                left_siblings.pop();
            }
        } else {
            let child = packed.first_sym();
            let count = packed.word1 as u64;
            let mut cur_q = q;
            for i in 0..count {
                if out_lines.len() >= limit {
                    break;
                }
                let cv = self.eval_sym_state(child, cur_q, memo);
                let next_q = cv.state();
                if !cv.emitted() {
                    if next_q == cur_q {
                        break;
                    }
                    cur_q = next_q;
                    continue;
                }
                if i > 0 {
                    left_siblings.push((child, i));
                }
                cur_q =
                    self.walk_emitted_lines(child, cur_q, limit, memo, left_siblings, out_lines);
                if i > 0 {
                    left_siblings.pop();
                }
            }
        }
        q_out
    }
}

/// Mutable state of an emission-offset walk (see `PackedEval::walk_emitted_offsets`).
struct OffsetWalk<'b, C: PackedCell> {
    archive: &'b MappedArchive,
    meta: MappedMeta,
    emit0_counts: &'b FxHashMap<u32, u64>,
    memo: FxHashMap<u64, (C, u64)>,
    limit: usize,
    out: Vec<u64>,
}

/// Appends the bytes of `sym` in reverse order to `rev_buf` until a `\n` is reached.
/// Returns `true` if a `\n` was found.
fn append_rev_until_nl(rules_bytes: &[u8], sym: SymbolId, rev_buf: &mut Vec<u8>) -> bool {
    if let Some(b) = sym.as_byte() {
        if b == b'\n' {
            return true;
        }
        rev_buf.push(b);
        return false;
    }
    let packed = PackedRuleNode::read_at(rules_bytes, sym.rule_index());
    if !packed.is_run() {
        append_rev_until_nl(rules_bytes, SymbolId(packed.word1), rev_buf)
            || append_rev_until_nl(rules_bytes, SymbolId(packed.word0), rev_buf)
    } else {
        let child = packed.first_sym();
        for _ in 0..packed.word1 {
            if append_rev_until_nl(rules_bytes, child, rev_buf) {
                return true;
            }
        }
        false
    }
}

#[cold]
fn too_many_states(pattern: &str, num_states: usize) -> ButtlickError {
    ButtlickError::InvalidRegex {
        pattern: pattern.to_string(),
        message: format!(
            "pattern compiles to {num_states} DFA states (maximum supported: {})",
            <u16 as PackedCell>::MAX_STATES
        ),
    }
}

impl MappedArchive {
    fn compile_transducer(pattern: &str, mode: GrepMode) -> Result<MealyTransducer> {
        match mode {
            GrepMode::LineCount => compile_line_grep_transducer(pattern),
            GrepMode::MatchCount => compile_match_count_transducer(pattern),
        }
    }

    /// Evaluates `transducer` over the whole rule table and returns the total emission count of
    /// each requested root (in order), picking the narrowest packed cell that fits the state count.
    pub(crate) fn count_emissions(
        &self,
        transducer: &MealyTransducer,
        roots: &[Option<SymbolId>],
        pattern: &str,
    ) -> Result<Vec<u64>> {
        fn run<C: PackedCell>(
            archive: &MappedArchive,
            transducer: &MealyTransducer,
            roots: &[Option<SymbolId>],
        ) -> Result<Vec<u64>> {
            let mut eval = PackedEval::<C>::new(archive, transducer);
            let emit0_counts = eval.build_count_table()?;
            Ok(roots
                .iter()
                .map(|r| r.map_or(0, |sym| eval.root_count(transducer, sym, &emit0_counts)))
                .collect())
        }
        match transducer.num_states {
            n if n <= <u8 as PackedCell>::MAX_STATES => run::<u8>(self, transducer, roots),
            n if n <= <u16 as PackedCell>::MAX_STATES => run::<u16>(self, transducer, roots),
            n => Err(too_many_states(pattern, n)),
        }
    }

    /// Returns the total emission count of the document rooted at `root` together with the
    /// document offsets of its first `limit` emitting bytes (stream emissions only; end-of-file
    /// emissions are not located).
    pub(crate) fn locate_emissions(
        &self,
        transducer: &MealyTransducer,
        root: SymbolId,
        limit: usize,
        pattern: &str,
    ) -> Result<(u64, Vec<u64>)> {
        fn run<C: PackedCell>(
            archive: &MappedArchive,
            transducer: &MealyTransducer,
            root: SymbolId,
            limit: usize,
        ) -> Result<(u64, Vec<u64>)> {
            let mut eval = PackedEval::<C>::new(archive, transducer);
            let emit0_counts = eval.build_count_table()?;
            let total = eval.root_count(transducer, root, &emit0_counts);
            let limit = limit.min(usize::try_from(total).unwrap_or(usize::MAX));
            let mut walk = OffsetWalk {
                archive,
                meta: archive.navigation_meta()?,
                emit0_counts: &emit0_counts,
                memo: FxHashMap::default(),
                limit,
                out: Vec::with_capacity(limit.min(1 << 20)),
            };
            if limit > 0 {
                eval.walk_emitted_offsets(&mut walk, root, 0, 0)?;
            }
            Ok((total, walk.out))
        }
        match transducer.num_states {
            n if n <= <u8 as PackedCell>::MAX_STATES => run::<u8>(self, transducer, root, limit),
            n if n <= <u16 as PackedCell>::MAX_STATES => run::<u16>(self, transducer, root, limit),
            n => Err(too_many_states(pattern, n)),
        }
    }

    /// Collects up to `limit` matching lines across the given `(name, root)` documents in order.
    fn collect_lines(
        &self,
        transducer: &MealyTransducer,
        docs: &[(&str, SymbolId)],
        limit: usize,
        pattern: &str,
    ) -> Result<Vec<(String, Vec<String>)>> {
        fn run<C: PackedCell>(
            archive: &MappedArchive,
            transducer: &MealyTransducer,
            docs: &[(&str, SymbolId)],
            limit: usize,
        ) -> Result<Vec<(String, Vec<String>)>> {
            let mut eval = PackedEval::<C>::new(archive, transducer);
            let mut memo: FxHashMap<u64, C> = FxHashMap::default();
            eval.build_line_table(&mut memo)?;
            let mut left_siblings = Vec::with_capacity(32);
            let mut results = Vec::new();
            let mut remaining = limit;
            for &(name, sym) in docs {
                if remaining == 0 {
                    break;
                }
                let lines = eval.collect_root_lines(
                    transducer,
                    sym,
                    remaining,
                    &mut memo,
                    &mut left_siblings,
                );
                if !lines.is_empty() {
                    remaining = remaining.saturating_sub(lines.len());
                    results.push((name.to_string(), lines));
                }
            }
            Ok(results)
        }
        match transducer.num_states {
            n if n <= <u8 as PackedCell>::MAX_STATES => run::<u8>(self, transducer, docs, limit),
            n if n <= <u16 as PackedCell>::MAX_STATES => run::<u16>(self, transducer, docs, limit),
            n => Err(too_many_states(pattern, n)),
        }
    }

    /// Zero-copy, 1-byte-per-symbol extraction of matching lines on a single document.
    pub fn grep_lines(
        &self,
        doc_name: Option<&str>,
        pattern: &str,
        limit: usize,
    ) -> Result<Vec<String>> {
        let root = self.find_root(doc_name)?;
        let Some(sym) = root.root_symbol else {
            return Ok(Vec::new());
        };
        let transducer = compile_line_grep_transducer(pattern)?;
        let mut results = self.collect_lines(&transducer, &[(&root.name, sym)], limit, pattern)?;
        Ok(results.pop().map(|(_, lines)| lines).unwrap_or_default())
    }

    /// Zero-copy, 1-byte-per-symbol extraction of matching lines across ALL documents in the archive.
    pub fn grep_lines_all_docs(
        &self,
        pattern: &str,
        limit: usize,
    ) -> Result<Vec<(String, Vec<String>)>> {
        let transducer = compile_line_grep_transducer(pattern)?;
        let docs: Vec<(&str, SymbolId)> = self
            .roots
            .iter()
            .filter_map(|r| r.root_symbol.map(|sym| (r.name.as_str(), sym)))
            .collect();
        self.collect_lines(&transducer, &docs, limit, pattern)
    }

    pub fn grep(&self, doc_name: Option<&str>, pattern: &str, mode: GrepMode) -> Result<u64> {
        let root = self.find_root(doc_name)?;
        if root.root_symbol.is_none() {
            return Ok(0);
        }
        let transducer = Self::compile_transducer(pattern, mode)?;
        let counts = self.count_emissions(&transducer, &[root.root_symbol], pattern)?;
        Ok(counts[0])
    }

    pub fn grep_all_docs(&self, pattern: &str, mode: GrepMode) -> Result<Vec<(String, u64)>> {
        let transducer = Self::compile_transducer(pattern, mode)?;
        let roots: Vec<Option<SymbolId>> = self.roots.iter().map(|r| r.root_symbol).collect();
        let counts = self.count_emissions(&transducer, &roots, pattern)?;
        Ok(self
            .roots
            .iter()
            .zip(counts)
            .map(|(r, c)| (r.name.clone(), c))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::Regex;

    fn oracle_line_count(data: &[u8], pattern: &str) -> u64 {
        if data.is_empty() {
            return 0;
        }
        let re = Regex::new(pattern).unwrap();
        let slice = if data.last() == Some(&b'\n') {
            &data[..data.len() - 1]
        } else {
            data
        };
        slice
            .split(|&b| b == b'\n')
            .filter(|line| re.is_match(line))
            .count() as u64
    }

    #[test]
    fn test_wreath_transducer_line_grep_and_match_count() {
        let mut log = Vec::new();
        for i in 0..300 {
            if i % 7 == 0 {
                log.extend_from_slice(
                    format!("2026-10-24 ERROR [auth] user={} code=500\n", i).as_bytes(),
                );
            } else if i % 5 == 0 {
                log.extend_from_slice(
                    format!("2026-10-24 WARN [db] slow_query={}ms code=200\n", i * 10).as_bytes(),
                );
            } else {
                log.extend_from_slice(format!("2026-10-24 INFO [api] ok id={}\n", i).as_bytes());
            }
        }
        // Also test without trailing newline!
        let mut log_no_nl = log.clone();
        log_no_nl.extend_from_slice(b"2026-10-24 ERROR [final] trailing_line_without_nl code=500");

        for dataset in [&log, &log_no_nl] {
            let dag = GrammarDag::from_bytes(dataset);
            for pat in [
                "ERROR",
                "WARN|ERROR",
                "^2026-10-24 ERROR",
                "code=500$",
                "\\[db\\].*code=200",
                "slow_query=[0-9]+ms",
                "NON_EXISTENT_PATTERN",
            ] {
                let got_lines = dag.grep(None, pat, GrepMode::LineCount).unwrap();
                let expected_lines = oracle_line_count(dataset, pat);
                assert_eq!(
                    got_lines, expected_lines,
                    "LineCount mismatch for pattern '{pat}'"
                );

                let got_matches = dag.grep(None, pat, GrepMode::MatchCount).unwrap();
                let re = regex::bytes::RegexBuilder::new(pat)
                    .multi_line(true)
                    .build()
                    .unwrap();
                let expected_matches = re.find_iter(dataset).count() as u64;
                assert_eq!(
                    got_matches, expected_matches,
                    "MatchCount mismatch for pattern '{pat}'"
                );

                let extracted = dag.grep_lines(None, pat, usize::MAX).unwrap();
                let slice = if dataset.last() == Some(&b'\n') {
                    &dataset[..dataset.len() - 1]
                } else {
                    dataset.as_slice()
                };
                let re_line = Regex::new(pat).unwrap();
                let expected_extracted: Vec<String> = slice
                    .split(|&b| b == b'\n')
                    .filter(|line| re_line.is_match(line))
                    .map(|l| String::from_utf8_lossy(l).into_owned())
                    .collect();
                assert_eq!(
                    extracted, expected_extracted,
                    "Extracted lines mismatch for pattern '{pat}'"
                );
            }
        }
    }
}
