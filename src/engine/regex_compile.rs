use regex_automata::dfa::{dense, Automaton, StartKind};
use regex_automata::util::primitives::StateID;
use regex_automata::util::syntax;
use regex_automata::{Anchored, Input, MatchKind};
use rustc_hash::FxHashMap;

use crate::engine::transducer::MealyTransducer;
use crate::error::{ButtlickError, Result};
use crate::format::header::PackedRuleNode;
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

    let map_active_state = |sid: StateID,
                            map: &mut FxHashMap<StateID, u16>,
                            vec: &mut Vec<StateID>|
     -> u16 {
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

    let intern_state = |sid: StateID,
                        map: &mut FxHashMap<StateID, u16>,
                        vec: &mut Vec<StateID>|
     -> u16 {
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

#[inline]
fn eval_sym_state(
    sym: SymbolId,
    q: u16,
    rules_bytes: &[u8],
    terminal_packed: &[u8],
    table: &[u8],
    memo: &mut FxHashMap<u64, u8>,
) -> u8 {
    if q == 0 {
        return unsafe { *table.get_unchecked(sym.0 as usize) };
    }
    if let Some(b) = sym.as_byte() {
        return terminal_packed[(q as usize) * 256 + (b as usize)];
    }
    let key = ((sym.0 as u64) << 16) | (q as u64);
    if let Some(&cached) = memo.get(&key) {
        return cached;
    }
    let off = sym.rule_index() * 8;
    let w0 = u32::from_le_bytes([
        rules_bytes[off],
        rules_bytes[off + 1],
        rules_bytes[off + 2],
        rules_bytes[off + 3],
    ]);
    let w1 = u32::from_le_bytes([
        rules_bytes[off + 4],
        rules_bytes[off + 5],
        rules_bytes[off + 6],
        rules_bytes[off + 7],
    ]);
    let res = if (w0 & PackedRuleNode::RUN_TAG_BIT) == 0 {
        let l_val = eval_sym_state(SymbolId(w0), q, rules_bytes, terminal_packed, table, memo);
        let q_mid = (l_val & 0x7F) as u16;
        let r_val = if q_mid == 0 {
            unsafe { *table.get_unchecked(w1 as usize) }
        } else {
            eval_sym_state(
                SymbolId(w1),
                q_mid,
                rules_bytes,
                terminal_packed,
                table,
                memo,
            )
        };
        r_val | (l_val & 0x80)
    } else {
        let child = SymbolId(w0 & !PackedRuleNode::RUN_TAG_BIT);
        eval_run_state(
            child,
            w1 as u64,
            q,
            rules_bytes,
            terminal_packed,
            table,
            memo,
        )
    };
    memo.insert(key, res);
    res
}

#[inline]
fn eval_run_state(
    child: SymbolId,
    count: u64,
    q: u16,
    rules_bytes: &[u8],
    terminal_packed: &[u8],
    table: &[u8],
    memo: &mut FxHashMap<u64, u8>,
) -> u8 {
    let mut cur_q = q;
    let mut emitted = 0u8;
    for _ in 0..count {
        let v = eval_sym_state(child, cur_q, rules_bytes, terminal_packed, table, memo);
        let next_q = (v & 0x7F) as u16;
        emitted |= v & 0x80;
        if next_q == cur_q {
            break;
        }
        cur_q = next_q;
    }
    (cur_q as u8) | emitted
}

fn append_rev_until_nl(rules_bytes: &[u8], sym: SymbolId, rev_buf: &mut Vec<u8>) -> bool {
    if let Some(b) = sym.as_byte() {
        if b == b'\n' {
            return true;
        }
        rev_buf.push(b);
        return false;
    }
    let off = sym.rule_index() * 8;
    let w0 = u32::from_le_bytes([
        rules_bytes[off],
        rules_bytes[off + 1],
        rules_bytes[off + 2],
        rules_bytes[off + 3],
    ]);
    let w1 = u32::from_le_bytes([
        rules_bytes[off + 4],
        rules_bytes[off + 5],
        rules_bytes[off + 6],
        rules_bytes[off + 7],
    ]);
    if (w0 & PackedRuleNode::RUN_TAG_BIT) == 0 {
        if append_rev_until_nl(rules_bytes, SymbolId(w1), rev_buf) {
            return true;
        }
        append_rev_until_nl(rules_bytes, SymbolId(w0), rev_buf)
    } else {
        let child = SymbolId(w0 & !PackedRuleNode::RUN_TAG_BIT);
        let count = w1 as u64;
        for _ in 0..count {
            if append_rev_until_nl(rules_bytes, child, rev_buf) {
                return true;
            }
        }
        false
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_emitted_lines_mapped(
    sym: SymbolId,
    q: u16,
    limit: usize,
    rules_bytes: &[u8],
    terminal_packed: &[u8],
    table: &[u8],
    memo: &mut FxHashMap<u64, u8>,
    left_siblings: &mut Vec<(SymbolId, u64)>,
    out_lines: &mut Vec<String>,
) -> u16 {
    let v = eval_sym_state(sym, q, rules_bytes, terminal_packed, table, memo);
    let q_out = (v & 0x7F) as u16;
    let has_emit = (v & 0x80) != 0;
    if !has_emit || out_lines.len() >= limit {
        return q_out;
    }
    if sym.is_terminal() {
        let mut rev_buf = Vec::with_capacity(128);
        for &(sib_sym, sib_count) in left_siblings.iter().rev() {
            let mut hit_nl = false;
            for _ in 0..sib_count {
                if append_rev_until_nl(rules_bytes, sib_sym, &mut rev_buf) {
                    hit_nl = true;
                    break;
                }
            }
            if hit_nl {
                break;
            }
        }
        rev_buf.reverse();
        out_lines.push(String::from_utf8_lossy(&rev_buf).into_owned());
        return q_out;
    }

    let off = sym.rule_index() * 8;
    let w0 = u32::from_le_bytes([
        rules_bytes[off],
        rules_bytes[off + 1],
        rules_bytes[off + 2],
        rules_bytes[off + 3],
    ]);
    let w1 = u32::from_le_bytes([
        rules_bytes[off + 4],
        rules_bytes[off + 5],
        rules_bytes[off + 6],
        rules_bytes[off + 7],
    ]);

    if (w0 & PackedRuleNode::RUN_TAG_BIT) == 0 {
        let left = SymbolId(w0);
        let right = SymbolId(w1);
        let q_mid = walk_emitted_lines_mapped(
            left,
            q,
            limit,
            rules_bytes,
            terminal_packed,
            table,
            memo,
            left_siblings,
            out_lines,
        );
        if out_lines.len() < limit {
            left_siblings.push((left, 1));
            let _ = walk_emitted_lines_mapped(
                right,
                q_mid,
                limit,
                rules_bytes,
                terminal_packed,
                table,
                memo,
                left_siblings,
                out_lines,
            );
            left_siblings.pop();
        }
        q_out
    } else {
        let child = SymbolId(w0 & !PackedRuleNode::RUN_TAG_BIT);
        let count = w1 as u64;
        let mut cur_q = q;
        for i in 0..count {
            if out_lines.len() >= limit {
                break;
            }
            let cv = eval_sym_state(child, cur_q, rules_bytes, terminal_packed, table, memo);
            let next_q = (cv & 0x7F) as u16;
            if (cv & 0x80) == 0 {
                if next_q == cur_q {
                    break;
                }
                cur_q = next_q;
                continue;
            }
            if i > 0 {
                left_siblings.push((child, i));
            }
            cur_q = walk_emitted_lines_mapped(
                child,
                cur_q,
                limit,
                rules_bytes,
                terminal_packed,
                table,
                memo,
                left_siblings,
                out_lines,
            );
            if i > 0 {
                left_siblings.pop();
            }
        }
        q_out
    }
}

impl MappedArchive {
    fn build_fast_line_table(
        &self,
        transducer: &MealyTransducer,
    ) -> (Vec<u8>, Vec<u8>, FxHashMap<u64, u8>) {
        let s = transducer.num_states;
        let mut terminal_packed = vec![0u8; s * 256];
        for q in 0..s {
            for b in 0..=255usize {
                let idx = q * 256 + b;
                let nq = transducer.byte_next[idx] as u8;
                let em = if transducer.byte_emit[idx] > 0 {
                    0x80
                } else {
                    0
                };
                terminal_packed[idx] = nq | em;
            }
        }

        let rules_bytes = self.rules_bytes();
        let mut table = vec![0u8; 256 + self.num_rules];
        table[0..256].copy_from_slice(&terminal_packed[0..256]);
        let mut memo: FxHashMap<u64, u8> = FxHashMap::default();

        for (idx, chunk) in rules_bytes.chunks_exact(8).enumerate() {
            let w0 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let w1 = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            let sym_idx = 256 + idx;
            if (w0 & PackedRuleNode::RUN_TAG_BIT) == 0 {
                let l_val = unsafe { *table.get_unchecked(w0 as usize) };
                if (l_val & 0x7F) == 0 {
                    let r_val = unsafe { *table.get_unchecked(w1 as usize) };
                    unsafe {
                        *table.get_unchecked_mut(sym_idx) = r_val | l_val;
                    }
                } else {
                    let q_mid = (l_val & 0x7F) as u16;
                    let r_val = eval_sym_state(
                        SymbolId(w1),
                        q_mid,
                        rules_bytes,
                        &terminal_packed,
                        &table,
                        &mut memo,
                    );
                    table[sym_idx] = r_val | (l_val & 0x80);
                }
            } else {
                let child = SymbolId(w0 & !PackedRuleNode::RUN_TAG_BIT);
                table[sym_idx] = eval_run_state(
                    child,
                    w1 as u64,
                    0,
                    rules_bytes,
                    &terminal_packed,
                    &table,
                    &mut memo,
                );
            }
        }

        (terminal_packed, table, memo)
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
        let (terminal_packed, table, mut memo) = self.build_fast_line_table(&transducer);
        let rules_bytes = self.rules_bytes();
        let mut out_lines = Vec::new();
        let mut left_siblings = Vec::with_capacity(32);

        let root_val = table[sym.0 as usize];
        let final_q = (root_val & 0x7F) as usize;
        if (root_val & 0x80) != 0 {
            let _ = walk_emitted_lines_mapped(
                sym,
                0,
                limit,
                rules_bytes,
                &terminal_packed,
                &table,
                &mut memo,
                &mut left_siblings,
                &mut out_lines,
            );
        }
        if out_lines.len() < limit && transducer.eof_emit[final_q] > 0 {
            let mut rev_buf = Vec::with_capacity(128);
            let _ = append_rev_until_nl(rules_bytes, sym, &mut rev_buf);
            rev_buf.reverse();
            out_lines.push(String::from_utf8_lossy(&rev_buf).into_owned());
        }
        Ok(out_lines)
    }

    /// Zero-copy, 1-byte-per-symbol extraction of matching lines across ALL documents in the archive.
    pub fn grep_lines_all_docs(
        &self,
        pattern: &str,
        limit: usize,
    ) -> Result<Vec<(String, Vec<String>)>> {
        let transducer = compile_line_grep_transducer(pattern)?;
        let (terminal_packed, table, mut memo) = self.build_fast_line_table(&transducer);
        let rules_bytes = self.rules_bytes();
        let mut results = Vec::new();
        let mut remaining = limit;
        let mut left_siblings = Vec::with_capacity(32);

        for root in &self.roots {
            if remaining == 0 {
                break;
            }
            let Some(sym) = root.root_symbol else {
                continue;
            };
            let root_val = table[sym.0 as usize];
            let final_q = (root_val & 0x7F) as usize;
            let has_eof = transducer.eof_emit[final_q] > 0;
            if (root_val & 0x80) == 0 && !has_eof {
                continue;
            }
            let mut doc_lines = Vec::new();
            if (root_val & 0x80) != 0 {
                left_siblings.clear();
                let _ = walk_emitted_lines_mapped(
                    sym,
                    0,
                    remaining,
                    rules_bytes,
                    &terminal_packed,
                    &table,
                    &mut memo,
                    &mut left_siblings,
                    &mut doc_lines,
                );
            }
            if doc_lines.len() < remaining && has_eof {
                let mut rev_buf = Vec::with_capacity(128);
                let _ = append_rev_until_nl(rules_bytes, sym, &mut rev_buf);
                rev_buf.reverse();
                doc_lines.push(String::from_utf8_lossy(&rev_buf).into_owned());
            }
            if !doc_lines.is_empty() {
                remaining = remaining.saturating_sub(doc_lines.len());
                results.push((root.name.clone(), doc_lines));
            }
        }
        Ok(results)
    }

    fn build_fast_count_table(
        &self,
        transducer: &MealyTransducer,
    ) -> (Vec<u8>, FxHashMap<u32, u64>) {
        let s = transducer.num_states;
        let mut terminal_packed = vec![0u8; s * 256];
        for q in 0..s {
            for b in 0..=255usize {
                let idx = q * 256 + b;
                let nq = transducer.byte_next[idx] as u8;
                let em = if transducer.byte_emit[idx] > 0 {
                    0x80
                } else {
                    0
                };
                terminal_packed[idx] = nq | em;
            }
        }

        let rules_bytes = self.rules_bytes();
        let mut table = vec![0u8; 256 + self.num_rules];
        table[0..256].copy_from_slice(&terminal_packed[0..256]);
        let mut emit0_counts: FxHashMap<u32, u64> = FxHashMap::default();
        let mut memo: FxHashMap<u64, (u8, u64)> = FxHashMap::default();

        for (idx, chunk) in rules_bytes.chunks_exact(8).enumerate() {
            let w0 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let w1 = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            let sym_idx = 256 + idx;
            if (w0 & PackedRuleNode::RUN_TAG_BIT) == 0 {
                let l_val = unsafe { *table.get_unchecked(w0 as usize) };
                if (l_val & 0x7F) == 0 {
                    let r_val = unsafe { *table.get_unchecked(w1 as usize) };
                    let out_val = r_val | l_val;
                    unsafe {
                        *table.get_unchecked_mut(sym_idx) = out_val;
                    }
                    if (out_val & 0x80) != 0 {
                        let lc = if (l_val & 0x80) == 0 {
                            0
                        } else if w0 < 256 {
                            1
                        } else {
                            emit0_counts[&w0]
                        };
                        let rc = if (r_val & 0x80) == 0 {
                            0
                        } else if w1 < 256 {
                            1
                        } else {
                            emit0_counts[&w1]
                        };
                        emit0_counts.insert(sym_idx as u32, lc + rc);
                    }
                } else {
                    let q_mid = (l_val & 0x7F) as u16;
                    let lc = if (l_val & 0x80) == 0 {
                        0
                    } else if w0 < 256 {
                        1
                    } else {
                        emit0_counts[&w0]
                    };
                    let (r_val, rc) = eval_sym_count_state(
                        SymbolId(w1),
                        q_mid,
                        rules_bytes,
                        &terminal_packed,
                        &table,
                        &emit0_counts,
                        &mut memo,
                    );
                    let out_val = r_val | (l_val & 0x80);
                    table[sym_idx] = out_val;
                    if (out_val & 0x80) != 0 {
                        emit0_counts.insert(sym_idx as u32, lc + rc);
                    }
                }
            } else {
                let child = SymbolId(w0 & !PackedRuleNode::RUN_TAG_BIT);
                let (out_val, c) = eval_run_count_state(
                    child,
                    w1 as u64,
                    0,
                    rules_bytes,
                    &terminal_packed,
                    &table,
                    &emit0_counts,
                    &mut memo,
                );
                table[sym_idx] = out_val;
                if (out_val & 0x80) != 0 {
                    emit0_counts.insert(sym_idx as u32, c);
                }
            }
        }

        (table, emit0_counts)
    }

    pub fn grep(&self, doc_name: Option<&str>, pattern: &str, mode: GrepMode) -> Result<u64> {
        let root = self.find_root(doc_name)?;
        let Some(sym) = root.root_symbol else {
            return Ok(0);
        };
        let transducer = match mode {
            GrepMode::LineCount => compile_line_grep_transducer(pattern)?,
            GrepMode::MatchCount => compile_match_count_transducer(pattern)?,
        };
        let (table, emit0_counts) = self.build_fast_count_table(&transducer);
        let root_val = table[sym.0 as usize];
        let final_q = (root_val & 0x7F) as usize;
        let stream_c = if (root_val & 0x80) == 0 {
            0
        } else if sym.0 < 256 {
            1
        } else {
            emit0_counts[&sym.0]
        };
        Ok(stream_c + transducer.eof_emit[final_q])
    }

    pub fn grep_all_docs(&self, pattern: &str, mode: GrepMode) -> Result<Vec<(String, u64)>> {
        let transducer = match mode {
            GrepMode::LineCount => compile_line_grep_transducer(pattern)?,
            GrepMode::MatchCount => compile_match_count_transducer(pattern)?,
        };
        let (table, emit0_counts) = self.build_fast_count_table(&transducer);
        let mut results = Vec::with_capacity(self.roots.len());
        for root in &self.roots {
            let c = match root.root_symbol {
                None => 0,
                Some(sym) => {
                    let root_val = table[sym.0 as usize];
                    let final_q = (root_val & 0x7F) as usize;
                    let stream_c = if (root_val & 0x80) == 0 {
                        0
                    } else if sym.0 < 256 {
                        1
                    } else {
                        emit0_counts[&sym.0]
                    };
                    stream_c + transducer.eof_emit[final_q]
                }
            };
            results.push((root.name.clone(), c));
        }
        Ok(results)
    }
}

#[allow(clippy::too_many_arguments)]
fn eval_sym_count_state(
    sym: SymbolId,
    q: u16,
    rules_bytes: &[u8],
    terminal_packed: &[u8],
    table: &[u8],
    emit0_counts: &FxHashMap<u32, u64>,
    memo: &mut FxHashMap<u64, (u8, u64)>,
) -> (u8, u64) {
    if q == 0 {
        let v = unsafe { *table.get_unchecked(sym.0 as usize) };
        let c = if (v & 0x80) == 0 {
            0
        } else if sym.0 < 256 {
            1
        } else {
            emit0_counts[&sym.0]
        };
        return (v, c);
    }
    if let Some(b) = sym.as_byte() {
        let v = terminal_packed[(q as usize) * 256 + (b as usize)];
        return (v, ((v & 0x80) != 0) as u64);
    }
    let key = ((sym.0 as u64) << 16) | (q as u64);
    if let Some(&cached) = memo.get(&key) {
        return cached;
    }
    let off = sym.rule_index() * 8;
    let w0 = u32::from_le_bytes([
        rules_bytes[off],
        rules_bytes[off + 1],
        rules_bytes[off + 2],
        rules_bytes[off + 3],
    ]);
    let w1 = u32::from_le_bytes([
        rules_bytes[off + 4],
        rules_bytes[off + 5],
        rules_bytes[off + 6],
        rules_bytes[off + 7],
    ]);
    let res = if (w0 & PackedRuleNode::RUN_TAG_BIT) == 0 {
        let (l_val, lc) = eval_sym_count_state(
            SymbolId(w0),
            q,
            rules_bytes,
            terminal_packed,
            table,
            emit0_counts,
            memo,
        );
        let q_mid = (l_val & 0x7F) as u16;
        let (r_val, rc) = eval_sym_count_state(
            SymbolId(w1),
            q_mid,
            rules_bytes,
            terminal_packed,
            table,
            emit0_counts,
            memo,
        );
        (r_val | (l_val & 0x80), lc + rc)
    } else {
        let child = SymbolId(w0 & !PackedRuleNode::RUN_TAG_BIT);
        eval_run_count_state(
            child,
            w1 as u64,
            q,
            rules_bytes,
            terminal_packed,
            table,
            emit0_counts,
            memo,
        )
    };
    memo.insert(key, res);
    res
}

#[allow(clippy::too_many_arguments)]
fn eval_run_count_state(
    child: SymbolId,
    count: u64,
    q: u16,
    rules_bytes: &[u8],
    terminal_packed: &[u8],
    table: &[u8],
    emit0_counts: &FxHashMap<u32, u64>,
    memo: &mut FxHashMap<u64, (u8, u64)>,
) -> (u8, u64) {
    let mut cur_q = q;
    let mut emitted_flag = 0u8;
    let mut total_c = 0u64;
    for i in 0..count {
        let (v, c) = eval_sym_count_state(
            child,
            cur_q,
            rules_bytes,
            terminal_packed,
            table,
            emit0_counts,
            memo,
        );
        let next_q = (v & 0x7F) as u16;
        if next_q == cur_q {
            let rem = count - i;
            if c > 0 {
                emitted_flag |= 0x80;
                total_c += rem * c;
            }
            break;
        }
        emitted_flag |= v & 0x80;
        total_c += c;
        cur_q = next_q;
    }
    ((cur_q as u8) | emitted_flag, total_c)
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
