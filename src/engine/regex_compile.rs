use regex_automata::dfa::{dense, Automaton, StartKind};
use regex_automata::util::primitives::StateID;
use regex_automata::util::syntax;
use regex_automata::{Anchored, Input, MatchKind};
use rustc_hash::FxHashMap;

use crate::engine::transducer::MealyTransducer;
use crate::error::{ButtlickError, Result};
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
