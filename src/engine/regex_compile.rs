use regex_automata::dfa::{dense, Automaton, StartKind};
use regex_automata::util::primitives::StateID;
use regex_automata::util::syntax;
use regex_automata::{Anchored, Input, MatchKind};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::engine::transducer::{advance_run, MealyTransducer};
use crate::error::{ButtlickError, Result};
use crate::format::header::{PackedRuleNode, PACKED_RULE_SIZE};
use crate::format::mapped::MappedMeta;
use crate::format::MappedArchive;
use crate::grammar::{GrammarDag, RootEntry, SymbolId};

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
/// (counting non-overlapping matches across the stream). Supports simple greedy byte
/// repetitions and context-free, nonempty matches that cannot extend after acceptance.
/// Other valid patterns return an error here; `GrammarDag::grep` / `MappedArchive::grep`
/// choose an exact regex engine for those patterns instead.
pub fn compile_match_count_transducer(pattern: &str) -> Result<MealyTransducer> {
    let hir = parse_match_hir(pattern)?;
    if let Some(transducer) = compile_byte_repetition(&hir) {
        return Ok(transducer);
    }
    if hir.properties().minimum_len() == Some(0) || !hir.properties().look_set().is_empty() {
        return Err(ButtlickError::InvalidQuery(
            "match counting requires the exact regex engine for nullable or contextual patterns"
                .into(),
        ));
    }
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

    let initial = dfa
        .start_state_forward(&Input::new(b"").anchored(Anchored::No))
        .map_err(|e| ButtlickError::InvalidRegex {
            pattern: pattern.to_string(),
            message: e.to_string(),
        })?;
    // DFA start states may carry search metadata despite having identical transitions
    // to the ordinary unanchored loop. Use that equivalent loop as packed state zero.
    let q_start = (0..=255)
        .map(|byte| dfa.next_state(initial, byte))
        .find(|&state| {
            !dfa.is_match_state(state)
                && dfa.next_eoi_state(state) == dfa.next_eoi_state(initial)
                && (0..=255)
                    .all(|byte| dfa.next_state(state, byte) == dfa.next_state(initial, byte))
        })
        .unwrap_or(initial);
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

    let start_state = intern_state(q_start, &mut dfa_to_trans, &mut trans_to_dfa);

    let restart_on_byte = |b: u8| dfa.next_state(q_start, b);
    let mut checked_matches = FxHashSet::default();

    let mut cursor = 0usize;
    while cursor < trans_to_dfa.len() {
        let sid = trans_to_dfa[cursor];
        cursor += 1;
        for b in 0..=255u8 {
            let next_sid = dfa.next_state(sid, b);
            let target_sid = if dfa.is_match_state(next_sid) {
                if checked_matches.insert(next_sid) && accepting_can_extend(&dfa, next_sid) {
                    return Err(ButtlickError::InvalidQuery("greedy match counting requires delayed match resolution by the exact regex engine".into()));
                }
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
        eof_emit[q] = if dfa.is_match_state(eoi) { 1 } else { 0 };

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

fn parse_match_hir(pattern: &str) -> Result<regex_syntax::hir::Hir> {
    regex_syntax::ParserBuilder::new()
        .multi_line(true)
        .utf8(false)
        .build()
        .parse(pattern)
        .map_err(|err| ButtlickError::InvalidRegex {
            pattern: pattern.into(),
            message: err.to_string(),
        })
}

/// Greedy repetitions of a single byte class count maximal runs. Emitting at the
/// beginning of each run avoids committing a premature greedy end; `*` additionally
/// counts empty positions except immediately after a nonempty match.
fn compile_byte_repetition(hir: &regex_syntax::hir::Hir) -> Option<MealyTransducer> {
    use regex_syntax::hir::{Class, Hir, HirKind};
    fn uncapture(mut hir: &Hir) -> &Hir {
        while let HirKind::Capture(capture) = hir.kind() {
            hir = &capture.sub;
        }
        hir
    }
    let HirKind::Repetition(repeat) = uncapture(hir).kind() else {
        return None;
    };
    if !repeat.greedy || repeat.max.is_some() || repeat.min > 1 {
        return None;
    }
    let mut member = [false; 256];
    match uncapture(&repeat.sub).kind() {
        HirKind::Literal(literal) if literal.0.len() == 1 => member[literal.0[0] as usize] = true,
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.iter() {
                for byte in range.start()..=range.end() {
                    member[byte as usize] = true;
                }
            }
        }
        HirKind::Class(Class::Unicode(class)) => {
            for range in class.iter() {
                if !range.end().is_ascii() {
                    return None;
                }
                for byte in range.start() as u8..=range.end() as u8 {
                    member[byte as usize] = true;
                }
            }
        }
        _ => return None,
    }
    let mut transducer = MealyTransducer {
        num_states: 2,
        start_state: 0,
        byte_next: vec![0; 512],
        byte_emit: vec![0; 512],
        eof_emit: vec![(repeat.min == 0) as u64, 0],
    };
    for q in 0..2 {
        for (byte, &matches) in member.iter().enumerate() {
            transducer.byte_next[q * 256 + byte] = matches as u16;
            transducer.byte_emit[q * 256 + byte] = (q == 0 && (matches || repeat.min == 0)) as u64;
        }
    }
    Some(transducer)
}

/// DFA matches are delayed by one byte. Committing immediately is sound only when
/// neither that consumed byte nor any following suffix can extend the saved match.
fn accepting_can_extend<A: Automaton>(dfa: &A, state: StateID) -> bool {
    let mut seen = FxHashSet::default();
    let mut stack = vec![state];
    seen.insert(state);
    while let Some(state) = stack.pop() {
        if dfa.is_match_state(dfa.next_eoi_state(state)) {
            return true;
        }
        for byte in 0..=255 {
            let next = dfa.next_state(state, byte);
            if dfa.is_match_state(next) || dfa.is_quit_state(next) {
                return true;
            }
            if !dfa.is_dead_state(next) && seen.insert(next) {
                stack.push(next);
            }
        }
    }
    false
}

/// Count regex matches with full leftmost-first/greedy/empty-match semantics. The fast
/// transducer is retained only where its counting semantics are sound; other patterns use the
/// regex crate on one expanded document at a time. Empty-language/empty-string patterns
/// need no expansion and therefore also work on enormous logical runs.
fn exact_match_counts(
    pattern: &str,
    roots: &[&RootEntry],
    evaluate: impl FnOnce(&MealyTransducer) -> Result<Vec<u64>>,
    mut expand: impl FnMut(&RootEntry, &mut Vec<u8>) -> Result<()>,
) -> Result<Vec<u64>> {
    let hir = parse_match_hir(pattern)?;
    if hir.properties().minimum_len().is_none() {
        return Ok(vec![0; roots.len()]);
    }
    if hir.properties().maximum_len() == Some(0) && hir.properties().look_set().is_empty() {
        return Ok(roots
            .iter()
            .map(|root| root.byte_len.saturating_add(1))
            .collect());
    }
    if let Ok(transducer) = compile_match_count_transducer(pattern) {
        if transducer.num_states <= <u16 as PackedCell>::MAX_STATES {
            return evaluate(&transducer);
        }
    }
    let regex = regex::bytes::RegexBuilder::new(pattern)
        .multi_line(true)
        .build()
        .map_err(|err| ButtlickError::InvalidRegex {
            pattern: pattern.into(),
            message: err.to_string(),
        })?;
    let mut bytes = Vec::new();
    let mut counts = Vec::with_capacity(roots.len());
    for root in roots {
        bytes.clear();
        let len = usize::try_from(root.byte_len).map_err(|_| {
            ButtlickError::InvalidQuery("document is too large for exact regex buffering".into())
        })?;
        bytes.try_reserve(len).map_err(|err| {
            ButtlickError::InvalidQuery(format!(
                "cannot buffer document '{}' for this regex: {err}",
                root.name
            ))
        })?;
        expand(root, &mut bytes)?;
        if bytes.len() as u64 != root.byte_len {
            return Err(ButtlickError::CorruptedFormat(format!(
                "Root '{}' length mismatch",
                root.name
            )));
        }
        counts.push(regex.find_iter(&bytes).count() as u64);
    }
    Ok(counts)
}

impl GrammarDag {
    pub(crate) fn match_counts(&self, pattern: &str, roots: &[&RootEntry]) -> Result<Vec<u64>> {
        exact_match_counts(
            pattern,
            roots,
            |transducer| {
                let eval = transducer.evaluate_dag(self);
                Ok(roots
                    .iter()
                    .map(|root| eval.query_root(root.root_symbol))
                    .collect())
            },
            |root, bytes| {
                if let Some(sym) = root.root_symbol {
                    self.decompress_symbol_into(sym, bytes);
                }
                Ok(())
            },
        )
    }

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
        if mode == GrepMode::MatchCount {
            return Ok(self.match_counts(pattern, &[root])?[0]);
        }
        let transducer = compile_line_grep_transducer(pattern)?;
        let eval = transducer.evaluate_dag(self);
        Ok(eval.query_root(root.root_symbol))
    }

    /// Zero-decompression extraction of matching lines in a named document in $O(n \cdot |Q| + k \log N)$ time.
    pub fn grep_lines(
        &self,
        doc_name: Option<&str>,
        pattern: &str,
        limit: usize,
    ) -> Result<Vec<String>> {
        let root = self.find_root(doc_name)?;
        let transducer = compile_line_grep_transducer(pattern)?;
        let Some(sym) = root.root_symbol else {
            return Ok(Vec::new());
        };
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
    type MemoCell: Copy;
    const ZERO: Self;
    const EMIT_FLAG: Self;
    const MAX_STATES: usize;
    fn from_state(q: u16) -> Self;
    fn state(self) -> u16;
    fn memo_table(len: usize) -> Vec<Self::MemoCell>;
    fn pack_memo(q: u16, exit: Self) -> Self::MemoCell;
    fn unpack_memo(word: Self::MemoCell) -> (u16, Self);
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
    type MemoCell = u16;
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
    fn memo_table(len: usize) -> Vec<u16> {
        vec![0; len]
    }
    #[inline(always)]
    fn pack_memo(q: u16, exit: Self) -> u16 {
        (q << 8) | exit as u16
    }
    #[inline(always)]
    fn unpack_memo(word: u16) -> (u16, Self) {
        (word >> 8, word as u8)
    }
}

impl PackedCell for u16 {
    type MemoCell = u32;
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
    fn memo_table(len: usize) -> Vec<u32> {
        vec![0; len]
    }
    #[inline(always)]
    fn pack_memo(q: u16, exit: Self) -> u32 {
        ((q as u32) << 16) | exit as u32
    }
    #[inline(always)]
    fn unpack_memo(word: u32) -> (u16, Self) {
        ((word >> 16) as u16, word as u16)
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
        packed.first_sym().0 < sym_id && packed.word1 >= 2
    } else {
        packed.word0 < sym_id && packed.word1 < sym_id
    };
    if ok {
        Ok(())
    } else {
        Err(topological_violation(rule_idx))
    }
}

/// Cache the first nonzero entry state of each rule directly. Most KMP lookups use the
/// same entry state (for example, the initial space of a C identifier pattern). Only
/// additional states and nonzero counts need hash entries. The zero-filled dense cache
/// costs two cells per rule, with physical pages allocated only where it is written.
/// Small evaluations keep a sparse cache; promote only once memo traffic can amortize
/// the dense table. This avoids increasing memory for rare-pattern and document queries.
struct CountMemo<C: PackedCell, const ADAPTIVE: bool = true> {
    first: Vec<C::MemoCell>,
    counts: FxHashMap<u32, u64>,
    additional: FxHashMap<u64, (C, u64)>,
    num_rules: usize,
    promote_at: usize,
}

impl<C: PackedCell, const ADAPTIVE: bool> CountMemo<C, ADAPTIVE> {
    fn new(num_rules: usize) -> Self {
        Self {
            first: Vec::new(),
            counts: FxHashMap::default(),
            additional: FxHashMap::default(),
            num_rules,
            promote_at: (num_rules / 32).max(4096),
        }
    }

    #[inline]
    fn get(&self, sym: SymbolId, q: u16) -> Option<(C, u64)> {
        if !ADAPTIVE || self.first.is_empty() {
            return self
                .additional
                .get(&(((sym.0 as u64) << 16) | q as u64))
                .copied();
        }
        let (entry, exit) = C::unpack_memo(self.first[sym.rule_index()]);
        if entry == q {
            let count = if exit.emitted() {
                self.counts[&sym.0]
            } else {
                0
            };
            Some((exit, count))
        } else if entry == 0 {
            None
        } else {
            self.additional
                .get(&(((sym.0 as u64) << 16) | q as u64))
                .copied()
        }
    }

    #[inline]
    fn insert(&mut self, sym: SymbolId, q: u16, value: (C, u64)) {
        if !ADAPTIVE || self.first.is_empty() {
            self.additional
                .insert(((sym.0 as u64) << 16) | q as u64, value);
            if ADAPTIVE && self.additional.len() >= self.promote_at {
                self.first = C::memo_table(self.num_rules);
                // Prefer the lowest queried state, independent of hash iteration order.
                // For KMP this keeps the common first-byte prefix in the direct cache.
                for (&key, &value) in &self.additional {
                    let sym = SymbolId((key >> 16) as u32);
                    let q = key as u16;
                    let entry = &mut self.first[sym.rule_index()];
                    let (old_q, _) = C::unpack_memo(*entry);
                    if old_q == 0 || q < old_q {
                        *entry = C::pack_memo(q, value.0);
                        if value.1 > 0 {
                            self.counts.insert(sym.0, value.1);
                        } else {
                            self.counts.remove(&sym.0);
                        }
                    }
                }
                // Retain other states in place instead of building a second large hash map.
                // A many-state literal can have numerous entries for very few rules.
                let first = &self.first;
                self.additional.retain(|key, _| {
                    C::unpack_memo(first[((key >> 16) as usize) - 256]).0 != *key as u16
                });
                if self.additional.len() < self.additional.capacity() / 4 {
                    self.additional.shrink_to_fit();
                }
            }
            return;
        }
        self.insert_dense(sym, q, value);
    }

    #[inline]
    fn insert_dense(&mut self, sym: SymbolId, q: u16, value: (C, u64)) {
        let entry = &mut self.first[sym.rule_index()];
        let (old_q, old_exit) = C::unpack_memo(*entry);
        if old_q == 0 || q <= old_q {
            if old_q != 0 && old_q != q {
                let count = if old_exit.emitted() {
                    self.counts[&sym.0]
                } else {
                    0
                };
                self.additional
                    .insert(((sym.0 as u64) << 16) | old_q as u64, (old_exit, count));
            }
            *entry = C::pack_memo(q, value.0);
            if value.1 > 0 {
                self.counts.insert(sym.0, value.1);
            } else if old_exit.emitted() {
                self.counts.remove(&sym.0);
            }
        } else {
            self.additional
                .insert(((sym.0 as u64) << 16) | q as u64, value);
        }
    }
}

/// Zero-copy evaluator of a `MealyTransducer` over the on-disk packed rule table.
struct PackedEval<'a, C: PackedCell> {
    rules_bytes: &'a [u8],
    /// `[q * 256 + b]` -> packed exit cell for terminal byte `b` entered in state `q`.
    terminal_packed: Vec<C>,
    /// `[sym]` -> packed exit cell for symbol `sym` entered in state 0.
    table: Vec<C>,
    /// Sorted reachable rule indices for a query restricted to one of many documents.
    selected: Option<Vec<usize>>,
}

impl<'a, C: PackedCell> PackedEval<'a, C> {
    fn new(
        archive: &'a MappedArchive,
        transducer: &MealyTransducer,
        root: Option<SymbolId>,
    ) -> Result<Self> {
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
        let selected = if archive.roots.len() > 1 {
            root.map(|root| archive.reachable_rules(root)).transpose()?
        } else {
            None
        };
        Ok(Self {
            rules_bytes: archive.rules_bytes(),
            terminal_packed,
            table,
            selected,
        })
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
        let selected = self.selected.take();
        if let Some(indices) = &selected {
            for &idx in indices {
                self.build_line_rule(idx, PackedRuleNode::read_at(rules_bytes, idx), memo)?;
            }
        } else {
            // Preserve the sequential whole-archive loop: checking the selection and slicing
            // by an arbitrary index on every rule adds measurable overhead at 150M rules.
            for (idx, chunk) in rules_bytes.chunks_exact(PACKED_RULE_SIZE).enumerate() {
                self.build_line_rule(
                    idx,
                    PackedRuleNode::from_bytes(chunk.try_into().unwrap()),
                    memo,
                )?;
            }
        }
        self.selected = selected;
        Ok(())
    }

    #[inline(always)]
    fn build_line_rule(
        &mut self,
        idx: usize,
        packed: PackedRuleNode,
        memo: &mut FxHashMap<u64, C>,
    ) -> Result<()> {
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
        if count == 0 {
            return C::from_state(q);
        }
        let first = self.eval_sym_state(child, q, memo);
        if count == 1 || first.state() == q {
            return first;
        }
        let (end, emitted) = advance_run(
            count - 1,
            first.state(),
            self.terminal_packed.len() / 256,
            |state| {
                let v = self.eval_sym_state(child, state, memo);
                (v.state(), v.emitted() as u64)
            },
        );
        C::from_state(end) | first.emit_bit() | if emitted > 0 { C::EMIT_FLAG } else { C::ZERO }
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
    fn build_count_table<const ADAPTIVE: bool>(&mut self) -> Result<FxHashMap<u32, u64>> {
        let rules_bytes = self.rules_bytes;
        let mut emit0_counts: FxHashMap<u32, u64> = FxHashMap::default();
        let mut memo = CountMemo::<C, ADAPTIVE>::new(rules_bytes.len() / PACKED_RULE_SIZE);

        let selected = self.selected.take();
        if let Some(indices) = &selected {
            for &idx in indices {
                self.build_count_rule(
                    idx,
                    PackedRuleNode::read_at(rules_bytes, idx),
                    &mut emit0_counts,
                    &mut memo,
                )?;
            }
        } else {
            for (idx, chunk) in rules_bytes.chunks_exact(PACKED_RULE_SIZE).enumerate() {
                self.build_count_rule(
                    idx,
                    PackedRuleNode::from_bytes(chunk.try_into().unwrap()),
                    &mut emit0_counts,
                    &mut memo,
                )?;
            }
        }
        self.selected = selected;
        Ok(emit0_counts)
    }

    #[inline(always)]
    fn build_count_rule<const ADAPTIVE: bool>(
        &mut self,
        idx: usize,
        packed: PackedRuleNode,
        emit0_counts: &mut FxHashMap<u32, u64>,
        memo: &mut CountMemo<C, ADAPTIVE>,
    ) -> Result<()> {
        check_topological(idx, packed)?;
        let (cell, count) = if !packed.is_run() {
            let (left, right) = (SymbolId(packed.word0), SymbolId(packed.word1));
            let l_val = self.table_at(left);
            let lc = Self::emit0_count(left, l_val, emit0_counts);
            if l_val.state() == 0 {
                let r_val = self.table_at(right);
                (
                    r_val | l_val,
                    lc + Self::emit0_count(right, r_val, emit0_counts),
                )
            } else {
                let (r_val, rc) =
                    self.eval_sym_count_state(right, l_val.state(), emit0_counts, memo);
                (r_val | l_val.emit_bit(), lc + rc)
            }
        } else {
            self.eval_run_count_state(
                packed.first_sym(),
                packed.word1 as u64,
                0,
                emit0_counts,
                memo,
            )
        };
        self.set_table(idx, cell);
        if cell.emitted() {
            emit0_counts.insert(SymbolId::from_rule_index(idx).0, count);
        }
        Ok(())
    }

    fn eval_sym_count_state<const ADAPTIVE: bool>(
        &self,
        sym: SymbolId,
        q: u16,
        emit0_counts: &FxHashMap<u32, u64>,
        memo: &mut CountMemo<C, ADAPTIVE>,
    ) -> (C, u64) {
        if q == 0 {
            let v = self.table_at(sym);
            return (v, Self::emit0_count(sym, v, emit0_counts));
        }
        if let Some(b) = sym.as_byte() {
            let v = self.terminal_packed[(q as usize) * 256 + (b as usize)];
            return (v, v.emitted() as u64);
        }
        if let Some(cached) = memo.get(sym, q) {
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
        memo.insert(sym, q, res);
        res
    }

    fn eval_run_count_state<const ADAPTIVE: bool>(
        &self,
        child: SymbolId,
        count: u64,
        q: u16,
        emit0_counts: &FxHashMap<u32, u64>,
        memo: &mut CountMemo<C, ADAPTIVE>,
    ) -> (C, u64) {
        if count == 0 {
            return (C::from_state(q), 0);
        }
        let (first, count_first) = self.eval_sym_count_state(child, q, emit0_counts, memo);
        if count == 1 || first.state() == q {
            return (first, count_first.saturating_mul(count));
        }
        let (end, total) = advance_run(
            count - 1,
            first.state(),
            self.terminal_packed.len() / 256,
            |state| {
                let (v, c) = self.eval_sym_count_state(child, state, emit0_counts, memo);
                (v.state(), c)
            },
        );
        (
            C::from_state(end) | first.emit_bit() | if total > 0 { C::EMIT_FLAG } else { C::ZERO },
            total.saturating_add(count_first),
        )
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
            .saturating_add(transducer.eof_emit[root_val.state() as usize])
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
            self.walk_run_offsets(walk, child, packed.word1 as u64, q, base)?;
        }
        Ok(v.state())
    }

    /// Treat repetitions as a virtual balanced tree, pruning whole non-emitting spans.
    fn walk_run_offsets(
        &self,
        walk: &mut OffsetWalk<'_, C>,
        child: SymbolId,
        count: u64,
        q: u16,
        base: u64,
    ) -> Result<u16> {
        if count == 1 {
            return self.walk_emitted_offsets(walk, child, q, base);
        }
        let (v, _) = self.eval_run_count_state(child, count, q, walk.emit0_counts, &mut walk.memo);
        if v.emitted() && walk.out.len() < walk.limit {
            let left_count = count / 2;
            let mid = self.walk_run_offsets(walk, child, left_count, q, base)?;
            if walk.out.len() < walk.limit {
                let child_len = walk.archive.sym_len(child, &mut walk.meta)?;
                self.walk_run_offsets(
                    walk,
                    child,
                    count - left_count,
                    mid,
                    base + child_len * left_count,
                )?;
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
                let start = rev_buf.len();
                if append_rev_until_nl(self.rules_bytes, sib_sym, &mut rev_buf) {
                    break 'siblings;
                }
                crate::grammar::repeat_tail(&mut rev_buf, start, sib_count);
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
            self.walk_run_lines(child, count, q, limit, memo, left_siblings, out_lines);
        }
        q_out
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_run_lines(
        &self,
        child: SymbolId,
        count: u64,
        q: u16,
        limit: usize,
        memo: &mut FxHashMap<u64, C>,
        left_siblings: &mut Vec<(SymbolId, u64)>,
        out_lines: &mut Vec<String>,
    ) -> u16 {
        if count == 1 {
            return self.walk_emitted_lines(child, q, limit, memo, left_siblings, out_lines);
        }
        let v = self.eval_run_state(child, count, q, memo);
        if v.emitted() && out_lines.len() < limit {
            let left_count = count / 2;
            let mid =
                self.walk_run_lines(child, left_count, q, limit, memo, left_siblings, out_lines);
            if out_lines.len() < limit {
                left_siblings.push((child, left_count));
                self.walk_run_lines(
                    child,
                    count - left_count,
                    mid,
                    limit,
                    memo,
                    left_siblings,
                    out_lines,
                );
                left_siblings.pop();
            }
        }
        v.state()
    }
}

/// Mutable state of an emission-offset walk (see `PackedEval::walk_emitted_offsets`).
struct OffsetWalk<'b, C: PackedCell> {
    archive: &'b MappedArchive,
    meta: MappedMeta,
    emit0_counts: &'b FxHashMap<u32, u64>,
    memo: CountMemo<C>,
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
        let start = rev_buf.len();
        if append_rev_until_nl(rules_bytes, child, rev_buf) {
            return true;
        }
        crate::grammar::repeat_tail(rev_buf, start, packed.word1 as u64);
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
    fn match_counts(&self, pattern: &str, roots: &[&RootEntry]) -> Result<Vec<u64>> {
        exact_match_counts(
            pattern,
            roots,
            |transducer| {
                let symbols: Vec<_> = roots.iter().map(|root| root.root_symbol).collect();
                self.count_emissions::<false>(transducer, &symbols, pattern)
            },
            |root, bytes| self.decompress_root_into(root, bytes),
        )
    }

    /// Evaluates `transducer` over the whole rule table and returns the total emission count of
    /// each requested root (in order), picking the narrowest packed cell that fits the state count.
    pub(crate) fn count_emissions<const ADAPTIVE: bool>(
        &self,
        transducer: &MealyTransducer,
        roots: &[Option<SymbolId>],
        pattern: &str,
    ) -> Result<Vec<u64>> {
        fn run<C: PackedCell, const ADAPTIVE: bool>(
            archive: &MappedArchive,
            transducer: &MealyTransducer,
            roots: &[Option<SymbolId>],
        ) -> Result<Vec<u64>> {
            let selected = if roots.len() == 1 { roots[0] } else { None };
            let mut eval = PackedEval::<C>::new(archive, transducer, selected)?;
            let emit0_counts = eval.build_count_table::<ADAPTIVE>()?;
            Ok(roots
                .iter()
                .map(|r| {
                    r.map_or(
                        transducer.eof_emit[transducer.start_state as usize],
                        |sym| eval.root_count(transducer, sym, &emit0_counts),
                    )
                })
                .collect())
        }
        match transducer.num_states {
            n if n <= <u8 as PackedCell>::MAX_STATES => {
                run::<u8, ADAPTIVE>(self, transducer, roots)
            }
            n if n <= <u16 as PackedCell>::MAX_STATES => {
                run::<u16, ADAPTIVE>(self, transducer, roots)
            }
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
            let mut eval = PackedEval::<C>::new(archive, transducer, Some(root))?;
            let emit0_counts = eval.build_count_table::<true>()?;
            let total = eval.root_count(transducer, root, &emit0_counts);
            let limit = limit.min(usize::try_from(total).unwrap_or(usize::MAX));
            let mut walk = OffsetWalk {
                archive,
                meta: archive.navigation_meta()?,
                emit0_counts: &emit0_counts,
                memo: CountMemo::<C>::new(archive.num_rules),
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
            let selected = if docs.len() == 1 {
                Some(docs[0].1)
            } else {
                None
            };
            let mut eval = PackedEval::<C>::new(archive, transducer, selected)?;
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
        let transducer = compile_line_grep_transducer(pattern)?;
        let Some(sym) = root.root_symbol else {
            return Ok(Vec::new());
        };
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
        if mode == GrepMode::MatchCount {
            return Ok(self.match_counts(pattern, &[root])?[0]);
        }
        let transducer = compile_line_grep_transducer(pattern)?;
        let counts = self.count_emissions::<false>(&transducer, &[root.root_symbol], pattern)?;
        Ok(counts[0])
    }

    pub fn grep_all_docs(&self, pattern: &str, mode: GrepMode) -> Result<Vec<(String, u64)>> {
        if mode == GrepMode::MatchCount {
            let roots: Vec<_> = self.roots.iter().collect();
            let counts = self.match_counts(pattern, &roots)?;
            return Ok(roots
                .into_iter()
                .zip(counts)
                .map(|(root, count)| (root.name.clone(), count))
                .collect());
        }
        let transducer = compile_line_grep_transducer(pattern)?;
        let roots: Vec<Option<SymbolId>> = self.roots.iter().map(|r| r.root_symbol).collect();
        let counts = self.count_emissions::<false>(&transducer, &roots, pattern)?;
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

    #[test]
    fn promoted_count_memo_preserves_states_and_full_width_counts() {
        fn check<C: PackedCell>() {
            let mut memo = CountMemo::<C>::new(512);
            memo.promote_at = 8;
            let mut reference = FxHashMap::default();
            for i in 0..10_000u64 {
                let sym = SymbolId::from_rule_index(((i * 37) % 512) as usize);
                let q = 1 + (i % (C::MAX_STATES as u64 - 1)) as u16;
                let key = ((sym.0 as u64) << 16) | q as u64;
                assert!(memo.get(sym, q) == reference.get(&key).copied());
                if memo.get(sym, q).is_some() {
                    continue;
                }
                let count = if i % 7 == 0 { u64::MAX - i } else { 0 };
                let mut cell = C::from_state((i % C::MAX_STATES as u64) as u16);
                if count > 0 {
                    cell = cell | C::EMIT_FLAG;
                }
                let value = (cell, count);
                memo.insert(sym, q, value);
                reference.insert(key, value);
            }
            assert!(!memo.first.is_empty());
            for (key, value) in reference {
                let got = memo.get(SymbolId((key >> 16) as u32), key as u16).unwrap();
                assert!(got == value);
            }
        }
        check::<u8>();
        check::<u16>();
    }

    #[test]
    fn packed_walkers_skip_nonemitting_cycles_after_a_match() {
        let mut dag = GrammarDag::new();
        let root = dag.intern_run(SymbolId::from_byte(b'\n'), 3_000_000_000);
        dag.roots.push(crate::grammar::RootEntry {
            name: "cycle".into(),
            root_symbol: Some(root),
            byte_len: dag.sym_len(root),
            kr_hash: dag.sym_hash(root),
        });
        let file = tempfile::NamedTempFile::new().unwrap();
        dag.save_to_path(file.path()).unwrap();
        let mapped = MappedArchive::open(file.path()).unwrap();
        let mut transducer = MealyTransducer {
            num_states: 3,
            start_state: 0,
            byte_next: vec![0; 3 * 256],
            byte_emit: vec![0; 3 * 256],
            eof_emit: vec![0; 3],
        };
        transducer.byte_next[b'\n' as usize] = 1;
        transducer.byte_emit[b'\n' as usize] = 1;
        transducer.byte_next[256 + b'\n' as usize] = 2;
        transducer.byte_next[512 + b'\n' as usize] = 1;
        assert_eq!(
            mapped
                .locate_emissions(&transducer, root, 10, "cycle")
                .unwrap(),
            (1, vec![0])
        );
        assert_eq!(
            mapped
                .count_emissions::<false>(&transducer, &[Some(root)], "cycle")
                .unwrap(),
            [1]
        );
        let mut eval = PackedEval::<u8>::new(&mapped, &transducer, Some(root)).unwrap();
        let mut memo = FxHashMap::default();
        eval.build_line_table(&mut memo).unwrap();
        assert_eq!(
            eval.collect_root_lines(&transducer, root, 10, &mut memo, &mut Vec::new()),
            [""]
        );
    }

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
