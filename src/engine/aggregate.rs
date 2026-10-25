use serde::{Deserialize, Serialize};

use crate::error::{ButtlickError, Result};
use crate::format::mapped::MappedMeta;
use crate::format::MappedArchive;
use crate::grammar::{repeat_tail, GrammarDag, RuleKind, SymbolId};

/// Algebra 3A: The Affine Base-10 Place-Value Monoid over digit fragments.
/// Represents a contiguous ASCII digit sequence $d_1 d_2 \dots d_m$ as $(v, 10^m)$
/// with associative composition $(v_1, p_1) \odot (v_2, p_2) = (v_1 \cdot p_2 + v_2, \; p_1 \cdot p_2)$.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AffineDigitMonoid {
    pub value: i128,
    pub pow10: i128,
}

impl AffineDigitMonoid {
    #[inline(always)]
    pub const fn identity() -> Self {
        Self { value: 0, pow10: 1 }
    }

    #[inline(always)]
    pub const fn from_digit(d: u8) -> Self {
        debug_assert!(d.is_ascii_digit());
        Self {
            value: (d - b'0') as i128,
            pow10: 10,
        }
    }

    /// Checked composition $(v_1, p_1) \odot (v_2, p_2) = (v_1 \cdot p_2 + v_2, \; p_1 \cdot p_2)$.
    /// Returns `None` when either component is outside `i128`.
    #[inline(always)]
    pub fn combine(self, rhs: Self) -> Option<Self> {
        Some(Self {
            value: self.value.checked_mul(rhs.pow10)?.checked_add(rhs.value)?,
            pow10: self.pow10.checked_mul(rhs.pow10)?,
        })
    }
}

/// Scalar summary for numerical record aggregations (`COUNT`, `SUM`, `MIN`, `MAX`, `AVG`).
/// Counts and sums saturate at their integer limits. A valid document with at most
/// `u64::MAX` bytes of `i64` records fits these limits exactly; saturation protects
/// callers composing summaries beyond the representable document size.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateSummary {
    pub count: u64,
    pub sum: i128,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

impl AggregateSummary {
    #[inline]
    pub const fn empty() -> Self {
        Self {
            count: 0,
            sum: 0,
            min: None,
            max: None,
        }
    }

    #[inline]
    pub const fn single(val: i64) -> Self {
        Self {
            count: 1,
            sum: val as i128,
            min: Some(val),
            max: Some(val),
        }
    }

    #[inline]
    pub fn combine(self, other: Self) -> Self {
        if self.count == 0 {
            return other;
        }
        if other.count == 0 {
            return self;
        }
        Self {
            count: self.count.saturating_add(other.count),
            sum: self.sum.saturating_add(other.sum),
            min: match (self.min, other.min) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            max: match (self.max, other.max) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
        }
    }

    /// Scales this aggregate summary across `k` identical repetitions of a block in O(1) time.
    #[inline]
    pub fn scale(self, k: u64) -> Self {
        if k == 0 || self.count == 0 {
            return Self::empty();
        }
        Self {
            count: self.count.saturating_mul(k),
            sum: self.sum.saturating_mul(k as i128),
            min: self.min,
            max: self.max,
        }
    }

    #[inline]
    pub fn avg(&self) -> Option<f64> {
        if self.count == 0 {
            None
        } else {
            Some((self.sum as f64) / (self.count as f64))
        }
    }
}

/// Specification for a structured column aggregation query over CSV/TSV/log streams.
#[derive(Clone, Debug)]
pub struct AggregateQuery {
    pub delimiter: u8,
    pub target_col: usize,
    /// Match either the whole field or the suffix after its first `=`.
    /// Target numeric fields likewise discard an optional `key=` prefix.
    pub filter: Option<(usize, Vec<u8>)>,
}

/// Evaluates a single `\n`-delimited record line against `query`.
/// Supports both plain delimited fields (`200,145`) and `key=value` fields (`status=200 latency=145`).
pub fn eval_single_line(mut line: &[u8], query: &AggregateQuery) -> AggregateSummary {
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    if line.is_empty() {
        return AggregateSummary::empty();
    }

    let max_needed_col = match &query.filter {
        Some((f_col, _)) => query.target_col.max(*f_col),
        None => query.target_col,
    };

    let mut target_slice: Option<&[u8]> = None;
    let mut filter_matched = query.filter.is_none();

    for (col_idx, field) in line.split(|&b| b == query.delimiter).enumerate() {
        if let Some((f_col, ref f_val)) = query.filter {
            if col_idx == f_col {
                if field == f_val.as_slice() {
                    filter_matched = true;
                } else if let Some(eq_pos) = field.iter().position(|&b| b == b'=') {
                    if &field[eq_pos + 1..] == f_val.as_slice() {
                        filter_matched = true;
                    }
                }
            }
        }
        if col_idx == query.target_col {
            target_slice = Some(field);
        }
        if col_idx >= max_needed_col {
            break;
        }
    }

    if !filter_matched {
        return AggregateSummary::empty();
    }

    let Some(mut raw_target) = target_slice else {
        return AggregateSummary::empty();
    };

    // Strip optional `key=` prefix if present
    if let Some(eq_pos) = raw_target.iter().position(|&b| b == b'=') {
        raw_target = &raw_target[eq_pos + 1..];
    }

    // Trim leading/trailing ASCII whitespace
    while let Some(&first) = raw_target.first() {
        if first.is_ascii_whitespace() {
            raw_target = &raw_target[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = raw_target.last() {
        if last.is_ascii_whitespace() {
            raw_target = &raw_target[..raw_target.len() - 1];
        } else {
            break;
        }
    }

    if let Some(val) = parse_int_affine(raw_target) {
        AggregateSummary::single(val)
    } else {
        AggregateSummary::empty()
    }
}

/// Parses a signed ASCII integer. Accumulating negatively admits `i64::MIN` and
/// checking the value (rather than 10^digit_count) preserves arbitrarily many leading zeros.
#[inline]
pub fn parse_int_affine(mut bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() {
        return None;
    }
    let mut negative = false;
    if bytes[0] == b'-' {
        negative = true;
        bytes = &bytes[1..];
    } else if bytes[0] == b'+' {
        bytes = &bytes[1..];
    }
    if bytes.is_empty() {
        return None;
    }
    let mut acc = 0i64;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_sub((b - b'0') as i64)?;
    }
    if negative {
        Some(acc)
    } else {
        acc.checked_neg()
    }
}

/// Homomorphic summary of a grammar node $X$ whose expansion contains at least one `\n`:
/// `prefix \n [middle complete lines] \n suffix`.
///
/// The partial first/last lines are NOT stored: they are byte ranges of $X$'s own expansion
/// (`[0, first_nl)` and `[last_nl + 1, len)`) and are only materialized, straight from the grammar,
/// when two such partial lines meet at a seam. Nodes without any `\n` need no summary at all.
#[derive(Copy, Clone, Debug)]
struct LineSpan {
    /// Offset of the first `\n` in the expansion.
    first_nl: u64,
    /// Offset of the last `\n` in the expansion.
    last_nl: u64,
    /// Aggregate over all complete lines strictly between the first and last `\n`, as an index
    /// into the `middles` table (`0` = empty aggregate, by far the most common case).
    middle: u32,
}

/// Read access to a topologically ordered rule table, as needed by the record aggregation.
pub(crate) trait RuleSource {
    fn num_rules(&self) -> usize;
    fn rule_kind(&mut self, idx: usize) -> Result<RuleKind>;
    fn sym_len(&mut self, sym: SymbolId) -> Result<u64>;
}

/// A query only needs fields through its last target/filter column. Stop materializing a
/// record once that field's delimiter is reached; later fields cannot affect its result.
struct RecordPrefix {
    bytes: Vec<u8>,
    delimiter: u8,
    fields: usize,
    remaining: usize,
}

impl RecordPrefix {
    fn new(query: &AggregateQuery) -> Self {
        let last_col = query
            .filter
            .as_ref()
            .map_or(query.target_col, |(col, _)| query.target_col.max(*col));
        let fields = last_col.saturating_add(1);
        Self {
            bytes: Vec::with_capacity(256),
            delimiter: query.delimiter,
            fields,
            remaining: fields,
        }
    }
    fn clear(&mut self) {
        self.bytes.clear();
        self.remaining = self.fields;
    }
    fn push(&mut self, byte: u8) {
        self.bytes.push(byte);
        if byte == self.delimiter {
            self.remaining -= 1;
        }
    }
}

fn append_record_full<S: RuleSource>(
    src: &mut S,
    sym: SymbolId,
    out: &mut RecordPrefix,
) -> Result<()> {
    if out.remaining == 0 {
        return Ok(());
    }
    if let Some(byte) = sym.as_byte() {
        out.push(byte);
        return Ok(());
    }
    match src.rule_kind(sym.rule_index())? {
        RuleKind::Pair { left, right } => {
            append_record_full(src, left, out)?;
            append_record_full(src, right, out)
        }
        RuleKind::Run { child, count } => append_record_repeats(src, child, count, out),
    }
}

fn append_record_repeats<S: RuleSource>(
    src: &mut S,
    child: SymbolId,
    count: u64,
    out: &mut RecordPrefix,
) -> Result<()> {
    if count == 0 || out.remaining == 0 {
        return Ok(());
    }
    let start = out.bytes.len();
    let remaining = out.remaining;
    append_record_full(src, child, out)?;
    if out.remaining == 0 {
        return Ok(());
    }
    let fields_per_copy = remaining - out.remaining;
    let copies = if fields_per_copy == 0 {
        count - 1
    } else {
        (count - 1).min(((out.remaining - 1) / fields_per_copy) as u64)
    };
    repeat_tail(&mut out.bytes, start, copies + 1);
    out.remaining -= copies as usize * fields_per_copy;
    if copies + 1 < count {
        append_record_full(src, child, out)?;
    }
    Ok(())
}

/// Appends only the useful prefix of `[start, end)`, shared by decoded and mapped sources.
fn append_record_range<S: RuleSource>(
    src: &mut S,
    sym: SymbolId,
    start: u64,
    end: u64,
    out: &mut RecordPrefix,
) -> Result<()> {
    if start >= end || out.remaining == 0 {
        return Ok(());
    }
    let total = src.sym_len(sym)?;
    if end > total {
        return Err(ButtlickError::CorruptedFormat(format!(
            "Record range exceeds symbol {}",
            sym.0
        )));
    }
    if start == 0 && end == total {
        return append_record_full(src, sym, out);
    }
    match src.rule_kind(sym.rule_index())? {
        RuleKind::Pair { left, right } => {
            let left_len = src.sym_len(left)?;
            if start < left_len {
                append_record_range(src, left, start, end.min(left_len), out)?;
            }
            if end > left_len {
                append_record_range(
                    src,
                    right,
                    start.saturating_sub(left_len),
                    end - left_len,
                    out,
                )?;
            }
        }
        RuleKind::Run { child, .. } => {
            let child_len = src.sym_len(child)?;
            let first = start / child_len;
            let last = (end - 1) / child_len;
            if first == last {
                return append_record_range(
                    src,
                    child,
                    start % child_len,
                    (end - 1) % child_len + 1,
                    out,
                );
            }
            append_record_range(src, child, start % child_len, child_len, out)?;
            append_record_repeats(src, child, last - first - 1, out)?;
            append_record_range(src, child, 0, (end - 1) % child_len + 1, out)?;
        }
    }
    Ok(())
}

/// `RuleSource` over a fully decoded `GrammarDag`.
struct DagSource<'a>(&'a GrammarDag);

impl RuleSource for DagSource<'_> {
    fn num_rules(&self) -> usize {
        self.0.rules.len()
    }
    #[inline]
    fn rule_kind(&mut self, idx: usize) -> Result<RuleKind> {
        Ok(self.0.rules[idx].kind)
    }
    #[inline]
    fn sym_len(&mut self, sym: SymbolId) -> Result<u64> {
        Ok(self.0.sym_len(sym))
    }
}

/// Marks every rule reachable from `root` (bitset indexed by rule index).
fn mark_reachable<S: RuleSource>(src: &mut S, root: SymbolId) -> Result<Vec<u64>> {
    let mut bits = vec![0u64; src.num_rules().div_ceil(64)];
    let mut stack = vec![root];
    while let Some(sym) = stack.pop() {
        if sym.is_terminal() {
            continue;
        }
        let idx = sym.rule_index();
        let (word, bit) = (idx / 64, 1u64 << (idx % 64));
        if bits[word] & bit != 0 {
            continue;
        }
        bits[word] |= bit;
        match src.rule_kind(idx)? {
            RuleKind::Pair { left, right } => {
                stack.push(right);
                stack.push(left);
            }
            RuleKind::Run { child, .. } => stack.push(child),
        }
    }
    Ok(bits)
}

/// Evaluates `query` over the document rooted at `root` in a single bottom-up pass over the
/// rules (restricted to the rules reachable from `root` when `restrict_to_reachable` is set).
pub(crate) fn aggregate_root<S: RuleSource>(
    src: &mut S,
    root: SymbolId,
    query: &AggregateQuery,
    restrict_to_reachable: bool,
) -> Result<AggregateSummary> {
    let num_evaluated = if root.is_terminal() {
        0
    } else {
        root.rule_index() + 1
    };
    let reachable = if restrict_to_reachable && num_evaluated > 0 {
        Some(mark_reachable(src, root)?)
    } else {
        None
    };
    // `slots[idx]` = 1 + index into `spans` for rules containing a '\n', `NO_SPAN` otherwise.
    // `spans[0]` is the terminal '\n'; rules whose span equals a child's share the child's slot.
    const NO_SPAN: u32 = 0;
    const NEWLINE_SLOT: u32 = 1;
    let mut slots = vec![NO_SPAN; num_evaluated];
    let mut spans: Vec<LineSpan> = vec![LineSpan {
        first_nl: 0,
        last_nl: 0,
        middle: 0,
    }];
    // `middles[0]` is the empty aggregate.
    let mut middles: Vec<AggregateSummary> = vec![AggregateSummary::empty()];
    let push_middle = |agg: AggregateSummary, middles: &mut Vec<AggregateSummary>| -> u32 {
        if agg.count == 0 {
            0
        } else {
            middles.push(agg);
            (middles.len() - 1) as u32
        }
    };
    let mut seam = RecordPrefix::new(query);

    let slot_of = |sym: SymbolId, slots: &[u32]| -> u32 {
        match sym.as_byte() {
            Some(b'\n') => NEWLINE_SLOT,
            Some(_) => NO_SPAN,
            None => slots[sym.rule_index()],
        }
    };

    for idx in 0..num_evaluated {
        if let Some(bits) = &reachable {
            if bits[idx / 64] & (1u64 << (idx % 64)) == 0 {
                continue;
            }
        }
        let span = match src.rule_kind(idx)? {
            RuleKind::Pair { left, right } => {
                match (slot_of(left, &slots), slot_of(right, &slots)) {
                    (NO_SPAN, NO_SPAN) => None,
                    (l_slot, NO_SPAN) => {
                        // Same span as `left`: share its slot.
                        slots[idx] = l_slot;
                        None
                    }
                    (NO_SPAN, r_slot) => {
                        let r = spans[r_slot as usize - 1];
                        let l_len = src.sym_len(left)?;
                        Some(LineSpan {
                            first_nl: l_len + r.first_nl,
                            last_nl: l_len + r.last_nl,
                            middle: r.middle,
                        })
                    }
                    (l_slot, r_slot) => {
                        let (l, r) = (spans[l_slot as usize - 1], spans[r_slot as usize - 1]);
                        let l_len = src.sym_len(left)?;
                        seam.clear();
                        append_record_range(src, left, l.last_nl + 1, l_len, &mut seam)?;
                        append_record_range(src, right, 0, r.first_nl, &mut seam)?;
                        let seam_agg = eval_single_line(&seam.bytes, query);
                        let middle = middles[l.middle as usize]
                            .combine(seam_agg)
                            .combine(middles[r.middle as usize]);
                        Some(LineSpan {
                            first_nl: l.first_nl,
                            last_nl: l_len + r.last_nl,
                            middle: push_middle(middle, &mut middles),
                        })
                    }
                }
            }
            RuleKind::Run { child, count } => match slot_of(child, &slots) {
                NO_SPAN => None,
                c_slot => {
                    let c = spans[c_slot as usize - 1];
                    let c_len = src.sym_len(child)?;
                    seam.clear();
                    append_record_range(src, child, c.last_nl + 1, c_len, &mut seam)?;
                    append_record_range(src, child, 0, c.first_nl, &mut seam)?;
                    let seam_agg = eval_single_line(&seam.bytes, query);
                    let middle = middles[c.middle as usize]
                        .scale(count)
                        .combine(seam_agg.scale(count - 1));
                    Some(LineSpan {
                        first_nl: c.first_nl,
                        last_nl: (count - 1) * c_len + c.last_nl,
                        middle: push_middle(middle, &mut middles),
                    })
                }
            },
        };
        if let Some(s) = span {
            spans.push(s);
            slots[idx] = spans.len() as u32;
        }
    }

    let root_len = src.sym_len(root)?;
    let mut line = RecordPrefix::new(query);
    Ok(match slot_of(root, &slots) {
        // A single (unterminated) line spanning the whole document.
        NO_SPAN => {
            append_record_range(src, root, 0, root_len, &mut line)?;
            eval_single_line(&line.bytes, query)
        }
        slot => {
            let s = spans[slot as usize - 1];
            append_record_range(src, root, 0, s.first_nl, &mut line)?;
            let first = eval_single_line(&line.bytes, query);
            let last = if s.last_nl + 1 < root_len {
                line.clear();
                append_record_range(src, root, s.last_nl + 1, root_len, &mut line)?;
                eval_single_line(&line.bytes, query)
            } else {
                AggregateSummary::empty()
            };
            first.combine(middles[s.middle as usize]).combine(last)
        }
    })
}

impl GrammarDag {
    /// Evaluates a structured aggregation query (`COUNT`, `SUM`, `MIN`, `MAX`, `AVG`)
    /// directly over the compressed `GrammarDag` without decompressing the file.
    pub fn aggregate_query(
        &self,
        doc_name: Option<&str>,
        query: &AggregateQuery,
    ) -> Result<AggregateSummary> {
        let root = self.find_root(doc_name)?;
        let Some(root_sym) = root.root_symbol else {
            return Ok(AggregateSummary::empty());
        };
        aggregate_root(&mut DagSource(self), root_sym, query, self.roots.len() > 1)
    }
}

/// `RuleSource` evaluated directly on a memory-mapped archive (lengths computed lazily).
struct MappedSource<'a> {
    archive: &'a MappedArchive,
    meta: MappedMeta,
}

impl RuleSource for MappedSource<'_> {
    fn num_rules(&self) -> usize {
        self.archive.num_rules
    }
    #[inline]
    fn rule_kind(&mut self, idx: usize) -> Result<RuleKind> {
        Ok(self
            .archive
            .checked_rule(SymbolId::from_rule_index(idx))?
            .decode_kind())
    }
    #[inline]
    fn sym_len(&mut self, sym: SymbolId) -> Result<u64> {
        self.archive.sym_len(sym, &mut self.meta)
    }
}

impl MappedArchive {
    /// Evaluates a structured aggregation query directly on the memory-mapped archive, visiting
    /// only the rules reachable from the document's root.
    pub fn aggregate_query(
        &self,
        doc_name: Option<&str>,
        query: &AggregateQuery,
    ) -> Result<AggregateSummary> {
        let root = self.find_root(doc_name)?;
        let Some(root_sym) = root.root_symbol else {
            return Ok(AggregateSummary::empty());
        };
        let mut src = MappedSource {
            archive: self,
            meta: self.navigation_meta()?,
        };
        aggregate_root(&mut src, root_sym, query, self.roots.len() > 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_affine_digit_monoid() {
        // "1" (1, 10) combine "45" (45, 100) == (145, 1000)
        let d1 = AffineDigitMonoid::from_digit(b'1');
        let d4 = AffineDigitMonoid::from_digit(b'4');
        let d5 = AffineDigitMonoid::from_digit(b'5');
        let d45 = d4.combine(d5).unwrap();
        assert_eq!(
            d45,
            AffineDigitMonoid {
                value: 45,
                pow10: 100
            }
        );
        let d145 = d1.combine(d45).unwrap();
        assert_eq!(
            d145,
            AffineDigitMonoid {
                value: 145,
                pow10: 1000
            }
        );
        // Associativity check: (d1 * d4) * d5 == d1 * (d4 * d5)
        assert_eq!(
            d1.combine(d4).unwrap().combine(d5),
            d1.combine(d4.combine(d5).unwrap())
        );
    }

    #[test]
    fn integer_overflow_and_leading_zeros() {
        assert_eq!(parse_int_affine(&[b'9'; 50]), None);
        assert_eq!(
            parse_int_affine(format!("{}42", "0".repeat(100)).as_bytes()),
            Some(42)
        );
        assert_eq!(parse_int_affine(b"9223372036854775807"), Some(i64::MAX));
        assert_eq!(parse_int_affine(b"-9223372036854775808"), Some(i64::MIN));
        for bad in [
            "9223372036854775808",
            "-9223372036854775809",
            "",
            "-",
            "+",
            "00x",
        ] {
            assert_eq!(parse_int_affine(bad.as_bytes()), None);
        }
        let huge = AffineDigitMonoid {
            value: i128::MAX,
            pow10: 10,
        };
        assert_eq!(huge.combine(AffineDigitMonoid::from_digit(b'1')), None);
        let query = AggregateQuery {
            delimiter: b',',
            target_col: 0,
            filter: None,
        };
        assert_eq!(
            eval_single_line(&[b'9'; 50], &query),
            AggregateSummary::empty()
        );
    }

    #[test]
    fn test_structured_csv_and_log_aggregation() {
        let mut csv_data = Vec::new();
        let mut expected_200 = AggregateSummary::empty();
        let mut expected_all = AggregateSummary::empty();

        for i in 0..1500i64 {
            let status = if i % 4 == 0 { "500" } else { "200" };
            let latency = if i % 7 == 0 { -(i * 3) } else { 100 + (i % 50) };
            let line = format!("2026-10-24,{status},{latency}\n");
            csv_data.extend_from_slice(line.as_bytes());

            expected_all = expected_all.combine(AggregateSummary::single(latency));
            if status == "200" {
                expected_200 = expected_200.combine(AggregateSummary::single(latency));
            }
        }
        // Add final line without trailing '\n' (Pitfall 6)
        csv_data.extend_from_slice(b"2026-10-24,200,9999");
        expected_all = expected_all.combine(AggregateSummary::single(9999));
        expected_200 = expected_200.combine(AggregateSummary::single(9999));

        let dag = GrammarDag::from_bytes(&csv_data);

        let q_all = AggregateQuery {
            delimiter: b',',
            target_col: 2,
            filter: None,
        };
        assert_eq!(dag.aggregate_query(None, &q_all).unwrap(), expected_all);

        let q_200 = AggregateQuery {
            delimiter: b',',
            target_col: 2,
            filter: Some((1, b"200".to_vec())),
        };
        assert_eq!(dag.aggregate_query(None, &q_200).unwrap(), expected_200);
    }
}
