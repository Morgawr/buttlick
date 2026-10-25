use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::format::mapped::MappedMeta;
use crate::format::MappedArchive;
use crate::grammar::{GrammarDag, RuleKind, SymbolId};

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

    /// Associative composition $(v_1, p_1) \odot (v_2, p_2) = (v_1 \cdot p_2 + v_2, \; p_1 \cdot p_2)$.
    #[inline(always)]
    pub const fn combine(self, rhs: Self) -> Self {
        Self {
            value: self.value * rhs.pow10 + rhs.value,
            pow10: self.pow10 * rhs.pow10,
        }
    }
}

/// Scalar commutative monoid for numerical record aggregations (`COUNT`, `SUM`, `MIN`, `MAX`, `AVG`).
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
            count: self.count + other.count,
            sum: self.sum + other.sum,
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
            count: self.count * k,
            sum: self.sum * (k as i128),
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

/// Parses an integer byte slice using the Affine Base-10 Place-Value Monoid.
#[inline]
pub fn parse_int_affine(mut bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() {
        return None;
    }
    let mut sign: i128 = 1;
    if bytes[0] == b'-' {
        sign = -1;
        bytes = &bytes[1..];
    } else if bytes[0] == b'+' {
        bytes = &bytes[1..];
    }
    if bytes.is_empty() {
        return None;
    }
    let mut acc = AffineDigitMonoid::identity();
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.combine(AffineDigitMonoid::from_digit(b));
    }
    let signed = sign * acc.value;
    i64::try_from(signed).ok()
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
    /// Appends bytes `[start, end)` of `sym`'s expansion to `out`.
    fn append_range(
        &mut self,
        sym: SymbolId,
        start: u64,
        end: u64,
        out: &mut Vec<u8>,
    ) -> Result<()>;
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
    fn append_range(
        &mut self,
        sym: SymbolId,
        start: u64,
        end: u64,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        if start < end {
            self.0.extract_slice_symbol(sym, start, end - start, out);
        }
        Ok(())
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
    let mut seam = Vec::with_capacity(256);

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
                        src.append_range(left, l.last_nl + 1, l_len, &mut seam)?;
                        src.append_range(right, 0, r.first_nl, &mut seam)?;
                        let seam_agg = eval_single_line(&seam, query);
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
                    src.append_range(child, c.last_nl + 1, c_len, &mut seam)?;
                    src.append_range(child, 0, c.first_nl, &mut seam)?;
                    let seam_agg = eval_single_line(&seam, query);
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
    let mut line = Vec::new();
    Ok(match slot_of(root, &slots) {
        // A single (unterminated) line spanning the whole document.
        NO_SPAN => {
            src.append_range(root, 0, root_len, &mut line)?;
            eval_single_line(&line, query)
        }
        slot => {
            let s = spans[slot as usize - 1];
            src.append_range(root, 0, s.first_nl, &mut line)?;
            let first = eval_single_line(&line, query);
            let last = if s.last_nl + 1 < root_len {
                line.clear();
                src.append_range(root, s.last_nl + 1, root_len, &mut line)?;
                eval_single_line(&line, query)
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
    fn append_range(
        &mut self,
        sym: SymbolId,
        start: u64,
        end: u64,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        self.archive
            .extract_range_into(sym, start, end, out, &mut self.meta)
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
        let d45 = d4.combine(d5);
        assert_eq!(
            d45,
            AffineDigitMonoid {
                value: 45,
                pow10: 100
            }
        );
        let d145 = d1.combine(d45);
        assert_eq!(
            d145,
            AffineDigitMonoid {
                value: 145,
                pow10: 1000
            }
        );
        // Associativity check: (d1 * d4) * d5 == d1 * (d4 * d5)
        assert_eq!(d1.combine(d4).combine(d5), d1.combine(d4.combine(d5)));
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
