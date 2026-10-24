use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::grammar::{GrammarDag, RuleKind};

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

/// Homomorphic summary of a grammar node $X$ for structured line-record aggregation.
#[derive(Clone, Debug)]
enum NodeRecordSummary {
    /// Node expansion contains zero `\n` bytes (pure intra-line fragment).
    NoNewline(Vec<u8>),
    /// Node expansion contains at least one `\n` byte:
    /// `prefix \n [middle complete lines] suffix`
    HasNewline {
        prefix: Vec<u8>,
        middle: AggregateSummary,
        suffix: Vec<u8>,
    },
}

impl NodeRecordSummary {
    #[inline]
    fn from_terminal(b: u8) -> Self {
        if b == b'\n' {
            Self::HasNewline {
                prefix: Vec::new(),
                middle: AggregateSummary::empty(),
                suffix: Vec::new(),
            }
        } else {
            Self::NoNewline(vec![b])
        }
    }

    fn combine(left: &Self, right: &Self, query: &AggregateQuery, seam_buf: &mut Vec<u8>) -> Self {
        match (left, right) {
            (Self::NoNewline(l), Self::NoNewline(r)) => {
                let mut both = Vec::with_capacity(l.len() + r.len());
                both.extend_from_slice(l);
                both.extend_from_slice(r);
                Self::NoNewline(both)
            }
            (
                Self::NoNewline(l),
                Self::HasNewline {
                    prefix: rp,
                    middle: rm,
                    suffix: rs,
                },
            ) => {
                let mut prefix = Vec::with_capacity(l.len() + rp.len());
                prefix.extend_from_slice(l);
                prefix.extend_from_slice(rp);
                Self::HasNewline {
                    prefix,
                    middle: *rm,
                    suffix: rs.clone(),
                }
            }
            (
                Self::HasNewline {
                    prefix: lp,
                    middle: lm,
                    suffix: ls,
                },
                Self::NoNewline(r),
            ) => {
                let mut suffix = Vec::with_capacity(ls.len() + r.len());
                suffix.extend_from_slice(ls);
                suffix.extend_from_slice(r);
                Self::HasNewline {
                    prefix: lp.clone(),
                    middle: *lm,
                    suffix,
                }
            }
            (
                Self::HasNewline {
                    prefix: lp,
                    middle: lm,
                    suffix: ls,
                },
                Self::HasNewline {
                    prefix: rp,
                    middle: rm,
                    suffix: rs,
                },
            ) => {
                seam_buf.clear();
                seam_buf.extend_from_slice(ls);
                seam_buf.extend_from_slice(rp);
                let seam_agg = eval_single_line(seam_buf, query);
                let middle = lm.combine(seam_agg).combine(*rm);
                Self::HasNewline {
                    prefix: lp.clone(),
                    middle,
                    suffix: rs.clone(),
                }
            }
        }
    }

    fn power(&self, k: u64, query: &AggregateQuery, seam_buf: &mut Vec<u8>) -> Self {
        debug_assert!(k >= 1);
        if k == 1 {
            return self.clone();
        }
        match self {
            Self::NoNewline(frag) => Self::NoNewline(frag.repeat(k as usize)),
            Self::HasNewline {
                prefix,
                middle,
                suffix,
            } => {
                seam_buf.clear();
                seam_buf.extend_from_slice(suffix);
                seam_buf.extend_from_slice(prefix);
                let seam_agg = eval_single_line(seam_buf, query);
                let total_middle = middle.scale(k).combine(seam_agg.scale(k - 1));
                Self::HasNewline {
                    prefix: prefix.clone(),
                    middle: total_middle,
                    suffix: suffix.clone(),
                }
            }
        }
    }

    fn finalize_root(&self, query: &AggregateQuery) -> AggregateSummary {
        match self {
            Self::NoNewline(frag) => {
                if frag.is_empty() {
                    AggregateSummary::empty()
                } else {
                    eval_single_line(frag, query)
                }
            }
            Self::HasNewline {
                prefix,
                middle,
                suffix,
            } => {
                let first = eval_single_line(prefix, query);
                let last = if suffix.is_empty() {
                    AggregateSummary::empty()
                } else {
                    eval_single_line(suffix, query)
                };
                first.combine(*middle).combine(last)
            }
        }
    }
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
        if let Some(b) = root_sym.as_byte() {
            return Ok(NodeRecordSummary::from_terminal(b).finalize_root(query));
        }

        let mut summaries: Vec<NodeRecordSummary> = Vec::with_capacity(self.rules.len());
        let mut seam_buf = Vec::with_capacity(256);

        for node in &self.rules {
            let sum = match node.kind {
                RuleKind::Pair { left, right } => match (left.as_byte(), right.as_byte()) {
                    (Some(lb), Some(rb)) => {
                        let ls = NodeRecordSummary::from_terminal(lb);
                        let rs = NodeRecordSummary::from_terminal(rb);
                        NodeRecordSummary::combine(&ls, &rs, query, &mut seam_buf)
                    }
                    (Some(lb), None) => {
                        let ls = NodeRecordSummary::from_terminal(lb);
                        let rs = &summaries[right.rule_index()];
                        NodeRecordSummary::combine(&ls, rs, query, &mut seam_buf)
                    }
                    (None, Some(rb)) => {
                        let ls = &summaries[left.rule_index()];
                        let rs = NodeRecordSummary::from_terminal(rb);
                        NodeRecordSummary::combine(ls, &rs, query, &mut seam_buf)
                    }
                    (None, None) => {
                        let ls = &summaries[left.rule_index()];
                        let rs = &summaries[right.rule_index()];
                        NodeRecordSummary::combine(ls, rs, query, &mut seam_buf)
                    }
                },
                RuleKind::Run { child, count } => {
                    if let Some(b) = child.as_byte() {
                        NodeRecordSummary::from_terminal(b).power(count, query, &mut seam_buf)
                    } else {
                        summaries[child.rule_index()].power(count, query, &mut seam_buf)
                    }
                }
            };
            summaries.push(sum);
        }

        Ok(summaries[root_sym.rule_index()].finalize_root(query))
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
        assert_eq!(d45, AffineDigitMonoid { value: 45, pow10: 100 });
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
