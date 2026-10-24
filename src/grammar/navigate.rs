use crate::error::{ButtlickError, Result};
use crate::grammar::{GrammarDag, RuleKind, SymbolId};
use crate::hash::{combine_hashes, repeat_hash_and_pow};

impl GrammarDag {
    /// O(log N) random access to the single byte at `offset` within `sym`.
    /// Panics if `offset >= self.sym_len(sym)`.
    pub fn byte_at_symbol(&self, mut sym: SymbolId, mut offset: u64) -> u8 {
        debug_assert!(offset < self.sym_len(sym));
        loop {
            if let Some(b) = sym.as_byte() {
                debug_assert_eq!(offset, 0);
                return b;
            }
            let node = self.rule(sym);
            if offset == 0 {
                return node.first_byte;
            }
            if offset + 1 == node.byte_len {
                return node.last_byte;
            }
            match node.kind {
                RuleKind::Pair { left, right } => {
                    let left_len = self.sym_len(left);
                    if offset < left_len {
                        sym = left;
                    } else {
                        offset -= left_len;
                        sym = right;
                    }
                }
                RuleKind::Run { child, .. } => {
                    let child_len = self.sym_len(child);
                    offset %= child_len;
                    sym = child;
                }
            }
        }
    }

    /// O(log N) random access to a single byte in a named document.
    pub fn byte_at(&self, doc_name: Option<&str>, offset: u64) -> Result<u8> {
        let root = self.find_root(doc_name)?;
        if offset >= root.byte_len {
            return Err(ButtlickError::OutOfBounds {
                offset,
                len: 1,
                total: root.byte_len,
            });
        }
        let sym = root.root_symbol.unwrap();
        Ok(self.byte_at_symbol(sym, offset))
    }

    /// Decomposes the byte interval `[start, end)` within `sym` into at most `2 * height`
    /// canonical `(SymbolId, repeat_count)` pieces in O(log N) time.
    pub fn decompose_range(
        &self,
        sym: SymbolId,
        start: u64,
        end: u64,
        out: &mut Vec<(SymbolId, u64)>,
    ) {
        if start >= end {
            return;
        }
        let total_len = self.sym_len(sym);
        debug_assert!(end <= total_len);

        if start == 0 && end == total_len {
            Self::push_piece(out, sym, 1);
            return;
        }

        let node = self.rule(sym);
        match node.kind {
            RuleKind::Pair { left, right } => {
                let left_len = self.sym_len(left);
                if start < left_len {
                    self.decompose_range(left, start, end.min(left_len), out);
                }
                if end > left_len {
                    self.decompose_range(
                        right,
                        start.saturating_sub(left_len),
                        end - left_len,
                        out,
                    );
                }
            }
            RuleKind::Run { child, .. } => {
                let c_len = self.sym_len(child);
                let first_idx = start / c_len;
                let first_rem = start % c_len;
                let last_idx = (end - 1) / c_len;
                let last_rem = (end - 1) % c_len + 1;

                if first_idx == last_idx {
                    self.decompose_range(child, first_rem, last_rem, out);
                } else {
                    let full_start = if first_rem > 0 {
                        self.decompose_range(child, first_rem, c_len, out);
                        first_idx + 1
                    } else {
                        first_idx
                    };

                    let full_end = if last_rem == c_len {
                        last_idx + 1
                    } else {
                        last_idx
                    };

                    if full_end > full_start {
                        Self::push_piece(out, child, full_end - full_start);
                    }

                    if last_rem < c_len {
                        self.decompose_range(child, 0, last_rem, out);
                    }
                }
            }
        }
    }

    #[inline]
    fn push_piece(out: &mut Vec<(SymbolId, u64)>, sym: SymbolId, count: u64) {
        if count == 0 {
            return;
        }
        if let Some(last) = out.last_mut() {
            if last.0 == sym {
                last.1 += count;
                return;
            }
        }
        out.push((sym, count));
    }

    /// Extracts the byte slice `[start, start + len)` from `sym` into `out` in O(log N + len) time.
    pub fn extract_slice_symbol(&self, sym: SymbolId, start: u64, len: u64, out: &mut Vec<u8>) {
        if len == 0 {
            return;
        }
        out.reserve(len as usize);
        let mut pieces = Vec::with_capacity(64);
        self.decompose_range(sym, start, start + len, &mut pieces);
        for (piece_sym, repeat_count) in pieces {
            let start_pos = out.len();
            self.decompress_symbol_into(piece_sym, out);
            let piece_len = out.len() - start_pos;
            if repeat_count > 1 && piece_len > 0 {
                let mut copied = 1u64;
                while copied < repeat_count {
                    let to_copy = copied.min(repeat_count - copied);
                    let copy_bytes = (to_copy as usize) * piece_len;
                    out.extend_from_within(start_pos..start_pos + copy_bytes);
                    copied += to_copy;
                }
            }
        }
    }

    /// Extracts the byte slice `[start, start + len)` from a named document in O(log N + len) time.
    pub fn extract_slice(&self, doc_name: Option<&str>, start: u64, len: u64) -> Result<Vec<u8>> {
        let root = self.find_root(doc_name)?;
        if start.saturating_add(len) > root.byte_len {
            return Err(ButtlickError::OutOfBounds {
                offset: start,
                len,
                total: root.byte_len,
            });
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        let sym = root.root_symbol.unwrap();
        let mut out = Vec::with_capacity(len as usize);
        self.extract_slice_symbol(sym, start, len, &mut out);
        Ok(out)
    }

    /// Computes the exact Karp-Rabin hash of the substring `[start, start + len)` inside `sym`
    /// in O(log N) time without decompressing the substring.
    pub fn range_hash_symbol(&self, sym: SymbolId, start: u64, len: u64) -> u64 {
        if len == 0 {
            return 0;
        }
        let mut pieces = Vec::with_capacity(64);
        self.decompose_range(sym, start, start + len, &mut pieces);
        let mut acc_hash = 0u64;
        for (piece_sym, repeat_count) in pieces {
            let (p_hash, p_pow) = if repeat_count == 1 {
                (self.sym_hash(piece_sym), self.sym_pow(piece_sym))
            } else {
                repeat_hash_and_pow(
                    self.sym_hash(piece_sym),
                    self.sym_pow(piece_sym),
                    repeat_count,
                )
            };
            acc_hash = combine_hashes(acc_hash, p_hash, p_pow);
        }
        acc_hash
    }

    /// Computes the exact Karp-Rabin hash of `[start, start + len)` in a named document in O(log N) time.
    pub fn range_hash(&self, doc_name: Option<&str>, start: u64, len: u64) -> Result<u64> {
        let root = self.find_root(doc_name)?;
        if start.saturating_add(len) > root.byte_len {
            return Err(ButtlickError::OutOfBounds {
                offset: start,
                len,
                total: root.byte_len,
            });
        }
        if len == 0 {
            return Ok(0);
        }
        let sym = root.root_symbol.unwrap();
        Ok(self.range_hash_symbol(sym, start, len))
    }

    /// O(log N) substring equality check between `[pos1, pos1 + len)` and `[pos2, pos2 + len)`
    /// inside a named document.
    pub fn substring_eq(
        &self,
        doc_name: Option<&str>,
        pos1: u64,
        pos2: u64,
        len: u64,
    ) -> Result<bool> {
        let root = self.find_root(doc_name)?;
        if pos1.saturating_add(len) > root.byte_len {
            return Err(ButtlickError::OutOfBounds {
                offset: pos1,
                len,
                total: root.byte_len,
            });
        }
        if pos2.saturating_add(len) > root.byte_len {
            return Err(ButtlickError::OutOfBounds {
                offset: pos2,
                len,
                total: root.byte_len,
            });
        }
        if len == 0 || pos1 == pos2 {
            return Ok(true);
        }
        let sym = root.root_symbol.unwrap();
        // Fast boundary byte filter before O(log N) range hash
        if self.byte_at_symbol(sym, pos1) != self.byte_at_symbol(sym, pos2) {
            return Ok(false);
        }
        if len > 1
            && self.byte_at_symbol(sym, pos1 + len - 1) != self.byte_at_symbol(sym, pos2 + len - 1)
        {
            return Ok(false);
        }
        let h1 = self.range_hash_symbol(sym, pos1, len);
        let h2 = self.range_hash_symbol(sym, pos2, len);
        Ok(h1 == h2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::raw_slice_hash;

    #[test]
    fn test_navigation_slicing_and_range_hashing() {
        let mut raw = Vec::new();
        for i in 0..500 {
            raw.extend_from_slice(format!("block-{:04}-AAAABBBBCCCC\n", i % 17).as_bytes());
        }
        let dag = GrammarDag::from_bytes(&raw);

        // Verify byte_at across the entire file
        for (idx, &b) in raw.iter().enumerate().step_by(7) {
            assert_eq!(dag.byte_at(None, idx as u64).unwrap(), b);
        }

        // Verify slices and range hashes for various spans
        for &(start, len) in &[
            (0usize, 0usize),
            (0, 1),
            (0, 25),
            (13, 100),
            (500, 2500),
            (raw.len() - 50, 50),
            (0, raw.len()),
        ] {
            let slice = dag.extract_slice(None, start as u64, len as u64).unwrap();
            assert_eq!(&slice[..], &raw[start..start + len]);

            let r_hash = dag.range_hash(None, start as u64, len as u64).unwrap();
            assert_eq!(r_hash, raw_slice_hash(&raw[start..start + len]));
        }

        // Verify O(log N) substring_eq on periodic repeats (period = 17 * 24 = 408 bytes)
        let period = 17 * 24;
        assert!(dag.substring_eq(None, 0, period as u64, 1500).unwrap());
        assert!(!dag.substring_eq(None, 0, 1, 1500).unwrap());
    }
}
