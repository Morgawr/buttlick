//! Random-access navigation (`slice`, `eq`, `decompress`) evaluated directly on the
//! memory-mapped packed rule table, without decoding the whole archive into a `GrammarDag`.
//!
//! Derived per-rule metadata (byte lengths, Karp-Rabin hashes) is computed lazily and memoized in
//! zero-initialized tables that the OS maps on demand, so only the pages belonging to symbols that
//! are actually visited become resident.

use crate::error::{ButtlickError, Result};
use crate::format::header::{PackedRuleNode, PACKED_RULE_SIZE};
use crate::format::MappedArchive;
use crate::grammar::{repeat_tail, RootEntry, SymbolId};
use crate::hash::{byte_hash, checksum64, combine_hashes, mod_mul, repeat_hash_and_pow, HASH_BASE};

/// Lazily memoized per-rule metadata for navigating a `MappedArchive`.
pub struct MappedMeta {
    /// Expanded byte length per rule (`0` = not computed yet; real rules are always >= 2 bytes).
    lens: Vec<u64>,
    /// Karp-Rabin hash per rule (valid only where `pows[idx] != 0`).
    hashes: Vec<u64>,
    /// `HASH_BASE^len mod P` per rule (`0` = not computed yet; never 0 for a real rule).
    pows: Vec<u64>,
}

#[cold]
fn corrupt_rule(sym: SymbolId) -> ButtlickError {
    ButtlickError::CorruptedFormat(format!("Invalid rule reference at symbol {}", sym.0))
}

impl MappedArchive {
    /// Creates an empty lazily-populated metadata cache for this archive.
    pub fn new_meta(&self) -> MappedMeta {
        MappedMeta {
            lens: vec![0u64; self.num_rules],
            hashes: Vec::new(),
            pows: Vec::new(),
        }
    }

    /// Metadata cache for navigating a document. For single-document archives (where essentially
    /// every rule is reachable from the root) all lengths are computed upfront in one sequential
    /// pass, which is far more cache-friendly than lazy recursion over the whole DAG.
    pub fn navigation_meta(&self) -> Result<MappedMeta> {
        let mut meta = self.new_meta();
        if self.roots.len() == 1 {
            self.prefill_lengths(&mut meta)?;
        }
        Ok(meta)
    }

    fn prefill_lengths(&self, meta: &mut MappedMeta) -> Result<()> {
        let lens = &mut meta.lens;
        let len_of = |sym: SymbolId, lens: &[u64]| -> u64 {
            if sym.is_terminal() {
                1
            } else {
                lens[sym.rule_index()]
            }
        };
        for (idx, chunk) in self
            .rules_bytes()
            .chunks_exact(PACKED_RULE_SIZE)
            .enumerate()
        {
            let p = PackedRuleNode::from_bytes(chunk.try_into().unwrap());
            let sym = SymbolId::from_rule_index(idx);
            let len = if p.is_run() {
                if p.first_sym().0 >= sym.0 || p.word1 < 2 {
                    return Err(corrupt_rule(sym));
                }
                len_of(p.first_sym(), lens).checked_mul(p.word1 as u64)
            } else {
                if p.word0 >= sym.0 || p.word1 >= sym.0 {
                    return Err(corrupt_rule(sym));
                }
                len_of(SymbolId(p.word0), lens).checked_add(len_of(SymbolId(p.word1), lens))
            };
            lens[idx] = len.ok_or_else(|| corrupt_rule(sym))?;
        }
        Ok(())
    }

    /// Reads rule `sym`, validating that it exists and only references strictly smaller symbols
    /// (which also guarantees that every recursion below terminates).
    #[inline]
    pub(crate) fn checked_rule(&self, sym: SymbolId) -> Result<PackedRuleNode> {
        let idx = sym.rule_index();
        if idx >= self.num_rules {
            return Err(corrupt_rule(sym));
        }
        let p = PackedRuleNode::read_at(self.rules_bytes(), idx);
        let ok = if p.is_run() {
            p.first_sym().0 < sym.0 && p.word1 >= 2
        } else {
            p.word0 < sym.0 && p.word1 < sym.0
        };
        if ok {
            Ok(p)
        } else {
            Err(corrupt_rule(sym))
        }
    }

    /// Expanded byte length of `sym` (memoized).
    pub fn sym_len(&self, sym: SymbolId, meta: &mut MappedMeta) -> Result<u64> {
        if sym.is_terminal() {
            return Ok(1);
        }
        let idx = sym.rule_index();
        match meta.lens.get(idx) {
            Some(&len) if len != 0 => return Ok(len),
            Some(_) => {}
            None => return Err(corrupt_rule(sym)),
        }
        let p = self.checked_rule(sym)?;
        let len = if p.is_run() {
            let c_len = self.sym_len(p.first_sym(), meta)?;
            c_len.checked_mul(p.word1 as u64)
        } else {
            let l_len = self.sym_len(SymbolId(p.word0), meta)?;
            let r_len = self.sym_len(SymbolId(p.word1), meta)?;
            l_len.checked_add(r_len)
        }
        .ok_or_else(|| corrupt_rule(sym))?;
        meta.lens[idx] = len;
        Ok(len)
    }

    /// Appends the full expansion of `sym` to `out`.
    pub fn expand_into(&self, sym: SymbolId, out: &mut Vec<u8>) -> Result<()> {
        if let Some(b) = sym.as_byte() {
            out.push(b);
            return Ok(());
        }
        let p = self.checked_rule(sym)?;
        if p.is_run() {
            let start = out.len();
            self.expand_into(p.first_sym(), out)?;
            repeat_tail(out, start, p.word1 as u64);
        } else {
            self.expand_into(SymbolId(p.word0), out)?;
            self.expand_into(SymbolId(p.word1), out)?;
        }
        Ok(())
    }

    /// Appends bytes `[start, end)` of `sym` to `out` in O(height + (end - start)) time
    /// (plus the one-time cost of computing the lengths of the visited subtrees).
    pub(crate) fn extract_range_into(
        &self,
        sym: SymbolId,
        start: u64,
        end: u64,
        out: &mut Vec<u8>,
        meta: &mut MappedMeta,
    ) -> Result<()> {
        if start >= end {
            return Ok(());
        }
        let total = self.sym_len(sym, meta)?;
        if end > total {
            return Err(corrupt_rule(sym));
        }
        if start == 0 && end == total {
            return self.expand_into(sym, out);
        }
        // `sym` cannot be a terminal here: a terminal only has the full range [0, 1).
        let p = self.checked_rule(sym)?;
        if p.is_run() {
            let child = p.first_sym();
            let c_len = self.sym_len(child, meta)?;
            let first_idx = start / c_len;
            let last_idx = (end - 1) / c_len;
            let first_rem = start % c_len;
            let last_rem = (end - 1) % c_len + 1;
            if first_idx == last_idx {
                return self.extract_range_into(child, first_rem, last_rem, out, meta);
            }
            self.extract_range_into(child, first_rem, c_len, out, meta)?;
            let full_copies = last_idx - first_idx - 1;
            if full_copies > 0 {
                let piece_start = out.len();
                self.expand_into(child, out)?;
                repeat_tail(out, piece_start, full_copies);
            }
            self.extract_range_into(child, 0, last_rem, out, meta)
        } else {
            let (left, right) = (SymbolId(p.word0), SymbolId(p.word1));
            let l_len = self.sym_len(left, meta)?;
            if start < l_len {
                self.extract_range_into(left, start, end.min(l_len), out, meta)?;
            }
            if end > l_len {
                self.extract_range_into(
                    right,
                    start.saturating_sub(l_len),
                    end - l_len,
                    out,
                    meta,
                )?;
            }
            Ok(())
        }
    }

    /// `(kr_hash, HASH_BASE^len)` of the full expansion of `sym` (memoized).
    fn sym_hash_pow(&self, sym: SymbolId, meta: &mut MappedMeta) -> Result<(u64, u64)> {
        if let Some(b) = sym.as_byte() {
            return Ok((byte_hash(b), HASH_BASE));
        }
        if meta.pows.is_empty() {
            meta.hashes = vec![0u64; self.num_rules];
            meta.pows = vec![0u64; self.num_rules];
        }
        let idx = sym.rule_index();
        match meta.pows.get(idx) {
            Some(&pow) if pow != 0 => return Ok((meta.hashes[idx], pow)),
            Some(_) => {}
            None => return Err(corrupt_rule(sym)),
        }
        let p = self.checked_rule(sym)?;
        let res = if p.is_run() {
            let (c_hash, c_pow) = self.sym_hash_pow(p.first_sym(), meta)?;
            repeat_hash_and_pow(c_hash, c_pow, p.word1 as u64)
        } else {
            let (l_hash, l_pow) = self.sym_hash_pow(SymbolId(p.word0), meta)?;
            let (r_hash, r_pow) = self.sym_hash_pow(SymbolId(p.word1), meta)?;
            (combine_hashes(l_hash, r_hash, r_pow), mod_mul(l_pow, r_pow))
        };
        meta.hashes[idx] = res.0;
        meta.pows[idx] = res.1;
        Ok(res)
    }

    /// `(kr_hash, HASH_BASE^len)` of bytes `[start, end)` of `sym` (requires `start < end`).
    fn range_hash_pow(
        &self,
        sym: SymbolId,
        start: u64,
        end: u64,
        meta: &mut MappedMeta,
    ) -> Result<(u64, u64)> {
        debug_assert!(start < end);
        let total = self.sym_len(sym, meta)?;
        if end > total {
            return Err(corrupt_rule(sym));
        }
        if start == 0 && end == total {
            return self.sym_hash_pow(sym, meta);
        }
        let p = self.checked_rule(sym)?;
        if p.is_run() {
            let child = p.first_sym();
            let c_len = self.sym_len(child, meta)?;
            let first_idx = start / c_len;
            let last_idx = (end - 1) / c_len;
            let first_rem = start % c_len;
            let last_rem = (end - 1) % c_len + 1;
            if first_idx == last_idx {
                return self.range_hash_pow(child, first_rem, last_rem, meta);
            }
            let head = self.range_hash_pow(child, first_rem, c_len, meta)?;
            let mut acc = head;
            let full_copies = last_idx - first_idx - 1;
            if full_copies > 0 {
                let (c_hash, c_pow) = self.sym_hash_pow(child, meta)?;
                let (m_hash, m_pow) = repeat_hash_and_pow(c_hash, c_pow, full_copies);
                acc = concat_hash_pow(acc, (m_hash, m_pow));
            }
            let tail = self.range_hash_pow(child, 0, last_rem, meta)?;
            Ok(concat_hash_pow(acc, tail))
        } else {
            let (left, right) = (SymbolId(p.word0), SymbolId(p.word1));
            let l_len = self.sym_len(left, meta)?;
            if end <= l_len {
                self.range_hash_pow(left, start, end, meta)
            } else if start >= l_len {
                self.range_hash_pow(right, start - l_len, end - l_len, meta)
            } else {
                let l = self.range_hash_pow(left, start, l_len, meta)?;
                let r = self.range_hash_pow(right, 0, end - l_len, meta)?;
                Ok(concat_hash_pow(l, r))
            }
        }
    }

    /// Extracts the byte slice `[start, start + len)` from a named document.
    pub fn extract_slice(&self, doc_name: Option<&str>, start: u64, len: u64) -> Result<Vec<u8>> {
        let root = self.find_root(doc_name)?;
        check_range(root, start, len)?;
        let Some(sym) = root.root_symbol.filter(|_| len > 0) else {
            return Ok(Vec::new());
        };
        let mut meta = self.navigation_meta()?;
        let mut out = Vec::with_capacity(len as usize);
        self.extract_range_into(sym, start, start + len, &mut out, &mut meta)?;
        Ok(out)
    }

    /// Substring equality between `[pos1, pos1 + len)` and `[pos2, pos2 + len)` of a named document,
    /// via boundary-byte filtering followed by Karp-Rabin range hashes.
    pub fn substring_eq(
        &self,
        doc_name: Option<&str>,
        pos1: u64,
        pos2: u64,
        len: u64,
    ) -> Result<bool> {
        let root = self.find_root(doc_name)?;
        check_range(root, pos1, len)?;
        check_range(root, pos2, len)?;
        if len == 0 || pos1 == pos2 {
            return Ok(true);
        }
        let sym = root.root_symbol.ok_or_else(|| {
            ButtlickError::CorruptedFormat("Empty root with non-zero length".into())
        })?;
        let mut meta = self.navigation_meta()?;
        let byte_at = |pos: u64, meta: &mut MappedMeta| -> Result<u8> {
            let mut b = Vec::with_capacity(1);
            self.extract_range_into(sym, pos, pos + 1, &mut b, meta)?;
            Ok(b[0])
        };
        if byte_at(pos1, &mut meta)? != byte_at(pos2, &mut meta)? {
            return Ok(false);
        }
        if len > 1 && byte_at(pos1 + len - 1, &mut meta)? != byte_at(pos2 + len - 1, &mut meta)? {
            return Ok(false);
        }
        let h1 = self.range_hash_pow(sym, pos1, pos1 + len, &mut meta)?.0;
        let h2 = self.range_hash_pow(sym, pos2, pos2 + len, &mut meta)?.0;
        Ok(h1 == h2)
    }

    /// Appends the full contents of `root` to `out`.
    pub fn decompress_root_into(&self, root: &RootEntry, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        if let Some(sym) = root.root_symbol {
            out.reserve(root.byte_len as usize);
            self.expand_into(sym, out)?;
        }
        if (out.len() - start) as u64 != root.byte_len {
            return Err(ButtlickError::CorruptedFormat(format!(
                "Root '{}' metadata mismatch with root symbol",
                root.name
            )));
        }
        Ok(())
    }

    /// Decompresses a named document (or the first document if `doc_name` is `None`).
    pub fn decompress(&self, doc_name: Option<&str>) -> Result<Vec<u8>> {
        let root = self.find_root(doc_name)?;
        let mut out = Vec::new();
        self.decompress_root_into(root, &mut out)?;
        Ok(out)
    }

    /// Verifies the whole-file footer checksum (one sequential pass over the mapping).
    pub fn verify_checksum(&self) -> Result<()> {
        let bytes = &self.mmap[..];
        let payload_end = bytes.len() - 8;
        let expected = checksum64(&bytes[..payload_end]);
        let actual = u64::from_le_bytes(bytes[payload_end..].try_into().unwrap());
        if expected != actual {
            return Err(ButtlickError::ChecksumMismatch {
                section: "footer",
                expected,
                actual,
            });
        }
        Ok(())
    }
}

/// Bounds check shared by slice / equality queries.
fn check_range(root: &RootEntry, start: u64, len: u64) -> Result<()> {
    if start.saturating_add(len) > root.byte_len {
        return Err(ButtlickError::OutOfBounds {
            offset: start,
            len,
            total: root.byte_len,
        });
    }
    Ok(())
}

#[inline]
fn concat_hash_pow(left: (u64, u64), right: (u64, u64)) -> (u64, u64) {
    (
        combine_hashes(left.0, right.0, right.1),
        mod_mul(left.1, right.1),
    )
}
