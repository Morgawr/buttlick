pub mod header;
pub mod mapped;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use memmap2::Mmap;
use rayon::prelude::*;

use crate::error::{ButtlickError, Result};
use crate::format::header::{
    BtlkHeader, PackedRuleNode, BTLK_HEADER_SIZE, BTLK_VERSION_V1, FLAG_LINE_ANCHORED_LCP,
    PACKED_RULE_SIZE,
};
use crate::grammar::{find_root_in, GrammarDag, RootEntry, RuleKind, RuleNode, SymbolId};
use crate::hash::checksum64;

/// Streaming checksum writer that computes `checksum64` on the fly without buffering the entire file in RAM.
struct ChecksumWriter<W: Write> {
    inner: W,
    acc: u64,
    tail: [u8; 8],
    tail_len: usize,
}

impl<W: Write> ChecksumWriter<W> {
    fn new(inner: W, total_payload_len: usize) -> Self {
        let acc = 0xcbf29ce484222325 ^ (total_payload_len as u64).wrapping_mul(0x9e3779b97f4a7c15);
        Self {
            inner,
            acc,
            tail: [0u8; 8],
            tail_len: 0,
        }
    }

    #[inline(always)]
    fn mix_word(&mut self, word: u64) {
        self.acc ^= word;
        self.acc = (self.acc ^ (self.acc >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        self.acc = (self.acc ^ (self.acc >> 27)).wrapping_mul(0x94d049bb133111eb);
        self.acc ^= self.acc >> 31;
    }

    fn write_payload(&mut self, mut buf: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(buf)?;
        if self.tail_len > 0 {
            let needed = (8 - self.tail_len).min(buf.len());
            self.tail[self.tail_len..self.tail_len + needed].copy_from_slice(&buf[..needed]);
            self.tail_len += needed;
            buf = &buf[needed..];
            if self.tail_len == 8 {
                let word = u64::from_le_bytes(self.tail);
                self.mix_word(word);
                self.tail_len = 0;
            }
        }
        let mut chunks = buf.chunks_exact(8);
        for chunk in &mut chunks {
            let word = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
            self.mix_word(word);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.tail[..rem.len()].copy_from_slice(rem);
            self.tail_len = rem.len();
        }
        Ok(())
    }

    fn finish_and_write_footer(mut self) -> std::io::Result<W> {
        if self.tail_len > 0 {
            let mut last = 0u64;
            for i in 0..self.tail_len {
                last |= (self.tail[i] as u64) << (i * 8);
            }
            self.mix_word(last);
            self.tail_len = 0;
        }
        self.inner.write_all(&self.acc.to_le_bytes())?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

/// Validated byte layout of a `.btlk` v1 archive (header + parsed root table + rule table bounds).
struct BtlkLayout {
    roots: Vec<RootEntry>,
    rules_offset: usize,
    rules_end: usize,
    num_rules: usize,
}

impl BtlkLayout {
    /// Parses and validates the header, section offsets, and root table of a `.btlk` v1 archive.
    /// Does NOT verify the footer checksum (callers decide whether to pay for a full-file scan).
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BTLK_HEADER_SIZE + 8 {
            return Err(ButtlickError::CorruptedFormat(format!(
                "File too small: {} bytes",
                bytes.len()
            )));
        }

        let header = BtlkHeader::from_bytes(&bytes[0..BTLK_HEADER_SIZE])?;
        let payload_end = bytes.len() - 8;
        let roots_offset = header.roots_offset as usize;
        let rules_offset = header.rules_offset as usize;
        let num_rules = header.num_rules as usize;
        let expected_rules_end = rules_offset
            .checked_add(num_rules.checked_mul(PACKED_RULE_SIZE).ok_or_else(|| {
                ButtlickError::CorruptedFormat("Rule table size overflow".into())
            })?)
            .ok_or_else(|| ButtlickError::CorruptedFormat("Rule offset overflow".into()))?;

        if roots_offset != BTLK_HEADER_SIZE
            || rules_offset < roots_offset
            || !rules_offset.is_multiple_of(8)
            || expected_rules_end != payload_end
        {
            return Err(ButtlickError::CorruptedFormat(
                "Invalid section offsets in .btlk header".into(),
            ));
        }

        // Symbols must reference either a terminal byte or an existing rule.
        let max_sym = SymbolId::from_rule_index(num_rules).0 as u64;
        let mut cursor = roots_offset;
        // Each root entry occupies at least 32 bytes, so cap the reservation by the section size
        // to avoid huge allocations from a corrupted `num_roots` field.
        let max_roots = (rules_offset - roots_offset) / 32;
        let mut roots = Vec::with_capacity((header.num_roots as usize).min(max_roots));
        for _ in 0..header.num_roots {
            if cursor + 32 > rules_offset {
                return Err(ButtlickError::CorruptedFormat(
                    "Truncated root entry header".into(),
                ));
            }
            let name_len =
                u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
            let has_symbol = bytes[cursor + 4];
            let sym_raw = u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());
            let byte_len = u64::from_le_bytes(bytes[cursor + 16..cursor + 24].try_into().unwrap());
            let kr_hash = u64::from_le_bytes(bytes[cursor + 24..cursor + 32].try_into().unwrap());
            cursor += 32;

            if name_len > rules_offset - cursor {
                return Err(ButtlickError::CorruptedFormat(
                    "Truncated root entry name".into(),
                ));
            }
            let name = std::str::from_utf8(&bytes[cursor..cursor + name_len])
                .map_err(|e| {
                    ButtlickError::CorruptedFormat(format!("Invalid UTF-8 root name: {e}"))
                })?
                .to_string();
            cursor += name_len;

            let root_symbol = if has_symbol == 0 {
                None
            } else {
                if sym_raw as u64 >= max_sym {
                    return Err(ButtlickError::CorruptedFormat(format!(
                        "Root '{name}' references out-of-range symbol {sym_raw}"
                    )));
                }
                Some(SymbolId(sym_raw))
            };
            roots.push(RootEntry {
                name,
                root_symbol,
                byte_len,
                kr_hash,
            });
        }

        Ok(Self {
            roots,
            rules_offset,
            rules_end: expected_rules_end,
            num_rules,
        })
    }
}

impl GrammarDag {
    fn btlk_header(&self, roots_section_len: usize) -> (BtlkHeader, usize) {
        let roots_offset = BTLK_HEADER_SIZE as u64;
        let rules_offset = roots_offset + (roots_section_len as u64);
        let payload_size = (rules_offset as usize) + self.rules.len() * PACKED_RULE_SIZE;
        let header = BtlkHeader {
            version: BTLK_VERSION_V1,
            flags: FLAG_LINE_ANCHORED_LCP,
            num_roots: self.roots.len() as u64,
            num_rules: self.rules.len() as u64,
            roots_offset,
            rules_offset,
            total_uncompressed_bytes: self.total_uncompressed_bytes(),
            header_checksum: 0,
        };
        (header, payload_size)
    }

    fn encode_roots_section(&self) -> Vec<u8> {
        let mut roots_buf = Vec::with_capacity(self.roots.len() * 48);
        for root in &self.roots {
            let name_bytes = root.name.as_bytes();
            let name_len = name_bytes.len() as u32;
            let (has_symbol, sym_raw) = match root.root_symbol {
                Some(sym) => (1u8, sym.0),
                None => (0u8, 0u32),
            };
            roots_buf.extend_from_slice(&name_len.to_le_bytes());
            roots_buf.push(has_symbol);
            roots_buf.extend_from_slice(&[0u8; 3]);
            roots_buf.extend_from_slice(&sym_raw.to_le_bytes());
            roots_buf.extend_from_slice(&0u32.to_le_bytes());
            roots_buf.extend_from_slice(&root.byte_len.to_le_bytes());
            roots_buf.extend_from_slice(&root.kr_hash.to_le_bytes());
            roots_buf.extend_from_slice(name_bytes);
        }
        while !roots_buf.len().is_multiple_of(8) {
            roots_buf.push(0);
        }
        roots_buf
    }

    /// Serializes this `GrammarDag` into a `.btlk` v1 byte vector in memory.
    pub fn to_btlk_bytes(&self) -> Vec<u8> {
        let roots_len: usize = self.roots.iter().map(|r| 32 + r.name.len()).sum();
        let capacity =
            BTLK_HEADER_SIZE + roots_len.next_multiple_of(8) + self.rules.len() * PACKED_RULE_SIZE + 8;
        // Writing into a `Vec<u8>` is infallible.
        self.write_btlk(Vec::with_capacity(capacity))
            .expect("in-memory write cannot fail")
    }

    /// Streams this `GrammarDag` directly to a `.btlk` file on disk using an 8 MB `BufWriter`
    /// with zero duplicate full-archive memory allocation.
    pub fn save_to_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let file = File::create(path)?;
        let buf_writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
        let _ = self.write_btlk(buf_writer)?;
        Ok(())
    }

    /// Serializes the archive (header, root table, packed rule table, footer checksum) into `inner`.
    fn write_btlk<W: Write>(&self, inner: W) -> std::io::Result<W> {
        let roots_buf = self.encode_roots_section();
        let (header, payload_size) = self.btlk_header(roots_buf.len());

        let mut writer = ChecksumWriter::new(inner, payload_size);
        writer.write_payload(&header.to_bytes())?;
        writer.write_payload(&roots_buf)?;
        const BATCH_RULES: usize = 2_097_152;
        let mut chunk_buf = vec![0u8; self.rules.len().min(BATCH_RULES) * PACKED_RULE_SIZE];
        for rules_batch in self.rules.chunks(BATCH_RULES) {
            let byte_len = rules_batch.len() * PACKED_RULE_SIZE;
            let dst_slice = &mut chunk_buf[..byte_len];
            let pack = |dst_chunk: &mut [u8], node_chunk: &[RuleNode]| {
                for (dst, node) in dst_chunk
                    .chunks_exact_mut(PACKED_RULE_SIZE)
                    .zip(node_chunk.iter())
                {
                    dst.copy_from_slice(&PackedRuleNode::from_rule_node(node).to_bytes());
                }
            };
            if rules_batch.len() >= 16_384 {
                dst_slice
                    .par_chunks_mut(4096 * PACKED_RULE_SIZE)
                    .zip(rules_batch.par_chunks(4096))
                    .for_each(|(dst_chunk, node_chunk)| pack(dst_chunk, node_chunk));
            } else {
                pack(dst_slice, rules_batch);
            }
            writer.write_payload(dst_slice)?;
        }
        writer.finish_and_write_footer()
    }

    /// Deserializes a `GrammarDag` from a `.btlk` v1 byte slice (or memory-mapped file),
    /// verifying both header and footer checksums.
    pub fn from_btlk_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BTLK_HEADER_SIZE + 8 {
            return Err(ButtlickError::CorruptedFormat(format!(
                "File too small: {} bytes",
                bytes.len()
            )));
        }

        // Validate the header checksum first, then the whole-file footer checksum, so that
        // corruption is reported as a checksum mismatch before any structural parsing.
        BtlkHeader::from_bytes(&bytes[0..BTLK_HEADER_SIZE])?;
        let payload_end = bytes.len() - 8;
        let expected_footer = checksum64(&bytes[0..payload_end]);
        let actual_footer = u64::from_le_bytes(bytes[payload_end..].try_into().unwrap());
        if expected_footer != actual_footer {
            return Err(ButtlickError::ChecksumMismatch {
                section: "footer",
                expected: expected_footer,
                actual: actual_footer,
            });
        }

        let BtlkLayout {
            roots,
            rules_offset,
            rules_end: expected_rules_end,
            num_rules,
        } = BtlkLayout::parse(bytes)?;

        // Parse Packed Rule Table Section in topological order
        let mut rules: Vec<RuleNode> = Vec::with_capacity(num_rules);
        let rules_slice = &bytes[rules_offset..expected_rules_end];

        for (idx, chunk) in rules_slice.chunks_exact(PACKED_RULE_SIZE).enumerate() {
            let arr: &[u8; PACKED_RULE_SIZE] = chunk.try_into().unwrap();
            let packed = PackedRuleNode::from_bytes(arr);
            let kind = packed.decode_kind();
            let cur_sym_id = SymbolId::from_rule_index(idx).0;
            let (byte_len, height, first_byte, last_byte) = match kind {
                RuleKind::Pair { left, right } => {
                    if left.0 >= cur_sym_id || right.0 >= cur_sym_id {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Topological ordering violation at rule {idx}"
                        )));
                    }
                    let (l_len, l_h, l_first) = if let Some(b) = left.as_byte() {
                        (1u64, 0u16, b)
                    } else {
                        let ln = &rules[left.rule_index()];
                        (ln.byte_len, ln.height, ln.first_byte)
                    };
                    let (r_len, r_h, r_last) = if let Some(b) = right.as_byte() {
                        (1u64, 0u16, b)
                    } else {
                        let rn = &rules[right.rule_index()];
                        (rn.byte_len, rn.height, rn.last_byte)
                    };
                    let byte_len = l_len.checked_add(r_len).ok_or_else(|| {
                        ButtlickError::CorruptedFormat(format!(
                            "Byte length overflow at rule {idx}"
                        ))
                    })?;
                    (byte_len, l_h.max(r_h).saturating_add(1), l_first, r_last)
                }
                RuleKind::Run { child, count } => {
                    if child.0 >= cur_sym_id || count < 2 {
                        return Err(ButtlickError::CorruptedFormat(format!(
                            "Invalid Run rule at index {idx}"
                        )));
                    }
                    let (c_len, c_h, c_first, c_last) = if let Some(b) = child.as_byte() {
                        (1u64, 0u16, b, b)
                    } else {
                        let cn = &rules[child.rule_index()];
                        (cn.byte_len, cn.height, cn.first_byte, cn.last_byte)
                    };
                    let byte_len = c_len.checked_mul(count).ok_or_else(|| {
                        ButtlickError::CorruptedFormat(format!(
                            "Byte length overflow at rule {idx}"
                        ))
                    })?;
                    (byte_len, c_h.saturating_add(1), c_first, c_last)
                }
            };
            rules.push(RuleNode {
                kind,
                byte_len,
                height,
                first_byte,
                last_byte,
            });
        }

        Ok(Self::from_parts(rules, roots))
    }

    /// Loads a `GrammarDag` from a `.btlk` file on disk using `memmap2::Mmap` for zero-copy OS page mapping.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        Self::from_btlk_bytes(&mmap)
    }
}

/// Zero-copy memory-mapped `.btlk` archive view that evaluates queries directly on the on-disk
/// 8-byte `PackedRuleNode` array without allocating `Vec<RuleNode>`.
pub struct MappedArchive {
    mmap: Mmap,
    pub roots: Vec<RootEntry>,
    rules_offset: usize,
    rules_end: usize,
    pub num_rules: usize,
}

impl MappedArchive {
    /// Memory-maps a `.btlk` archive and parses its root table.
    ///
    /// Unlike [`GrammarDag::load_from_path`], this does not verify the whole-file footer checksum
    /// (that would require touching every page of the archive). Rule-table structure is validated
    /// lazily by the query routines instead.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let BtlkLayout {
            roots,
            rules_offset,
            rules_end,
            num_rules,
        } = BtlkLayout::parse(&mmap)?;

        Ok(Self {
            mmap,
            roots,
            rules_offset,
            rules_end,
            num_rules,
        })
    }

    #[inline(always)]
    pub fn rules_bytes(&self) -> &[u8] {
        &self.mmap[self.rules_offset..self.rules_end]
    }

    pub fn find_root(&self, doc_name: Option<&str>) -> Result<&RootEntry> {
        find_root_in(&self.roots, doc_name)
    }

    /// Fully decodes the archive into an in-memory `GrammarDag` (verifying the footer checksum).
    pub fn load_grammar_dag(&self) -> Result<GrammarDag> {
        GrammarDag::from_btlk_bytes(&self.mmap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_btlk_roundtrip_and_corruption_detection() {
        let mut dag = GrammarDag::new();
        let doc1 = b"2026-10-24 INFO request=1 status=200\n".repeat(500);
        let doc2 = b"2026-10-24 ERROR request=2 status=500\n".repeat(300);
        dag.add_document("access.log", &doc1);
        dag.add_document("error.log", &doc2);
        dag.add_document("empty.log", b"");

        let tmp = NamedTempFile::new().unwrap();
        dag.save_to_path(tmp.path()).unwrap();

        let loaded = GrammarDag::load_from_path(tmp.path()).unwrap();
        loaded.validate_invariants().unwrap();
        assert_eq!(loaded.roots.len(), 3);
        assert_eq!(loaded.rules.len(), dag.rules.len());
        assert_eq!(loaded.decompress(Some("access.log")).unwrap(), doc1);
        assert_eq!(loaded.decompress(Some("error.log")).unwrap(), doc2);
        assert_eq!(loaded.decompress(Some("empty.log")).unwrap(), b"");

        let raw = dag.to_btlk_bytes();

        let mut corrupted_header = raw.clone();
        corrupted_header[10] ^= 1;
        assert!(matches!(
            GrammarDag::from_btlk_bytes(&corrupted_header),
            Err(ButtlickError::ChecksumMismatch {
                section: "header",
                ..
            })
        ));

        let mut corrupted_body = raw.clone();
        let mid = corrupted_body.len() / 2;
        corrupted_body[mid] ^= 1;
        assert!(matches!(
            GrammarDag::from_btlk_bytes(&corrupted_body),
            Err(ButtlickError::ChecksumMismatch {
                section: "footer",
                ..
            })
        ));
    }
}
