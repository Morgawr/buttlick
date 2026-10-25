use crate::error::{ButtlickError, Result};
use crate::grammar::{RuleKind, RuleNode, SymbolId};
use crate::hash::checksum64;

pub const BTLK_MAGIC_PREFIX: &[u8; 4] = b"BTLK";
pub const BTLK_VERSION_V1: u16 = 1;
pub const BTLK_HEADER_SIZE: usize = 64;
/// Compact 8-byte on-disk rule representation (8 rules per 64-byte cache line!).
/// All derived metadata (`byte_len`, `height`, `first_byte`, `last_byte`) is reconstructed
/// in a single linear topological pass on load.
pub const PACKED_RULE_SIZE: usize = 8;

pub const FLAG_LINE_ANCHORED_LCP: u64 = 1 << 0;

/// 64-byte fixed file header for `.btlk` v1 archives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BtlkHeader {
    pub version: u16,
    pub flags: u64,
    pub num_roots: u64,
    pub num_rules: u64,
    pub roots_offset: u64,
    pub rules_offset: u64,
    pub total_uncompressed_bytes: u64,
    pub header_checksum: u64,
}

impl BtlkHeader {
    pub fn to_bytes(&self) -> [u8; BTLK_HEADER_SIZE] {
        let mut buf = [0u8; BTLK_HEADER_SIZE];
        buf[0..4].copy_from_slice(BTLK_MAGIC_PREFIX);
        buf[4] = 0;
        buf[5..7].copy_from_slice(&self.version.to_le_bytes());
        buf[7] = 0;

        buf[8..16].copy_from_slice(&self.flags.to_le_bytes());
        buf[16..24].copy_from_slice(&self.num_roots.to_le_bytes());
        buf[24..32].copy_from_slice(&self.num_rules.to_le_bytes());
        buf[32..40].copy_from_slice(&self.roots_offset.to_le_bytes());
        buf[40..48].copy_from_slice(&self.rules_offset.to_le_bytes());
        buf[48..56].copy_from_slice(&self.total_uncompressed_bytes.to_le_bytes());

        let csum = checksum64(&buf[0..56]);
        buf[56..64].copy_from_slice(&csum.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < BTLK_HEADER_SIZE {
            return Err(ButtlickError::CorruptedFormat(format!(
                "File too small for header: {} bytes",
                buf.len()
            )));
        }
        if &buf[0..4] != BTLK_MAGIC_PREFIX || buf[4] != 0 || buf[7] != 0 {
            return Err(ButtlickError::InvalidMagic);
        }
        let version = u16::from_le_bytes([buf[5], buf[6]]);
        if version != BTLK_VERSION_V1 {
            return Err(ButtlickError::UnsupportedVersion(version));
        }
        let expected_csum = checksum64(&buf[0..56]);
        let actual_csum = u64::from_le_bytes(buf[56..64].try_into().unwrap());
        if expected_csum != actual_csum {
            return Err(ButtlickError::ChecksumMismatch {
                section: "header",
                expected: expected_csum,
                actual: actual_csum,
            });
        }

        Ok(Self {
            version,
            flags: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            num_roots: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            num_rules: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            roots_offset: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            rules_offset: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            total_uncompressed_bytes: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
            header_checksum: actual_csum,
        })
    }
}

/// 8-byte packed representation of a non-terminal rule on disk:
/// - `word0`: Bit 31 is `0` for `Pair` (`left = word0`), `1` for `Run` (`child = word0 & 0x7FFF_FFFF`).
/// - `word1`: `right.0` (if `Pair`) or `count as u32` (if `Run`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedRuleNode {
    pub word0: u32,
    pub word1: u32,
}

impl PackedRuleNode {
    pub const RUN_TAG_BIT: u32 = 0x8000_0000;

    #[inline(always)]
    pub fn from_rule_node(node: &RuleNode) -> Self {
        match node.kind {
            RuleKind::Pair { left, right } => Self {
                word0: left.0,
                word1: right.0,
            },
            RuleKind::Run { child, count } => {
                debug_assert!(
                    count <= u32::MAX as u64,
                    "Run count {count} does not fit the on-disk u32 field"
                );
                Self {
                    word0: child.0 | Self::RUN_TAG_BIT,
                    word1: count as u32,
                }
            }
        }
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; PACKED_RULE_SIZE] {
        let mut out = [0u8; PACKED_RULE_SIZE];
        out[0..4].copy_from_slice(&self.word0.to_le_bytes());
        out[4..8].copy_from_slice(&self.word1.to_le_bytes());
        out
    }

    #[inline(always)]
    pub fn from_bytes(buf: &[u8; PACKED_RULE_SIZE]) -> Self {
        Self {
            word0: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            word1: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
        }
    }

    /// Reads the packed rule at `rule_idx` from a raw on-disk rule table.
    #[inline(always)]
    pub fn read_at(rules_bytes: &[u8], rule_idx: usize) -> Self {
        let off = rule_idx * PACKED_RULE_SIZE;
        Self::from_bytes(rules_bytes[off..off + PACKED_RULE_SIZE].try_into().unwrap())
    }

    #[inline(always)]
    pub const fn is_run(&self) -> bool {
        self.word0 & Self::RUN_TAG_BIT != 0
    }

    /// The `left` symbol of a `Pair`, or the `child` symbol of a `Run`.
    #[inline(always)]
    pub const fn first_sym(&self) -> SymbolId {
        SymbolId(self.word0 & !Self::RUN_TAG_BIT)
    }

    #[inline(always)]
    pub fn decode_kind(&self) -> RuleKind {
        if self.word0 & Self::RUN_TAG_BIT == 0 {
            RuleKind::Pair {
                left: SymbolId(self.word0),
                right: SymbolId(self.word1),
            }
        } else {
            RuleKind::Run {
                child: SymbolId(self.word0 & !Self::RUN_TAG_BIT),
                count: self.word1 as u64,
            }
        }
    }
}
