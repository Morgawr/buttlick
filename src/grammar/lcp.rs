use rayon::prelude::*;
use rustc_hash::FxHashMap;

use crate::error::Result;
use crate::grammar::builder::{RuleInterner, LINE_CACHE_MASK, SEEN_TABLE_MASK};
use crate::grammar::{GrammarDag, RootEntry, RuleKind, RuleNode, SymbolId};
use crate::hash::{checksum64, combine_hashes, mod_pow, raw_slice_hash, HASH_BASE};

/// Target chunk size (256 KB) for parallel L2-cache-resident LCP compression.
const PARALLEL_CHUNK_SIZE: usize = 256 * 1024;

#[inline(always)]
const fn splitmix64_non_zero(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    let val = z ^ (z >> 31);
    if val == 0 {
        1
    } else {
        val
    }
}

#[inline(always)]
const fn terminal_shash(b: u8) -> u64 {
    if b == b'\n' {
        0
    } else {
        splitmix64_non_zero(b as u64)
    }
}

/// A lightweight, thread-local RLSLP DAG produced independently for a partition of chunks on a worker thread.
#[derive(Clone, Debug)]
struct LocalPartitionDag {
    nodes: Vec<RuleNode>,
    roots: Vec<Option<SymbolId>>,
}

/// Fast thread-local LCP compressor that fits inside a single CPU core's L2 cache
/// with zero lock contention, packed 64-bit pair keys, and content-intrinsic landmark hashes.
struct LocalChunkCompressor<'s> {
    seed_rules: &'s [RuleNode],
    seed_interner: Option<&'s RuleInterner>,
    seed_watermark: u32,
    nodes: Vec<RuleNode>,
    pair_map: FxHashMap<u64, SymbolId>,
    run_map: FxHashMap<(SymbolId, u64), SymbolId>,
}

impl<'s> LocalChunkCompressor<'s> {
    fn with_capacity_and_seed(
        est_rules: usize,
        seed_rules: &'s [RuleNode],
        seed_interner: Option<&'s RuleInterner>,
    ) -> Self {
        let mut pair_map = FxHashMap::default();
        pair_map.reserve(est_rules);
        let mut run_map = FxHashMap::default();
        run_map.reserve(est_rules / 8);
        let seed_watermark = SymbolId::from_rule_index(seed_rules.len()).0;
        Self {
            seed_rules,
            seed_interner,
            seed_watermark,
            nodes: Vec::with_capacity(est_rules),
            pair_map,
            run_map,
        }
    }

    #[inline(always)]
    fn landmark_hash(&self, sym: SymbolId) -> u64 {
        if let Some(b) = sym.as_byte() {
            terminal_shash(b)
        } else {
            splitmix64_non_zero(sym.0 as u64)
        }
    }

    #[inline(always)]
    fn sym_meta(&self, sym: SymbolId) -> (u64, u16, u8, u8) {
        if let Some(b) = sym.as_byte() {
            (1, 0, b, b)
        } else {
            let idx = sym.rule_index();
            let s_len = self.seed_rules.len();
            let n = if idx < s_len {
                &self.seed_rules[idx]
            } else {
                &self.nodes[idx - s_len]
            };
            (n.byte_len, n.height, n.first_byte, n.last_byte)
        }
    }

    #[inline(always)]
    fn as_run(&self, sym: SymbolId) -> (SymbolId, u64) {
        if !sym.is_terminal() {
            let idx = sym.rule_index();
            let s_len = self.seed_rules.len();
            let kind = if idx < s_len {
                self.seed_rules[idx].kind
            } else {
                self.nodes[idx - s_len].kind
            };
            if let RuleKind::Run { child, count } = kind {
                return (child, count);
            }
        }
        (sym, 1)
    }

    #[inline]
    fn intern_run(&mut self, child: SymbolId, count: u64) -> SymbolId {
        if count == 1 {
            return child;
        }
        let (base_child, base_count) = self.as_run(child);
        let total_count = base_count * count;
        if base_child.0 < self.seed_watermark {
            if let Some(si) = self.seed_interner {
                if let Some(existing) = si.get_run(base_child, total_count) {
                    return existing;
                }
            }
        }
        if let Some(&existing) = self.run_map.get(&(base_child, total_count)) {
            return existing;
        }
        let (c_len, c_height, first_byte, last_byte) = self.sym_meta(base_child);
        let byte_len = c_len * total_count;
        let height = c_height.saturating_add(1);

        let sym = SymbolId::from_rule_index(self.seed_rules.len() + self.nodes.len());
        self.nodes.push(RuleNode {
            kind: RuleKind::Run {
                child: base_child,
                count: total_count,
            },
            byte_len,
            height,
            first_byte,
            last_byte,
        });
        self.run_map.insert((base_child, total_count), sym);
        sym
    }

    #[inline]
    fn intern_pair(&mut self, left: SymbolId, right: SymbolId) -> SymbolId {
        let (l_base, l_count) = self.as_run(left);
        let (r_base, r_count) = self.as_run(right);
        if l_base == r_base {
            return self.intern_run(l_base, l_count + r_count);
        }
        let (l_len, l_height, first_byte, _) = self.sym_meta(left);
        let (r_len, r_height, _, last_byte) = self.sym_meta(right);
        let byte_len = l_len + r_len;
        if (byte_len <= 16 || (byte_len <= 28 && last_byte != b'\n'))
            && left.0 < self.seed_watermark
            && right.0 < self.seed_watermark
        {
            if let Some(si) = self.seed_interner {
                if let Some(existing) = si.get_pair(left, right) {
                    return existing;
                }
            }
        }
        let key = ((left.0 as u64) << 32) | (right.0 as u64);
        if let Some(&existing) = self.pair_map.get(&key) {
            return existing;
        }
        let height = l_height.max(r_height).saturating_add(1);

        let sym = SymbolId::from_rule_index(self.seed_rules.len() + self.nodes.len());
        self.nodes.push(RuleNode {
            kind: RuleKind::Pair { left, right },
            byte_len,
            height,
            first_byte,
            last_byte,
        });
        self.pair_map.insert(key, sym);
        sym
    }

    #[inline]
    fn contract_span(&mut self, span: &[SymbolId], out: &mut Vec<SymbolId>) {
        let mut p = 0;
        let len = span.len();
        if len == 1 {
            out.push(span[0]);
            return;
        }
        while len - p > 3 {
            let pair = self.intern_pair(span[p], span[p + 1]);
            out.push(pair);
            p += 2;
        }
        match len - p {
            2 => {
                let pair = self.intern_pair(span[p], span[p + 1]);
                out.push(pair);
            }
            3 => {
                let left = self.intern_pair(span[p], span[p + 1]);
                let triple = self.intern_pair(left, span[p + 2]);
                out.push(triple);
            }
            0 => {}
            _ => unreachable!(),
        }
    }

    #[inline]
    fn fold_sym_slice(&mut self, syms: &[SymbolId]) -> SymbolId {
        match syms.len() {
            0 => unreachable!(),
            1 => syms[0],
            2 => self.intern_pair(syms[0], syms[1]),
            3 => {
                let l = self.intern_pair(syms[0], syms[1]);
                self.intern_pair(l, syms[2])
            }
            n => {
                let mid = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
                let l = self.fold_sym_slice(&syms[..mid]);
                let r = self.fold_sym_slice(&syms[mid..]);
                self.intern_pair(l, r)
            }
        }
    }

    #[inline]
    fn fold_ascii_word<'a>(
        &mut self,
        word: &'a [u8],
        seg_cache: &mut FxHashMap<&'a [u8], SymbolId>,
    ) -> SymbolId {
        if word.len() == 1 {
            return SymbolId::from_byte(word[0]);
        }
        if let Some(&cached) = seg_cache.get(word) {
            return cached;
        }
        let mut buf = [SymbolId(0); 32];
        let mut n = 0usize;
        let mut i = 0usize;
        let len = word.len();
        while i < len {
            let b = word[i];
            let mut j = i + 1;
            while j < len && word[j] == b {
                j += 1;
            }
            let sym = SymbolId::from_byte(b);
            buf[n] = if j - i == 1 {
                sym
            } else {
                self.intern_run(sym, (j - i) as u64)
            };
            n += 1;
            i = j;
        }
        let res = self.fold_sym_slice(&buf[..n]);
        seg_cache.insert(word, res);
        res
    }

    /// Tokenizes a byte segment into lexical ASCII word/punctuation tokens, UTF-8 character symbols, and run-length symbols.
    /// Returns `true` if any non-ASCII byte (`>= 0x80`) was encountered.
    #[inline]
    fn tokenize_segment<'a>(
        &mut self,
        bytes: &'a [u8],
        out: &mut Vec<SymbolId>,
        seg_cache: &mut FxHashMap<&'a [u8], SymbolId>,
    ) -> bool {
        out.clear();
        let len = bytes.len();
        let mut i = 0;
        let mut has_non_ascii = false;
        while i < len {
            let b0 = bytes[i];
            if b0 < 0x80 {
                if (b0.is_ascii_alphanumeric() || b0 == b'_')
                    && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'))
                    && (i + 1 >= len || bytes[i + 1] != b0)
                {
                    let max_end = (i + 25).min(len);
                    let mut j = i + 1;
                    while j < max_end && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                        j += 1;
                    }
                    if j - i <= 24
                        && (j == len || !(bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_'))
                    {
                        let word_sym = self.fold_ascii_word(&bytes[i..j], seg_cache);
                        out.push(word_sym);
                        i = j;
                        continue;
                    }
                } else if b0 != b'\t' && (i + 1 < len && bytes[i + 1] != b0) {
                    let is_punct = |b: u8| {
                        b < 0x80 && b != b'\t' && !(b.is_ascii_alphanumeric() || b == b'_')
                    };
                    if is_punct(b0) && (i == 0 || !is_punct(bytes[i - 1])) {
                        let max_end = (i + 9).min(len);
                        let mut j = i + 1;
                        while j < max_end && is_punct(bytes[j]) {
                            j += 1;
                        }
                        if j - i >= 2 && j - i <= 8 && (j == len || !is_punct(bytes[j])) {
                            let p_sym = self.fold_ascii_word(&bytes[i..j], seg_cache);
                            out.push(p_sym);
                            i = j;
                            continue;
                        }
                    }
                }
                let mut next_i = i + 1;
                while next_i < len && bytes[next_i] == b0 {
                    next_i += 1;
                }
                let run_len = (next_i - i) as u64;
                let sym = SymbolId::from_byte(b0);
                if run_len == 1 {
                    out.push(sym);
                } else {
                    out.push(self.intern_run(sym, run_len));
                }
                i = next_i;
                continue;
            }
            has_non_ascii = true;

            let (sym, step) = if i + 2 < len
                && (0xE0..=0xEF).contains(&b0)
                && (bytes[i + 1] & 0xC0) == 0x80
                && (bytes[i + 2] & 0xC0) == 0x80
            {
                let p01 = self.intern_pair(
                    SymbolId::from_byte(b0),
                    SymbolId::from_byte(bytes[i + 1]),
                );
                let s = self.intern_pair(p01, SymbolId::from_byte(bytes[i + 2]));
                (s, 3usize)
            } else if i + 1 < len && (0xC2..=0xDF).contains(&b0) && (bytes[i + 1] & 0xC0) == 0x80 {
                let s = self.intern_pair(
                    SymbolId::from_byte(b0),
                    SymbolId::from_byte(bytes[i + 1]),
                );
                (s, 2usize)
            } else if i + 3 < len
                && (0xF0..=0xF4).contains(&b0)
                && (bytes[i + 1] & 0xC0) == 0x80
                && (bytes[i + 2] & 0xC0) == 0x80
                && (bytes[i + 3] & 0xC0) == 0x80
            {
                let p01 = self.intern_pair(
                    SymbolId::from_byte(b0),
                    SymbolId::from_byte(bytes[i + 1]),
                );
                let p23 = self.intern_pair(
                    SymbolId::from_byte(bytes[i + 2]),
                    SymbolId::from_byte(bytes[i + 3]),
                );
                let s = self.intern_pair(p01, p23);
                (s, 4usize)
            } else {
                (SymbolId::from_byte(b0), 1usize)
            };

            let mut run_len = 1u64;
            let mut next_i = i + step;
            if step == 1 {
                while next_i < len && bytes[next_i] == b0 {
                    run_len += 1;
                    next_i += 1;
                }
            } else {
                let pat = &bytes[i..i + step];
                while next_i + step <= len && &bytes[next_i..next_i + step] == pat {
                    run_len += 1;
                    next_i += step;
                }
            }

            if run_len == 1 {
                out.push(sym);
            } else {
                out.push(self.intern_run(sym, run_len));
            }
            i = next_i;
        }
        has_non_ascii
    }

    /// Reduces a non-empty symbol sequence in-place to a single root `SymbolId` using LCP recompression.
    #[inline]
    fn reduce_sequence(&mut self, seq: &mut Vec<SymbolId>, next_seq: &mut Vec<SymbolId>) -> SymbolId {
        debug_assert!(!seq.is_empty());
        while seq.len() > 1 {
            let n = seq.len();
            if n == 2 {
                return self.intern_pair(seq[0], seq[1]);
            }
            if n == 3 {
                let left = self.intern_pair(seq[0], seq[1]);
                return self.intern_pair(left, seq[2]);
            }

            next_seq.clear();
            let mut span_start = 0usize;
            let mut prev_hash = self.landmark_hash(seq[0]);
            let mut cur_hash = self.landmark_hash(seq[1]);

            for idx in 1..(n - 1) {
                let next_hash = self.landmark_hash(seq[idx + 1]);
                if cur_hash < prev_hash && cur_hash < next_hash {
                    self.contract_span(&seq[span_start..idx], next_seq);
                    span_start = idx;
                }
                prev_hash = cur_hash;
                cur_hash = next_hash;
            }
            self.contract_span(&seq[span_start..n], next_seq);

            seq.clear();
            let m = next_seq.len();
            let mut p = 0;
            while p < m {
                let sym = next_seq[p];
                let mut q = p + 1;
                while q < m && next_seq[q] == sym {
                    q += 1;
                }
                let run_len = (q - p) as u64;
                if run_len == 1 {
                    seq.push(sym);
                } else {
                    seq.push(self.intern_run(sym, run_len));
                }
                p = q;
            }
        }
        seq[0]
    }

    #[inline]
    fn compress_line_body<'a>(
        &mut self,
        body: &'a [u8],
        seq: &mut Vec<SymbolId>,
        next_seq: &mut Vec<SymbolId>,
        seg_cache: &mut FxHashMap<&'a [u8], SymbolId>,
    ) -> SymbolId {
        if body.len() == 1 {
            return SymbolId::from_byte(body[0]);
        }
        if body.len() <= 512 {
            if let Some(&cached) = seg_cache.get(body) {
                return cached;
            }
        }
        let has_non_ascii = self.tokenize_segment(body, seq, seg_cache);
        let sym = if !has_non_ascii && body.len() <= 1024 {
            self.fold_sym_slice(seq)
        } else {
            self.reduce_sequence(seq, next_seq)
        };
        if body.len() <= 512 {
            seg_cache.insert(body, sym);
        }
        sym
    }

    #[inline]
    fn compress_core_line<'a>(
        &mut self,
        line: &'a [u8],
        seq: &mut Vec<SymbolId>,
        next_seq: &mut Vec<SymbolId>,
        seg_cache: &mut FxHashMap<&'a [u8], SymbolId>,
    ) -> SymbolId {
        if line.len() == 1 {
            return SymbolId::from_byte(line[0]);
        }
        if line.len() <= 512 {
            if let Some(&cached) = seg_cache.get(line) {
                return cached;
            }
        }
        let b0 = line[0];
        if b0 == b'\t' || b0 == b' ' {
            let mut indent_len = 1usize;
            while indent_len < line.len() && line[indent_len] == b0 {
                indent_len += 1;
            }
            if indent_len < line.len() {
                let indent_sym = self.intern_run(SymbolId::from_byte(b0), indent_len as u64);
                let body = &line[indent_len..];
                let body_sym = self.compress_line_body(body, seq, next_seq, seg_cache);
                let sym = self.intern_pair(indent_sym, body_sym);
                if line.len() <= 512 {
                    seg_cache.insert(line, sym);
                }
                return sym;
            }
        }
        self.compress_line_body(line, seq, next_seq, seg_cache)
    }

    #[inline]
    fn compress_line<'a>(
        &mut self,
        line: &'a [u8],
        seq: &mut Vec<SymbolId>,
        next_seq: &mut Vec<SymbolId>,
        seg_cache: &mut FxHashMap<&'a [u8], SymbolId>,
    ) -> SymbolId {
        if line.len() == 1 {
            return SymbolId::from_byte(line[0]);
        }
        let mut core_end = line.len();
        while core_end > 1 && line[core_end - 1] == b'\n' && line[core_end - 2] == b'\n' {
            core_end -= 1;
        }
        if core_end < line.len() {
            let core_sym = self.compress_core_line(&line[..core_end], seq, next_seq, seg_cache);
            let extra_nl =
                self.intern_run(SymbolId::from_byte(b'\n'), (line.len() - core_end) as u64);
            return self.intern_pair(core_sym, extra_nl);
        }
        self.compress_core_line(line, seq, next_seq, seg_cache)
    }

    fn compress_unit<'a>(
        &mut self,
        unit: &'a [u8],
        seq: &mut Vec<SymbolId>,
        next_seq: &mut Vec<SymbolId>,
        seg_cache: &mut FxHashMap<&'a [u8], SymbolId>,
    ) -> Option<SymbolId> {
        if unit.is_empty() {
            return None;
        }
        if unit.len() == 1 {
            return Some(SymbolId::from_byte(unit[0]));
        }
        if unit[0] == b'\n' {
            return Some(self.intern_run(SymbolId::from_byte(b'\n'), unit.len() as u64));
        }
        Some(self.compress_line(unit, seq, next_seq, seg_cache))
    }

    fn compress_partition(units: &[&[u8]]) -> LocalPartitionDag {
        Self::compress_partition_with_seed(units, &[], None)
    }

    fn compress_partition_with_seed<'a>(
        units: &[&'a [u8]],
        seed_rules: &'s [RuleNode],
        seed_interner: Option<&'s RuleInterner>,
    ) -> LocalPartitionDag {
        let total_bytes: usize = units.iter().map(|c| c.len()).sum();
        let mut comp = Self::with_capacity_and_seed(
            (total_bytes / 6).clamp(64, 131_072),
            seed_rules,
            seed_interner,
        );
        let mut seq: Vec<SymbolId> = Vec::with_capacity(256);
        let mut next_seq: Vec<SymbolId> = Vec::with_capacity(256);
        let mut seg_cache: FxHashMap<&'a [u8], SymbolId> = FxHashMap::default();
        seg_cache.reserve((total_bytes / 32).clamp(64, 8192));

        let mut roots = Vec::with_capacity(units.len());
        for &unit in units {
            let root = comp.compress_unit(unit, &mut seq, &mut next_seq, &mut seg_cache);
            roots.push(root);
        }
        LocalPartitionDag {
            nodes: comp.nodes,
            roots,
        }
    }
}

/// Thread-local document sequence reducer that builds document-level LCP trees above
/// already-merged global line `SymbolId`s in parallel across all CPU cores.
struct LocalDocTreeCompressor<'a> {
    global_rules: &'a [RuleNode],
    local_nodes: Vec<RuleNode>,
    pair_map: FxHashMap<u64, SymbolId>,
    run_map: FxHashMap<(SymbolId, u64), SymbolId>,
}

impl<'a> LocalDocTreeCompressor<'a> {
    fn new(global_rules: &'a [RuleNode], est_nodes: usize) -> Self {
        let mut pair_map = FxHashMap::default();
        pair_map.reserve(est_nodes);
        let mut run_map = FxHashMap::default();
        run_map.reserve(est_nodes / 8);
        Self {
            global_rules,
            local_nodes: Vec::with_capacity(est_nodes),
            pair_map,
            run_map,
        }
    }

    #[inline(always)]
    fn rule_ref(&self, sym: SymbolId) -> &RuleNode {
        let idx = sym.rule_index();
        if idx < self.global_rules.len() {
            &self.global_rules[idx]
        } else {
            &self.local_nodes[idx - self.global_rules.len()]
        }
    }

    #[inline(always)]
    fn sym_meta(&self, sym: SymbolId) -> (u64, u16, u8, u8) {
        if let Some(b) = sym.as_byte() {
            (1, 0, b, b)
        } else {
            let n = self.rule_ref(sym);
            (n.byte_len, n.height, n.first_byte, n.last_byte)
        }
    }

    #[inline(always)]
    fn content_landmark_hash(&self, sym: SymbolId) -> u64 {
        if let Some(b) = sym.as_byte() {
            terminal_shash(b)
        } else {
            splitmix64_non_zero(sym.0 as u64)
        }
    }

    #[inline(always)]
    fn as_run(&self, sym: SymbolId) -> (SymbolId, u64) {
        if !sym.is_terminal() {
            if let RuleKind::Run { child, count } = self.rule_ref(sym).kind {
                return (child, count);
            }
        }
        (sym, 1)
    }

    #[inline]
    fn intern_run(&mut self, child: SymbolId, count: u64) -> SymbolId {
        if count == 1 {
            return child;
        }
        let (base_child, base_count) = self.as_run(child);
        let total_count = base_count * count;
        if let Some(&existing) = self.run_map.get(&(base_child, total_count)) {
            return existing;
        }
        let (c_len, c_height, first_byte, last_byte) = self.sym_meta(base_child);
        let byte_len = c_len * total_count;
        let height = c_height.saturating_add(1);
        let sym = SymbolId::from_rule_index(self.global_rules.len() + self.local_nodes.len());
        self.local_nodes.push(RuleNode {
            kind: RuleKind::Run {
                child: base_child,
                count: total_count,
            },
            byte_len,
            height,
            first_byte,
            last_byte,
        });
        self.run_map.insert((base_child, total_count), sym);
        sym
    }

    #[inline]
    fn intern_pair(&mut self, left: SymbolId, right: SymbolId) -> SymbolId {
        let key = ((left.0 as u64) << 32) | (right.0 as u64);
        if let Some(&existing) = self.pair_map.get(&key) {
            return existing;
        }
        let (l_base, l_count) = self.as_run(left);
        let (r_base, r_count) = self.as_run(right);
        if l_base == r_base {
            return self.intern_run(l_base, l_count + r_count);
        }
        let (l_len, l_height, first_byte, _) = self.sym_meta(left);
        let (r_len, r_height, _, last_byte) = self.sym_meta(right);
        let byte_len = l_len + r_len;
        let height = l_height.max(r_height).saturating_add(1);
        let sym = SymbolId::from_rule_index(self.global_rules.len() + self.local_nodes.len());
        self.local_nodes.push(RuleNode {
            kind: RuleKind::Pair { left, right },
            byte_len,
            height,
            first_byte,
            last_byte,
        });
        self.pair_map.insert(key, sym);
        sym
    }

    #[inline]
    fn contract_span(&mut self, span: &[SymbolId], out: &mut Vec<SymbolId>) {
        let mut p = 0;
        let len = span.len();
        if len == 1 {
            out.push(span[0]);
            return;
        }
        while len - p > 3 {
            let pair = self.intern_pair(span[p], span[p + 1]);
            out.push(pair);
            p += 2;
        }
        match len - p {
            2 => {
                let pair = self.intern_pair(span[p], span[p + 1]);
                out.push(pair);
            }
            3 => {
                let left = self.intern_pair(span[p], span[p + 1]);
                let triple = self.intern_pair(left, span[p + 2]);
                out.push(triple);
            }
            0 => {}
            _ => unreachable!(),
        }
    }

    fn compress_doc_sequence(
        &mut self,
        seq: &mut Vec<SymbolId>,
        next_seq: &mut Vec<SymbolId>,
    ) -> Option<SymbolId> {
        if seq.is_empty() {
            return None;
        }
        if seq.len() == 1 {
            return Some(seq[0]);
        }

        // Collapse initial runs
        let mut write = 0usize;
        let mut read = 0usize;
        while read < seq.len() {
            let s = seq[read];
            let mut q = read + 1;
            while q < seq.len() && seq[q] == s {
                q += 1;
            }
            seq[write] = if q - read == 1 {
                s
            } else {
                self.intern_run(s, (q - read) as u64)
            };
            write += 1;
            read = q;
        }
        seq.truncate(write);

        while seq.len() > 1 {
            let n = seq.len();
            if n == 2 {
                return Some(self.intern_pair(seq[0], seq[1]));
            }
            if n == 3 {
                let left = self.intern_pair(seq[0], seq[1]);
                return Some(self.intern_pair(left, seq[2]));
            }

            next_seq.clear();
            let mut span_start = 0usize;
            let mut prev_hash = self.content_landmark_hash(seq[0]);
            let mut cur_hash = self.content_landmark_hash(seq[1]);

            for idx in 1..(n - 1) {
                let next_hash = self.content_landmark_hash(seq[idx + 1]);
                if cur_hash < prev_hash && cur_hash < next_hash {
                    self.contract_span(&seq[span_start..idx], next_seq);
                    span_start = idx;
                }
                prev_hash = cur_hash;
                cur_hash = next_hash;
            }
            self.contract_span(&seq[span_start..n], next_seq);

            seq.clear();
            let m = next_seq.len();
            let mut p = 0;
            while p < m {
                let sym = next_seq[p];
                let mut q = p + 1;
                while q < m && next_seq[q] == sym {
                    q += 1;
                }
                let run_len = (q - p) as u64;
                if run_len == 1 {
                    seq.push(sym);
                } else {
                    seq.push(self.intern_run(sym, run_len));
                }
                p = q;
            }
        }
        Some(seq[0])
    }
}

type LineUnit<'a> = (&'a [u8], u64);

fn split_into_line_units_seq<'a>(
    bytes: &'a [u8],
    rules_ref: &[RuleNode],
    line_cache_ref: &[(u64, SymbolId)],
) -> Vec<LineUnit<'a>> {
    let len = bytes.len();
    let has_lc = !line_cache_ref.is_empty();
    let mut units: Vec<LineUnit<'a>> = Vec::with_capacity((len / 64).clamp(1, 65_536));
    let mut i = 0usize;
    while i < len {
        let start = i;
        if bytes[i] == b'\n' {
            while i < len && bytes[i] == b'\n' {
                i += 1;
            }
        } else {
            let search_end = (i + PARALLEL_CHUNK_SIZE).min(len);
            if let Some(pos) = bytes[i..search_end].iter().position(|&b| b == b'\n') {
                i += pos + 1;
                while i < len && bytes[i] == b'\n' {
                    i += 1;
                }
            } else {
                i = search_end;
                while i < len && bytes[i] == bytes[i - 1] {
                    i += 1;
                }
            }
        }
        let slice = &bytes[start..i];
        let hash = checksum64(slice);
        if has_lc && slice.len() <= 256 {
            let (cached_hash, sym) = line_cache_ref[(hash as usize) & LINE_CACHE_MASK];
            if cached_hash == hash && sym.0 != 0 && sym_matches_slice(rules_ref, sym, slice) {
                units.push((&[], sym.0 as u64));
                continue;
            }
        }
        units.push((slice, hash));
    }
    units
}

/// Splits a byte slice into line units (each consisting of a line body plus any immediately
/// following `\n` bytes, or a chunk up to `PARALLEL_CHUNK_SIZE` when no newlines exist)
/// paired with its 64-bit checksum for fast cross-document line deduplication.
fn split_into_line_units(bytes: &[u8]) -> Vec<LineUnit<'_>> {
    split_into_line_units_cached(bytes, &[], &[])
}

fn split_into_line_units_cached<'a>(
    bytes: &'a [u8],
    rules_ref: &[RuleNode],
    line_cache_ref: &[(u64, SymbolId)],
) -> Vec<LineUnit<'a>> {
    let len = bytes.len();
    if len == 0 {
        return Vec::new();
    }
    let first = bytes[0];
    if len > 64 && bytes[len - 1] == first && bytes.iter().all(|&b| b == first) {
        return vec![(bytes, checksum64(bytes))];
    }
    if len >= 2 * 1024 * 1024 {
        const CHUNK_STEP: usize = 512 * 1024;
        let mut bounds = Vec::with_capacity(len / CHUNK_STEP + 2);
        bounds.push(0usize);
        let mut pos = CHUNK_STEP;
        while pos < len {
            let search_end = (pos + PARALLEL_CHUNK_SIZE).min(len);
            if let Some(nl) = bytes[pos..search_end].iter().position(|&b| b == b'\n') {
                pos += nl + 1;
                while pos < len && bytes[pos] == b'\n' {
                    pos += 1;
                }
                if pos < len {
                    bounds.push(pos);
                }
                pos += CHUNK_STEP;
            } else {
                break;
            }
        }
        if bounds.len() > 1 {
            bounds.push(len);
            let parts: Vec<Vec<LineUnit<'a>>> = bounds
                .par_windows(2)
                .map(|w| {
                    split_into_line_units_seq(&bytes[w[0]..w[1]], rules_ref, line_cache_ref)
                })
                .collect();
            let total: usize = parts.iter().map(|p| p.len()).sum();
            let mut out = Vec::with_capacity(total);
            for mut p in parts {
                out.append(&mut p);
            }
            return out;
        }
    }
    split_into_line_units_seq(bytes, rules_ref, line_cache_ref)
}

fn parallel_kr_hash(bytes: &[u8]) -> u64 {
    if bytes.len() <= PARALLEL_CHUNK_SIZE {
        return raw_slice_hash(bytes);
    }
    let chunk_hashes: Vec<(u64, usize)> = bytes
        .par_chunks(PARALLEL_CHUNK_SIZE)
        .map(|c| (raw_slice_hash(c), c.len()))
        .collect();
    let mut acc = 0u64;
    for (h, len) in chunk_hashes {
        acc = combine_hashes(acc, h, mod_pow(HASH_BASE, len as u64));
    }
    acc
}

#[inline]
fn sym_matches_slice(rules: &[RuleNode], sym: SymbolId, slice: &[u8]) -> bool {
    if let Some(b) = sym.as_byte() {
        return slice.len() == 1 && slice[0] == b;
    }
    let node = &rules[sym.rule_index()];
    if node.byte_len != slice.len() as u64
        || slice.is_empty()
        || node.first_byte != slice[0]
        || node.last_byte != slice[slice.len() - 1]
    {
        return false;
    }
    let mut pos = 0usize;
    sym_matches_inner(rules, sym, slice, &mut pos) && pos == slice.len()
}

fn sym_matches_inner(rules: &[RuleNode], sym: SymbolId, slice: &[u8], pos: &mut usize) -> bool {
    if let Some(b) = sym.as_byte() {
        if *pos < slice.len() && slice[*pos] == b {
            *pos += 1;
            return true;
        }
        return false;
    }
    let node = &rules[sym.rule_index()];
    let len = node.byte_len as usize;
    if *pos + len > slice.len() {
        return false;
    }
    if node.first_byte != slice[*pos] || node.last_byte != slice[*pos + len - 1] {
        return false;
    }
    match node.kind {
        RuleKind::Pair { left, right } => {
            sym_matches_inner(rules, left, slice, pos)
                && sym_matches_inner(rules, right, slice, pos)
        }
        RuleKind::Run { child, count } => {
            let start = *pos;
            if !sym_matches_inner(rules, child, slice, pos) {
                return false;
            }
            let c_len = *pos - start;
            let pat = &slice[start..*pos];
            for _ in 1..count {
                if slice[*pos..*pos + c_len] != *pat {
                    return false;
                }
                *pos += c_len;
            }
            true
        }
    }
}

/// Groups unique line units into ~512 KB L2-cache-sized partitions so each Rayon worker thread
/// compresses a batch of unique lines inside L2 cache.
fn group_into_partitions<'b, 'a>(unique_chunks: &'b [&'a [u8]]) -> Vec<&'b [&'a [u8]]> {
    const TARGET_PARTITION_BYTES: usize = 512 * 1024;
    let mut partitions = Vec::new();
    let mut start = 0usize;
    let mut acc_bytes = 0usize;
    for (i, &c) in unique_chunks.iter().enumerate() {
        acc_bytes += c.len();
        if acc_bytes >= TARGET_PARTITION_BYTES {
            partitions.push(&unique_chunks[start..=i]);
            start = i + 1;
            acc_bytes = 0;
        }
    }
    if start < unique_chunks.len() {
        partitions.push(&unique_chunks[start..]);
    }
    partitions
}

impl GrammarDag {
    /// Merges a thread-local `LocalPartitionDag` into the canonical global `GrammarDag`,
    /// deduplicating shared production rules via the global `RuleInterner`.
    fn merge_local_partition_dag(
        &mut self,
        local: &LocalPartitionDag,
        remap_scratch: &mut Vec<SymbolId>,
        out_roots: &mut Vec<SymbolId>,
    ) {
        self.merge_seeded_partition_dag(local, 0, remap_scratch, out_roots);
    }

    fn merge_seeded_partition_dag(
        &mut self,
        local: &LocalPartitionDag,
        seed_len: usize,
        remap_scratch: &mut Vec<SymbolId>,
        out_roots: &mut Vec<SymbolId>,
    ) {
        self.ensure_interner();
        let seed_watermark = SymbolId::from_rule_index(seed_len).0;
        let watermark = SymbolId::from_rule_index(self.rules.len()).0;
        remap_scratch.clear();
        remap_scratch.reserve(local.nodes.len());

        let map_sym = |sym: SymbolId, remap: &[SymbolId]| -> SymbolId {
            if sym.0 < seed_watermark {
                sym
            } else {
                remap[sym.rule_index() - seed_len]
            }
        };

        for &node in &local.nodes {
            let global_sym = match node.kind {
                RuleKind::Pair { left, right } => {
                    let gl = map_sym(left, remap_scratch);
                    let gr = map_sym(right, remap_scratch);
                    let can_match = gl.0 < watermark
                        && gr.0 < watermark
                        && !(watermark == seed_watermark
                            && gl.0 < seed_watermark
                            && gr.0 < seed_watermark);
                    self.interner
                        .merge_precomputed_pair(&mut self.rules, gl, gr, node, can_match)
                }
                RuleKind::Run { child, count } => {
                    let gc = map_sym(child, remap_scratch);
                    let can_match =
                        gc.0 < watermark && !(watermark == seed_watermark && gc.0 < seed_watermark);
                    self.interner
                        .merge_precomputed_run(&mut self.rules, gc, count, node, can_match)
                }
            };
            remap_scratch.push(global_sym);
        }

        for &root_opt in &local.roots {
            let root = root_opt.unwrap();
            out_roots.push(map_sym(root, remap_scratch));
        }
    }

    /// Compresses a raw byte slice into the DAG using Locally Consistent Parsing (Recompression).
    /// Automatically parallelizes across all CPU cores using `rayon` for multi-chunk inputs.
    pub fn compress_bytes(&mut self, bytes: &[u8]) -> Option<SymbolId> {
        if bytes.is_empty() {
            return None;
        }
        if bytes.len() == 1 {
            return Some(SymbolId::from_byte(bytes[0]));
        }

        let units = split_into_line_units(bytes);
        let mut unique_units: Vec<&[u8]> = Vec::with_capacity(units.len());
        let mut unit_to_unique_idx: Vec<u32> = Vec::with_capacity(units.len());
        let mut seen: FxHashMap<(usize, u64), u32> = FxHashMap::default();
        seen.reserve(units.len());

        for (slice, hash) in units {
            let key = (slice.len(), hash);
            if let Some(&u_idx) = seen.get(&key) {
                if unique_units[u_idx as usize] == slice {
                    unit_to_unique_idx.push(u_idx);
                    continue;
                }
            }
            let u_idx = unique_units.len() as u32;
            seen.insert(key, u_idx);
            unique_units.push(slice);
            unit_to_unique_idx.push(u_idx);
        }

        let partitions = group_into_partitions(&unique_units);
        let local_dags: Vec<LocalPartitionDag> = if partitions.len() <= 1 {
            partitions
                .iter()
                .map(|&part| LocalChunkCompressor::compress_partition(part))
                .collect()
        } else {
            partitions
                .par_iter()
                .map(|&part| LocalChunkCompressor::compress_partition(part))
                .collect()
        };

        let mut remap_scratch = Vec::new();
        let mut unique_root_syms: Vec<SymbolId> = Vec::with_capacity(unique_units.len());
        for local in &local_dags {
            self.merge_local_partition_dag(local, &mut remap_scratch, &mut unique_root_syms);
        }

        let unit_syms: Vec<SymbolId> = unit_to_unique_idx
            .into_iter()
            .map(|u_idx| unique_root_syms[u_idx as usize])
            .collect();

        self.compress_symbol_sequence(unit_syms)
    }

    /// Compresses multiple documents in parallel across all CPU cores into the shared `GrammarDag`.
    pub fn add_documents_parallel(&mut self, docs: &[(String, Vec<u8>)]) -> Vec<RootEntry> {
        let need_exact_kr = self.roots.len() + docs.len() <= 64;
        let rules_ref = &self.rules[..];
        let line_cache_ref = &self.interner.line_cache;

        // Step 1: Segment all documents into line units + resolve cross-batch line_cache hits in parallel!
        let doc_units_and_hashes: Vec<(Vec<LineUnit<'_>>, u64)> = docs
            .par_iter()
            .map(|(_, bytes)| {
                let units = split_into_line_units_cached(bytes, rules_ref, line_cache_ref);
                let kr = if need_exact_kr {
                    parallel_kr_hash(bytes)
                } else {
                    let mut h = 0xcbf29ce484222325u64;
                    for &(_, uh) in &units {
                        h = h.rotate_left(13) ^ uh;
                    }
                    h
                };
                (units, kr)
            })
            .collect();

        // Step 2: Deduplicate new line units across the batch before running LCP!
        let total_units: usize = doc_units_and_hashes.iter().map(|(u, _)| u.len()).sum();
        let est_unique = (total_units * 3) / 5 + 1;
        let mut unique_units: Vec<&[u8]> = Vec::with_capacity(est_unique);
        let mut unique_hashes: Vec<u64> = Vec::with_capacity(est_unique);
        let mut doc_unit_ranges: Vec<std::ops::Range<usize>> = Vec::with_capacity(docs.len());
        // Bit 31 == 0 => already-resolved SymbolId(v); Bit 31 == 1 => unique_root_syms[(v & 0x7FFF_FFFF)]
        let mut unit_to_sym: Vec<u32> = Vec::with_capacity(total_units);

        if total_units >= 65_536 {
            let seen = self.interner.prepare_seen_table();
            for (units, _) in &doc_units_and_hashes {
                let start = unit_to_sym.len();
                for &(slice, hash) in units {
                    if slice.is_empty() {
                        unit_to_sym.push(hash as u32);
                        continue;
                    }
                    let slot = &mut seen[(hash as usize) & SEEN_TABLE_MASK];
                    let prev = *slot;
                    if prev != u32::MAX {
                        let u_idx = prev as usize;
                        if unique_hashes[u_idx] == hash && unique_units[u_idx] == slice {
                            unit_to_sym.push(0x8000_0000 | prev);
                            continue;
                        }
                    }
                    let u_idx = unique_units.len() as u32;
                    *slot = u_idx;
                    unique_units.push(slice);
                    unique_hashes.push(hash);
                    unit_to_sym.push(0x8000_0000 | u_idx);
                }
                let end = unit_to_sym.len();
                doc_unit_ranges.push(start..end);
            }
        } else {
            let mut seen: FxHashMap<u64, u32> = FxHashMap::default();
            seen.reserve(est_unique);
            for (units, _) in &doc_units_and_hashes {
                let start = unit_to_sym.len();
                for &(slice, hash) in units {
                    if slice.is_empty() {
                        unit_to_sym.push(hash as u32);
                        continue;
                    }
                    match seen.entry(hash) {
                        std::collections::hash_map::Entry::Occupied(e) => {
                            let u_idx = *e.get();
                            if unique_units[u_idx as usize] == slice {
                                unit_to_sym.push(0x8000_0000 | u_idx);
                                continue;
                            }
                        }
                        std::collections::hash_map::Entry::Vacant(v) => {
                            let u_idx = unique_units.len() as u32;
                            v.insert(u_idx);
                            unique_units.push(slice);
                            unique_hashes.push(hash);
                            unit_to_sym.push(0x8000_0000 | u_idx);
                            continue;
                        }
                    }
                    let u_idx = unique_units.len() as u32;
                    unique_units.push(slice);
                    unique_hashes.push(hash);
                    unit_to_sym.push(0x8000_0000 | u_idx);
                }
                let end = unit_to_sym.len();
                doc_unit_ranges.push(start..end);
            }
        }

        // Step 3 & Step 4: Compress only the new unique line units in parallel and merge into global GrammarDag!
        let partitions = group_into_partitions(&unique_units);
        let mut remap_scratch = Vec::new();
        let mut unique_root_syms: Vec<SymbolId> = Vec::with_capacity(unique_units.len());

        let rem_partitions = if self.interner.seed_rules_len == 0 && partitions.len() > 4 {
            let init_dags: Vec<LocalPartitionDag> = partitions[..4]
                .par_iter()
                .map(|&part| LocalChunkCompressor::compress_partition(part))
                .collect();
            for local in &init_dags {
                self.merge_seeded_partition_dag(local, 0, &mut remap_scratch, &mut unique_root_syms);
            }
            self.interner.seed_rules_len = self.rules.len();
            &partitions[4..]
        } else {
            &partitions[..]
        };

        if !rem_partitions.is_empty() {
            let seed_len = self.interner.seed_rules_len;
            let seed_slice = &self.rules[..seed_len];
            let seed_interner_opt = if seed_len > 0 {
                Some(&self.interner)
            } else {
                None
            };
            let mut local_dags: Vec<LocalPartitionDag> = rem_partitions
                .par_iter()
                .map(|&part| {
                    LocalChunkCompressor::compress_partition_with_seed(
                        part,
                        seed_slice,
                        seed_interner_opt,
                    )
                })
                .collect();

            let total_local_nodes: usize = local_dags.iter().map(|d| d.nodes.len()).sum();
            self.rules.reserve(total_local_nodes);
            let seed_watermark = SymbolId::from_rule_index(seed_len).0;

            let mut split_idx = 0usize;
            let max_merge = local_dags.len().min(8);
            while split_idx < max_merge && self.interner.pair_map_len() < 1_200_000 {
                self.merge_seeded_partition_dag(
                    &local_dags[split_idx],
                    seed_len,
                    &mut remap_scratch,
                    &mut unique_root_syms,
                );
                self.interner.seed_rules_len = self.rules.len();
                split_idx += 1;
            }

            if split_idx < local_dags.len() {
                let tail_dags: Vec<LocalPartitionDag> = local_dags.drain(split_idx..).collect();
                let start_rules_len = self.rules.len();
                let start_roots_len = unique_root_syms.len();
                let mut cur_rules_len = start_rules_len;
                let mut cur_roots_len = start_roots_len;
                let mut offsets = Vec::with_capacity(tail_dags.len());
                for local in &tail_dags {
                    offsets.push((cur_rules_len - seed_len) as u32);
                    cur_rules_len += local.nodes.len();
                    cur_roots_len += local.roots.len();
                }

                let added_rules = cur_rules_len - start_rules_len;
                let added_roots = cur_roots_len - start_roots_len;
                self.rules.reserve(added_rules);
                unique_root_syms.reserve(added_roots);

                let mut node_slices: Vec<&mut [std::mem::MaybeUninit<RuleNode>]> =
                    Vec::with_capacity(tail_dags.len());
                let mut rem_nodes = &mut self.rules.spare_capacity_mut()[..added_rules];
                let mut root_slices: Vec<&mut [std::mem::MaybeUninit<SymbolId>]> =
                    Vec::with_capacity(tail_dags.len());
                let mut rem_roots = &mut unique_root_syms.spare_capacity_mut()[..added_roots];
                for local in &tail_dags {
                    let (n_head, n_tail) = rem_nodes.split_at_mut(local.nodes.len());
                    node_slices.push(n_head);
                    rem_nodes = n_tail;
                    let (r_head, r_tail) = rem_roots.split_at_mut(local.roots.len());
                    root_slices.push(r_head);
                    rem_roots = r_tail;
                }

                tail_dags
                    .into_par_iter()
                    .zip(node_slices.into_par_iter())
                    .zip(root_slices.into_par_iter())
                    .zip(offsets.par_iter())
                    .for_each(|(((local, dst_nodes), dst_roots), &offset)| {
                        let shift_sym = |s: SymbolId| -> SymbolId {
                            if s.0 >= seed_watermark {
                                SymbolId(s.0 + offset)
                            } else {
                                s
                            }
                        };
                        for (dst, &node) in dst_nodes.iter_mut().zip(local.nodes.iter()) {
                            let mut n = node;
                            match &mut n.kind {
                                RuleKind::Pair { left, right } => {
                                    *left = shift_sym(*left);
                                    *right = shift_sym(*right);
                                }
                                RuleKind::Run { child, .. } => {
                                    *child = shift_sym(*child);
                                }
                            }
                            dst.write(n);
                        }
                        for (dst_r, &r_opt) in dst_roots.iter_mut().zip(local.roots.iter()) {
                            dst_r.write(shift_sym(r_opt.unwrap()));
                        }
                    });
                unsafe {
                    self.rules.set_len(cur_rules_len);
                    unique_root_syms.set_len(cur_roots_len);
                }
            }
        }

        // Populate persistent cross-batch direct-mapped line_cache for lines <= 256 bytes
        self.interner.ensure_line_cache();
        let lc = &mut self.interner.line_cache[..];
        for (i, &slice) in unique_units.iter().enumerate() {
            if slice.len() <= 256 {
                let h = unique_hashes[i];
                lc[(h as usize) & LINE_CACHE_MASK] = (h, unique_root_syms[i]);
            }
        }
        drop(unique_hashes);

        // Step 5: Reduce each document's line unit symbol sequence to a single root symbol in parallel across all CPU cores!
        let base_rules_len = self.rules.len();
        let target_units_per_part = (total_units / 32).max(4096);
        let mut doc_part_ranges: Vec<std::ops::Range<usize>> = Vec::new();
        let mut p_start = 0usize;
        let mut acc_units = 0usize;
        for d_idx in 0..docs.len() {
            acc_units += doc_unit_ranges[d_idx].len();
            if acc_units >= target_units_per_part && d_idx + 1 < docs.len() {
                let cur_name = docs[d_idx].0.as_bytes();
                let next_name = docs[d_idx + 1].0.as_bytes();
                let p_len = cur_name.len().min(next_name.len()).min(12);
                if p_len < 8 || cur_name[..p_len] != next_name[..p_len] || acc_units >= 250_000 {
                    doc_part_ranges.push(p_start..d_idx + 1);
                    p_start = d_idx + 1;
                    acc_units = 0;
                }
            }
        }
        if p_start < docs.len() {
            doc_part_ranges.push(p_start..docs.len());
        }

        let global_rules_slice = &self.rules[..base_rules_len];
        let doc_tree_parts: Vec<(Vec<RuleNode>, Vec<Option<SymbolId>>)> = doc_part_ranges
            .par_iter()
            .map(|d_range| {
                let part_units: usize = doc_unit_ranges[d_range.clone()]
                    .iter()
                    .map(|r| r.len())
                    .sum();
                let mut comp = LocalDocTreeCompressor::new(
                    global_rules_slice,
                    (part_units / 2).clamp(16, 131_072),
                );
                let mut seq = Vec::new();
                let mut next_seq = Vec::new();
                let mut roots = Vec::with_capacity(d_range.len());
                for d_idx in d_range.clone() {
                    let u_range = &doc_unit_ranges[d_idx];
                    if u_range.is_empty() {
                        roots.push(None);
                    } else {
                        seq.clear();
                        seq.reserve(u_range.len());
                        for u_pos in u_range.clone() {
                            let code = unit_to_sym[u_pos];
                            let sym = if (code & 0x8000_0000) == 0 {
                                SymbolId(code)
                            } else {
                                unique_root_syms[(code & 0x7FFF_FFFF) as usize]
                            };
                            seq.push(sym);
                        }
                        roots.push(comp.compress_doc_sequence(&mut seq, &mut next_seq));
                    }
                }
                (comp.local_nodes, roots)
            })
            .collect();

        let mut cur_doc_rules_len = base_rules_len;
        let mut doc_offsets = Vec::with_capacity(doc_tree_parts.len());
        for (local_nodes, _) in &doc_tree_parts {
            doc_offsets.push((cur_doc_rules_len - base_rules_len) as u32);
            cur_doc_rules_len += local_nodes.len();
        }
        let added_doc_rules = cur_doc_rules_len - base_rules_len;
        self.rules.reserve(added_doc_rules);
        let mut doc_root_syms: Vec<Option<SymbolId>> = vec![None; docs.len()];

        let mut doc_node_slices: Vec<&mut [std::mem::MaybeUninit<RuleNode>]> =
            Vec::with_capacity(doc_tree_parts.len());
        let mut rem_doc_nodes = &mut self.rules.spare_capacity_mut()[..added_doc_rules];
        let mut doc_root_slices: Vec<&mut [Option<SymbolId>]> =
            Vec::with_capacity(doc_tree_parts.len());
        let mut rem_doc_roots = &mut doc_root_syms[..];
        for (local_nodes, local_roots) in &doc_tree_parts {
            let (n_head, n_tail) = rem_doc_nodes.split_at_mut(local_nodes.len());
            doc_node_slices.push(n_head);
            rem_doc_nodes = n_tail;
            let (r_head, r_tail) = rem_doc_roots.split_at_mut(local_roots.len());
            doc_root_slices.push(r_head);
            rem_doc_roots = r_tail;
        }

        let base_watermark = SymbolId::from_rule_index(base_rules_len).0;
        doc_tree_parts
            .into_par_iter()
            .zip(doc_node_slices.into_par_iter())
            .zip(doc_root_slices.into_par_iter())
            .zip(doc_offsets.par_iter())
            .for_each(
                |((((local_nodes, local_roots), dst_nodes), dst_roots), &offset)| {
                    if offset == 0 {
                        for (dst, &node) in dst_nodes.iter_mut().zip(local_nodes.iter()) {
                            dst.write(node);
                        }
                        dst_roots.copy_from_slice(&local_roots);
                        return;
                    }
                    let shift_sym = |s: SymbolId| -> SymbolId {
                        if s.0 >= base_watermark {
                            SymbolId(s.0 + offset)
                        } else {
                            s
                        }
                    };
                    for (dst, &node) in dst_nodes.iter_mut().zip(local_nodes.iter()) {
                        let mut n = node;
                        match &mut n.kind {
                            RuleKind::Pair { left, right } => {
                                *left = shift_sym(*left);
                                *right = shift_sym(*right);
                            }
                            RuleKind::Run { child, .. } => {
                                *child = shift_sym(*child);
                            }
                        }
                        dst.write(n);
                    }
                    for (dst_r, &r) in dst_roots.iter_mut().zip(local_roots.iter()) {
                        *dst_r = r.map(shift_sym);
                    }
                },
            );
        unsafe {
            self.rules.set_len(cur_doc_rules_len);
        }
        self.interner.set_indexed_rules(self.rules.len());

        let check_existing = self.roots.len() <= 64;
        self.roots.reserve(docs.len());
        let mut entries = Vec::with_capacity(docs.len());
        for ((name, _), ((units, doc_kr_hash), root_symbol)) in docs
            .iter()
            .zip(doc_units_and_hashes.into_iter().zip(doc_root_syms.into_iter()))
        {
            drop(units);
            let byte_len = match root_symbol {
                Some(sym) => self.sym_len(sym),
                None => 0,
            };
            let entry = RootEntry {
                name: name.clone(),
                root_symbol,
                byte_len,
                kr_hash: doc_kr_hash,
            };
            if check_existing {
                if let Some(existing) = self.roots.iter_mut().find(|r| r.name == *name) {
                    *existing = entry.clone();
                    entries.push(entry);
                    continue;
                }
            }
            self.roots.push(entry.clone());
            entries.push(entry);
        }
        entries
    }

    #[inline(always)]
    fn content_landmark_hash(&self, sym: SymbolId) -> u64 {
        if let Some(b) = sym.as_byte() {
            terminal_shash(b)
        } else {
            let n = &self.rules[sym.rule_index()];
            let tag = match n.kind {
                RuleKind::Pair { left, right } => {
                    (self.sym_len(left).rotate_left(13) ^ self.sym_len(right))
                        .wrapping_add((self.sym_first_byte(left) as u64) << 8)
                        .wrapping_add(self.sym_last_byte(right) as u64)
                }
                RuleKind::Run { child, count } => {
                    self.sym_len(child).rotate_left(29) ^ count.wrapping_mul(0xbf58476d1ce4e5b9)
                }
            };
            splitmix64_non_zero(
                tag ^ n.byte_len.wrapping_mul(0x9e3779b97f4a7c15)
                    ^ ((n.height as u64) << 16)
                    ^ ((n.first_byte as u64) << 8)
                    ^ (n.last_byte as u64),
            )
        }
    }

    /// Runs iterative Recompression (Phase B local-minimum block contraction followed by
    /// Phase A run-length contraction) on an initial sequence of symbols.
    pub(crate) fn compress_symbol_sequence(&mut self, mut seq: Vec<SymbolId>) -> Option<SymbolId> {
        if seq.is_empty() {
            return None;
        }
        if seq.len() == 1 {
            return Some(seq[0]);
        }

        seq = self.contract_runs(seq);

        let mut next_seq = Vec::with_capacity((seq.len() * 2) / 3 + 4);
        while seq.len() > 1 {
            next_seq.clear();
            let n = seq.len();

            if n == 2 {
                let root = self.intern_pair(seq[0], seq[1]);
                return Some(root);
            }
            if n == 3 {
                let left = self.intern_pair(seq[0], seq[1]);
                let root = self.intern_pair(left, seq[2]);
                return Some(root);
            }

            let mut span_start = 0usize;
            let mut prev_hash = self.content_landmark_hash(seq[0]);
            let mut cur_hash = self.content_landmark_hash(seq[1]);

            for idx in 1..(n - 1) {
                let next_hash = self.content_landmark_hash(seq[idx + 1]);
                if cur_hash < prev_hash && cur_hash < next_hash {
                    self.contract_span(&seq[span_start..idx], &mut next_seq);
                    span_start = idx;
                }
                prev_hash = cur_hash;
                cur_hash = next_hash;
            }
            self.contract_span(&seq[span_start..n], &mut next_seq);

            seq.clear();
            let m = next_seq.len();
            let mut p = 0;
            while p < m {
                let sym = next_seq[p];
                let mut q = p + 1;
                while q < m && next_seq[q] == sym {
                    q += 1;
                }
                let run_len = (q - p) as u64;
                if run_len == 1 {
                    seq.push(sym);
                } else {
                    seq.push(self.intern_run(sym, run_len));
                }
                p = q;
            }
        }

        Some(seq[0])
    }

    #[inline]
    fn contract_runs(&mut self, seq: Vec<SymbolId>) -> Vec<SymbolId> {
        let mut has_adjacent_dup = false;
        for w in seq.windows(2) {
            if w[0] == w[1] {
                has_adjacent_dup = true;
                break;
            }
        }
        if !has_adjacent_dup {
            return seq;
        }
        let mut out = Vec::with_capacity(seq.len());
        let mut i = 0;
        while i < seq.len() {
            let sym = seq[i];
            let mut j = i + 1;
            while j < seq.len() && seq[j] == sym {
                j += 1;
            }
            let count = (j - i) as u64;
            if count == 1 {
                out.push(sym);
            } else {
                out.push(self.intern_run(sym, count));
            }
            i = j;
        }
        out
    }

    #[inline]
    fn contract_span(&mut self, span: &[SymbolId], out: &mut Vec<SymbolId>) {
        let mut p = 0;
        let len = span.len();
        if len == 1 {
            out.push(span[0]);
            return;
        }
        while len - p > 3 {
            let pair = self.intern_pair(span[p], span[p + 1]);
            out.push(pair);
            p += 2;
        }
        match len - p {
            2 => {
                let pair = self.intern_pair(span[p], span[p + 1]);
                out.push(pair);
            }
            3 => {
                let left = self.intern_pair(span[p], span[p + 1]);
                let triple = self.intern_pair(left, span[p + 2]);
                out.push(triple);
            }
            0 => {}
            _ => unreachable!(),
        }
    }

    /// Compresses a named document and adds or updates its `RootEntry` in `self.roots`.
    pub fn add_document(&mut self, name: impl Into<String>, bytes: &[u8]) -> RootEntry {
        let name = name.into();
        let root_symbol = self.compress_bytes(bytes);
        let (byte_len, kr_hash) = match root_symbol {
            Some(sym) => (self.sym_len(sym), self.sym_hash(sym)),
            None => (0, 0),
        };
        let entry = RootEntry {
            name: name.clone(),
            root_symbol,
            byte_len,
            kr_hash,
        };
        if let Some(existing) = self.roots.iter_mut().find(|r| r.name == name) {
            *existing = entry.clone();
        } else {
            self.roots.push(entry.clone());
        }
        entry
    }

    /// Convenience constructor: compresses a single anonymous/default byte slice into a new `GrammarDag`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut dag = Self::new();
        dag.add_document("default", bytes);
        dag
    }

    /// Decompresses a specific `SymbolId` by appending its exact byte expansion into `out`.
    pub fn decompress_symbol_into(&self, sym: SymbolId, out: &mut Vec<u8>) {
        let total_len = self.sym_len(sym) as usize;
        out.reserve(total_len);
        self.expand_recursive(sym, out);
    }

    fn expand_recursive(&self, sym: SymbolId, out: &mut Vec<u8>) {
        if let Some(b) = sym.as_byte() {
            out.push(b);
            return;
        }
        let node = self.rule(sym);
        match node.kind {
            RuleKind::Pair { left, right } => {
                self.expand_recursive(left, out);
                self.expand_recursive(right, out);
            }
            RuleKind::Run { child, count } => {
                let start = out.len();
                self.expand_recursive(child, out);
                let child_len = out.len() - start;
                if child_len == 0 {
                    return;
                }
                let mut copied = 1u64;
                while copied < count {
                    let to_copy = copied.min(count - copied);
                    let copy_bytes = (to_copy as usize) * child_len;
                    out.extend_from_within(start..start + copy_bytes);
                    copied += to_copy;
                }
            }
        }
    }

    /// Decompresses a named root (or the default root if `doc_name` is `None`) into a new `Vec<u8>`.
    pub fn decompress(&self, doc_name: Option<&str>) -> Result<Vec<u8>> {
        let root = self.find_root(doc_name)?;
        let mut out = Vec::with_capacity(root.byte_len as usize);
        if let Some(sym) = root.root_symbol {
            self.decompress_symbol_into(sym, &mut out);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::raw_slice_hash;

    #[test]
    fn test_lcp_edge_cases() {
        let dag_empty = GrammarDag::from_bytes(b"");
        dag_empty.validate_invariants().unwrap();
        assert_eq!(dag_empty.decompress(None).unwrap(), b"");
        assert_eq!(dag_empty.rules.len(), 0);

        let dag_single = GrammarDag::from_bytes(b"Z");
        dag_single.validate_invariants().unwrap();
        assert_eq!(dag_single.decompress(None).unwrap(), b"Z");
        assert_eq!(dag_single.rules.len(), 0);

        let run_data = vec![b'A'; 1_000_000];
        let dag_run = GrammarDag::from_bytes(&run_data);
        dag_run.validate_invariants().unwrap();
        assert_eq!(dag_run.rules.len(), 1);
        assert_eq!(dag_run.decompress(None).unwrap(), run_data);
        assert_eq!(
            dag_run.find_root(None).unwrap().kr_hash,
            raw_slice_hash(&run_data)
        );

        let alt_data = b"ab".repeat(50_000);
        let dag_alt = GrammarDag::from_bytes(&alt_data);
        dag_alt.validate_invariants().unwrap();
        assert!(
            dag_alt.rules.len() <= 5,
            "Expected tiny rule count for periodic string, got {}",
            dag_alt.rules.len()
        );
        assert_eq!(dag_alt.decompress(None).unwrap(), alt_data);
        assert_eq!(
            dag_alt.find_root(None).unwrap().kr_hash,
            raw_slice_hash(&alt_data)
        );
    }

    #[test]
    fn test_lcp_structured_logs() {
        let mut log_data = Vec::new();
        for i in 0..2000 {
            let line = format!(
                "2026-10-24T12:00:00Z INFO service=api status={} latency={}\n",
                if i % 10 == 0 { 500 } else { 200 },
                100 + (i % 25)
            );
            log_data.extend_from_slice(line.as_bytes());
        }
        let dag = GrammarDag::from_bytes(&log_data);
        dag.validate_invariants().unwrap();
        let decompressed = dag.decompress(None).unwrap();
        assert_eq!(decompressed, log_data);
        assert_eq!(
            dag.find_root(None).unwrap().kr_hash,
            raw_slice_hash(&log_data)
        );
        assert!(
            dag.rules.len() < log_data.len() / 15,
            "Expected high deduplication: rules={}, bytes={}",
            dag.rules.len(),
            log_data.len()
        );
    }
}
