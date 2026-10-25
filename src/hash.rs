use crate::grammar::SymbolId;

/// Mersenne prime modulus P = 2^61 - 1.
pub const MOD_P: u64 = (1u64 << 61) - 1;

/// Fixed polynomial rolling hash base B = 257 in GF(2^61 - 1).
pub const HASH_BASE: u64 = 257;

/// Computes (a + b) mod (2^61 - 1), assuming a < MOD_P and b < MOD_P.
#[inline(always)]
pub const fn mod_add(a: u64, b: u64) -> u64 {
    let s = a + b;
    let s = (s & MOD_P) + (s >> 61);
    if s >= MOD_P {
        s - MOD_P
    } else {
        s
    }
}

/// Computes (a - b) mod (2^61 - 1), assuming a < MOD_P and b < MOD_P.
#[inline(always)]
pub const fn mod_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        MOD_P - (b - a)
    }
}

/// Computes (a * b) mod (2^61 - 1), assuming a < MOD_P and b < MOD_P.
#[inline(always)]
pub const fn mod_mul(a: u64, b: u64) -> u64 {
    let prod = (a as u128) * (b as u128);
    let lo = (prod as u64) & MOD_P;
    let hi = (prod >> 61) as u64;
    // Note: hi can be up to (2^61 - 2)^2 >> 61 < 2^61 - 1, but could have bit 61 set if a,b weren't reduced.
    // Since a, b < 2^61 - 1, prod < (2^61 - 1)^2 = 2^122 - 2^62 + 1, so hi = prod >> 61 < 2^61 - 1.
    mod_add(lo, hi)
}

/// Computes base^exp mod (2^61 - 1) in O(log exp) time.
#[inline]
pub const fn mod_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut res = 1u64;
    base %= MOD_P;
    while exp > 0 {
        if exp & 1 == 1 {
            res = mod_mul(res, base);
        }
        base = mod_mul(base, base);
        exp >>= 1;
    }
    res
}

/// Computes the geometric series (1 + r + r^2 + ... + r^{k-1}) mod (2^61 - 1)
/// in O(log k) time without division (safe even when r == 1).
#[inline]
pub const fn geom_sum(r: u64, k: u64) -> u64 {
    if k == 0 {
        return 0;
    }
    if k == 1 {
        return 1;
    }
    if k & 1 == 0 {
        let half = geom_sum(mod_mul(r, r), k >> 1);
        mod_mul(mod_add(1, r), half)
    } else {
        let rest = geom_sum(r, k - 1);
        mod_add(1, mod_mul(r, rest))
    }
}

/// Karp-Rabin hash of a single terminal byte b in 0..=255.
#[inline(always)]
pub const fn byte_hash(b: u8) -> u64 {
    (b as u64) + 1
}

/// Combines Karp-Rabin hashes for concatenation L || R:
/// hash(L || R) = (hash(L) * pow(R) + hash(R)) mod P.
#[inline(always)]
pub const fn combine_hashes(left_hash: u64, right_hash: u64, right_pow: u64) -> u64 {
    mod_add(mod_mul(left_hash, right_pow), right_hash)
}

/// Computes the Karp-Rabin hash and B^len mod P for a repeated symbol A^k:
/// hash(A^k) = hash(A) * geom_sum(pow(A), k) mod P
/// pow(A^k) = pow(A)^k mod P
#[inline]
pub const fn repeat_hash_and_pow(child_hash: u64, child_pow: u64, count: u64) -> (u64, u64) {
    let g = geom_sum(child_pow, count);
    let h = mod_mul(child_hash, g);
    let p = mod_pow(child_pow, count);
    (h, p)
}

/// Directly computes the Karp-Rabin polynomial hash of a raw byte slice in O(N) time.
/// Used for testing and verification against O(log N) homomorphic DAG hashes.
pub fn raw_slice_hash(bytes: &[u8]) -> u64 {
    let mut h = 0u64;
    for &b in bytes {
        h = mod_add(mod_mul(h, HASH_BASE), byte_hash(b));
    }
    h
}

/// Deterministic 64-bit SplitMix64 finalizer, remapped so that it never returns 0
/// (0 is reserved as the minimum landmark priority of `\n`).
#[inline(always)]
pub const fn splitmix64_non_zero(mut z: u64) -> u64 {
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

/// Deterministic 64-bit bijective SplitMix64 hash for Locally Consistent Parsing landmarks.
/// Assigns newline (`\n` = 10) the minimum possible priority 0 so line boundaries act as
/// natural synchronization points at Level 0.
#[inline(always)]
pub const fn landmark_hash(sym: SymbolId) -> u64 {
    if sym.0 == b'\n' as u32 {
        return 0;
    }
    splitmix64_non_zero(sym.0 as u64)
}

/// Fast, deterministic 64-bit checksum over an arbitrary byte slice for file headers and footers.
pub fn checksum64(data: &[u8]) -> u64 {
    let mut acc: u64 = 0xcbf29ce484222325 ^ (data.len() as u64).wrapping_mul(0x9e3779b97f4a7c15);
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        acc ^= word;
        acc = (acc ^ (acc >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        acc = (acc ^ (acc >> 27)).wrapping_mul(0x94d049bb133111eb);
        acc ^= acc >> 31;
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut last = 0u64;
        for (i, &b) in rem.iter().enumerate() {
            last |= (b as u64) << (i * 8);
        }
        acc ^= last;
        acc = (acc ^ (acc >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        acc = (acc ^ (acc >> 27)).wrapping_mul(0x94d049bb133111eb);
        acc ^= acc >> 31;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mersenne_arithmetic() {
        assert_eq!(mod_add(MOD_P - 1, 1), 0);
        assert_eq!(mod_add(MOD_P - 1, 2), 1);
        assert_eq!(mod_sub(0, 1), MOD_P - 1);
        assert_eq!(mod_sub(10, 3), 7);
        assert_eq!(mod_mul(MOD_P - 1, MOD_P - 1), 1);
        assert_eq!(mod_pow(HASH_BASE, 0), 1);
        assert_eq!(mod_pow(HASH_BASE, 1), HASH_BASE);
    }

    #[test]
    fn test_geom_sum_matches_brute_force() {
        for &r in &[1u64, 2, 257, 123456789, MOD_P - 1] {
            for &k in &[0u64, 1, 2, 3, 7, 16, 63, 64, 65, 1000, 10000] {
                let fast = geom_sum(r, k);
                let mut brute = 0u64;
                let mut cur = 1u64;
                for _ in 0..k {
                    brute = mod_add(brute, cur);
                    cur = mod_mul(cur, r);
                }
                assert_eq!(fast, brute, "Mismatch for r={r}, k={k}");
            }
        }
    }

    #[test]
    fn test_homomorphic_hash_consistency() {
        let s1 = b"hello ";
        let s2 = b"world!";
        let mut both = Vec::new();
        both.extend_from_slice(s1);
        both.extend_from_slice(s2);

        let h1 = raw_slice_hash(s1);
        let h2 = raw_slice_hash(s2);
        let p2 = mod_pow(HASH_BASE, s2.len() as u64);
        let combined = combine_hashes(h1, h2, p2);
        assert_eq!(combined, raw_slice_hash(&both));

        // Test RLE repetition hash
        let repeated = b"abc".repeat(37);
        let h_abc = raw_slice_hash(b"abc");
        let p_abc = mod_pow(HASH_BASE, 3);
        let (h_rep, p_rep) = repeat_hash_and_pow(h_abc, p_abc, 37);
        assert_eq!(h_rep, raw_slice_hash(&repeated));
        assert_eq!(p_rep, mod_pow(HASH_BASE, (3 * 37) as u64));
    }

    #[test]
    fn test_landmark_hash_bijection_and_newline() {
        assert_eq!(landmark_hash(SymbolId(b'\n' as u32)), 0);
        for id in 0..1000u32 {
            if id != b'\n' as u32 {
                assert_ne!(landmark_hash(SymbolId(id)), 0);
            }
            assert_ne!(landmark_hash(SymbolId(id)), landmark_hash(SymbolId(id + 1)));
        }
    }
}
