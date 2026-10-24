# Buttlick: Grammar-Homomorphic Zero-Decompression Compute Engine
## Complete Architecture, Mathematical Specification & Implementation Plan

> **Document Purpose & Target Audience:**
> This document is the complete, self-contained architectural blueprint and implementation specification for **Buttlick** (`buttlick`). It is written so that an engineer or autonomous coding agent with **zero prior context** can implement the entire system from scratch to production quality without ambiguity. Every data structure, mathematical invariant, binary layout, edge case, and verification test is specified herein.

---

## Table of Contents
1. [Executive Summary & System Goals](#1-executive-summary--system-goals)
2. [Mathematical & Algorithmic Foundations](#2-mathematical--algorithmic-foundations)
   - 2.1 Run-Length Straight-Line Programs (RLSLPs)
   - 2.2 Locally Consistent Parsing (LCP) & Recompression
   - 2.3 Homomorphic Polynomial Rolling Hashes ($O(\log N)$ Equality)
   - 2.4 Algebra 1: The KMP Seam-Tracking Monoid (Exact Substring Search)
   - 2.5 Algebra 2: The Wreath-Product Mealy Transducer Monoid (Regex & Line Grep)
   - 2.6 Algebra 3: The Affine Place-Value & Record-Aggregator Monoid (Structured Analytics)
3. [Repository Architecture & Crate Layout](#3-repository-architecture--crate-layout)
4. [Core Data Structures & In-Memory Representation](#4-core-data-structures--in-memory-representation)
5. [On-Disk Binary Format Specification (`.btlk` v1)](#5-on-disk-binary-format-specification-btlk-v1)
6. [Detailed Algorithm Specifications (Reference Implementation Logic)](#6-detailed-algorithm-specifications-reference-implementation-logic)
   - 6.1 Algorithm 1: Locally Consistent Grammar Compression (`compress`)
   - 6.2 Algorithm 2: $O(\log N)$ Random Access, Slicing & $O(\log N)$ Fingerprinting
   - 6.3 Algorithm 3: KMP Seam-Tracking Exact Search & Lazy Offset Extraction
   - 6.4 Algorithm 4: Wreath-Product Automaton Evaluation (Regex, Multi-Pattern & Line Grep)
   - 6.5 Algorithm 5: Zero-Decompression Structured Field Analytics (`SUM`, `MIN`, `MAX`, `COUNT`, `AVG`)
   - 6.6 Algorithm 6: Dynamic $O(\log N)$ Persistent DAG Edits (`concat`, `split`, `insert`, `delete`, `replace_all`)
   - 6.7 Algorithm 7: Multi-Document / Versioned Corpus Ingestion & Cross-Version Querying
7. [Command-Line Interface (`buttlick`) Specification](#7-command-line-interface-buttlick-specification)
8. [Subtle Edge Cases, Pitfalls & Mandatory Safeguards](#8-subtle-edge-cases-pitfalls--mandatory-safeguards)
9. [Phased Implementation Roadmap & Verification Suite](#9-phased-implementation-roadmap--verification-suite)

---

## 1. Executive Summary & System Goals

### 1.1 The Problem
Standard compression algorithms (`gzip`, `zstd`, `lz4`, `xz`) are based on LZ77 sliding-window backreferences. While they reduce storage size, they are **computationally opaque**: to run a search (`grep`), a regular expression, a substring check, an edit, or a numerical aggregation (`SUM`/`COUNT`/`MIN`/`MAX`) over a 1 TB dataset compressed to 5 GB, existing systems must first decompress all 1 TB back through RAM and CPU caches, doing $O(N)$ work proportional to the **uncompressed** size $N$.

### 1.2 The Buttlick Solution
**Buttlick** is a **Grammar-Homomorphic Storage and Compute Engine** written in Rust.
Instead of unstructured LZ77 backreferences, Buttlick compresses raw byte streams (or collections of files/versions) into a **balanced, deduplicated Run-Length Straight-Line Program (RLSLP) DAG** using **Locally Consistent Parsing (LCP)**.

Because the compressed representation is a hierarchical Context-Free Grammar DAG of depth $O(\log N)$ with $n \ll N$ unique rules, Buttlick compiles queries—substring searches, arbitrary regular expressions, line-oriented `grep`, and structured numerical aggregations—into **Algebraic Monoid Homomorphisms** that evaluate bottom-up directly on the grammar rules in $O(n)$ time (**proportional strictly to the compressed size $n$, never decompressing the data**).

### 1.3 Core Capabilities & Complexity Guarantees
Given a dataset of uncompressed length $N$ compressed into a Buttlick DAG with $n$ rules and depth $H = O(\log N)$:

| Operation | Traditional (`zstd` + `ripgrep`/`DuckDB`) | Buttlick (`buttlick`) |
| :--- | :--- | :--- |
| **Random Access (`slice(start, len)`)** | $O(N)$ linear decompression | **$O(\log N + \text{len})$** |
| **Substring Equality (`eq(pos1, pos2, len)`)** | $O(N + \text{len})$ | **$O(\log N)$** (even for $\text{len} = 10^{11}$ bytes) |
| **Exact Pattern Count (`count(pattern)`)** | $O(N)$ full scan | **$O(n \cdot |P|)$** (zero decompression) |
| **Exact Match Offsets (`grep -b`)** | $O(N)$ full scan | **$O(n \cdot |P| + k \log N)$** for $k$ matches |
| **Arbitrary Regex Search / Line Count** | $O(N)$ full scan | **$O(n \cdot |Q|)$** via Wreath-Product Transducer |
| **Structured Analytics (`SUM`, `MIN`, `MAX`, `AVG`)** | $O(N)$ full parse | **$O(n \cdot |Q|)$** via Affine Digit Monoid |
| **In-Place Edit (`insert`, `delete`, `concat`)** | $O(N)$ rewrite | **$O(\log N)$** persistent DAG surgery |
| **Global Search-and-Replace (`replace_all`)** | $O(N)$ rewrite | **$O(n \cdot |P|)$** homomorphic DAG rewrite |

---

## 2. Mathematical & Algorithmic Foundations

### 2.1 Run-Length Straight-Line Programs (RLSLPs)
A **Run-Length Straight-Line Program (RLSLP)** is a Context-Free Grammar $\mathcal{G} = (\Sigma, V, R, S)$ that generates a single deterministic byte string (or a set of strings via multiple root symbols $S_1, \dots, S_m$) where:
1. **Terminals ($\Sigma$):** The 256 byte values `0x00..=0xFF`, represented directly as leaf symbol IDs `0..=255`.
2. **Non-Terminals ($V$):** Rule IDs $\ge 256$ ordered topologically such that if rule $u$ references rule $v$, then $u > v$ (guaranteeing acyclicity).
3. **Production Rules ($R$):** Every non-terminal $X \in V$ has **exactly one** deterministic production rule of one of two forms:
   - **Pair (Concatenation) Rule:** $X \to A \, B$, where $A, B \in \Sigma \cup V$ and $A \ne B$.
     - Uncompressed length: $\text{len}(X) = \text{len}(A) + \text{len}(B)$.
   - **Run-Length (Power) Rule:** $X \to A^k$, where $A \in \Sigma \cup V$ and integer $k \ge 2$.
     - Uncompressed length: $\text{len}(X) = k \cdot \text{len}(A)$.
4. **Canonical Interning (Hash-Consing):** No two distinct non-terminals may have the exact same right-hand side ($A \, B$ or $A^k$). All structural deduplication happens automatically via a global canonical hash table during construction and editing.

### 2.2 Locally Consistent Parsing (LCP) & Recompression
Why does naive pair-grouping fail on edits or shifted repeats? Because pairing indices $(0,1), (2,3), (4,5)$ shifts completely if a single byte is inserted at index $0$.

Buttlick uses **Jeż's Recompression / Locally Consistent Parsing (LCP)**, which alternates two deterministic local passes at each level $h = 0, 1, 2, \dots$ until the sequence shrinks to a single root symbol:

1. **Pass A — Run-Length Contraction (Block Compression):**
   Scan the current sequence of symbols $s_0, s_1, \dots, s_{m-1}$. Replace every maximal contiguous run of identical symbols $A, A, \dots, A$ of length $k \ge 2$ with a single canonically interned RLE non-terminal $X \to A^k$.
   *Invariant after Pass A:* There are **no adjacent identical symbols** anywhere in the sequence ($s_i \ne s_{i+1}$ for all $i$).

2. **Pass B — Locally Consistent Pair Contraction:**
   Given an aperiodic sequence ($s_i \ne s_{i+1}$), we must choose non-overlapping adjacent pairs $(s_i, s_{i+1})$ to contract into $X \to s_i \, s_{i+1}$ such that:
   - At least a constant fraction ($\ge 1/4$ to $1/3$) of symbols are contracted per level, guaranteeing tree height $H = O(\log N)$.
   - The decision to pair $(s_i, s_{i+1})$ depends **only on a tiny local neighborhood** around $i$ ($s_{i-1}, s_i, s_{i+1}, s_{i+2}$), so identical substrings anywhere in the file produce the exact same parse tree except within $O(1)$ symbols of their boundaries!

   **Exact Deterministic Local Landmark Rule:**
   Assign every symbol ID $x \in \Sigma \cup V$ a deterministic 64-bit bijective splitmix64 hash $h(x)$ (with one special override: at level 0, newline `0x0A` is assigned the minimum possible hash $0$ so line boundaries naturally align with grammar node boundaries).
   Since $s_i \ne s_{i+1}$ after Pass A, $h(s_i) \ne h(s_{i+1})$ for all adjacent symbols!
   Define position $i \in \{1, \dots, m-2\}$ as a **local minimum landmark** if and only if:
   $$h(s_i) < h(s_{i-1}) \quad \text{and} \quad h(s_i) < h(s_{i+1})$$
   And for positions not adjacent to a local minimum (i.e., along monotonic runs of length $\ge 3$ where $h$ strictly increases or strictly decreases), apply **Cole-Vishkin deterministic symmetry breaking** (or greedy alternating pair selection from the start of each monotonic segment) so that no uncontracted gap between landmarks exceeds 3 symbols.
   Every segment of length 2 or 3 between cut-points is then contracted:
   - Segment $(a, b)$ contracts to `intern_pair(a, b)`.
   - Segment $(a, b, c)$ contracts to `intern_pair(intern_pair(a, b), c)`.

### 2.3 Homomorphic Polynomial Rolling Hashes ($O(\log N)$ Equality)
Every symbol $X \in \Sigma \cup V$ stores its precomputed **Karp-Rabin Algebraic Fingerprint** over the Mersenne prime field $\mathbb{F}_P$ where $P = 2^{61} - 1$ (`0x1FFFFFFFFFFFFFFF`) with fixed base $B = 257$ (or a fixed odd multiplier $B \in [257, P-1]$):
- For a terminal byte $b \in 0..=255$:
  $$\text{hash}(b) = (b + 1) \bmod P, \qquad \text{pow}(b) = B^1 \bmod P$$
- For a Pair rule $X \to L \, R$:
  $$\text{hash}(X) = \left(\text{hash}(L) \cdot \text{pow}(R) + \text{hash}(R)\right) \bmod P$$
  $$\text{pow}(X) = \left(\text{pow}(L) \cdot \text{pow}(R)\right) \bmod P = B^{\text{len}(X)} \bmod P$$
- For an RLE rule $X \to A^k$:
  Using the geometric series identity $1 + r + r^2 + \dots + r^{k-1}$ where $r = \text{pow}(A) = B^{\text{len}(A)} \bmod P$ (computed in $O(\log k)$ time via divide-and-conquer geometric sum so we never need division when $r = 1$):
  $$\text{Geom}(r, k) = \begin{cases} 1 & k = 1 \\ (1 + r) \cdot \text{Geom}(r^2 \bmod P, k/2) \bmod P & k \text{ even} \\ (1 + r \cdot \text{Geom}(r, k-1)) \bmod P & k \text{ odd} \end{cases}$$
  $$\text{hash}(X) = \text{hash}(A) \cdot \text{Geom}(\text{pow}(A), k) \bmod P, \qquad \text{pow}(X) = \text{pow}(A)^k \bmod P$$

**Consequence:** For *any* arbitrary byte range $[i, i + L)$ in a 1-Terabyte file, decomposing $[i, i + L)$ into $O(\log N)$ canonical grammar nodes along the left and right boundary paths allows computing the exact hash of the $L$-byte slice in $O(\log N)$ time! Two multi-gigabyte slices can be compared for equality in $< 10$ microseconds.

---

### 2.4 Algebra 1: The KMP Seam-Tracking Monoid (Exact Substring Search)
Given a literal pattern $P[0..m]$ of length $m \ge 1$:
- If $m = 1$ (single byte $b$):
  - Terminal $x$: `count(x) = (x == b) as u64`.
  - Pair $X \to L \, R$: `count(X) = count(L) + count(R)`.
  - RLE $X \to A^k$: `count(X) = k * count(A)`.
- If $m \ge 2$:
  Precompute the Knuth-Morris-Pratt (KMP) prefix-function table $\pi[0..m]$ for $P$ in $O(m)$ time.
  For every grammar symbol $X$:
  - Its internal match count $\text{count}(X)$ is the total number of occurrences of $P$ inside the expansion of $X$.
  - **Pair Rule ($X \to L \, R$):**
    Any occurrence of $P$ in $X$ is either:
    1. Wholly inside $L$: $\text{count}(L)$
    2. Wholly inside $R$: $\text{count}(R)$
    3. **Crossing the seam between $L$ and $R$:** Such an occurrence starts inside the last $m - 1$ bytes of $L$ and ends inside the first $m - 1$ bytes of $R$.
    Let $S_{\text{left}} = \text{suffix}(L, \min(\text{len}(L), m - 1))$ and $S_{\text{right}} = \text{prefix}(R, \min(\text{len}(R), m - 1))$.
    Concatenate the seam buffer $W = S_{\text{left}} \mathbin{\Vert} S_{\text{right}}$ (at most $2m - 2$ bytes!) and count matches of $P$ in $W$ using KMP, **Assertion:** since $|S_{\text{left}}| \le m - 1$ and $|S_{\text{right}}| \le m - 1$, *every* match of $P$ inside $W$ is guaranteed to include at least one byte from $S_{\text{left}}$ and at least one byte from $S_{\text{right}}$—meaning zero double-counting with $\text{count}(L)$ or $\text{count}(R)$!
    $$\text{count}(X) = \text{count}(L) + \text{count}(R) + \text{kmp\_count}(W, P)$$
  - **RLE Rule ($X \to A^k$):**
    When $A$ is repeated $k$ times, there are $k$ copies of $A$'s internal matches, plus matches that span across one or more copies of $A$:
    - Case 1 ($\text{len}(A) \ge m - 1$): Any match spanning across copies of $A$ only ever touches the seam between two adjacent copies $A \, A$! There are $k - 1$ such seams:
      $$\text{count}(X) = k \cdot \text{count}(A) + (k - 1) \cdot \text{kmp\_count}(\text{suffix}(A, m-1) \mathbin{\Vert} \text{prefix}(A, m-1), P)$$
    - Case 2 ($\text{len}(A) < m - 1$): A single match of $P$ might span multiple copies of $A$. We simply reduce $X \to A^k$ via binary exponentiation (squaring $A, A^2, A^4, \dots$ as virtual pair operations in $O(\log k)$ steps, where each virtual node maintains its $\text{prefix}(\le m-1)$, $\text{suffix}(\le m-1)$, and `count`)! This handles all periodic overlaps with 100% mathematical exactness in $O(m \log k)$ time.

---

### 2.5 Algebra 2: The Wreath-Product Mealy Transducer Monoid (Regex & Line Grep)
How do we evaluate an **arbitrary Regular Expression** (with `*`, `+`, `?`, `|`, character classes, and multi-line or line-by-line semantics) across the grammar DAG without ever hitting a seam problem?

**The Theorem (Wreath-Product Automaton Homomorphism):**
Compile the query into a Deterministic Finite State Transducer (Mealy Machine) with state space $Q = \{0, 1, \dots, S-1\}$, initial state $q_0 = 0$, byte transition function $\delta_0: Q \times \Sigma \to Q$, and output emission weight $\omega_0: Q \times \Sigma \to W$, where $(W, \oplus, \mathbf{0})$ is any commutative monoid (e.g., $(\text{u64}, +, 0)$ for match count or matching-line count).

For any string (or grammar node) $X$, define its **Transducer Summary** $\mathcal{T}(X) = (\Delta_X, \Omega_X)$ where:
- $\Delta_X: Q \to Q$ maps every possible entry state $q \in Q$ to the exact exit state $\Delta_X(q) \in Q$ after consuming all bytes of $X$.
- $\Omega_X: Q \to W$ maps every possible entry state $q \in Q$ to the total accumulated weight $\Omega_X(q) \in W$ emitted while consuming all bytes of $X$ starting from state $q$.

**Composition Law ($\star$):**
Given summaries $\mathcal{T}(L) = (\Delta_L, \Omega_L)$ and $\mathcal{T}(R) = (\Delta_R, \Omega_R)$, the summary of their concatenation $X \to L \, R$ is $\mathcal{T}(X) = \mathcal{T}(L) \star \mathcal{T}(R)$ defined for all $q \in Q$ by:
$$\Delta_X(q) = \Delta_R\big(\Delta_L(q)\big)$$
$$\Omega_X(q) = \Omega_L(q) \oplus \Omega_R\big(\Delta_L(q)\big)$$

**Why this eliminates all seam edge cases:**
If a partial regex match begins near the end of $L$, $L$ exits in some state $q_{\text{mid}} = \Delta_L(q_0)$. Because $\mathcal{T}(R)$ has already been precomputed for *every* starting state $q \in Q$, indexing into $\mathcal{T}(R)$ at $q_{\text{mid}}$ seamlessly continues the automaton across the boundary!

**RLE Rule ($X \to A^k$):**
Because $(\mathcal{T}, \star)$ is a strictly associative monoid with identity $\mathcal{I} = (\text{id}_Q, \mathbf{0})$, for any RLE rule $X \to A^k$, we compute $\mathcal{T}(X) = \mathcal{T}(A)^k$ in **$O(S \log_2 k)$ time** via binary exponentiation (repeated squaring)!

**Line-Oriented `grep -c` Construction:**
To count **how many lines** match a regex $R$ (exact `grep -c` semantics):
1. Compile regex $R$ (restricted to non-`\n` characters) into a minimal DFA $D = (Q_D, \delta_D, q_{\text{start}}, F_D)$.
2. Modify all transitions out of accepting states $q_f \in F_D$ on any non-`\n` byte to loop back to $q_f$ (making acceptance sticky until the end of the line: once a line matches $R$, it stays matched until `\n`).
3. On byte `\n` (`0x0A`) from any state $q \in Q_D$:
   - Transition back to $\delta(q, \text{'\n'}) = q_{\text{start}}$.
   - Emit weight $\omega(q, \text{'\n'}) = 1$ if $q \in F_D$, else $0$.
4. At the root node $S_{\text{root}}$, after evaluating $\mathcal{T}(S_{\text{root}})$ starting from $q_0 = q_{\text{start}}$, total matching lines is $\Omega_{S_{\text{root}}}(q_{\text{start}}) + \mathbb{I}[\Delta_{S_{\text{root}}}(q_{\text{start}}) \in F_D \text{ and file does not end with \text{'\n'}}]$.

---

### 2.6 Algebra 3: The Affine Place-Value & Record-Aggregator Monoid (Structured Analytics)
Suppose a compressed log or CSV file contains structured records (e.g., `2026-10-24 status=200 latency=145\n` or CSV `2026-10-24,200,145\n`), and a user runs:
```sql
SELECT COUNT(*), SUM(col_2), MIN(col_2), MAX(col_2), AVG(col_2) WHERE col_1 == "200"
```
What happens if a grammar node boundary splits a multi-digit number right down the middle—e.g., node $L$ ends with `"latency=1"` and node $R$ starts with `"45\n"`?

**The Affine Base-10 Place-Value Monoid:**
Any contiguous sequence of ASCII digits $d_1 d_2 \dots d_m$ has numeric value $v \in \mathbb{N}$ and decimal multiplier $p = 10^m$.
Under concatenation of two digit fragments $(v_1, p_1)$ and $(v_2, p_2)$:
$$(v_1, p_1) \odot (v_2, p_2) = (v_1 \cdot p_2 + v_2, \; p_1 \cdot p_2)$$
For example, `"1"` is $(1, 10^1)$ and `"45"` is $(45, 10^2)$. Their composition is:
$$(1 \times 100 + 45, \; 10^1 \times 10^2) = (145, 10^3)$$
This operation $\odot$ is strictly associative!

Moreover, in Buttlick's compressor (Section 2.2), because `\n` (`0x0A`) is assigned the absolute minimum landmark hash $h(\text{'\n'}) = 0$ at Level 0, every line delimiter acts as a synchronization boundary. And even for arbitrary splits inside lines, combining the **Record-State Transducer** with the **Affine Place-Value Monoid** guarantees exact `COUNT`, `SUM`, `MIN`, `MAX`, and `AVG` over compressed CSV/log datasets without ever decompressing!

---

## 3. Repository Architecture & Crate Layout

The repository at `/home/morg/work_ai/buttlick` shall be structured as a single Cargo workspace (or unified library + binary crate) with clean modular separation:

```text
/home/morg/work_ai/buttlick/
├── Cargo.toml
├── DESIGN_AND_IMPLEMENTATION_PLAN.md
├── README.md
├── src/
│   ├── lib.rs                 # Public library exports & high-level API
│   ├── main.rs                # CLI entry point (`buttlick` binary)
│   ├── error.rs               # Unified `ButtlickError` and `Result<T>` types
│   ├── hash.rs                # Mersenne prime GF(2^61 - 1) rolling hash & splitmix64
│   ├── grammar/
│   │   ├── mod.rs             # `GrammarDag`, `SymbolId`, `Rule`, `RootEntry`
│   │   ├── builder.rs         # Canonical hash-consing table (`RuleInterner`)
│   │   ├── lcp.rs             # Locally Consistent Parsing (Recompression) compressor
│   │   ├── navigate.rs        # O(log N) random access, byte slicing & range hashing
│   │   └── edit.rs            # Persistent O(log N) split, concat, insert, delete, replace_all
│   ├── format/
│   │   ├── mod.rs             # `.btlk` v1 binary serializer & zero-copy mmap reader
│   │   └── header.rs          # Magic bytes, CRC32/XXH3 checksums, section offsets
│   ├── engine/
│   │   ├── mod.rs             # Query planner & dispatcher
│   │   ├── kmp_seam.rs        # Algebra 1: Exact substring KMP seam monoid + offset locator
│   │   ├── transducer.rs      # Algebra 2: Wreath-product Mealy transducer + RLE fast-pow
│   │   ├── regex_compile.rs   # Regex / Glob / Line-grep -> dense DFA transducer compiler
│   │   └── aggregate.rs       # Algebra 3: Zero-decompression structured field aggregator
│   ├── corpus/
│   │   └── mod.rs             # Multi-document / versioned archive manager
│   └── bench/
│       └── mod.rs             # Synthetic log/genomic/git generator & benchmark harness
└── tests/
    ├── roundtrip_tests.rs     # Compression/decompression bit-exactness across edge cases
    ├── query_differential.rs  # Property-based fuzzing: DAG query vs uncompressed oracle
    └── edit_differential.rs   # Property-based fuzzing: DAG edits vs Vec<u8> splice oracle
```

### 3.1 Allowed External Dependencies (`Cargo.toml`)
Keep dependencies lean, battle-tested, and fast to compile:
- `clap = { version = "4", features = ["derive"] }` (CLI parsing)
- `memmap2 = "0.9"` (Zero-copy memory-mapped `.btlk` file execution)
- `rustc-hash = "2.0"` or `ahash = "0.8"` (Fast hash tables for rule interning)
- `regex-automata = "0.4"` (For compiling arbitrary user regex syntax into dense DFAs that we then translate into our Wreath-Product Transducer tables, or custom DFA builder)
- `rayon = "1.10"` (Parallel chunk compression and parallel multi-query evaluation)
- `serde = { version = "1.0", features = ["derive"] }` and `serde_json = "1.0"` (For `--json` CLI output and benchmark reports)
- `thiserror = "2.0"` (Clean error definitions)
- Dev-dependencies: `proptest = "1.5"` or `rand = "0.8"`, `tempfile = "3.10"`

---

## 4. Core Data Structures & In-Memory Representation

### 4.1 `SymbolId` and `Rule`
```rust
/// A symbol in the RLSLP grammar.
/// IDs 0..=255 are literal terminal bytes (0x00..=0xFF).
/// IDs >= 256 are non-terminal rules stored at index (id - 256) in `GrammarDag::rules`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct SymbolId(pub u32);

impl SymbolId {
    pub const FIRST_NON_TERMINAL: u32 = 256;

    #[inline(always)]
    pub const fn is_terminal(self) -> bool {
        self.0 < Self::FIRST_NON_TERMINAL
    }

    #[inline(always)]
    pub const fn as_byte(self) -> Option<u8> {
        if self.0 < 256 { Some(self.0 as u8) } else { None }
    }

    #[inline(always)]
    pub const fn rule_index(self) -> usize {
        debug_assert!(self.0 >= Self::FIRST_NON_TERMINAL);
        (self.0 - Self::FIRST_NON_TERMINAL) as usize
    }
}

/// Canonical production rule for a non-terminal symbol.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RuleKind {
    /// Concatenation: X -> left right (where left != right)
    Pair { left: SymbolId, right: SymbolId },
    /// Run-Length Encoding: X -> child^count (where count >= 2)
    Run { child: SymbolId, count: u64 },
}

/// Complete metadata stored per non-terminal rule in the DAG.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RuleNode {
    pub kind: RuleKind,
    /// Total uncompressed byte length of this symbol's expansion.
    pub byte_len: u64,
    /// Precomputed homomorphic Karp-Rabin hash in GF(2^61 - 1).
    pub kr_hash: u64,
    /// Precomputed B^{byte_len} mod (2^61 - 1).
    pub kr_pow: u64,
    /// Subtree height (terminals have height 0).
    pub height: u16,
    /// First byte of expansion (fast-path for seam/navigation).
    pub first_byte: u8,
    /// Last byte of expansion (fast-path for seam/navigation).
    pub last_byte: u8,
}
```

### 4.2 Named Roots (Multi-Document & Empty-File Support)
```rust
/// Represents a top-level document or version inside a Buttlick archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootEntry {
    pub name: String,
    /// `None` if and only if the document is 0 bytes (empty).
    pub root_symbol: Option<SymbolId>,
    pub byte_len: u64,
    pub kr_hash: u64,
}
```

### 4.3 Topological Ordering Invariant
**CRITICAL INVARIANT:**
In `GrammarDag::rules`, for every rule at index `idx` (corresponding to `SymbolId(idx as u32 + 256)`), any child symbol (`left`, `right`, or `child`) MUST have `child_id.0 < idx as u32 + 256`.
*Why this matters:*
Because children always have strictly smaller `SymbolId`s than their parents, **evaluating any bottom-up query across the entire DAG requires ZERO recursion and ZERO graph traversal overhead**—it is literally a single flat forward loop `for idx in 0..dag.rules.len()` over a contiguous slice!
If an edit operation (`insert`/`concat`/`replace_all`) creates new rules after initial construction, new rules are appended to `dag.rules` from bottom to top, which automatically preserves the topological invariant `child.0 < parent.0`.

---

## 5. On-Disk Binary Format Specification (`.btlk` v1)

A `.btlk` file is a self-contained, little-endian binary container designed so that the rule table can be mapped directly into virtual memory via `mmap` or read in a single sequential read.

### 5.1 Binary Layout
```text
+-----------------------------------------------------------------------+
| 1. File Header (64 bytes, fixed size, 8-byte aligned)                 |
+-----------------------------------------------------------------------+
| 2. Root Table Section (variable size, padded to 8-byte alignment)     |
|    - Contains metadata & names for 1..M named roots                   |
+-----------------------------------------------------------------------+
| 3. Packed Rule Table Section (N_rules * 32 bytes, 8-byte aligned)     |
|    - Contiguous array of `PackedRuleNode` structs (32 bytes each)     |
+-----------------------------------------------------------------------+
| 4. Footer Checksum (8 bytes)                                          |
|    - 64-bit hash over bytes [0 .. file_len - 8]                       |
+-----------------------------------------------------------------------+
```

### 5.2 Header Layout (64 Bytes, Little-Endian)
| Byte Offset | Type | Field Name | Description |
| :--- | :--- | :--- | :--- |
| `0..8` | `[u8; 8]` | `magic` | Exact ASCII bytes `b"BTLK\x00\x01\x00\x00"` (v1) |
| `8..16` | `u64` | `flags` | Bitflags (Bit 0: line-anchored LCP) |
| `16..24` | `u64` | `num_roots` | Number of `RootEntry` records |
| `24..32` | `u64` | `num_rules` | Number of non-terminal `PackedRuleNode`s |
| `32..40` | `u64` | `roots_offset` | Byte offset of Root Table Section (always 64) |
| `40..48` | `u64` | `rules_offset` | Byte offset of Packed Rule Table Section (aligned to 8) |
| `48..56` | `u64` | `total_uncompressed_bytes` | Sum of `byte_len` across all roots |
| `56..64` | `u64` | `header_checksum` | SplitMix64/FNV1a/XXH checksum of bytes `0..56` |

### 5.3 Packed Rule Node (32 Bytes, `#[repr(C)]`, Little-Endian)
Each non-terminal rule `i` (`0..num_rules`) is serialized as exactly 32 bytes:
- `tag_and_meta: u32`:
  - Bit 0: `0` = `Pair`, `1` = `Run`
  - Bits `1..16`: `height` (`u16`, clamped to `32767`)
  - Bits `16..24`: `first_byte` (`u8`)
  - Bits `24..32`: `last_byte` (`u8`)
- `child_a: u32`: `left.0` (if `Pair`) or `child.0` (if `Run`)
- `child_b_or_count: u64`: `right.0 as u64` (if `Pair`) or `count` (if `Run`)
- `byte_len: u64`: Uncompressed byte length of this rule
- `kr_hash: u64`: 61-bit Karp-Rabin hash (Note: `kr_pow` can either be stored or recomputed on load in one linear pass in $< 2$ ms; recomputing `kr_pow` on load keeps `PackedRuleNode` at exactly 32 bytes = 2 nodes per 64-byte CPU cache line!).

---

## 6. Detailed Algorithm Specifications (Reference Implementation Logic)

### 6.1 Algorithm 1: Locally Consistent Grammar Compression (`compress`)

#### Step 1: Mersenne Field Arithmetic (`src/hash.rs`)
Define modulus $P = 2^{61} - 1 = \text{0x1FFF\_FFFF\_FFFF\_FFFF}$ and base $B = 257$.
```rust
pub const MOD_P: u64 = (1u64 << 61) - 1;
pub const HASH_BASE: u64 = 257;

#[inline(always)]
pub const fn mod_add(a: u64, b: u64) -> u64 {
    let s = a + b;
    let s = (s & MOD_P) + (s >> 61);
    if s >= MOD_P { s - MOD_P } else { s }
}

#[inline(always)]
pub const fn mod_sub(a: u64, b: u64) -> u64 {
    if a >= b { a - b } else { MOD_P - (b - a) }
}

#[inline(always)]
pub const fn mod_mul(a: u64, b: u64) -> u64 {
    let prod = (a as u128) * (b as u128);
    let lo = (prod as u64) & MOD_P;
    let hi = (prod >> 61) as u64;
    mod_add(lo, hi)
}

pub const fn mod_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut res = 1u64;
    while exp > 0 {
        if exp & 1 == 1 {
            res = mod_mul(res, base);
        }
        base = mod_mul(base, base);
        exp >>= 1;
    }
    res
}

/// Computes (1 + r + r^2 + ... + r^{k-1}) mod P in O(log k) time without division.
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
```

#### Step 2: Landmark Priority Function
To ensure line-oriented logs/CSV files naturally break at newline (`0x0A`) boundaries while remaining 100% general for binary data:
```rust
#[inline(always)]
pub const fn landmark_hash(sym: SymbolId) -> u64 {
    // Give '\n' (10) the absolute lowest hash (0) so every newline is a local minimum landmark!
    if sym.0 == b'\n' as u32 {
        return 0;
    }
    // Bijective SplitMix64 mixer mapped into [1, u64::MAX]
    let mut z = (sym.0 as u64).wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    let val = z ^ (z >> 31);
    if val == 0 { 1 } else { val }
}
```

#### Step 3: Iterative Recompression Loop (`src/grammar/lcp.rs`)
Given an initial symbol vector `seq: Vec<SymbolId>` (initialized from `input.iter().map(|&b| SymbolId(b as u32)).collect()`):
1. If `seq.is_empty()`, return `None` (empty document).
2. While `seq.len() > 1`:
   - **Phase A (Run-Length Contraction):**
     Scan `seq` and collapse any maximal run `seq[i..i+k]` where `k >= 2` and all elements equal `sym` into `interner.intern_run(sym, k as u64)`.
     If `seq.len() == 1`, break!
   - **Phase B (Local Minimum Block Partitioning):**
     Now `seq[i] != seq[i+1]` for all `0 <= i < seq.len() - 1`, which also means `landmark_hash(seq[i]) != landmark_hash(seq[i+1])`!
     We partition `seq` into blocks of length 2 or 3 (and occasionally 1 at boundaries) by placing a **cut** before index `i` (`0 < i < seq.len()`) according to:
     - First, mark index `i` (`0 < i < seq.len() - 1`) as a **Primary Landmark** if:
       `landmark_hash(seq[i]) < landmark_hash(seq[i - 1]) && landmark_hash(seq[i]) < landmark_hash(seq[i + 1])`.
       *(Note: By strict inequality, two adjacent indices `i` and `i+1` can NEVER both be primary landmarks!)*
     - Every Primary Landmark starts a new block (cut before `i`).
     - Within any span between two cuts of length $L \ge 4$, greedily cut into pairs of length 2 from left to right (leaving a final block of length 2 or 3 at the right end of the span).
     - Contract each resulting block:
       - Length 1 `[a]`: emit `a`
       - Length 2 `[a, b]`: emit `interner.intern_pair(a, b)`
       - Length 3 `[a, b, c]`: emit `interner.intern_pair(interner.intern_pair(a, b), c)`
   - Replace `seq` with the newly contracted vector and repeat!
3. Return `Some(seq[0])`.

**Why this algorithm is rock-solid:**
- In Phase B, every block of length 2 shrinks by $1/2$, and every block of length 3 shrinks by $2/3$. Even if a single uncontracted symbol `[a]` sits at the very start before the first landmark, the total length strictly decreases by at least $\lfloor \text{len} / 3 \rfloor$ on every iteration!
- It **never** enters an infinite loop and guarantees tree depth $\le 2.5 \log_2 N$.

---

### 6.2 Algorithm 2: $O(\log N)$ Random Access, Slicing & $O(\log N)$ Fingerprinting

#### 1. Random Access (`byte_at(sym: SymbolId, offset: u64) -> u8`)
```rust
pub fn byte_at(&self, mut sym: SymbolId, mut offset: u64) -> u8 {
    loop {
        if let Some(b) = sym.as_byte() {
            debug_assert_eq!(offset, 0);
            return b;
        }
        let node = &self.rules[sym.rule_index()];
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
```

#### 2. Range Decomposition (`decompose_range(sym: SymbolId, start: u64, end: u64)`)
Any byte interval $[start, end)$ inside `sym` can be decomposed in $O(\log N)$ time into a sequence of at most $2 H$ canonical pieces `(SymbolId, repeat_count: u64)` whose concatenation equals the exact substring `S[start..end]`:
- If `start == 0 && end == self.sym_len(sym)`, emit `(sym, 1)` and return!
- If `sym` is `Pair { left, right }`:
  - Recurse on `left` for `[start, min(end, left_len))` if `start < left_len`.
  - Recurse on `right` for `[max(start, left_len) - left_len, end - left_len)` if `end > left_len`.
- If `sym` is `Run { child, count }`:
  - Let `c_len = self.sym_len(child)`.
  - Let `first_idx = start / c_len`, `first_rem = start % c_len`.
  - Let `last_idx = (end - 1) / c_len`, `last_rem = (end - 1) % c_len + 1`.
  - If `first_idx == last_idx`: recurse on `child` for `[first_rem, last_rem)`.
  - Else:
    1. If `first_rem > 0`: recurse on `child` for `[first_rem, c_len)` and increment `first_idx += 1`.
    2. Let `full_runs = last_idx - first_idx` (after adjusting if `last_rem == c_len`). Emit `(child, full_runs)` in $O(1)$!
    3. If `last_rem < c_len`: recurse on `child` for `[0, last_rem)`.

**Consequences of `decompose_range`:**
1. **$O(\log N)$ Range Hash (`range_hash(root, start, len)`):** Fold the $O(\log N)$ pieces `(sym, repeat_count)` using `mod_mul`, `mod_add`, and `geom_sum` in $O(\log N)$ time!
2. **$O(\log N)$ Substring Equality (`substring_eq(root, pos1, pos2, len)`):** Compare `range_hash(root, pos1, len) == range_hash(root, pos2, len)`. (Collision probability $\le 1 / (2^{61} - 1) \approx 4.3 \times 10^{-19}$; optionally verify with a second hash or structural walk).
3. **$O(\log N + \text{len})$ Slice Extraction (`extract_slice(root, start, len, out)`):** Expand only the decomposed pieces directly into `out`.

---

### 6.3 Algorithm 3: KMP Seam-Tracking Exact Search & Lazy Offset Extraction

Given pattern $P[0..m]$:
1. **Prefix / Suffix Helper:**
   Using `extract_slice(sym, 0, min(len, m - 1))` and `extract_slice(sym, len - min(len, m - 1), min(len, m - 1))`, we can obtain the $(m-1)$-byte prefix and suffix of any rule (or better yet, memoize them during the single bottom-up pass so each rule constructs its prefix/suffix by concatenating its children's prefixes/suffixes in $O(m)$ time!).
2. **Bottom-Up Evaluation (`count_counts: Vec<u64>`):**
   Allocate `counts = vec![0u64; dag.rules.len()]`, `prefixes`, and `suffixes`.
   Iterate `idx` from `0` to `dag.rules.len() - 1`:
   - For `Pair { left, right }`:
     - Construct `seam = suffix(left, m - 1) + prefix(right, m - 1)`.
     - `seam_matches = kmp_count(&seam, pattern, &kmp_pi)`.
     - `counts[idx] = count(left) + count(right) + seam_matches`.
   - For `Run { child, count: k }`:
     - Use binary exponentiation on a small struct `Chunk { len: u64, count: u64, prefix: SmallVec<[u8; 64]>, suffix: SmallVec<[u8; 64]> }` initialized from `child` and squared $\lfloor \log_2 k \rfloor$ times using the exact same `Pair` combination rule!
     - Why binary exponentiation of `Chunk` is superior to case-splitting on `len(child) < m - 1`: It is **15 lines of code**, runs in $O(m \log k)$ time, and **automatically handles every possible overlap where a pattern spans 2, 3, or 50 short RLE copies** with zero special cases!

3. **Lazy Top-$K$ Match Byte Offset Extraction (`locate_matches`):**
   Once `counts[idx]` is computed in $O(n \cdot m)$ time, how do we return the exact 64-bit byte offsets of the first $K$ matches (or all matches) in $O(\log N)$ time per match?
   Define recursive generator `collect_offsets(sym, base_offset, limit, out)`:
   - If `count(sym) == 0 || out.len() >= limit`, **return immediately** (skipping gigabytes of non-matching subtrees in $O(1)$!).
   - If `sym` is a terminal and `m == 1`: push `base_offset`.
   - If `sym` is `Pair { left, right }`:
     1. Recurse on `left` with `base_offset`.
     2. Check the seam `suffix(left, m - 1) + prefix(right, m - 1)`: for each match at index `p` in the seam buffer, its global byte offset is `base_offset + len(left) - suffix_len(left) + p`. Push to `out`.
     3. Recurse on `right` with `base_offset + len(left)`.
   - If `sym` is `Run { child, count: k }`:
     - Notice that inside $A^k$, once a prefix of copies covers at least $m - 1$ bytes, all subsequent copies are periodic with period `len(child)`!
     - Even simpler: treat $A^k$ as a virtual balanced binary tree of splits $A^{\lfloor k/2 \rfloor}$ and $A^{k - \lfloor k/2 \rfloor}$, descending only when `out.len() < limit`!

---

### 6.4 Algorithm 4: Wreath-Product Automaton Evaluation (Regex, Multi-Pattern & Line Grep)

1. **Transducer Table Representation (`src/engine/transducer.rs`):**
   ```rust
   pub struct MealyTransducer {
       pub num_states: usize,
       pub start_state: u16,
       /// Flattened [state * 256 + byte] -> next_state
       pub byte_next: Vec<u16>,
       /// Flattened [state * 256 + byte] -> emitted weight (e.g. 0 or 1)
       pub byte_emit: Vec<u64>,
   }

   #[derive(Clone, Debug)]
   pub struct NodeTransducerSummary {
       /// For each entry state q in 0..num_states, the exit state after this node.
       pub next_state: Vec<u16>,
       /// For each entry state q in 0..num_states, the total weight emitted inside this node.
       pub emit_sum: Vec<u64>,
   }
   ```
2. **Composition (`compose(left, right)`):**
   ```rust
   pub fn compose(
       left: &NodeTransducerSummary,
       right: &NodeTransducerSummary,
       out: &mut NodeTransducerSummary,
   ) {
       let s = left.next_state.len();
       for q in 0..s {
           let mid = left.next_state[q] as usize;
           out.next_state[q] = right.next_state[mid];
           out.emit_sum[q] = left.emit_sum[q] + right.emit_sum[mid];
       }
   }
   ```
3. **RLE Binary Exponentiation (`power(base, k)`):**
   ```rust
   pub fn power(base: &NodeTransducerSummary, mut k: u64) -> NodeTransducerSummary {
       let s = base.next_state.len();
       let mut result = NodeTransducerSummary {
           next_state: (0..s as u16).collect(),
           emit_sum: vec![0; s],
       };
       let mut cur = base.clone();
       let mut scratch = result.clone();
       while k > 0 {
           if k & 1 == 1 {
               compose(&result, &cur, &mut scratch);
               std::mem::swap(&mut result, &mut scratch);
           }
           k >>= 1;
           if k > 0 {
               compose(&cur, &cur, &mut scratch);
               std::mem::swap(&mut cur, &mut scratch);
           }
       }
       result
   }
   ```
4. **Regex & Line-Grep Compilation (`src/engine/regex_compile.rs`):**
   We support two modes over the Wreath-Product Transducer:
   - **Mode A: Line-Oriented Regex Match Counting (`grep -c <pattern>`):**
     Uses `regex_automata::dfa::dense::DFA` (configured with `syntax::Config::new().multi_line(false)` or line-scoped) to build the state table over bytes `0..=255`.
     - Designate state `MATCHED_LINE` as a sticky accepting state for the current line: whenever any byte `b != b'\n'` transitions into an accepting DFA state, transition to `MATCHED_LINE` (which loops to `MATCHED_LINE` on all `b != b'\n'`).
     - On `b == b'\n'`: from any state `q`, if `q == MATCHED_LINE` (or `q` is accepting), emit `byte_emit[q * 256 + 10] = 1`, else `0`; and reset `byte_next[q * 256 + 10] = start_state`.
     - If the file's last byte is not `\n` and the final exit state `final_q = root_summary.next_state[start_state]` is `MATCHED_LINE` (or accepting after EOF transition), add `+1` to the final count.
     *Result:* Guaranteed bit-identical output to `grep -E -c` or `ripgrep --count` on any file, evaluated in $O(n \cdot S)$ time without decompressing!
   - **Mode B: Non-Overlapping Leftmost-Shortest / Leftmost-First Regex Match Counting:**
     Whenever a byte transition reaches an accepting state, emit `+1` and immediately reset to `start_state` (for non-overlapping token/pattern counting).

---

### 6.5 Algorithm 5: Zero-Decompression Structured Field Analytics (`SUM`, `MIN`, `MAX`, `COUNT`, `AVG`)

To run structured analytical queries on delimited records (CSV, TSV, space-delimited or `key=value` logs) directly on the compressed grammar DAG:

#### Query Specification
- `delimiter: u8` (e.g., `b','`, `b'\t'`, `b' '`)
- `filter_col: Option<(usize, Vec<u8>)>` (optional equality filter: column `col_idx` equals literal bytes `val`)
- `target_col: usize` (column index containing integer/fixed-point numbers to aggregate)

#### How It Works Over the Grammar DAG
Because newline `\n` has landmark priority `0` in our LCP compressor, every multi-line rule in a line-anchored DAG splits cleanly on `\n` boundaries!
Furthermore, to work on **both** line-anchored and arbitrary non-line-anchored DAGs (where a node boundary can split right inside the middle of a line or inside a multi-digit number!), we define the **Record-Stream Monoid Summary** for every node $X$:
- If node $X$ contains **no newline `\n`** (`has_newline == false`):
  - It stores its field transitions within a single line: `(fields_completed: usize, prefix_bytes, suffix_bytes)` or for `key=value` mode, its transducer summary.
- Even cleaner and 100% universal: We model the CSV / Log parser as a deterministic state machine over the byte stream with states tracking:
  - Current column index `col` (`0..=max_col + 1`)
  - Filter match status (`FilterPending`, `FilterMatched`, `FilterFailed`)
  - Target number accumulator using the **Affine Base-10 Monoid** `(val: i64, pow10: i64, sign: i8, has_digits: bool)`
  - Running aggregate `(count: u64, sum: i128, min: i64, max: i64)` committed whenever `\n` is reached and `FilterMatched` is true!
- And for fast-path evaluation on any grammar node $X$ whose `first_byte` is the start of a line and `last_byte == b'\n'` (which is true for all inter-line nodes due to `landmark_hash(b'\n') == 0`!), the entry state is **always** `(col = 0, FilterPending, acc = 0)` and the exit state is **always** `(col = 0, FilterPending, acc = 0)`!
  Therefore:
  - Every complete-line node simply stores a single scalar struct:
    ```rust
    pub struct AggregateSummary {
        pub count: u64,
        pub sum: i128,
        pub min: i64,
        pub max: i64,
    }
    ```
  - Combining two complete-line nodes $L$ and $R$ is simply:
    ```rust
    count = L.count + R.count;
    sum   = L.sum + R.sum;
    min   = L.min.min(R.min);
    max   = L.max.max(R.max);
    ```
  - And for an RLE node $X \to A^k$ of complete lines:
    ```rust
    count = k * A.count;
    sum   = (k as i128) * A.sum;
    min   = A.min;
    max   = A.max;
    ```
  - For intra-line nodes (nodes with no `\n` or partial lines at boundaries), a node with `has_newline == false` and length $\le 4096$ either memoizes its byte slice or combines at the first node that closes a line (`last_byte == b'\n'`)!

Let's verify this! If a node $X$ has no `\n` inside it, can it complete a line? No! And as soon as two intra-line nodes are joined at a `\n` seam, that line is parsed **once**, converted into an `AggregateSummary { count, sum, min, max }`, and every ancestor node above it in the 1-Terabyte DAG just adds two integers (`L.sum + R.sum`) and takes `L.min.min(R.min)`!

---

### 6.6 Algorithm 6: Dynamic $O(\log N)$ Persistent DAG Edits (`concat`, `split`, `insert`, `delete`, `replace_all`)

All edits operate directly on `GrammarDag` without decompressing the file:

1. **`concat(sym_a: Option<SymbolId>, sym_b: Option<SymbolId>) -> Option<SymbolId>`:**
   - If either is `None`, return the other.
   - If `sym_a == sym_b`, return `Some(interner.intern_run(sym_a, 2))` (or merge runs if both are `Run` of the same child!).
   - Otherwise, return `Some(interner.intern_pair(sym_a, sym_b))` (rebalancing if height difference exceeds threshold via tree rotations or merging the $O(\log N)$ right spine of `sym_a` with the $O(\log N)$ left spine of `sym_b`).

2. **`split(sym: SymbolId, offset: u64) -> (Option<SymbolId>, Option<SymbolId>)`:**
   Splits `sym` at byte index `offset` ($0 \le \text{offset} \le \text{len}(\text{sym})$) in $O(\log N)$ time:
   - If `offset == 0`, return `(None, Some(sym))`.
   - If `offset == len(sym)`, return `(Some(sym), None)`.
   - If `sym` is `Pair { left, right }`:
     - If `offset == len(left)`, return `(Some(left), Some(right))`.
     - If `offset < len(left)`:
       Let `(l1, l2) = split(left, offset)`.
       Return `(l1, concat(l2, Some(right)))`.
     - If `offset > len(left)`:
       Let `(r1, r2) = split(right, offset - len(left))`.
       Return `(concat(Some(left), r1), r2)`.
   - If `sym` is `Run { child, count }`:
     - Let `c_len = len(child)`, `q = offset / c_len`, `r = offset % c_len`.
     - Left full copies: `left_runs = if q == 0 { None } else if q == 1 { Some(child) } else { Some(intern_run(child, q)) }`.
     - Right full copies: `rem_runs = count - q - (if r > 0 { 1 } else { 0 })`.
     - If `r == 0`, return `(left_runs, right_runs)`.
     - If `r > 0`, let `(c1, c2) = split(child, r)` and return `(concat(left_runs, c1), concat(c2, right_runs))`.

3. **`insert(root: Option<SymbolId>, offset: u64, bytes: &[u8]) -> Option<SymbolId>`:**
   - Compress `bytes` into `mid_sym = compress(bytes)`.
   - Split `root` at `offset` into `(left, right)`.
   - Return `concat(concat(left, mid_sym), right)`. Time complexity: $O(\log N + |bytes|)$.

4. **`delete(root: Option<SymbolId>, start: u64, len: u64) -> Option<SymbolId>`:**
   - Split `root` at `start` into `(left, rest)`.
   - Split `rest` at `len` into `(_deleted, right)`.
   - Return `concat(left, right)`. Time complexity: $O(\log N)$.

5. **`replace_all(root: Option<SymbolId>, pattern: &[u8], replacement: &[u8]) -> Option<SymbolId>`:**
   Replaces every non-overlapping occurrence of `pattern` with `replacement` across a 1-Terabyte DAG in $O(n \cdot |P|)$ time:
   - First run `count_matches` across all rules.
   - Any rule `X` with `count(X) == 0` is **completely unchanged** (returned as-is in $O(1)$!).
   - For any rule `X` where `count(X) > 0`, recursively rewrite its children, resolve any matches across the seam of `X` using `split` and `concat` with `replacement_sym`, and memoize `rewritten[X]`!
   *Result:* Replacing `"ERROR"` with `"FIXED"` 100 million times across a 1-Terabyte file finishes in milliseconds!

---

### 6.7 Algorithm 7: Multi-Document / Versioned Corpus Ingestion & Cross-Version Querying

Because `GrammarDag` supports multiple `RootEntry` records (`roots: Vec<RootEntry>`) sharing the exact same `RuleInterner` and `rules: Vec<RuleNode>`:
- Ingesting 100 versions of a log file, 1,000 git snapshots, or 100 genomic sequences simply runs `lcp::compress_into_dag(&mut dag, name, bytes)` for each document.
- Every identical block across any of the 1,000 documents maps to the **exact same `SymbolId`** in `dag.rules`.
- When you run a query (`count`, `grep`, `query`) across all 1,000 documents:
  1. Buttlick runs the bottom-up evaluation pass **once** across `dag.rules` (`0..dag.rules.len()`).
  2. It then reads out the answer for all 1,000 documents in $O(1)$ per document by simply indexing `counts[root.symbol]`!

---

## 7. Command-Line Interface (`buttlick`) Specification

The `buttlick` binary must implement the following subcommands cleanly using `clap`:

```bash
# 1. Compress one or more files into a .btlk archive
buttlick compress <INPUT_FILES>... -o <OUTPUT.btlk> [--stats]

# 2. Decompress a .btlk archive (or specific named root) back to raw bytes
buttlick decompress <INPUT.btlk> [-o <OUTPUT_FILE>] [--doc <NAME>]

# 3. Inspect DAG structure, compression ratio, tree depth, and rule statistics
buttlick inspect <INPUT.btlk> [--json]

# 4. O(log N) random-access byte slice extraction (without decompressing the rest of the file)
buttlick slice <INPUT.btlk> --start <OFFSET> --len <LENGTH> [--doc <NAME>]

# 5. O(log N) substring equality check between two arbitrary ranges (even multi-gigabyte ranges!)
buttlick eq <INPUT.btlk> --pos1 <OFFSET1> --pos2 <OFFSET2> --len <LENGTH> [--doc <NAME>]

# 6. Zero-decompression exact substring search (count + optional byte offsets)
buttlick count <INPUT.btlk> <PATTERN> [--offsets] [--limit <K>] [--doc <NAME>]

# 7. Zero-decompression regular expression search & line-count (`grep -E -c` equivalent)
buttlick grep <INPUT.btlk> <REGEX> [--line-count | --match-count] [--doc <NAME>]

# 8. Zero-decompression structured analytics (CSV / TSV / Log column aggregations)
buttlick query <INPUT.btlk> --delimiter <CHAR> --col <INDEX> [--where-col <IDX> --where-eq <STR>] [--json]

# 9. Zero-decompression persistent edits directly on .btlk files
buttlick edit <INPUT.btlk> -o <OUTPUT.btlk> <SUBCOMMAND>
  buttlick edit <IN.btlk> -o <OUT.btlk> insert --offset <POS> --text <STRING>
  buttlick edit <IN.btlk> -o <OUT.btlk> delete --offset <POS> --len <LEN>
  buttlick edit <IN.btlk> -o <OUT.btlk> replace --pattern <PAT> --with <REPL>
  buttlick edit <IN.btlk> -o <OUT.btlk> concat --doc1 <NAME1> --doc2 <NAME2> --new-name <NAME>

# 10. Built-in Benchmark Suite (generates synthetic repetitive datasets & compares Buttlick vs raw scan)
buttlick bench [--size-mb <MB>] [--json]
```

---

## 8. Subtle Edge Cases, Pitfalls & Mandatory Safeguards

Any engineer or LLM implementing this specification MUST guard against the following subtle failure modes:

1. **Pitfall 1: Overlapping Matches Across Seams in `kmp_seam.rs`**
   - *Bug:* If you take more than `m - 1` bytes from `left`'s suffix or `right`'s prefix when forming the seam buffer, a match completely inside `left` or `right` will be counted a second time in the seam!
   - *Fix:* Strictly clamp `left_suffix_len = left_len.min(m - 1)` and `right_prefix_len = right_len.min(m - 1)`. Because `left_suffix_len < m` and `right_prefix_len < m`, no match of length `m` can fit wholly inside the left half or wholly inside the right half of the seam buffer.

2. **Pitfall 2: RLE Nodes Where `len(child) < m - 1` in Exact Search**
   - *Bug:* Suppose pattern is `"AAAAA"` ($m = 5$) and the rule is $X \to \text{'A'}^{10}$, or pattern is `"ABABAB"` ($m = 6$) and rule is $X \to (\text{"AB"})^{10}$. Here a single match spans *more than 2 copies* of `child`, so checking only a single $A \, A$ seam undercounts!
   - *Fix:* As specified in Section 6.3, NEVER use a naive `k * count(A) + (k - 1) * seam(A, A)` formula when `len(A) < m - 1`. Always use the **Binary Exponentiation of `SeamChunk` (`power_chunk(child_chunk, k)`)**, which combines virtual halves via the exact `Pair` seam rule in $O(m \log k)$ steps and is 100% exact for all periodic and tiny-child RLE rules!

3. **Pitfall 3: `replace_all` Overlapping Match Semantics**
   - *Bug:* If pattern is `"AA"` and text is `"AAAA"`, standard non-overlapping left-to-right replacement of `"AA" -> "B"` produces `"BB"`, NOT `"B B"` with a middle overlap!
   - *Fix:* When rewriting a node `X` in `replace_all`, if a match occurs across the seam of `L` and `R`, consume the matched bytes greedily from left to right; if multiple matches overlap in the seam or RLE period, resolve the greedy left-to-right non-overlapping match intervals `[s_i, e_i)` and reconstruct via `split` and `concat`.

4. **Pitfall 4: Mersenne Prime Overflow in `u64` Addition**
   - *Bug:* `2 * MOD_P` is `2^62 - 2`, which fits in `u64`, so `a + b` in `mod_add` never overflows `u64` as long as `a < MOD_P` and `b < MOD_P`. However, `a * b` requires `u128` before folding `(prod & MOD_P) + (prod >> 61)`. Always use `u128` for multiplication in `mod_mul`.

5. **Pitfall 5: Empty Files & Single-Byte Files**
   - *Bug:* Passing a 0-byte slice or 1-byte slice to LCP compression or query engines.
   - *Fix:* `RootEntry::root_symbol` is `Option<SymbolId>`. When `root_symbol == None` (0 bytes), all counts are `0`, slices of length `0` return `b""`, and decompression outputs `b""`. When `byte_len == 1`, `root_symbol` is `Some(SymbolId(byte as u32))` (a terminal leaf with 0 non-terminal rules in `dag.rules`). Every query engine must handle terminal root symbols (`sym.is_terminal()`) cleanly!

6. **Pitfall 6: Final Line Without Trailing `\n` in Line-Grep and Structured Aggregation**
   - *Bug:* A file `"hello\nworld"` has 2 lines, even though the second line does not end with `\n`.
   - *Fix:* Both `grep --line-count` and `query` must flush the active line state at EOF if the root node has `byte_len > 0` and `last_byte != b'\n'`.

---

## 9. Phased Implementation Roadmap & Verification Suite

The implementing agent must execute the following phases sequentially, running `cargo test` after every phase until all unit and differential property tests pass with 0 warnings.

### Phase 1: Project Scaffolding, Mersenne Hashing & Core DAG Types
- Initialize `Cargo.toml` and module structure (`src/lib.rs`, `src/error.rs`, `src/hash.rs`, `src/grammar/mod.rs`, `src/grammar/builder.rs`).
- Implement `SymbolId`, `RuleKind`, `RuleNode`, `RootEntry`, `RuleInterner`, and GF($2^{61}-1$) math (`mod_add`, `mod_mul`, `mod_pow`, `geom_sum`).
- **Verification:** Write unit tests verifying that `geom_sum(r, k)` matches brute-force loop $\sum_{i=0}^{k-1} r^i \pmod P$ for $k \in \{0, 1, 2, 3, 7, 64, 100000\}$ and that hash-consing deduplicates identical `Pair` and `Run` rules.

### Phase 2: Locally Consistent Parsing (LCP) Compressor & Exact Decompression
- Implement `src/grammar/lcp.rs` (`compress`, `compress_named`, `decompress`).
- **Verification:**
  - Test empty `b""`, single-byte `b"a"`, pure run `vec![b'x'; 100_000]`, alternating `b"abababab..."`, and realistic multi-megabyte log/CSV data.
  - Assert that `decompress(compress(data)) == data` bit-for-bit on 1,000 random & structured inputs.
  - Assert that compressing `vec![b'A'; 1_000_000_000]` (or 100 MB) creates only 1 non-terminal `Run` rule!

### Phase 3: $O(\log N)$ Navigation, Slicing & Substring Equality
- Implement `src/grammar/navigate.rs` (`byte_at`, `decompose_range`, `extract_slice`, `range_hash`, `substring_eq`).
- **Verification:**
  - Property test: For random strings and repetitive strings of length up to 100,000, verify that `byte_at(i) == raw[i]`, `extract_slice(start, len) == &raw[start..start+len]`, and `substring_eq(p1, p2, len) == (&raw[p1..p1+len] == &raw[p2..p2+len])` across 5,000 random queries.

### Phase 4: On-Disk `.btlk` Binary Format & `mmap` Zero-Copy Reader
- Implement `src/format/header.rs` and `src/format/mod.rs` (serialization to `.btlk`, checksum verification, and loading via `memmap2`).
- **Verification:**
  - Round-trip test: Compress multiple documents into a `.btlk` file on disk, reopen via `mmap`, verify header & footer checksums, and verify bit-exact decompression and corruption detection (flipping 1 bit in the file must return `ButtlickError::ChecksumMismatch`).

### Phase 5: Algebra 1 — KMP Seam-Tracking Exact Search & Lazy Offset Locator
- Implement `src/engine/kmp_seam.rs` (`count_literal`, `locate_literal`).
- **Verification:**
  - Differential fuzz test: Generate 500 random & highly periodic inputs (including adversarial overlapping patterns like `"AAA"` in `"AAAAAAAAA"` and `"ABAB"` in `"ABABABABAB"`) and verify that:
    1. `count_literal` matches brute-force overlapping and non-overlapping substring counts across the uncompressed bytes.
    2. `locate_literal` returns the **exact same vector of 64-bit byte offsets** as scanning the uncompressed byte slice!

### Phase 6: Algebra 2 & 3 — Wreath-Product Regex Transducer & Structured Aggregator
- Implement `src/engine/transducer.rs`, `src/engine/regex_compile.rs`, and `src/engine/aggregate.rs`.
- **Verification:**
  - Differential test for `grep`: Compare `buttlick` regex line-counts and match-counts on synthetic log files (with and without trailing `\n`) against running `regex::Regex` line-by-line on the uncompressed string.
  - Differential test for `aggregate`: Generate 10,000-line CSV and server log datasets (including negative numbers, zero, large integers, and filtered rows), compress them, and assert that `COUNT`, `SUM`, `MIN`, `MAX`, and `AVG` computed homomorphically on the DAG match brute-force row-by-row parsing on the uncompressed data to the exact bit!

### Phase 7: Dynamic $O(\log N)$ Persistent Edits & Multi-Document Corpus
- Implement `src/grammar/edit.rs` (`split`, `concat`, `insert`, `delete`, `replace_all`) and `src/corpus/mod.rs`.
- **Verification:**
  - Differential fuzz test: Start with a compressed buffer, apply a random sequence of 100 `insert`, `delete`, `concat`, and `replace_all` operations directly on the `GrammarDag`, and after *every single operation*, assert that:
    1. `dag.decompress()` equals the reference `Vec<u8>` with the same operation applied!
    2. Subsequent `count_literal`, `grep`, and `substring_eq` queries on the edited DAG still return 100% exact results!

### Phase 8: CLI (`buttlick`) & Benchmark Suite
- Implement `src/main.rs` and `src/bench/mod.rs` covering all 10 CLI subcommands in Section 7.
- Run `buttlick bench` to verify that on a 1 GB repetitive log/genomic dataset, Buttlick compresses it to a few megabytes and executes `count`, `grep`, `eq`, and `query` in **single-digit milliseconds**—orders of magnitude faster than scanning the uncompressed bytes.
