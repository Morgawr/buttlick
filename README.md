# Buttlick (`buttlick`)

**Grammar-Homomorphic Zero-Decompression Storage & Compute Engine**

Buttlick compresses raw byte streams and multi-document corpora into a canonically hash-consed **Run-Length Straight-Line Program (RLSLP) DAG** using **Locally Consistent Parsing (Recompression)**. Because the compressed representation is a balanced Context-Free Grammar DAG of depth $O(\log N)$ with $n \ll N$ unique production rules, Buttlick compiles queries—substring searches, arbitrary regular expressions, line-oriented `grep`, structured numerical aggregations (`COUNT`, `SUM`, `MIN`, `MAX`, `AVG`), random-access slicing, $O(\log N)$ substring equality, and persistent edits—into **Algebraic Monoid Homomorphisms** that execute directly on the compressed grammar rules in $O(n)$ or $O(\log N)$ time **without decompressing the underlying data**.

---

## Core Algebraic Engines

1. **Mersenne Prime $\mathbb{F}_{2^{61}-1}$ Homomorphic Fingerprinting (`src/hash.rs`, `src/grammar/navigate.rs`)**
   - Every symbol maintains its precomputed Karp-Rabin polynomial hash and power over $P = 2^{61}-1$.
   - Arbitrary byte intervals $[i, i+L)$ decompose into at most $2H = O(\log N)$ canonical grammar pieces, enabling $O(\log N)$ equality checks across multi-gigabyte ranges.
2. **Algebra 1: KMP Seam-Tracking Monoid (`src/engine/kmp_seam.rs`)**
   - Counts exact literal occurrences in $O(n \cdot |P|)$ time by tracking $(m-1)$-byte prefixes/suffixes across `Pair` seams and binary-exponentiating `Run` rules in $O(|P| \log k)$ time.
   - Extracts top-$K$ 64-bit byte offsets lazily in $O(K \log N)$ time by pruning zero-match subtrees in $O(1)$.
3. **Algebra 2: Wreath-Product Mealy Transducer Monoid (`src/engine/transducer.rs`, `src/engine/regex_compile.rs`)**
   - Compiles arbitrary regular expressions (`LineCount` / `grep -E -c` and `MatchCount`) into dense state-to-state transition and weight-emission summaries $\mathcal{T}(X) = (\Delta_X, \Omega_X)$ composed in $O(|Q|)$ time and raised to $k$-th powers on RLE rules in $O(|Q| \log k)$ time.
4. **Algebra 3: Affine Place-Value & Line-Stream Record Aggregator (`src/engine/aggregate.rs`)**
   - Evaluates `COUNT`, `SUM`, `MIN`, `MAX`, and `AVG` with optional column equality predicates directly over compressed CSV, TSV, and `key=value` log streams.
5. **Dynamic $O(\log N)$ Persistent DAG Surgery (`src/grammar/edit.rs`)**
   - Supports height-balanced `concat`, `split`, `insert`, `delete`, and homomorphic `replace_all` directly on `.btlk` archives without full decompression.

---

## Command-Line Interface

```bash
# 1. Compress one or more files into a .btlk archive
buttlick compress <INPUT_FILES>... -o <OUTPUT.btlk> [--stats]

# 2. Decompress a .btlk archive (or specific named root) back to raw bytes
buttlick decompress <INPUT.btlk> [-o <OUTPUT_FILE>] [--doc <NAME>]

# 3. Inspect DAG structure, compression ratio, tree depth, and rule statistics
buttlick inspect <INPUT.btlk> [--json]

# 4. O(log N) random-access byte slice extraction
buttlick slice <INPUT.btlk> --start <OFFSET> --len <LENGTH> [--doc <NAME>]

# 5. O(log N) substring equality check between two arbitrary ranges
buttlick eq <INPUT.btlk> --pos1 <OFFSET1> --pos2 <OFFSET2> --len <LENGTH> [--doc <NAME>]

# 6. Zero-decompression exact substring search (count + optional byte offsets)
buttlick count <INPUT.btlk> <PATTERN> [--offsets] [--limit <K>] [--doc <NAME>]

# 7. Zero-decompression regular expression search & line-count (`grep -E -c` equivalent)
buttlick grep <INPUT.btlk> <REGEX> [--line-count | --match-count] [--doc <NAME>]

# 8. Zero-decompression structured analytics (CSV / TSV / Log column aggregations)
buttlick query <INPUT.btlk> --delimiter <CHAR> --col <INDEX> [--where-col <IDX> --where-eq <STR>] [--json]

# 9. Zero-decompression persistent edits directly on .btlk files
buttlick edit <IN.btlk> -o <OUT.btlk> insert --offset <POS> --text <STRING>
buttlick edit <IN.btlk> -o <OUT.btlk> delete --offset <POS> --len <LEN>
buttlick edit <IN.btlk> -o <OUT.btlk> replace --pattern <PAT> --with <REPL>
buttlick edit <IN.btlk> -o <OUT.btlk> concat --doc1 <NAME1> --doc2 <NAME2> --new-name <NAME>

# 10. Built-in Benchmark Suite
buttlick bench [--size-mb <MB>] [--json]
```
