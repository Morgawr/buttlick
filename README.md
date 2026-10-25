# buttlick

`buttlick` is a compression tool and archive format (`.btlk`) that lets you slurp, slice, aggregate, and edit compressed files directly—without decompressing them first.

Standard compressors (`zstd`, `gzip`, `xz`) pack data into opaque blocks. To grep or slice a compressed archive, you have to decompress the stream back into memory. `buttlick` instead compresses files into a deduplicated tree of grammar rules, allowing queries to run directly on the compressed structure via `mmap`.

## Build

```bash
cargo build --release
```

## Quick Start

### 1. Compress files or entire directories

Compress a directory or set of files into a single `.btlk` archive. All files in the archive share the same deduplicated rule dictionary.

```bash
# Compress a directory tree with progress stats
buttlick compress ./source_code -o source_code.btlk --stats

# Skip binary media/archives (.png, .jpg, .zip, etc.) or specific extensions
buttlick compress ./game_data -o script.btlk --text-only
buttlick compress ./logs -o logs.btlk --exclude-ext bin,idx
```

### 2. Slurp a compressed buttlick archive

`slurp` is like `grep -E` directly inside a `.btlk` compressed file.

```bash
# Print matching lines across all files in the archive
buttlick slurp script.btlk "I can't let you get close!" -n

# Print matching lines for a regex pattern, capped at 50 results
buttlick slurp linux_kernel.btlk "kfree_rcu\(" -n --limit 50

# Count matching lines across the archive (like grep -E -c)
buttlick slurp linux_kernel.btlk "EXPORT_SYMBOL_GPL" -c

# Search inside a single specific file in the archive
buttlick slurp linux_kernel.btlk "schedule_timeout" -n --doc kernel/sched/core.c
```

`--match-count` counts non-overlapping matches with greedy, anchor, and empty-match semantics.
Simple byte repetitions such as `a+`, `[a-z]*`, and fixed matches use compressed transducers.
Compound greedy patterns such as `a.*b`, other nullable patterns, and contextual assertions
use an exact regex engine that expands one document at a time. Exact counting can therefore
need memory proportional to the largest selected document. Empty-string-only patterns need
no expansion. Emission totals saturate at `u64::MAX` if their mathematical result is larger.

### 3. Extract byte slices directly without decompression

Slices navigate the grammar using subtree lengths. Lengths are computed lazily for multi-document
archives; single-document archives currently prefill a length table, so opening a large one has
an O(number of rules) setup cost.

```bash
# Read 256 bytes starting at offset 10,000,000
buttlick slice linux_kernel.btlk --doc drivers/gpu/drm/amd/amdgpu/amdgpu_drv.c --start 10000 --len 256

# Compare two 1MB regions using a probabilistic 61-bit Karp-Rabin hash
buttlick eq archive.btlk --pos1 0 --pos2 1048576 --len 1048576
```

### 4. Count substrings and find byte offsets

```bash
# Count exact occurrences across all documents
buttlick count linux_kernel.btlk " mutex_lock(" --all

# Print the first 20 byte offsets where the pattern appears
buttlick count script.btlk "I can't let you get close!" --offsets --limit 20
```

### 5. Run analytics on compressed CSV / TSV / logs

Compute `COUNT`, `SUM`, `MIN`, `MAX`, and `AVG` on a numeric column directly on the compressed rules.

```bash
# Aggregate column 3 (0-indexed) where column 1 == "ERROR"
buttlick query access.btlk --delimiter "," --col 3 --where-col 1 --where-eq "ERROR"
```

### 6. Edit a compressed archive in place

Insert, delete, concatenate, or replace text directly in the grammar tree without decompressing and recompressing the whole archive.

```bash
# Replace all occurrences of a string across a document
buttlick edit input.btlk -o output.btlk --doc config.json replace --pattern "localhost" --with "10.0.0.1"

# Insert or delete bytes at an exact offset
buttlick edit input.btlk -o output.btlk insert --offset 0 --text "// Header\n"
buttlick edit input.btlk -o output.btlk delete --offset 0 --len 10
```

Multi-document edits require `--doc` (except `concat`, which names both inputs). Edits retain old
rules for reuse. Use `edit --compact` to remove unreachable rules before saving, or compact an
existing archive separately:

```bash
buttlick compact input.btlk -o compact.btlk
```

Compaction preserves every document and its bytes. It loads the decoded grammar and needs
additional memory for reachability and symbol renumbering.

### 7. Decompress (`decompress` & `inspect`)

```bash
# Extract an entire multi-file archive back to a directory
buttlick decompress linux_kernel.btlk --out-dir ./linux

# Extract a single file to stdout
buttlick decompress linux_kernel.btlk --doc README > README

# Inspect archive size, rule count, and tree height
buttlick inspect linux_kernel.btlk

# Check file integrity before running queries on untrusted or transferred storage
buttlick verify linux_kernel.btlk
```

`decompress` and `inspect` verify the checksum automatically. Search, slicing, equality, and
aggregation validate rule structure as they visit it and skip the full checksum scan for latency;
run `verify` explicitly when integrity verification is needed. Inputs and archives must remain
unchanged while mapped. Compression stores regular files; recursive directory traversal skips
symbolic links, empty directories, and special files (counts are reported with `--stats`).
Explicit input paths follow symbolic links. Unreadable inputs fail the
command rather than silently producing an incomplete archive. Duplicate document names also
fail compression; the library's named insertion APIs consistently replace an existing name.

Numeric queries accept signed `i64` fields, including leading zeros, and ignore invalid or
out-of-range fields. For log-style `key=value` fields, the target column uses the suffix after
the first `=`; filters match either that suffix or the complete field.

---

## How It Works

Instead of sliding-window LZ77 + entropy coding (which destroys random access and forces sequential decompression), `buttlick` builds a **Grammar DAG** (Directed Acyclic Graph):

1. **Deduplicated Grammar Rules**:
   Every file is broken into lines and tokens, then bottom-up paired into two kinds of rules:
   - `Pair(left, right)`: concatenates two symbols (`left` followed by `right`).
   - `Run(child, count)`: repeats `child` `count` times in a row.

   Reused tokens and lines share 32-bit `SymbolId`s. Bulk ingestion limits cross-chunk pair
   indexing to short expansions to bound dictionary memory, so arbitrary identical substrings
   are not guaranteed to share one subtree.

2. **Deterministic Cut Points (Locally Consistent Parsing)**:
   When two files differ by a few bytes in the middle, naive pair-folding shifts boundaries and ruins deduplication. `buttlick` picks merge boundaries using local hash landmarks (local maxima/minima of adjacent symbol hashes), so edits stay localized and identical surrounding text always compiles to the same rule IDs.

3. **Bottom-Up Query Evaluation (Why `slurp` is fast)**:
   On disk, the `.btlk` rule table is stored as a flat array of 8-byte `PackedRuleNode` structs in topological order (children always have lower IDs than parents).
   - `buttlick slurp` maps the packed rule table and evaluates a finite-state transducer over it.
     State cells use 1 or 2 bytes per symbol, with additional memoized states and emission counts.
     Memory depends on the query and reachable rules; mmap pages also contribute to RSS.
   - Literal search uses an overlapping KMP transducer. Bottom-up summaries are reused wherever
     rules appear. Single-document search in a multi-document archive visits only reachable rules.
   - To print matching lines (`-n`), `buttlick` only descends into branches flagged as containing a match and expands the surrounding `[prev_newline, next_newline]` span. Branches without matches are skipped in $O(1)$.

4. **$O(\log N)$ Random Access & Slicing**:
   Expanded lengths and 61-bit Karp-Rabin hashes are derived from packed rules and cached as
   needed. Slicing follows the requested range; hashing a previously unseen full subtree can
   visit all its reachable rules. Hash equality is probabilistic, not a byte-for-byte proof.

The format stores 8 bytes per rule without entropy coding. Compression is workload-dependent:
the handoff's Linux source corpus produced a 1.35x input/archive ratio, while a concatenated
514 MB C file produced 0.95x (larger than its input). Highly repetitive logs compress much better.
These corpus measurements are examples, not a general compression or memory guarantee.

Library callers should prefer `MappedArchive` for large read workloads. The decoded
`MealyTransducer::evaluate_dag` API allocates a rule-by-state table, which can be much larger.
