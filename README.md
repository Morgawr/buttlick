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

### 3. Extract byte slices directly without decompression

Because the archive is a balanced tree, jumping to an arbitrary byte offset takes microseconds even on very large files

```bash
# Read 256 bytes starting at offset 10,000,000
buttlick slice linux_kernel.btlk --doc drivers/gpu/drm/amd/amdgpu/amdgpu_drv.c --start 10000 --len 256

# Check if two 1MB regions are byte-for-byte identical in O(log N) time
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

### 7. Decompress (`decompress` & `inspect`)

```bash
# Extract an entire multi-file archive back to a directory
buttlick decompress linux_kernel.btlk --out-dir ./linux

# Extract a single file to stdout
buttlick decompress linux_kernel.btlk --doc README > README

# Inspect archive size, rule count, and tree height
buttlick inspect linux_kernel.btlk
```

---

## How It Works

Instead of sliding-window LZ77 + entropy coding (which destroys random access and forces sequential decompression), `buttlick` builds a **Grammar DAG** (Directed Acyclic Graph):

1. **Deduplicated Grammar Rules**:
   Every file is broken into lines and tokens, then bottom-up paired into two kinds of rules:
   - `Pair(left, right)`: concatenates two symbols (`left` followed by `right`).
   - `Run(child, count)`: repeats `child` `count` times in a row.

   Identical substrings, tokens, and lines anywhere across the archive are hash-consed to the exact same 32-bit `SymbolId`. If a boilerplate header or log prefix appears 50,000 times across 10,000 files, it is represented by a single rule subtree.

2. **Deterministic Cut Points (Locally Consistent Parsing)**:
   When two files differ by a few bytes in the middle, naive pair-folding shifts boundaries and ruins deduplication. `buttlick` picks merge boundaries using local hash landmarks (local maxima/minima of adjacent symbol hashes), so edits stay localized and identical surrounding text always compiles to the same rule IDs.

3. **Bottom-Up Query Evaluation (Why `slurp` is fast)**:
   On disk, the `.btlk` rule table is stored as a flat array of 8-byte `PackedRuleNode` structs in topological order (children always have lower IDs than parents).
   - When you run `buttlick slurp`, the binary `mmap`s the `.btlk` file directly from the OS page cache with near-zero RAM overhead (~18 MB RSS on a 200 MB archive).
   - For literal queries, a single bottom-up pass checks if the pattern appears at the seam between `left` and `right` of each rule. Because rules are evaluated in order, if a rule matches, that result is reused everywhere the rule appears.
   - To print matching lines (`-n`), `buttlick` only descends into branches flagged as containing a match and expands the surrounding `[prev_newline, next_newline]` span. Branches without matches are skipped in $O(1)$.

4. **$O(\log N)$ Random Access & Slicing**:
   Each rule stores its expanded byte length and a 61-bit Karp-Rabin hash. Because the grammar tree height is bounded ($H \approx 30\text{–}40$ even for multi-gigabyte corpora), `slice` and `eq` walk down from a document's root symbol using subtree byte lengths like a B-tree, touching only the nodes along the path.
