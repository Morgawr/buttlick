# Handoff implementation status (2026-10-25)

The user explicitly permits incompatible API/archive changes and different compression output.
Correctness takes priority; archive size must not significantly worsen. The implementation
retains the 8-byte rule encoding, with corrected root hashes and an explicit hash-guarantee flag.

## Changes against the handoff

| Items | Result |
|---|---|
| 5.1 | Checked affine composition; signed parsing handles arbitrary zero padding and both i64 endpoints. Oversized fields are ignored. CLI JSON preserves i128 sums beyond 64-bit values. |
| 5.2 | Every new parallel-ingestion root has an exact polynomial hash, including empty documents and batches over 64 roots. A header bit distinguishes these from legacy fingerprints. |
| 5.3 | CLI duplicate names fail before output is written. Library batches consistently upsert, including duplicates within one batch, using a name index. |
| 5.4 | Run evaluation skips finite-state cycles. Offset and line walkers prune virtual balanced run trees. Repeated line fragments expand once, then copy by doubling. |
| 5.5 | Mapped single-document queries evaluate sorted reachable rules; whole-archive queries retain sequential evaluation. |
| 5.6 | Literal counting uses an adaptive sparse/packed memo, with full-width emission counts and additional-state overflow storage. Sparse regex queries retain their smaller cache. |
| 5.7 | Aggregation materializes record prefixes only through the last requested/filter field. Shared range walkers stop early and skip unused repeated tails. |
| 5.8 | Edits hash/index only reachable rules and reuse long pairs after reload. Optional library/CLI compaction removes unreachable rules. Multi-document edits require an explicit target. |
| 5.9–5.10 | Added checksum `verify`; reject unrepresentable run counts, invalid run counts, 31-bit symbol/tag collisions, oversized names, and overflowing archive totals. |
| 5.11–5.12 | Borrow KMP summaries; remove redundant byte lengths (56 rather than 64 bytes per summary on x86-64). Small fragments no longer allocate full long-pattern windows. |
| 5.13–5.15 | Saturating aggregate/count arithmetic with documented limits; documented field/key=value matching. |
| 5.16–5.21 | Fail explicitly on input I/O errors, report skipped directory entries with stats, mmap compression inputs, explain the one-shot CLI allocation leak, and reject conflicting search modes. Explicit symlink inputs are followed; recursive traversal skips links. |
| 5.22 | Split bulk ingestion into deduplication, merge/remap, and root-building helpers. Guard tagged unit/symbol limits before remapping. |
| 5.23, 5.29 | Tested broader/narrower interning thresholds and rejected both as inconsistent compression wins. Retain default thresholds, dictionary trimming, and fixed-width encoding; see experiments below. |
| 5.24–5.28, 5.30 | Document decoded transducer costs, add four mapped built-in benchmarks with byte oracles, remove hard-coded test header offsets, clarify empty-archive errors, correct README measurements, and document the advisory producer flag. |

Additional reproduced correctness fixes:

- Manual pair/run interning followed by parallel ingestion could reuse an invalid seed ID
  and panic during remapping. Keep the seed watermark current and reject dictionary entries
  outside a chunk's seed range. Regression tests exercise both pair and run reuse.
- Regex match counting previously returned incorrect answers for greedy patterns, empty
  matches, anchors, and newlines. Use a sound compressed counter for fixed matches and simple
  greedy byte repetitions; other patterns use the exact regex engine one document at a time.
  Empty-string-only patterns count without expansion, including u64::MAX logical lengths.
  Both backends are compared against the Rust regex engine, including invalid UTF-8 input.
- Decoded transducer identity now supports all 65,536 states. Weighted composition and EOF
  counts saturate instead of wrapping; an empty root can still emit at EOF.
- Subtraction-based range checks reject overflowing start/length combinations. Insert and
  concat reject overflowing result lengths before mutation. Archive parsing validates root
  presence flags and checked root totals against the header.

## Verification and provenance

The final release suite has 51 tests: 23 library, 1 sequential random-edit differential,
16 handoff regressions, 6 mapped differential, 2 query differential, and 3 round-trip tests.
Debug/release tests, Clippy, formatting, diff checks, and benchmark script syntax checks
are recorded in scripts/bench/results/2026-10-25-final-checks.txt.

Regressions cover long numeric fields, 70-document hash/upsert batches, repeated edits with
multiple documents, compaction/save/reload/future edits, huge periodic runs, long literals,
record-prefix truncation, malformed format boundaries, and CLI failure behavior. Logical-run
tests reach u64::MAX bytes without expanding them. Standalone compact and edit --compact
also passed a CLI smoke comparison while preserving the other document.

Baseline: f896174, copied before any changes. Benchmark artifacts live under
/tmp/buttlick-bench; original corpus and archives under /home/morg/work_ai were read only.
Final executable SHA-256:
953687b226cb13ed268669172569a8457db5483a7383b3614231e08d5040f7bf.

Final raw evidence is in scripts/bench/results/2026-10-25-final-*.txt. Earlier before/after
and alternating logs are retained for provenance; they represent earlier implementation
stages, not the final binary. Inspection hashes change intentionally with the new guarantee
metadata. Search, navigation, aggregation, and decompression answers must retain their
expected hashes; the freshly compressed kernel archive must have zero unexpected diffs.

| Final compression round | Baseline | Final | Archive size, both |
|---|---:|---:|---:|
| Kernel tree | 10.05 s / 5473 MiB | 11.51 s / 5473 MiB | 1,239,786,152 bytes |
| Concatenated C | 6.47 s / 4434 MiB | 6.35 s / 4011 MiB | 543,921,200 bytes |

Archive sizes are unchanged. Exact root hashing adds work on the kernel tree; there is no
claim of universal CPU parity. Both large-file round trips pass streaming SHA-256 checks.
The corrected archive SHA-1s are f1544ef77a468bf797db50fa902a0326f27bb25d (kernel) and
1d00f8a5bb59948c365579b26f5e43a350326368 (C). Their packed rule tables are unchanged from
baseline: SHA-256 2219c5189c3ac0a5c3a153bcd024d07f09696932eb025726e2572b92ac83f725
and afac09cf9b4a4a131d9875cfd94ec6a24db25c05f813c42a88b7125f8e304fc2 respectively.

Selected measurements (single runs/small repeat sets, not a statistical performance model):

| Workload | Baseline | Improved |
|---|---:|---:|
| Kernel literal count, all documents | 5.148 s / 2144.3 MiB | 2.591 s / 1573.6 MiB, final |
| Kernel matching lines, core.c only | 0.809 s / 1378.2 MiB | 0.020 s / 55.8 MiB, final |
| Kernel literal offsets, core.c only | 2.747 s / 1667.3 MiB | 0.022 s / 57.8 MiB, final |
| C aggregation, column 2 | 9.572 s | 8.117 s, final |
| C filtered aggregation | 9.585 s | 9.660 s, final |
| Kernel insertion | 18.514 s / 8186.8 MiB | 5.552 s / 5897.1 MiB, final |

Whole-archive regex/line queries show small timing regressions in some runs; their memory
stays comparable and correctness is preserved. The literal-count target (<3 s, <2.2 GB) is
met. Both aggregation queries meet the handoff's <10.8 s target. Edit output matched the
raw-byte oracle in both versions; its SHA-256 was
d3344ba0dd15647d65e18c8e32527bef2e637056555accb60a73cd863dc0faa7.

## Profiling and rejected experiments

Callgrind completed after perf recording was denied by system permissions. The original
count profile used 15,536,807,685 instructions, dominated by table construction, stateful
symbol evaluation, and memo insertion. This motivated the adaptive memo layout.
Aggregation used 72,095,578,104 instructions: expansion ~50%, range extraction ~14%, length
lookup ~9%, aggregate traversal ~8%. This motivated bounded record-prefix extraction.
Raw profiles stay in /tmp/buttlick-bench and are not repository artifacts.

Interning experiments retained exact round trips but failed to provide a broad size win:

| Pair thresholds | Kernel bytes | C bytes | Mixed text/code bytes |
|---|---:|---:|---:|
| Default 16/28 | 1,239,786,152 | 543,921,200 | 6,588,912 |
| Broader 24/48 | 1,248,845,080 (+0.731%) | 543,720,808 (-0.037%) | 6,547,344 (-0.631%) |
| Narrower 12/24 | 1,233,907,496 (-0.474%) | 544,227,096 (+0.056%) | 6,895,944 (+4.660%) |

The mixed fixture freezes src/tests/README plus 30,000 records each of English text,
Japanese text, and logs (28 files). Mixed timing overlapped compilation, so only its sizes
and round-trip checks are evidence. Defaults were restored and the final large archives
regenerated. Final baseline/current comparison on the same frozen mixed fixture also has
identical sizes (6,588,912 bytes) and passes extraction comparisons for all 28 files.
No entropy codec was added: that is a separate design project rather than a
necessary correctness fix. Compacting an unedited kernel archive removed only 703 rules,
saving <0.001% while costing 14.321 s / 6477.9 MiB, so compaction remains explicit for edits.

## Limits and reproduction

Exact fallback regex counting can buffer the largest selected document. Returned matching
line bytes also require output-proportional memory. The decoded generic transducer and
edit load path remain memory-heavy; edits are not a fully mapped engine. Hash equality is
probabilistic. Aggregate/emission totals saturate at their documented numeric bounds;
writers reject totals that the archive cannot represent. No compatibility guarantee is made
for the changed public APIs or old archives.

Use BENCH_DIR=/tmp/buttlick-bench and BASE_REV=f896174 with scripts/bench/setup.sh.
parity.py enforces a configurable archive-size limit (default 1%) and streams the C round trip.
Set BENCH_ARCHIVE=/tmp/buttlick-bench/parity_new_corpus.btlk for bench.py to query and
round-trip the freshly generated kernel archive. Run bench_big.py separately, without
concurrent builds or benchmarks. Benchmark setup exports baseline sources without mutating
git worktrees. No Android tests are relevant to this Rust project.
