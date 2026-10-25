#!/usr/bin/env python3
"""Single-document stress benchmark on $BENCH_DIR/big.btlk (514 MB file, ~68M rules).

Usage: bench_big.py <buttlick-binary> <label>

Exercises the single-root code paths (e.g. `navigation_meta` length prefill, whole-document
aggregation). Each command runs twice and the faster run is kept. Output columns: label,
operation, wall seconds, peak RSS (MB), SHA-1 prefix of stdout, stdout length, exit code.
Outputs must match the baseline, except `slurp -n lim`: the original binary returns WRONG
results for that pattern (>128 DFA states bug, fixed in c211338).
Run scripts/bench/setup.sh first.
"""
import hashlib, os, subprocess, sys

BIN, LABEL = sys.argv[1], sys.argv[2]
BENCH_DIR = os.environ.get("BENCH_DIR", "/home/morg/work_ai/bench_tmp")
A = f"{BENCH_DIR}/big.btlk"
N = os.path.getsize(f"{BENCH_DIR}/big.c")


def run(args, repeat=2):
    import time
    best = None
    for _ in range(repeat):
        t0 = time.perf_counter()
        p = subprocess.Popen([BIN] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = p.stdout.read()
        err = p.stderr.read()
        _, status, ru = os.wait4(p.pid, 0)
        dt = time.perf_counter() - t0
        if best is None or dt < best[0]:
            best = (dt, ru.ru_maxrss / 1024.0, out, err, status)
    return best


for name, args in [
    ("query col2 ' '", ["query", A, "--delimiter", " ", "--col", "2"]),
    ("query col1 where", ["query", A, "--delimiter", "=", "--col", "1", "--where-col", "0", "--where-eq", "\tret "]),
    ("slice near end", ["slice", A, "--start", str(N - 5000), "--len", "4096"]),
    ("slice middle", ["slice", A, "--start", str(N // 2), "--len", "100000"]),
    ("eq 1MB", ["eq", A, "--pos1", "1000", "--pos2", str(N // 3), "--len", "1048576"]),
    ("eq self-ish", ["eq", A, "--pos1", "0", "--pos2", "0", "--len", str(N)]),
    ("count struct", ["count", A, "struct"]),
    ("count offsets", ["count", A, "kfree_rcu", "--offsets", "--limit", "20"]),
    ("slurp -c", ["slurp", A, "EXPORT_SYMBOL_GPL", "-c"]),
    ("slurp -n lim", ["slurp", A, "a.{6}b", "-n", "--limit", "30", "--color=never"]),
    ("decompress", ["decompress", A]),
    ("inspect", ["inspect", A]),
]:
    dt, rss, out, err, status = run(args)
    h = hashlib.sha1(out).hexdigest()[:12]
    print(f"{LABEL:6} {name:22} {dt:8.3f}s {rss:9.1f} MB out={h} len={len(out)} rc={status}"
          + (f" ERR={err[:200]!r}" if status else ""), flush=True)
