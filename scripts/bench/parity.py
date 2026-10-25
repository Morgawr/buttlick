#!/usr/bin/env python3
"""Compare compression time, memory, and archive sizes against the baseline.
Correctness fixes may change archive bytes; size regression is capped by MAX_SIZE_REGRESSION
(default 0.01, or 1%). Round-trip correctness is checked by bench.py and the test suites.

Usage: parity.py [rounds]   (default 2)

Alternates $BENCH_DIR/bin/buttlick_base and $BENCH_DIR/bin/buttlick_new compressing $CORPUS
(Linux tree, multi-document path) and $BENCH_DIR/big.c (single-document path), printing wall time,
peak RSS, archive size and SHA-1. Hashes are informational; sizes must not materially worsen.
Timing noise between rounds can be large (disk cache); compare within the same round.
Run scripts/bench/setup.sh first (it also refreshes buttlick_new).
"""
import hashlib, os, subprocess, sys, time

T = os.environ.get("BENCH_DIR", "/home/morg/work_ai/bench_tmp")
CORPUS = os.environ.get("CORPUS", "/home/morg/work_ai/linux_kernel/linux")
ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 2
inputs = [("corpus", CORPUS), ("big.c", f"{T}/big.c")]
with open(f"{T}/big.c", "rb") as f:
    expected_big_hash = hashlib.file_digest(f, "sha256").hexdigest()
max_regression = float(os.environ.get("MAX_SIZE_REGRESSION", "0.01"))
failed = False
for rnd in range(ROUNDS):
    base_sizes = {}
    for label in ["base", "new"]:
        for name, inp in inputs:
            out = f"{T}/parity_{label}_{name}.btlk"
            t0 = time.perf_counter()
            p = subprocess.Popen([f"{T}/bin/buttlick_{label}", "compress", inp, "-o", out],
                                 stdout=subprocess.DEVNULL)
            _, st, ru = os.wait4(p.pid, 0)
            dt = time.perf_counter() - t0
            if st != 0:
                raise SystemExit(f"{label} compression failed: wait status {st}")
            with open(out, "rb") as f:
                h = hashlib.file_digest(f, "sha1").hexdigest()[:12]
            size = os.path.getsize(out)
            if label == "base":
                base_sizes[name] = size
            else:
                delta = size / base_sizes[name] - 1
                print(f"{name} archive size change: {delta:+.3%}", flush=True)
                failed |= delta > max_regression
            print(f"round{rnd} {label:5} {name:6} {dt:7.2f}s {ru.ru_maxrss/1024:8.0f} MB "
                  f"size={os.path.getsize(out)} sha={h} rc={st}", flush=True)
            if name == "big.c":
                # A smaller archive is useful only if it still contains the complete input.
                # Stream the output hash so the benchmark driver needs no whole-file buffer.
                dec = subprocess.Popen([f"{T}/bin/buttlick_{label}", "decompress", out],
                                       stdout=subprocess.PIPE)
                decoded_hash = hashlib.file_digest(dec.stdout, "sha256").hexdigest()
                if dec.wait() != 0 or decoded_hash != expected_big_hash:
                    raise SystemExit(f"{label} big.c round trip failed")
                print(f"{label} big.c round trip OK", flush=True)

if failed:
    raise SystemExit("Archive size regression exceeds MAX_SIZE_REGRESSION")
