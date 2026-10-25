#!/usr/bin/env python3
"""Multi-document benchmark on the Linux kernel tree.

Usage: bench.py <buttlick-binary> <label> [--skip-compress]

1. (unless --skip-compress) compresses $CORPUS into $BENCH_DIR/<label>.btlk and prints wall time,
   peak RSS, archive size and SHA-1 (hash changes are allowed; compare sizes with parity.py).
2. Runs a fixed set of read queries against $BENCH_DIR/base.btlk (the archive made by the
   baseline binary, so every binary queries the same file), twice each, keeping the faster run.
3. Decompresses the whole archive with --out-dir and diffs it against $CORPUS.
   Symlinks (and directories containing only symlinks) are expected to be missing: `compress`
   does not store them.

Each line prints: label, operation, wall seconds, peak RSS (MB), SHA-1 prefix of stdout,
stdout length, exit code. Outputs (out=...) must match the baseline's.
Run scripts/bench/setup.sh first.
"""
import hashlib, os, subprocess, sys, time

BIN, LABEL = sys.argv[1], sys.argv[2]
SKIP_COMPRESS = "--skip-compress" in sys.argv
CORPUS = os.environ.get("CORPUS", "/home/morg/work_ai/linux_kernel/linux")
OUTDIR = os.environ.get("BENCH_DIR", "/home/morg/work_ai/bench_tmp")
ARCH = f"{OUTDIR}/{LABEL}.btlk"
REF = f"{OUTDIR}/base.btlk"  # queries always run on the same archive
DOC_PREFIX = os.path.basename(CORPUS.rstrip("/"))  # archive doc names start with this


def run(args, repeat=1):
    best = None
    for _ in range(repeat):
        t0 = time.perf_counter()
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = p.stdout.read()
        err = p.stderr.read()
        _, status, ru = os.wait4(p.pid, 0)
        dt = time.perf_counter() - t0
        rss = ru.ru_maxrss / 1024.0
        if best is None or dt < best[0]:
            best = (dt, rss, out, err, status)
    return best


def report(name, res):
    dt, rss, out, err, status = res
    h = hashlib.sha1(out).hexdigest()[:12]
    print(f"{LABEL:6} {name:40} {dt:8.3f}s  {rss:9.1f} MB  out={h} len={len(out)} rc={status}"
          + (f" ERR={err[:200]!r}" if status else ""), flush=True)


if not SKIP_COMPRESS:
    res = run([BIN, "compress", CORPUS, "-o", ARCH, "--stats"])
    report("compress corpus", res)
    print("   ", res[2].decode().strip())
    print("    archive size", os.path.getsize(ARCH), "sha1",
          hashlib.sha1(open(ARCH, "rb").read()).hexdigest()[:12], flush=True)

arch = os.environ.get("BENCH_ARCHIVE", REF if os.path.exists(REF) else ARCH)
core_c = f"{DOC_PREFIX}/kernel/sched/core.c"
queries = [
    ("slurp -c EXPORT_SYMBOL_GPL", ["slurp", arch, "EXPORT_SYMBOL_GPL", "-c"]),
    ("slurp -n kfree_rcu\\( limit50", ["slurp", arch, r"kfree_rcu\(", "-n", "--limit", "50", "--color=never"]),
    ("slurp -n doc core.c", ["slurp", arch, "schedule_timeout", "-n", "--doc", core_c, "--color=never"]),
    ("slurp --match-count mutex", ["slurp", arch, r"mutex_(un)?lock", "--match-count"]),
    ("count --all mutex_lock(", ["count", arch, " mutex_lock(", "--all"]),
    ("count offsets doc", ["count", arch, "struct", "--offsets", "--limit", "20", "--doc", core_c]),
    ("slice", ["slice", arch, "--doc", core_c, "--start", "10000", "--len", "256"]),
    ("inspect --json", ["inspect", arch, "--json"]),
    ("query col", ["query", arch, "--delimiter", " ", "--col", "2", "--doc", f"{DOC_PREFIX}/MAINTAINERS"]),
]
for name, args in queries:
    report(name, run([BIN] + args, repeat=2))

# Full decompress to a dir (round trip check)
dec = f"{OUTDIR}/{LABEL}_dec"
subprocess.run(["rm", "-rf", dec])
res = run([BIN, "decompress", arch, "--out-dir", dec])
report("decompress --out-dir", res)
r = subprocess.run(["diff", "-rq", "--no-dereference", CORPUS, f"{dec}/{DOC_PREFIX}"],
                   capture_output=True, env=dict(os.environ, LC_ALL="C"))
lines = []
for l in r.stdout.decode(errors="replace").splitlines():
    if l.startswith("Only in " + CORPUS):
        d, name = l[len("Only in "):].split(": ", 1)
        p = os.path.join(d, name)
        if os.path.islink(p) or (os.path.isdir(p) and all(
                os.path.islink(os.path.join(p, e)) for e in os.listdir(p))):
            continue
    lines.append(l)
print(f"{LABEL:6} roundtrip diff unexpected={len(lines)} {lines[:5]}", flush=True)
subprocess.run(["rm", "-rf", dec])
