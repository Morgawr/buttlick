#!/usr/bin/env bash
# Prepares everything the benchmark scripts need (idempotent: existing artifacts are reused).
#
#   $BENCH_DIR/bin/buttlick_base   original binary, built from commit 84f0697 (pre-review reference)
#   $BENCH_DIR/bin/buttlick_new    current working-tree release binary (rebuilt on every run)
#   $BENCH_DIR/base.btlk           Linux tree compressed with buttlick_base (shared query input)
#   $BENCH_DIR/big.c               ~514 MB single file: first 30000 sorted drivers/*.c files concatenated
#   $BENCH_DIR/big.btlk            big.c compressed with buttlick_base (single-document query input)
#
# Environment overrides:
#   BENCH_DIR  (default /home/morg/work_ai/bench_tmp)
#   CORPUS     (default /home/morg/work_ai/linux_kernel/linux)
#   BASE_REV   (default 84f0697)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCH_DIR="${BENCH_DIR:-/home/morg/work_ai/bench_tmp}"
CORPUS="${CORPUS:-/home/morg/work_ai/linux_kernel/linux}"
BASE_REV="${BASE_REV:-84f0697}"

mkdir -p "$BENCH_DIR/bin"

if [ ! -x "$BENCH_DIR/bin/buttlick_base" ]; then
    echo "[setup] building baseline binary from $BASE_REV"
    # Export into a script-owned directory; benchmark setup need not mutate git worktrees.
    baseline_src="$(mktemp -d "$BENCH_DIR/base-src.XXXXXX")"
    trap 'rm -rf "$baseline_src"' EXIT
    git -C "$REPO" archive "$BASE_REV" | tar -x -C "$baseline_src"
    cargo build --release --manifest-path "$baseline_src/Cargo.toml" \
        --target-dir "$BENCH_DIR/base_target"
    cp "$BENCH_DIR/base_target/release/buttlick" "$BENCH_DIR/bin/buttlick_base"
    rm -rf "$baseline_src"
    trap - EXIT
fi

echo "[setup] building current binary"
cargo build --release --manifest-path "$REPO/Cargo.toml"
cp "$REPO/target/release/buttlick" "$BENCH_DIR/bin/buttlick_new"

if [ ! -f "$BENCH_DIR/base.btlk" ]; then
    echo "[setup] compressing $CORPUS -> base.btlk"
    "$BENCH_DIR/bin/buttlick_base" compress "$CORPUS" -o "$BENCH_DIR/base.btlk" --stats
fi

if [ ! -f "$BENCH_DIR/big.c" ]; then
    echo "[setup] generating big.c"
    # Avoid SIGPIPE with pipefail and preserve paths containing whitespace.
    env -u PYTHONHOME -u PYTHONPATH /usr/bin/python3 - "$CORPUS" "$BENCH_DIR/big.c" <<'PY'
import os, pathlib, shutil, sys
paths = [p for p in (pathlib.Path(sys.argv[1]) / "drivers").rglob("*.c")
         if p.is_file() and not p.is_symlink()]
with open(sys.argv[2], "wb") as out:
    for path in sorted(paths, key=os.fsencode)[:30000]:
        with path.open("rb") as inp:
            shutil.copyfileobj(inp, out)
PY
fi

if [ ! -f "$BENCH_DIR/big.btlk" ]; then
    echo "[setup] compressing big.c -> big.btlk"
    "$BENCH_DIR/bin/buttlick_base" compress "$BENCH_DIR/big.c" -o "$BENCH_DIR/big.btlk" --stats
fi

echo "[setup] done: $(ls "$BENCH_DIR")"
