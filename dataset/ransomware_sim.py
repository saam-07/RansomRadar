"""
Safe, controlled ransomware-BEHAVIOR simulator. This does NOT contain, run,
or download any real ransomware binary. It reproduces the FILE-SYSTEM-LEVEL
behavioral pattern (rapid rename + high-entropy rewrite + extension change)
that your Review-1 report already specifies as the required test category
in Sec 7.1 ("controlled ransomware-like workloads ... without deploying
real ransomware").

If you obtain the WannaLaugh emulator from its authors (see roadmap Sec 4),
prefer that for closer fidelity to real ransomware I/O patterns; use this
script as the fallback / complement, and clearly label which generator
produced which trace in your dataset metadata.
"""
import argparse
import os
import random
import secrets
import time
from pathlib import Path


def encrypt_like_rewrite(path: Path, mode: str, chunk_size: int = 4096):
    """mode: 'full' | 'partial' | 'intermittent'
    Overwrites the file with random (high-entropy) bytes, mimicking the
    output of real encryption without performing any actual encryption."""
    size = path.stat().st_size
    if size == 0:
        return
    with open(path, "r+b") as f:
        if mode == "full":
            f.write(secrets.token_bytes(size))
        elif mode == "partial":
            n = min(size, 4096)  # only first 4KB, like LockBit-style fast partial encryption
            f.write(secrets.token_bytes(n))
        elif mode == "intermittent":
            pos = 0
            while pos < size:
                n = min(chunk_size, size - pos)
                f.write(secrets.token_bytes(n))
                pos += chunk_size * 2  # skip every other chunk
                f.seek(pos)


def run_simulation(target_dir: str, mode: str, rate_files_per_sec: float,
                    extension: str, max_files: int | None, seed: int):
    rng = random.Random(seed)
    target = Path(target_dir)
    files = [p for p in target.rglob("*") if p.is_file()]
    rng.shuffle(files)
    if max_files:
        files = files[:max_files]

    delay = 1.0 / rate_files_per_sec if rate_files_per_sec > 0 else 0
    log = []
    for p in files:
        t0 = time.monotonic()
        try:
            encrypt_like_rewrite(p, mode)
            new_path = p.with_suffix(p.suffix + extension)
            os.rename(p, new_path)
        except OSError as e:
            print(f"skip {p}: {e}")
            continue
        log.append({"path": str(p), "ts": time.time(), "mode": mode})
        elapsed = time.monotonic() - t0
        if delay > elapsed:
            time.sleep(delay - elapsed)
    return log


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target-dir", required=True,
                     help="scratch directory populated with test files -- "
                          "NEVER point this at a real user directory")
    ap.add_argument("--mode", choices=["full", "partial", "intermittent"], default="full")
    ap.add_argument("--rate", type=float, default=20.0, help="files per second")
    ap.add_argument("--extension", default=".locked")
    ap.add_argument("--max-files", type=int, default=None)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    assert "testfs_" in args.target_dir or "/scratch" in args.target_dir, (
        "Refusing to run: --target-dir does not look like a scratch test "
        "directory (expected a path containing 'testfs_' or '/scratch'). "
        "This simulator performs real destructive overwrites."
    )
    run_simulation(args.target_dir, args.mode, args.rate, args.extension,
                   args.max_files, args.seed)


if __name__ == "__main__":
    main()
