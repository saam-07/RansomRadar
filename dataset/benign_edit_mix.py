"""
Benign-normal workload (roadmap Sec 7.1, workload class 1): an ordinary
mix of file creation, editing, renaming and deletion at human-plausible
rates, used as the clean negative class distinct from the "legitimate
high-volume" (backup/OLTP) class.
"""
import argparse
import random
import time
from pathlib import Path


def run(target_dir: str, seed: int, duration_s: float = 60.0, ops_per_sec: float = 0.5):
    rng = random.Random(seed)
    d = Path(target_dir) / "data"
    d.mkdir(parents=True, exist_ok=True)
    t_end = time.monotonic() + duration_s
    counter = 0
    while time.monotonic() < t_end:
        op = rng.choice(["create", "edit", "rename", "delete"])
        files = list(d.glob("*.txt"))
        if op == "create" or not files:
            p = d / f"doc_{counter}.txt"
            p.write_text("lorem ipsum " * rng.randint(10, 200))
            counter += 1
        elif op == "edit" and files:
            p = rng.choice(files)
            with open(p, "a") as f:
                f.write("more text " * rng.randint(1, 20))
        elif op == "rename" and files:
            p = rng.choice(files)
            p.rename(p.with_name(p.stem + "_v2" + p.suffix))
        elif op == "delete" and len(files) > 5:
            p = rng.choice(files)
            p.unlink(missing_ok=True)
        time.sleep(max(0.0, 1.0 / ops_per_sec + rng.uniform(-0.2, 0.2)))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--rate", type=float, default=0.5)
    args = ap.parse_args()
    run(args.dir, args.seed, args.duration, args.rate)
