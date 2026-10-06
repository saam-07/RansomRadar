# Baseline 4 — Literature Reference Point

Source: Reategui, Pletka, Diamantopoulos, *"On the Generalizability of
Machine Learning-based Ransomware Detection in Block Storage,"* arXiv:2412.21084.

## What this baseline is
Their pipeline runs at the **block-storage / device-mapper layer** via a
custom kernel module (`dm-entropy`) sitting *underneath* the filesystem.
AdaptShield runs one layer *above* that, at the filesystem-event/process
layer (fanotify + eBPF syscall tracing). These are genuinely different
observation points in the I/O stack.

## What we reproduce
We borrow their **feature design**, adapted to our layer:

| Their block-layer feature | Our filesystem-layer analogue |
|---|---|
| Per-I/O entropy histogram | Per-write sampled entropy (`tier1_bridge.py: shannon_entropy`) |
| LBA (logical block address) locality/positional features | File-offset / extent locality within a file (implement as an addition to `feature_aggregator.py` if time allows — NOT implemented in the v1 pipeline above; flag as future work if you don't get to it) |
| Transfer-size histogram | `t1_mean_write_size` / write-size distribution per window |
| Cross-filesystem (NTFS vs EXT4 vs XFS) evaluation | Cross-filesystem (ext4 vs btrfs vs xfs) evaluation, same idea, our layer |
| OLTP (MySQL/PostgreSQL, sysbench) as an adversarial benign workload | Same tool (`sysbench`), same idea |

## What we do NOT reproduce
- Their exact `dm-entropy` kernel module or its specific entropy-computation
  algorithm internals.
- Their exact reported numbers (e.g., the PostgreSQL 93.33% FPR figure). Do
  **not** claim you replicated Table 1/2 of their paper. You may cite their
  number as a literature fact and compare your own, independently measured
  FPR on the same *class* of workload (OLTP) at your layer — but it is a
  qualitative comparison of *pattern* (does the generalization problem
  reappear at this layer too?), not a numeric reproduction.

## How to use this in your report
State plainly: *"We treat [Reategui et al.] as our strongest literature
baseline in spirit — same problem, same workload classes, different OS
layer — and reproduce their feature *design*, not their kernel module or
numeric results."* This is the honest framing required by the roadmap.
