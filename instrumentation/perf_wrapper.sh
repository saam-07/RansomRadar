#!/usr/bin/env bash
# Wraps a workload command with `perf stat` to capture task-clock, context
# switches, and page-faults -- used to quantify monitored-workload
# degradation under each configuration (baseline vs AdaptShield).
# Usage: perf_wrapper.sh <output.txt> -- <workload command...>
set -euo pipefail
OUT="$1"; shift
if [ "$1" == "--" ]; then shift; fi
perf stat -o "$OUT" -e task-clock,context-switches,page-faults,cycles,instructions -- "$@"
