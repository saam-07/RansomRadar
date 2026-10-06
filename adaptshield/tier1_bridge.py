"""
Tier 1 control plane: loads the eBPF program (ebpf/tier1_trace.bpf.c) via
BCC, adds/removes PIDs from the in-kernel target_pid map, and streams
perf-buffer events into Python, where entropy is computed on the sampled
buffer prefix.

Design point that matters for the roadmap's cost-model claim: attaching
kprobes happens ONCE at process start (cheap, one-time cost); the
PER-EVENT cost is gated by the in-kernel `is_target()` check, so a
resident-but-inactive Tier-1 program costs only a hash-map lookup per
syscall system-wide, not a full trace. This is what allows a fair
"always-on Tier-1" baseline comparison in Sec. 6/7 of the roadmap.
"""
import os
import time
import ctypes

from bcc import BPF

from .math_utils import shannon_entropy

_BPF_SRC_PATH = os.path.join(os.path.dirname(__file__), "..", "ebpf", "tier1_trace.bpf.c")


class Tier1Tracer:
    def __init__(self):
        with open(_BPF_SRC_PATH) as f:
            src = f.read()
        self.bpf = BPF(text=src)
        self.bpf.attach_kprobe(event="__x64_sys_write", fn_name="trace_write_entry")
        # renameat2 / unlinkat symbol names vary slightly by kernel build;
        # fall back gracefully and log if a probe point is missing.
        for sym, fn in [
            ("__x64_sys_renameat2", "trace_renameat2_entry"),
            ("__x64_sys_unlinkat", "trace_unlinkat_entry"),
        ]:
            try:
                self.bpf.attach_kprobe(event=sym, fn_name=fn)
            except Exception as e:
                print(f"[tier1_bridge] WARNING: could not attach {sym}: {e}")

        self._events_buffer = []
        self.bpf["events"].open_perf_buffer(self._handle_event)
        self._target_map = self.bpf["target_pid"]

    def _handle_event(self, cpu, data, size):
        evt = self.bpf["events"].event(data)
        entropy = shannon_entropy(bytes(evt.sample)) if evt.syscall == 0 else None
        self._events_buffer.append({
            "pid": evt.pid,
            "ts_ns": evt.ts_ns,
            "syscall": evt.syscall,
            "arg_size": evt.arg_size,
            "entropy": entropy,
        })

    def escalate(self, pid: int):
        """Start expensive tracing for this PID. Timestamp this call with
        CLOCK_MONOTONIC in the CALLER so escalation latency can be measured
        end-to-end (Tier-0 decision -> Tier-1 active)."""
        key = ctypes.c_uint32(pid)
        val = ctypes.c_uint8(1)
        self._target_map[key] = val

    def deescalate(self, pid: int):
        key = ctypes.c_uint32(pid)
        try:
            del self._target_map[key]
        except KeyError:
            pass

    def poll(self, timeout_ms: int = 100):
        """Drain perf buffer; call this in a tight loop from the daemon."""
        self.bpf.perf_buffer_poll(timeout=timeout_ms)

    def drain_events(self) -> list:
        out, self._events_buffer = self._events_buffer, []
        return out
