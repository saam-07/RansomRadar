"""
Tier 1 control plane: loads eBPF program via BCC, attaches kprobes,
and streams perf-buffer events into Python.
Supports graceful degradation when BCC or kernel headers are missing.
"""
import os
import time
import ctypes
from pathlib import Path

from .math_utils import shannon_entropy

try:
    from bcc import BPF
    _BCC_AVAILABLE = True
    _BCC_IMPORT_ERROR = None
except Exception as exc:
    BPF = None
    _BCC_AVAILABLE = False
    _BCC_IMPORT_ERROR = str(exc)


def is_tier1_available() -> bool:
    """Returns True if BCC is available on the current system."""
    return _BCC_AVAILABLE


def get_tier1_status() -> dict:
    """Returns detailed status of Tier-1 eBPF subsystem."""
    return {
        "available": _BCC_AVAILABLE,
        "error": _BCC_IMPORT_ERROR,
        "mode": "ebpf_bcc" if _BCC_AVAILABLE else "tier0_fallback",
    }


def _find_bpf_src() -> str:
    candidates = [
        Path(__file__).parent.parent / "ebpf" / "tier1_trace.bpf.c",
        Path(__file__).parent.parent.parent.parent / "ebpf" / "tier1_trace.bpf.c",
        Path("ebpf/tier1_trace.bpf.c"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return str(candidates[0])


class Tier1Tracer:
    def __init__(self):
        if not _BCC_AVAILABLE:
            raise RuntimeError(
                f"Tier-1 eBPF tracing requires BCC and Linux kernel headers, but BCC is not available: {_BCC_IMPORT_ERROR}"
            )

        src_path = _find_bpf_src()
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()

        self.bpf = BPF(text=src)
        self.bpf.attach_kprobe(event="__x64_sys_write", fn_name="trace_write_entry")

        for sym, fn in [
            ("__x64_sys_renameat2", "trace_renameat2_entry"),
            ("__x64_sys_unlinkat", "trace_unlinkat_entry"),
        ]:
            try:
                self.bpf.attach_kprobe(event=sym, fn_name=fn)
            except Exception as e:
                pass

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
        self.bpf.perf_buffer_poll(timeout=timeout_ms)

    def drain_events(self) -> list:
        out, self._events_buffer = self._events_buffer, []
        return out
