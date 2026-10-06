// AdaptShield Tier 1 -- expensive, escalation-triggered tracer.
// Loaded via BCC (see adaptshield/tier1_bridge.py). Only attached
// for the specific suspect PID chosen by the Tier-0 escalation decision.
//
// Captures, per syscall event: pid, syscall id, timestamp, byte count
// (for write), and a sampled buffer prefix (for entropy computation in
// user space -- we deliberately do NOT compute entropy in-kernel to keep
// the eBPF program simple and verifiable).

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define SAMPLE_BYTES 64  // only sample a small prefix of each write buffer;
                          // this bounds per-event kernel->user copy cost,
                          // which is the whole point of Tier 1 being "expensive
                          // but bounded" rather than "unbounded".

struct event_t {
    u32 pid;
    u64 ts_ns;
    u32 syscall; // 0=write 1=openat 2=rename 3=unlink
    u64 arg_size;
    char sample[SAMPLE_BYTES];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(target_pid, u32, u8);  // set of PIDs we are currently tracing

static inline int is_target(u32 pid) {
    u8 *v = target_pid.lookup(&pid);
    return v != 0;
}

int trace_write_entry(struct pt_regs *ctx, unsigned int fd, const char __user *buf, size_t count) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target(pid)) return 0;

    struct event_t evt = {};
    evt.pid = pid;
    evt.ts_ns = bpf_ktime_get_ns();
    evt.syscall = 0;
    evt.arg_size = count;
    bpf_probe_read_user(&evt.sample, SAMPLE_BYTES, buf);
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

int trace_renameat2_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target(pid)) return 0;
    struct event_t evt = {};
    evt.pid = pid;
    evt.ts_ns = bpf_ktime_get_ns();
    evt.syscall = 2;
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

int trace_unlinkat_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target(pid)) return 0;
    struct event_t evt = {};
    evt.pid = pid;
    evt.ts_ns = bpf_ktime_get_ns();
    evt.syscall = 3;
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
