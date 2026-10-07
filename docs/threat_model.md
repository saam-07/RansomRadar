# AdaptShield Threat Model & Security Specification

## 1. Security Objectives & Asset Definition

AdaptShield protects Linux endpoints, workstations, and servers against unauthorized cryptographic locking of user and application data.

### Core Assets Protected:
1. **User & Workload Files:** Documents, source code, databases, application storage located in monitored directories (`/home`, `/srv`, `/var/www`, `/opt/data`).
2. **System Availability:** Ensuring host operating systems, critical services (`systemd`, `sshd`, DBMS), and user logins remain unaffected by false alarms.
3. **Audit Integrity:** Unalterable record of detection alerts, forensic evidence, and rollback histories stored in `/var/log/adaptshield/` and `/var/lib/adaptshield/`.

---

## 2. Threat Actor Assumptions & Trust Boundaries

| Element | Trust Level | Description |
|---|:---:|---|
| **AdaptShield Agent** | **Trusted (Root)** | Runs as `root` with `CAP_SYS_ADMIN` in dedicated cgroups; manages fanotify, eBPF, and overlayfs mounts. |
| **Linux Kernel** | **Trusted** | Kernel version $\ge 5.9$, enforcing cgroups v2, fanotify permission events, and eBPF bytecode safety. |
| **System Daemons** | **Semi-Trusted** | `systemd`, `sshd`, package managers (`apt`, `dpkg`) operate with root privileges but are protected by safety allowlists. |
| **User Processes** | **Untrusted** | Any application, script, or binary executing in user space under standard or unprivileged service accounts. |
| **External Network** | **Untrusted** | Inbound network traffic, command-and-control channels, or remote payload downloaders. |

### Attacker Capability Matrix:
- **Capabilities Granted:**
  - Execute arbitrary unprivileged binaries or scripts.
  - Read, modify, rename, and delete files within permissions granted to user accounts.
  - Spawn concurrent child processes and worker threads.
- **Capabilities Denied:**
  - Cannot access `/sys/fs/cgroup/adaptshield` to thaw its own cgroup freezer.
  - Cannot unmount or modify `/var/lib/adaptshield/quarantine` due to filesystem permissions (`0700` owned by root).
  - Cannot forge or tamper with kernel-level fanotify or eBPF kprobe streams.

---

## 3. In-Scope Attack Scenarios

AdaptShield is explicitly designed to detect and contain:

1. **Rapid Mass Encryption (Fast Ransomware):**
   - High-throughput encryption loops modifying dozens of files per second.
   - *Mitigation:* Caught by Tier-0 modification rate within 1–2 evaluation windows.
2. **Intermittent / Header Encryption:**
   - Encrypting only headers, footers, or every $N$-th block to evade simplistic entropy detectors.
   - *Mitigation:* Multi-feature tracking (`concentration_gini`, `create_del_rate`, eBPF entropy spread).
3. **Rename-Then-Encrypt (Extension Morphing):**
   - Renaming targets to `.locked` or `.crypto` prior to encrypting file contents.
   - *Mitigation:* Dedicated `rename_rate` tracking combined with `t1_rename_rate` kernel syscall counter.
4. **Slow-and-Low Encryption:**
   - Evading burst rate limits by inserting intentional sleep intervals between file operations.
   - *Mitigation:* Multi-window EWMA risk smoothing accumulates persistent suspicious indicators over time.
5. **Multi-Process / Chaos Swarms:**
   - Distributing file encryption across multiple worker child processes.
   - *Mitigation:* Independent per-PID cgroup containment isolates attackers individually without halting sibling workloads.

---

## 4. Out-of-Scope Threats & Non-Goals

1. **Kernel-Level Rootkits & Zero-Day Kernel Exploits:**
   - If an adversary acquires arbitrary kernel code execution (ring 0), they can disable fanotify listeners or kill the agent process directly. Mitigation requires hardware-enforced secure boot, SELinux/AppArmor, and kernel lockdown.
2. **Pure Data Exfiltration (Double Extortion without Local Destruction):**
   - Exfiltration attacks that read files and transmit them over HTTPS without modifying local disk blocks do not exhibit ransomware encryption patterns. Mitigation requires network DLP and firewall egress controls.
3. **Physical / Block-Level Drive Destruction:**
   - Raw disk overwriting (e.g. `dd if=/dev/urandom of=/dev/sda`) or hardware destruction.
4. **Memory Injection into Allowlisted Daemons:**
   - If an attacker injects shellcode directly into an immune process (e.g. `sshd` or `mysqld`), AdaptShield will suppress automated containment to prevent denial of service. Mitigation requires ASLR, stack canaries, and endpoint memory protection.

---

## 5. Denial-of-Service Defense & Safety Rails

A security agent that halts critical system services or causes false-positive lockouts is unacceptable in production environments:

- **System Daemon Immunity:** Hardcoded immunity checks ensure PID 1, kernel threads, systemd daemons, SSH, and login sessions can never be frozen.
- **Process Allowlist:** Configurable name, path, and user allowlists protect high-churn legitimate workloads (e.g. `rsync`, `tar`, `restic`, DB indexing).
- **False-Positive Storm Panic Switch:** If more than 5 distinct PIDs trigger CRITICAL alerts within a 30-second sliding window, AdaptShield drops immediately to `monitor` mode, raises a high-priority storm alert, and avoids freezing the machine.
- **Automatic Manual Timeout:** When running under `manual` policy, unattended processes automatically resolve to `release` or `confirm` after a configurable timeout (default 300s) to prevent indefinite lockups.
