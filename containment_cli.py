"""
Human-in-the-loop control tool for RollbackPolicy.MANUAL.

When the daemon freezes a process under the MANUAL policy, it writes a
pending-decision file and waits. Use this tool to inspect the evidence
and make the call:

    python3 containment_cli.py list --control-dir results/raw/control
    python3 containment_cli.py show --control-dir results/raw/control --pid 12345
    python3 containment_cli.py release --control-dir results/raw/control --pid 12345
    python3 containment_cli.py confirm --control-dir results/raw/control --pid 12345

'release' = false positive, unfreeze and let the process continue normally.
'confirm' = true positive, quarantine+rollback+kill (handled by the daemon,
            which is polling for this decision -- this CLI only writes the
            decision file, it does not perform containment actions itself).
"""
import argparse
import json
import time
from pathlib import Path


def list_pending(control_dir: str):
    files = sorted(Path(control_dir).glob("decision_pid*.json"))
    if not files:
        print("No pending decisions.")
        return
    for f in files:
        data = json.loads(f.read_text())
        age_s = time.time() - data.get("requested_at", time.time())
        print(f"pid={data['pid']:<8} status={data['status']:<10} age={age_s:.0f}s  ({f.name})")


def show(control_dir: str, pid: int):
    f = Path(control_dir) / f"decision_pid{pid}.json"
    if not f.exists():
        print(f"No pending decision file for pid {pid}.")
        return
    data = json.loads(f.read_text())
    print(json.dumps(data, indent=2))


def set_decision(control_dir: str, pid: int, decision: str):
    f = Path(control_dir) / f"decision_pid{pid}.json"
    if not f.exists():
        print(f"No pending decision file for pid {pid} -- nothing to update.")
        return
    data = json.loads(f.read_text())
    data["status"] = decision
    data["decided_at"] = time.time()
    f.write_text(json.dumps(data, indent=2))
    print(f"Recorded decision '{decision}' for pid {pid}. "
          f"The running daemon will act on this within one poll cycle.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--control-dir", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    p_show = sub.add_parser("show")
    p_show.add_argument("--pid", type=int, required=True)
    p_release = sub.add_parser("release")
    p_release.add_argument("--pid", type=int, required=True)
    p_confirm = sub.add_parser("confirm")
    p_confirm.add_argument("--pid", type=int, required=True)

    args = ap.parse_args()
    if args.cmd == "list":
        list_pending(args.control_dir)
    elif args.cmd == "show":
        show(args.control_dir, args.pid)
    elif args.cmd == "release":
        set_decision(args.control_dir, args.pid, "release")
    elif args.cmd == "confirm":
        set_decision(args.control_dir, args.pid, "confirm")


if __name__ == "__main__":
    main()
