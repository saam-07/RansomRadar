"""
AdaptShield Containment CLI -- Compatibility Shim.

This file provides backward-compatibility for legacy scripts invoking `containment_cli.py`.
Directly delegates to the unified `adaptshield` CLI implementation.
"""
import sys
from adaptshield.cli import main as cli_main
from adaptshield.response.containment_manager import (
    request_manual_decision,
    check_manual_decision,
    clear_manual_decision,
)

if __name__ == "__main__":
    # If legacy syntax: 'python containment_cli.py list --control-dir DIR'
    # Translate to adaptshield CLI arguments
    args = sys.argv[1:]
    if len(args) >= 1 and args[0] in ("list", "show", "release", "confirm"):
        cmd = args[0]
        # Extract --pid and --control-dir if present
        pid = None
        ctrl_dir = None
        for i, a in enumerate(args):
            if a == "--pid" and i + 1 < len(args):
                pid = args[i + 1]
            elif a == "--control-dir" and i + 1 < len(args):
                ctrl_dir = args[i + 1]

        sys_args = ["adaptshield", cmd]
        if pid:
            sys_args.append(pid)
        sys.argv = sys_args
    cli_main()
