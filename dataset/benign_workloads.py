"""
Wraps REAL Linux tools as the "legitimate high-volume" workload class
(roadmap Sec 4 / Sec 7.1). Using the actual tools -- not synthetic
approximations -- is what makes the false-positive results meaningful.
"""
import argparse
import subprocess
from pathlib import Path


def run_backup_rsync(src: str, dst: str):
    Path(dst).mkdir(parents=True, exist_ok=True)
    subprocess.run(["rsync", "-a", "--delete", src.rstrip("/") + "/", dst], check=True)


def run_backup_tar(src: str, out_tar_gz: str):
    subprocess.run(["tar", "-czf", out_tar_gz, "-C", str(Path(src).parent), Path(src).name],
                    check=True)


def run_sysbench_oltp(db_driver: str, tables: int, table_size: int,
                       threads: int, duration_s: int, distribution: str = "uniform",
                       db_name: str = "sbtest", db_user: str = "sbtest",
                       db_password: str = "password", db_host: str = "127.0.0.1",
                       db_port: int | None = None):
    """db_driver: 'mysql' | 'pgsql'.

    Default credentials (db_name=sbtest, db_user=sbtest, db_password=password)
    match EXACTLY the account created by setup/create_sysbench_db.sh -- run
    that script once before using this function/CLI, or pass different
    --db-* flags matching whatever account you set up yourself.
    """
    conn_flags = [f"--{db_driver}-db={db_name}", f"--{db_driver}-user={db_user}",
                  f"--{db_driver}-password={db_password}", f"--{db_driver}-host={db_host}"]
    if db_port:
        conn_flags.append(f"--{db_driver}-port={db_port}")

    prepare_cmd = [
        "sysbench", "oltp_read_write",
        f"--db-driver={db_driver}", *conn_flags,
        f"--tables={tables}", f"--table-size={table_size}",
        "prepare",
    ]
    run_cmd = [
        "sysbench", "oltp_read_write",
        f"--db-driver={db_driver}", *conn_flags,
        f"--tables={tables}", f"--table-size={table_size}",
        f"--threads={threads}", f"--time={duration_s}",
        f"--rand-type={distribution}",
        "run",
    ]
    subprocess.run(prepare_cmd, check=True)
    subprocess.run(run_cmd, check=True)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_rsync = sub.add_parser("rsync")
    p_rsync.add_argument("--src", required=True)
    p_rsync.add_argument("--dst", required=True)

    p_tar = sub.add_parser("tar")
    p_tar.add_argument("--src", required=True)
    p_tar.add_argument("--out", required=True)

    p_sysbench = sub.add_parser("sysbench")
    p_sysbench.add_argument("--driver", choices=["mysql", "pgsql"], default="mysql")
    p_sysbench.add_argument("--tables", type=int, default=8)
    p_sysbench.add_argument("--table-size", type=int, default=100000)
    p_sysbench.add_argument("--threads", type=int, default=4)
    p_sysbench.add_argument("--duration", type=int, default=60)
    p_sysbench.add_argument("--distribution", choices=["uniform", "pareto"], default="uniform")
    p_sysbench.add_argument("--db-name", default="sbtest")
    p_sysbench.add_argument("--db-user", default="sbtest")
    p_sysbench.add_argument("--db-password", default="password")
    p_sysbench.add_argument("--db-host", default="127.0.0.1")
    p_sysbench.add_argument("--db-port", type=int, default=None)

    args = ap.parse_args()
    if args.cmd == "rsync":
        run_backup_rsync(args.src, args.dst)
    elif args.cmd == "tar":
        run_backup_tar(args.src, args.out)
    elif args.cmd == "sysbench":
        run_sysbench_oltp(args.driver, args.tables, args.table_size,
                           args.threads, args.duration, args.distribution,
                           db_name=args.db_name, db_user=args.db_user,
                           db_password=args.db_password, db_host=args.db_host,
                           db_port=args.db_port)


if __name__ == "__main__":
    main()
