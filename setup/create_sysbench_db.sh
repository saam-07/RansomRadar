#!/usr/bin/env bash
# Creates the MySQL database + user that dataset/benign_workloads.py's
# sysbench wrapper expects by default (db=sbtest, user=sbtest,
# password=password). Run this ONCE after setup/install_deps.sh, before
# using the "oltp" workload.
#
# If you'd rather use different credentials, skip this script and pass
# --db-name/--db-user/--db-password/--db-host to benign_workloads.py
# matching your own setup instead.
set -euo pipefail

echo "== Ensuring MySQL is running =="
sudo systemctl enable --now mysql

echo "== Creating sbtest database and user =="
sudo mysql <<'SQL'
CREATE DATABASE IF NOT EXISTS sbtest;
CREATE USER IF NOT EXISTS 'sbtest'@'localhost' IDENTIFIED BY 'password';
CREATE USER IF NOT EXISTS 'sbtest'@'127.0.0.1' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON sbtest.* TO 'sbtest'@'localhost';
GRANT ALL PRIVILEGES ON sbtest.* TO 'sbtest'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

echo "== Verifying connection with the credentials benign_workloads.py will use =="
mysql -h127.0.0.1 -usbtest -ppassword -e "SHOW DATABASES;" | grep sbtest && \
  echo "OK: sbtest database reachable with sbtest/password over TCP (127.0.0.1)."

echo ""
echo "Done. You can now run, e.g.:"
echo "  python3 dataset/benign_workloads.py sysbench --driver mysql --duration 60"
