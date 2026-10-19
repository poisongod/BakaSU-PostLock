#!/bin/bash
# Pull chain-run artifacts after an attempt: runner log (on /sdcard, survives
# reboot), reboot verdict ledger, and pstore oops files if the kernel panicked.
# Usage: tools/chain_pull.sh [outdir]   (default outdir=/tmp/opencode)
set -uo pipefail
ADB="${ADB:-/mnt/c/WINDOWS/system32/adb.exe}"
OUT="${1:-/tmp/opencode}"
mkdir -p "$OUT"
"$ADB" pull /sdcard/chain5.log "$OUT/chain5.log" && echo "pulled chain5.log" || echo "chain5.log missing"
"$ADB" pull /sdcard/chain_run.state "$OUT/chain_run.state" 2>/dev/null || true
"$ADB" pull /sdcard/chain_reboot.log "$OUT/chain_reboot.log" 2>/dev/null || true
for f in console-ramoops-0 console-ramoops dmesg-ramoops-0 dmesg-ramoops; do
  "$ADB" pull "/sys/fs/pstore/$f" "$OUT/pstore_$f" 2>/dev/null && echo "pulled pstore_$f" || true
done
echo "== boot identity:"
"$ADB" shell 'echo boot_id=$(cat /proc/sys/kernel/random/boot_id) uptime=$(cut -d" " -f1 /proc/uptime)' || true
echo "== contents of $OUT:"
ls -la --time-style=+%F_%T "$OUT" | tail -n +2
