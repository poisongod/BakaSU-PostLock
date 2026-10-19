#!/bin/bash
# Host-side idempotent bootstrap for the CVE-2026-43499 chain run. Run this
# whenever the device comes online (after a reboot temp is wiped): recreates
# /data/local/temp, pushes preload.so + run_fops.sh, fixes the SELinux label.
# Usage: tools/prep_device.sh [PROJECT]   (default PROJECT=pfum10c48)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="${1:-pfum10c48}"
ADB="${ADB:-/mnt/c/WINDOWS/system32/adb.exe}"
SO="$ROOT/build/$PROJECT/bin/preload.so"
RUN="$ROOT/tools/run_fops.sh"

[ -f "$SO" ] || { echo "missing $SO -- run: make PROJECT=$PROJECT -j\$(nproc)"; exit 1; }
[ -f "$RUN" ] || { echo "missing $RUN"; exit 1; }

echo "== waiting for device..."
"$ADB" wait-for-device
echo "== model: $("$ADB" shell getprop ro.product.model | tr -d '\r')"

echo "== previous run state / reboot verdict:"
"$ADB" shell 'cat /sdcard/chain_run.state 2>/dev/null; tail -c 400 /sdcard/chain_reboot.log 2>/dev/null' || true

echo "== recreate temp + labels:"
# -R: stale children keep system_data_file from before the first chcon and
# adbd (shell) then gets EACCES overwriting them (seen on preload.so).
# `|| true`: -R walks into the mounted ovl/lower subtree and those bind-mount
# endpoints return EOPNOTSUPP — expected, only real files need relabeling;
# a bare failure would abort prep here (set -e) before any push.
"$ADB" shell '/system/bin/su -c "mkdir -p /data/local/temp && chmod 777 /data/local/temp && chcon -R u:object_r:shell_data_file:s0 /data/local/temp || true"'

echo "== push artifacts:"
"$ADB" push "$SO" /data/local/temp/preload.so
"$ADB" push "$RUN" /data/local/temp/run_fops.sh
"$ADB" shell 'chmod 755 /data/local/temp/preload.so /data/local/temp/run_fops.sh'

# The chain itself sets permissive mid-run, but its early kprobe/tracefs
# probes run before that; needs root (plain `setenforce 0` as shell = EPERM).
"$ADB" shell '/system/bin/su -c "setenforce 0" 2>/dev/null || true'

# pipe-user-pages-soft defaults to 16384 pages = 512 pipes at 32 slots; the
# kmalloc-2k drain needs 2048 to exhaust the free list and force buddy grows.
"$ADB" shell '/system/bin/su -c "echo 262144 > /proc/sys/fs/pipe-user-pages-soft" 2>/dev/null || true'

echo "== verify:"
"$ADB" shell 'ls -la /data/local/temp/preload.so /data/local/temp/run_fops.sh; getenforce'
echo "== bootstrap done. Next:"
echo "   $ADB shell sh /data/local/temp/run_fops.sh"
echo "   $ADB pull /sdcard/chain5.log ."
