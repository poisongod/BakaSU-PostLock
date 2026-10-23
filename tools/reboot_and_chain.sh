#!/usr/bin/env bash
# Reboot -> catch the app-uid tailscaled window -> run postlock.sh on the
# fresh boot -> report verify.  One-shot recovery per RECOVERY_PLAN.md.
#
# Why the window matters: after reboot the tailnet is dead (shell-uid
# daemon died with the boot); the app's BOOT_COMPLETED autostart starts an
# app-uid tailscaled that comes online for ~10-86s before HANS freezes it
# (LcdOff).  We must adb connect inside that window -- reconnect loops
# every 5s from the moment we issue the reboot.
#
# Usage:  SERIAL=100.71.26.6:5555 bash tools/reboot_and_chain.sh
#         (SERIAL defaults to the tailnet node)
set -uo pipefail

SERIAL="${SERIAL:-100.71.26.6:5555}"
ADB_BIN="${ADB_BIN:-$(command -v adb.exe || command -v adb)}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
ab() { timeout "${2:-30}" "$ADB_BIN" -s "$SERIAL" "${@:3}"; }

echo "== [1/4] reboot =="
timeout 30 "$ADB_BIN" -s "$SERIAL" reboot || echo "WARN: reboot cmd failed (may already be down)"
sleep 8

echo "== [2/4] catch tailnet window (up to 10 min) =="
CAUGHT=0
for i in $(seq 1 60); do
  if timeout 15 "$ADB_BIN" connect "$SERIAL" 2>&1 | tr -d '\r' | grep -q "connected to"; then
    BOOT=$(ab shell 'echo B; getprop sys.boot_completed' 15 2>&1 | tr -d '\r' | grep -c '^1$')
    [ "$BOOT" = "1" ] && { CAUGHT=1; break; }
  fi
  sleep 5
done
if [ "$CAUGHT" != 1 ]; then
  echo "FAIL: no window within 10min -- device may be stopped/frozen; user must open PostLock once"
  exit 2
fi
echo "  window caught at attempt $i"

echo "== [3/4] postlock.sh (fresh boot + detached chain) =="
cd "$REPO" || exit 3
ADB="$ADB_BIN" SERIAL="$SERIAL" timeout 560 bash tools/postlock.sh
PL_RC=$?
echo "  postlock.sh rc=$PL_RC"

echo "== [4/4] report =="
ab shell 'grep -c POSTLOCK-RESTORE-OK /data/local/tmp/postlock_restore.log 2>/dev/null; ls -la /product/bin/su 2>&1 | head -1; head -c 60 /data/misc/adb/adb_keys 2>/dev/null | tr -d "\n"; echo' 20 2>&1 | tr -d '\r' | sed 's/^/  /'
echo "DONE (postlock rc=$PL_RC)"
[ "$PL_RC" = 0 ]
