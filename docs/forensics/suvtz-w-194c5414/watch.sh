#!/bin/bash
# Watch one acceptance round: boot change / chain progress / restore markers.
set -u
A=/mnt/c/WINDOWS/system32/adb.exe
S=100.120.155.127:5555
OUT=/tmp/opencode/accept_watch/boot194c5414
LOG=$OUT/watch.log
BOOT0=${BOOT0:-194c5414}
ROUNDS=${ROUNDS:-180}

say() { printf '[%s] %s\n' "$(date +%F' '%T)" "$*" >> "$LOG"; }
say "=== watch start boot0=$BOOT0 rounds=$ROUNDS ==="

for i in $(seq 1 "$ROUNDS"); do
  TS=$(date +%H:%M:%S)
  # host side postlock.log tail (no adb needed)
  HT=$(grep -aE '==>|quiet after|DETACHED|restore OK|POSTLOCK|ERROR|WARN|scan:' "$OUT/postlock.log" 2>/dev/null | tail -2 | tr '\n' '|' | cut -c1-220)
  # one adb round-trip
  R=$(timeout 20 "$A" -s "$S" shell '
    echo "B:$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
    echo "C:$(grep -ac "root=1" /data/local/tmp/postlock_chain.log 2>/dev/null)"
    grep -aE "win tick|set-fail|pipe-physrw-summary|CHAIN_EXIT|waves=|route done|payload gate" /data/local/tmp/postlock_chain.log 2>/dev/null | tail -2
    echo "RS:$(ls -l /data/local/tmp/postlock_restore.log 2>/dev/null | wc -l)"
    grep -aE "suvtz-w:|overlay-retired|RESTORE-OK|STRICT-OK|WARN-suvtz|holder pid" /data/local/tmp/postlock_restore.log 2>/dev/null | tail -4
  ' 2>/dev/null | tr -d '\r')
  B8=$(printf '%s\n' "$R" | sed -n 's/^B:\(.\{8\}\).*/\1/p' | head -1)
  CH=$(printf '%s\n' "$R" | sed -n 's/^C://p' | head -1)
  REST=$(printf '%s\n' "$R" | grep -aE 'suvtz-w:|overlay-retired|RESTORE-OK|STRICT-OK|WARN-suvtz|holder pid' | tail -3 | tr '\n' '|' | cut -c1-300)
  CHL=$(printf '%s\n' "$R" | grep -aE 'win tick|set-fail|pipe-physrw-summary|CHAIN_EXIT|waves=|route done|payload gate' | tail -2 | tr '\n' '|' | cut -c1-300)
  RSN=$(printf '%s\n' "$R" | sed -n 's/^RS://p' | head -1)
  say "i=$i boot=${B8:-?} root1=${CH:-?} restore_file=${RSN:-?} chain=[$CHL] rest=[$REST] host=[$HT]"
  if [ -n "$B8" ] && [ "$B8" != "$BOOT0" ]; then
    say "*** BOOT CHANGED $BOOT0 -> $B8 (panic/reboot) -> stop watch ***"
    exit 0
  fi
  # stop when postlock.sh has exited and restore marker seen (or clear failure)
  if ! ps -ef | grep -q '[p]ostlock\.sh'; then
    say "*** postlock.sh exited -> stop watch (tail below) ***"
    grep -aE 'POSTLOCK|restore OK|scan:|ERROR|WARN' "$OUT/postlock.log" 2>/dev/null | tail -8 | sed 's/^/    /' >> "$LOG"
    exit 0
  fi
  sleep 20
done
say "*** watch rounds exhausted ***"
