#!/bin/bash
# live_chain.sh — shell-permission live chain log viewer (no root needed).
# Incrementally tails /data/local/tmp/chain5.log key lines + state heartbeat.
# Usage: tools/live_chain.sh <serial> <known-boot-prefix> [poll-sec]
# Stops on: DONE(rc=), boot change, or device offline x3.
SERIAL=${1:?serial}
BOOTP=${2:?boot-prefix}
POLL=${3:-6}
LAST=0
EMPTY=0
while true; do
  OUT=$(adb.exe -s "$SERIAL" shell "
L=\$(wc -l < /data/local/tmp/chain5.log 2>/dev/null)
if [ -n \"\$L\" ] && [ \"\$L\" -gt 0 ] && [ \"\$L\" -gt $LAST ]; then
  sed -n \"$LAST,\$ p\" /data/local/tmp/chain5.log 2>/dev/null | \
    grep -aE 'win tick|contract|root child|root self|insmod|finitmod|fail|dead|panic|cfi |sig_enforce|CHAIN|payload|prepare|skip' | tail -40
  echo \"@@LINES=\$L@@\"
fi
cat /data/local/tmp/chain_run.state 2>/dev/null | tail -1
" 2>/dev/null | tr -d '\r')
  if [ -z "$OUT" ]; then
    EMPTY=$((EMPTY+1))
    echo "[$(date +%H:%M:%S)] EMPTY(x$EMPTY)"
    [ $EMPTY -ge 3 ] && { echo "DEVICE_OFFLINE"; exit 2; }
  else
    EMPTY=0
    echo "[$(date +%H:%M:%S)]"
    echo "$OUT" | head -45
    echo "$OUT" | grep -q "rc=" && exit 0
    echo "$OUT" | grep -q "$BOOTP" || { echo "BOOT_CHANGED"; exit 3; }
  fi
  N=$(echo "$OUT" | grep -o "@@LINES=[0-9]*" | cut -d= -f2)
  [ -n "$N" ] && LAST=$N
  sleep "$POLL"
done
