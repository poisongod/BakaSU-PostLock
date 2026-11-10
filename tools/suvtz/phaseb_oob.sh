#!/bin/bash
# SUVTZ Phase B/C out-of-band transport fidelity check.
#
# Phase B stages restore-only assets inside W by cp from N.  The in-band log
# lines ("cksum ok", added for Phase C) prove the comparison at restore time;
# this script re-reads the live W bytes through the running kernel:s0 holder
# and compares them against a reference:
#
#   * N copy still present  -> reference = the N original (Phase B semantics)
#   * N copy purged         -> reference = the crc recorded in-band during the
#                              restore round (Phase C semantics; this also
#                              proves the recorded value was not fabricated,
#                              because the live W bytes must still match it)
#
# Requires: a live holder (created by restore during a chain round).
#
# Usage: ADB=/path/to/adb bash tools/suvtz/phaseb_oob.sh [outdir]
#        SER=<serial>  target device (default: the LAN tailnet address)
#        ADB           adb binary; defaults to `adb` in PATH
set -u
ADB="${ADB:-adb}"
SER="${SER:-100.120.155.127:5555}"
OUT="${1:-/tmp/opencode/accept_watch/phaseb_oob}"
STAGE=/data/local/tmp/ksu_boot
WMP=/data/local/tmp/.w
WNS=$STAGE/wns
RLOG=/data/local/tmp/postlock_restore.log

# Hard timeout on every call: an offline node makes `adb shell` block for
# minutes (measured), and this script is meant to run unattended.
ab() { timeout 40 "$ADB" -s "$SER" "$@" 2>/dev/null | tr -d '\r'; }

mkdir -p "$OUT"
REPORT="$OUT/phaseb_transfer.txt"
: > "$REPORT"
say() { echo "$@" | tee -a "$REPORT"; }

say "== SUVTZ Phase B/C out-of-band transport fidelity =="
say "time=$(date -u +%FT%TZ)"
BOOT=$(ab shell cat /proc/sys/kernel/random/boot_id)
say "boot=${BOOT}"
# `pgrep -f` would match this very script's command line; anchor on the helper
# invocation instead (wns hold <pid> <path> <sig>).
PID=$(ab shell "pgrep -f '^$WNS hold '" | head -n1)
say "holder_pid=${PID:-none}"
if [ -z "${PID:-}" ]; then
	say "RESULT=SKIP (no live holder)"
	exit 2
fi

say "holder_ns=$(ab shell "su -c 'readlink /proc/$PID/ns/mnt'")"
say "n_side_stage=$(ab shell "if [ -e $WMP/stage ]; then echo visible; else echo ENOENT; fi")"
say "ocsk=$(ab shell 'if [ -d /sys/module/oplus_check_suppress ]; then echo loaded; else echo absent; fi')"
say ""

# In-band reference table: "<file> <crc> <size>" from the restore log.
INBAND=$(ab shell "cat $RLOG 2>/dev/null" | grep -o 'suvtz-w: cksum ok [^ ]* [0-9]* [0-9]*' | awk '{print $4" "$5" "$6}')

fail=0
for f in oplus_check_suppress.ko postlock_adbkey.pub pp_adb_tcp.bin; do
	n=""
	if [ "$(ab shell "if [ -f $STAGE/$f ]; then echo y; fi")" = "y" ]; then
		# adb shell merges stderr into stdout, and `wns run` prints its
		# diagnostic line there, so drop those before parsing.
		n=$(ab shell "cksum < $STAGE/$f" | grep -v '^wns:' | awk '{print $1" "$2}')
		src="N"
	else
		n=$(echo "$INBAND" | awk -v f="$f" '$1==f{print $2" "$3}')
		src="in-band"
	fi
	w=$(ab shell "su -c 'timeout 20 $WNS run $PID /system/bin/cksum $WMP/stage/$f'" | grep -v '^wns:' | awk '{print $1" "$2}')
	if [ -z "$n" ]; then
		say "SKIP  $f (no N copy and no in-band reference)"
		continue
	fi
	if [ -n "$w" ] && [ "$n" = "$w" ]; then
		say "OK    $f  ref=$src cksum=$n"
	else
		say "FAIL  $f  ref=$src n=[$n] w=[$w]"
		fail=1
	fi
done

say ""
if [ "$fail" -eq 0 ]; then
	say "RESULT=PASS (live W copies match their references)"
else
	say "RESULT=FAIL"
fi
exit "$fail"
