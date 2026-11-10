#!/bin/bash
# SUVTZ v3 fresh-boot acceptance criteria checker (17 criteria).
#
# Reads the evidence files produced by a fresh-boot acceptance run and prints
# PASS/FAIL/UNKNOWN per criterion.  Expected inputs in <outdir>:
#   postlock.log / postlock_restore.log / postlock_chain.log / verdict.txt
#   watch.log (optional rc fallback)
# and the scan snapshot under $SUVTZ_SCAN_BASE/auto_<boot8>/stdout.txt.
#
# Usage: bash tools/suvtz/check_accept.sh [outdir]
#        (default outdir: /tmp/opencode/accept_watch)
set -u

OUT="${1:-/tmp/opencode/accept_watch}"
HOST="$OUT/postlock.log"
REST="$OUT/postlock_restore.log"
CHAIN="$OUT/postlock_chain.log"

np=0; nf=0; nu=0
row() { # row <status> <id> <detail>
	local st="$1" id="$2"; shift 2
	case "$st" in
		PASS) np=$((np+1)) ;;
		FAIL) nf=$((nf+1)) ;;
		*)    nu=$((nu+1)) ;;
	esac
	printf '%-7s %-8s %s\n' "$st" "$id" "$*"
}
cnt() { # cnt <file> <pattern> -> count (0 when missing)
	[ -f "$1" ] || { echo 0; return; }
	local n
	n=$(grep -c -- "$2" "$1" 2>/dev/null || true)
	echo "${n:-0}"
}
has() { [ "$(cnt "$1" "$2")" -gt 0 ]; }

echo "== SUVTZ v3 acceptance check =="
echo "outdir=$OUT"
for f in "$HOST" "$REST" "$CHAIN"; do
	[ -f "$f" ] && printf '  %-24s %s bytes\n' "$(basename "$f")" "$(wc -c < "$f")" \
		|| printf '  %-24s MISSING\n' "$(basename "$f")"
done
echo

# ---- 1. overlay retirement ----
if has "$REST" 'suvtz: overlay-retired mounts=0'; then
	row PASS RETIRE-0 "$(grep -m1 'suvtz: overlay-retired' "$REST")"
elif has "$REST" 'suvtz: overlay-retired'; then
	row FAIL RETIRE-0 "mounts != 0: $(grep -m1 'suvtz: overlay-retired' "$REST")"
elif [ -f "$REST" ]; then
	row FAIL RETIRE-0 "no 'suvtz: overlay-retired' line in restore log"
else
	row UNKNOWN RETIRE-0 "restore log missing"
fi

if has "$REST" 'WARN-suvtz-overlay-residual'; then
	row FAIL RETIRE-RESID "$(grep -m1 'WARN-suvtz-overlay-residual' "$REST")"
elif [ -f "$REST" ]; then
	row PASS RETIRE-RESID "no WARN-suvtz-overlay-residual"
else
	row UNKNOWN RETIRE-RESID "restore log missing"
fi

if [ -f "$REST" ]; then
	n=$(cnt "$REST" 'mount -t overlay')
	[ "$n" = 0 ] && row PASS RETIRE-NOBUILD "overlay 创建块已删除（mount -t overlay 计数 0）" \
		|| row FAIL RETIRE-NOBUILD "restore 里仍有 mount -t overlay x$n"
else
	row UNKNOWN RETIRE-NOBUILD "restore log missing"
fi

# ---- 2. holder ----
if has "$REST" 'suvtz-w: holder pid='; then
	line=$(grep -m1 'suvtz-w: holder pid=' "$REST")
	row PASS W-HOLDER "$line"
	case "$line" in
		*'ns=mnt:['*) row PASS W-NS "ns 已解析（非 unknown）" ;;
		*)             row FAIL W-NS "ns 未解析: $line" ;;
	esac
	case "$line" in
		*'by=kernel'*) row PASS W-BY "by=kernel（direct kernel:s0 优先路径成功）" ;;
		*'by=ksu'*)    row PASS W-BY "by=ksu（su 回落路径）" ;;
		*'by=reused'*) row PASS W-BY "by=reused（复用已有 holder）" ;;
		*)             row FAIL W-BY "by= 缺失或未知: $line" ;;
	esac
else
	if [ -f "$REST" ]; then
		row FAIL W-HOLDER "无 'suvtz-w: holder' 行"
		if has "$REST" 'WARN-suvtz-w-'; then
			row FAIL W-WARN "$(grep -m1 'WARN-suvtz-w-' "$REST")"
			has "$REST" 'WARN-suvtz-w-hold-log:' \
				&& row FAIL W-HOLDLOG "$(grep -m1 'WARN-suvtz-w-hold-log:' "$REST")"
		fi
	else
		row UNKNOWN W-HOLDER "restore log missing"
	fi
fi

if has "$REST" 'suvtz-w: mountpoint=yes'; then
	row PASS W-MP "$(grep -m1 'suvtz-w: mountpoint=' "$REST")"
elif has "$REST" 'suvtz-w: n-side-absent'; then
	row FAIL W-MP "有 n-side-absent 但无 mountpoint=yes（顺序异常）"
else
	row UNKNOWN W-MP "无 mountpoint 判据行"
fi

# exec probe (gap section 6 item 2 prerequisite): restore must be able to run
# an arbitrary binary inside W.  mountpoint=yes already proves setns+execvp,
# but this row names the capability that Phase B migration depends on.
if has "$REST" 'suvtz-w: exec=yes'; then
	row PASS W-EXEC "$(grep -m1 'suvtz-w: exec=' "$REST")"
elif has "$REST" 'WARN-suvtz-w-exec'; then
	row FAIL W-EXEC "$(grep -m1 'WARN-suvtz-w-exec' "$REST")"
elif has "$REST" 'suvtz-w: n-side-absent'; then
	row UNKNOWN W-EXEC "有 n-side-absent 但无 exec 行（本轮 restore 是旧版，无 exec 探针）"
else
	row UNKNOWN W-EXEC "无 exec 判据行"
fi

if has "$REST" 'suvtz-w: n-side-absent stage=ENOENT'; then
	row PASS W-NABSENT "$(grep -m1 'suvtz-w: n-side-absent' "$REST")"
elif has "$REST" 'suvtz-w: n-side-absent'; then
	row FAIL W-NABSENT "$(grep -m1 'suvtz-w: n-side-absent' "$REST")"
else
	row UNKNOWN W-NABSENT "无 n-side-absent 判据行"
fi

# ---- 3. restore markers ----
has "$REST" 'POSTLOCK-RESTORE-OK' && row PASS RESTORE-OK "POSTLOCK-RESTORE-OK x$(cnt "$REST" 'POSTLOCK-RESTORE-OK')" \
	|| row FAIL RESTORE-OK "无 POSTLOCK-RESTORE-OK"
has "$REST" 'SELINUX-STRICT-OK' && row PASS STRICT-OK "SELINUX-STRICT-OK x$(cnt "$REST" 'SELINUX-STRICT-OK')" \
	|| row FAIL STRICT-OK "无 SELINUX-STRICT-OK"
# postlock.sh has NO 'POSTLOCK-EXIT' marker (verified in source) -- take the
# real exit code from run.sh's verdict.txt, fallback to its watch.log line.
rcv=""
if [ -f "$OUT/verdict.txt" ]; then
	rcv=$(sed -n 's/^postlock_rc=\([0-9][0-9]*\).*/\1/p' "$OUT/verdict.txt" | head -1)
fi
if [ -z "$rcv" ] && [ -f "$OUT/watch.log" ]; then
	rcv=$(sed -n 's/.*p5: postlock\.sh rc=\([0-9][0-9]*\).*/\1/p' "$OUT/watch.log" | tail -1)
fi
if [ -n "$rcv" ]; then
	[ "$rcv" = 0 ] && row PASS EXIT0 "postlock.sh rc=0" \
		|| row FAIL EXIT0 "postlock.sh rc=$rcv"
else
	row UNKNOWN EXIT0 "无 rc 证据（verdict.txt / watch.log 均缺失）"
fi

if has "$REST" '\[host-verify\] probe: uid=0'; then
	row PASS SU-PROBE "$(grep -m1 '\[host-verify\] probe:' "$REST")"
else
	row FAIL SU-PROBE "无 [host-verify] probe: uid=0（/system/bin/su 入口未验证）"
fi

# ---- 4. chain ----
has "$CHAIN" 'pipe-physrw-summary.*done=1 root=1' \
	&& row PASS CHAIN-ROOT "done=1 root=1 x$(cnt "$CHAIN" 'pipe-physrw-summary.*done=1 root=1')" \
	|| row FAIL CHAIN-ROOT "链未 root=1"
has "$CHAIN" 'route done.*success=1' && row PASS CHAIN-ROUTE "route done success=1" \
	|| row FAIL CHAIN-ROUTE "无 route done success=1"

# ---- 5. suvtz scan (40 probes) ----
# scan.sh runs on the HOST side from postlock.sh's tail; its summary line lands
# in $SUVTZ_SCAN_BASE/auto_<boot8>/stdout.txt, NOT in restore.log.
SCANBASE="${SUVTZ_SCAN_BASE:-/tmp/opencode/suvtz}"
boot8=""
if [ -f "$OUT/verdict.txt" ]; then
	# run.sh writes boot_before=... and boot_after=... on the SAME line, so an
	# anchored ^boot_after= never matches.  Accept both layouts (line start or
	# after whitespace) -- without this the SCAN row is a permanent UNKNOWN.
	boot8=$(sed -n -e 's/^boot_after=\([0-9a-fA-F]\{8\}\).*/\1/p' \
	               -e 's/.*[[:space:]]boot_after=\([0-9a-fA-F]\{8\}\).*/\1/p' \
	         "$OUT/verdict.txt" | head -1)
fi
scanf=""
if [ -n "$boot8" ] && [ -f "$SCANBASE/auto_$boot8/stdout.txt" ]; then
	scanf="$SCANBASE/auto_$boot8/stdout.txt"
fi
if [ -z "$scanf" ]; then
	for c in "$OUT"/scan_*.txt; do [ -f "$c" ] && scanf="$c" && break; done
fi
# No "newest auto_*" fallback on purpose: that would silently grade this boot
# with an earlier run's snapshot (measured: a 35-probe file from auto_2961a4ee
# turned a missing-scan case into a false PASS).  boot8 comes from this run's
# verdict.txt; without it there is no evidence for this boot.
if [ -n "$scanf" ] && [ -f "$scanf" ]; then
	line=$(grep -m1 -a '^FAIL=' "$scanf" 2>/dev/null | tr -d '\r' || true)
	if [ -n "$line" ]; then
		case "$line" in
			FAIL=0*) row PASS SCAN "$line  ($scanf)" ;;
			*)       row FAIL SCAN "$line  ($scanf)" ;;
		esac
	else
		row UNKNOWN SCAN "有扫描输出但无 FAIL= 汇总行: $scanf"
	fi
else
	row UNKNOWN SCAN "无扫描产物（scan 旁路失败或 SUVTZ_SCAN=0）"
fi

# ---- 6. modules / selinux / retire side effects ----
if [ -f "$HOST" ]; then
	mods=$(grep -m1 'p6: modules=' "$OUT/verdict.txt" 2>/dev/null || true)
	[ -n "$mods" ] && echo "        modules: $mods"
fi
# The hide-switch reset is a silent best-effort call (>/dev/null 2>&1, no log
# line by design) that sits in the SAME block as the retirement loop, so
# "overlay-retired present" implies "hide 0 was issued".  There is no way to
# read the switch back (SUSFS ABI has no getter), so this stays a proxy.
if has "$REST" 'suvtz: overlay-retired'; then
	row PASS HIDE-OFF "退役块已执行 ⇒ hide 0 已静默下发（同段，无独立日志）"
elif [ -f "$REST" ]; then
	row UNKNOWN HIDE-OFF "restore 有日志但无 overlay-retired（退役块未跑）"
else
	row UNKNOWN HIDE-OFF "restore log missing"
fi

echo
echo "== summary: PASS=$np FAIL=$nf UNKNOWN=$nu =="
[ "$nf" = 0 ] && echo "RESULT: OK（无 FAIL）" || echo "RESULT: HAS-FAIL（见上）"
exit 0
