#!/bin/bash
# SUVTZ Phase C (N-copy purge / real isolation) criteria checker.
#
# Phase B staged restore-only material into W but kept the N copy as a
# fallback, so the same bytes existed in both worlds -- that is migration, not
# isolation.  Phase C deletes the N copy once the W copy is proven
# byte-identical in-band (cksum) and every consumer has already run.
#
# Rows:
#   PC-CKSUM  W 副本与 N 源逐字节一致（cksum 相同）——删除的前提
#   PC-PURGE  N 副本已删（$STAGE 与 $TMP 两侧都无残留）
#   PC-VERIFY 无 purge/cksum 失败告警
#   PC-KEEP   链关键集仍在 N（kernelsu.ko/finitmod/preload.so/ksud/sep_enforce1.txt）
#
# Usage: bash tools/suvtz/check_phasec.sh [outdir]
#        (default outdir: /tmp/opencode/accept_watch)
#
# Expected input: <outdir>/postlock_restore.log
set -u

OUT="${1:-/tmp/opencode/accept_watch}"
REST="$OUT/postlock_restore.log"

np=0; nf=0; nu=0
row() { # row <status> <id> <detail>
	local st="$1" id="$2"; shift 2
	case "$st" in
		PASS) np=$((np+1)) ;;
		FAIL) nf=$((nf+1)) ;;
		*)    nu=$((nu+1)) ;;
	esac
	printf '%-7s %-10s %s\n' "$st" "$id" "$*"
}
g1() { [ -f "$REST" ] && grep -m1 -- "$1" "$REST" 2>/dev/null || true; }
gn() { [ -f "$REST" ] && grep -c -- "$1" "$REST" 2>/dev/null || echo 0; }
has() { [ -n "$(g1 "$1")" ]; }

echo "== SUVTZ Phase C (N-copy purge) check =="
echo "outdir=$OUT"
if [ -f "$REST" ]; then
	printf '  %-24s %s bytes\n' "$(basename "$REST")" "$(wc -c < "$REST")"
else
	printf '  %-24s MISSING\n' "$(basename "$REST")"
fi
echo

# 1. transport fidelity: every purged file must have an in-band cksum match.
#    Three restore-only assets are expected; hotload is legacy-only.
ck=$(gn 'suvtz-w: cksum ok ')
if [ "$ck" -ge 3 ]; then
	row PASS PC-CKSUM "cksum 一致文件数=$ck（ocsk/pub/pp 至少三项）: $(g1 'suvtz-w: cksum ok oplus_check_suppress.ko ')"
elif [ "$ck" -gt 0 ]; then
	row FAIL PC-CKSUM "只有 $ck 个文件通过 cksum（期望 >=3）"
elif has 'suvtz-w: purge-'; then
	row FAIL PC-CKSUM "无 'cksum ok' 行"
else
	[ -f "$REST" ] && row FAIL PC-CKSUM "无 Phase C 判据行（迁移段未跑）" \
		|| row UNKNOWN PC-CKSUM "restore log 缺失"
fi

# 2. purge happened, and it covered the three restore-only assets.
line=$(g1 'suvtz-w: n-side-purged')
if [ -n "$line" ]; then
	miss=""
	for f in oplus_check_suppress.ko postlock_adbkey.pub pp_adb_tcp.bin; do
		case " $line" in *" $f"*) ;; *) miss="$miss $f" ;; esac
	done
	if [ -z "$miss" ]; then
		row PASS PC-PURGE "$line"
	else
		row FAIL PC-PURGE "N 副本未删全，缺:$miss  ($line)"
	fi
elif has 'suvtz-w: purge-skipped'; then
	row FAIL PC-PURGE "purge 被跳过: $(g1 'suvtz-w: purge-skipped')"
elif has 'WARN-suvtz-w-purge-empty'; then
	row FAIL PC-PURGE "有 cksum 候选但 purge 清单为空"
else
	[ -f "$REST" ] && row FAIL PC-PURGE "无 'n-side-purged' 行（Phase C 未生效）" \
		|| row UNKNOWN PC-PURGE "restore log 缺失"
fi

# 3. no residual / failed-delete warnings.
if has 'WARN-suvtz-w-purge-residual' || has 'WARN-suvtz-w-cksum'; then
	row FAIL PC-VERIFY "$(g1 'WARN-suvtz-w-purge-residual'; g1 'WARN-suvtz-w-cksum')"
elif has 'WARN-suvtz-w-purge-empty'; then
	row FAIL PC-VERIFY "purge 清单为空"
else
	row PASS PC-VERIFY "无 purge/cksum 告警"
fi

# 4. scope: the chain's critical set must survive in N (deleting it would
#    break the next chain, which consumes it before a holder exists).
kline=$(g1 'suvtz-w: n-side-kept')
if [ -n "$kline" ]; then
	miss=""
	for f in kernelsu.ko finitmod preload.so ksud sep_enforce1.txt; do
		case " $kline" in *" $f"*) ;; *) miss="$miss $f" ;; esac
	done
	if [ -z "$miss" ]; then
		row PASS PC-KEEP "$kline"
	else
		row FAIL PC-KEEP "链关键集被误删，缺:$miss  ($kline)"
	fi
elif has 'suvtz-w: purge-skipped'; then
	row UNKNOWN PC-KEEP "purge 未执行，未记录保留集"
else
	[ -f "$REST" ] && row FAIL PC-KEEP "无 'n-side-kept' 行" \
		|| row UNKNOWN PC-KEEP "restore log 缺失"
fi

echo
echo "PASS=$np FAIL=$nf UNKNOWN=$nu 总计=$((np+nf+nu))"
[ "$nf" -eq 0 ] || exit 1
exit 0
