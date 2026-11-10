#!/bin/bash
# SUVTZ Phase B (W material migration) criteria checker.
#
# Phase B keeps the N copy as the fallback and only *prefers* the copy staged
# inside W, so every row here is a positive signal: PASS means the W path was
# actually taken, FAIL means it silently fell back to N (the boot still works
# -- that is the design -- but the migration is not verified).
#
# Usage: bash tools/suvtz/check_phaseb.sh [outdir]
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
has() { [ -n "$(g1 "$1")" ]; }

echo "== SUVTZ Phase B (W material migration) check =="
echo "outdir=$OUT"
if [ -f "$REST" ]; then
	printf '  %-24s %s bytes\n' "$(basename "$REST")" "$(wc -c < "$REST")"
else
	printf '  %-24s MISSING\n' "$(basename "$REST")"
fi
echo

# 1. fill result: all three restore-only assets landed inside W.
line=$(g1 'suvtz-w: staged ocsk=')
if [ -n "$line" ]; then
	case "$line" in
		*'ocsk=1'*'pub=1'*'pp=1'*)
			row PASS PB-STAGE "$line" ;;
		*)
			row FAIL PB-STAGE "填充不全（消费者会回退 N）: $line" ;;
	esac
else
	[ -f "$REST" ] && row FAIL PB-STAGE "无 'suvtz-w: staged' 行（迁移段未跑）" \
		|| row UNKNOWN PB-STAGE "restore log 缺失"
fi

# 2. ocsk loaded from inside W (the load itself is namespace-agnostic; only
#    the .ko path has to resolve inside W).
if has 'oplus_check_suppress-finitmod-ok-w'; then
	row PASS PB-OCSK "$(g1 'oplus_check_suppress-finitmod-ok-w')"
elif has 'oplus_check_suppress-already-loaded'; then
	row UNKNOWN PB-OCSK "ocsk 同 boot 已加载，未走 W 加载路径"
elif has 'oplus_check_suppress-finitmod-ok'; then
	row FAIL PB-OCSK "从 N 加载成功（回退路径），W 消费未验证"
elif has 'WARN-oplus_check_suppress-finitmod-failed'; then
	row FAIL PB-OCSK "$(g1 'WARN-oplus_check_suppress-finitmod-failed')"
else
	[ -f "$REST" ] && row FAIL PB-OCSK "无 ocsk 加载判据行" \
		|| row UNKNOWN PB-OCSK "restore log 缺失"
fi

# 3. adb key appended by reading it from inside W.
if has 'adb-keys-from-w'; then
	row PASS PB-PUB "$(g1 'adb-keys-from-w')"
elif has 'WARN-adb-keys-append'; then
	row FAIL PB-PUB "N 兜底 append 失败: $(g1 'WARN-adb-keys-append')"
elif has 'suvtz-w: staged ocsk='; then
	# The adb_keys block is skipped entirely when the key is already present
	# (idempotent), so absence of adb-keys-from-w with pub=1 means "skipped".
	row UNKNOWN PB-PUB "adb_keys 已含 postlock_bootstrap，本轮未走 append 路径"
else
	[ -f "$REST" ] && row FAIL PB-PUB "无 adb key 判据行" \
		|| row UNKNOWN PB-PUB "restore log 缺失"
fi

# 4. persist.adb.tcp.port appended by reading the protobuf from inside W.
if has 'pp-from-w'; then
	row PASS PB-PP "$(g1 'pp-from-w')"
elif has 'WARN-pp-append'; then
	row FAIL PB-PP "N 兜底 append 失败: $(g1 'WARN-pp-append')"
elif has 'suvtz-w: staged ocsk='; then
	row UNKNOWN PB-PP "persistent_properties 已含该键，本轮未走 append 路径"
else
	[ -f "$REST" ] && row FAIL PB-PP "无 pp 判据行" \
		|| row UNKNOWN PB-PP "restore log 缺失"
fi

# 5. the su fallback must be gated off before ocsk is loaded (ungated su
#    trips OPLUS_ROOT_CHECK -> popup -> 15s forced reboot).
#
#    Observed states (restore.sh >= v36-w-su-gate):
#      "su-gate closed (domain=other su-visible=no; ...)" -> the gate fired and
#         refused: this is the normal, safe outcome on a fresh boot.
#      "su-gate open (domain=ksu ocsk=yes)"             -> gate fired and allowed
#         (only possible if restore ever runs inside u:r:ksu:s0).
#      "su-fallback-skipped (ocsk not loaded)"          -> gate fired and refused
#         because the module was not loaded yet.
#    All three are a *fired* gate, so all three are PASS.
#
#    Why the gate can never open on this device (measured 2026-11-10, boot
#    c0a9c70b, source-verified in ../BakaSU): sucompat rewrites
#    /system/bin/su only for allow-listed uids, and uid 0 is allowed only
#    inside u:r:ksu:s0 (policy/allowlist.c __ksu_is_allow_uid_for_current ->
#    is_ksu_domain()).  Restore runs as u:r:kernel:s0, so the stat facade and
#    the execve rewrite are both skipped: the real /system/bin/su does not
#    exist, so "test -x" is false and "su -c" would be ENOENT.  Old restore
#    versions tested only "-x" and printed nothing on the false branch, which
#    is why the gate looked UNKNOWN instead of closed.
if has 'suvtz-w: su-gate closed'; then
	row PASS PB-SUGATE "$(g1 'suvtz-w: su-gate closed')"
elif has 'suvtz-w: su-gate open'; then
	row PASS PB-SUGATE "$(g1 'suvtz-w: su-gate open')"
elif has 'suvtz-w: su-fallback-skipped (ocsk not loaded)'; then
	row PASS PB-SUGATE "$(g1 'suvtz-w: su-fallback-skipped')"
elif has 'suvtz-w: staged ocsk='; then
	# Phase B ran on an old restore whose gate was silent.  The gate *was*
	# closed (it cannot open in kernel:s0, see above), but it left no
	# evidence, so this stays UNKNOWN -- never PASS.  Re-run with a restore
	# that carries the in-band line to convert it.
	if has 'oplus_check_suppress-already-loaded'; then
		row UNKNOWN PB-SUGATE "旧版 restore（静默门控，无 su-gate 行）：ocsk 已加载，门控无法从日志证实"
	else
		row UNKNOWN PB-SUGATE "旧版 restore（静默门控，无 su-gate 行）：kernel:s0 看不到 /system/bin/su，门控结构性关闭但无 in-band 证据"
	fi
elif has 'suvtz-w: holder'; then
	row FAIL PB-SUGATE "旧版 restore（有 holder、无 Phase B 迁移段）"
else
	[ -f "$REST" ] && row FAIL PB-SUGATE "无 su 门控判据行（可能未门控）" \
		|| row UNKNOWN PB-SUGATE "restore log 缺失"
fi

# 6. hotload stays retired: the late branch is self-sufficient.
if has 'hotload-skipped-late-init-selfsufficient'; then
	row PASS PB-HOTLOAD "$(g1 'hotload-skipped-late-init-selfsufficient')"
elif has 'hotload-finitmod-ok-w'; then
	row UNKNOWN PB-HOTLOAD "KS_HOTLOAD_LEGACY=1 轮：从 W 加载成功（legacy 路径）"
elif has 'hotload-already-loaded'; then
	row UNKNOWN PB-HOTLOAD "hotload 同 boot 已加载"
else
	[ -f "$REST" ] && row FAIL PB-HOTLOAD "无 hotload 判据行" \
		|| row UNKNOWN PB-HOTLOAD "restore log 缺失"
fi

echo
echo "PASS=$np FAIL=$nf UNKNOWN=$nu 总计=$((np+nf+nu))"
[ "$nf" -eq 0 ] || exit 1
exit 0
