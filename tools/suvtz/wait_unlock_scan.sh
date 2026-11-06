#!/bin/bash
# 等设备解锁后再跑一次 SUVTZ 扫描。
#
# 背景: 冷 boot 后设备常停在 State: RUNNING_LOCKED（有锁屏凭据），CE 存储不可见
# → run-as 一律 failed → 扫描器的 app 域(runas) 段只能全部记 INFO（32/35），
# 那份快照对 T0 命题几乎没有判据。恢复流程尾部那次扫描因此通常拿不到完整数据。
#
# 本脚本就是补这一刀：由 postlock.sh 在「本轮扫描 runas=no」时**后台**拉起，
# 轮询到设备真正解锁（run-as 可用）后自动补跑一次，产出完整快照并更新台账。
# 期间不阻塞恢复流程、不写设备（scan.sh 全部是只读探针）。
#
# 用法:
#   tools/suvtz/wait_unlock_scan.sh --outdir DIR [选项]
#     --outdir DIR      报告目录（同一 boot 的 scan_<boot8>.{txt,tsv} 会覆盖，
#                       旧的锁屏快照先另存 scan_<boot8>_locked.txt）
#     --adb PATH        adb 可执行文件（默认 adb）
#     --serial S        设备序列号（多设备必须给；WSL 下 ANDROID_SERIAL 不生效）
#     --pkg PKG         runas 载体（不设 = 交给 scan.sh 自动探测）
#     --no-pkg          强制不用载体（runas 段全 INFO）
#     --boot8 XXXXXXXX  期望的 boot 前缀；本 boot 已变则放弃（默认不校验）
#     --ledger FILE     台账路径（默认 <outdir 的父目录>/history.tsv）
#     --timeout SEC     等解锁上限（默认 10800 = 3h）
#     --interval SEC    轮询间隔（默认 30s）
#
# 退出码: 0 已补跑 / 2 等解锁超时 / 3 boot 已变 / 4 adb 连续不可用
# 产物: <outdir>/defer.log、defer_status.txt、deferred_stdout.txt/stderr.txt，
#       以及 scan_<boot8>.{txt,tsv}（scan.sh 写）
set -u

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCAN="$SELF_DIR/scan.sh"

ADB=adb
OUTDIR=""
SERIAL=""
PKG=""
PKG_SET=0
BOOT8=""
LEDGER=""
TIMEOUT=10800
INTERVAL=30

while [ $# -gt 0 ]; do
	case "$1" in
		--outdir)   OUTDIR=${2:-}; shift 2 ;;
		--adb)      ADB=${2:-}; shift 2 ;;
		--serial)   SERIAL=${2:-}; shift 2 ;;
		--pkg)      PKG=${2:-}; PKG_SET=1; shift 2 ;;
		--no-pkg)   PKG=""; PKG_SET=1; shift ;;
		--boot8)    BOOT8=${2:-}; shift 2 ;;
		--ledger)   LEDGER=${2:-}; shift 2 ;;
		--timeout)  TIMEOUT=${2:-}; shift 2 ;;
		--interval) INTERVAL=${2:-}; shift 2 ;;
		-h|--help)  sed -n '2,30p' "$0"; exit 0 ;;
		*) echo "unknown arg: $1" >&2; exit 64 ;;
	esac
done

if [ -z "$OUTDIR" ]; then echo "--outdir 必填" >&2; exit 64; fi
if [ ! -x "$SCAN" ]; then echo "scan.sh 不可执行: $SCAN" >&2; exit 64; fi
mkdir -p "$OUTDIR" 2>/dev/null || true
[ -n "$LEDGER" ] || LEDGER="$(dirname "$OUTDIR")/history.tsv"

LOG="$OUTDIR/defer.log"
STATUS="$OUTDIR/defer_status.txt"
log() { printf '[%s] %s\n' "$(date +%F' '%T)" "$*" >> "$LOG"; }

# ab: 统一走 -s 指定设备（WSL 调 adb.exe 时 ANDROID_SERIAL 不生效）
ab() {
	if [ -n "$SERIAL" ]; then "$ADB" -s "$SERIAL" "$@"; else "$ADB" "$@"; fi
}

boot_id() { ab shell cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r' | head -1; }

# 就绪判据: 有载体时直接以 run-as 成功为准（这正是 app 域测量需要的那个能力；
# dumpsys 的 RUNNING_UNLOCKED 只是它的必要条件，DAC/SELinux 仍可能拒）。无载体
# 时只能看 dumpsys。
ready() {
	if [ "$PKG_SET" = 1 ] && [ -n "$PKG" ]; then
		ab shell "run-as $PKG true" >/dev/null 2>&1
	else
		local st
		st=$(ab shell 'dumpsys user 2>/dev/null | grep -m1 -E "State:"' 2>/dev/null | tr -d '\r')
		case "$st" in *RUNNING_UNLOCKED*) return 0 ;; *) return 1 ;; esac
	fi
}

log "start outdir=$OUTDIR adb=$ADB serial=${SERIAL:-<auto>} pkg=${PKG:-<auto>} boot8=${BOOT8:-<any>} timeout=${TIMEOUT}s interval=${INTERVAL}s"

deadline=$(( $(date +%s) + TIMEOUT ))
adb_fails=0
while :; do
	bid=$(boot_id)
	if [ -z "$bid" ]; then
		adb_fails=$((adb_fails + 1))
		[ "$adb_fails" -ge 6 ] && { log "adb 连续 6 次不可用, 放弃"; echo "ADB_LOST" > "$STATUS"; exit 4; }
	else
		adb_fails=0
		if [ -n "$BOOT8" ] && [ "${bid%%-*}" != "$BOOT8" ]; then
			log "boot 已变 ($BOOT8 -> ${bid%%-*}), 放弃"
			echo "BOOT_CHANGED" > "$STATUS"
			exit 3
		fi
		[ -n "$BOOT8" ] || BOOT8=${bid%%-*}
	fi
	if ready; then log "设备已就绪 (runas 可用/已解锁), 开始补跑扫描"; break; fi
	if [ "$(date +%s)" -ge "$deadline" ]; then
		log "等待解锁超时 (${TIMEOUT}s), 放弃 —— 解锁后单跑 tools/suvtz/scan.sh 即可"
		echo "TIMEOUT" > "$STATUS"
		exit 2
	fi
	sleep "$INTERVAL"
done

# 保底：把解锁前那份（多半是锁屏态 INFO 满屏的）快照另存，别被覆盖掉。
if [ -f "$OUTDIR/scan_$BOOT8.txt" ]; then
	cp -f "$OUTDIR/scan_$BOOT8.txt" "$OUTDIR/scan_${BOOT8}_locked.txt" 2>/dev/null || true
	[ -f "$OUTDIR/scan_$BOOT8.tsv" ] && cp -f "$OUTDIR/scan_$BOOT8.tsv" "$OUTDIR/scan_${BOOT8}_locked.tsv" 2>/dev/null || true
fi

# scan.sh 的 env 前缀同样只能用**解析期字面量**（见 postlock.sh 同处注释），
# 变量/数组展开出来的 VAR=val 会被当成命令名 → 一律走 env。
SCAN_ENV=(env ADB_BIN="$ADB" OUT="$OUTDIR")
[ -n "$SERIAL" ] && SCAN_ENV+=(SERIAL="$SERIAL")
if [ "$PKG_SET" = 1 ]; then SCAN_ENV+=(PKG="$PKG"); fi

log "run scan"
if "${SCAN_ENV[@]}" bash "$SCAN" -q > "$OUTDIR/deferred_stdout.txt" 2> "$OUTDIR/deferred_stderr.txt"; then
	scan_rc=0
else
	scan_rc=$?
fi
sum=$(tail -1 "$OUTDIR/deferred_stdout.txt" 2>/dev/null | tr -d '\r')
if [ "$scan_rc" != 0 ] || [ -z "$sum" ]; then
	log "scan 失败 rc=$scan_rc"
	echo "SCAN_FAILED" > "$STATUS"
	exit 5
fi
log "scan ok: $sum"

# 台账：与 postlock.sh P2 段同款（每 boot 一行，同一 boot 整行替换）。
if [ -f "$LEDGER" ]; then
	grep -v "^$BOOT8"$'\t' "$LEDGER" > "$LEDGER.tmp" 2>/dev/null || true
	mv -f "$LEDGER.tmp" "$LEDGER" 2>/dev/null || true
else
	printf '# boot8\tdate\tfail/pass/info\tsummary\n' > "$LEDGER"
fi
printf '%s\t%s\t%s\n' "$BOOT8" "$(date +%F' '%T)" "$sum" >> "$LEDGER"
log "ledger updated: $LEDGER"
echo "OK $sum" > "$STATUS"
exit 0
