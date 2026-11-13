#!/usr/bin/env bash
# TrySU P1 一键验收（宿主侧）：N1–N11 由设备侧 n_rows.sh 收，N12 由 scan.sh 收。
#
# 用法：
#   SERIAL=100.120.155.127:5555 tools/tsu/n_accept.sh
#   SERIAL=... ADB_BIN=/mnt/c/WINDOWS/system32/adb.exe tools/tsu/n_accept.sh
#   SERIAL=... tools/tsu/n_accept.sh --no-scan      # 跳过 N12（调试设备侧脚本时用）
#
# 前置：一次冷 boot + tools/postlock.sh（tsu 落点 /data/adb/ksud + su 可用）。
# 退出码：0 = 无 FAIL；1 = 有 FAIL；2 = 环境问题。
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ADB_BIN="${ADB_BIN:-adb.exe}"
SERIAL="${SERIAL:-}"
DO_SCAN=1
[ "${1:-}" = "--no-scan" ] && DO_SCAN=0

if [ -z "$SERIAL" ]; then
  echo "error: SERIAL 未设置（例：SERIAL=100.120.155.127:5555 $0）" >&2
  exit 2
fi
A="$ADB_BIN -s $SERIAL"

if ! $A get-state 2>/dev/null | grep -q device; then
  echo "error: 设备 $SERIAL 不可用" >&2
  exit 2
fi

echo "== push n_rows.sh =="
$A push "$ROOT/tools/tsu/n_rows.sh" /data/local/tmp/tsu_n_rows.sh >/dev/null 2>&1 || {
  echo "error: push 失败" >&2; exit 2
}

echo "== 设备侧 N1–N11 =="
OUT=$($A shell "N8_ARM=${N8_ARM:-0} N10_ARM=${N10_ARM:-0} sh /data/local/tmp/tsu_n_rows.sh" 2>&1 | tr -d '\r')
echo "$OUT"
NR_P=$(printf '%s\n' "$OUT" | grep -c '^PASS ')
NR_F=$(printf '%s\n' "$OUT" | grep -c '^FAIL ')
NR_I=$(printf '%s\n' "$OUT" | grep -c '^INFO ')

SCAN_P=0; SCAN_F=0; SCAN_STATUS="skipped"
if [ "$DO_SCAN" = 1 ]; then
  echo
  echo "== N12 观测面回归（scan.sh -q）=="
  SCAN_OUT=$(SERIAL="$SERIAL" ADB_BIN="$ADB_BIN" "$ROOT/tools/suvtz/scan.sh" -q 2>&1)
  echo "$SCAN_OUT" | tail -n 6
  SUM=$(printf '%s\n' "$SCAN_OUT" | grep -E '^FAIL=' | tail -n 1)
  if [ -z "$SUM" ]; then
    SCAN_STATUS="error"; SCAN_F=1
    echo "FAIL  N12 scan.sh 无汇总行（无法判定）"
  else
    SF=$(printf '%s\n' "$SUM" | sed -n 's/^FAIL=\([0-9]*\).*/\1/p')
    SP=$(printf '%s\n' "$SUM" | sed -n 's/.*PASS=\([0-9]*\).*/\1/p')
    SCAN_P=${SP:-0}
    if [ "${SF:-1}" -eq 0 ]; then
      SCAN_STATUS="pass"; SCAN_F=0
      echo "PASS  N12 scan.sh FAIL=0（PASS=$SCAN_P）"
    else
      SCAN_STATUS="fail"; SCAN_F=1
      echo "FAIL  N12 scan.sh FAIL=$SF"
    fi
  fi
else
  echo
  echo "INFO  N12 跳过（--no-scan）"
fi

TOT_F=$((NR_F + SCAN_F))
FORM=$(printf '%s\n' "$OUT" | sed -n 's/.*form=\([a-z]*\).*/\1/p' | head -n 1)
echo
echo "===== N1–N12 验收: 设备侧 PASS=$NR_P FAIL=$NR_F INFO=$NR_I | form=${FORM:-?} | N12=$SCAN_STATUS ====="
if [ "$TOT_F" -eq 0 ]; then
  echo "RESULT: OK"
  exit 0
fi
if [ "$FORM" = daemonless ]; then
  echo "RESULT: FAIL（daemonless 形态下仅 N7=manifest/度量未实现 属预期红）"
else
  echo "RESULT: FAIL（legacy 形态：N1/N2b/N4b/N4c/N6/N7/N9a/N10a 属预期红；见 n_rows.sh 头部）"
fi
exit 1
