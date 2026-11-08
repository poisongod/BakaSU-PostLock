#!/usr/bin/env bash
# 从 tools/postlock.sh 的 restore heredoc 生成 app 内嵌的 assets/postlock/restore.sh。
#
# 为什么需要：app 的 shell 域全链路径要在 fresh 设备（无 host、无 stage）上
# 从零自举，restore.sh 必须随 APK 一起分发；而它的唯一权威源是 postlock.sh
# 里那段 `cat > "$RESTORE_LOCAL" <<EOF`（展开式 heredoc，host 变量在生成时
# 就变成字面值）。手工复制必然脱节（2026-11-07 实测：设备 4ec876aa vs assets
# 44b35a80，差了一整版），所以固化成这个生成器。
#
# 用法：
#   tools/gen_app_restore.sh [输出路径]
# 默认输出到 ../PostLock-Boot/postlock-app/app/src/main/assets/postlock/restore.sh
#
# 生成后自动跑 `sh -n`。改完 restore 必须同步跑一次 tools/check_restore_heredoc.sh
# （那个抓的是「heredoc body 里未转义的命令替换会被 host 执行」，bash -n 抓不到）。
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO/tools/postlock.sh"
OUT="${1:-$REPO/../PostLock-Boot/postlock-app/app/src/main/assets/postlock/restore.sh}"

[ -f "$SRC" ] || { echo "ERROR: $SRC not found" >&2; exit 1; }

START=$(grep -n '^cat > "\$RESTORE_LOCAL" <<EOF$' "$SRC" | cut -d: -f1 | head -1)
[ -n "$START" ] || { echo "ERROR: restore heredoc start marker not found in $SRC" >&2; exit 1; }
END=$(awk -v s="$START" 'NR>s && /^EOF$/{print NR; exit}' "$SRC")
[ -n "$END" ] || { echo "ERROR: restore heredoc end marker not found in $SRC" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# 这些变量在 postlock.sh 运行期就是这个值；heredoc 是展开式的，所以生成物里
# 它们必须是字面量（设备上没有 $STAGE/$TMP 这类变量）。
APP=com.resukisu.resukisu
ACT=org.bakasu.bakasu.ui.MainActivity
STAGE=/data/local/tmp/ksu_boot
TMP=/data/local/tmp
# 默认值与 postlock.sh 一致；restore 内部已改成 ${SUVTZ_CHAIN_LOG_MODE:-...}
# 运行时覆盖，所以这里写默认值即可（app 触发时通过环境变量传 0644）。
CHAIN_LOG_MODE=0600
KASLR_MODE=0600
RESTORE_LOCAL="$WORK/restore.sh"

sed -n "${START},${END}p" "$SRC" > "$WORK/gen.sh"

# set -u：heredoc 里若引用了上面没定义的 host 变量，这里立刻炸掉，
# 而不是把空串静默写进 restore.sh（那会让设备端跑出半截路径）。
(
  set -u
  # shellcheck disable=SC1090
  . "$WORK/gen.sh"
)

[ -s "$RESTORE_LOCAL" ] || { echo "ERROR: generated restore.sh is empty" >&2; exit 1; }
sh -n "$RESTORE_LOCAL" || { echo "ERROR: generated restore.sh fails 'sh -n'" >&2; exit 1; }

mkdir -p "$(dirname "$OUT")"
cp "$RESTORE_LOCAL" "$OUT"
chmod 644 "$OUT"

echo "wrote $OUT"
echo "  $(wc -c < "$OUT") bytes / $(wc -l < "$OUT") lines / sha1 $(sha1sum "$OUT" | cut -d' ' -f1)"
echo "  heredoc lines ${START}-${END} of $SRC"
echo
echo "next: tools/check_restore_heredoc.sh   # 抓未转义的命令替换（bash -n 抓不到）"
