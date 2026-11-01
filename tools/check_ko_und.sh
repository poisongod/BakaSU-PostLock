#!/usr/bin/env bash
# 校验 kernelsu.ko 的全部未定义符号（UND）都能被设备内核导出。
#
# 背景：设备内核里有一批数据符号没有 EXPORT_SYMBOL（selinux_state /
# security_hook_heads / selinux_blob_sizes 等），模块若把它们当普通 UND
# 引用，finitmod 加载时报 "Unknown symbol xxx (err -2)"（-ENOENT），整个模块
# 不生效、管理器红卡「未检测到驱动」。这个错误与 modversions CRC 不匹配
# （-ENOEXEC）完全不同，别混。
#
# 判据：UND 集合 ⊆ 设备内核 __ksymtab 里的导出名集合。
#
# 用法：
#   tools/check_ko_und.sh [ko路径]        # 默认 ../BakaSU/kernel/kernelsu.ko
#
# 导出名集合来源（按优先级）：
#   1. $KALLSYMS_DUMP 指定的 kallsyms 文本（root 下 `cat /proc/kallsyms`）
#   2. build/work/ksymtab_kallsyms.txt（本地缓存的离线全量 kallsyms）
# 结果缓存到 build/work/ksymtab_exported.txt。
set -euo pipefail

# comm 在非 C locale 下会按本地化顺序比较并报 "not in sorted order"，给出错误差集
export LC_ALL=C

REPO=$(cd "$(dirname "$0")/.." && pwd)
KO=${1:-$REPO/../BakaSU/kernel/kernelsu.ko}
CACHE=$REPO/build/work
DUMP=${KALLSYMS_DUMP:-$CACHE/ksymtab_kallsyms.txt}
EXPORTED=$CACHE/ksymtab_exported.txt

NM=${NM:-$HOME/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm}
[ -x "$NM" ] || NM=llvm-nm

[ -f "$KO" ] || { echo "ERROR: ko not found: $KO" >&2; exit 2; }

mkdir -p "$CACHE"
if [ ! -s "$EXPORTED" ]; then
	[ -f "$DUMP" ] || {
		echo "ERROR: 缺 kallsyms dump：$DUMP" >&2
		echo "       从设备取一份：adb shell 'cat /proc/kallsyms' > $DUMP" >&2
		exit 2
	}
	awk '{print $3}' "$DUMP" | grep -E '^__ksymtab' \
		| sed -E 's/^__ksymtab(_gpl)?_//' | sort -u > "$EXPORTED"
fi

UND=$(mktemp); trap 'rm -f "$UND"' EXIT
"$NM" "$KO" | awk '$1=="U"{print $2}' | sort -u > "$UND"

BAD=$(comm -23 "$UND" "$EXPORTED")
TOTAL=$(wc -l < "$UND")
NBAD=$(printf '%s' "$BAD" | grep -c . || true)

echo "ko        : $KO"
echo "sha1      : $(sha1sum "$KO" | cut -d' ' -f1)"
echo "UND 总数  : $TOTAL"
echo "导出符号集: $EXPORTED ($(wc -l < "$EXPORTED") 条)"

if [ "$NBAD" -ne 0 ]; then
	echo
	echo "!! 以下 $NBAD 个 UND 符号设备内核没有导出 —— 加载会报 Unknown symbol (-ENOENT)：" >&2
	printf '%s\n' "$BAD" | sed 's/^/   /' >&2
	echo >&2
	echo "数据符号请走 compat/unexported_shim.c 的 ksu_g_* 间接层" >&2
	echo "（见 kernel/compat/unexported_data.h 顶部注释）。" >&2
	exit 1
fi

echo
echo "OK: 全部 UND 符号均由设备内核导出"
