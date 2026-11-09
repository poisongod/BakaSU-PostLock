#!/bin/sh
# 编译 wns（aarch64 Android 静态可执行）
#
# 与 tools/tshealth 同款工具链（NDK r29 clang，API 31，-static）。
# 为什么必须静态：restore 在 kernel:s0 / ksu 域里跑，动态链接器路径与
# LD_LIBRARY_PATH 都不可靠；静态 ELF 忽略 LD_PRELOAD，行为可预期。
set -e

here=$(cd "$(dirname "$0")" && pwd)
NDK=${ANDROID_NDK_HOME:-$HOME/android-ndk-r29}
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang"

if [ ! -x "$CC" ]; then
	echo "wns: 找不到 clang: $CC" >&2
	echo "wns: 设置 ANDROID_NDK_HOME 或安装 NDK 到 ~/android-ndk-r29" >&2
	exit 1
fi

"$CC" -static -O2 -s -Wall -Wextra -o "$here/wns" "$here/wns.c"

echo "built: $here/wns"
echo "  size: $(stat -c%s "$here/wns") bytes"
echo "  sha1: $(sha1sum "$here/wns" | cut -d' ' -f1)"
echo "  file: $(file -b "$here/wns" 2>/dev/null || echo '(file 不可用)')"
