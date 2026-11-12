#!/bin/sh
# 构建并镜像 TrySU 的执行体 tsu（纯 Zig，无 libc 的 static-pie ELF）。
#
# 权威源码在体系自有仓 ../TrySU（cli/），本仓只保留一份**镜像产物**用于
# 恢复链部署（与 tools/wns/wns 同款做法：restore 窗口里内核域不能跑
# 构建，stage 必须自带可执行文件）。
#
# 为什么产物必须镜像而不是现场编译：
#   * restore 跑在 u:r:kernel:s0 + Enforcing，不具备 Zig 工具链与构建缓存；
#   * 镜像产物入库后，任何一次 clone + 冷 boot 都能把 tsu 铺到内核常量
#     KSUD_PATH（/data/adb/ksud）上，不依赖 TrySU 仓是否在场。
#
# 一致性纪律：改 cli/ 源码后必须重跑本脚本并提交镜像（sha1 变化 = 设备侧
# 需要一次冷 boot 才会换上新版）。校验两端一致：
#   sha1sum ../TrySU/cli/zig-out/bin/tsu tools/tsu/tsu
set -e

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
trysu=${TRYSU_DIR:-$repo/../TrySU}
zig=${ZIG:-/home/yang1/zig-0.17.1/zig}

if [ ! -d "$trysu/cli" ]; then
	echo "tsu: 找不到 TrySU 源码: $trysu/cli" >&2
	echo "tsu: 设置 TRYSU_DIR 指向 TrySU 仓根目录" >&2
	exit 1
fi
if [ ! -x "$zig" ]; then
	echo "tsu: 找不到 zig: $zig（设置 ZIG=...）" >&2
	exit 1
fi

(cd "$trysu/cli" && "$zig" build check-cli)

cp -f "$trysu/cli/zig-out/bin/tsu" "$here/tsu"
chmod 755 "$here/tsu"

echo "mirrored: $here/tsu"
echo "  size: $(stat -c%s "$here/tsu") bytes"
echo "  sha1: $(sha1sum "$here/tsu" | cut -d' ' -f1)"
echo "  file: $(file -b "$here/tsu" 2>/dev/null || echo '(file 不可用)')"
