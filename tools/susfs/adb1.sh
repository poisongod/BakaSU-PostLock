#!/bin/bash
# adb 封装: 永远打到目标设备 (PFUM10 = 192.168.8.10 / 100.71.26.6),
# 绝不落到错设备 401e909a (V2020CA, 红线勿动).
#
# 用法: adb1.sh shell id        # 也可 SERIAL=xxx adb1.sh ...
ADB=/mnt/c/WINDOWS/system32/adb.exe

if [ -n "${SERIAL:-}" ]; then
	exec "$ADB" -s "$SERIAL" "$@"
fi

for s in 192.168.8.10:5555 100.71.26.6:5555; do
	if "$ADB" -s "$s" get-state 2>/dev/null | grep -q '^device$'; then
		exec "$ADB" -s "$s" "$@"
	fi
done

# 兜底: 唯一在线且不是错设备的序列号
list=$("$ADB" devices 2>/dev/null | awk 'NR>1 && $2=="device"{print $1}' | grep -v '^401e909a$')
n=$(printf '%s\n' "$list" | grep -c .)
if [ "$n" = 1 ]; then
	exec "$ADB" -s "$list" "$@"
fi

echo "adb1: no target device (online: ${list:-none})" >&2
exit 1
