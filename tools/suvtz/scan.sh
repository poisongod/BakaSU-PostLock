#!/bin/bash
# SUVTZ P0 —— 观测面扫描器
#
# 设计文档: docs/suvtz-v3-design.md §3 / §5.3
#
# 目的: 把设计文档里的观测面清单变成可执行探针, 输出 PASS/FAIL/INFO。
#
# 四条设计纪律:
#   1. 诚实: 探针本身执行不了 (exec 被拒 / 命令缺失) 判 INFO, 绝不判 PASS。
#      "观测不到" 与 "没法观测" 是两件事。
#   2. 视角分级: shell 域能力远超检测方, 只作对照; runas 域是 app uid 的 DAC 近似,
#      但仍不是真正的 untrusted_app 域 (SELinux 域不同) —— 结论里标注视角。
#   3. 期望值来自设计文档 §5.3 定义的 stock 期望, 不是实测 stock 基线
#      (手头没有同型号 stock 对照机)。这一条写在输出里。
#   4. 每个探针一条独立 adb 往返, 拿得到独立的 rc —— 合并执行会丢掉 rc 语义,
#      而 rc 正是区分"不可见"与"没跑成"的唯一依据。
#
# 用法:
#   tools/suvtz/scan.sh                  # 扫描并打印
#   tools/suvtz/scan.sh -q               # 只写文件, 打印汇总
#   SERIAL=1.2.3.4:5555 tools/suvtz/scan.sh
#   PKG=com.postlock.boot tools/suvtz/scan.sh   # 用于近似 app 域的 app (需 debuggable)
#
# 退出码: 0 = 无 FAIL; 1 = 有 FAIL; 2 = 设备不可用

set -u

ADB="${ADB_BIN:-/mnt/c/WINDOWS/system32/adb.exe}"
PKG="${PKG:-com.postlock.boot}"
OUT="${OUT:-/tmp/opencode/suvtz}"
SERIAL="${SERIAL:-}"
QUIET=0
[ "${1:-}" = "-q" ] && QUIET=1

T=$'\t'

mkdir -p "$OUT" || exit 2

# ---------------------------------------------------------------- 设备选择
pick_device() {
	[ -n "${SERIAL:-}" ] && { printf '%s' "$SERIAL"; return 0; }
	local st
	for s in 192.168.137.10:5555 192.168.8.10:5555 100.71.26.6:5555; do
		st=$("$ADB" -s "$s" get-state 2>/dev/null | tr -d '\r')
		[ "$st" = device ] && { printf '%s' "$s"; return 0; }
		"$ADB" connect "$s" >/dev/null 2>&1 || true
		st=$("$ADB" -s "$s" get-state 2>/dev/null | tr -d '\r')
		[ "$st" = device ] && { printf '%s' "$s"; return 0; }
	done
	local l n
	l=$("$ADB" devices 2>/dev/null | tr -d '\r' | awk 'NR>1 && $2=="device"{print $1}' | grep -v '^401e909a$')
	n=$(printf '%s\n' "$l" | grep -c .)
	[ "$n" = 1 ] && { printf '%s' "$l"; return 0; }
	return 1
}

S=$(pick_device) || { echo "scan: 无可用目标设备 (错设备 401e909a 已排除)" >&2; exit 2; }
echo "device: $S" >&2

# ---------------------------------------------------------------- 基础信息
BOOT=$("$ADB" -s "$S" shell 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\r\n')
[ -n "$BOOT" ] || BOOT=unknown
BOOT8=${BOOT:0:8}
SUMMARY="$OUT/scan_${BOOT8}.tsv"
REPORT="$OUT/scan_${BOOT8}.txt"
: > "$SUMMARY"

# runas 视角是否可用 (需 debuggable + run-as)
RUNAS_OK=1
"$ADB" -s "$S" shell "run-as $PKG true" >/dev/null 2>&1 || RUNAS_OK=0

# runas 域的命令执行能力自检: 若连 getprop 都 exec 不了, 该视角所有探针记 INFO,
# 因为 "exec 失败" 不是 "观测不到"。
RUNAS_EXEC=0
if [ "$RUNAS_OK" = 1 ]; then
	_o=$("$ADB" -s "$S" shell "run-as $PKG sh -c 'getprop ro.build.type'" 2>&1 | tr -d '\r')
	printf '%s' "$_o" | grep -q '^user' && RUNAS_EXEC=1
fi

# ---------------------------------------------------------------- 探针执行
LAST_RC=0
LAST_OUT=""

# exec_v <view> <cmd>   view ∈ {shell,runas}
# 命令体约束: 不含单引号 (runas 外层用 sh -c '...' 包裹)。全部探针已遵守。
exec_v() {
	local view="$1" cmd="$2" raw rc
	# 设备侧必须先把 stderr 并进 stdout (2>&1), 否则 echo 的 __RC__ 会插进
	# 命令 stderr 的两次写之间 (实测 ls: "<path>__RC__1\n: Permission denied"),
	# 输出顺序被打乱、实测值被污染。
	if [ "$view" = runas ]; then
		raw=$("$ADB" -s "$S" shell "run-as $PKG sh -c '$cmd' 2>&1; echo __RC__\$?" 2>&1)
	else
		raw=$("$ADB" -s "$S" shell "sh -c '$cmd' 2>&1; echo __RC__\$?" 2>&1)
	fi
	raw=$(printf '%s' "$raw" | tr -d '\r')
	rc=$(printf '%s\n' "$raw" | sed -n 's/.*__RC__\([0-9][0-9]*\).*/\1/p' | tail -1)
	[ -n "$rc" ] || rc=255
	LAST_RC="$rc"
	LAST_OUT=$(printf '%s\n' "$raw" | sed 's/__RC__[0-9][0-9]*$//' | sed '/^$/d')
}

# ---------------------------------------------------------------- 判定
# judge <expect> -> 设置 VERDICT / REASON
#   absent    对象应不可见: rc!=0 / 空 / 拒绝 = PASS; 有内容 = FAIL
#   empty     值应为空:    rc==0 且空 = PASS; 非空 = FAIL; rc!=0 = INFO
#   zero      数字应为 0   (注意 grep -c 无匹配时输出 0 但 rc=1, 不能拿 rc 判失败)
#   value:X   应等于 X
#   info      仅记录
judge() {
	local expect="$1" v
	VERDICT="INFO"; REASON=""
	local denied=0
	printf '%s' "$LAST_OUT" | grep -qiE 'permission denied|operation not permitted|eacces' && denied=1
	printf '%s' "$LAST_OUT" | grep -qiE 'no such file|does not exist' && denied=1

	case "$expect" in
	absent)
		if [ "$LAST_RC" != 0 ] || [ -z "$LAST_OUT" ] || [ "$denied" = 1 ]; then
			VERDICT="PASS"
			[ "$LAST_RC" != 0 ] && REASON="不可见(rc=$LAST_RC)"
			[ "$denied" = 1 ] && REASON="拒绝/不存在"
		else
			VERDICT="FAIL"; REASON="可见"
		fi
		;;
	empty)
		if [ "$LAST_RC" != 0 ]; then
			VERDICT="INFO"; REASON="命令未能执行(rc=$LAST_RC)"
		elif [ -z "$LAST_OUT" ]; then
			VERDICT="PASS"; REASON="空"
		else
			VERDICT="FAIL"; REASON="有值"
		fi
		;;
	zero)
		if [ "$LAST_RC" = 255 ] || [ "$LAST_RC" = 126 ] || [ "$LAST_RC" = 127 ]; then
			VERDICT="INFO"; REASON="命令未能执行(rc=$LAST_RC)"
		elif [ "$denied" = 1 ]; then
			# 读不到源文件 = 检测方同样看不到 = 等价于 0 命中
			VERDICT="PASS"; REASON="源不可读(拒绝)"
		else
			v=$(printf '%s' "$LAST_OUT" | tr -dc '0-9' | head -c 12)
			if [ -z "$v" ]; then VERDICT="INFO"; REASON="无数字输出"
			elif [ "$v" = 0 ]; then VERDICT="PASS"; REASON="0"
			else VERDICT="FAIL"; REASON="$v"
			fi
		fi
		;;
	value:*)
		local want="${expect#value:}"
		if [ "$LAST_RC" != 0 ]; then
			VERDICT="INFO"; REASON="命令未能执行(rc=$LAST_RC)"
		elif [ "$LAST_OUT" = "$want" ]; then
			VERDICT="PASS"; REASON="$want"
		elif [ -z "$LAST_OUT" ]; then
			VERDICT="INFO"; REASON="空(读不到)"
		else
			VERDICT="FAIL"; REASON="$LAST_OUT"
		fi
		;;
	*)
		VERDICT="INFO"; REASON="仅记录"
		;;
	esac
}

# ---------------------------------------------------------------- 探针表
# 字段(Tab 分隔): ID  类  描述  视角  命令  期望
# 命令里可以出现 | (管道), 因为分隔符是 Tab。
#   A 包与进程   B 文件系统   C 内核符号与模块   D 系统属性   E SELinux 与挂载
PROBES=(
"A1${T}A${T}管理器包可枚举${T}shell${T}pm list packages | grep -i -e resukisu -e bakasu${T}absent"
"A2${T}A${T}工具包可枚举${T}shell${T}pm list packages | grep -i -e postlock${T}absent"
"A3${T}A${T}其它 root 工具包${T}shell${T}pm list packages | grep -i -e kernelsu -e magisk -e apatch${T}absent"
"A4${T}A${T}app 可见 ksud 进程${T}runas${T}ps -A -o NAME | grep -c -e ksud${T}zero"
"A5${T}A${T}app 可见 tailscaled${T}runas${T}ps -A -o NAME | grep -c -e tailscaled${T}zero"
"B1${T}B${T}物料目录 /data/local/tmp/ksu_boot${T}runas${T}ls /data/local/tmp/ksu_boot${T}absent"
"B2${T}B${T}/data/local/tmp 可枚举${T}runas${T}ls /data/local/tmp${T}absent"
"B3${T}B${T}/data/adb 可枚举${T}runas${T}ls /data/adb${T}absent"
"B4${T}B${T}/product/bin/su 存在${T}runas${T}ls -l /product/bin/su${T}absent"
"B5${T}B${T}/system/bin/su 存在${T}runas${T}ls -l /system/bin/su${T}absent"
"B6${T}B${T}物料 ko 可读${T}runas${T}ls -l /data/local/tmp/ksu_boot/kernelsu.ko${T}absent"
"B7${T}B${T}ksud 二进制可读${T}runas${T}wc -c < /data/local/tmp/ksud${T}absent"
"B8${T}B${T}链日志可读${T}runas${T}head -1 /data/local/tmp/postlock_chain.log${T}absent"
"B9${T}B${T}overlay upper 可列${T}runas${T}ls /data/local/tmp/ovl/tmp/upper${T}absent"
"B10${T}B${T}KASLR 参考可读${T}runas${T}cat /data/local/tmp/ksu_kaslr${T}absent"
"B11${T}B${T}restore.sh 可读${T}runas${T}head -1 /data/local/tmp/ksu_boot/restore.sh${T}absent"
"C1${T}C${T}/sys/module/kernelsu${T}runas${T}ls /sys/module/kernelsu${T}absent"
"C2${T}C${T}/sys/module/oplus_check_suppress${T}runas${T}ls /sys/module/oplus_check_suppress${T}absent"
"C3${T}C${T}/proc/modules 含 kernelsu${T}runas${T}grep -c kernelsu /proc/modules${T}zero"
"C4${T}C${T}/proc/kallsyms 含 ksu_/susfs_${T}runas${T}grep -c -e ksu_ -e susfs_ /proc/kallsyms${T}zero"
"C5${T}C${T}ksu 参数文件可读${T}runas${T}ls /sys/module/kernelsu/parameters${T}absent"
"D1${T}D${T}persist.adb.tcp.port${T}runas${T}getprop persist.adb.tcp.port${T}empty"
"D2${T}D${T}wrap.* 注入属性${T}runas${T}getprop | grep -c -e wrap${T}zero"
"D3${T}D${T}ro.debuggable${T}runas${T}getprop ro.debuggable${T}value:0"
"D4${T}D${T}ro.build.type${T}runas${T}getprop ro.build.type${T}value:user"
"D5${T}D${T}verifiedbootstate${T}runas${T}getprop ro.boot.verifiedbootstate${T}value:green"
"D6${T}D${T}sys.oem_unlock_allowed${T}runas${T}getprop sys.oem_unlock_allowed${T}value:0"
"E1${T}E${T}SELinux enforce 可读${T}runas${T}cat /sys/fs/selinux/enforce${T}absent"
"E2${T}E${T}mountinfo 暴露 overlay${T}runas${T}grep product/bin /proc/self/mountinfo | grep -c overlay${T}zero"
"E3${T}E${T}mountinfo 暴露 tmpfs upper${T}runas${T}grep -c ksu_boot /proc/self/mountinfo${T}zero"
)

# ---------------------------------------------------------------- 主循环
npass=0; nfail=0; ninfo=0
{
	echo "=================================================================="
	echo "SUVTZ 观测面扫描  boot=$BOOT  device=$S"
	echo "app 域代理包=$PKG  runas_ok=$RUNAS_OK  runas_exec=$RUNAS_EXEC"
	echo "时间: $(date -Is)"
	echo "------------------------------------------------------------------"
	echo "视角说明: shell = 对照 (能力远超检测方);"
	echo "          runas = app uid + runas_app 域 (DAC 精确, SELinux 域不等价于"
	echo "          untrusted_app) => runas 的 PASS 是必要条件, 不是充分条件,"
	echo "          真正判据需 app 自身代码复测。"
	echo "期望值来源: docs/suvtz-v3-design.md §5.3 定义的 stock 期望 (非实测对照机)。"
	echo "=================================================================="
	printf '%-5s %-3s %-40s %-6s %s\n' ID 类 观测面 判定 实测/原因
	echo "------------------------------------------------------------------"
} > "$REPORT"

for p in "${PROBES[@]}"; do
	IFS="$T" read -r id cls desc view cmd expect <<< "$p"

	if [ "$view" = runas ] && [ "$RUNAS_EXEC" = 0 ]; then
		LAST_RC=255; LAST_OUT=""
		VERDICT="INFO"; REASON="runas 域不可用(exec 被拒/run-as 失败)"
	else
		exec_v "$view" "$cmd"
		judge "$expect"
	fi

	case "$VERDICT" in
		PASS) npass=$((npass+1));;
		FAIL) nfail=$((nfail+1));;
		*)    ninfo=$((ninfo+1));;
	esac

	# 实测值压成一行, 最多 90 字符
	act=$(printf '%s' "$LAST_OUT" | tr '\n' ';' | cut -c1-90)
	[ -n "$act" ] || act="-"
	[ -n "$REASON" ] && act="$act  ($REASON)"

	printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$cls" "$view" "$VERDICT" "$expect" "$act" >> "$SUMMARY"
	if [ "$QUIET" = 0 ]; then
		printf '%-5s %-3s %-40s %-6s %s\n' "$id" "$cls" "$desc" "$VERDICT" "$act" | tee -a "$REPORT" >&2
	else
		printf '%-5s %-3s %-40s %-6s %s\n' "$id" "$cls" "$desc" "$VERDICT" "$act" >> "$REPORT"
	fi
done

{
	echo "------------------------------------------------------------------"
	echo "FAIL=$nfail  PASS=$npass  INFO=$ninfo  总计=$((nfail+npass+ninfo))"
	echo
	if [ "$nfail" -gt 0 ]; then
		echo "FAIL 项 (检测方可直接观测到的 root 证据):"
		awk -F'\t' '$4=="FAIL"{printf "  %-5s %s\n",$1,$6}' "$SUMMARY"
		echo
	fi
	if [ "$ninfo" -gt 0 ]; then
		echo "INFO 项 (视角不足需 app 域复测 / 或属不可覆盖类):"
		awk -F'\t' '$4=="INFO"{printf "  %-5s %s\n",$1,$6}' "$SUMMARY"
		echo
	fi
	echo "结果: $REPORT"
} > /tmp/.suvtz_tail.$$

cat /tmp/.suvtz_tail.$$ >> "$REPORT"
if [ "$QUIET" = 0 ]; then cat /tmp/.suvtz_tail.$$ >&2; fi
rm -f /tmp/.suvtz_tail.$$

# 持久性判据的雏形: 换 boot 后与同设备历史结果比对
PREV=$(ls -1 "$OUT"/scan_*.tsv 2>/dev/null | grep -v "scan_${BOOT8}\.tsv" | tail -1)
if [ -n "$PREV" ]; then
	echo
	echo "(历史基线: $PREV —— 换 boot 后可用它验证「持久性」判据)"
fi

[ "$nfail" -gt 0 ] && exit 1
exit 0
