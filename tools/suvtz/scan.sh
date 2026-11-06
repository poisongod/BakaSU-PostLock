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
#   PKG=<包名> tools/suvtz/scan.sh       # runas 近似域的载体（需 debuggable）
#                                        # 不设 = 自动取已安装的验收载体
#                                        # （com.postlock.boot > com.postlock.privateapp）
#                                        # PKG= (空串) = 强制不用载体、runas 段记 INFO
#                                        # （PostLock-Boot 已冻结，但仍是 SUSFS
#                                        #  app 域自检载体，装了就默认用它）
#
# 退出码: 0 = 无 FAIL; 1 = 有 FAIL; 2 = 设备不可用

set -u

ADB="${ADB_BIN:-/mnt/c/WINDOWS/system32/adb.exe}"
# PostLock-Boot 自 2026-11-06 冻结为 legacy，不再作为默认载体。
# runas 视角只是 app uid 的 DAC 近似，载体可以是任何 debuggable app。
# PKG 未设置 => 自动探测已安装的验收载体 (见 pick_carrier);
# PKG= (空串) => 强制不用载体, runas 视角整段记 INFO。
PKG_AUTO=0
[ -z "${PKG+x}" ] && PKG_AUTO=1
PKG="${PKG:-}"
OUT="${OUT:-/tmp/opencode/suvtz}"
SERIAL="${SERIAL:-}"
QUIET=0
[ "${1:-}" = "-q" ] && QUIET=1

T=$'\t'
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

mkdir -p "$OUT" || exit 2

# ---------------------------------------------------- 已接受暴露面
# tools/suvtz/accepted.tsv : 每行 "<ID>\t<裁决日期>\t<理由>", # 开头为注释。
#
# 语义纪律: 被列为「已接受」的项**判定仍是 FAIL**, 只是从「未处理 FAIL」里摘出来
# 单独计数。绝不改判 PASS —— 观测到就是观测到, 接受与否是威胁模型的取舍, 不是
# 事实的改变。这样扫描输出仍能一眼看出「哪些残留是已知裁决过的」与「哪些是新泄漏」。
#
# 默认文件不存在/为空 => 行为与未引入该机制时完全一致。
# ACCEPTED_FILE=  (空串) 可临时禁用;  ACCEPTED_FILE=/path 可换表。
ACCEPTED_FILE="${ACCEPTED_FILE-$SCRIPT_DIR/accepted.tsv}"

acc_reason() {
	[ -n "$ACCEPTED_FILE" ] && [ -r "$ACCEPTED_FILE" ] || return 1
	local r
	r=$(awk -F'\t' -v id="$1" \
		'!/^[[:space:]]*#/ && NF>=3 && $1==id {print $3; exit}' \
		"$ACCEPTED_FILE" 2>/dev/null)
	[ -n "$r" ] || return 1
	printf '%s' "$(printf '%s' "$r" | tr '\t' ' ')"
}

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

# ---------------------------------------------------------------- 载体选择
# runas 视角需要一个 debuggable 载体（app uid 的 DAC 近似）。PKG 未设置时
# 自动取第一个**已安装**的验收载体；都没有就退化成「无载体」(整段 INFO)。
# 注意 run-as 依赖 CE 存储：锁屏/休眠时即使装了也会失败，这是环境限制不是缺陷。
if [ "$PKG_AUTO" = 1 ]; then
	for c in com.postlock.boot com.postlock.privateapp; do
		if "$ADB" -s "$S" shell "pm list packages" 2>/dev/null \
			| tr -d '\r' | grep -qx "package:$c"; then
			PKG=$c
			break
		fi
	done
	if [ -n "$PKG" ]; then
		echo "carrier: $PKG (auto)" >&2
	else
		echo "carrier: 无已安装载体 (PKG=<pkg> 可指定; runas 段将记 INFO)" >&2
	fi
fi

# ---------------------------------------------------------------- 基础信息
BOOT=$("$ADB" -s "$S" shell 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\r\n')
[ -n "$BOOT" ] || BOOT=unknown
BOOT8=${BOOT:0:8}
SUMMARY="$OUT/scan_${BOOT8}.tsv"
REPORT="$OUT/scan_${BOOT8}.txt"
: > "$SUMMARY"

# 设备是否锁屏未解锁。CE (credential encrypted) 存储在解锁前不可用，此时
# run-as 会报 "couldn't stat /data/user/0/<pkg>"，runas 段只能记 INFO。
# 这条**不是扫描失败**，但必须在报告里写明白，否则读者只会看到几十条一模一样
# 的「runas 域不可用」而无从下手（实测踩过：设备重启后锁屏，快照 32/35 全 INFO）。
DEV_LOCKED=0
_userstate=$("$ADB" -s "$S" shell 'dumpsys user 2>/dev/null | grep -m1 -E "State:"' 2>/dev/null | tr -d '\r')
case "$_userstate" in *RUNNING_LOCKED*) DEV_LOCKED=1 ;; esac

# runas 视角是否可用 (需 PKG 非空 + debuggable + run-as)，并给出**具体原因**
RUNAS_OK=1
RUNAS_ERR=""
RUNAS_WHY="runas 域不可用"
if [ -z "$PKG" ]; then
	RUNAS_OK=0
	RUNAS_WHY="无 app 域载体(载体未安装 / 或 PKG= 被强制置空)"
else
	RUNAS_ERR=$("$ADB" -s "$S" shell "run-as $PKG true" 2>&1 | tr -d '\r' | head -1)
	if [ -n "$RUNAS_ERR" ]; then
		RUNAS_OK=0
		case "$RUNAS_ERR" in
			*"couldn't stat"*|*"No such file"*)
				if [ "$DEV_LOCKED" = 1 ]; then
					RUNAS_WHY="设备未解锁(CE 存储不可用, State: RUNNING_LOCKED)"
				else
					RUNAS_WHY="载体 $PKG 无数据目录(从未启动过?)"
				fi
				;;
			*"not debuggable"*) RUNAS_WHY="载体 $PKG 不可调试" ;;
			*)                  RUNAS_WHY="run-as 失败(${RUNAS_ERR})" ;;
		esac
	fi
fi

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
	local denied=0 broken=0
	printf '%s' "$LAST_OUT" | grep -qiE 'permission denied|operation not permitted|eacces' && denied=1
	printf '%s' "$LAST_OUT" | grep -qiE 'no such file|does not exist' && denied=1
	# 工具能力不足 ≠ 观测不到。toybox ps 的 -o 支持随版本变化, 用法文本里
	# 也带数字 (实测 "Try 'ps --help simple|list'"), 不拦住会被 zero 判成
	# FAIL 假阳性。命令能跑但参数不被支持, 属于"没法观测", 记 INFO。
	printf '%s' "$LAST_OUT" \
		| grep -qiE "unknown (user-defined )?format specifier|try '[^']*--help|usage:|^用法" \
		&& broken=1

	case "$expect" in
	absent)
		if [ "$broken" = 1 ]; then
			VERDICT="INFO"; REASON="命令能力不足(参数/工具不支持)"
		elif [ "$LAST_RC" != 0 ] || [ -z "$LAST_OUT" ] || [ "$denied" = 1 ]; then
			VERDICT="PASS"
			[ "$LAST_RC" != 0 ] && REASON="不可见(rc=$LAST_RC)"
			[ "$denied" = 1 ] && REASON="拒绝/不存在"
		else
			VERDICT="FAIL"; REASON="可见"
		fi
		;;
	empty)
		if [ "$broken" = 1 ]; then
			VERDICT="INFO"; REASON="命令能力不足(参数/工具不支持)"
		elif [ "$LAST_RC" != 0 ]; then
			VERDICT="INFO"; REASON="命令未能执行(rc=$LAST_RC)"
		elif [ -z "$LAST_OUT" ]; then
			VERDICT="PASS"; REASON="空"
		else
			VERDICT="FAIL"; REASON="有值"
		fi
		;;
	zero)
		if [ "$broken" = 1 ]; then
			VERDICT="INFO"; REASON="命令能力不足(参数/工具不支持)"
		elif [ "$LAST_RC" = 255 ] || [ "$LAST_RC" = 126 ] || [ "$LAST_RC" = 127 ]; then
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
		if [ "$broken" = 1 ]; then
			VERDICT="INFO"; REASON="命令能力不足(参数/工具不支持)"
		elif [ "$LAST_RC" != 0 ]; then
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
# A2 的 postlock 是 legacy 工具包名：PostLock-Boot 已冻结但仍在设备上，探针语义
# 是「我们的工具包是否可被第三方枚举」，不随冻结失效。
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

# ---------------------------------------------------------------- X 类: 成对交叉验证
# 同一个事实经两条**独立通道**测量, 要求同向:
#   两通道都不可见 -> PASS; 两通道都可见 -> FAIL; 只有一条可见 -> FAIL(分歧);
#   任一侧测不出来(rc 语义丢失/命令缺失) -> INFO。
# 为什么需要: 单点探针的 PASS 可能来自"这条通道恰好被挡住", 而不是"对象真的
# 不可见"。分歧是最有价值的信号 —— 说明存在一条我们没建模的读取路径, 必须
# 定案(要么补实现, 要么在文档里记为已接受的暴露面)。
# 字段(Tab 分隔): ID 类 描述 视角 命令A 期望A 命令B 期望B
PAIRS=(
"X1${T}X${T}模块面双通道(/proc/modules vs /sys/module)${T}runas${T}grep -c kernelsu /proc/modules${T}zero${T}ls /sys/module/kernelsu${T}absent"
"X2${T}X${T}符号面双通道(/proc/kallsyms vs /proc/modules)${T}runas${T}grep -c -e ksu_ -e susfs_ /proc/kallsyms${T}zero${T}grep -c kernelsu /proc/modules${T}zero"
"X3${T}X${T}挂载视图双通道(mountinfo vs mounts)${T}runas${T}grep product/bin /proc/self/mountinfo | grep -c overlay${T}zero${T}grep -c product/bin /proc/self/mounts${T}zero"
"X4${T}X${T}物料目录双通道(父目录 vs 物料目录)${T}runas${T}ls /data/local/tmp${T}absent${T}ls /data/local/tmp/ksu_boot${T}absent"
"X5${T}X${T}进程面双通道(ps vs 直接枚举 /proc)${T}runas${T}ps -A -o NAME | grep -c -e ksud${T}zero${T}for f in /proc/[0-9]*/comm; do cat \$f 2>/dev/null; done | grep -c -e ksud${T}zero"
)

# pair_side <view> <cmd> <expect> -> "<1|0|255>\t<实测值>"
#   1 = 按该期望判 PASS(不可见/为 0), 0 = FAIL(可见), 255 = 测不出(INFO)
pair_side() {
	local view="$1" cmd="$2" expect="$3" h raw
	if [ "$view" = runas ] && [ "$RUNAS_EXEC" = 0 ]; then
		printf '255\t%s' "$RUNAS_WHY"
		return
	fi
	exec_v "$view" "$cmd"
	judge "$expect"
	case "$VERDICT" in
		PASS) h=1 ;;
		FAIL) h=0 ;;
		*)    h=255 ;;
	esac
	raw=$(printf '%s' "$LAST_OUT" | tr '\n' ';' | cut -c1-40)
	[ -n "$raw" ] || raw="-"
	printf '%s\t%s' "$h" "$raw"
}

# <hidden> -> 人话
side_word() {
	case "$1" in
		1)   printf '不可见' ;;
		0)   printf '可见' ;;
		*)   printf '测不出' ;;
	esac
}

# ---------------------------------------------------------------- 主循环
npass=0; nfail=0; ninfo=0; nacc=0
{
	echo "=================================================================="
	echo "SUVTZ 观测面扫描  boot=$BOOT  device=$S"
	echo "app 域代理包=$PKG  runas_ok=$RUNAS_OK  runas_exec=$RUNAS_EXEC  device_locked=$DEV_LOCKED"
	echo "时间: $(date -Is)"
	echo "------------------------------------------------------------------"
	echo "视角说明: shell = 对照 (能力远超检测方);"
	echo "          runas = app uid + runas_app 域 (DAC 精确, SELinux 域不等价于"
	echo "          untrusted_app) => runas 的 PASS 是必要条件, 不是充分条件,"
	echo "          真正判据需 app 自身代码复测。"
	echo "期望值来源: docs/suvtz-v3-design.md §5.3 定义的 stock 期望 (非实测对照机)。"
	echo "类别: A 包与进程  B 文件系统  C 内核符号与模块  D 系统属性  E SELinux 与挂载"
	echo "      X 成对交叉验证 (同一事实两条独立通道, 要求同向; 分歧=FAIL)"
	echo "判定: PASS / FAIL / INFO ; FAIL* = 已显式裁决接受的 FAIL (仍计 FAIL, 单独列出)"
	echo "      接受表: ${ACCEPTED_FILE:-<disabled>}"
	echo "=================================================================="
	if [ "$DEV_LOCKED" = 1 ]; then
		echo "提示: 设备锁屏未解锁 (dumpsys user: RUNNING_LOCKED) — CE 存储不可见,"
		echo "      app 域(runas) 段必然全部 INFO。这不是扫描失败; 解锁屏幕后重跑"
		echo "      同一命令即可得到完整快照。"
	fi
	if [ "$RUNAS_OK" = 0 ] && [ "$DEV_LOCKED" = 0 ]; then
		echo "提示: runas 视角不可用 — $RUNAS_WHY"
	fi
	printf '%-5s %-3s %-40s %-6s %s\n' ID 类 观测面 判定 实测/原因
	echo "------------------------------------------------------------------"
} > "$REPORT"

for p in "${PROBES[@]}"; do
	IFS="$T" read -r id cls desc view cmd expect <<< "$p"

	if [ "$view" = runas ] && [ "$RUNAS_EXEC" = 0 ]; then
		LAST_RC=255; LAST_OUT=""
		VERDICT="INFO"; REASON="$RUNAS_WHY"
	else
		exec_v "$view" "$cmd"
		judge "$expect"
	fi

	acc=""   # set -u: every branch below reads it
	case "$VERDICT" in
		PASS) npass=$((npass+1));;
		FAIL)
			if acc=$(acc_reason "$id"); then
				nacc=$((nacc+1))
			else
				acc=""; nfail=$((nfail+1))
			fi
			;;
		*)    ninfo=$((ninfo+1));;
	esac

	# 实测值压成一行, 最多 90 字符
	act=$(printf '%s' "$LAST_OUT" | tr '\n' ';' | cut -c1-90)
	[ -n "$act" ] || act="-"
	[ -n "$REASON" ] && act="$act  ($REASON)"
	[ -n "$acc" ] && act="$act  (已接受: $acc)"

	vtag="$VERDICT"
	[ -n "$acc" ] && vtag="FAIL*"

	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$cls" "$view" "$VERDICT" "$expect" "$act" "$acc" >> "$SUMMARY"
	if [ "$QUIET" = 0 ]; then
		printf '%-5s %-3s %-40s %-6s %s\n' "$id" "$cls" "$desc" "$vtag" "$act" | tee -a "$REPORT" >&2
	else
		printf '%-5s %-3s %-40s %-6s %s\n' "$id" "$cls" "$desc" "$vtag" "$act" >> "$REPORT"
	fi
done

# X 类: 成对交叉验证(同一事实两条通道, 要求同向)
for p in "${PAIRS[@]}"; do
	IFS="$T" read -r id cls desc view ca ea cb eb <<< "$p"

	ra=$(pair_side "$view" "$ca" "$ea"); ha=${ra%%$T*}; va=${ra#*$T}
	rb=$(pair_side "$view" "$cb" "$eb"); hb=${rb%%$T*}; vb=${rb#*$T}

	if [ "$ha" = 255 ] || [ "$hb" = 255 ]; then
		VERDICT="INFO"
		REASON="至少一侧测不出(A=$(side_word "$ha") B=$(side_word "$hb"))"
	elif [ "$ha" = 1 ] && [ "$hb" = 1 ]; then
		VERDICT="PASS"
		REASON="两通道同为不可见"
	elif [ "$ha" = 0 ] && [ "$hb" = 0 ]; then
		VERDICT="FAIL"
		REASON="两通道同为可见"
	else
		VERDICT="FAIL"
		REASON="通道分歧 A=$(side_word "$ha") B=$(side_word "$hb")"
	fi

	acc=""   # set -u: every branch below reads it
	case "$VERDICT" in
		PASS) npass=$((npass+1));;
		FAIL)
			if acc=$(acc_reason "$id"); then
				nacc=$((nacc+1))
			else
				acc=""; nfail=$((nfail+1))
			fi
			;;
		*)    ninfo=$((ninfo+1));;
	esac

	act="A=$va | B=$vb"
	[ -n "$REASON" ] && act="$act  ($REASON)"
	[ -n "$acc" ] && act="$act  (已接受: $acc)"

	vtag="$VERDICT"
	[ -n "$acc" ] && vtag="FAIL*"

	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$cls" "$view" "$VERDICT" "same-direction" "$act" "$acc" >> "$SUMMARY"
	if [ "$QUIET" = 0 ]; then
		printf '%-5s %-3s %-40s %-6s %s\n' "$id" "$cls" "$desc" "$vtag" "$act" | tee -a "$REPORT" >&2
	else
		printf '%-5s %-3s %-40s %-6s %s\n' "$id" "$cls" "$desc" "$vtag" "$act" >> "$REPORT"
	fi
done

SUM=""
{
	echo "------------------------------------------------------------------"
	# 汇总里带上 runas 状态: PASS/INFO 的构成取决于它, 台账只看这一行时
	# 必须能区分「真的全测了」与「app 域整段没测」(锁屏/无载体)。
	if [ "$RUNAS_OK" = 1 ] && [ "$RUNAS_EXEC" = 1 ]; then RUNAS_TAG=ok; else RUNAS_TAG=no; fi
	if [ "$nacc" -gt 0 ]; then
		SUM="FAIL=$nfail (另有已接受 $nacc)  PASS=$npass  INFO=$ninfo  总计=$((nfail+npass+ninfo+nacc))  runas=$RUNAS_TAG"
	else
		SUM="FAIL=$nfail  PASS=$npass  INFO=$ninfo  总计=$((nfail+npass+ninfo))  runas=$RUNAS_TAG"
	fi
	echo "$SUM"
	echo
	if [ "$nfail" -gt 0 ]; then
		echo "FAIL 项 (检测方可直接观测到的 root 证据, 未裁决):"
		awk -F'\t' '$4=="FAIL" && $7=="" {printf "  %-5s %s\n",$1,$6}' "$SUMMARY"
		echo
	fi
	if [ "$nacc" -gt 0 ]; then
		echo "已接受暴露面 (判定仍为 FAIL, 经显式裁决接受; 表: $ACCEPTED_FILE):"
		awk -F'\t' '$4=="FAIL" && $7!="" {printf "  %-5s %s\n",$1,$7}' "$SUMMARY"
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
if [ "$QUIET" = 0 ]; then
	cat /tmp/.suvtz_tail.$$ >&2
else
	# -q 只打一行汇总到 stdout, 方便调用方 (如 postlock.sh 台账) 直接取用。
	echo "$SUM"
fi
rm -f /tmp/.suvtz_tail.$$

# 持久性判据的雏形: 换 boot 后与同设备历史结果比对
PREV=$(ls -1 "$OUT"/scan_*.tsv 2>/dev/null | grep -v "scan_${BOOT8}\.tsv" | tail -1)
if [ -n "$PREV" ]; then
	echo
	echo "(历史基线: $PREV —— 换 boot 后可用它验证「持久性」判据)"
fi

[ "$nfail" -gt 0 ] && exit 1
exit 0
