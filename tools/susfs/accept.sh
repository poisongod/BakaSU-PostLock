#!/bin/bash
# SuSFS v2.3.0 (LKM edition) 九项功能验收
#
# 两级判据
#   Level 1 = 命令受理：内核侧 dmesg 出现 "CMD_SUSFS_xxx -> ret: 0"
#             （dmesg 是唯一权威：shell 域直接跑 ksud 根本进不到内核）
#   Level 2 = 语义生效：真实 app 进程里「标记前 / 标记后」自检对照，
#             唯一变量是内核标记命令，不靠任何猜测
#
# 为什么语义验收只能在 app 进程里做：SUSFS 的隐藏判定要求进程带
# TIF_PROC_UMOUNTED（只有 zygote fork 出来的 app 才有）。shell / run-as / su
# 看到的永远是未隐藏的世界（见 platform/SusfsSelfTest.kt 头注释）。
#
# 载体：PKG 默认 com.postlock.boot。该 app 自 2026-11-06 起冻结为 legacy，但保留
# SusfsSelfTest 这一个能力——上面的限制没有变，它是「隐藏对 app 真生效」的唯一
# 证据来源。换载体只需改 PKG= 且实现同款 SUSFS_SELFTEST 广播契约。
#
# 两个刻意的设计选择（踩过的坑）：
#   1. 隐藏只对「app 进程」生效：所有路径/映射/挂载隐藏都门控在
#      susfs_is_current_proc_umounted_app() = TIF_PROC_UMOUNTED && uid>=10000，
#      而 susfs_path_inode_hidden() 对属主另有一条豁免（current_uid == i_uid）。
#      所以标记 /system/bin/toybox 之后，shell(2000) 与 root(0) 都不受影响，
#      本脚本仍然一律走 root（RR）读设备——不是因为 shell 会被隐藏，而是因为
#      root 上下文才能跑 ksud susfs 命令（非 root 上下文根本进不到内核）。
#   2. dmesg 判据按「标记前后计数增量」比对，不用「出现即通过」——重复命令
#      （add_sus_kstat 与 statically 共用标签）也能分辨。
#
# 本 ABI 没有 DEL_* 命令：SUS_PATH / SUS_MAP / SUS_KSTAT / OPEN_REDIRECT /
# CMDLINE 的标记只能靠重启清除。脚本末尾只复原 uname、mount 隐藏开关与挂载。
#
# 用法：./accept.sh</dev/null   （验收完必须重启；同 boot 不允许重跑）

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
AB="${AB:-$HERE/adb1.sh}"
OUT="${OUT:-/tmp/opencode/susfs/out}"
PKG="${PKG:-com.postlock.boot}"

SUS_SRC=/data/local/tmp/sus_src
SUS_DST=/data/local/tmp/sus_dst
FAKE_CMDLINE=/data/local/tmp/sus_fake_cmdline

# SUS_PATH 目标必须是「app 能列出的目录下的普通文件」：判断 readdir 面隐藏
# （listed 1 -> 0）要先能 list 父目录，而 /system/bin 对 app 是 Permission
# denied（会假失败）。/system/etc 可列，且 NOTICE.xml.gz 没有运行期读取者。
T_PATH_CANDS="/system/etc/NOTICE.xml.gz /system/etc/apns-conf.xml \
/vendor/etc/NOTICE.xml.gz"
T_PATH_LOOP_CANDS="/system/etc/prop.default /system/build.prop"
T_KSTAT=/system/etc/hosts                   # SUS_KSTAT（普通文件，非符号链接）
T_REDIR=/system/etc/security/otacerts.zip  # OPEN_REDIRECT target
T_REDIR_SRC=/system/etc/hosts              # OPEN_REDIRECT redirected
# 对照项候选（不标记）：必须同样位于 app 可列目录（否则 listed 恒 0，
# 「对照未受影响」判据失去意义），且 inode 与两个被标记目标、SUS_KSTAT 目标
# 都不同（个别 ROM 会把这些名字做成同一 inode 的链接）。
C_PATH_CANDS="/system/etc/gps_debug.conf /system/etc/apns-conf.xml \
/system/etc/audio_effects.conf /system/framework/framework.jar /system/bin/sh"
# SUS_MAP 目标：必须是进程真的已映射的实际路径（/system/lib64/libc.so 是符号
# 链接，kern_path 解析到 apex，用 apex 实路径更直观）。按序取第一个存在的。
MAP_CANDIDATES="/apex/com.android.runtime/lib64/bionic/libc.so \
/apex/com.android.art/lib64/libc++.so"

K_INO=777001
K_SIZE=123456
# 伪造串不能以 '#' 或 '-' 开头：经 su -c '...' 传给设备 sh 时会被当注释/选项。
FAKE_RELEASE=6.1.99-android13-8-gdeadbeef001
FAKE_VERSION=TestBuild-SMP-PREEMPT-aarch64
FAKE_CMDLINE_TXT="console=ttyMSM0,115200n8 androidboot.susfs=lkm-test"

PASS=0
FAIL=0
mkdir -p "$OUT"
: >"$OUT/summary.txt"
: >"$OUT/cli.txt"

res() {
	case "$1" in
	PASS) PASS=$((PASS + 1)) ;;
	FAIL) FAIL=$((FAIL + 1)) ;;
	esac
	printf '%-4s %-30s %s\n' "$1" "$2" "${3:-}" | tee -a "$OUT/summary.txt"
}

# 信息项：不参与 PASS/FAIL 计数。用于「该环境无法观测」的诚实结论——
# 绝不把不可观测写成 PASS（真协议红线）。
info() {
	printf '%-4s %-30s %s\n' INFO "$1" "${2:-}" | tee -a "$OUT/summary.txt"
}

die() {
	printf 'ABORT: %s\n' "$*" | tee -a "$OUT/summary.txt" >&2
	exit 2
}

# ---------------------------------------------------------------------------
# adb / root 原语
# ---------------------------------------------------------------------------
d() { "$AB" shell "$1" 2>&1 | tr -d '\r'; }

SU_KIND=""
SU_BIN=""
KSUD_CLI=""

RR() {
	local cmd=$1
	case "$SU_KIND" in
	su) d "$SU_BIN -c '$cmd'" ;;
	ksud) d "printf '%s\n' '$cmd' | $KSUD_CLI debug su" ;;
	*) return 1 ;;
	esac
}

RR_ok() { RR "$1; echo RC=\$?" | grep -q 'RC=0'; }

# 注意不能写成 `RR "test -f $f" && ...`：RR 的返回码来自管道末端的 tr，
# 永远是 0。只能看输出。
file_exists() { [ "$(RR "test -e $1 && echo Y")" = "Y" ]; }
file_nonempty() { [ "$(RR "test -s $1 && echo Y")" = "Y" ]; }
mounted() { [ "$(RR "grep -c $1 /proc/mounts" | tr -d ' \r\n')" != "0" ]; }

detect_channel() {
	[ -x "$AB" ] || die "缺少 $AB（chmod +x）"
	d 'id' | grep -q 'uid=' || die "设备不在线：adb1.sh 找不到目标设备"

	local out
	out=$(d '/product/bin/su -c id' 2>/dev/null)
	if printf '%s' "$out" | grep -q 'uid=0'; then
		SU_KIND=su
		SU_BIN=/product/bin/su
	else
		out=$(d "printf 'id\n' | /data/local/tmp/ksud debug su" 2>/dev/null)
		if printf '%s' "$out" | grep -q 'uid=0'; then
			SU_KIND=ksud
			KSUD_CLI=/data/local/tmp/ksud
		else
			die "无 root 通道（/product/bin/su 与 ksud debug su 均不可用）"
		fi
	fi

	local k
	for k in /product/bin/ksud /data/adb/ksud /data/local/tmp/ksud; do
		if RR_ok "test -x $k"; then
			KSUD_CLI=$k
			break
		fi
	done
	[ -n "$KSUD_CLI" ] || die "找不到可执行的 ksud"
	printf 'channel: %s  ksud=%s\n' "$SU_KIND" "$KSUD_CLI"
}

susfs_cli() { RR "$KSUD_CLI susfs $*"; }

# 内核侧看到该命令成功的次数（全量 dmesg，容忍环形缓冲滚动）
#
# 注意：RR 会把命令塞进 `su -c '...'`，因此命令体内**绝对不能出现单引号**
# （会提前闭合、把后半截交给外层 shell）。这里用双引号包标记与 "ret: 0"：
# 双引号在 su -c 的单引号内是字面量，正好由设备侧 sh 解释。
# 标记必须整体加引号再交给 grep -F：一来避免 `->` 被当成重定向，二来调用方
# 可以传入带空格的精确标记（`CMD_SUSFS_ADD_SUS_PATH ->`），否则它作为
# `..._LOOP` / `..._STATICALLY` 的前缀会被一起数进去。
count_marker() {
	RR "dmesg | grep -F \"$1\" | grep -c \"ret: 0\"" | tr -d '\r\n '
}

# 通用日志行计数（不加 "ret: 0" 过滤）
count_plain() {
	RR "dmesg | grep -c -F \"$1\"" | tr -d ' \r\n'
}

# root 侧读 /proc/cmdline。SPOOF_CMDLINE 的钩子整体替换 cmdline_proc_show，
# 没有 uid 门控 → root 看到的同样是伪造值，这是本项唯一可用的观测通道
# （app 域读 /proc/cmdline 被 SELinux 拒，见 Level 2 的 INFO 项）。
root_cmdline() { RR "cat /proc/cmdline" | tr -d '\r' | sed 's/[[:space:]]*$//'; }

# root 侧 /proc/kallsyms 计数（按 name 前缀命中；同样无 uid 门控 → root 一致）。
# 命令体内不能出现单引号（RR 会塞进 su -c '...'），所以用双引号。
ksym_count() {
	RR "grep -c -F \" $1\" /proc/kallsyms" | tr -d ' \r\n'
}

# ---------------------------------------------------------------------------
# Level 1：命令受理
# ---------------------------------------------------------------------------
run1() {
	local label=$1 marker=$2 c0 c1 cli
	shift 2
	c0=$(count_marker "$marker")
	cli=$(susfs_cli "$@" 2>&1)
	c1=$(count_marker "$marker")
	printf '### %s :: ksud susfs %s\n%s\n\n' "$label" "$*" "$cli" >>"$OUT/cli.txt"
	if [ "${c1:-0}" -gt "${c0:-0}" ]; then
		res PASS "$label" "$marker ret=0"
	else
		res FAIL "$label" "dmesg 未见 $marker ret=0（$(
			RR "dmesg | grep -F \"$marker\" | tail -n 2" | tr '\n' '|'
		)）"
	fi
}

# 负向测试：不存在的路径必须被内核拒绝（证明打点不是无条件打印）
run1_reject() {
	local label=$1 marker=$2 cli c0 c1
	shift 2
	c0=$(count_marker "$marker")
	cli=$(susfs_cli "$@" 2>&1)
	c1=$(count_marker "$marker")
	printf '### %s (negative) :: ksud susfs %s\n%s\n\n' "$label" "$*" "$cli" >>"$OUT/cli.txt"
	if [ "${c1:-0}" -eq "${c0:-0}" ] &&
		RR "dmesg | grep -F \"$marker\" | tail -n 1" | grep -q 'ret: -'; then
		res PASS "$label(负向)" "不存在的路径被拒"
	else
		res FAIL "$label(负向)" "内核未拒绝该路径（打点可能是无条件打印）"
	fi
}

show_features() {
	local out n
	out=$(susfs_cli show enabled_features 2>&1)
	printf '%s\n' "$out" >"$OUT/features_$1.txt"
	n=$(printf '%s\n' "$out" | grep -c '^CONFIG_KSU_SUSFS_')
	printf '%s' "$n"
}

# ---------------------------------------------------------------------------
# 自检（app 私有目录一律用 root 读写：标记 toybox 后 run-as 里的 toybox 全没了）
# ---------------------------------------------------------------------------
selftest() {
	local tag=$1 i f out
	f="/data/user/0/$PKG/files/susfs_selftest_$tag.txt"
	out="$OUT/selftest_$tag.txt"
	RR "rm -f $f" >/dev/null 2>&1
	d "am broadcast -n $PKG/.BootReceiver -a com.postlock.boot.SUSFS_SELFTEST --es tag $tag $ST_EXTRAS" \
		>/dev/null 2>&1
	for i in $(seq 1 60); do
		file_exists "$f" && break
		sleep 0.5
	done
	if ! file_exists "$f"; then
		# app 被 HANS 冻结时广播会排队不执行（熄屏场景）。拉前台解冻是
		# 最小必要的 UI 动作（用户在亮屏使用设备时不会走到这里）。
		printf 'selftest[%s]: 30s 未生成，拉前台重试\n' "$tag"
		d "am start -n $PKG/.MainActivity" >/dev/null 2>&1
		sleep 1
		# 必须重发一次：首次广播若落在 stopped 包上会被丢弃且不补投，
		# 光 am start 只解锁状态，不会再触发那一发已丢的广播。
		RR "rm -f $f" >/dev/null 2>&1
		d "am broadcast -n $PKG/.BootReceiver -a com.postlock.boot.SUSFS_SELFTEST --es tag $tag $ST_EXTRAS" \
			>/dev/null 2>&1
		for i in $(seq 1 40); do
			file_exists "$f" && break
			sleep 0.5
		done
	fi
	RR "cat $f" >"$out"
	if ! grep -q '^end=1' "$out" 2>/dev/null; then
		res FAIL "selftest[$tag]" "自检文件未生成（app 未运行？先手动打开一次 app 再跑）"
		return 1
	fi
	return 0
}

kv() { sed -n "s/^$1=//p" "$2" | head -n 1; }

# cmp_eq <name> <key> <before期望> <after期望>
cmp_eq() {
	local name=$1 key=$2 eb=$3 ea=$4 b a
	b=$(kv "$key" "$OUT/selftest_before.txt")
	a=$(kv "$key" "$OUT/selftest_after.txt")
	if [ "$b" = "$eb" ] && [ "$a" = "$ea" ]; then
		res PASS "$name" "$key: $b -> $a"
	else
		res FAIL "$name" "期望 $eb -> $ea，实测 $b -> $a"
	fi
}

# cmp_same <name> <key>   对照项：前后必须一致且不是 ERR
cmp_same() {
	local name=$1 key=$2 b a
	b=$(kv "$key" "$OUT/selftest_before.txt")
	a=$(kv "$key" "$OUT/selftest_after.txt")
	if [ -n "$a" ] && [ "$a" = "$b" ] && ! printf '%s' "$a" | grep -q '^ERR'; then
		res PASS "$name" "$key 未受影响（$a）"
	else
		res FAIL "$name" "$key 前后不一致（$b -> $a）"
	fi
}

# cmp_changed <name> <key>   要求 before != after，且两侧都不是 ERR
cmp_changed() {
	local name=$1 key=$2 b a
	b=$(kv "$key" "$OUT/selftest_before.txt")
	a=$(kv "$key" "$OUT/selftest_after.txt")
	if [ -n "$a" ] && [ "$a" != "$b" ] &&
		! printf '%s' "$b" | grep -q '^ERR' &&
		! printf '%s' "$a" | grep -q '^ERR'; then
		res PASS "$name" "$key: $b -> $a"
	else
		res FAIL "$name" "$key 未变化（$b -> $a）"
	fi
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
detect_channel

BOOT=$(RR 'cat /proc/sys/kernel/random/boot_id' | tr -d ' \r\n-')
[ -n "$BOOT" ] || die "读不到 boot_id"
MARKED_FILE="$OUT/.marked_boot"
if [ -f "$MARKED_FILE" ] && [ "$(cat "$MARKED_FILE")" = "$BOOT" ]; then
	die "本 boot ($BOOT) 已标记过，重启后再验收（本 ABI 无 DEL 命令）"
fi
printf 'boot: %s\n' "$BOOT"

# ---- 语义前提：进程必须带 TIF_PROC_UMOUNTED ----
# SUS_PATH / SUS_MAP / OPEN_REDIRECT(uid_scheme=unmounted-app) / SUS_MOUNT 的隐藏
# 都门控在 susfs_is_current_proc_umounted_app() = TIF_PROC_UMOUNTED && uid>=10000，
# 而该 thread flag 只由内核在「模块已加载后 zygote fork 出的进程 setresuid」
# 那一刻打上（ksu_handle_umount，default 非 root profile umount_modules=true）。
# app 进程若早于模块加载就已存在，就永远没有这个标记 —— 验收会假失败。
# 所以先把旧进程杀掉，让下面第一次广播冷启动出一个带标记的新进程。
# 注意用 kill -9 而不是 am force-stop：后者会把包置 stopped，害死 BOOT_COMPLETED。
# 进程名要按 comm 的 15 字符上限截断：com.postlock.boot(17) 在 /proc/pid/stat 里
# 是 com.postlock.bo，用全名 pidof 永远查不到（toybox pidof 比的是 comm）。
APP_COMM=${PKG:0:15}
# pidof 输出可能是多行（多进程）：把换行换成空格，交给 kill 一次性处理；
# 全用 -d 会把两个 pid 粘成一个不存在的数字。
OLD_PID=$(RR "pidof $PKG" | tr '\n' ' ')
OLD_PID=$(printf '%s' "$OLD_PID" | tr -s ' ')
[ -n "${OLD_PID// /}" ] || OLD_PID=$(RR "pidof $APP_COMM" | tr '\n' ' ')
OLD_PID=$(printf '%s' "$OLD_PID" | tr -s ' ' | sed 's/^ *//;s/ *$//')
if [ -n "$OLD_PID" ]; then
	RR "kill -9 $OLD_PID" >/dev/null 2>&1
	sleep 1
	printf 'killed stale app pid=%s（等广播冷启动带标记的新进程）\n' "$OLD_PID"
else
	printf 'no stale app process（首次广播将冷启动一个新进程）\n'
fi

# ---- 0. 目标选择（找不到就在打标之前早退，不在设备上留半套标记） ----
ino_of() { RR "stat -c %i $1" | tr -d ' \r\n'; }

# 取候选表里第一个「存在且是普通文件（跟随符号链接）」的路径
pick_file() {
	local p
	for p in $1; do
		[ "$(RR "test -f $p && echo Y")" = "Y" ] || continue
		printf '%s' "$p"
		return 0
	done
	return 1
}

T_PATH=$(pick_file "$T_PATH_CANDS") || die "SUS_PATH 目标候选都不存在：$T_PATH_CANDS"
T_PATH_LOOP=$(pick_file "$T_PATH_LOOP_CANDS") || die "SUS_PATH_LOOP 目标候选都不存在：$T_PATH_LOOP_CANDS"
for p in "$T_KSTAT" "$T_REDIR" "$T_REDIR_SRC"; do
	file_exists "$p" || die "目标不存在：$p"
done

P_INO=$(ino_of "$T_PATH")
L_INO=$(ino_of "$T_PATH_LOOP")
K_INO_REAL=$(ino_of "$T_KSTAT")
[ -n "$P_INO" ] || die "读不到 $T_PATH 的 inode"

# 对照项必须与两个被标记目标、以及 SUS_KSTAT 目标都不同 inode：/system/bin
# 下一大批文件名都是 toybox 的符号链接，一旦 sh 也是它的链接，标记 toybox
# 会连带隐藏对照，判据就自相矛盾（假 FAIL）。找不到合适对照就在打标之前
# die —— 设备上不会留半套标记，修完可直接重跑。
C_PATH="" C_INO=""
for p in $C_PATH_CANDS; do
	[ "$(RR "test -f $p && echo Y")" = "Y" ] || continue
	i=$(ino_of "$p")
	[ -n "$i" ] || continue
	[ "$i" = "$P_INO" ] && continue
	[ "$i" = "$L_INO" ] && continue
	[ "$i" = "$K_INO_REAL" ] && continue
	C_PATH=$p C_INO=$i
	break
done
[ -n "$C_PATH" ] || die "找不到与被标记目标不同 inode 的对照文件：$C_PATH_CANDS"
printf 'control inode: %s=%s  %s=%s\n' "$T_PATH" "$P_INO" "$C_PATH" "$C_INO"

T_MAP=""
for p in $MAP_CANDIDATES; do
	if file_exists "$p"; then
		T_MAP=$p
		break
	fi
done
[ -n "$T_MAP" ] || die "SUS_MAP 目标都不存在：$MAP_CANDIDATES"

# OPEN_REDIRECT 的第二种拼写：同一 inode 的规范路径（目标常是符号链接，
# 例如 /system/etc/security/otacerts.zip -> /my_engineering/...）。规则按
# 「调用方写的字符串」匹配，内核把规范名存成别名，这里取出来在 app 侧验证
# 两侧都能命中。不是符号链接时为空，该项只记 INFO。
T_REDIR_ALIAS=$(RR "readlink -f $T_REDIR" | tr -d ' \r\n')
[ "$T_REDIR_ALIAS" = "$T_REDIR" ] && T_REDIR_ALIAS=""
printf 'targets: path=%s loop=%s kstat=%s map=%s redirect=%s<-%s alias=%s\n' \
	"$T_PATH" "$T_PATH_LOOP" "$T_KSTAT" "$T_MAP" "$T_REDIR" "$T_REDIR_SRC" \
	"${T_REDIR_ALIAS:-无}"

# 自检广播的 extras：目标全部由 host 选定后下发，app 侧不写死任何路径
# （不同 ROM 的 toybox/prop.default/对照文件位置并不一致）。
ST_EXTRAS="--es map $T_MAP --es path $T_PATH --es pathloop $T_PATH_LOOP"
ST_EXTRAS="$ST_EXTRAS --es ctl $C_PATH --es redir $T_REDIR --es redirsrc $T_REDIR_SRC"
[ -n "$T_REDIR_ALIAS" ] && ST_EXTRAS="$ST_EXTRAS --es rediralias $T_REDIR_ALIAS"

# ---- 1. 准备 ----
RR "mkdir -p $SUS_SRC $SUS_DST"
# 值里只有一个空格、没有单引号：不加引号时 echo 会把两个词原样用空格连回去。
RR "echo $FAKE_CMDLINE_TXT > $FAKE_CMDLINE"
file_nonempty "$FAKE_CMDLINE" || die "伪造 cmdline 文件写失败"
printf '%s\n' "$FAKE_CMDLINE_TXT" >"$OUT/fake_cmdline.txt"

# 假挂载必须由 ksu 域建立：SUS_MOUNT 只给 ksu 域建的 mount 打伪 id
mounted "$SUS_DST" || RR "mount --bind $SUS_SRC $SUS_DST" >/dev/null 2>&1
mounted "$SUS_DST" || die "bind mount 失败：$SUS_SRC -> $SUS_DST"

# 让 app 也能看见它：zygote（以及开机预热好的 usap 池）在启动时就各自持有
# 一份挂载命名空间拷贝，之后 shell 域新建的挂载不会传播进去 —— 而 app 进程
# 正是从这些命名空间 fork 出来的。所以再逐个 nsenter 进去 bind 一次；每次
# 都由 ksu 域发起，同样会被 alloc_vfsmnt 钩子打上伪 id。
NS_PIDS=""
for n in zygote64 zygote usap64 usap32; do
	for pid in $(RR "pidof $n" | tr '\n' ' '); do
		RR "nsenter -t $pid -m mount --bind $SUS_SRC $SUS_DST" >/dev/null 2>&1
		v=$(RR "nsenter -t $pid -m grep -c $SUS_DST /proc/self/mounts" |
			tr -d ' \r\n')
		[ "${v:-0}" != 0 ] && NS_PIDS="$NS_PIDS $pid"
	done
done
printf 'prepared: %s -> %s (额外打标命名空间 pid:%s)\n' \
	"$SUS_SRC" "$SUS_DST" "${NS_PIDS:- 无}"

# ---- 2. 基线 ----
F_BEFORE=$(show_features before)
[ "$F_BEFORE" = 9 ] && res PASS "features(before)" "9 项全部上报" ||
	res FAIL "features(before)" "只上报 $F_BEFORE 项"

VERSION_OUT=$(susfs_cli show version 2>&1)
VARIANT_OUT=$(susfs_cli show variant 2>&1)
printf 'show version: %s\nshow variant: %s\n\n' "$VERSION_OUT" "$VARIANT_OUT" >>"$OUT/cli.txt"
printf '%s' "$VERSION_OUT" | grep -q 'v2\.3\.0' &&
	res PASS "show version" "$VERSION_OUT" ||
	res FAIL "show version" "$VERSION_OUT"
printf '%s' "$VARIANT_OUT" | grep -q 'GKI' &&
	res PASS "show variant" "$VARIANT_OUT" ||
	res FAIL "show variant" "$VARIANT_OUT"

# 真实 kstat（必须在标记前读；SUS_KSTAT 的 stat 伪装没有 uid 门控）
REAL_INO=$(RR "stat -c %i $T_KSTAT" | tr -d ' \r\n')
REAL_SIZE=$(RR "stat -c %s $T_KSTAT" | tr -d ' \r\n')
printf 'real kstat: ino=%s size=%s\n' "$REAL_INO" "$REAL_SIZE"
case "$REAL_INO" in '' | *[!0-9]*) die "读不到 $T_KSTAT 的真实 ino（$REAL_INO）" ;; esac

SELFTEST_OK=1
selftest before || SELFTEST_OK=0

# root 侧 cmdline 基线（必须在 set_cmdline 之前读；伪造后 root 也读到假值）
CM_B=$(root_cmdline)
printf 'root cmdline before: %.100s\n' "$CM_B"

# 内核侧直接证据的基线：susfs_path_inode_hidden() 命中时会打 "hiding ino"
# （需要 enable_log=1，下面第一件事就是开它）。
HID0=$(count_plain "hiding ino")

# ---- 3. Level 1 ----
# 标记统一带 " ->" 后缀：`CMD_SUSFS_ADD_SUS_PATH` 是 `..._LOOP` 的前缀、
# `CMD_SUSFS_ADD_SUS_KSTAT` 是 `..._STATICALLY` 的前缀，不区分就会把
# 后者的成功行数进前者的增量里（负向测试会因此假通过/假失败）。
run1 "enable_log" CMD_SUSFS_ENABLE_LOG enable_log 1
run1 "add_sus_path" "CMD_SUSFS_ADD_SUS_PATH ->" add_sus_path "$T_PATH"
run1 "add_sus_path_loop" "CMD_SUSFS_ADD_SUS_PATH_LOOP ->" \
	add_sus_path_loop "$T_PATH_LOOP"
run1 "add_sus_map" CMD_SUSFS_ADD_SUS_MAP add_sus_map "$T_MAP"
run1 "add_sus_kstat" "CMD_SUSFS_ADD_SUS_KSTAT ->" add_sus_kstat "$T_KSTAT"
run1 "update_sus_kstat_full_clone" CMD_SUSFS_UPDATE_SUS_KSTAT update_sus_kstat_full_clone "$T_KSTAT"
# statically 必须最后跑：它整体覆盖同一路径的 info（memcpy），
# 最终 spoofed_ino/spoofed_size 才是这里给的固定值。
run1 "add_sus_kstat_statically" "CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY ->" \
	add_sus_kstat_statically "$T_KSTAT" "$K_INO" default default "$K_SIZE"
run1 "add_open_redirect" CMD_SUSFS_ADD_OPEN_REDIRECT \
	add_open_redirect "$T_REDIR" "$T_REDIR_SRC" 3
run1 "hide_sus_mnts" CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS \
	hide_sus_mnts_for_non_su_procs 1
run1 "set_uname" CMD_SUSFS_SET_UNAME set_uname "$FAKE_RELEASE" "$FAKE_VERSION"
run1 "set_cmdline" CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG \
	set_cmdline_or_bootconfig "$FAKE_CMDLINE"

run1_reject "add_sus_path" "CMD_SUSFS_ADD_SUS_PATH ->" add_sus_path /data/local/tmp/no_such_susfs_target

# 未实现的命令必须诚实报 unsupported（内核侧不写 err，userspace 初值 126）
AVC_OUT=$(susfs_cli enable_avc_log_spoofing 1 2>&1)
printf '### enable_avc_log_spoofing\n%s\n\n' "$AVC_OUT" >>"$OUT/cli.txt"
if printf '%s' "$AVC_OUT" | grep -qi 'unsupported'; then
	res PASS "enable_avc_log_spoofing" "诚实报 unsupported"
else
	res FAIL "enable_avc_log_spoofing" "未报 unsupported：$AVC_OUT"
fi

# ---- 4. arm 之后 feature 列表必须仍是 9 项（钩子装不上会降级） ----
F_AFTER=$(show_features after)
[ "$F_AFTER" = 9 ] && res PASS "features(after)" "9 项（arm 后无降级）" ||
	res FAIL "features(after)" "降到 $F_AFTER 项（某处 arm 失败）"

# ---- 5. Level 2：语义对照 ----
if [ "$SELFTEST_OK" = 1 ]; then
	selftest after || SELFTEST_OK=0
fi

if [ "$SELFTEST_OK" = 1 ]; then
	cmp_eq "SUS_PATH exists" path.target.exists 1 0
	cmp_eq "SUS_PATH listed" path.target.listed 1 0
	cmp_eq "SUS_PATH_LOOP exists" path.loop.exists 1 0
	cmp_eq "SUS_PATH_LOOP listed" path.loop.listed 1 0
	cmp_same "SUS_PATH 对照" path.ctl.exists
	cmp_same "SUS_PATH 对照 listed" path.ctl.listed

	# 内核侧独立证据：susfs_path_inode_hidden() 命中会打 "hiding ino"。
	# 有增量 = 内核真的执行了隐藏分支（与 app 观测量两条独立证据链）。
	HID1=$(count_plain "hiding ino")
	if [ "${HID1:-0}" -gt "${HID0:-0}" ]; then
		res PASS "SUS_PATH 内核侧" "dmesg 'hiding ino' $HID0 -> $HID1"
	else
		res FAIL "SUS_PATH 内核侧" "dmesg 'hiding ino' 无增量（$HID0 -> ${HID1:-?}）"
	fi

	cmp_eq "SUS_KSTAT ino" kstat.target.ino "$REAL_INO" "$K_INO"
	cmp_eq "SUS_KSTAT size" kstat.target.size "$REAL_SIZE" "$K_SIZE"
	cmp_same "SUS_KSTAT 对照 ino" kstat.ctl.ino

	# SUS_MAP：判定单位是 VMA，目标库的每条映射占 maps 一行（libc 通常 4 段），
	# 所以判据是「标记前 >=1 行 → 标记后 0 行」，行数取自 app 侧对 host 传入
	# 目标路径的精确计数（不是布尔、也不是写死的文件名）。
	MB=$(kv map.target.lines "$OUT/selftest_before.txt")
	MA=$(kv map.target.lines "$OUT/selftest_after.txt")
	if [ "${MB:-0}" -ge 1 ] && [ "${MA:-1}" = 0 ]; then
		res PASS "SUS_MAP maps" "$T_MAP 行数 $MB -> $MA"
	else
		res FAIL "SUS_MAP maps" "$T_MAP 行数 $MB -> $MA（before 应 >=1，after 应为 0）"
	fi
	# map.numentries 只写入 out/selftest_*.txt 供人工比对，不参与评分：
	# 进程自身会不断创建/释放线程栈与 JIT 页，行数浮动属正常噪声。

	cmp_changed "OPEN_REDIRECT 内容" redirect.target
	cmp_same "OPEN_REDIRECT 对照" redirect.src

	# 同一文件的第二种拼写（符号链接的目标）。规则按调用方写的字符串
	# 匹配，内核把规范名存成别名 —— 两侧都必须命中，否则「用哪个拼写
	# 打开」就会成为可用性差异（真实 app 两种都会用）。
	if [ -n "$T_REDIR_ALIAS" ]; then
		RB=$(kv redirect.alias "$OUT/selftest_before.txt")
		RA=$(kv redirect.alias "$OUT/selftest_after.txt")
		if [ -n "$RA" ] && [ "$RA" != "$RB" ] &&
			! printf '%s' "$RA" | grep -q '^ERR'; then
			res PASS "OPEN_REDIRECT 别名内容" "$T_REDIR_ALIAS: $RB -> $RA"
		else
			res FAIL "OPEN_REDIRECT 别名内容" \
				"$T_REDIR_ALIAS: $RB -> $RA（别名未命中重定向）"
		fi
	else
		info "OPEN_REDIRECT 别名" "$T_REDIR 不是符号链接，无第二种拼写可测"
	fi

	# SUS_MOUNT 有两条彼此独立的证据：
	# ① 内核侧（与挂载命名空间无关，权威）：ksu 域创建的挂载会被
	#    alloc_vfsmnt/clone_mnt 的 kretprobe 换成伪 id（>= DEFAULT_KSU_MNT_ID
	#    = 2000000000）。真实 id 由内核 ida 从 0 起分配、永远到不了该区间，
	#    所以「伪 id」本身就是「这个挂载对 app 隐藏」的内核标记。
	#    root/su 处在 ksu 域，不受隐藏影响，能把它读出来。
	# ② app 侧：该挂载从 /proc/self/mounts 消失。前提是 app 与该挂载在同一个
	#    挂载命名空间——Android 11+ 若给了 app 私有 namespace，它本来就不在
	#    里面，此时 0 -> 0 无法区分「隐藏生效」与「从来没看见」，只能记信息项，
	#    不能伪造成 PASS。
	MI_LINE=$(RR "grep -F $SUS_DST /proc/self/mountinfo")
	FAKE_ID=$(printf '%s' "$MI_LINE" | cut -d' ' -f1)
	case "$FAKE_ID" in '' | *[!0-9]*) FAKE_ID=0 ;; esac
	if [ "$FAKE_ID" -ge 2000000000 ]; then
		res PASS "SUS_MOUNT 内核打标" "mnt_id=$FAKE_ID（>= 2e9 伪 id）"
	else
		res FAIL "SUS_MOUNT 内核打标" \
			"mnt_id=$FAKE_ID（alloc_vfsmnt 钩子应换成 >= 2e9）"
	fi

	MB_M=$(kv mount.sus_dst "$OUT/selftest_before.txt")
	MA_M=$(kv mount.sus_dst "$OUT/selftest_after.txt")
	MB_I=$(kv mountinfo.sus_dst "$OUT/selftest_before.txt")
	MA_I=$(kv mountinfo.sus_dst "$OUT/selftest_after.txt")
	if [ "${MB_M:-0}" = 1 ] && [ "${MA_M:-1}" = 0 ]; then
		res PASS "SUS_MOUNT app 隐藏" \
			"mounts 1 -> 0（mountinfo $MB_I -> $MA_I）"
	elif [ "${MB_M:-1}" = 0 ] && [ "${MA_M:-1}" = 0 ]; then
		info "SUS_MOUNT app 隐藏: app 看不到该挂载（私有挂载命名空间），本项不作判据"
	else
		res FAIL "SUS_MOUNT app 隐藏" \
			"mounts 期望 1 -> 0，实测 $MB_M -> $MA_M（mountinfo $MB_I -> $MA_I）"
	fi

	cmp_eq "SPOOF_UNAME release" uname.release \
		"$(kv uname.release "$OUT/selftest_before.txt")" "$FAKE_RELEASE"
	cmp_eq "SPOOF_UNAME version" uname.version \
		"$(kv uname.version "$OUT/selftest_before.txt")" "$FAKE_VERSION"

	# app 域读 /proc/cmdline 被 SELinux 拒（FileNotFoundException），因此
	# 该项改在下面的 root 侧小节判定；钩子整体替换 cmdline_proc_show、
	# 没有 uid 门控，root 与 app 看到的是同一个被改写的结果。
	info "SPOOF_CMDLINE(app)" \
		"app 域不可读（$(kv cmdline "$OUT/selftest_after.txt")），改由 root 侧观测"
	# 本内核 CONFIG_BOOT_CONFIG 未开、没有 /proc/bootconfig，所以
	# SPOOF_CMDLINE_OR_BOOTCONFIG 只对 /proc/cmdline 可观测（已文档化）。
	# 这一半是「本环境无法观测」，不是通过也不是失败 —— 记 INFO。
	info "SPOOF bootconfig" "本内核无 /proc/bootconfig（CONFIG_BOOT_CONFIG=n），该半边不可观测"

	# /proc/kallsyms 同样在 app 域不可读，改由 root 侧小节判定（该钩子也
	# 没有 uid 门控）。这里只如实记录 app 侧的观测结果。
	info "HIDE_SYMBOLS(app)" \
		"app 域不可读 /proc/kallsyms（$(kv kallsyms.err "$OUT/selftest_after.txt")），改由 root 侧观测"
fi

# ---- 5b. root 侧观测：两项特性都没有 uid 门控，root 与 app 等价 ----
# 这两项之所以不能像其它项一样只看 app：untrusted_app 域读 /proc/cmdline 与
# /proc/kallsyms 均被 SELinux 拒（dontaudit 静默）。而内核侧的钩子既不判
# uid 也不判 TIF 标志，root 通道看到的完全一致，因此用 root 观测是等价且
# 可复现的证据，不是降低标准。
CM_A=$(root_cmdline)
# before 必须不是伪造串（否则本轮无法证明「被替换」）、after 必须精确等于伪造串。
if [ -n "${CM_B:-}" ] && [ "$CM_B" != "$FAKE_CMDLINE_TXT" ] &&
	[ "$CM_A" = "$FAKE_CMDLINE_TXT" ]; then
	res PASS "SPOOF_CMDLINE" "root 侧 /proc/cmdline 已整体替换为伪造串"
else
	res FAIL "SPOOF_CMDLINE" \
		"root 侧未替换（before=${CM_B:0:60} after=${CM_A:0:60}）"
fi

KS_SUSFS=$(ksym_count susfs_)
KS_KSU=$(ksym_count ksu_)
KS_KSX=$(ksym_count __ksu_)
KS_STEXT=$(ksym_count _stext)
KS_DOEXIT=$(ksym_count do_exit)
# 判据：所有隐藏前缀命中数为 0，且两个绝不在前缀表里的普通符号可见。
# 后者排除「整个 /proc/kallsyms 读不到所以是 0」这种假阳性。
if [ "${KS_SUSFS:-1}" = 0 ] && [ "${KS_KSU:-1}" = 0 ] && [ "${KS_KSX:-1}" = 0 ] &&
	[ "${KS_STEXT:-0}" -gt 0 ] && [ "${KS_DOEXIT:-0}" -gt 0 ]; then
	res PASS "HIDE_KSU_SUSFS_SYMBOLS" \
		"susfs_/ksu_/__ksu_ 均 0 条，_stext=$KS_STEXT do_exit=$KS_DOEXIT 可见"
else
	res FAIL "HIDE_KSU_SUSFS_SYMBOLS" \
		"susfs_=$KS_SUSFS ksu_=$KS_KSU __ksu_=$KS_KSX _stext=$KS_STEXT do_exit=$KS_DOEXIT"
fi

# ---- 6. 复原能复原的部分 ----
susfs_cli set_uname default default >/dev/null 2>&1
susfs_cli hide_sus_mnts_for_non_su_procs 0 >/dev/null 2>&1
RR "umount $SUS_DST" >/dev/null 2>&1
for pid in $NS_PIDS; do
	RR "nsenter -t $pid -m umount $SUS_DST" >/dev/null 2>&1
done
printf '%s\n' "$BOOT" >"$MARKED_FILE"

# ---- 7. 汇总 ----
{
	printf '\n=========== SUSFS ACCEPTANCE ===========\n'
	printf 'boot   : %s\n' "$BOOT"
	printf 'device : %s\n' "$(RR 'getprop ro.product.model')"
	printf 'kernel : %s\n' "$(RR 'uname -r')"
	printf 'driver : %s\n' "$(RR 'cat /sys/module/kernelsu/version 2>/dev/null')"
	printf 'app    : uid=%s ctx=%s\n' \
		"$(kv uid "$OUT/selftest_after.txt")" \
		"$(kv context "$OUT/selftest_after.txt")"
	printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
	printf '注意：SUS_PATH / SUS_MAP / SUS_KSTAT / OPEN_REDIRECT / CMDLINE 的标记\n'
	printf '      无法撤销，必须重启设备才能回到干净状态。\n'
	if [ "$FAIL" != 0 ]; then
		printf '\n— 诊断提示（全部隐藏项都失败时先看这里）—\n'
		printf '隐藏只对带 TIF_PROC_UMOUNTED 的 app 进程生效，它要求：\n'
		printf '  1) 进程是模块加载之后由 zygote fork 的（脚本已 kill 旧进程重来）；\n'
		printf '  2) 该 uid 没有 su 授权（allow_su=1 的 profile 会让\n'
		printf '     ksu_uid_should_umount() 返回 false，标志就不打）。\n'
		printf '管理器「超级用户」里若能看到 %s，先撤销授权再重跑。\n' "$PKG"
	fi
} | tee -a "$OUT/summary.txt"

[ "$FAIL" = 0 ] || exit 1
exit 0
