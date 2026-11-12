#!/system/bin/sh
# tsu 直调判据（V0b 的「不等冷 boot」部分）
#
# 运行方式（root 内，本 boot 已有可用 su 时）：
#   adb push tools/tsu/direct_probe.sh /data/local/tmp/tsu_direct_probe.sh
#   adb shell "su -c 'sh /data/local/tmp/tsu_direct_probe.sh'"
#
# 为什么可以直调：内核 sucompat 给 su 落点的凭证就是 uid=0 + u:r:ksu:s0（KSU
# 域）。用旧 su 起一个 root shell 再直调 $B，凭证与 sucompat 交付给 tsu 的
# 完全一致 —— 因此 T2/T3/T4/T5/T6 的语义可以在不替换落点的前提下验证。
# 只差 T0（落点 sha1）与 T1（新 ko 加冕 / 管理器 fd），那两项必须冷 boot。
#
# 本脚本只读；写入仅限 /data/local/tmp 下的临时文件（sidecar 演练后还原）。
B=/data/local/tmp/tsu
S=/data/local/tmp/vtz_w.pid
X=/data/local/tmp/tsu_probe_scratch
P=0; F=0; I=0
say()  { echo; echo "##### $*"; }
ok()   { P=$((P+1)); echo "PASS  $*"; }
bad()  { F=$((F+1)); echo "FAIL  $*"; }
info() { I=$((I+1)); echo "INFO  $*"; }
run()  { OUT=$("$@" 2>&1); RC=$?; }
# 只取关键行，避免整段 usage 把输出淹掉
brief() { printf '%s\n' "$1" | head -n 3 | tr '\n' ' '; }
# 状态行形如 "  CapEff=0000003fffffffff" / "  mnt_ns=mnt:[4026533362]" /
# "  driver_fd=<none> (说明)"：取第一个 "=" 之后、首个空白之前的值。
val()  { printf '%s\n' "$OUT" | sed -n "s/^[[:space:]]*$1=//p" | head -n 1 | sed 's/[[:space:]].*$//'; }

say "环境"
echo "uid=$(id -u) ctx=$(cat /proc/self/attr/current 2>/dev/null)"
echo "bin=$B"
if [ ! -x "$B" ]; then
  bad "D0 $B 不存在或不可执行"
  echo; echo "===== direct probe: PASS=0 FAIL=1 ====="; echo "RESULT: FAIL"; exit 1
fi
echo "bin_sha1=$(sha1sum "$B" | awk '{print $1}')"
NS_N=$(readlink /proc/self/ns/mnt)
NS_INIT=$(readlink /proc/1/ns/mnt)
echo "ns_now=$NS_N ns_init=$NS_INIT"
if [ "$(id -u)" != 0 ]; then
  bad "D0 不是 root 上下文（必须 su -c 运行本脚本）"
fi

say "D1 自述版本"
run "$B" --trysu-version
echo "rc=$RC out=$(brief "$OUT")"
case "$OUT" in
  *"tsu 0.3.0"*) ok "D1 --trysu-version -> tsu 0.3.0" ;;
  *) bad "D1 版本不符：$(brief "$OUT")" ;;
esac

say "D2 权能自述（--trysu-status）"
run "$B" --trysu-status
echo "$OUT"
CAP=$(val CapEff)
SEC=$(val Seccomp)
CTX=$(val context)
MNS=$(val mnt_ns)
DFD=$(val driver_fd)
case "$CAP" in
  ''|*[!0]*) [ -n "$CAP" ] && ok "D2 CapEff=$CAP（非零）" || bad "D2 无 CapEff 行" ;;
  *) bad "D2 CapEff 全零（$CAP）" ;;
esac
case "$SEC" in
  0) ok "D2b Seccomp=0" ;;
  '') bad "D2b 无 Seccomp 行" ;;
  *) bad "D2b Seccomp=$SEC" ;;
esac
case "$CTX" in
  *"u:r:ksu:s0"*) ok "D2c context=$CTX" ;;
  *) bad "D2c context 不是 ksu 域：$CTX" ;;
esac
if [ -n "$MNS" ] && [ "$MNS" = "$NS_N" ]; then
  ok "D2d mnt_ns 自述与实测一致（$MNS）"
else
  bad "D2d mnt_ns 自述 $MNS != 实测 $NS_N"
fi
case "$DFD" in
  0|'<none>') info "D2e driver_fd=$DFD（直调 root shell 未经 ksud 的 fd 安装路径，属预期）" ;;
  *) ok "D2e driver_fd=$DFD" ;;
esac

say "D3 -c 执行身份"
run "$B" -c 'id'
echo "rc=$RC out=$(brief "$OUT")"
case "$OUT" in
  *uid=0*"u:r:ksu:s0"*) ok "D3 -c id -> uid=0 + ksu 域" ;;
  *) bad "D3 -c id 异常：$(brief "$OUT")" ;;
esac

say "D4 argv 透传（\$0/\$1）"
run "$B" -c 'echo "A=$0 B=$1"' xx yy
echo "rc=$RC out=$(brief "$OUT")"
case "$OUT" in
  "A=xx B=yy"*) ok "D4 \$0/\$1 原样透传" ;;
  *) bad "D4 透传错位：$(brief "$OUT")" ;;
esac
run "$B" -s /system/bin/sh -c 'echo S-OK'
case "$OUT" in
  S-OK*) ok "D4b -s /system/bin/sh 生效" ;;
  *) bad "D4b -s 未生效：$(brief "$OUT")" ;;
esac
run "$B" -c 'exit 7'
if [ "$RC" = 7 ]; then ok "D4c 退出码透传（rc=7）"; else bad "D4c 退出码未透传（rc=$RC）"; fi

say "D5 真进入 VN（--vtz）"
if [ -f "$S" ]; then
  echo "sidecar=[$(cat "$S")]"
  WINO=$(awk '{print $2}' "$S")
  WPID=$(awk '{print $1}' "$S")
  NS_VN="mnt:[$WINO]"
  run "$B" --vtz -c 'readlink /proc/self/ns/mnt'
  echo "rc=$RC out=$(brief "$OUT") want=$NS_VN"
  case "$OUT" in
    *"[$WINO]") ok "D5 --vtz 会话在 VN（inode $WINO）" ;;
    *) bad "D5 --vtz 未进入 VN：$(brief "$OUT")" ;;
  esac
  run "$B" --vtz -c 'ls /data/local/tmp/.w >/dev/null 2>&1 && echo W-VISIBLE'
  case "$OUT" in
    *W-VISIBLE*) ok "D5b VN 内可见 .w（holder tmpfs 生效）" ;;
    *) info "D5b VN 内看不到 .w：$(brief "$OUT")" ;;
  esac
  run "$B" --vtz -c 'id'
  case "$OUT" in
    *uid=0*) ok "D5c VN 内保持 uid=0" ;;
    *) bad "D5c VN 内身份异常：$(brief "$OUT")" ;;
  esac
  run "$B" --vtz -c 'tail -n 2 /data/local/tmp/.w/log/access.log 2>&1'
  echo "log: $(printf '%s\n' "$OUT" | tr '\n' '|')"
  case "$OUT" in
    *kind=enter*via=sidecar*) ok "D5d access.log 记下 kind=enter via=sidecar" ;;
    *kind=enter*) info "D5d access.log 有 kind=enter 但 via 不是 sidecar：$(brief "$OUT")" ;;
    *) bad "D5d access.log 无 kind=enter：$(brief "$OUT")" ;;
  esac
  # 显式 ns：以 holder pid 为参数，结果应与 sidecar 一致
  run "$B" --trysu-ns "$WPID" -c 'readlink /proc/self/ns/mnt'
  case "$OUT" in
    *"[$WINO]") ok "D5e --trysu-ns $WPID 落在同一 ns" ;;
    *) bad "D5e --trysu-ns 落点不符：$(brief "$OUT")" ;;
  esac
  run "$B" --trysu-ns "$WPID" -c 'tail -n 1 /data/local/tmp/.w/log/access.log'
  case "$OUT" in
    *via=ns-explicit*) ok "D5f access.log 区分 via=ns-explicit" ;;
    *) info "D5f 未见 via=ns-explicit：$(brief "$OUT")" ;;
  esac
else
  info "D5 无 sidecar（VN 未建立），跳过进入类判据"
fi

say "D6 -M 优先级（init ns 高于 --vtz）"
run "$B" -M --vtz -c 'readlink /proc/self/ns/mnt'
echo "rc=$RC out=$(brief "$OUT") init=$NS_INIT"
if [ -n "$NS_INIT" ] && [ "$OUT" = "$NS_INIT" ]; then
  ok "D6 -M 覆盖 --vtz，落在 init ns"
else
  bad "D6 -M 落点不符：$(brief "$OUT") != $NS_INIT"
fi

say "D7 fail-closed"
run "$B" -M --trysu-ns 1 -c 'echo SHOULD-NOT-PRINT'
case "$RC:$OUT" in
  2:*参数冲突*) ok "D7 -M + --trysu-ns 冲突直接失败（rc=2）" ;;
  *SHOULD-NOT-PRINT*) bad "D7 冲突仍执行了命令（rc=$RC）" ;;
  *) info "D7 冲突失败但措辞不同（rc=$RC）：$(brief "$OUT")" ;;
esac
run "$B" -l
case "$RC:$OUT" in
  2:*未实现*) ok "D7b -l 报「未实现的 su 用法」（rc=2）" ;;
  *) info "D7b -l 语义：rc=$RC $(brief "$OUT")" ;;
esac
if [ -f "$S" ]; then
  mv "$S" "$S.probe-bak" 2>/dev/null
  run "$B" --vtz -c 'echo SHOULD-NOT-PRINT'
  case "$RC:$OUT" in
    2:*SHOULD-NOT-PRINT*) bad "D7c 无 sidecar 仍执行（rc=$RC）" ;;
    2:*"no W registered"*) ok "D7c 无 sidecar 时 fail-closed 且保留 no W registered（rc=2）" ;;
    *) info "D7c 无 sidecar 语义：rc=$RC $(brief "$OUT")" ;;
  esac
  mkdir -p "$X"; printf '1 999999999\n' >"$S"
  run "$B" --vtz -c 'echo SHOULD-NOT-PRINT'
  case "$RC:$OUT" in
    2:*SHOULD-NOT-PRINT*) bad "D7d inode 校验缺失（rc=$RC，命令被执行）" ;;
    2:*) ok "D7d sidecar inode 不符时回读校验生效（rc=2）" ;;
    *) info "D7d 语义：rc=$RC $(brief "$OUT")" ;;
  esac
  rm -f "$S"
  mv "$S.probe-bak" "$S" 2>/dev/null
  echo "sidecar restored=[$(cat "$S" 2>/dev/null)]"
  run "$B" -c 'true'
  if [ "$RC" = 0 ] && [ -f "$S" ]; then ok "D7e 演练后 sidecar 已还原且 tsu 正常"; else info "D7e 还原后 rc=$RC"; fi
else
  info "D7c-e 无 sidecar，跳过一致性演练"
fi

say "D8 与内核/系统约定的一致性"
run "$B" --status
case "$OUT" in
  *"tsu 0.3.0"*|*uid=0*) ok "D8 --status 别名可用" ;;
  *) info "D8 --status 输出：$(brief "$OUT")" ;;
esac
echo "kernel_ksud_path=$(su -c 'cat /sys/module/kernelsu/parameters/ksu_debug_manager_appid' 2>/dev/null)"
info "D8b 落点替换与内核加冕属冷 boot 判据（T0/T1），本脚本不判"

echo
echo "===== tsu direct probe: PASS=$P FAIL=$F INFO=$I ====="
[ "$F" -eq 0 ] && echo "RESULT: OK" || echo "RESULT: FAIL"
