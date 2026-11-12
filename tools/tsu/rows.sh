#!/system/bin/sh
# TrySU V0b 判据脚本（../TrySU/docs/trysu-implementation.md §2.4 的可执行版本）
#
# 用法（设备侧，shell 域即可，内部按需 su）：
#   adb push tools/tsu/rows.sh /data/local/tmp/tsu_rows.sh
#   adb shell 'sh /data/local/tmp/tsu_rows.sh'
#
# 前置：一次冷 boot + tools/postlock.sh（restore 装落点 /data/adb/ksud，并起
# VN holder + 写 sidecar /data/local/tmp/vtz_w.pid）。
#
# 本脚本只读；唯一写入是 /data/local/tmp 下的 dmesg 快照。
#
# 观察限制（沿用 tools/suvtz/v0a_rows.sh 的实测结论，别当缺陷）：
#   * shell 域读 /proc/<pid>/ns/mnt 被 SELinux 拒（空输出）-> 一律经 su 读；
#   * shell 域无 dmesg 权限、/proc/kallsyms 地址全 0 -> 经 su 读；
#   * su 只在 allow-list uid（本环境 shell 因 CONFIG_KSU_DEBUG 放行）+ ocsk 已
#     加载时才安全；恢复链窗口之外勿跑（ocsk 不在时会弹安全警告并可能重启）。
#
# 判据口径：只认可观测事实。读不到的记 INFO，绝不记 PASS。
T=/data/local/tmp
S=$T/vtz_w.pid
TSHA=05d486e6fff01817caafa9f8f35f44812d5c2c2d	# tools/tsu/tsu
TVERS=0.3.0
P=0; F=0; I=0
say()  { echo; echo "##### $*"; }
ok()   { P=$((P+1)); echo "PASS  $*"; }
bad()  { F=$((F+1)); echo "FAIL  $*"; }
info() { I=$((I+1)); echo "INFO  $*"; }
# su 的 stderr 一起抓，失败语义要能被看见
suc()  { su "$@" 2>&1; }
# 按完整 cmdline 找进程（comm 被内核截到 15 字符，pidof 包名不可靠）
pids() { ps -A -o PID,ARGS 2>/dev/null | grep -F "$1" | grep -v grep | awk '{print $1}'; }

say "环境"
echo "boot_reason=$(getprop ro.boot.bootreason)"
echo "selinux=$(getenforce 2>/dev/null)"
SUID=$(suc -c 'id' 2>&1)
echo "su -c id -> $SUID"
case "$SUID" in
  *uid=0*) HAZ_SU=1 ;;
  *) HAZ_SU=0; info "su 不可用（本 boot 未跑恢复链？）——以下 su 依赖项必然 INFO/FAIL" ;;
esac

say "T0 部署落点 /data/adb/ksud"
if [ "$HAZ_SU" = 1 ]; then
  SHA=$(suc -c 'sha1sum /data/adb/ksud 2>/dev/null' | awk '{print $1}')
  echo "sha1=$SHA"
  suc -c 'ls -l /data/adb/ksud 2>/dev/null'
  if [ "$SHA" = "$TSHA" ]; then
    ok "T0 落点 == tools/tsu/tsu ($TSHA)"
  else
    bad "T0 落点不是 tsu（sha1=$SHA）"
  fi
  RSHA=$(suc -c 'sha1sum /data/local/tmp/ksud 2>/dev/null' | awk '{print $1}')
  echo "rust-ksud sha1=$RSHA"
  if [ -z "$RSHA" ]; then
    info "T0b /data/local/tmp/ksud 缺失（host 排障 CLI 不可用，不影响 su）"
  elif [ "$RSHA" = "$SHA" ]; then
    bad "T0b 两条 ksud 路径指向同一文件（分工被破坏）"
  else
    ok "T0b 分工成立（/data/local/tmp/ksud 仍是 Rust build）"
  fi
  V=$(suc --trysu-version)
  echo "su --trysu-version -> $V"
  case "$V" in
    *"tsu $TVERS"*) ok "T0c 落点自述 tsu $TVERS" ;;
    *) bad "T0c 落点不是 tsu $TVERS：$V" ;;
  esac
else
  info "T0 跳过（无 su）"
fi

say "T1 内核侧加冕"
MPID=$(pids io.trysu.manager | head -n 1)
echo "manager pid=${MPID:-<none>}"
DM=$T/tsu_rows_dmesg.txt
if [ "$HAZ_SU" = 1 ]; then
  suc -c 'dmesg' >"$DM" 2>/dev/null
  echo "dmesg bytes=$(wc -c <"$DM" 2>/dev/null)"
  grep -E 'manager pkg:|track_throne|install fd for ksu manager' "$DM" 2>/dev/null | tail -n 8
  MP=$(grep -c 'manager pkg:.*io.trysu.manager' "$DM" 2>/dev/null)
  if [ "${MP:-0}" -ge 1 ]; then
    ok "T1 内核认 TrySU 管理器（manager pkg: io.trysu.manager）"
  else
    info "T1 dmesg 未见 io.trysu.manager（环形缓冲可能已滚掉；以驱动 fd 为准）"
  fi
  if [ -n "$MPID" ]; then
    FD=$(suc -c "ls -l /proc/$MPID/fd 2>/dev/null | grep -c ksu_driver")
    echo "manager ksu_driver fd count=${FD:-0}"
    if [ "${FD:-0}" -ge 1 ]; then
      ok "T1b 管理器进程持有 [ksu_driver] 句柄（${FD} 个）"
    else
      bad "T1b 管理器进程没有 [ksu_driver] 句柄（未加冕 / 进程早于模块加载）"
    fi
  else
    info "T1b 管理器进程不在（未启动，无法观测 fd）"
  fi
else
  info "T1 跳过（无 su）"
fi

say "T2 落点身份（su -c id）"
if [ "$HAZ_SU" = 1 ]; then
  case "$SUID" in
    *uid=0*"u:r:ksu:s0"*) ok "T2 uid=0 且 SELinux 域 u:r:ksu:s0" ;;
    *uid=0*) info "T2 uid=0 但域不是 ksu：$SUID" ;;
    *) bad "T2 未拿到 uid=0：$SUID" ;;
  esac
else
  info "T2 跳过（无 su）"
fi

say "T3 权能审计（su --trysu-status）"
if [ "$HAZ_SU" = 1 ]; then
  ST=$(suc --trysu-status)
  echo "$ST"
  CAP=$(echo "$ST" | awk -F': *' '/CapEff/{print $2; exit}')
  SEC=$(echo "$ST" | awk -F': *' '/Seccomp/{print $2; exit}')
  NNP=$(echo "$ST" | awk -F': *' '/NoNewPrivs/{print $2; exit}')
  echo "CapEff=$CAP NoNewPrivs=$NNP Seccomp=$SEC"
  case "$CAP" in
    '') bad "T3 status 无 CapEff 行" ;;
    *[!0]*) ok "T3 CapEff=$CAP（非零）" ;;
    *) bad "T3 CapEff 全零（$CAP）：setns/mount 不可能成功" ;;
  esac
  case "$SEC" in
    0) ok "T3b Seccomp=0（su 会话未被 seccomp 限制）" ;;
    '') bad "T3b status 无 Seccomp 行" ;;
    *) bad "T3b Seccomp=$SEC（非 0，链原语会受影响）" ;;
  esac
else
  info "T3 跳过（无 su）"
fi

say "T4 真进入 VN（su --vtz）"
if [ "$HAZ_SU" = 1 ]; then
  if [ -f "$S" ]; then
    echo "sidecar: [$(cat "$S")]"
    WINO=$(awk '{print $2}' "$S")
    SES=$(suc --vtz -c 'readlink /proc/self/ns/mnt')
    echo "session-ns=$SES want=mnt:[$WINO]"
    case "$SES" in
      *"[$WINO]") ok "T4 会话真在 VN（inode $WINO）" ;;
      *) bad "T4 会话不在 sidecar 指定的 ns：$SES" ;;
    esac
    NID=$(suc --vtz -c 'id')
    case "$NID" in
      *uid=0*) ok "T4b VN 内仍是 uid=0" ;;
      *) bad "T4b VN 内身份异常：$NID" ;;
    esac
  else
    info "T4 sidecar $S 不存在（VN 未建立 → --vtz 应 fail-closed）"
    OUT=$(suc --vtz -c 'echo SHOULD-NOT-PRINT')
    echo "$OUT"
    case "$OUT" in
      *SHOULD-NOT-PRINT*) bad "T4 无 sidecar 时仍执行了命令（未 fail-closed）" ;;
      *"no W registered"*) ok "T4 无 sidecar 时 fail-closed 且保留 no W registered 关键字" ;;
      *) info "T4 无 sidecar 的拒绝措辞不匹配：$OUT" ;;
    esac
  fi
else
  info "T4 跳过（无 su）"
fi

say "T5 -M 优先级（高于 --vtz）"
if [ "$HAZ_SU" = 1 ]; then
  NS1=$(suc -c 'readlink /proc/1/ns/mnt')
  NS5=$(suc -M --vtz -c 'readlink /proc/self/ns/mnt')
  echo "init-ns=$NS1  -M+--vtz=$NS5"
  if [ -n "$NS1" ] && [ "$NS1" = "$NS5" ]; then
    ok "T5 -M 覆盖 --vtz，落在 init ns（$NS1）"
  else
    bad "T5 -M 未落在 init ns：$NS5 != $NS1"
  fi
else
  info "T5 跳过（无 su）"
fi

say "T6 入口记录（VN 侧 access.log）"
if [ "$HAZ_SU" = 1 ]; then
  AL=$(suc --vtz -c 'tail -n 3 /data/local/tmp/.w/log/access.log 2>&1')
  echo "$AL"
  case "$AL" in
    *kind=enter*) ok "T6 access.log 有 kind=enter 行" ;;
    *) bad "T6 access.log 无 kind=enter 行" ;;
  esac
  case "$AL" in
    *via=sidecar*) ok "T6b 本次进入 via=sidecar" ;;
    *) info "T6b 未见 via=sidecar（-M / --trysu-ns 路径会是别的 via）" ;;
  esac
  # 不判决：N 侧能否看到 VN 侧日志取决于 holder 的隔离布点，只记录事实。
  echo "N 侧 su 视角: $(suc -c 'ls -ld /data/local/tmp/.w/log 2>&1' | tr -s ' ')"
  info "T6c N 侧可见性仅作观测记录（不判 PASS/FAIL）"
else
  info "T6 跳过（无 su）"
fi

say "T7 回归（host 侧后续）"
if [ -f "$T/vtz_rows.sh" ]; then
  echo "-- 发现 $T/vtz_rows.sh，R1-R10 输出如下 --"
  sh "$T/vtz_rows.sh" 2>&1 | tail -n 80
else
  info "T7 未推送 vtz_rows.sh；host 另跑 tools/suvtz/v0a_rows.sh + scan.sh -q"
fi

echo
echo "===== tsu rows: PASS=$P FAIL=$F INFO=$I ====="
[ "$F" -eq 0 ] && echo "RESULT: OK" || echo "RESULT: FAIL"
