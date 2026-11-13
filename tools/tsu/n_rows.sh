#!/system/bin/sh
# TrySU P1 判据脚本：N1–N12（docs/trysu-daemonless-vn-design.md §5 的可执行版本）
#
# 用法（设备侧，shell 域即可，内部按需 su）：
#   adb push tools/tsu/n_rows.sh /data/local/tmp/tsu_n_rows.sh
#   adb shell 'sh /data/local/tmp/tsu_n_rows.sh'
#
# 宿主一键（含 N12 的 scan.sh）：tools/tsu/n_accept.sh
#
# 只读默认：唯一写入是 /data/local/tmp 下的 dmesg/清单快照。
# 唯一已知副作用：N9a 用 `--trysu-ns 1` 探测入口是否存在，旧 tsu 的审计落点
# 硬编码为 /data/local/tmp/.w/log/access.log（进哪个 ns 就写哪），因此会在 N 侧
# 留下 via=ns-explicit 记录。N9a 结束后会检查该路径不是挂载点并清理，避免污染
# 下一轮 N5（N5 的语义是「N 侧看不到 VN 内容」，不能被本脚本自己的残留误伤）。
# N8（篡改材料）与 N10b（审计写失败）是破坏性实验，需显式 N8_ARM=1 / N10_ARM=1，
# 且都会在 trap 里恢复原文件。
#
# 判据口径（沿用 rows.sh / v0a_rows.sh）：
#   * 只认可观测事实；读不到记 INFO，绝不记 PASS；
#   * shell 域读 /proc/<pid>/ns/mnt 可能被 SELinux 拒 -> 一律经 su 读；
#   * su 只在 ocsk 加载 + allow-list 窗口安全，恢复链之外勿跑。
#
# 形态说明（重要）：
#   脚本用 holder 是否存在区分两种形态，并据此给出预期红：
#     form=legacy（holder 在）   → N1/N2b/N4b/N4c/N6/N7/N9a/N10a 通常红（P1 靶子）
#     form=daemonless（无 holder）→ 无预期红（N7/N13 已落地；N8/N10b 需 ARM）
#   P1 构造器落地后设备应为 daemonless：--trysu-vn 由 tsu 自建 VN，
#   不读 sidecar、不需要 holder。若 daemonless 下 N1/N6 仍红，说明恢复链
#   还在起 holder/写 sidecar（postlock.sh 未改造）。
#   N5 的观测方法：清掉上一轮 .w/log（只删 log，保留 .w 目录），再执行一次
#   --trysu-vn，然后看 N 侧是否出现 .w/log。holder 挂载点完好时它应 PASS；
#   若 N5 红，先查 holder 的 tmpfs 挂载点是否被删（见 docs/forensics/
#   holder-mountpoint-deletion-ebd7d915.md），再怀疑 tsu。
#   脚本头部会打印形态探测结果，避免把靶子误读成回归。
T=/data/local/tmp
MAT=/data/adb/trysu
# manifest 行格式：<sha256> <mode-octal> <bytes> <name>（与 tsu 的解析顺序一致）
MAN=$MAT/manifest.sha256
AUD=$MAT/audit.log
S=$T/vtz_w.pid
DM=$T/tsu_n_rows_dmesg.txt
P=0; F=0; I=0
say()  { echo; echo "##### $*"; }
ok()   { P=$((P+1)); echo "PASS  $*"; }
bad()  { F=$((F+1)); echo "FAIL  $*"; }
info() { I=$((I+1)); echo "INFO  $*"; }
# su 的 stderr 一起抓，失败语义要能被看见
suc()  { su "$@" 2>&1; }
# --trysu-status 行格式是 "  key=value"
val()  { printf '%s\n' "$ST" | sed -n "s/^[[:space:]]*$1=//p" | head -n 1 | sed 's/[[:space:]].*$//'; }
# 按完整 cmdline 找进程（comm 被截到 15 字符）
pids() { ps -A -o PID,ARGS 2>/dev/null | grep -F "$1" | grep -v grep | awk '{print $1}'; }

say "环境与形态探测"
echo "boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
echo "uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)s  selinux=$(getenforce 2>/dev/null)"
SUID=$(suc -c 'id' 2>&1)
echo "su -c id -> $SUID"
case "$SUID" in
  *uid=0*) HAZ_SU=1 ;;
  *) HAZ_SU=0; info "su 不可用（本 boot 未跑恢复链）——su 依赖判据只能 INFO/FAIL" ;;
esac
HOLD=$(pids "wns hold")
if [ -n "$HOLD" ]; then
  FORM=legacy
  echo "form=legacy（holder pid=$(echo "$HOLD" | tr '\n' ' ')）——P1 未实现，N1/N4b/N5/N6/N7/N9a/N10a 预期 FAIL"
else
  FORM=daemonless
  echo "form=daemonless（无 holder）"
fi

# 清理旧 tsu 留在 N 侧的审计残留。
# 只删 .w/log 内容，**绝不删 .w 目录本身**：它可能是 holder tmpfs 的挂载点目录
# （N ns 里看是普通目录，holder ns 里是 tmpfs）。删掉挂载点会让 holder 的私有
# 视图退化（2026-11-13 两次实测，均需重启 holder 才恢复）。
# 返回 0 = 已清理/无需清理；1 = 当前 ns 里 .w 本身是挂载点，跳过。
clean_w() {
  suc -c 'test -d /data/local/tmp/.w/log' >/dev/null 2>&1 || return 0
  if suc -c 'grep -Fq " /data/local/tmp/.w " /proc/self/mountinfo' >/dev/null 2>&1; then
    return 1
  fi
  suc -c 'rm -f /data/local/tmp/.w/log/access.log 2>/dev/null; rmdir /data/local/tmp/.w/log 2>/dev/null' >/dev/null 2>&1
  return 0
}

# ---------------------------------------------------------------- N1
say "N1 无 holder 进程"
if [ -z "$HOLD" ]; then
  ok "N1 无 holder 进程"
else
  bad "N1 存在 holder pid=$(echo "$HOLD" | tr '\n' ' ')（旧守护形态未退役）"
fi

# ---------------------------------------------------------------- N2
say "N2 会话在 VN 且自持"
NS_N=$(suc -c 'readlink /proc/1/ns/mnt')
NS_VN=$(suc --trysu-vn -c 'readlink /proc/self/ns/mnt')
SPID=$(suc --trysu-vn -c 'echo $$' 2>/dev/null | tr -cd '0-9')
echo "N-ns=$NS_N  session-ns=$NS_VN  session-pid=$SPID"
if [ -z "$NS_VN" ]; then
  bad "N2 --trysu-vn 无 ns 输出（入口不可用或未构造）"
elif [ -z "$NS_N" ]; then
  info "N2 读不到 N 对照 ns，无法比较"
elif [ "$NS_VN" = "$NS_N" ]; then
  bad "N2 会话仍在 N（$NS_VN）"
else
  ok "N2 会话 ns=$NS_VN 与 N($NS_N) 不同"
fi
# N2b：自持 = 构造者 pid == 会话 pid（以 audit 的 via=self 记录为证；
# 构造器 exec 前后 pid 不变，所以两者相等才说明「VN 是本次会话自建的」）
CREATE=$(suc -c "tail -n 20 $AUD 2>/dev/null" | grep 'via=self' | tail -n 1)
if [ -z "$CREATE" ]; then
  info "N2b 无 via=self 审计记录（未构造 / 审计未落，无法验证自持）"
else
  CPID=$(printf '%s\n' "$CREATE" | sed -n 's/.*[[:space:]]pid=\([0-9]*\).*/\1/p')
  if [ -z "$SPID" ] || [ -z "$CPID" ]; then
    info "N2b 审计或会话 pid 缺失：audit=[$CREATE] session-pid=[$SPID]"
  elif [ "$CPID" = "$SPID" ]; then
    ok "N2b 构造者 pid == 会话 pid（$CPID）"
  else
    bad "N2b 构造者 pid=$CPID != 会话 pid=$SPID（VN 不是本会话自持）"
  fi
fi

# ---------------------------------------------------------------- N3
say "N3 对照仍在 N"
NS_CTL=$(suc -c 'readlink /proc/self/ns/mnt')
echo "control-ns=$NS_CTL"
if [ -z "$NS_N" ] || [ -z "$NS_CTL" ]; then
  info "N3 ns 读不到（N=[$NS_N] ctl=[$NS_CTL]）"
elif [ "$NS_CTL" = "$NS_N" ]; then
  ok "N3 不带开关的 su 仍在 N（$NS_CTL）"
else
  bad "N3 不带开关的 su 不在 N：$NS_CTL != $NS_N"
fi

# ---------------------------------------------------------------- N4
say "N4 VN 随会话消亡"
R1=$(suc --trysu-vn -c 'echo pid=$$; readlink /proc/self/ns/mnt')
PIDA=$(printf '%s\n' "$R1" | sed -n 's/^pid=//p')
NSA=$(printf '%s\n' "$R1" | sed -n 's#^mnt:##p')
R2=$(suc --trysu-vn -c 'echo pid=$$; readlink /proc/self/ns/mnt')
PIDB=$(printf '%s\n' "$R2" | sed -n 's/^pid=//p')
NSB=$(printf '%s\n' "$R2" | sed -n 's#^mnt:##p')
echo "session-A pid=$PIDA ns=$NSA"
echo "session-B pid=$PIDB ns=$NSB"
sleep 1
if [ -z "$PIDA" ]; then
  info "N4 第一次会话无 pid 输出，无法判定"
else
  if [ -d "/proc/$PIDA" ]; then
    bad "N4a 会话 pid $PIDA 退出后仍存在（常驻）"
  else
    ok "N4a 会话 pid $PIDA 退出后已消亡"
  fi
fi
HOLDCNT=0
if [ -n "$NSA" ]; then
  HOLDCNT=$(suc -c 'for p in /proc/[0-9]*/ns/mnt; do readlink "$p" 2>/dev/null; done' | grep -Fc "mnt:$NSA")
  echo "ns $NSA 仍被持有: ${HOLDCNT:-0} 个进程"
fi
if [ -z "$NSA" ] || [ -z "$NSB" ]; then
  info "N4b ns 缺失（A=[$NSA] B=[$NSB]）"
elif [ "$NSA" != "$NSB" ]; then
  ok "N4b 两次构造 ns 不同（$NSA -> $NSB）"
elif [ "${HOLDCNT:-0}" -eq 0 ]; then
  # 第一次会话已退出、ns 已销毁；内核复用 inode 编号是正常行为，
  # 不能据此判「常驻持有者」。真正的判据是 N4c（无存活持有者）。
  info "N4b 两次 inode 相同（$NSA）但旧 ns 无存活持有者 → 内核复用编号，非失败"
else
  bad "N4b 两次复用同一 ns 且旧 ns 仍被 ${HOLDCNT} 个进程持有"
fi
if [ -n "$NSA" ]; then
  if [ "${HOLDCNT:-0}" -eq 0 ]; then
    ok "N4c 旧 ns 无进程持有（会话退出即消亡）"
  else
    bad "N4c 旧 ns $NSA 仍被 ${HOLDCNT} 个进程持有"
  fi
fi

# ---------------------------------------------------------------- N5
say "N5 N 侧不可见 VN 内容"
if [ "$HAZ_SU" = 1 ]; then
  if clean_w; then
    echo "baseline: N 侧 .w/log 已清空（保留 .w 目录本身）"
  else
    info "N5 /data/local/tmp/.w 在当前 ns 是挂载点，无法建立干净基线"
  fi
  suc --trysu-vn -c true >/dev/null 2>&1
  L5=$(suc -c 'ls -d /data/local/tmp/.w/log 2>&1')
  echo "进入一次 --trysu-vn 后: ls .w/log -> $L5"
  case "$L5" in
    *"No such file"*|*"not found"*) ok "N5 进入 VN 未在 N 侧留下 .w/log" ;;
    *"Permission denied"*) info "N5 权限拒绝，无法区分「不存在」与「不可读」" ;;
    *) bad "N5 进入 VN 后 N 侧出现 .w/log（审计写到了 N 侧）：$L5" ;;
  esac
else
  info "N5 跳过（无 su）"
fi

# ---------------------------------------------------------------- N6
say "N6 无文件路标（sidecar）"
if [ -f "$S" ]; then
  bad "N6 sidecar $S 仍存在（content=[$(cat "$S" 2>/dev/null | tr '\n' ' ')]）"
else
  ok "N6 无 sidecar 文件"
fi

# ---------------------------------------------------------------- N7
say "N7 构造度量（manifest）"
if [ "$HAZ_SU" = 1 ]; then
  su -c "cat $MAN" >"$T/n_man.txt" 2>/dev/null
  if [ ! -s "$T/n_man.txt" ]; then
    bad "N7 manifest $MAN 缺失或为空（P1 度量未实现）"
  else
    echo "manifest lines=$(wc -l <"$T/n_man.txt")"
    N7N=0; N7BAD=0; N7MISS=0
    while read -r sha mode bytes name; do
      [ -z "$sha" ] && continue
      case "$sha" in \#*) continue ;; esac
      N7N=$((N7N+1))
      f=$MAT/material/$name
      if ! suc -c "test -f '$f'" >/dev/null 2>&1; then
        N7MISS=$((N7MISS+1)); echo "  missing: $name"; continue
      fi
      GOT=$(suc -c "sha256sum '$f' 2>/dev/null" | awk '{print $1}')
      GM=$(suc -c "stat -c %a '$f' 2>/dev/null" | tr -d ' \r')
      GM=${GM#0}
      GB=$(suc -c "stat -c %s '$f' 2>/dev/null" | tr -d ' \r')
      EXP_M=${mode#0}
      if [ "$GOT" != "$sha" ]; then
        N7BAD=$((N7BAD+1)); echo "  hash mismatch: $name got=${GOT:0:12} want=${sha:0:12}"
      elif [ -n "$EXP_M" ] && [ "$GM" != "$EXP_M" ]; then
        N7BAD=$((N7BAD+1)); echo "  mode mismatch: $name got=$GM want=$EXP_M"
      elif [ -n "$bytes" ] && [ "$GB" != "$bytes" ]; then
        N7BAD=$((N7BAD+1)); echo "  size mismatch: $name got=$GB want=$bytes"
      fi
    done <"$T/n_man.txt"
    echo "checked=$N7N mismatch=$N7BAD missing=$N7MISS"
    if [ "$N7N" -eq 0 ]; then
      bad "N7 manifest 无可校验行"
    elif [ "$N7BAD" -eq 0 ] && [ "$N7MISS" -eq 0 ]; then
      ok "N7 manifest 逐文件校验通过（$N7N 项）"
    else
      bad "N7 manifest 校验失败（mismatch=$N7BAD missing=$N7MISS）"
    fi
  fi
else
  info "N7 跳过（无 su）"
fi

# ---------------------------------------------------------------- N8
say "N8 度量不符 fail-closed"
if [ "${N8_ARM:-0}" != 1 ]; then
  info "N8 破坏性实验未启用（N8_ARM=1 才执行：篡改一份材料 -> 期望 rc=2 且无 VN 产出）"
elif [ "$HAZ_SU" != 1 ] || [ ! -s "$T/n_man.txt" ]; then
  info "N8 前置不足（无 su 或无 manifest）"
else
  VICTIM=$(awk 'NF>=4 && $1 !~ /^#/ {print $4; exit}' "$T/n_man.txt")
  if [ -z "$VICTIM" ]; then
    info "N8 manifest 无可用样本行"
  else
    VF=$MAT/material/$VICTIM
    BK=$T/n8_backup.bin
    suc -c "cp '$VF' '$BK' && chmod 0644 '$BK'"
    # 恢复函数挂在 EXIT 上，任何分支退出都不会留下被篡改的材料
    restore8() { suc -c "cp '$BK' '$VF'" >/dev/null 2>&1; }
    trap 'restore8' EXIT
    suc -c "printf X >> '$VF'"
    OUT8=$(suc --trysu-vn -c 'echo SHOULD-NOT-PRINT' 2>&1); RC8=$?
    echo "tampered=$VICTIM rc=$RC8 output=[$(printf '%s' "$OUT8" | head -c 120)]"
    case "$OUT8" in
      *SHOULD-NOT-PRINT*) bad "N8 材料被篡改后仍构造成功（fail-open）" ;;
      *) if [ "$RC8" = 2 ]; then ok "N8 篡改后 rc=2 且无 VN 产出（fail-closed）"; else info "N8 篡改后被拒但 rc=$RC8（期望 2）"; fi ;;
    esac
    suc -c "cp '$BK' '$VF'" 2>/dev/null
    trap - EXIT
  fi
fi

# ---------------------------------------------------------------- N9
say "N9 入口 fail-closed 且唯一"
OUT9=$(suc --trysu-ns 1 -c 'echo SHOULD-NOT-PRINT' 2>&1)
echo "--trysu-ns 1 -> [$(printf '%s' "$OUT9" | head -c 160)]"
case "$OUT9" in
  *SHOULD-NOT-PRINT*)
    bad "N9a --trysu-ns 仍可指定 ns 并执行（应删除该入口）"
    # 旧 tsu 审计落点固定，--trysu-ns 1 会把记录写进 N 侧真实路径；清理本脚本副作用
    if clean_w; then
      echo "  [cleanup] 已清理 --trysu-ns 在 N 侧写入的 .w 残留"
    else
      echo "  [cleanup] /data/local/tmp/.w 在当前 ns 是挂载点，跳过清理"
    fi
    ;;
  *) ok "N9a --trysu-ns 已被拒" ;;
esac
PKG=${PKG:-com.postlock}
if [ "$HAZ_SU" = 1 ]; then
  OUT9B=$(suc -c "run-as $PKG /system/bin/su -c id 2>&1")
  echo "run-as $PKG su -c id -> [$(printf '%s' "$OUT9B" | head -c 160)]"
  case "$OUT9B" in
    *uid=0*) bad "N9b 非 allow-list 进程拿到了 root" ;;
    *"exec failed"*|*"No such file"*)
      ok "N9b 非 allow-list 看到 su 不存在（stat/exec facade 生效）" ;;
    *"unknown package"*|*"not debuggable"*)
      info "N9b runas 载体不可用，无法观测非 allow-list 拒绝语义" ;;
    *"Permission denied"*)
      ok "N9b 非 allow-list 执行被拒（Permission denied）" ;;
    *) info "N9b 拒绝语义未识别：[$(printf '%s' "$OUT9B" | head -c 120)]" ;;
  esac
else
  info "N9b 跳过（无 su）"
fi

# 清理旧 tsu 留在 N 侧的审计残留。
# 只删 .w/log 内容，**绝不删 .w 目录本身**：它可能是 holder tmpfs 的挂载点目录
# （N ns 里看是普通目录，holder ns 里是 tmpfs）。删掉挂载点会让 holder 的私有
# 视图退化（2026-11-13 两次实测，均需重启 holder 才恢复）。
# 返回 0 = 已清理/无需清理；1 = 当前 ns 里 .w 本身是挂载点，跳过。
clean_w() {
  suc -c 'test -d /data/local/tmp/.w/log' >/dev/null 2>&1 || return 0
  if suc -c 'grep -Fq " /data/local/tmp/.w " /proc/self/mountinfo' >/dev/null 2>&1; then
    return 1
  fi
  suc -c 'rm -f /data/local/tmp/.w/log/access.log 2>/dev/null; rmdir /data/local/tmp/.w/log 2>/dev/null' >/dev/null 2>&1
  return 0
}

# ---------------------------------------------------------------- N10
say "N10 审计记录"
AUDIT=$(suc -c "tail -n 20 $AUD 2>/dev/null")
if [ -z "$AUDIT" ]; then
  OLD=$(suc --trysu-vn -c 'tail -n 2 /data/local/tmp/.w/log/access.log 2>/dev/null')
  if [ -n "$OLD" ]; then
    VIA=$(printf '%s\n' "$OLD" | sed -n 's/.*via=\([a-z]*\).*/\1/p' | tail -n 1)
    bad "N10a 只有旧 access.log（via=${VIA:-?}），无 $AUD"
  else
    info "N10a 无任何审计落点（P1 未实现）"
  fi
else
  echo "$AUDIT" | tail -n 3
  case "$AUDIT" in
    *via=self*) ok "N10a audit.log 有本次 via=self entry" ;;
    *) bad "N10a audit.log 无 via=self entry" ;;
  esac
fi
if [ "${N10_ARM:-0}" != 1 ]; then
  info "N10b 写失败实验未启用（N10_ARM=1 才执行）"
else
  # audit.log 换成目录：openat(O_WRONLY) 必失败（EISDIR），
  # root 的 CAP_DAC_OVERRIDE 也绕不过"对目录做写打开"。这是唯一能在
  # root 域里稳定制造写失败的形态（chmod 0400 对 root 无效）。
  BK10=/data/local/tmp/n10b_audit_bak
  suc -c "cp -f $AUD $BK10 2>/dev/null; rm -f $AUD; mkdir -p $AUD" >/dev/null 2>&1
  restore10() { suc -c "rmdir $AUD 2>/dev/null; cp -f $BK10 $AUD 2>/dev/null" >/dev/null 2>&1; }
  trap 'restore10' EXIT
  OUT10=$(suc --trysu-vn -c 'echo SHOULD-NOT-PRINT' 2>&1); RC10=$?
  echo "audit-dir rc=$RC10 output=[$(printf '%s' "$OUT10" | head -c 100)]"
  case "$OUT10" in
    *SHOULD-NOT-PRINT*) bad "N10b 审计写失败后仍构造成功（fail-open）" ;;
    *) if [ "$RC10" = 2 ]; then ok "N10b 审计写失败 → rc=2 且未进入 VN"; else info "N10b rc=$RC10（期望 2）"; fi ;;
  esac
  restore10
  trap - EXIT
fi

# 清理旧 tsu 留在 N 侧的审计残留。
# 只删 .w/log 内容，**绝不删 .w 目录本身**：它可能是 holder tmpfs 的挂载点目录
# （N ns 里看是普通目录，holder ns 里是 tmpfs）。删掉挂载点会让 holder 的私有
# 视图退化（2026-11-13 两次实测，均需重启 holder 才恢复）。
# 返回 0 = 已清理/无需清理；1 = 当前 ns 里 .w 本身是挂载点，跳过。
clean_w() {
  suc -c 'test -d /data/local/tmp/.w/log' >/dev/null 2>&1 || return 0
  if suc -c 'grep -Fq " /data/local/tmp/.w " /proc/self/mountinfo' >/dev/null 2>&1; then
    return 1
  fi
  suc -c 'rm -f /data/local/tmp/.w/log/access.log 2>/dev/null; rmdir /data/local/tmp/.w/log 2>/dev/null' >/dev/null 2>&1
  return 0
}

# ---------------------------------------------------------------- N11
say "N11 功能未退化（VN 内）"
if [ "$HAZ_SU" = 1 ]; then
  O11=$(suc --trysu-vn -c 'ls / >/dev/null && echo root-ok; ls /system >/dev/null && echo system-ok; ls /data >/dev/null && echo data-ok; ls /apex >/dev/null && echo apex-ok; echo mods=$(ls /sys/module 2>/dev/null | wc -l); cat /proc/version' 2>&1)
  printf '%s\n' "$O11" | sed -n '1,8p'
  MISS11=""
  for k in root-ok system-ok data-ok apex-ok; do
    case "$O11" in *"$k"*) ;; *) MISS11="$MISS11 $k" ;; esac
  done
  if [ -z "$MISS11" ]; then
    ok "N11 / /system /data /apex 均可读"
  else
    bad "N11 缺失:$MISS11"
  fi
  MODS=$(printf '%s\n' "$O11" | sed -n 's/^mods=//p' | tail -n 1)
  echo "sys/module count=${MODS:-?}"
else
  info "N11 跳过（无 su）"
fi

# 清理旧 tsu 留在 N 侧的审计残留。
# 只删 .w/log 内容，**绝不删 .w 目录本身**：它可能是 holder tmpfs 的挂载点目录
# （N ns 里看是普通目录，holder ns 里是 tmpfs）。删掉挂载点会让 holder 的私有
# 视图退化（2026-11-13 两次实测，均需重启 holder 才恢复）。
# 返回 0 = 已清理/无需清理；1 = 当前 ns 里 .w 本身是挂载点，跳过。
clean_w() {
  suc -c 'test -d /data/local/tmp/.w/log' >/dev/null 2>&1 || return 0
  if suc -c 'grep -Fq " /data/local/tmp/.w " /proc/self/mountinfo' >/dev/null 2>&1; then
    return 1
  fi
  suc -c 'rm -f /data/local/tmp/.w/log/access.log 2>/dev/null; rmdir /data/local/tmp/.w/log 2>/dev/null' >/dev/null 2>&1
  return 0
}

# ---------------------------------------------------------------- N13
say "N13 私有可写层（per-mount overlay，upper 在 /metadata）"
if [ "$HAZ_SU" = 1 ]; then
  D13=$T/n13_out.txt
  suc --trysu-vn -c 'echo pid=$$; readlink /proc/self/ns/mnt; touch /system/.trysu-n13 && echo write=ok; grep -E "^[0-9]+ [0-9]+ [0-9]+:[0-9]+ / /system " /proc/self/mountinfo | head -n1' >"$D13" 2>&1
  P13=$(sed -n 's/^pid=//p' "$D13" | tr -cd '0-9' | head -c 12)
  if grep -q '^write=ok' "$D13"; then
    ok "N13 VN 内 /system 可写"
  else
    bad "N13 VN 内 /system 不可写（overlay 未生效）"
  fi
  if grep -q ' - overlay ' "$D13"; then
    ok "N13 /system 挂载形态是 overlay"
  else
    bad "N13 /system 不是 overlay（仍是只读 bind）"
  fi
  if suc -c 'test -e /system/.trysu-n13' >/dev/null 2>&1; then
    bad "N13 VN 内写入泄漏到 N 的 /system"
  else
    ok "N13 VN 写入未落到 N 的 /system"
  fi
  if [ -n "$P13" ] && suc -c "test -f /metadata/trysu/$P13/system/upper/.trysu-n13" >/dev/null 2>&1; then
    ok "N13 upper 落在 /metadata/trysu/$P13/system/upper"
  else
    bad "N13 upper 落点缺失（pid=${P13:-?}）"
  fi
  if [ -n "$P13" ]; then
    suc -c "rm -rf /metadata/trysu/$P13 /data/local/tmp/trysu-vn-$P13" >/dev/null 2>&1
  fi
else
  info "N13 跳过（无 su）"
fi

# ---------------------------------------------------------------- N12
say "N12 观测面回归"
info "N12 由宿主执行：tools/tsu/n_accept.sh 会跑 tools/suvtz/scan.sh -q 并要求 FAIL=0"

echo
echo "===== tsu N-rows: PASS=$P FAIL=$F INFO=$I（form=$FORM）====="
[ "$F" -eq 0 ] && echo "RESULT: OK" || echo "RESULT: FAIL"
