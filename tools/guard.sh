#!/bin/bash
# 考试一息屏守护: 用户亮屏时不碰设备; 息屏(闲置)才起链。
# 归因(2026-10-21, 11次重启): 活跃期外人 fork 必抢满 kill 空窗
# (post-kill rcu wait w=5 tsc=非0 inuse=34 2s 恒满), 且风暴期暴毙/重启率
# 高。息屏期安静 -> 满页率与暴毙率同降。
# 用法: tools/guard.sh [max_rounds]   (后台跑, SUCCESS 写 /tmp/opencode/GUARD_SUCCESS)
ADB="${ADB:-$(command -v adb)}"
S="${GUARD_SERIAL:-192.168.8.10:5555}"
MAX="${1:-20}"
D=/data/local/tmp/ksu_boot
OUT=/tmp/opencode/guard_rounds
mkdir -p "$OUT"
[ -f /tmp/opencode/GUARD_SUCCESS ] && rm -f /tmp/opencode/GUARD_SUCCESS

started=0   # 起链轮计数(亮屏 idle 不消耗配额)

env_chain="LD_PRELOAD=$D/preload.so KS_LOG_SYNC=1 KS_PSELECT_BSS_LOCK=1 \
KS_CFGFS_LOG=1 KS_PAYLOAD_SCAN=1 KSNITCH_VERBOSE=1 \
KS_RECLAIM_DETERMINISTIC=1 KS_PSELECT_FOPS_VOFF=1 \
KSUD_DST=$D/ksud KSUD_NO_PARENT_INSTALL=1 SU_INSTALL=0 \
KS_COLDSTART=$D/restore.sh KS_FINITMOD=$D/finitmod KS_KO=$D/kernelsu.ko \
KS_PIPE_SLABS=15 KS_PIPE_MAX_ATTEMPTS=3"

dev_ok() {
  timeout 8 "$ADB" connect "$S" >/dev/null 2>&1
  [ "$(timeout 10 "$ADB" -s "$S" shell 'echo x' 2>/dev/null | tr -d '\r')" = "x" ]
}

round=0
while true; do
  dev_ok || { echo "[g$round] device offline, retry 30s"; sleep 30; continue; }
  boot=$("$ADB" -s "$S" shell 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\r')

  # 有链在跑 -> 盯到结束或换 boot
  run=$("$ADB" -s "$S" shell 'pgrep -f "[e]cho CHAIN_EXIT_DONE"' 2>/dev/null | tr -d '\r' | head -1)
  if [ -n "$run" ]; then
    echo "[g$round] chain pid=$run running; polling"
    for i in $(seq 1 60); do
      sleep 10
      dev_ok || continue
      b2=$("$ADB" -s "$S" shell 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\r')
      if [ "$b2" != "$boot" ]; then
        echo "[g$round] REBOOT detected ($boot -> $b2)"
        "$ADB" -s "$S" shell "[ -s /data/local/tmp/plock_chain.log ] && cp /data/local/tmp/plock_chain.log /data/local/tmp/plock_chain.reboot_$round.log" 2>/dev/null
        continue 2
      fi
      res=$("$ADB" -s "$S" shell 'grep -E "root=1 kaslr=1|uid=2000->0|POSTLOCK-RESTORE-OK" /data/local/tmp/plock_chain.log 2>/dev/null | tail -2' 2>/dev/null)
      if echo "$res" | grep -q "root=1"; then
        echo "[g$round] ROOT=1 HIT: $res"
        # 等 DONE/RESTORE 再判成功
        sleep 40
        fin=$("$ADB" -s "$S" shell 'grep -cE "POSTLOCK-RESTORE-OK" /data/local/tmp/plock_chain.log 2>/dev/null' | tr -d '\r')
        "$ADB" -s "$S" shell 'cp /data/local/tmp/plock_chain.log /data/local/tmp/plock_chain.SUCCESS.log' 2>/dev/null
        cp_out="$OUT/round$round.success.log"
        "$ADB" -s "$S" pull /data/local/tmp/plock_chain.SUCCESS.log "$cp_out" >/dev/null 2>&1
        echo "[g$round] restore_ok=$fin" | tee /tmp/opencode/GUARD_SUCCESS
        exit 0
      fi
      alive=$("$ADB" -s "$S" shell 'pgrep -f "[e]cho CHAIN_EXIT_DONE"' 2>/dev/null | tr -d '\r' | head -1)
      [ -z "$alive" ] && { echo "[g$round] chain exited (root=0)"; break; }
      # 亮屏 -> 本链跑完即可, 不再干预
    done
    # 归档败轮
    "$ADB" -s "$S" shell 'mv -f /data/local/tmp/plock_chain.log /data/local/tmp/plock_chain.guard_arch.log' 2>/dev/null
    "$ADB" -s "$S" pull /data/local/tmp/plock_chain.guard_arch.log "$OUT/round$round.log" >/dev/null 2>&1
    sleep 15
    continue
  fi

  # 无链 -> 息屏起; 亮屏但完全静止(1min load<0.5)视为等效闲置
  wake=$("$ADB" -s "$S" shell 'dumpsys power 2>/dev/null | grep -m1 mWakefulness=' 2>/dev/null | tr -d '\r')
  load=$("$ADB" -s "$S" shell 'cut -d" " -f1 /proc/loadavg' 2>/dev/null | tr -d '\r')
  case "$wake" in
    *Asleep*) ;;
    *)
      if awk -v l="$load" 'BEGIN{exit !(l<0.5)}' 2>/dev/null; then
        echo "[g$round] awake but idle (load=$load); proceed"
      else
        echo "[g$round] screen awake ($wake) load=$load; idle 30s"
        sleep 30
        continue
      fi
      ;;
  esac
  round=$((round + 1))
  if [ "$round" -gt "$MAX" ]; then
    echo "[guard] max chain rounds ($MAX) done"
    exit 1
  fi
  echo "[g$round] asleep load=$load boot=${boot:0:8}; starting chain"
  # 归档旧日志
  "$ADB" -s "$S" shell 'mv -f /data/local/tmp/plock_chain.log /data/local/tmp/plock_chain.guard_arch.log 2>/dev/null' 2>/dev/null
  "$ADB" -s "$S" shell "setsid nohup env $env_chain /system/bin/sh -c 'echo CHAIN_EXIT_DONE' > /data/local/tmp/plock_chain.log 2>&1 < /dev/null &" 2>/dev/null
  sleep 8
  "$ADB" -s "$S" shell 'head -1 /data/local/tmp/plock_chain.log' 2>/dev/null
done
echo "[guard] max rounds done"
exit 1
