#!/system/bin/sh
# shell 域全链唯一入口（device-side）。
#
# 设计约束（2026-11-14 用户裁决）：
#   主仓 tools/postlock.sh 与 PostLock app 的「执行恢复链」按钮必须是**同一个入口**，
#   不允许两边各写一份 trigger.sh 生成逻辑。
#
# 两类调用方只做三件事：
#   1) 把 stage 物料放到 $STAGE（preload.so / ksud / finitmod / kernelsu.ko / restore.sh …）
#   2) 写 $STAGE/chain.env（本次可选覆盖；不存在就只用基线）
#   3) 执行 `sh $STAGE/chain_entry.sh start`，等 stdout 出现 DETACHED
#
# 清理、日志、detach、LD_PRELOAD/KS_COLDSTART 载体全部在本文件里。
#
# 版本：任何语义变更都要 +1；两侧调用方都会断言这个值，避免一边新一边旧。

CHAIN_ENTRY_VERSION=1

STAGE=${STAGE:-/data/local/tmp/ksu_boot}
CHAIN_LOG=${CHAIN_LOG:-/data/local/tmp/postlock_chain.log}
RESTORE_LOG=${RESTORE_LOG:-/data/local/tmp/postlock_restore.log}

# 可选覆盖（调用方写；只认下面用到的变量名）
if [ -f "$STAGE/chain.env" ]; then
  . "$STAGE/chain.env"
fi

# 基线环境：与 2026-10-19 run_fops 实测通过的那份保持一致。
build_env() {
  E="KS_LOG_SYNC=1 KS_PSELECT_BSS_LOCK=1 KS_CFGFS_LOG=1 KS_PAYLOAD_SCAN=1 KSNITCH_VERBOSE=1"
  E="$E KS_RECLAIM_DETERMINISTIC=1 KS_PSELECT_FOPS_VOFF=1"
  E="$E KSUD_DST=$STAGE/ksud KSUD_NO_PARENT_INSTALL=1 SU_INSTALL=0"
  E="$E KS_COLDSTART=$STAGE/restore.sh KS_FINITMOD=$STAGE/finitmod KS_KO=$STAGE/kernelsu.ko"
  E="$E KS_PIPE_SLABS=15 KS_PAYLOAD_BASE_FILE=$STAGE/skbdelta"
  if [ -n "${KS_RUN_KSUD_EVENTS:-}" ]; then
    E="$E KS_RUN_KSUD_EVENTS=$KS_RUN_KSUD_EVENTS"
  fi
  if [ -n "${KS_BOUNCE_ZYGOTE:-}" ]; then
    E="$E KS_BOUNCE_ZYGOTE=$KS_BOUNCE_ZYGOTE"
  fi
  if [ -n "${KS_TRACEFS_SUDO:-}" ]; then
    E="$E KS_TRACEFS_SUDO=$KS_TRACEFS_SUDO"
  fi
  if [ -n "${KS_LAYOUT_PVO:-}" ]; then
    E="$E KS_LAYOUT_PVO=$KS_LAYOUT_PVO"
  fi
  if [ -n "${KS_LAYOUT_VM:-}" ]; then
    E="$E KS_LAYOUT_VM=$KS_LAYOUT_VM"
  fi
}

# ---- _exec：detach 之后的真正载体 ------------------------------------------
# 只有它会把 preload 塞进 /system/bin/sh；start 模式不执行任何提权代码。
if [ "$1" = "_exec" ]; then
  build_env
  exec env LD_PRELOAD="$STAGE/preload.so" $E /system/bin/sh -c 'echo CHAIN_EXIT_DONE'
fi

if [ "$1" != "start" ]; then
  echo "usage: $0 start|_exec" >&2
  exit 2
fi

# ---- start：清理 → 建日志 → detached 起链 ---------------------------------
# 必须从**文件** detach：同步 adb shell 会在 host 超时时半途断掉，留下 dangling
# fops（下一轮任何 misc open 直接 panic）。inline `setsid nohup &` 也实测在
# adbd 会话销毁时丢作业，所以固定为「写文件 → nohup 该文件」。
rm -f "$STAGE/skbdelta" "$CHAIN_LOG" "$RESTORE_LOG"
: > "$CHAIN_LOG" || { echo "CHAIN_LOG_UNWRITABLE"; exit 3; }
chmod "${SUVTZ_CHAIN_LOG_MODE:-0600}" "$CHAIN_LOG" 2>/dev/null

# `{ ...; echo DETACHED; }` 让 `&` 只绑定 nohup；裸的 `... && nohup ... &`
# 会把整个 && 链后台化，DETACHED 会在 trigger 写之前就回显（两侧都踩过）。
{ nohup sh "$0" _exec >> "$CHAIN_LOG" 2>&1 < /dev/null & echo DETACHED; } || echo DETACH_FAIL
