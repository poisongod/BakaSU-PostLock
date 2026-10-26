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
# unified log line prefix, same shape as chain/restore/receiver logs
BOOT8='????????'
step() { echo; echo "[$BOOT8 $(date +%T)] ==> $*"; }
info() { echo "[$BOOT8 $(date +%T)] $*"; }

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
BOOT8=$(ab shell cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r' | cut -c1-8)
[ -n "$BOOT8" ] || BOOT8='????????'

# --- host artifacts ----------------------------------------------------
step "check host artifacts"
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
if [ ! -f "$PRELOAD_SRC" ]; then
  (cd "$REPO" && make PROJECT=pfum10c48 -j"$(nproc)")
fi
[ -f "$PRELOAD_SRC" ] || die "make failed"

# manager appid (for the ROOT_SCRIPT below; resolve from package manager)
MUID=$(ab shell "pm list packages -U $APP" | tr -d '\r' | grep -oE 'uid:[0-9]+' | head -n1 | cut -d: -f2 || true)
[ -n "$MUID" ] || die "cannot resolve uid of $APP (installed?)"

# --- stage payloads (shell-writable, NO root needed) --------------------
step "stage payloads at $STAGE"
ab shell "mkdir -p $STAGE" || die "cannot create $STAGE (is /data/local/tmp gone?)"
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
  ab keygen "$ADBKEY_DIR/postlock_adbkey" >/dev/null
  sed -i "s/ .*/ postlock_bootstrap/" "$ADBKEY_DIR/postlock_adbkey.pub"
  echo "generated fresh adb keypair at $ADBKEY_DIR (APP APK MUST RE-EMBED IT)"
fi
ab push "$PP_ENTRY" "$STAGE/pp_adb_tcp.bin" >/dev/null
ab push "$ADBKEY_DIR/postlock_adbkey.pub" "$STAGE/postlock_adbkey.pub" >/dev/null
# +x matters: the root child's insmod helper gates on access(fm, X_OK);
# adb push lands 666.
ab shell "chmod 755 $STAGE/finitmod" >/dev/null 2>&1 || true

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
BOOT8=\$(cut -c1-8 /proc/sys/kernel/random/boot_id 2>/dev/null || echo "????????")
# fix76: log to fd2 -- fd1 (the exec redirect) is fully buffered and a
# non-gentle exit drops the tail (redo34's log ended mid "probing" with no
# WARN/OK line ever reaching disk); stderr is unbuffered, lands instantly.
# fix78: date guarded -- in redo39 the original child died in the flip
# window with 202x "Segmentation fault" and zero log lines (its log()'s
# date was the only unprotected exec left after the flip); a failing date
# must degrade to '???:???' instead of taking the whole log call down.
log() { printf "[%s %s] %s\\n" "\$BOOT8" "\$(date +%H:%M:%S 2>/dev/null || echo '???:???')" "\$*" >&2; }
# --- fix77 (redo35 root cause, measured): the instant 'setenforce 1'
# flips, kernel:s0 loses exec of every /system/bin/* -- log()'s date and
# printf both died with "inaccessible or not found" (dontaudit-silent, zero
# avc), the PROBE assignment swallowed its own exec failure via 2>&1, the
# case silently took *) and set -e killed the script before any WARN/OK
# line; the host then timed out its 480s marker.  The flip itself stays
# with kernel:s0 (only domain with setenforce permission -- measured:
# shell:s0 = Permission denied), but every post-flip step runs in this
# shell:s0 child, launched while still Permissive.  shell:s0 keeps exec
# permission under enforcing (measured: log() works there).  On probe
# failure the child signals USR1; the parent's trap rewrites selinuxfs with
# mksh builtin 'print' (no exec possible after the flip) so a failed round
# never strands the device.  Branch BEFORE 'set -e'.
if [ "\${1:-}" = "--strict-child" ]; then
  # fix79: the runcon-forked child (redo42: 101 Segmentation faults, one per
  # forked external command) inherited the restore parent's environment --
  # adb-shell reruns of the same script produced ZERO segfaults, so drop any
  # residual LD_PRELOAD (the chain's preload.so constructor would otherwise
  # rerun inside every forked sleep/probe) and print it as evidence first.
  print -r -- "strict-child env LD_PRELOAD=[\$LD_PRELOAD]" >&2
  unset LD_PRELOAD
  log "strict-child: waiting for kernel:s0 to flip enforcing"
  ENF=0
  i=0
  while [ \$i -lt 100 ]; do
    # fix78: builtin read instead of \$(cat ...) -- zero forks in the flip
    # window (redo39's original child burned 202 segfaults here; each loop
    # iteration forked cat+sleep, and a crashing cat left ENF=0 forever).
    # fix79: read on selinuxfs returns rc=1 even on SUCCESS (the enforce
    # file has no trailing newline -> read reports EOF), so the old
    # '|| ENF=0' fallback overwrote the value it had just read ("1" -> 0,
    # measured: read=[1] rc=1).  ENF is pre-seeded above; '|| :' discards
    # the status without touching the variable.
    ENF=0
    read ENF < /sys/fs/selinux/enforce 2>/dev/null || :
    [ "\$ENF" = "1" ] && break
    [ \$((i % 10)) -eq 0 ] && print -r -- "strict-child poll i=\$i en=\$ENF" >&2
    sleep 0.1 || true
    i=\$((i + 1))
  done
  if [ "\$ENF" != "1" ]; then
    log "WARN-selinux-strict: flip never observed (enforce=\$ENF after 10s)"
    log POSTLOCK-RESTORE-OK
    exit 0
  fi
  log "strict-child: probing su under enforcing"
  PROBE=\$(timeout 5 /product/bin/su -c id 2>&1) || true
  log "strict-child: probe done"
  case "\$PROBE" in
    *uid=0*)
      log "SELINUX-STRICT-OK enforce=\$ENF probe=\$PROBE"
      log POSTLOCK-RESTORE-OK ;;
    *)
      log "WARN-selinux-strict: shell channel blocked under enforcing: \$PROBE"
      log "diag labels: \$(ls -Z /product/bin/su $TMP/ksud 2>&1)"
      log "diag temp-ksud control: \$(echo id | timeout 5 $TMP/ksud debug su 2>&1 | head -2)"
      log "diag wrapper: \$(timeout 5 /product/bin/su -c id 2>&1 | head -3)"
      log "diag avc: \$(logcat -d 2>/dev/null | grep 'avc:' | tail -4)"
      kill -USR1 \$PPID 2>/dev/null || true
      j=0
      while [ \$j -lt 50 ]; do
        RV=1
        # fix79: same read-status trap as above -- never overwrite the value.
        read RV < /sys/fs/selinux/enforce 2>/dev/null || :
        [ "\$RV" = "0" ] && break
        sleep 0.1 || true
        j=\$((j + 1))
      done
      RVX=?
      read RVX < /sys/fs/selinux/enforce 2>/dev/null || :
      log "strict: revert observed enforce=\$RVX"
      log POSTLOCK-RESTORE-OK ;;
  esac
  exit 0
fi
log "== restore start \$(date '+%F %T') pid=\$\$ uid=\$(id -u)"
id
ls -ld /data /data/local /data/local/temp 2>&1 || true
getenforce 2>/dev/null || true
set -e
# Wait for the chain itself to finish its exit tail (neutralize/pipe
# clear) before anything below restarts processes: the zygote bounce
# kills every app-uid process, and in exam-2 mode the chain IS an
# app-uid process -- killing it mid-neutralize leaves a dangling fake
# fops table (third-party misc open -> panic).  \$PPID snapshot is the
# chain pid (coldstart fork); 120s cap for manual reruns where the
# parent never goes away.
CHAIN_PID=\$PPID
i=0
if [ "\$CHAIN_PID" -gt 1 ] 2>/dev/null; then
  while kill -0 \$CHAIN_PID 2>/dev/null && [ \$i -lt 60 ]; do sleep 2; i=\$((i+1)); done
  log "chain pid \$CHAIN_PID exit-wait done (\$((i*2))s)"
else
  log "chain already exited (reparented to init) - skip exit-wait"
fi
mkdir -p $TMP
chcon u:object_r:shell_data_file:s0 $TMP
chmod 777 $TMP
echo 262144 > /proc/sys/fs/pipe-user-pages-soft
# roll back the OMK injector config BEFORE ksud services (which triggers the
# OMK injection that reads it): the uid:1000 scoop variant caused a
# kernel_panic on 2026-10-24 (twice); .bak is the original stable config.
[ -f /data/adb/modules/oh_my_keymint/injector.toml.bak ] && cp /data/adb/modules/oh_my_keymint/injector.toml.bak /data/adb/modules/oh_my_keymint/injector.toml && log OMK-ROLLED-BACK || log WARN-no-omk-bak
# rm-before-cp keeps reruns safe: unlink-then-copy never hits ETXTBSY on
# a binary some previous round left mapped/executing.
for f in kernelsu.ko finitmod ocsk.ko preload.so; do
  rm -f $TMP/\$f
  cp $STAGE/\$f $TMP/\$f
done
chmod 755 $TMP/kernelsu.ko $TMP/finitmod $TMP/ocsk.ko $TMP/preload.so
if grep -q ^kernelsu /proc/modules; then log driver-already-loaded; else $TMP/finitmod $TMP/kernelsu.ko 0 || log WARN-finitmod-failed; fi
# ocsk: silence the OPPO oplus_root_check_succ kill path BEFORE the app
# restarts below -- without it libksud.so setuid(0) trips the detector
# and force_sig kills the app (round 60 verified 61/61 kills intercepted).
# WARN-only: sig_enforce is 0 on this boot because the chain just ran.
if grep -q ^ocsk /proc/modules; then log ocsk-already-loaded; else $TMP/finitmod $TMP/ocsk.ko 0 arm=1 || log WARN-ocsk-finitmod-failed; fi
# register the manager appid so zygote setresuid installs the
# [ksu_driver] fd for the manager (CONFIG_KSU_DEBUG param; must
# precede the app start)
if [ -w /sys/module/kernelsu/parameters/ksu_debug_manager_appid ]; then
  echo $MUID > /sys/module/kernelsu/parameters/ksu_debug_manager_appid
fi
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
  cat $STAGE/postlock_adbkey.pub >> /data/misc/adb/adb_keys || log WARN-adb-keys-append
  chmod 640 /data/misc/adb/adb_keys || true
  chown root:shell /data/misc/adb/adb_keys || true
fi
# persist.adb.tcp.port=5555 -> persistent_properties (raw protobuf entry,
# 30 bytes, generated by build/work/pp_adb_tcp.bin): setprop on this name
# is SELinux-denied (default_prop) even as root, but init applies the
# persisted value itself at boot and adbd then listens on [::]:5555.
# Takes effect from the NEXT reboot; harmless when already present.
if ! grep -qF persist.adb.tcp.port /data/property/persistent_properties 2>/dev/null; then
  cat $STAGE/pp_adb_tcp.bin >> /data/property/persistent_properties || log WARN-pp-append
fi
# phantom-process killer off (persist): AMS culled the app-uid chain's
# >32 clone children as "Trimming phantom processes" (rounds 1/2/4 silent
# kills).  It is a framework quota reaper, not a security boundary; the
# setting survives reboots but not a factory reset.  Written via settings
# (root here; untrusted_app cannot write global settings).
settings put global settings_enable_monitor_phantom_procs false 2>/dev/null || log WARN-phantom-settings
# fix61 (2026-10-24): the ksud events run BEFORE the overlay build below,
# not after.  Measured on-device: ksud post-fs-data umounts our freshly
# mounted /product/bin overlay (the wrapper+ksud upper vanishes, shell
# 'ls /product/bin/su' falls back to the stock ro partition and gets
# Permission denied) -- so events-after-overlay guarantees a broken su
# even when nothing panics.  Running events first means their mount
# churn finishes before our overlay lands.  fix59's gate stays (events x
# post-chain window is still a suspect for the 12:21 panic): default OFF,
# KS_RUN_KSUD_EVENTS=1 to enable.  All three events tested safe on a
# healthy system (14:26-14:39, OMK injector came up clean).
if [ "\${KS_RUN_KSUD_EVENTS:-0}" = "1" ] && [ -x /data/adb/ksud ]; then
  timeout 60 /data/adb/ksud post-fs-data > /dev/null 2>&1 || log WARN-ksud-postfs
  timeout 90 /data/adb/ksud services > /dev/null 2>&1 || log WARN-ksud-services
  timeout 30 /data/adb/ksud boot-completed > /dev/null 2>&1 || log WARN-ksud-bootcomp
fi
if [ ! -x /product/bin/su ]; then
  mkdir -p $TMP/ovl/lower $TMP/ovl/tmp
  mountpoint -q $TMP/ovl/lower || mount --bind /product/bin $TMP/ovl/lower
  # tmpfs sb context (2026-10-25 strict-mode root fix): upper inodes inherit
  # the tmpfs sb label, so without context= su/ksud land as shell_data_file
  # and shell loses exec of them the moment enforcing flips (measured:
  # DAC 777 passes, MAC denies, avc dontaudit-silent).  Fallback keeps the
  # old behaviour if this kernel rejects context= on tmpfs.
  mountpoint -q $TMP/ovl/tmp || mount -t tmpfs -o size=16m,context=u:object_r:system_file:s0 tmpfs $TMP/ovl/tmp \
    || mount -t tmpfs -o size=16m tmpfs $TMP/ovl/tmp || log WARN-tmpfs-mount
  mkdir -p $TMP/ovl/tmp/upper $TMP/ovl/tmp/work
  rm -f $TMP/ovl/tmp/upper/su $TMP/ovl/tmp/upper/ksud
  # su = compatibility shim, NOT the custom daemon client anymore: on this
  # device /system/bin/su is a kernel-forged KernelPatch fake whose real
  # file ENOENTs on exec (root-context 'su -c' fails outright), which
  # broke module WebUIs (YH_YC panel's "状态读取失败") that hardcode
  # 'su -c'.  Root callers are already root: pass through to sh -c;
  # non-root falls back to the real driver's ksud (cp'd into the overlay
  # because /data/adb is 0700 and shell cannot exec it there -- fix57:
  # the old fallback exec'd /system/bin/su which ENOENTs post-relock,
  # so shell-uid 'su -c' failed verify every time).
  cat > $TMP/ovl/tmp/upper/su <<'SUW'
#!/system/bin/sh
if [ "\$(id -u)" = 0 ]; then
  if [ "\$1" = "-c" ]; then
    shift
    exec /system/bin/sh -c "\$*"
  fi
  exec /system/bin/sh
fi
# fix60: ksud debug su is a pipe-fed root shell (no -c flag: passing -c
# made clap fail with "unexpected argument '-c'").  Feed the command on
# stdin; EOF makes the su shell exit, and its rc carries the command's.
# fix76 (redo34): ksud lives in $TMP (shell_data_file), NOT
# /product/bin (system_file).  shell-domain exec of system_file is
# dontaudit-silent denied: mmap(PROT_EXEC) fails inside the linker and
# surfaces as "can't enable GNU RELRO protection ... Permission denied"
# with ZERO avc records; the identical binary runs fine from $TMP
# (measured uid=0 root shell under enforcing 2026-10-25).
if [ "\$1" = "-c" ]; then
  shift
  printf '%s\n' "\$*" | $TMP/ksud debug su
  exit \$?
fi
exec $TMP/ksud debug su "\$@"
SUW
  chmod 755 $TMP/ovl/tmp/upper/su
  if [ -x /data/adb/ksud ]; then
    cp /data/adb/ksud $TMP/ovl/tmp/upper/ksud || log WARN-ksud-cp
    chmod 755 $TMP/ovl/tmp/upper/ksud 2>/dev/null || true
  fi
  mount -t overlay overlay -o lowerdir=$TMP/ovl/lower,upperdir=$TMP/ovl/tmp/upper,workdir=$TMP/ovl/tmp/work,context=u:object_r:system_file:s0 /product/bin || log WARN-overlay-mount
  # belt+braces: force the visible labels too (no-op when tmpfs sb context
  # already covers them; ENOTSUP on xattr-less tmpfs is tolerated)
  chcon u:object_r:system_file:s0 /product/bin/su /product/bin/ksud 2>/dev/null || true
else
  log "overlay wrapper already present"
fi
# fix76: the wrapper execs ksud from $TMP, not /product/bin -- see the
# wrapper comment (shell cannot exec system_file, dontaudit-silent).
# Idempotent: runs even when the overlay branch above was skipped, so a
# stale overlay from a previous boot still gets its wrapper fed.
if [ -x /data/adb/ksud ]; then
  cp -f /data/adb/ksud $TMP/ksud 2>/dev/null || log WARN-ksud-temp-cp
  chmod 755 $TMP/ksud 2>/dev/null || true
  chcon u:object_r:shell_data_file:s0 $TMP/ksud 2>/dev/null || true
fi
# --- late-load module stage (2026-10-24) -------------------------------
# The driver insmods long after boot, so ksud's boot events never fire
# and zygote had already started before Zygisk Next could inject: every
# zygisk module showed "无法正常工作" until these three events + a
# zygote bounce ran.  ctl.* setprop is rejected by init's property
# service even as root, so bounce via signal; init respawns zygote and
# the fresh one picks up the injection (verified: module.prop reports
# [✓ zygote, ✓ zygote_secondary]).  The bounce restarts the framework
# (~40s) and re-broadcasts BOOT_COMPLETED -- the ran_boot guard makes
# the app skip dispatch.  adbd, this script and setsid daemons are not
# zygote children: unaffected.  Must run BEFORE the am start below so
# the manager app comes back on a zygisk-injected framework.
#  fix58 (2026-10-24): bounce is now OFF by default (KS_BOUNCE_ZYGOTE=1
#   to enable) -- its first automated run at 11:53 killed zygote on the
#   just-fragile post-chain system and the framework never came back:
#   device rescue-rebooted ~2min later (bootreason=reboot, driver/ocsk/
#   overlay all lost).  The manual flow (events -> kill zygote, 08:13)
#   ran on an already-stable system and was safe; until that window is
#   understood, re-enable consciously.
#   (fix59's events gate and fix61's events-before-overlay ordering now
#   live above the overlay block -- see fix61 there.)
if [ "\${KS_BOUNCE_ZYGOTE:-0}" = "1" ] && [ -n "\$(pidof zygote64)" ]; then
  log "bouncing zygote for late zygisk injection"
  kill -9 \$(pidof zygote64) \$(pidof zygote) 2>/dev/null || true
  i=0
  while [ "\$(getprop sys.boot_completed)" != 1 ] && [ \$i -lt 45 ]; do
    sleep 4; i=\$((i+1))
  done
  log "framework back: boot_completed=\$(getprop sys.boot_completed) wait=\$((i*4))s"
fi
am force-stop $APP || true
sleep 1
am start -n $APP/$ACT > /dev/null 2>&1 || true
# --- SELinux strict end-state (fix77: kernel:s0 flips, shell:s0 works) ----
# Everything above ran as kernel-domain root while Permissive.  The flip
# must stay with kernel:s0 (measured: shell:s0 has no setenforce
# permission), but after the flip kernel:s0 cannot exec anything -- redo35
# proved it: log()'s date+printf both died "inaccessible or not found" and
# set -e killed the script before any marker.  So probe and logging run in
# the shell:s0 child launched just before the flip (the --strict-child
# branch at the top of this file; transition passes because the launch
# happens while still Permissive).  USR1 trap = probe-failure revert via
# builtin 'print' (no exec is possible after the flip); a failed probe must
# never strand the device with a dead shell channel -- avc is
# dontaudit-silent and shell cannot flip back on its own.
log "selinux strict: launching shell:s0 worker, then flipping"
trap 'print -r -- 0 > /sys/fs/selinux/enforce' USR1
runcon u:r:shell:s0 sh "\$0" --strict-child &
CH=\$!
sleep 0.3
if setenforce 1 2>/dev/null; then
  :
else
  log "WARN-selinux-strict: setenforce 1 failed"
fi
wait \$CH || true
trap - USR1
exit 0
EOF
sh -n "$RESTORE_LOCAL" || die "restore.sh syntax error"
ab push "$RESTORE_LOCAL" "$STAGE/restore.sh" >/dev/null || die "cannot push restore.sh to $STAGE"

# --- wait for system quiet ----------------------------------------------
# 2026-10-24 PM verdict history below, but 2026-10-25 the user verdict
# "do nothing without value" settled it: this host's steady-state load
# floor is ~4.5 (787 procs, 11.2G RAM), so <2.0 is only reachable in the
# first seconds after a cold boot -- every round waited the full 20-min
# timeout before launching (redo5/redo14 both passed after timeout).
# load was empirically irrelevant to outcomes (user ruling), and the
# operational launch line is load<5 (AGENTS).  Threshold raised to <5.0
# (exact-length edit: -lt 200 -> -lt 500, since li = load*100): gate now
# passes within seconds and skips only the >5.0 boot storm peak.
step "wait for system quiet (1-min load < 5.0)"
quiet=0
for i in $(seq 1 240); do   # up to 20 min
  l=$(ab shell 'cut -d" " -f1 /proc/loadavg' 2>/dev/null | grep -o '^[0-9][0-9.]*' | head -1)
  li=$(echo "$l" | sed 's/\.//' | tr -cd '0-9')
  if [ -n "$li" ] && [ "$li" -lt 500 ] 2>/dev/null; then
    info "quiet after $((i*5))s (load=$l) -> GO"
    quiet=1
    break
  fi
  sleep 5
done
[ "$quiet" = 1 ] || info "WARN-quiet-timeout (still triggering; expect storm-phase risk)"

# --- ONE exploit run ----------------------------------------------------
# stale restore.log survives in /data/local/temp across reboots (temp
# is NOT wiped) -- without this the wait loop below false-positives on
# the PREVIOUS boot's POSTLOCK-RESTORE-OK (observed 2026-10-24 round
# where the chain panicked before ever forking restore).
ab shell 'rm -f /data/local/tmp/postlock_restore.log' 2>/dev/null || true
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
# host-side pass-through for restore gates (fix61): export
# KS_RUN_KSUD_EVENTS=1 / KS_BOUNCE_ZYGOTE=1 before invoking this script
# to enable them for this round only; unset keeps restore's default (off).
if [ -n "${KS_RUN_KSUD_EVENTS:-}" ]; then TRIGGER_ENV="$TRIGGER_ENV KS_RUN_KSUD_EVENTS=$KS_RUN_KSUD_EVENTS"; fi
if [ -n "${KS_BOUNCE_ZYGOTE:-}" ]; then TRIGGER_ENV="$TRIGGER_ENV KS_BOUNCE_ZYGOTE=$KS_BOUNCE_ZYGOTE"; fi
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
# DETACHED via a device-side script file: a synchronous ab shell dies with
# host timeouts and leaves the chain half-way through the route -- dangling
# fops state that panics on the next misc open (AGENTS; round c23b8a27->
# e4eaa672).  Inlining `setsid nohup ... &` into the adb shell line raced
# adbd's session teardown: the background job never exec'd and even
# $CHAIN_OUT stayed absent (2026-10-23).  Writing trigger.sh first (base64
# to dodge quoting) and nohup-ing IT is the run_fops.sh pattern that
# survived every round.
TRIGGER_SCRIPT=$STAGE/trigger.sh
TRIG_B64=$(mktemp)
printf '#!/system/bin/sh\nenv LD_PRELOAD=%s %s /system/bin/sh -c %s\n' \
  "$STAGE/preload.so" "$TRIGGER_ENV" "'echo CHAIN_EXIT_DONE'" | base64 -w0 > "$TRIG_B64"
ab push "$TRIG_B64" $STAGE/trigger.b64 >/dev/null
ab shell "base64 -d $STAGE/trigger.b64 > $TRIGGER_SCRIPT && chmod 755 $TRIGGER_SCRIPT" \
  || echo "WARN: trigger script write failed"
rm -f "$TRIG_B64"
ab shell "rm -f $STAGE/skbdelta $CHAIN_OUT /data/local/tmp/postlock_restore.log; nohup sh $TRIGGER_SCRIPT > $CHAIN_OUT 2>&1 < /dev/null & echo DETACHED" \
  || echo "WARN: detach failed (see $CHAIN_OUT)"

# --- wait for the async KS_COLDSTART restore -----------------------------
# The restore forks inside the chain (root.c coldstart fork) and keeps
# running after the constructor returns; verify must not race it.  Success
# markers: the RESTORE-OK line, or the overlay target it creates.
step "wait for restore (KS_COLDSTART fork)"
RESTORE_OK=0
# 240x2s=480s: restore now also waits for the chain exit-tail, runs the
# three ksud module events (~60s) and bounces zygote (~40s framework
# restart) -- the old 180s was too tight for that tail.
for _ in $(seq 1 240); do
  # fix76 (redo34): ONLY the OK line counts.  The old `[ -x /product/bin/su ]`
  # fallback matched the overlay restore had already mounted while restore
  # was still running its later steps -- verify raced ahead of the strict
  # block, read enforce=0 and died (false-positive pass).
  if ab shell "grep -q POSTLOCK-RESTORE-OK /data/local/tmp/postlock_restore.log 2>/dev/null"; then
    RESTORE_OK=1
    break
  fi
  sleep 2
done
if [ "$RESTORE_OK" = 1 ]; then
  echo "  restore OK; tail:"
  ab shell "tail -8 /data/local/tmp/postlock_restore.log 2>/dev/null" | sed 's/^/    /' || true
else
  echo "WARN: restore marker not seen after 480s"
  ab shell "cat /data/local/tmp/postlock_restore.log 2>/dev/null" | tail -15 | sed 's/^/    /' || true
  echo "  chain log tail:"
  ab shell "tail -25 $CHAIN_OUT 2>/dev/null" | sed 's/^/    /' || true
fi

# --- verify as shell (su wrapper: non-root falls to the KP fake, whose
# whitelist covers shell uid 2000; the wrapper passes root through) ------
step "verify"
ab shell "/product/bin/su -c id" | grep -q "uid=0" || die "/product/bin/su failed (overlay wrapper?)"
# strict-mode exam criterion (2026-10-25): the restore must leave
# Enforcing on.  restore's own fail-safe reverts to Permissive + WARN on
# channel failure -- that path must fail the round here, never pass.
ENC=$(ab shell "cat /sys/fs/selinux/enforce" | tr -d '\r')
[ "$ENC" = "1" ] || die "SELinux not strict (enforce=$ENC) — see WARN-selinux-strict in restore.log"
ab shell "grep -q ^kernelsu /proc/modules" || die "kernelsu.ko not loaded"
if ab shell "getprop wrap.$APP" | grep -q "libgrant"; then
  die "legacy libgrant wrap still set — clear it: setprop wrap.$APP \"\""
fi
# fix77 (redo35 host death): pipefail made this assignment rc=1 when the
# param file read EACCES under enforcing (shell:s0 cannot read it) and set
# -e killed the whole verify silently -- no ERROR, no OK, just "cat:
# Permission denied" as the last line.  Value-empty only triggers the WARN
# below, which is the designed handling.
CUR_MUID=$(ab shell "/product/bin/su -c 'cat /sys/module/kernelsu/parameters/ksu_debug_manager_appid'" | tr -d '\r') || true
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
