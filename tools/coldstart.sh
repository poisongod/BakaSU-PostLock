#!/usr/bin/env bash
# Restore the ReSukiSU + su-daemon chain on the device after a reboot.
# Reboot wipes /data/local/temp, drops the /product/bin overlay and
# re-enables SELinux enforcing.  See AGENTS.md "reboot 恢复清单".
# Safe to re-run: every step is idempotent.
# Requires an existing root channel (APatch /system/bin/su) — after a BL
# relock that channel is gone and this script cannot bootstrap by itself.
#
# Standard-mode era (2026-10-09): the real kernelsu.ko answers the app via
# its [ksu_driver] fd, so the legacy wrap.$APP=libgrant.so property and the
# libkernelsu.so movz/ret patch are RETIRED.  Do not re-add local JNI
# fakery while the driver can answer — that is the deception ⑤ removed.
#
# Usage:
#   tools/coldstart.sh                # full restore + verify
#   tools/coldstart.sh --skip-patch   # deprecated no-op (kept for compat)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP=com.resukisu.resukisu
ACT=org.bakasu.bakasu.ui.MainActivity
TMP=/data/local/temp
SKIP_PATCH=0
[ "${1:-}" = "--skip-patch" ] && SKIP_PATCH=1

die() { echo "coldstart: ERROR: $*" >&2; exit 1; }
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

# run a script on device as root; the script must not contain single quotes
root() {
  case $1 in
    *"'"*) die "root script contains a single quote: $1" ;;
  esac
  ab shell "/system/bin/su -c '$1'"
}

# --- host artifacts ----------------------------------------------------
step "check host artifacts"
SU_SRC=$REPO/build/embed/su_daemon_aarch64_pie
PRELOAD_SRC=$REPO/build/pfum10c48/bin/preload.so
KO_SRC=$REPO/build/embed/kernelsu.ko
FIN_SRC=$REPO/build/embed/finitmod
# ocsk.ko (v8, live-site probe at entry+0xa30) silences the OPPO
# oplus_root_check_succ kill path.  Without it the real driver mode is
# unusable: every libksud.so setuid(0) trips the detector and force_sig
# kills the app.  Must match this kernel exactly (built from kheaders).
OCSK_SRC=$REPO/tools/ocsk/ocsk.ko

[ -f "$KO_SRC" ] || die "missing $KO_SRC (ReSukiSU kernelsu.ko build artifact, lives in build/embed/)"
[ -f "$FIN_SRC" ] || die "missing $FIN_SRC (NDK aarch64-linux-android31-clang -static -O2 -o build/embed/finitmod tools/finitmod.c)"
[ -f "$OCSK_SRC" ] || die "missing $OCSK_SRC (OPPO kill silencer, tools/ocsk/)"
if [ ! -f "$SU_SRC" ] || [ ! -f "$PRELOAD_SRC" ]; then
  echo "building preload + static su (make PROJECT=pfum10c48)..."
  (cd "$REPO" && make PROJECT=pfum10c48 -j"$(nproc)")
fi
[ -f "$SU_SRC" ] && [ -f "$PRELOAD_SRC" ] || die "make failed to produce $SU_SRC / $PRELOAD_SRC"

# --- recreate temp -----------------------------------------------------
step "recreate $TMP (reboot wipes it)"
root "mkdir -p $TMP && chcon u:object_r:shell_data_file:s0 $TMP && chmod 777 $TMP && setenforce 0 && echo 262144 > /proc/sys/fs/pipe-user-pages-soft"
ab shell "getenforce" | grep -qi permissive || echo "WARN: getenforce not Permissive"

# --- libkernelsu.so patch: RETIRED (2026-10-09) ---------------------------
# The app reads version/uAPI/late-load from the real driver fd
# ([ksu_driver], installed by setuid_hook.c once the manager appid is
# registered below).  The movz/ret JNI patch is obsolete: its TABLE predates
# the 35220 APK (so is 18392B, patch expects 18520B) and faking local JNI
# results while the kernel answers honestly is exactly what ⑤ retired.
# "--skip-patch" is accepted as a deprecated no-op.

# --- push payloads ------------------------------------------------------
step "push payloads"
ab push "$SU_SRC" "$TMP/su" >/dev/null
ab push "$PRELOAD_SRC" "$TMP/preload.so" >/dev/null
# kernelsu.ko is 13.5MB: skip the push when the device copy already matches
DEV_KO_SZ=$(ab shell "stat -c %s $TMP/kernelsu.ko 2>/dev/null" | tr -d '\r')
if [ "$DEV_KO_SZ" != "$(stat -c %s "$KO_SRC")" ]; then
  ab push "$KO_SRC" "$TMP/kernelsu.ko" >/dev/null
fi
ab push "$FIN_SRC" "$TMP/finitmod" >/dev/null
ab push "$OCSK_SRC" "$TMP/ocsk.ko" >/dev/null
root "chmod 755 $TMP/su $TMP/preload.so $TMP/kernelsu.ko $TMP/finitmod $TMP/ocsk.ko; \
[ -f $TMP/su.allow ] || { echo 10282 > $TMP/su.allow; echo 10283 >> $TMP/su.allow; echo 2000 >> $TMP/su.allow; }; \
chmod 666 $TMP/su.allow"

# --- kernel driver (kernelsu.ko via finit_module) ------------------------
# NOTE: needs sig_enforce=0, which is patched by the exploit chain itself
# (src/root.c patch_sig_enforce, logged as "sig_enforce ... 1->0 write=1"
# in /sdcard/chain5.log). A fresh boot without a completed chain run keeps
# CONFIG_MODULE_SIG_FORCE=y's default and finit_module fails with
# "Loading of unsigned module is rejected" (EKEYREJECTED).
step "kernel driver"
if ab shell "grep -q ^kernelsu /proc/modules"; then
  echo "already loaded: $(ab shell "grep ^kernelsu /proc/modules" | tr -d '\r')"
else
  FIN_ERR=$(root "$TMP/finitmod $TMP/kernelsu.ko 0" 2>&1) || {
    case "$FIN_ERR" in
      *"unsigned module"*|*"rejected"*)
        die "finit_module rejected: sig_enforce still 1 — run the chain first on this boot (adb shell sh /data/local/temp/run_fops.sh), then re-run coldstart" ;;
    esac
    die "finitmod failed: $FIN_ERR"
  }
  ab shell "grep -q ^kernelsu /proc/modules" || die "driver not visible after finitmod"
  echo "loaded: $(ab shell "grep ^kernelsu /proc/modules" | tr -d '\r')"
fi

# --- ocsk: silence OPPO oplus_root_check_succ kill path ------------------
# Real-driver mode without this = app suicide: libksud.so's setuid(0)
# trips the OPPO ocs detector every time -> "Kill the process of
# escalation..." -> force_sig(SIGKILL).  ocsk probes the LIVE kill site
# (entry+0xa30) and skips the bl + zeroes x0 so the signal dies silently
# (round 60 verified 61/61 kills intercepted, app survived).  arm=1 is
# parsed at load time and registers the probes.  MUST be armed before the
# app restarts below.  WARN-only: the chain/driver still work without it,
# the app just cannot do privileged syscalls safely.
step "ocsk (OPPO kill silencer)"
if ab shell "grep -q ^ocsk /proc/modules"; then
  echo "already loaded: $(ab shell "grep ^ocsk /proc/modules" | tr -d '\r')"
else
  OCSK_ERR=$(root "$TMP/finitmod $TMP/ocsk.ko 0 arm=1" 2>&1) || {
    case "$OCSK_ERR" in
      *"unsigned module"*|*"rejected"*)
        echo "WARN: ocsk rejected — sig_enforce back to 1? (run the chain first on this boot); app may get killed by OPPO ocs" ;;
      *)
        echo "WARN: ocsk finitmod failed: $OCSK_ERR (app may get killed by OPPO ocs)" ;;
    esac
  }
  if ab shell "grep -q ^ocsk /proc/modules"; then
    echo "loaded+armed state=$(ab shell "cat /sys/module/ocsk/parameters/state 2>/dev/null | head -1" | tr -d '\r')"
  fi
fi

# --- manager appid registration (the real fd path) -----------------------
# The app only ever gets its [ksu_driver] fd when zygote setresuid()s into
# a uid that is (a) allow-allowed and (b) on ksu_manager_appid_list
# (hook/setuid_hook.c -> ksu_install_fd).  The stock auto-registration
# paths (throne tracker / pkg observer) key off /data/adb/ksu state we do
# not populate, so register explicitly through the upstream CONFIG_KSU_DEBUG
# module param — writing it re-registers (unregister+register), idempotent.
# MUST happen before the app is (re)started below, else no fd.
step "register manager appid"
MUID=$(ab shell "pm list packages -U $APP" | tr -d '\r' | grep -oE 'uid:[0-9]+' | head -n1 | cut -d: -f2)
[ -n "$MUID" ] || die "cannot resolve uid of $APP"
root "echo $MUID > /sys/module/kernelsu/parameters/ksu_debug_manager_appid" \
  || die "manager param write failed (CONFIG_KSU_DEBUG not built into kernelsu.ko?)"
echo "registered manager uid=$MUID"

# --- daemon -------------------------------------------------------------
# Liveness = pidfile pid exists AND really is `su --daemon`.  su.pid and
# su.sock SURVIVE a reboot (temp does), so a bare kill -0 can hit a reused
# pid — observed 2026-10-09 boot af472689: pidfile 26172 belonged to
# com.follow.clash, daemon was dead the whole boot and su clients silently
# fell back to APatch /system/bin/su (verify stayed green anyway!).
step "su daemon"
SU_PID=$(ab shell "cat $TMP/su.pid 2>/dev/null" | tr -d '\r')
if [ -n "$SU_PID" ] &&
   root "P=$SU_PID; [ \"\$(cat /proc/\$P/comm 2>/dev/null)\" = su ] && grep -q -- \"--daemon\" /proc/\$P/cmdline 2>/dev/null"; then
  echo "already running pid=$SU_PID"
else
  echo "stale/dead daemon (pidfile=$SU_PID) — restarting"
  root "for p in \$(ps -A -o PID=,ARGS= | grep \"su --daemon\" | grep -v grep | sed \"s/ .*//\"); do kill -9 \$p; done; \
rm -f $TMP/su.sock $TMP/su.pid; \
setsid $TMP/su --daemon >> $TMP/su.log 2>&1 < /dev/null &"
  sleep 1
  echo "started pid=$(ab shell "cat $TMP/su.pid 2>/dev/null" | tr -d '\r')"
fi

# --- /product/bin overlay (PATH hijack target) --------------------------
step "/product/bin overlay"
if ab shell "[ -x /product/bin/su ]"; then
  echo "already mounted"
else
  root "mkdir -p $TMP/ovl/lower $TMP/ovl/tmp; \
mountpoint -q $TMP/ovl/lower || mount --bind /product/bin $TMP/ovl/lower; \
mountpoint -q $TMP/ovl/tmp || mount -t tmpfs -o size=16m tmpfs $TMP/ovl/tmp; \
mkdir -p $TMP/ovl/tmp/upper $TMP/ovl/tmp/work; \
cp $TMP/su $TMP/ovl/tmp/upper/su; \
chmod 755 $TMP/ovl/tmp/upper/su; \
mount -t overlay overlay -o lowerdir=$TMP/ovl/lower,upperdir=$TMP/ovl/tmp/upper,workdir=$TMP/ovl/tmp/work,context=u:object_r:system_file:s0 /product/bin"
  echo "mounted"
fi

# --- app restart: clear legacy wrap, pick up the driver fd ---------------
# wrap.$APP=libgrant.so used to fake the KSU uAPI in-app; retired now that
# the real driver answers (see header).  Restart after the manager appid
# registration so setuid_hook installs the fd during this cold start.
step "restart $APP (no wrap)"
root "setprop wrap.$APP \"\"; am force-stop $APP; sleep 1; am start -n $APP/$ACT >/dev/null"

# --- verify -------------------------------------------------------------
step "verify"
# verify as uid 2000: su.allow is a strict whitelist and does NOT contain uid 0
# (root-as-client is denied by client_uid_allowed — shell 2000 is seeded)
ab shell "/product/bin/su -c id" | grep -q "uid=0" || die "/product/bin/su does not yield root"
ab shell "grep -q ^kernelsu /proc/modules" || die "kernelsu driver not loaded"
if ab shell "getprop wrap.$APP" | grep -q "libgrant"; then
  die "legacy libgrant wrap still set — clear it: setprop wrap.$APP \"\""
fi
CUR_MUID=$(root "cat /sys/module/kernelsu/parameters/ksu_debug_manager_appid" | tr -d '\r')
[ "$CUR_MUID" = "$MUID" ] || die "manager param=$CUR_MUID, want $MUID"
echo "OK:"
echo "  $(ab shell "/product/bin/su -c id" | tr -d '\r')"
echo "  $(ab shell "grep ^kernelsu /proc/modules" | tr -d '\r')"
echo "  manager uid=$CUR_MUID (param registered)"
echo "  wrap.$APP=$(ab shell "getprop wrap.$APP" | tr -d '\r')  (must be empty)"
echo "  daemon pid=$(ab shell "cat $TMP/su.pid 2>/dev/null" | tr -d '\r')"
echo "  su.allow: $(ab shell "tr \"\\n\" \" \" < $TMP/su.allow" | tr -d '\r')"
APID=$(ab shell "pidof $APP 2>/dev/null" | tr -d '\r' | awk '{print $1}')
if [ -n "$APID" ] && root "ls -l /proc/$APID/fd 2>/dev/null | grep -q ksu_driver"; then
  echo "  app fd: [ksu_driver] present (pid $APID)"
else
  echo "  WARN: app fd not confirmed — dmesg should show 'install fd for ksu manager'; restart the app if needed"
fi
echo
echo "manual checks: ReSukiSU blue card == driver (35220/5), 越狱模式 badge absent (ksu_late_loaded=false),"
echo "                APatch warning card is HONEST (gone only after ⑦ stock-boot reflash)"
