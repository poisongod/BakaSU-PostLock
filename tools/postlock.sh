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
#                                       /data/local/tmp pr_error-kills us
#   KSUD_NO_PARENT_INSTALL=1         -> skips in-process ksud install
#   SU_INSTALL=0                     -> skip chain su install; we cp our own
#                                       static su (chain would write it into
#                                       /data/local/tmp before it exists)
#
# Usage: tools/postlock.sh            (idempotent, re-runnable)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP=com.resukisu.resukisu
ACT=org.bakasu.bakasu.ui.MainActivity
STAGE=/data/local/tmp/ksu_boot
TMP=/data/local/tmp
# SUVTZ P1-1: 0600 keeps the chain log (KASLR base + pvo in clear text) out
# of any app's reach; the PostLock log panel then only shows app-domain
# chains.  SUVTZ_CHAIN_LOG_MODE=0644 restores the old cross-uid readability.
CHAIN_LOG_MODE=${SUVTZ_CHAIN_LOG_MODE:-0600}
# SUVTZ B10: ksu_kaslr is written by the chain (shell umask -> 0644) and used to
# be the only input the app-domain gate read.  That self-dispatch path is frozen
# with PostLock-Boot, so nothing outside the shell/ksu domain needs to read it.
# 2026-11-07 裁决: 默认改 0600 -- the file carries the real KASLR base and slide
# of the current boot, i.e. a full exploit prerequisite handed to any app that
# can reach /data/local/tmp (measured: runas read goes from a readable 93-byte
# line to "Permission denied", docs/suvtz-p0-baseline §5.1.2).
# SUVTZ_KASLR_MODE=0644 restores the old behaviour if the app-domain gate is
# ever revived.  Applied from restore (kernel:s0) so the chmod always sticks.
KASLR_MODE=${SUVTZ_KASLR_MODE:-0600}

die() { echo "postlock: ERROR: $*" >&2; exit 1; }
# unified log line prefix, same shape as chain/restore/receiver logs
BOOT8='????????'
step() { echo; echo "[$BOOT8 $(date +%T)] ==> $*"; }
info() { echo "[$BOOT8 $(date +%T)] $*"; }

# --- adb ---------------------------------------------------------------
# 选择顺序：显式 $ADB > 真正**能看到设备**的那个 adb。
# WSL 里常同时存在 /usr/bin/adb（Linux server，看不到 Windows adb.exe 的设备）
# 与 /mnt/c/WINDOWS/system32/adb.exe；原先是「谁先找到用谁」，于是脚本会选到
# Linux adb 然后死在 `no device`（实测）。现在按「列得到设备」来判，两者都能用
# 时仍优先 PATH 里的那个。
pick_adb() {
  local cand="" c
  if [ -n "${ADB:-}" ]; then printf '%s' "$ADB"; return 0; fi
  for c in "$(command -v adb 2>/dev/null || true)" /mnt/c/WINDOWS/system32/adb.exe; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    if "$c" devices 2>/dev/null | tr -d '\r' | awk 'NR>1 && $2=="device"' | grep -q .; then
      printf '%s' "$c"; return 0
    fi
    [ -z "$cand" ] && cand=$c
  done
  printf '%s' "$cand"
}
ADB_BIN=$(pick_adb)
[ -n "$ADB_BIN" ] || die "adb not found (set \$ADB)"
ab() {
  if [ -n "${SERIAL:-}" ]; then "$ADB_BIN" -s "$SERIAL" "$@"; else "$ADB_BIN" "$@"; fi
}
# 多设备时必须显式指定：WSL 里跑 Windows 的 adb.exe，ANDROID_SERIAL 不会被
# 传进去（实测仍报 more than one device），只能靠 ab() 加 -s。
# 本机常连着另一台 401e909a（PD2020，非本项目，勿动）——所以这条不是可选优化。
if [ -z "${SERIAL:-}" ]; then
  NDEV=$(ab devices 2>/dev/null | tr -d '\r' | awk 'NR>1 && $2=="device"' | grep -c . || true)
  if [ "$NDEV" -gt 1 ]; then
    die "检测到 $NDEV 台设备，请用 SERIAL=<序列号> 指定目标（错设备 401e909a 勿动）"
  fi
fi
[ "$(ab get-state 2>/dev/null | tr -d '\r')" = device ] || die "no device"
BOOT8=$(ab shell cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r' | cut -c1-8)
[ -n "$BOOT8" ] || BOOT8='????????'

# --- host artifacts ----------------------------------------------------
step "check host artifacts"
PRELOAD_SRC=$REPO/build/pfum10c48/bin/preload.so
KO_SRC=$REPO/build/embed/kernelsu.ko
FIN_SRC=$REPO/build/embed/finitmod
# oplus_check_suppress.ko (v8) silences the OPPO oplus_root_check_succ kill path; without
# it the real driver mode is unusable (app's libksud.so setuid trips the
# detector -> force_sig).  Must match this kernel exactly.
OCSK_SRC=$REPO/../oplus-check-suppress/oplus_check_suppress.ko
[ -f "$OCSK_SRC" ] || die "missing $OCSK_SRC (build in ../oplus-check-suppress)"
# kernelsu_hotload_init.ko (renamed 2026-10-28 from kernelsu_init.ko):
# OPTIONAL legacy companion.  Since 2026-10-31 kernelsu.ko reports its real
# load timing (current->pid != 1) and therefore runs the driver's own
# late-load init (allowlist / observer / throne scan / boot_completed), so
# the companion is only loaded when KS_HOTLOAD_LEGACY=1 is passed.  A missing
# build artifact must never block a run, hence WARN instead of die.
HOTLOAD_SRC=$REPO/../kernelsu-hotload-init/kernelsu_hotload_init.ko
if [ ! -f "$HOTLOAD_SRC" ]; then
  info "WARN: missing $HOTLOAD_SRC (optional: hotload companion is legacy-only, KS_HOTLOAD_LEGACY=1)"
fi
[ -f "$KO_SRC" ] || die "missing $KO_SRC (ReSukiSU kernelsu.ko build artifact, lives in build/embed/)"
[ -f "$FIN_SRC" ] || die "missing $FIN_SRC (NDK aarch64-linux-android31-clang -static -O2 -o build/embed/finitmod tools/finitmod.c)"
if [ ! -f "$PRELOAD_SRC" ]; then
  (cd "$REPO" && make PROJECT=pfum10c48 -j"$(nproc)")
fi
[ -f "$PRELOAD_SRC" ] || die "make failed"

# manager appid (belt-and-braces for the driver param; see the restore
# block).  Empty is NOT fatal: kernelsu.ko's late-load branch runs a
# synchronous track_throne() scan that crowns the manager by APK signature,
# so the param is only a fallback.  Never guess a value -- a wrong uid would
# be crowned as manager (KSU_SIGNATURE_INDEX_KSU_DEBUG) and could obtain a
# driver fd.
MUID=$(ab shell "pm list packages -U $APP" | tr -d '\r' | grep -oE 'uid:[0-9]+' | head -n1 | cut -d: -f2 || true)
if [ -z "$MUID" ]; then
  info "WARN: cannot resolve uid of $APP -- relying on track_throne (appid param will not be written)"
fi

# --- stage payloads (shell-writable, NO root needed) --------------------
step "stage payloads at $STAGE"
ab shell "mkdir -p $STAGE" || die "cannot create $STAGE (is /data/local/tmp gone?)"

# Skip any file whose sha1 already matches on device (measured 2026-11-06:
# the 15.5MB kernelsu.ko takes 0.42s over USB at 35MB/s but ~14 minutes over
# a tailnet relay; an unchanged stage is the common case on a re-run).  A
# handful of extra shell round-trips is always cheaper than one relayed push.
push_if_changed() {  # <local-path> <stage-basename>
  local src=$1 name=$2 want got
  [ -f "$src" ] || return 0
  want=$(sha1sum "$src" | cut -d' ' -f1)
  got=$(ab shell "sha1sum $STAGE/$name 2>/dev/null" 2>/dev/null | tr -d '\r' \
        | cut -d' ' -f1 || true)
  if [ "$want" = "$got" ] && [ -n "$got" ]; then
    info "stage-unchanged $name"
    return 0
  fi
  ab push "$src" "$STAGE/$name" >/dev/null || die "push failed: $name"
  info "stage-pushed $name"
}

push_if_changed "$PRELOAD_SRC" preload.so
push_if_changed "$KO_SRC" kernelsu.ko
push_if_changed "$FIN_SRC" finitmod
push_if_changed "$OCSK_SRC" oplus_check_suppress.ko
if [ -f "$HOTLOAD_SRC" ]; then
  push_if_changed "$HOTLOAD_SRC" kernelsu_hotload_init.ko
fi
# ksud blob (2026-10-30, fresh-boot first-run gap): the restore script and
# the su wrapper exec ksud from $TMP, and restore used to source it from
# /data/adb/ksud -- a file only previous chain runs leave behind.  On a
# factory-reset device that file does not exist, the chain itself never
# writes it (KSUD_NO_PARENT_INSTALL=1 skips install_embedded_ksud), the
# cp is silently skipped by its `[ -x /data/adb/ksud ]` guard, and the
# wrapper dies with rc=127 -> verify fails on the very first run.  Stage
# the embedded blob (same binary the preload.so incbin ships) directly;
# restore now sources ksud from $STAGE exclusively.
KSUD_SRC="$REPO/build/embed/ksud"
[ -f "$KSUD_SRC" ] || die "missing $KSUD_SRC (embedded ksud blob)"
push_if_changed "$KSUD_SRC" ksud
ab shell "chmod 755 $STAGE/ksud" >/dev/null || true
# W world helper (2026-11-09): static aarch64 binary that owns the private
# mount namespace holding W.  Committed artifact (tools/wns/wns), same
# policy as the other stage payloads -- host pushes, restore execs from
# $STAGE.  Missing is fatal here rather than a silent WARN later: the app
# assets ship the same file (StageDeploy.EXEC), so a missing host copy
# means one of the two sides is stale and the boundary would silently
# not exist.
WNS_SRC="$REPO/tools/wns/wns"
[ -f "$WNS_SRC" ] || die "missing $WNS_SRC (run tools/wns/build.sh)"
push_if_changed "$WNS_SRC" wns
ab shell "chmod 755 $STAGE/wns" >/dev/null || true
# Retired payload (2026-11-10): the self-built su daemon is gone and
# restore.sh only calls /system/bin/su (sucompat rewrites the allow-listed
# uid's execve), so a stale $STAGE/su is a dead executable entry.  Remove
# it idempotently -- old boots still carry the file from earlier runs.
ab shell "rm -f $STAGE/su" >/dev/null || true
push_if_changed "$REPO/tools/sepolicy_enforce1.txt" sep_enforce1.txt
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
# The file is created by whoever runs first (the shell-domain trigger pre-creates
# it as uid 2000 / 0600 in the app-driven path), and restore itself is root so it
# can widen the mode. Without this the app's observer (uid 10xxx) cannot DAC-read
# the marker and mis-reports FAIL on an otherwise successful run (2026-11-08).
chmod \${SUVTZ_CHAIN_LOG_MODE:-$CHAIN_LOG_MODE} /data/local/tmp/postlock_restore.log 2>/dev/null || true
BOOT8=\$(cut -c1-8 /proc/sys/kernel/random/boot_id 2>/dev/null || echo "????????")
# fix76: log to fd2 -- fd1 (the exec redirect) is fully buffered and a
# non-gentle exit drops the tail (redo34's log ended mid "probing" with no
# WARN/OK line ever reaching disk); stderr is unbuffered, lands instantly.
# fix78: date guarded -- in redo39 the original child died in the flip
# window with 202x "Segmentation fault" and zero log lines (its log()'s
# date was the only unprotected exec left after the flip); a failing date
# must degrade to '???:???' instead of taking the whole log call down.
log() { printf "[%s %s] %s\\n" "\$BOOT8" "\$(date +%H:%M:%S 2>/dev/null || echo '???:???')" "\$*" >&2; }
# (fix77's runcon --strict-child branch removed by fix81 -- see the tail block.)
log "== restore start \$(date '+%F %T') pid=\$\$ uid=\$(id -u)"
id
ls -ld /data /data/local /data/local/tmp 2>&1 || true
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
# SUVTZ P1-1 (2026-11-03): 0777 handed every app a writable AND listable
# stash -- a single ls of /data/local/tmp enumerated the whole toolkit.  Stock
# Android ships 0711 (traverse-only for non-owners), which is also what the
# app-domain gate needs (it must traverse to read ksu_kaslr).  The chain
# runs as shell (the owner) and restore as root, so both keep full access.
chmod 0711 $TMP
echo 262144 > /proc/sys/fs/pipe-user-pages-soft
# roll back the OMK injector config BEFORE ksud services (which triggers the
# OMK injection that reads it): the uid:1000 scoop variant caused a
# kernel_panic on 2026-10-24 (twice); .bak is the original stable config.
[ -f /data/adb/modules/oh_my_keymint/injector.toml.bak ] && cp /data/adb/modules/oh_my_keymint/injector.toml.bak /data/adb/modules/oh_my_keymint/injector.toml && log OMK-ROLLED-BACK || log WARN-no-omk-bak
# rm-before-cp keeps reruns safe: unlink-then-copy never hits ETXTBSY on
# a binary some previous round left mapped/executing.
for f in kernelsu.ko finitmod oplus_check_suppress.ko preload.so; do
  rm -f $TMP/\$f
  cp $STAGE/\$f $TMP/\$f
done
chmod 755 $TMP/kernelsu.ko $TMP/finitmod $TMP/oplus_check_suppress.ko $TMP/preload.so
# hotload companion is legacy-only (see the load block below): copy it only
# when the stage actually carries it.  Keeping it in the loop above would make
# a stage built without ../kernelsu-hotload-init kill the restore under set -e.
if [ -f $STAGE/kernelsu_hotload_init.ko ]; then
  rm -f $TMP/kernelsu_hotload_init.ko
  cp $STAGE/kernelsu_hotload_init.ko $TMP/kernelsu_hotload_init.ko
  chmod 755 $TMP/kernelsu_hotload_init.ko
fi
if grep -q ^kernelsu /proc/modules; then log driver-already-loaded; else $TMP/finitmod $TMP/kernelsu.ko 0 || log WARN-finitmod-failed; fi
# kernelsu_hotload_init (hotload companion) is no longer needed: kernelsu.ko
# now reports its real load timing (current->pid != 1) and therefore takes the
# driver's own late-load init path, which performs allowlist load / manager
# observer / throne scan / boot_completed inside kernelsu_init().  Loading the
# companion on top of that would run the same steps twice.  Kept as an opt-in
# fallback for older kernelsu.ko builds: KS_HOTLOAD_LEGACY=1.
if [ "\${KS_HOTLOAD_LEGACY:-0}" = 1 ]; then
  if grep -q ^kernelsu_hotload_init /proc/modules; then log hotload-already-loaded; elif [ ! -f $TMP/kernelsu_hotload_init.ko ]; then log WARN-hotload-missing-stage; elif $TMP/finitmod $TMP/kernelsu_hotload_init.ko 0; then log hotload-finitmod-ok; else log WARN-hotload-finitmod-failed; fi
else
  log hotload-skipped-late-init-selfsufficient
fi
# oplus_check_suppress: silence the OPPO oplus_root_check_succ kill path BEFORE the app
# restarts below -- without it libksud.so setuid(0) trips the detector
# and force_sig kills the app (round 60 verified 61/61 kills intercepted).
# WARN-only: sig_enforce is 0 on this boot because the chain just ran.
if grep -q ^oplus_check_suppress /proc/modules; then log oplus_check_suppress-already-loaded; elif $TMP/finitmod $TMP/oplus_check_suppress.ko 0 arm=1; then log oplus_check_suppress-finitmod-ok; else log WARN-oplus_check_suppress-finitmod-failed; fi
# popup-suppress diagnostics (2026-10-29, oplus_check_suppress): restore's own ksud execve trips
# oplus_exec_block and was reported -> popup forced-reboot wiped the boot
# right after POSTLOCK-RESTORE-OK (pstore kevent_send_to_user:execve x3 at
# finitmod+2s).  v12 popup probes (rep1/rep2) are best-effort: finitmod-ok
# does NOT mean they armed.  Read state, retry arm once (helps entry-stage
# FAIL; rep-anchor MISMATCH is per-boot static), WARN loudly when not armed=2
# so the next popup is attributed, not rediscovered.
OCS=/sys/module/oplus_check_suppress/parameters
log "oplus_check_suppress-state: \$(tr '\n' '|' < \$OCS/state 2>/dev/null)"
log "kallsyms-ors: \$(grep -a oplus_root_check_succ /proc/kallsyms 2>/dev/null | tr '\n' '|')"
log "kallsyms-oeb: \$(grep -a oplus_exec_block /proc/kallsyms 2>/dev/null | tr '\n' '|')"
if grep -q patched=1 \$OCS/state 2>/dev/null; then log oplus_check_suppress-kill-armed; else log WARN-oplus_check_suppress-kill-not-armed; fi
if grep -q '^rep armed=2' \$OCS/state 2>/dev/null; then log oplus_check_suppress-rep-armed; elif echo 1 > \$OCS/arm 2>/dev/null; then sleep 0.2; if grep -q '^rep armed=2' \$OCS/state 2>/dev/null; then log oplus_check_suppress-rep-armed-after-retry; else log WARN-oplus_check_suppress-rep-not-armed-popup-risk; fi; else log WARN-oplus_check_suppress-rep-not-armed-popup-risk; fi
# register the manager appid so zygote setresuid installs the
# [ksu_driver] fd for the manager (CONFIG_KSU_DEBUG param; must
# precede the app start).  Resolved HERE at run time, not baked in by
# the host: an uninstall+reinstall re-allocates the uid (10279 -> 10300
# observed 2026-10-29) and a stale value leaves the manager without a
# driver fd ("no KernelSU driver detected" red card).  packages.list is
# a plain file readable in kernel:s0 without binder; pm is the fallback.
# Never fall back to a hardcoded uid -- the driver's late-load branch
# runs a synchronous track_throne() scan that crowns the manager by APK
# signature, so an unresolved uid only means "skip this belt-and-braces
# param"; a guessed uid would be crowned as manager
# (KSU_SIGNATURE_INDEX_KSU_DEBUG) and could obtain a driver fd.
if [ -w /sys/module/kernelsu/parameters/ksu_debug_manager_appid ]; then
  MUID=\$(grep -m1 '^$APP ' /data/system/packages.list 2>/dev/null | awk '{print \$2}')
  [ -n "\$MUID" ] || MUID=\$(pm list packages -U $APP 2>/dev/null | grep -oE 'uid:[0-9]+' | head -n1 | cut -d: -f2)
  if [ -n "\$MUID" ]; then
    echo \$MUID > /sys/module/kernelsu/parameters/ksu_debug_manager_appid
    log "manager-appid=\$MUID"
  else
    log WARN-manager-appid-unresolved
  fi
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
# fix61 (2026-10-24): the ksud events run BEFORE any mount work in the tail,
# not after.  Measured on-device: ksud post-fs-data umounts mounts a restore
# step just created (the old /product/bin overlay's wrapper+ksud upper
# vanished, shell 'ls /product/bin/su' fell back to the stock ro partition and
# got Permission denied).  That overlay is retired as of 2026-11-09, but the
# ordering rule stays: mount work must land after the events, because the
# events churn the mount table.  fix59's gate stays (events x post-chain
# window is still a suspect for the 12:21 panic): default OFF,
# KS_RUN_KSUD_EVENTS=1 to enable.  All three events tested safe on a healthy
# system (14:26-14:39, OMK injector came up clean).
if [ "\${KS_RUN_KSUD_EVENTS:-0}" = "1" ] && [ -x $STAGE/ksud ]; then
  timeout 60 $STAGE/ksud post-fs-data > /dev/null 2>&1 || log WARN-ksud-postfs
  timeout 90 $STAGE/ksud services > /dev/null 2>&1 || log WARN-ksud-services
  timeout 30 $STAGE/ksud boot-completed > /dev/null 2>&1 || log WARN-ksud-bootcomp
fi
# --- SUVTZ: /product/bin overlay RETIRED (2026-11-09) ----------------------
# The overlay gave the su entry point a filesystem presence: a 412-byte
# wrapper at /product/bin/su plus /product/bin/ksud in a tmpfs upper over a
# bind of the stock /product/bin.  Two measured facts made that the wrong
# design:
#
#   1. The real entry point has no filesystem presence.  The driver's sucompat
#      rewrites execve("/system/bin/su") for allow-listed uids at sys_enter and
#      execs ksud through a fd (BakaSU kernel/feature/sucompat.c SU_PATH).
#      stat("/system/bin/su") resolves to the ksud inode, open() answers
#      ENOENT, and the exec works anyway.  TrustZone's own entry (smc #0) is
#      instruction-level too -- an entry that needs a path to exist is a
#      filter-layer artifact, not structural isolation.
#   2. The overlay was a mount every domain could enumerate.  SUS_MOUNT tagged
#      it (mnt_id >= 2000000000) but hiding it required
#      hide_sus_mnts_for_non_su_procs=1, and that switch also blinded this
#      script's own mountpoint -q (restore runs as u:r:kernel:s0, a non-ksu
#      domain): on a same-boot re-run the overlay got bind-mounted onto its own
#      lower dir -- measured two layers on $TMP/ovl/lower, mnt ids 2000000000
#      and 2000000241, same overlay sb 0:217.  Structural isolation cannot
#      depend on a switch that has to lie to half the system.
#
# Measured after manual retirement on boot 13b5a48a: shell 'su -c id' ->
# uid=0 u:r:ksu:s0 (both with the default PATH and with a PATH without
# /product/bin), /product/bin back to the stock four files, zero product/bin
# lines in shell and ksu mountinfo, manager still holds its [ksu_driver] fd,
# and both ksud copies work (stage 4.2.0-rc3-51, /data/adb/ksud 4.2.0-rc3-81).
#
# On a fresh boot nothing is mounted and this is a no-op; it exists for the
# same-boot upgrade path and for devices still carrying an older run's
# overlay.  Order matters: drop the hide switch FIRST, otherwise tagged mounts
# are invisible to mountpoint -q and the umount loop silently does nothing.
if [ -x $STAGE/ksud ]; then
  timeout 10 $STAGE/ksud susfs hide_sus_mnts_for_non_su_procs 0 >/dev/null 2>&1 || true
fi
retired=0
for round in 1 2 3; do
  for m in /product/bin $TMP/ovl/lower $TMP/ovl/tmp; do
    if mountpoint -q "\$m" 2>/dev/null; then
      if umount "\$m" 2>/dev/null; then
        retired=\$((retired+1)); log "suvtz: retired mount \$m"
      elif umount -f "\$m" 2>/dev/null; then
        retired=\$((retired+1)); log "suvtz: retired mount \$m (force)"
      else
        log "WARN-suvtz-umount \$m"
      fi
    fi
  done
done
if ! mountpoint -q /product/bin 2>/dev/null \
   && ! mountpoint -q $TMP/ovl/lower 2>/dev/null \
   && ! mountpoint -q $TMP/ovl/tmp 2>/dev/null; then
  rm -rf $TMP/ovl 2>/dev/null || true
  log "suvtz: overlay-retired mounts=\$retired"
else
  log "WARN-suvtz-overlay-residual mounts=\$retired"
fi
# $TMP/ksud is the shell/root-facing copy (restore + host triage use it;
# $TMP is shell_data_file so shell can exec it).
# 2026-10-30: source moved from /data/adb/ksud to $STAGE/ksud (host
# stages the embedded blob; /data/adb/ksud only exists on devices where
# an older chain run left it behind -- factory-reset first run died here).
if [ -x $STAGE/ksud ]; then
  cp -f $STAGE/ksud $TMP/ksud 2>/dev/null || log WARN-ksud-temp-cp
  chmod 755 $TMP/ksud 2>/dev/null || true
  chcon u:object_r:shell_data_file:s0 $TMP/ksud 2>/dev/null || true
fi
# v27 (2026-11-05): sucompat's KSUD_PATH is a compile-time
# /data/adb/ksud -- the execve rewrite opens exactly that file.  The
# manager installs it, but only once it has started (measured 2026-11-05:
# /data/adb/ksud appeared when the manager first ran with root), so on a
# fresh boot before any manager start every allow-listed 'su' would fall
# back to the real exec and be refused.  Provision it here, and never
# overwrite an existing install (the manager's copy is the release build).
if [ -x $STAGE/ksud ] && [ ! -e /data/adb/ksud ]; then
  cp -f $STAGE/ksud /data/adb/ksud 2>/dev/null && chmod 755 /data/adb/ksud 2>/dev/null \
    && log su-driver-ksud-provisioned || log WARN-su-driver-ksud-cp
fi
# --- SUVTZ W world: structural isolation #1 (2026-11-09) ---------------
# SUVTZ is defined as two execution worlds with a structural boundary, not
# as a filter (docs/suvtz-v3-design.md).  W lives in its own mount
# namespace: a tmpfs mounted on $TMP/.w inside a private namespace, so its
# contents (stage/log/state) have no path in N at all -- N sees only the
# empty mountpoint directory.  That is the observable difference between
# "structurally absent" (ENOENT) and "hidden by a filter" (EACCES), and it
# is what makes this a boundary rather than another layer of masking.
#
# Order is load-bearing (measured C7): unshare(CLONE_NEWNS), then
# mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL), then the tmpfs.  Without the
# second step the mount propagates back into N's namespace through
# shared:1 and the boundary does not exist.  wns hold does all three.
#
# Who owns the holder: W is consumed by this very script (the stage payload
# is the future content), i.e. u:r:kernel:s0 uid 0 with full caps, so a
# direct start is tried first.  The ksu-domain start is the fallback for a
# domain that cannot unshare; measured 2026-11-09: ksu can open its own
# namespace, shell cannot, so cross-domain access is never assumed.
#
# WARN-only by construction: W is an addition.  A boot without a holder
# still reaches POSTLOCK-RESTORE-OK.
WMP=$TMP/.w
WLOG=$TMP/wns_hold.log
WNSBIN=$STAGE/wns
WPID=
WBY=
WNS=
if [ ! -x \$WNSBIN ]; then
  log WARN-suvtz-w-wns-missing
else
  WPID=\$(pgrep -f "^\$WNSBIN hold " 2>/dev/null | head -n1)
  if [ -n "\$WPID" ]; then
    WBY=reused
  else
    rm -f \$WLOG 2>/dev/null || true
    setsid \$WNSBIN hold \$WMP >> \$WLOG 2>&1 < /dev/null &
    i=0
    while [ \$i -lt 50 ]; do
      WPID=\$(pgrep -f "^\$WNSBIN hold " 2>/dev/null | head -n1)
      if [ -n "\$WPID" ]; then break; fi
      sleep 0.2
      i=\$((i+1))
    done
    if [ -n "\$WPID" ]; then WBY=kernel; fi
  fi
  if [ -z "\$WPID" ] && [ -x /system/bin/su ]; then
    # Keep whatever the direct attempt wrote: if unshare(CLONE_NEWNS) was
    # denied there, that line is the only evidence for why we fell back.
    /system/bin/su -c "setsid \$WNSBIN hold \$WMP >> \$WLOG 2>&1 < /dev/null &" >/dev/null 2>&1 || true
    i=0
    while [ \$i -lt 50 ]; do
      WPID=\$(pgrep -f "^\$WNSBIN hold " 2>/dev/null | head -n1)
      if [ -n "\$WPID" ]; then break; fi
      sleep 0.2
      i=\$((i+1))
    done
    if [ -n "\$WPID" ]; then WBY=ksu; fi
  fi
  if [ -z "\$WPID" ]; then
    log WARN-suvtz-w-holder-missing
    if [ -s \$WLOG ]; then
      log "WARN-suvtz-w-hold-log: \$(tail -n3 \$WLOG 2>/dev/null | tr '\n' '|')"
    fi
  else
    # The holder prints its ns right after mounting, but pgrep can see the
    # process a few ms earlier, so read the namespace from procfs (we own the
    # process) and only fall back to the log line.
    WNS=\$(readlink /proc/\$WPID/ns/mnt 2>/dev/null || true)
    if [ -z "\$WNS" ]; then
      WNS=\$(grep -o 'mnt:\[[0-9]*\]' \$WLOG 2>/dev/null | tail -n1)
    fi
    if [ -z "\$WNS" ]; then WNS=unknown; fi
    log "suvtz-w: holder pid=\$WPID ns=\$WNS mp=\$WMP by=\$WBY"
    if \$WNSBIN run \$WPID /system/bin/mountpoint -q \$WMP >/dev/null 2>&1; then
      log "suvtz-w: mountpoint=yes"
    elif /system/bin/su -c "\$WNSBIN run \$WPID /system/bin/mountpoint -q \$WMP" >/dev/null 2>&1; then
      log "suvtz-w: mountpoint=yes-via-su"
    else
      log WARN-suvtz-w-mountpoint
    fi
    if [ -e \$WMP/stage ]; then
      log WARN-suvtz-w-visible-in-n
    else
      log "suvtz-w: n-side-absent stage=ENOENT"
    fi
  fi
fi
# --- SUVTZ P1-1: DAC hygiene (2026-11-03) -----------------------------
# The P0 baseline (docs/suvtz-p0-baseline.md, 30 probes) measured what a
# third-party app still reaches by simply guessing a path: ksu_boot/ and
# ovl/ were 0777, and every .ko / finitmod / ksud / preload copy was
# world-readable (kernelsu.ko 13.7MB, chain log 431KB with the KASLR base
# and pvo in clear text).  None of it is needed by untrusted_app: the app
# reads its OWN private filesDir/postlock copy (ChainTrigger ->
# PayloadRepo.ensure; the STAGE_DIR constant there has zero references),
# and restore runs as root, so CAP_DAC_OVERRIDE keeps every path working.
# Deliberately left world-readable (tracked as an open decision in the
# report): ksu_kaslr / ksu_payload -- the app-domain gate + paste inputs;
# closing them permanently disables app self-dispatch on BOOT_COMPLETED.
if [ -d $STAGE ]; then
  chown 2000:2000 $STAGE 2>/dev/null || true
  chmod 0700 $STAGE 2>/dev/null || true
fi
for f in kernelsu.ko oplus_check_suppress.ko kernelsu_hotload_init.ko; do
  if [ -f $TMP/\$f ]; then chmod 0600 $TMP/\$f 2>/dev/null || true; fi
done
if [ -f $TMP/finitmod ]; then chmod 0700 $TMP/finitmod 2>/dev/null || true; fi
# shell-exec'd binaries: owner shell + 0700 (run_fops.sh LD_PRELOADs
# /data/local/tmp/preload.so; the ksud copy is what restore and triage exec).
for f in ksud preload.so; do
  if [ -f $TMP/\$f ]; then
    chown 2000:2000 $TMP/\$f 2>/dev/null || true
    chmod 0700 $TMP/\$f 2>/dev/null || true
  fi
done
# Run residue: the chain/restore logs carry the KASLR base and pvo in clear
# text, pstore_dump is a raw kernel log, ts.state is the tailnet node key.
# shell stays owner so the host can still append the host-verify probe line.
for f in postlock_restore.log chain_run.state pstore_dump ts.state tsd.log .ks_lock_slots .cfgfslock; do
  if [ -f $TMP/\$f ]; then
    chown 2000:2000 $TMP/\$f 2>/dev/null || true
    chmod 0600 $TMP/\$f 2>/dev/null || true
  fi
done
# The chain log is the one file with a legitimate cross-uid reader: the
# PostLock app's log panel tails it.  0600 (default) closes the leak and
# limits the panel to app-domain chains; SUVTZ_CHAIN_LOG_MODE=0644 restores
# the old behaviour at the cost of the KASLR base being app-readable.
#
# The mode is read from the environment at restore time so ONE generated
# restore.sh serves both callers: the host script leaves it unset (0600) and
# the in-app shell-domain runner exports SUVTZ_CHAIN_LOG_MODE=0644 for the
# round it triggers, then chmods the log back to 0600 once the chain is done.
if [ -f $TMP/postlock_chain.log ]; then
  chown 2000:2000 $TMP/postlock_chain.log 2>/dev/null || true
  chmod \${SUVTZ_CHAIN_LOG_MODE:-$CHAIN_LOG_MODE} $TMP/postlock_chain.log 2>/dev/null || true
fi
# B10: the app-domain gate input (written by the chain as shell, umask 0644).
# 0600 = default since 2026-11-07, i.e. unreadable to any app uid;
# SUVTZ_KASLR_MODE=0644 re-opens it.  Owner stays shell so the chain can
# rewrite it next round with O_TRUNC (which does not reset the mode).
for f in ksu_kaslr ksu_payload; do
  if [ -f $TMP/\$f ]; then
    chown 2000:2000 $TMP/\$f 2>/dev/null || true
    chmod $KASLR_MODE $TMP/\$f 2>/dev/null || true
  fi
done
log "suvtz-b10: ksu_kaslr mode=\$(stat -c %a $TMP/ksu_kaslr 2>/dev/null || echo absent) (want $KASLR_MODE)"
log "suvtz-p1-1: dac hardened (tmp 0711 / stage 0700 / materials 0600-0700 / logs 0600)"
# --- su/fd regression triage (2026-11-03) ------------------------------
# The host verify's '/system/bin/su -c id' dies with "could not retrieve
# kernelsu driver fd" although kernelsu is Live.  Root only exists inside
# this window, so snapshot the kernel ring buffer here: it still holds the
# module init of this boot AND every earlier su attempt.  Plus the ksu_dbg_*
# parameters (shell cannot stat them: sysfs SELinux label -> -?????????) and
# a root-context 'ksud debug su', which separates "reboot() supercall hook
# not installed" from "uid 2000 / shell-domain only".
dmesg > $TMP/dmesg_boot.txt 2>/dev/null || true
chmod 0644 $TMP/dmesg_boot.txt 2>/dev/null || true
{
  for p in ksu_dbg_stage ksu_dbg_kp_rc ksu_dbg_kp_hits ksu_dbg_kp_reg ksu_dbg_kp_kps ksu_dbg_exec_fd ksu_dbg_sysent ksu_dbg_disp ksu_dbg_disp_hits ksu_dbg_patch ksu_dbg_tp_rc ksu_dbg_tp_hits ksu_dbg_setuid_hits ksu_debug_manager_appid enforce_on_load lookup_hook; do
    echo "\$p=\$(cat /sys/module/kernelsu/parameters/\$p 2>&1)"
  done
  echo "--- /proc/modules ---"
  cat /proc/modules 2>&1
} > $TMP/ksu_dbg_params.txt 2>&1 || true
chmod 0644 $TMP/ksu_dbg_params.txt 2>/dev/null || true
if [ -x $TMP/ksud ]; then
  {
    echo "== as root (uid 0, kernel:s0) =="
    printf 'id\n' | $TMP/ksud debug su
    echo "rc=\$?"
  } > $TMP/ksu_su_asroot.txt 2>&1 || true
  chmod 0644 $TMP/ksu_su_asroot.txt 2>/dev/null || true
fi
log "su-triage: dmesg + ksu_dbg params + root ksud probe captured"
# --- enforce=1 data-path rules (2026-10-28) ----------------------------
# Manager data features under strict SELinux (measured 2026-10-28, boot
# 587002ff): service check package / RootService / pm list packages all
# fail until these land.  The pm failure is uid0-specific and comes from
# binder_translate_fd: selinux_binder_transfer_file refuses to hand the
# su-session pipe fds to system_server (dmesg "transaction failed
# 29201/-1, size 172-40"), so cmd's shellCommand dies with Failed
# transaction (2147483646) -> SuperUserRepository PACKAGE_LOAD_FAILED.
# allow system_server ksu/shell fifo_file read/write is the fix (file/
# socket fds passed all along; only the pipe was rejected).  check rc
# is the only trustworthy parse verdict -- apply exits 0 on bad input
# too (non-strict skips unparseable lines silently).
if [ -f $STAGE/sep_enforce1.txt ] && [ -x $TMP/ksud ]; then
  $TMP/ksud sepolicy check $STAGE/sep_enforce1.txt >/dev/null 2>&1 \\
    || log WARN-sep-check-failed
  $TMP/ksud sepolicy apply $STAGE/sep_enforce1.txt >/dev/null 2>&1 \\
    || log WARN-sep-apply-failed
  log "sepolicy enforce1 rules applied"
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
#   device rescue-rebooted ~2min later (bootreason=reboot, driver/oplus_check_suppress/
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
# --- SELinux strict end-state (fix81: builtin-only post-flip markers) ----
# Everything above ran as kernel-domain root while Permissive; only this
# kernel:s0 shell may flip (measured: shell:s0 setenforce = Permission
# denied).  fix77 tried to hand post-flip work to a runcon shell:s0 child --
# 4 consecutive native deaths (redo39/42/43/45: 202/101/64/13 Segmentation
# faults after "poll i=0", silent exit, no marker ever), while the SAME
# script run by hand from adb shell completed both markers cleanly (measured
# 2026-10-27 05:47).  Death needs runcon+flip; nothing here does.  After the
# flip this shell's OWN builtins keep working -- proved since fix77 by the
# USR1 trap's builtin write to selinuxfs.  So: flip, poll enforce with
# builtin read, write both markers with builtin print -- zero fork, zero
# exec post-flip.  The su probe runs from kernel:s0?  impossible post-flip;
# host verify owns it (enforce=1 hard check + su uid=0, measured working
# under enforcing from shell:s0) and appends its probe line to this log.
log "selinux strict: flipping (builtin-only markers follow)"
TF=\$(date +%H:%M:%S 2>/dev/null || echo '???:???')
trap 'print -r -- 0 > /sys/fs/selinux/enforce' USR1
if setenforce 1 2>/dev/null; then
  :
else
  print -r -- "[\$BOOT8 \$TF] WARN-selinux-strict: setenforce 1 failed" >&2 || :
fi
ENF=0
i=0
while [ \$i -lt 5000 ]; do
  ENF=0
  read ENF < /sys/fs/selinux/enforce 2>/dev/null || :
  if [ "\$ENF" = "1" ]; then break; fi
  i=\$((i + 1))
done
if [ "\$ENF" = "1" ]; then
  print -r -- "[\$BOOT8 \$TF] SELINUX-STRICT-OK enforce=1 probe=host-verify" >&2 || :
else
  # flip never observed (cannot happen: the trap's own builtin write to this
  # same file succeeds post-flip) -- revert rather than strand the device.
  print -r -- 0 > /sys/fs/selinux/enforce || :
  print -r -- "[\$BOOT8 \$TF] WARN-selinux-strict: enforce never observed=\$ENF, reverted" >&2 || :
fi
trap - USR1
print -r -- "[\$BOOT8 \$TF] POSTLOCK-RESTORE-OK" >&2 || :
exit 0
EOF
sh -n "$RESTORE_LOCAL" || die "restore.sh syntax error"
ab push "$RESTORE_LOCAL" "$STAGE/restore.sh" >/dev/null || die "cannot push restore.sh to $STAGE"

# --- popup source kill (2026-10-29) ---------------------------------------
# Manager cold-start execs libksud.so; oplus_exec_block reports that execve
# (pstore: kevent_send_to_user:execve .../libksud.so x2) and exsystemservice
# pops the no-button 15s forced-reboot dialog.  The report fires BEFORE our
# chain (manager autostarts mid-boot), so force-stop here -- early, ahead of
# the whole quiet-gate wait -- and restore's tail restarts it afterwards
# (force-stop + am start under the oplus_check_suppress-armed window).
ab shell "am force-stop com.resukisu.resukisu" 2>/dev/null || true

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
# stale restore.log survives in /data/local/tmp across reboots (temp
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
ab shell "rm -f $STAGE/skbdelta $CHAIN_OUT /data/local/tmp/postlock_restore.log; : > $CHAIN_OUT; chmod $CHAIN_LOG_MODE $CHAIN_OUT; nohup sh $TRIGGER_SCRIPT >> $CHAIN_OUT 2>&1 < /dev/null & echo DETACHED" \
  || echo "WARN: detach failed (see $CHAIN_OUT)"

# --- wait for the async KS_COLDSTART restore -----------------------------
# The restore forks inside the chain (root.c coldstart fork) and keeps
# running after the constructor returns; verify must not race it.  Success
# marker: the RESTORE-OK line (the old "[ -x /product/bin/su ]" fallback was
# removed together with the overlay, see fix76 below).
step "wait for restore (KS_COLDSTART fork)"
RESTORE_OK=0
# 240x2s=480s: restore now also waits for the chain exit-tail, runs the
# three ksud module events (~60s) and bounces zygote (~40s framework
# restart) -- the old 180s was too tight for that tail.
for _ in $(seq 1 240); do
  # fix76 (redo34): ONLY the OK line counts.  The old `[ -x /product/bin/su ]`
  # fallback matched the overlay restore had already mounted while restore
  # was still running its later steps -- verify raced ahead of the strict
  # block, read enforce=0 and died (false-positive pass).  The overlay is
  # retired as of 2026-11-09; the rule stays because any pre-marker side
  # effect would reintroduce the same race.
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

# --- verify as shell (the driver's sucompat entry: shell uid 2000 is
# allow-listed via CONFIG_KSU_DEBUG, so execve("/system/bin/su") is rewritten
# to the root ksud and yields uid=0 in the u:r:ksu:s0 domain) ---------------
step "verify"
if ! ab shell "/system/bin/su -c id" | grep -q "uid=0"; then
  echo "  [diag] su targets:"
  ab shell "ls -la /data/local/tmp/ksud /data/adb/ksud 2>/dev/null" | sed 's/^/    /' || true
  echo "  [diag] su raw output:"
  ab shell "timeout 8 /system/bin/su -c id 2>&1; echo rc=\$?" | sed 's/^/    /' || true
  echo "  [diag] temp ksud direct:"
  ab shell "timeout 8 sh -c 'echo id | /data/local/tmp/ksud debug su 2>&1' | head -5" | sed 's/^/    /' || true
  echo "  [diag] modules:"
  ab shell "ls /sys/module/ 2>/dev/null | grep -E '^kernelsu|^oplus_check'" | sed 's/^/    /' || true
  echo "  [diag] chain log tail:"
  ab shell "tail -12 $CHAIN_OUT 2>/dev/null" | sed 's/^/    /' || true
  die "/system/bin/su failed (sucompat entry)"
fi
# strict-mode exam criterion (2026-10-25): the restore must leave
# Enforcing on.  restore's own fail-safe reverts to Permissive + WARN on
# channel failure -- that path must fail the round here, never pass.
ENC=$(ab shell "cat /sys/fs/selinux/enforce" | tr -d '\r')
[ "$ENC" = "1" ] || die "SELinux not strict (enforce=$ENC) — see WARN-selinux-strict in restore.log"
# fix81: kernel:s0 cannot exec post-flip, so the su probe lives here now.
# Append the real measurement to restore.log so the STRICT-OK marker's
# probe=host-verify field is backed by an on-log line, automatically.
PROBE_OUT=$(ab shell "/system/bin/su -c id" | tr -d '\r')
ab shell "echo '[host-verify] probe: $PROBE_OUT' >> /data/local/tmp/postlock_restore.log; chmod 0600 /data/local/tmp/postlock_restore.log 2>/dev/null" || true
ab shell "grep -q ^kernelsu /proc/modules" || die "kernelsu.ko not loaded"
if ab shell "getprop wrap.$APP" | grep -q "libgrant"; then
  die "legacy libgrant wrap still set — clear it: setprop wrap.$APP \"\""
fi
# fix77 (redo35 host death): pipefail made this assignment rc=1 when the
# param file read EACCES under enforcing (shell:s0 cannot read it) and set
# -e killed the whole verify silently -- no ERROR, no OK, just "cat:
# Permission denied" as the last line.  Value-empty only triggers the WARN
# below, which is the designed handling.
CUR_MUID=$(ab shell "/system/bin/su -c 'cat /sys/module/kernelsu/parameters/ksu_debug_manager_appid'" | tr -d '\r') || true
if [ -n "$MUID" ]; then
  [ "$CUR_MUID" = "$MUID" ] || echo "WARN: manager param=$CUR_MUID, want $MUID (app fd may be missing)"
else
  echo "INFO: appid param not written (unresolved); driver must crown the manager via track_throne (param=$CUR_MUID)"
fi
echo "OK:"
echo "  $(ab shell "/system/bin/su -c id" | tr -d '\r')"
echo "  $(ab shell "grep ^kernelsu /proc/modules" | tr -d '\r')"
echo "  daemon pid=$(ab shell "cat $TMP/su.pid 2>/dev/null" | tr -d '\r')"
echo "  manager uid=$CUR_MUID  wrap.$APP=$(ab shell "getprop wrap.$APP" | tr -d '\r') (must be empty)"
# pidof rc=1 when the app is not running; pipefail would kill the script
# after all verify steps passed (round 998d4c8d: OK: printed, rc=1).
APID=$(ab shell "pidof $APP 2>/dev/null" | tr -d '\r' | awk '{print $1}' || true)
if [ -n "$APID" ] && ab shell "/system/bin/su -c 'ls -l /proc/$APID/fd 2>/dev/null | grep -q ksu_driver'"; then
  echo "  app fd: [ksu_driver] present (pid $APID)"
else
  echo "  WARN: app fd not confirmed — restart the app if the blue card is missing"
fi
# 版本对齐验收（用户要求：内核驱动版本号必须与管理器完全一致）。
# 内核侧唯一权威来源 = insmod 时打的那行 dmesg；shell 域读 dmesg 被拒，
# 走 su 通道读。KSU_VERSION/KSU_VERSION_FULL 由 make 命令行覆盖注入。
DRV=$(ab shell "/system/bin/su -c 'dmesg | grep -m1 \"Initialized with driver version\"'" | tr -d '\r') || true
echo "  driver: $DRV"
echo
echo "manual check: BakaSU blue card 工作中 Built-in, driver == manager version (v4.2.0-rc3 / 35252 / UAPI 6), 越狱模式 badge expected (真 late load), enforce=1"

# ---------------------------------------------------------------------------
# P2: SUVTZ 观测面回归 (T0 命题 Obs(W) ⊆ Trusted(W) 的持续取证)
#
# 诚实口径: 这**不是** boot hook。PostLock-Boot 已于 2026-11-06 冻结为 legacy,
# 设备上没有任何开机自跑通道; 本段挂在**恢复流程**尾部 —— 本轮 postlock.sh 跑到
# 这里 (即恢复成功) 就顺带产出一份真机观测面快照 + 台账, 让「一次 boot 一次
# 恢复」= 「一次观测面回归」。
#
#   SUVTZ_SCAN=0        关闭本段
#   SUVTZ_SCAN_PKG=xxx  指定 runas 载体 (不设 = scan.sh 自动探测已安装载体)
#   SUVTZ_SCAN_DEFER=0  不挂「等解锁后自动补扫」的后台任务 (默认挂)
#   SUVTZ_SCAN_DEFER_TIMEOUT / _INTERVAL  补扫等解锁的上限(默认 3h)与轮询间隔(30s)
#
# 扫描是旁路观测, 判据全在 scan.sh 里; 这里只在**旁路本身失败**时 WARN,
# 并且绝不影响本脚本退出码 (恢复成功不该被观测工具判死)。
SUVTZ_SCAN_BASE=${SUVTZ_SCAN_BASE:-/tmp/opencode/suvtz}
if [ "${SUVTZ_SCAN:-1}" != "0" ]; then
  step "SUVTZ scan (观测面回归)"
  SCAN_OUT="$SUVTZ_SCAN_BASE/auto_$BOOT8"
  mkdir -p "$SCAN_OUT" 2>/dev/null || true
  # 注意: 不能用 "${ARR[@]}" 直接当前缀 —— bash 只在**解析期**识别 VAR=val 前缀,
  # 展开出来的词会被当成命令名 (实测: "ADB_BIN=/...: 没有那个文件或目录")。
  # 所以显式走 env。
  SCAN_ENV=(env ADB_BIN="$ADB_BIN" OUT="$SCAN_OUT")
  [ -n "${SERIAL:-}" ] && SCAN_ENV+=(SERIAL="$SERIAL")
  [ -n "${SUVTZ_SCAN_PKG+x}" ] && SCAN_ENV+=(PKG="$SUVTZ_SCAN_PKG")
  # 不依赖 pipefail: rc 与最后一行分别从文件取, 旁路失败也能给出原因。
  if "${SCAN_ENV[@]}" bash "$REPO/tools/suvtz/scan.sh" -q \
       > "$SCAN_OUT/stdout.txt" 2> "$SCAN_OUT/stderr.txt"; then
    SCAN_RC=0
  else
    SCAN_RC=$?
  fi
  SCAN_SUM=$(grep -a '^FAIL=' "$SCAN_OUT/stdout.txt" 2>/dev/null | tail -1 | tr -d '\r')
  # scan.sh 用 rc=1 表示「跑完了但有未裁决 FAIL」——扫描成功、结果不好，
  # 台账必须照实记下来（有回归的 boot 恰恰是最该留记录的那一轮）。
  if [ -n "$SCAN_SUM" ] && { [ "$SCAN_RC" = 0 ] || [ "$SCAN_RC" = 1 ]; }; then
    info "suvtz: $SCAN_SUM"
    info "suvtz: report $SCAN_OUT/scan_$BOOT8.txt"
    # app 域整段没测时给一条可操作提示。冷 boot 后设备常还在锁屏 (CE 存储不可用),
    # 那时 runas 段必然全是 INFO——如实告知, 不要让人对着 32 条 INFO 猜。
    # 并且默认挂一个后台补扫: 等设备真正解锁 (run-as 可用) 后自动重跑一次，
    # 把完整快照写进同一目录 + 更新台账 (scan.sh 全是只读探针, 不碰恢复结果)。
    # 只在**确实锁着**时挂: 已经解锁却仍然 runas=no ⇒ 是「没有可调试载体」,
    # 再等也等不来, 补扫纯属白跑。报告头没有该字段(旧版 scan.sh 产物)时按
    # 「可能锁着」处理——后台补扫是无害的, 漏挂才会留下一份只测了 3 项的废快照。
    case "$SCAN_SUM" in
      *runas=no*)
        if grep -q 'device_locked=1' "$SCAN_OUT/scan_$BOOT8.txt" 2>/dev/null; then
          LOCK_STATE=locked
        elif grep -q 'device_locked=0' "$SCAN_OUT/scan_$BOOT8.txt" 2>/dev/null; then
          LOCK_STATE=unlocked
        else
          LOCK_STATE=unknown
        fi
        case "$LOCK_STATE" in
          locked)
            info "suvtz: app 域本次未测 (设备锁屏未解锁) —— runas 段全 INFO 属预期, 不是扫描器坏了"
            ;;
          unknown)
            info "suvtz: app 域本次未测 —— 报告未标明锁屏状态 (疑似旧版产物), 按可能锁屏处理"
            ;;
          *)
            info "suvtz: app 域本次未测 —— 设备已解锁但没有可调试载体 (runas 段记 INFO); 装一个 debuggable 包或用 SUVTZ_SCAN_PKG= 指定"
            ;;
        esac
        if [ "$LOCK_STATE" != unlocked ] && [ "${SUVTZ_SCAN_DEFER:-1}" != "0" ]; then
          DEFER_ARGS=(--outdir "$SCAN_OUT" --adb "$ADB_BIN" --boot8 "$BOOT8"
                      --timeout "${SUVTZ_SCAN_DEFER_TIMEOUT:-10800}"
                      --interval "${SUVTZ_SCAN_DEFER_INTERVAL:-30}"
                      --ledger "$SUVTZ_SCAN_BASE/history.tsv")
          [ -n "${SERIAL:-}" ] && DEFER_ARGS+=(--serial "$SERIAL")
          if [ -n "${SUVTZ_SCAN_PKG+x}" ]; then
            if [ -n "${SUVTZ_SCAN_PKG:-}" ]; then DEFER_ARGS+=(--pkg "$SUVTZ_SCAN_PKG")
            else DEFER_ARGS+=(--no-pkg); fi
          fi
          # 必须 setsid nohup + </dev/null: 普通 nohup & 会随调用方 shell 收尾被组杀。
          setsid nohup bash "$REPO/tools/suvtz/wait_unlock_scan.sh" "${DEFER_ARGS[@]}" \
            </dev/null >/dev/null 2>&1 &
          info "suvtz: 已挂后台补扫 (解锁后自动重跑, 上限 ${SUVTZ_SCAN_DEFER_TIMEOUT:-10800}s, 日志 $SCAN_OUT/defer.log; SUVTZ_SCAN_DEFER=0 关闭)"
        elif [ "$LOCK_STATE" != unlocked ]; then
          info "suvtz: 解锁屏幕后单跑 tools/suvtz/scan.sh 可得完整快照"
        fi
        ;;
    esac
    # 台账: 每 boot 一行, 便于跨轮对比 (同一 boot 重跑则整行替换)。
    LEDGER="$SUVTZ_SCAN_BASE/history.tsv"
    if [ -f "$LEDGER" ]; then
      grep -v "^$BOOT8"$'\t' "$LEDGER" > "$LEDGER.tmp" 2>/dev/null || true
      mv -f "$LEDGER.tmp" "$LEDGER" 2>/dev/null || true
    else
      printf '# boot8\tdate\tfail/pass/info\tsummary\n' > "$LEDGER"
    fi
    printf '%s\t%s\t%s\n' "$BOOT8" "$(date +%F' '%T)" "$SCAN_SUM" >> "$LEDGER"
  else
    echo "WARN: suvtz scan 未产出结果 (rc=$SCAN_RC) —— 旁路观测失败, 恢复结果不受影响"
    tail -2 "$SCAN_OUT/stderr.txt" 2>/dev/null | sed 's/^/  scan: /' || true
  fi
fi
