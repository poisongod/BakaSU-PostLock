#!/system/bin/sh
# Post-root persistence tail, executed by the detached insmod helper
# (uid0, setsid, PDEATHSIG=0) AFTER finit_module succeeds.  Failures are
# logged but never fatal: the chain contract (root=1 + driver Live) is
# already settled before this script runs.
#
# v6 (2026-10-18): PROBE-DRIVEN key surgery.  v5 unconditionally ran the
# full CE-deadlock rescue (rm spblob/keystore/vold keys -> create/unlock
# -> am restart); on a fresh wiped device with HEALTHY keys this sequence
# destroyed a working CE keypair (vold key rebuilt but keystore keyblobs
# deleted) and the following am restart sent the device straight into
# recovery (TWICE).  Now every destructive step is gated behind a health
# probe: vold ce/0/current key present AND user 0 RUNNING_UNLOCKED =>
# skip all key surgery and am restart entirely; only install + verify run.
LOG=/data/local/tmp/post_root.log
exec >> "$LOG" 2>&1
echo "== post_root start $(date) =="

# v23: ocs SILENCER FIRST (before anything else touches userspace).
#     ocsk.ko is built against this exact kernel (kheaders utsrelease
#     5.4.254-qgki-g977b99b1fbb9 + OPPO-tree KDIR; anchor-verified at
#     load: str x30,[x18]@entry / ret@+0x14c) and registers a kprobe on
#     oplus_root_check_succ that sets x0=0 and jumps straight to the
#     shared ret epilogue (prologue never ran -> sp/x29/x30 all
#     balanced).  From this point the detector always reports "no
#     escalation": the OPLUS_ROOT_CHECK kill chain (libksud/ksud SIGKILL)
#     and the "security warning" popup both stem from its verdict.
#     Rounds 44/45/46 proved .text is unreachable from user primitives
#     (configfs read AND pipe-physmap write both panic) -> kernel-side
#     kprobe is the only remaining path.
if [ -f /data/local/tmp/ocsk.ko ] && [ -x /data/local/tmp/home/finitmod_v2 ]; then
    # v28 (v7 module): boot 0e62a8cf proved ocs_init NEVER runs on this
    # kernel (preset state=PREINIT/entry_addr=4242 survived a rc=0 load;
    # root cause: this KDIR's struct module is 64B smaller than the
    # kernel's -- .init rela @0x178 vs kernelsu's @0x180, so the kernel
    # reads NULL at its own offset 0x180 and skips init silently).
    # v7 therefore registers the probes from an arm= module_param SETTER,
    # which parse_args() runs inside load_module() BEFORE the never-
    # reached do_init_module() -- the same channel the preset experiment
    # already proved works.
    /data/local/tmp/home/finitmod_v2 /data/local/tmp/ocsk.ko 0 arm=1 >/dev/null 2>&1
    echo "ocsk finitmod arm=1 rc=$? (verdict in dmesg: 'ocsk: ... silenced')"
    echo "--ocsk-verify--"
    grep -a ocsk /proc/modules
    # v26: +state (v6c param_string channel -- the full load-time trace:
    #     ret.entry/entry/kill.word.before/ret.kill/kill.word.after).
    for p in hits last_pc entry_addr state arm; do
        echo "param.$p=$(cat /sys/module/ocsk/parameters/$p 2>&1)"
    done
    echo "ko.sha1=$(sha1sum /data/local/tmp/ocsk.ko | cut -c1-8)"
    dmesg 2>/dev/null | grep -a ocsk | tail -4 || echo "dmesg ocsk: (silent)"
    # (v27 preset-param reload experiment concluded on boot 0e62a8cf:
    #  PREINIT survived => init never ran; v7 must NOT be rmmod'd -- a
    #  registered kprobe pointing into unloaded module text would oops.)
else
    echo "ocsk MISSING: ko=$([ -f /data/local/tmp/ocsk.ko ] && echo yes || echo no) finitmod_v2=$([ -x /data/local/tmp/home/finitmod_v2 ] && echo yes || echo no)"
fi

# v24: ocs forensics.  This kernel drops module-side KERN_INFO from dmesg
#     (init pr_info never appeared despite rc=0), so the verdict must come
#     from files.  Grab the kprobe registration state + every root_check
#     related symbol right after load: round 50's kprobe registered Live
#     but the kevent payload/Kill path still fired -- either a symbol
#     clone bypasses the probe (visible here) or the Kill path is
#     independent of ocs (told apart later by /sys/module/ocsk/hits).
echo "--ocsk-forensics--"
[ -d /sys/kernel/debug/kprobes ] || mount -t debugfs none /sys/kernel/debug 2>/dev/null
head -6 /sys/kernel/debug/kprobes/list 2>/dev/null || echo "kprobes/list: n/a"
grep -E "root_check|kevent" /proc/kallsyms > /data/local/tmp/rc_syms 2>&1
echo "rc_syms lines=$(wc -l < /data/local/tmp/rc_syms) sample:"
head -8 /data/local/tmp/rc_syms


# v8: PSTORE DUMP (panic forensics).  Shell (2000) gets EACCES on
#     /sys/fs/pstore, so oops traces from early-panic rounds are only
#     reachable from this uid0 helper.  Grab everything BEFORE any
#     later step might reset anything.
# v14: full byte-exact export FIRST.  The round-29 evidence chain
#     (OPLUS_ROOT_CHECK kill x5 at uptime 502.5s -> panic at ~650s)
#     puts the killer's context minutes BEFORE the panic point; the old
#     `tail -c 8000 | tail -60` summary loses exactly that window.
#     Next panic overwrites pstore, so copy before anything else runs.
mkdir -p /data/local/tmp/pstore
rm -f /data/local/tmp/pstore/* 2>/dev/null
echo "--pstore--"
ls -la /sys/fs/pstore/ 2>&1 | head -10
for f in /sys/fs/pstore/console-ramoops* /sys/fs/pstore/dmesg-ramoops* \
         /sys/fs/pstore/pmsg-ramoops*; do
  [ -f "$f" ] && {
    bn=$(basename "$f")
    cat "$f" > "/data/local/tmp/pstore/$bn" 2>/dev/null
    echo "-- $f saved=$(wc -c < "/data/local/tmp/pstore/$bn" 2>/dev/null) --"
    tail -c 8000 "$f" 2>&1 | tail -60
  }
done
echo "--endpstore--"
echo "pstore-exports: $(ls /data/local/tmp/pstore 2>/dev/null | wc -l)"

# 0. REAL permissive attempts + channel probes.  Facts so far: the chain's
#    kernel-memory write fools /sys/fs/selinux/enforce only (avc keeps
#    enforcing: permissive=0 with enforce=0); shell setenforce = EACCES;
#    adb root refused; /data is nosuid (no setuid helper).  Channels to try:
#      A) kernel-domain setenforce (sysfs write => enforcing_update syncs
#         the avc path too) -- errors NOT swallowed this time,
#      B) /sys/fs/selinux/disable (one-shot, may be rejected when initialized),
#      C) runcon u:r:shell:s0 -- shell domain has find-mount rules and uid0
#         clears STORAGE_INTERNAL; needs a kernel->shell transition rule.
setenforce 0; echo "setenforce-rc=$?"
echo 1 > /sys/fs/selinux/disable 2>/dev/null; echo "disable-rc=$?"
logcat -b all -c 2>/dev/null
# v10: NEVER call mount:65 here.  The old "direct-probe" used
#      `service call mount 65 i32 0` == lockUserKey(0); it evicted user 0's
#      fscrypt key within seconds of every post_root start (vold log:
#      "fscrypt_lock_user_key 0" / "Evicted fscrypt key ... from /data"),
#      which is the single root cause behind every post-chain app crash
#      (IOException on mkdirs, failed-to-attach/start-timeout).  Probe
#      service reachability with the side-effect-free `service check`.
echo "direct-probe: $(service check mount 2>&1 | head -2 | tr -d '\r\n')"
echo "direct-avc: $(logcat -d -b all 2>/dev/null | grep -c 'avc:')"
SC=""
R2=$(runcon u:r:shell:s0 /system/bin/id -Z 2>&1 | head -1 | tr -d '\r\n')
echo "runcon-id: $R2"
case "$R2" in
  *shell*)
    R3=$(runcon u:r:shell:s0 /system/bin/service check mount 2>&1 | head -1 | tr -d '\r\n')
    echo "runcon-check-mount: $R3"
    case "$R3" in
      *found*) SC="runcon u:r:shell:s0";;
    esac
    ;;
esac
echo "channel: ${SC:-none}"
echo "vold-iface: $($SC service call vold 1598968905 2>&1 | head -2 | tr -d '\r\n')"

# 0. Environment diagnostics: the first run showed every binder-based cmd
#    (pm/am/cmd/locksettings) failing with "Can't find service" while
#    system_server was healthy, and screencap SIGSEGV'd.  File ops worked.
#    Capture the helper's identity so the next run pins the cause.
echo "--diag--"
id
echo "path=$PATH"
cat /proc/self/attr/current 2>&1
getenforce 2>&1
ls -l /dev/binder /dev/binderfs 2>&1 | head -3
echo "environ:"
tr '\0' '\n' < /proc/self/environ 2>/dev/null | grep -E '^(LD_|KS_|PATH|ANDROID)' | head -10
echo "--endiag--"

# 1. CE HEALTH PROBE (v6 gate).  Healthy = the vold-managed user-0 CE key
#    directory exists with its key blob AND user 0 is RUNNING_UNLOCKED
#    (fresh-wipe state).  Either missing => we are in the CE-deadlock
#    scenario and the v5 rescue sequence below is allowed to run.
echo "ce probe: $(ls /data/user/0/ 2>&1 | head -3)"
echo "ce probe2: $(ls /data/user/0/com.android.shell 2>&1 | head -2)"
echo "voldkeys: $(ls -R /data/misc/vold/user_keys/ 2>&1 | head -12)"
STATE_LINE=$($SC dumpsys user 2>/dev/null | grep -m1 'State:')
CE_OK=0
[ -e /data/misc/vold/user_keys/ce/0/current/keymaster_key_blob ] && CE_OK=1
UNLOCK_OK=0
case "$STATE_LINE" in
  *UNLOCKED*) UNLOCK_OK=1;;
esac
echo "v6-probe: ce_key=$CE_OK unlock=$UNLOCK_OK state=[$STATE_LINE]"

if [ "$CE_OK" = "1" ] && [ "$UNLOCK_OK" = "1" ]; then
  echo "v6: CE HEALTHY -- skipping ALL key surgery (spblob/keystore/vold/create/unlock/am-restart)"
else
  echo "v6: CE BROKEN -- running v5 rescue sequence"

  # 1a. Credential wipe (pure file ops, no binder): the PIN db was already
  #     removed on an earlier round, but keyguard still demanded "reboot to
  #     enter password" and CE storage stayed locked.  The synthetic-password
  #     blobs in /data/system_de/0/spblob keep the credential alive -- wipe
  #     them so the NEXT boot comes up credential-free with CE unlocked.
  rm -f /data/system/locksettings.db /data/system/locksettings.db-shm \
         /data/system/locksettings.db-wal /data/system/locksettingsbackup.db* \
         /data/system/password.key /data/system/gesture.key
  echo "spblob before: $(ls /data/system_de/0/spblob/ 2>&1 | head -3)"
  rm -f /data/system_de/0/spblob/* 2>/dev/null
  echo "spblob after: $(ls /data/system_de/0/spblob/ 2>&1 | head -3)"
  # The real CE lock: keyblobs under /data/misc/keystore/user_0 are bound to
  # the OLD credential, so LockSettingsService's clearUserKeyAuth hits
  # IVold/keystore "Device is locked" and user 0 never unlocks.
  echo "keystore before: $(ls /data/misc/keystore/user_0/ 2>&1 | wc -l)"
  rm -f /data/misc/keystore/user_0/* 2>/dev/null
  echo "keystore after: $(ls /data/misc/keystore/user_0/ 2>&1 | wc -l)"
  # CE KEY RECOVERY: vold's unlockUserKey has NO create branch, so deleting
  # /data/misc/vold/user_keys/ce leaves user 0 RUNNING_LOCKED forever.  The
  # ONLY fix is a fresh createUserKey + unlockUserKey with EMPTY auth.  NEVER
  # wipe these dirs unless the probe above says the key is already broken.
  # OPPO IStorageManager code map (measured 2026-10-18):  mount:62=
  # createUserKey, mount:64=unlockUserKey, mount:63=DESTROYUserKeys (never
  # call it), mount:65=lockUserKey.  Only mount via runcon works (vold find
  # denied in every domain).  create() refuses when the ce/0 dir exists even
  # if empty, so rm first.
  rm -rf /data/misc/vold/user_keys/ce/0 2>/dev/null
  logcat -b all -c 2>/dev/null
  echo "create: $($SC service call mount 62 i32 0 i32 0 i32 0 2>&1 | head -1 | tr -d '\r\n')"
  echo "ce0: $(ls -la /data/misc/vold/user_keys/ce/0/ 2>&1 | head -5)"
  echo "unlock: $($SC service call mount 64 i32 0 i32 0 i32 0 i32 0 2>&1 | head -1 | tr -d '\r\n')"
  echo "vold-after: $(logcat -d -b all 2>/dev/null | grep -a vold | grep -av Brightness | tail -4 | tr '\n' ';')"
  echo "state-after-unlock: $($SC dumpsys user 2>/dev/null | grep -E 'State:|Unlock time' | tr '\n' ';')"

  # 1b. PMS session pipeline cleanup: frozen commit sessions resurrect
  #     across reboots via stageDirs, install_sessions/*.xml, and content
  #     matches.  Wipe all three sources (deadlock-scenario only).
  echo "vmdl before: $(ls -d /data/app/vmdl*.tmp 2>&1 | wc -l)"
  rm -rf /data/app/vmdl*.tmp 2>/dev/null
  echo "vmdl after: $(ls -d /data/app/vmdl*.tmp 2>&1 | wc -l)"
  echo "isess before: $(ls /data/system/install_sessions/ 2>&1 | wc -l)"
  rm -rf /data/system/install_sessions/* 2>/dev/null
  echo "isess after: $(ls /data/system/install_sessions/ 2>&1 | wc -l)"
  for s in 854877074 1330188180 1287572191; do
    for f in $(grep -rls "$s" /data/system /data/system_ce /data/system_de \
               /data/misc_ce /data/misc_de /data/misc 2>/dev/null | head -10); do
      echo "content-hit: $f"
      rm -f "$f" 2>/dev/null
    done
  done
  find /data \( -path /data/local -o -path /data/media -o -path /data/app \) -prune -o -name 'vmdl*' -print -exec rm -rf {} + 2>/dev/null

  # 1c. package-restrictions.xml holds a per-user DISABLED leftover (ABX
  #     binary) that resolves every component of the app to null ("Error
  #     type 3").  Delete it; PMS recreates fresh on next boot.
  F=/data/system/users/0/package-restrictions.xml
  echo "restrictions before: $(grep -c resukisu "$F" 2>/dev/null) (ABX binary)"
  rm -f "$F" /data/system/users/0/package-restrictions-backup-oplus.xml 2>/dev/null
  echo "restrictions deleted: $(ls "$F" 2>&1 | head -1)"

  # 1d. Soft-reboot the framework so system_server re-runs finishUserBoot
  #     against the REBUILT key (ctl.restart denied for every domain, so
  #     `am restart` is the only channel).  Never run this on healthy CE --
  #     it was the recovery trigger on fresh devices together with the key
  #     surgery above.
  echo "locksettings clear skipped (key-recovery mode)"
  $SC am restart 2>&1 | head -1
  echo "am-restart issued $(date)"
  sleep 55
  echo "state-after-softreboot: $($SC dumpsys user 2>/dev/null | grep -E 'State:|Unlock time' | tr '\n' ';')"
fi

# 2. APK insurance: drop a pristine base.apk where PMS's BOOT-TIME directory
#    scan will find it (works even while a frozen commit session blocks
#    pm-install).  Harmless on healthy CE; the normal pm install below is
#    the primary path.
if [ -f /data/local/tmp/resu.apk ]; then
  rm -rf /data/app/resukisu_stage
  mkdir -p /data/app/resukisu_stage
  cp /data/local/tmp/resu.apk /data/app/resukisu_stage/base.apk
  chown system:system /data/app/resukisu_stage /data/app/resukisu_stage/base.apk
  chmod 755 /data/app/resukisu_stage
  chmod 644 /data/app/resukisu_stage/base.apk
  chcon u:object_r:apk_data_file:s0 /data/app/resukisu_stage /data/app/resukisu_stage/base.apk
  echo "staged: $(ls -l /data/app/resukisu_stage/ 2>&1 | tail -2)"
fi

# 3. Reinstall the manager app as root (timeout-bounded, never fatal).
if [ -f /data/local/tmp/resu.apk ]; then
  timeout 90 $SC pm install -r /data/local/tmp/resu.apk
  echo "install rc=$?"
else
  echo "resu.apk missing"
fi
$SC pm path com.resukisu.resukisu

echo "restarting systemui"
$SC am force-stop com.android.systemui
sleep 3
$SC wm dismiss-keyguard

# 4. Driver state (finit_module result from the insmod helper).
echo "modules: $(grep -E 'kernelsu' /proc/modules 2>&1 | head -2)"
echo "driver: $(ls /sys/module/kernelsu 2>&1 | head -2)"

# 4b. CE data-dir BAILOUT (v7): installd's createAppData has been skipping
#     the CE dir for this package while building the DE one (12:09 log:
#     restorecon ran on /data/user_de/0/<pkg>/cache, CE missing forever).
#     The app then crashes on first launch with mkdir ENOENT on its own
#     files/datastore path.  Hand-build the top dir as root with the
#     package's CURRENT uid (re-read from PMS -- uid rotates across
#     reinstall) and the same SELinux category installd put on the DE dir
#     (same uid => same category).  Children (files/, shared_prefs/,
#     datastore/) are created by the app itself once the top dir exists.
# v11: DROP the unconditional nuke (v9).  Timeline proof: with a MISSING
#      top dir the app aborts (SIGABRT) within ~60ms of zygote fork --
#      before attach (crash_dump sees kDebuggerdAnyIntercept, AMS logs
#      "failed to attach"/"start timeout"); with the dir present the app
#      attaches fine all the way to Java (19-round IOException happened
#      only because the v6+ mount:65 probe had evicted the CE key; v10
#      removed that probe).  So: never delete the data dir.  Keep only
#      the v7 hand-built fallback for the dir-missing case.
PKG=com.resukisu.resukisu
PUID=$($SC dumpsys package "$PKG" 2>/dev/null | grep -m1 -oE 'userId=[0-9]+' | cut -d= -f2)
[ -n "$PUID" ] || PUID=10279
if [ ! -d "/data/data/$PKG" ]; then
  CAT=$(ls -Zd "/data/user_de/0/$PKG" 2>/dev/null | grep -oE 'app_data_file:s0[^ ]*')
  case "$CAT" in
    app_data_file:s0*) ;;
    *) CAT="app_data_file:s0";;
  esac
  mkdir -p "/data/data/$PKG" 2>&1
  chown "$PUID:$PUID" "/data/data/$PKG" 2>&1
  chmod 700 "/data/data/$PKG" 2>&1
  chcon "u:object_r:$CAT" "/data/data/$PKG" 2>&1
  echo "data-dir hand-built uid=$PUID label=$CAT -> $(ls -lad "/data/data/$PKG" 2>&1)"
else
  echo "data-dir present (untouched): $(ls -lad "/data/data/$PKG" 2>&1)"
fi

# 4c. Register the manager uid (v12): finitmod takes the else branch of
#     kernelsu_init (module_load_filter line in dmesg => ksu_late_loaded
#     path not taken) so neither track_throne() nor on_post_fs_data()
#     ever runs -> ksu_manager_appid_list stays EMPTY.  zygote's setuid
#     hook only calls ksu_install_fd() when uid is allow && manager, so
#     the app never receives a [ksu_driver] fd (red card "no driver
#     detected" while /proc/modules shows Live).  Writing the official
#     CONFIG_KSU_DEBUG module param fires ksu_register_manager() in its
#     set callback.  Must precede the am restart below -- the fd is
#     handed out at zygote specialize time, not on app's own request.
echo "$PUID" > /sys/module/kernelsu/parameters/ksu_debug_manager_appid 2>&1
echo "debug-manager-uid: rc=$? value=$PUID"
sleep 1
echo "dmesg-reg: $(dmesg 2>/dev/null | grep -E 'ksu_manager_appid set to' | tail -1)"

# 4d. OPLUS_ROOT_CHECK kill forensics (v13, round 28): every GRANT_ROOT
#     (91/91 in dmesg) is SIGKILLed ~2.6ms after setup_selinux by
#     "[OPLUS_ROOT_CHECK]:Kill the process of escalation..." -- in-kernel,
#     comm still libksud, no execve-sh kevent => dies around commit_creds.
#     Shell repro: `libksud debug su` => `allow root for: 2000` then
#     RC=137.  Register kprobes on the exported guard symbols + a
#     sig==9 signal_generate stacktrace BEFORE the am start below (the
#     app self-check runs `debug su` in a loop and gets killed), then
#     harvest the killer's call stack after it.  Skip deleting foreign
#     probes (kvfy may linger): only drop our own names on rerun.
TP=/sys/kernel/tracing
echo '-ocs' >> $TP/kprobe_events 2>/dev/null
echo '-seb' >> $TP/kprobe_events 2>/dev/null
# v19: round38 root cause of the empty kprobes list was simpler than %pK
#    zeroing -- /sys/kernel/debug/kprobes simply did not exist because
#    debugfs was never mounted (ls: "No such file or directory").  Mount
#    it as root first; if the list prints real addresses (%px) we get the
#    ocs probe address without needing any hit or fetch field.
# v19 tried mkdir /sys/kernel/debug first -- sysfs does not support mkdir
#    (rc=1, swallowed), so debugfs never got a mountpoint. v20 mounts it
#    under /data/local/tmp/dbg instead; if kprobes/list prints %px we win,
#    if it prints %pK zeros (kptr_restrict=2) we fall back to bootdump.
mkdir -p /data/local/tmp/dbg 2>/dev/null
mount -t debugfs debugfs /data/local/tmp/dbg 2>/dev/null && echo "debugfs: mounted" || echo "debugfs: mount rc=$?"
# v18 fetch-matrix results: every DEREF form ("+0(pc)", "+0(elr)") was
#    rejected -- arm64 regs_query_register_offset either lacks those names
#    or deref-of-pc is invalid; "$stack0" worked but yields stack data
#    (round38 harvested ffffffc029aabe70, a vmalloc stack addr BELOW text
#    base, which the chain-side hip>htext guard rightly rejected).
#    v19 tries BARE register names first: bare "pc" at the brk exception
#    IS the probe address if the regname table has it.
ok_field=""
errf=/data/local/tmp/kpe_err.txt
for spec in 'adr=pc' 'pc=pc' 'adr=elr' 'adr=+0(pc)' 'adr=+0(elr)' 'adr=$stack0'; do
  echo '-ocs' >> $TP/kprobe_events 2>/dev/null
  echo "p:ocs oplus_root_check_succ $spec" > $TP/kprobe_events 2>$errf
  rc=$?
  if [ $rc -eq 0 ]; then
    ok_field=${spec%%=*}
    echo "kp-ocs: ok($spec)"
    break
  fi
  echo "kp-ocs: reject($spec): $(tr '\n' ' ' < $errf | cut -c1-140)"
done
if [ -z "$ok_field" ]; then
  echo '-ocs' >> $TP/kprobe_events 2>/dev/null
  if echo 'p:ocs oplus_root_check_succ' > $TP/kprobe_events 2>$errf; then
    echo "kp-ocs: ok(plain)"
  else
    echo "kp-ocs: FAIL: $(tr '\n' ' ' < $errf | cut -c1-140)"
  fi
fi
echo "$ok_field" > /data/local/tmp/ocs_fetch_field
{
  echo "--- ls:"; ls -la /data/local/tmp/dbg/kprobes/ 2>&1 | head -6
  echo "--- cat:"; cat /data/local/tmp/dbg/kprobes/list 2>&1 | head -8
  echo "--- mounts:"; grep -w debugfs /proc/mounts 2>&1
} > /data/local/tmp/ocs_list_diag 2>&1
echo "kprobes-list-diag bytes=$(wc -c < /data/local/tmp/ocs_list_diag)"
grep -a oplus_root_check_succ /data/local/tmp/ocs_list_diag 2>/dev/null | head -1 | sed 's/^/kprobes-list: /'
echo 'p:seb oplus_exec_block' >> $TP/kprobe_events && echo "kp-seb: ok" || echo "kp-seb: FAIL $?"
echo 'stacktrace' > $TP/events/kprobes/ocs/trigger 2>/dev/null && echo "kp-ocs-stack: ok" || echo "kp-ocs-stack: FAIL"
echo 'stacktrace' > $TP/events/kprobes/seb/trigger 2>/dev/null
echo 'sig == 9' > $TP/events/signal/signal_generate/filter 2>/dev/null && echo "sig9-filter: ok" || echo "sig9-filter: FAIL"
echo 'stacktrace' > $TP/events/signal/signal_generate/trigger 2>/dev/null
echo > $TP/trace
echo 1 > $TP/events/kprobes/enable 2>/dev/null
echo 1 > $TP/events/signal/signal_generate/enable 2>/dev/null
echo 1 > $TP/tracing_on

# v15: the chain now patches oplus_root_check_succ (mov w0,#0; ret) as its
#    first act after sig_enforce and writes this flag only on verified
#    read-back. The app self-check below SIGKILLs libksud the instant it
#    flips uid unless that patch is in place (red-card root cause), so
#    wait for it. Chain-side patch failure shows as MISSING after 10s --
#    proceed anyway so the probes above still capture the kills.
oplus_flag=/data/local/tmp/.oplus_patched
i=0
while [ ! -f "$oplus_flag" ] && [ $i -lt 50 ]; do i=$((i+1)); sleep 0.2; done
if [ -f "$oplus_flag" ]; then
  echo "oplus-patched: $(cat "$oplus_flag")"
else
  echo "oplus-patched: MISSING (chain patch absent, self-check may be killed)"
fi

# 5. Bring the manager to the foreground and snapshot the status card.
#    The first am start after the data-dir nuke triggers prepareAppData
#    rebuild; give it a beat, then verify the process actually lives.
$SC am start -n com.resukisu.resukisu/org.bakasu.bakasu.ui.MainActivity
sleep 6
echo "app-pid-after-rebuild: $(pidof $PKG 2>/dev/null || ps -A -o PID,UID 2>/dev/null | awk -v u=$PUID '$2==u{print $1; exit}')"
echo "driver-fd: $(dmesg 2>/dev/null | grep -E 'ksu fd installed|install fd for ksu manager' | tail -2 | tr '\n' '|')"
echo "app-crash: $(logcat -d -b crash 2>/dev/null | grep -a $PKG | tail -1 | cut -c1-160)"
# v13: harvest kill-caller stacks from the self-check's `debug su` runs.
sleep 1
echo 0 > $TP/tracing_on 2>/dev/null
cat $TP/trace > /data/local/tmp/ocs_trace.txt 2>/dev/null
echo "ocs-trace-bytes: $(wc -c < /data/local/tmp/ocs_trace.txt 2>/dev/null)"
grep -aE "ocs:|seb:|signal_generate" /data/local/tmp/ocs_trace.txt 2>/dev/null | head -8
grep -aA9 -E "<- ocs|<-\s+ocs|oplus_root_check_succ|signal_generate" /data/local/tmp/ocs_trace.txt 2>/dev/null | head -45
# v20: deterministic fallback harvest -- dump the boot partition so the
#    host can extract kallsyms offline (static file, immune to runtime
#    kptr_restrict/SELinux). Host writes back ip=<link addr of
#    oplus_root_check_succ> text=<link addr of _text>; the difference is
#    the KASLR-invariant offset the chain-side guard (hip>htext, <64MB)
#    already validates.
BOOTDEV=$(ls -l /dev/block/by-name/boot_a 2>/dev/null | awk '{print $NF}')
[ -z "$BOOTDEV" ] && BOOTDEV=$(ls -l /dev/block/by-name/boot 2>/dev/null | awk '{print $NF}')
if [ -n "$BOOTDEV" ]; then
  dd if="$BOOTDEV" of=/data/local/tmp/bootdump.img bs=1048576 2>/dev/null
  echo "bootdump: $(wc -c < /data/local/tmp/bootdump.img 2>/dev/null) bytes from $BOOTDEV"
else
  echo "bootdump: FAIL no boot partition"
fi
# v16: persist the detector address as a slide-independent offset. The
#    ocs probe carries ip=$ip, so each self-check hit line reads
#    "oplus_root_check_succ+0x0/0x24c) ip=0x<abs>". off=ip-text is
#    KASLR-invariant; the chain reads /data/local/tmp/ocs_sym_off on its
#    next fresh boot and patches with its own kaslr_base+off (its own
#    kptr_restrict rewrite dies on the proc_security SELinux deny, and
#    toybox sh can't do the 64-bit subtraction -- chain side is C).
# v17 harvest, two sources: (1) the ip= fetch field in trace hits (hex,
#    with or without 0x), (2) the debugfs kprobes list address (available
#    right after registration, no hit needed). Chain side does the 64-bit
#    subtraction (toybox sh truncates kernel addresses to 32 bits).
field=$(cat /data/local/tmp/ocs_fetch_field 2>/dev/null)
ocs_ip=""
# v20: $stack0 is a stack-slot fetch -- at the brk exception its first word
#    is vmalloc stack data (round38/39 both landed ffffffc0... below text
#    base), never the probe address itself. Skip that source entirely.
if [ -n "$field" ] && [ "$field" != "stack0" ]; then
  ocs_ip=$(grep -aoE "${field}=0?x?[0-9a-f]{8,16}" /data/local/tmp/ocs_trace.txt 2>/dev/null | head -1 | sed -E "s/^${field}=0?x?//")
fi
if [ -z "$ocs_ip" ]; then
  ocs_ip=$(grep -a 'oplus_root_check_succ' /data/local/tmp/ocs_list_diag 2>/dev/null | grep -aoE '0?x?f[0-9a-f]{11,15}' | head -1 | sed 's/^0x//')
fi
# text addresses never start with ffffffc0/c1 (vmalloc); reject stack junk
# even if a source above slipped one through.
case "$ocs_ip" in
  ffffffc0*|ffffffc1*) echo "ocs-harvest: rejected vmalloc-stack value '$ocs_ip'"; ocs_ip="" ;;
esac
kaslr_text=$(sed -n 's/.* text=\([0-9a-f]\{8,\}\).*/\1/p' /data/local/tmp/ksu_kaslr 2>/dev/null | head -1)
if [ -n "$ocs_ip" ] && [ -n "$kaslr_text" ]; then
  echo "ip=$ocs_ip text=$kaslr_text" > /data/local/tmp/ocs_sym_off
  echo "ocs-harvest: $(cat /data/local/tmp/ocs_sym_off)"
else
  echo "ocs-harvest: FAIL ip='$ocs_ip' text='$kaslr_text'"
fi
echo 0 > $TP/events/kprobes/enable 2>/dev/null
echo 0 > $TP/events/signal/signal_generate/enable 2>/dev/null
sleep 2
$SC dumpsys window | grep mCurrentFocus
# screencap under runcon: bare screencap SIGSEGV'd under the kernel domain.
$SC screencap -p /data/local/tmp/ksu_screen.png 2>&1 | head -2
echo "screencap bytes=$(wc -c < /data/local/tmp/ksu_screen.png 2>/dev/null)"
uiautomator dump /data/local/tmp/ksu_ui.xml >/dev/null 2>&1
# v22: ocsk.ko route prerequisites -- rounds 45/46 proved .text is
#    unreachable through BOTH primitives (phys-probe write dies on linear
#    RO; configfs dies on the KIMAGE RX mapping), while .data writes stay
#    green all round.  The kernel itself may poke .text via kprobes (r41
#    tracefs registration on oplus_root_check_succ worked), so the plan
#    is a tiny LKM: register_kprobe(addr=kallsyms lookup) with pre_handler
#    setting regs->x0=0 and returning 1 (skip the detector, caller reads
#    x0=0 = "no escalation").  IKHEADERS=y gives the exact build tree.
cp /sys/kernel/kheaders.tar.xz /data/local/tmp/kheaders.tar.xz 2>/dev/null \
  && echo "kheaders: $(wc -c < /data/local/tmp/kheaders.tar.xz) bytes" \
  || echo "kheaders: FAIL rc=$?"
echo "uname: $(uname -r)"
mount -t debugfs debugfs /data/local/tmp/dbg2 2>/dev/null && echo "dbg2: mounted" || echo "dbg2: mount rc=$?"
FF=""
ls /data/local/tmp/dbg2/fail_function/ >/dev/null 2>&1 && FF=/data/local/tmp/dbg2/fail_function
ls /sys/kernel/debug/fail_function/ >/dev/null 2>&1 && FF=/sys/kernel/debug/fail_function
if [ -n "$FF" ]; then
  echo "fail_function entries: $(ls "$FF" | tr '\n' ' ')"
  echo oplus_root_check_succ > "$FF/inject" 2>&1 && echo "failfn-inject: OK (ocs IS error-injectable!)" \
    || echo "failfn-inject: $(cat "$FF/inject" 2>/dev/null; echo rc=$?)"
else
  echo "fail_function: unavailable"
fi
echo "== post_root done $(date) =="
# v25b: DELAYED ocsk effect check -- by now the manager app was started
#     (am start above) and the detector has had time to fire.  Expect:
#       hits>0            = v5 kill-bl probe actually triggers (rounds
#                          50/53 entry-probe stayed 0 because the kill
#                          logic lives in a cold tail entered by mid-body
#                          branches, never through the symbol entry)
#       ksud alive        = force_sig no longer kills it (root=1 means
#                          the chain installed ksud; it was dead by OPPO
#                          Kill in every prior round)
#       kill count stable = dmesg "Kill the process" lines stop growing
sleep 12
echo "--ocsk-verify-late--"
echo "hits=$(cat /sys/module/ocsk/parameters/hits 2>&1) last_pc=$(cat /sys/module/ocsk/parameters/last_pc 2>&1)"
echo "kill-lines=$(dmesg 2>/dev/null | grep -acE 'Kill the process')"
ps -A -o PID,ARGS 2>/dev/null | grep -a ksud | grep -av grep | head -3 || true
echo "(ksud lines above; empty = dead)"
echo "final-state: $($SC dumpsys user 2>/dev/null | grep -E 'State:|Unlock time' | tr '\n' ';')"
