#!/system/bin/sh
exec >> /data/local/tmp/postlock_restore.log 2>&1
echo "== restore start $(date) pid=$$ uid=$(id -u)"
id
ls -ld /data /data/local /data/local/temp 2>&1 || true
getenforce 2>/dev/null || true
set -e
mkdir -p /data/local/temp
chcon u:object_r:shell_data_file:s0 /data/local/temp
chmod 777 /data/local/temp
echo 262144 > /proc/sys/fs/pipe-user-pages-soft
# rm-before-cp: a rerun copies over binaries the previous run left running
# (su daemon executes /data/local/temp/su) -> cp hits ETXTBSY and set -e aborts
# mid-script. unlink-then-copy is always safe: the old process keeps its
# unlinked inode, and the daemon/app restart below pick up the fresh file.
for f in kernelsu.ko finitmod ocsk.ko su preload.so; do
  rm -f /data/local/temp/$f
  cp /data/local/tmp/ksu_boot/$f /data/local/temp/$f
done
chmod 755 /data/local/temp/kernelsu.ko /data/local/temp/finitmod /data/local/temp/ocsk.ko /data/local/temp/su /data/local/temp/preload.so
if grep -q ^kernelsu /proc/modules; then echo driver-already-loaded; else /data/local/temp/finitmod /data/local/temp/kernelsu.ko 0 || echo WARN-finitmod-failed; fi
# ocsk: silence the OPPO oplus_root_check_succ kill path BEFORE the app
# restarts below -- without it libksud.so setuid(0) trips the detector
# and force_sig kills the app (round 60 verified 61/61 kills intercepted).
# WARN-only: sig_enforce is 0 on this boot because the chain just ran.
if grep -q ^ocsk /proc/modules; then echo ocsk-already-loaded; else /data/local/temp/finitmod /data/local/temp/ocsk.ko 0 arm=1 || echo WARN-ocsk-finitmod-failed; fi
# register the manager appid so zygote setresuid installs the
# [ksu_driver] fd for the manager (CONFIG_KSU_DEBUG param; must
# precede the app start)
if [ -w /sys/module/kernelsu/parameters/ksu_debug_manager_appid ]; then
  echo 10279 > /sys/module/kernelsu/parameters/ksu_debug_manager_appid
fi
[ -f /data/local/temp/su.allow ] || { echo 10282 > /data/local/temp/su.allow; echo 10283 >> /data/local/temp/su.allow; echo 2000 >> /data/local/temp/su.allow; }
chmod 666 /data/local/temp/su.allow
# --- adb-loopback bootstrap (idempotent; mirrors tools/postlock.sh) ------
if ! grep -qF postlock_bootstrap /data/misc/adb/adb_keys 2>/dev/null; then
  cat /data/local/tmp/ksu_boot/postlock_adbkey.pub >> /data/misc/adb/adb_keys || echo WARN-adb-keys-append
  chmod 640 /data/misc/adb/adb_keys || true
  chown root:shell /data/misc/adb/adb_keys || true
fi
if ! grep -qF persist.adb.tcp.port /data/property/persistent_properties 2>/dev/null; then
  cat /data/local/tmp/ksu_boot/pp_adb_tcp.bin >> /data/property/persistent_properties || echo WARN-pp-append
fi
for p in $(ps -A -o PID=,ARGS= | grep "su --daemon" | grep -v grep | sed "s/ .*//"); do kill -9 $p 2>/dev/null || true; done
rm -f /data/local/temp/su.sock /data/local/temp/su.pid
setsid /data/local/temp/su --daemon >> /data/local/temp/su.log 2>&1 < /dev/null &
sleep 1
if [ ! -x /product/bin/su ]; then
  mkdir -p /data/local/temp/ovl/lower /data/local/temp/ovl/tmp
  mountpoint -q /data/local/temp/ovl/lower || mount --bind /product/bin /data/local/temp/ovl/lower
  mountpoint -q /data/local/temp/ovl/tmp || mount -t tmpfs -o size=16m tmpfs /data/local/temp/ovl/tmp
  mkdir -p /data/local/temp/ovl/tmp/upper /data/local/temp/ovl/tmp/work
  rm -f /data/local/temp/ovl/tmp/upper/su
  cp /data/local/temp/su /data/local/temp/ovl/tmp/upper/su
  chmod 755 /data/local/temp/ovl/tmp/upper/su
  mount -t overlay overlay -o lowerdir=/data/local/temp/ovl/lower,upperdir=/data/local/temp/ovl/tmp/upper,workdir=/data/local/temp/ovl/tmp/work,context=u:object_r:system_file:s0 /product/bin
fi
am force-stop com.resukisu.resukisu || true
sleep 1
am start -n com.resukisu.resukisu/org.bakasu.bakasu.ui.MainActivity > /dev/null 2>&1 || true
echo POSTLOCK-RESTORE-OK
