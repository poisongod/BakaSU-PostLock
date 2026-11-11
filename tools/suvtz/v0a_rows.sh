#!/system/bin/sh
# VtzSU V0a 判据脚本（docs/vtzsu-design.md §7 的可执行版本）
#
# 用法（设备侧，shell 域即可，内部按需 su）：
#   adb push tools/suvtz/v0a_rows.sh /data/local/tmp/vtz_rows.sh
#   adb shell 'sh /data/local/tmp/vtz_rows.sh'
#
# 前置：一次冷 boot + tools/postlock.sh（restore 会起 holder 并写 sidecar）。
# 本脚本只读判据，唯一写入是 R8 的失败语义实验（删 sidecar 后立即恢复）。
#
# 观察限制（2026-11-11 实测，写在这里避免下次误判为缺陷）：
#   * shell 域读 /proc/<pid>/ns/mnt 被 SELinux 拒（Permission denied，空输出）
#     -> holder/init 的 ns 一律经 su 读取；
#   * /proc/1/ns/mnt 同理，shell 直读恒空。
T=/data/local/tmp
S=$T/vtz_w.pid
say() { echo; echo "##### $*"; }

say "R1 sidecar"
if [ -f "$S" ]; then
  echo "content: [$(cat $S)]"
  ls -l $S
  WPID=$(awk '{print $1}' $S); WINO=$(awk '{print $2}' $S)
  echo "pid=$WPID inode=$WINO"
  echo "holder ns(live): $(su -c "readlink /proc/$WPID/ns/mnt" 2>&1)"
  echo "holder comm: $(su -c "cat /proc/$WPID/cmdline" 2>&1 | tr '\0' ' ')"
else
  echo "MISSING $S"
fi

say "R2 session ns (su --vtz)"
su --vtz -c 'echo session-ns=$(readlink /proc/self/ns/mnt); id' 2>&1

say "R3 control ns (su, no flag)"
su -c 'echo session-ns=$(readlink /proc/self/ns/mnt)' 2>&1

say "R4 W-side record"
su --vtz -c 'echo wlog-lines=$(wc -l < /data/local/tmp/.w/log/access.log 2>/dev/null); tail -n 3 /data/local/tmp/.w/log/access.log 2>&1' 2>&1

say "R5 N side invisible (shell domain)"
ls -l $T/.w 2>&1
ls -l $T/.w/log 2>&1
cat $T/.w/log/access.log 2>&1

say "R6 functionality inside W"
su --vtz -c 'ls / >/dev/null && echo root-ok; ls /system >/dev/null && echo system-ok; ls /data >/dev/null && echo data-ok; ls /apex >/dev/null && echo apex-ok; head -c 40 /proc/version; echo; echo mods=$(ls /sys/module | wc -l)' 2>&1

say "R7 -M precedence over --vtz"
su -M --vtz -c 'echo session-ns=$(readlink /proc/self/ns/mnt)' 2>&1
echo "init ns: $(su -c 'readlink /proc/1/ns/mnt' 2>&1)"

say "R8 failure semantics (sidecar removed)"
cp $S $T/vtz_w.pid.bak 2>/dev/null
rm -f $S
su --vtz -c 'echo SHOULD-NOT-PRINT' ; echo "rc=$?"
cp $T/vtz_w.pid.bak $S 2>/dev/null; echo "restored=[$(cat $S 2>/dev/null)]"

say "R9 W-side root vs N-side root (ns difference)"
su --vtz -c 'echo w-root-ns=$(readlink /proc/self/ns/mnt)' 2>&1
su -c 'echo n-root-ns=$(readlink /proc/self/ns/mnt)' 2>&1

say "R10 access.log kind counts"
su --vtz -c 'grep -c kind=enter /data/local/tmp/.w/log/access.log; tail -1 /data/local/tmp/.w/log/access.log' 2>&1
