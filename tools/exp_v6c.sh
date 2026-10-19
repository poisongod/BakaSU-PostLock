#!/system/bin/sh
# v6c diagnosis: did ocs_init ever run?
#   1. dump current ocsk state (params, sections, kallsyms)
#   2. rmmod ocsk   (EBUSY => kprobe holds ref => init DID run)
#   3. reload with PRESET params (state=PREINIT entry_addr=4242)
#   4. read back: init's emit() would overwrite PREINIT -> init ran;
#      PREINIT survives -> init never executed.
exec >> /data/local/tmp/exp.log 2>&1
echo "== exp start $(date) boot=$(cat /proc/sys/kernel/random/boot_id) uptime=$(cut -d' ' -f1 /proc/uptime) =="
echo "kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict)"
echo "-- module line --"
grep -a ocsk /proc/modules
echo "-- kallsyms ocs --"
grep -E 'ocs' /proc/kallsyms | head -12
echo "-- sections --"
for s in .text .init.text .bss .data __param; do
  echo "sec.$s=$(cat /sys/module/ocsk/sections/$s 2>&1)"
done
echo "-- param pre --"
for p in hits last_pc entry_addr state; do
  echo "pre.$p=[$(cat /sys/module/ocsk/parameters/$p 2>&1)]"
done
echo "-- rmmod --"
/data/local/tmp/rmmod ocsk; echo "rmmod rc=$?"
ls -d /sys/module/ocsk 2>&1
echo "-- reload with preset params --"
/data/local/tmp/home/finitmod_v2 /data/local/tmp/ocsk.ko 0 'state=PREINIT' 'entry_addr=4242'
echo "finitmod rc=$?"
sleep 1
echo "-- param post --"
for p in hits last_pc entry_addr state; do
  echo "post.$p=[$(cat /sys/module/ocsk/parameters/$p 2>&1)]"
done
echo "-- dmesg module/cfi --"
dmesg 2>/dev/null | grep -iE 'ocsk|cfi fail|verification' | tail -12
echo "== exp done $(date) =="
