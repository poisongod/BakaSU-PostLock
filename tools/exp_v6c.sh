#!/system/bin/sh
# v6c diagnosis: did ocs_init ever run?
#   1. dump current oplus_check_suppress state (params, sections, kallsyms)
#   2. rmmod oplus_check_suppress   (EBUSY => kprobe holds ref => init DID run)
#   3. reload with PRESET params (state=PREINIT entry_addr=4242)
#   4. read back: init's emit() would overwrite PREINIT -> init ran;
#      PREINIT survives -> init never executed.
exec >> /data/local/tmp/exp.log 2>&1
echo "== exp start $(date) boot=$(cat /proc/sys/kernel/random/boot_id) uptime=$(cut -d' ' -f1 /proc/uptime) =="
echo "kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict)"
echo "-- module line --"
grep -a oplus_check_suppress /proc/modules
echo "-- kallsyms ocs --"
grep -E 'ocs' /proc/kallsyms | head -12
echo "-- sections --"
for s in .text .init.text .bss .data __param; do
  echo "sec.$s=$(cat /sys/module/oplus_check_suppress/sections/$s 2>&1)"
done
echo "-- param pre --"
for p in hits last_pc entry_addr state; do
  echo "pre.$p=[$(cat /sys/module/oplus_check_suppress/parameters/$p 2>&1)]"
done
echo "-- rmmod --"
/data/local/tmp/rmmod oplus_check_suppress; echo "rmmod rc=$?"
ls -d /sys/module/oplus_check_suppress 2>&1
echo "-- reload with preset params --"
/data/local/tmp/home/finitmod_v2 /data/local/tmp/oplus_check_suppress.ko 0 'state=PREINIT' 'entry_addr=4242'
echo "finitmod rc=$?"
sleep 1
echo "-- param post --"
for p in hits last_pc entry_addr state; do
  echo "post.$p=[$(cat /sys/module/oplus_check_suppress/parameters/$p 2>&1)]"
done
echo "-- dmesg module/cfi --"
dmesg 2>/dev/null | grep -iE 'oplus_check_suppress|cfi fail|verification' | tail -12
echo "== exp done $(date) =="
