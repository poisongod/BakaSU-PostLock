/* ocsk.ko -- silence OPPO's oplus_root_check_succ kill path from kernel side.
 *
 * v10 (round 998d4c8d, 2nd finding): OPPO keeps its OWN trace kprobe on
 * the same function -- `p:kprobes/ocs oplus_root_check_succ adr=$stack0`
 * in /sys/kernel/tracing/kprobe_events (plus `seb` on oplus_exec_block)
 * -- whose `brk #0x80` placeholder at entry+0 NEVER reverts.  v9's
 * anchor retry then failed all 100 tries on word d4200080 even long
 * after any of our own pokes had settled.  A foreign kprobe parked at
 * entry+0 is itself evidence the site is a valid probe point (its
 * registration ran the same instruction-stream checks), so accept
 * EITHER the SCS push OR the kprobe placeholder; the exact kill-word
 * match (0x94004415, KASLR-invariant pc-relative bl) is the real
 * safety anchor.
 *
 * v9 (round 998d4c8d): make the anchor read robust against the kprobe
 * text-poke race, and allow an online retry after a FAIL.
 *
 * v8's arm_set did register_kprobe(entry) -> unregister_kprobe(entry) ->
 * probe_kernel_read(entry+0) back to back.  aarch64 kprobes plant a
 * `brk #0x80` (word 0xd4200080) as the single-step placeholder; when the
 * unregister text-poke restore is still in flight the read sees THAT
 * instead of the SCS push and the anchor FAILs, leaving kp_kill
 * unregistered (boot 998d4c8d: "FAIL entry-anchor d4200080"; boot
 * 20b88ae4 raced the other way and passed).  Fixes:
 *   - retry the anchor read for up to ~100ms until the SCS push shows;
 *   - on any FAIL, clear armed_flag so `echo 1 > .../arm` can rerun the
 *     whole sequence later (the app kill will keep occurring until then,
 *     so a one-shot latch turns a transient race into a permanent hole);
 *   - entry = boot base + 0x26a620 sanity held on both boots.
 *
 * v8 (round 59): move the probe to the LIVE force_sig site.
 *
 * v7 verdict (boot c582161d): probe at entry+0x268 registered fine
 * (ret.kill=0, word 94004607->d4200080 read back) yet hits stayed 0
 * across 68+40 kill printks after registration, while the entry+0
 * trace event hit 1:1 with the last 7 kills.  Static re-analysis of
 * bootdump (sha1 2fac633f, with the KERN_INFO SOH prefix \x01'6'
 * included in the needle -- v5's "unique xref @0x258" was wrong
 * because it missed the 2-byte prefix) shows WHY:
 *
 *   The kill string has exactly TWO adrp+add xrefs:
 *     entry+0x258 : inside a standalone 0x28-byte clone at
 *                   entry+0x24c (SCS push, stp, adrp/add, bl printk,
 *                   mov w0,#9, bl force_sig, ret) which has ZERO bl
 *                   callers anywhere in the kernel -- dead code.
 *                   v7's probe sat inside it; nobody ever executes it.
 *     entry+0xa20 : the LIVE path:  +0xa1c bl entry+0x0 (recursion into
 *                   ocs proper -- explains the 1:1 entry-trace hits)
 *                   -> adrp/add -> +0xa28 bl printk (all 108 kill lines)
 *                   -> +0xa2c mov w0,#9 -> +0xa30 bl force_sig
 *                   -> +0xa34 b +0x9b0.
 *
 * So probe the live site: entry+0xa30.  Both sites call force_sig with
 * the same link-relative target (0x11a84), and KILL_BL word
 * 0x94004415 is KASLR-invariant (pc-relative).  The dead clone's word
 * is still read back as a cross-check (dead.word@268).
 *
 * kill_pre skips exactly one instruction (pc+=4) and zeroes x0 so
 * force_sig returns 0 instead of 9; sp/x29/x30 untouched.  The
 * +0xa28 printk still runs (harmless log line); only the signal dies.
 *
 * Load-time anchors via probe_kernel_read: entry word must be the SCS
 * push (f800865e), live kill-site word must be a BL (0x94xxxxxx, exact
 * expect 94004415).  Anchor mismatch: the setter records FAIL in state
 * and returns 0 anyway so the module stays loadable and the
 * diagnostics stay readable.  All diagnostics go to the `state`
 * module_param_string (sysfs); this kernel's filp_open-in-finitmod-
 * context failed silently (v6b) and its module printk never reaches
 * dmesg (v24 lesson).
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>	/* v9: msleep while the kprobe text poke settles */

#define OCS_SYM       "oplus_root_check_succ"
#define OCS_ENTRY_SCS 0xf800865eU	/* str x30,[x18],#8 (SCS push) */
#define KPROBE_BRK80  0xd4200080U	/* v10: foreign trace-kprobe placeholder */
#define KILL_BL_WORD  0x94004415U	/* v10: exact `bl force_sig` (link-rel) */
#define KILL_BL_OFF   0xa30		/* bl force_sig, LIVE path (xref2) */
#define DEAD_BL_OFF   0x268		/* bl force_sig in dead clone (xref1) */

static unsigned long hits;
static unsigned long last_pc;
static unsigned long entry_addr;
static int armed;

static char state_buf[512];
static int armed_flag;		/* set once the probes are registered */

static void emit(const char *fmt, ...)
{
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(state_buf + strlen(state_buf),
			sizeof(state_buf) - strlen(state_buf), fmt, ap);
	va_end(ap);
	(void)len;
}

static int kill_pre(struct kprobe *p, struct pt_regs *regs)
{
	__sync_fetch_and_add(&hits, 1);
	last_pc = regs->pc;
	regs->pc += 4;			/* skip `bl force_sig` */
	regs->regs[0] = 0;		/* clean return: 0, not SIGKILL/9 */
	return 0;
}

static struct kprobe kp_entry = {
	.symbol_name = OCS_SYM,
};

static struct kprobe kp_kill = {
	.pre_handler = kill_pre,
};

/* arm setter -- runs from parse_args() inside load_module(), long before
 * the (never reached) do_init_module().  Always returns 0 so the module
 * loads and `state` stays readable; every outcome is recorded there.
 */
static int arm_set(const char *val, const struct kernel_param *kp)
{
	unsigned int w_before = 0, w_after = 0, w_entry = 0;
	int ret = 0;

	if (armed_flag) {
		emit("arm-reentry ignored\n");
		return 0;
	}
	emit("ocsk-v8 arm=%s smod=%zu\n",
	     val && *val ? val : "", sizeof(struct module));
	if (!val || !*val || *val == '0') {
		emit("arm=0 no-op\n");
		return 0;
	}
	armed_flag = 1;

	ret = register_kprobe(&kp_entry);
	emit("ret.entry=%d\n", ret);
	if (ret) {
		emit("FAIL resolve " OCS_SYM "\n");
		armed_flag = 0;		/* v9: allow a later echo 1 > arm */
		return 0;		/* keep module loadable */
	}
	entry_addr = (unsigned long)kp_entry.addr;
	unregister_kprobe(&kp_entry);
	emit("entry=%lx\n", entry_addr);

	/* v10: accept the SCS push OR a foreign kprobe's `brk #0x80`
	 * placeholder (OPPO's trace kprobe `ocs` parks one there forever);
	 * v9's retry loop stays for the pure text-poke race case. */
	{
		int i;

		for (i = 0; i < 100; i++) {
			if (!probe_kernel_read(&w_entry, (const void *)entry_addr,
					       sizeof(w_entry)) &&
			    (w_entry == OCS_ENTRY_SCS || w_entry == KPROBE_BRK80))
				break;
			msleep(1);
		}
		emit("anchor tries=%d word=%08x\n", i, w_entry);
		if (i == 100) {
			emit("FAIL entry-anchor %08x\n", w_entry);
			armed_flag = 0;
			return 0;
		}
	}
	kp_kill.addr = (kprobe_opcode_t *)(entry_addr + KILL_BL_OFF);
	probe_kernel_read(&w_before, kp_kill.addr, sizeof(w_before));
	emit("kill.word.before=%08x bl=%d\n", w_before, (w_before >> 26) == 0x25);
	/* cross-check: the dead clone's bl must still be a plain bl (v7
	 * probed it in a previous boot only; fresh boot = untouched) */
	{
		unsigned int w_dead = 0;

		probe_kernel_read(&w_dead,
				  (const void *)(entry_addr + DEAD_BL_OFF),
				  sizeof(w_dead));
		emit("dead.word@268=%08x\n", w_dead);
	}
	if (w_before != KILL_BL_WORD) {
		emit("FAIL kill-anchor %08x\n", w_before);
		armed_flag = 0;		/* v9: allow retry */
		return 0;
	}

	ret = register_kprobe(&kp_kill);
	emit("ret.kill=%d\n", ret);
	if (ret) {
		armed_flag = 0;		/* v9: allow retry */
		return 0;
	}

	probe_kernel_read(&w_after, kp_kill.addr, sizeof(w_after));
	emit("kill.word.after=%08x patched=%d\n", w_after, w_after != w_before);
	armed = 1;
	pr_err("ocsk: entry @%px, kill-bl @%px ret=%d word %08x->%08x\n",
	       (void *)entry_addr, (void *)kp_kill.addr, ret, w_before, w_after);
	return 0;
}

static const struct kernel_param_ops arm_ops = {
	.set = arm_set,
	.get = param_get_int,
};
module_param_cb(arm, &arm_ops, &armed, 0644);
MODULE_PARM_DESC(arm, "write 1 to register the kill-site kprobe (setter runs in load context)");

module_param(hits, ulong, 0444);
MODULE_PARM_DESC(hits, "skipped-kill count");
module_param(last_pc, ulong, 0444);
MODULE_PARM_DESC(last_pc, "kaddr of last skipped bl force_sig");
module_param(entry_addr, ulong, 0444);
MODULE_PARM_DESC(entry_addr, "resolved symbol entry (sanity: boot base + 0x26a620)");
module_param_string(state, state_buf, sizeof(state_buf), 0444);
MODULE_PARM_DESC(state, "load-time diagnostic trace");

static int __init ocs_init(void)
{
	/* Normally unreachable on this kernel (mod->init reads NULL --
	 * see header).  Kept for completeness; armed_flag makes it safe
	 * should the KDIR layout ever be repaired.
	 */
	if (armed_flag)
		return 0;
	arm_set("1", NULL);
	return 0;
}

static void __exit ocs_exit(void)
{
	if (armed_flag)
		unregister_kprobe(&kp_kill);
}

module_init(ocs_init);
module_exit(ocs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kprobe killer of oplus_root_check_succ's live force_sig site (entry+0xa30)");
