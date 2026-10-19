/* ocsk.ko -- silence OPPO's oplus_root_check_succ kill path from kernel side.
 *
 * v11.2 (round 998d4c8d, THE fix): v11's entry-side `br x30` never
 * worked in practice -- entry_hits and kill-hits stayed 1:1 (42/42)
 * with kill printks matching, i.e. the whole function STILL RAN even
 * though entry_pre set pc=x30 and returned 1, because OPPO's trace
 * kprobe `ocs` aggregates with ours on entry+0 and the interaction
 * defeats the pc redirect (details not fully pinned; debugfs is
 * CONFIG_DEBUG_FS=n on this kernel so kprobes/list is unavailable).
 * What actually unlocked uid=0: kill_pre switched to `return 1` with
 * the x0=0 patch REMOVED.  Returning non-zero makes arm64
 * kprobe_handler skip setup_singlestep entirely ("it will modify the
 * execution path and no need to single stepping"), so `pc += 4`
 * genuinely lands and `bl force_sig` is never CALLED -- versus v8..v11.1
 * where force_sig(0) still ran (x0 cleared, signal no-op) and the mere
 * call kept rolling the escalation back: ksud ioctl stayed uid=10279
 * and KsuCli reported "Created process is not a shell".  With v11.2:
 * dmesg `ksu ioctl ... from uid=0`, no KsuCli errors, BakaSu blue card
 * "工作中 Built-in" on the stock relocked kernel.  The entry probe stays
 * registered as a (currently inert) observer; kp_kill is the enforcer.
 *
 * v11 (round 998d4c8d, 3rd finding): skipping `force_sig` was NOT enough.
 * After v10 armed (hits=40 kills intercepted, app alive) the ksud child
 * still ran with uid=10279 -- dmesg `ksu ioctl: cmd=0xc0004b0d from
 * uid=10279` -- and KsuCli reported `Created process is not a shell`:
 * the detector blocks the privilege escalation ITSELF before the printk
 * (+0xa1c `bl entry+0x0` recursion into ocs proper runs first; force_sig
 * at +0xa30 is just the tail).  So skip the WHOLE function instead:
 *
 *   entry probe stays registered (aggregated with OPPO's own trace
 *   kprobe on the same address) and its pre_handler does
 *   `regs->pc = regs->x30` -- an aarch64 `br x30`.  The probe fires at
 *   entry+0 BEFORE the SCS push / frame setup, so x30 still holds the
 *   caller's return address, sp/x29/x18 are untouched, nothing was
 *   pushed to the shadow call stack: the function becomes a no-op that
 *   returns with x0 (= its first argument) unchanged.  printk, force_sig
 *   and any cred blocking in ocs proper all vanish.  kp_kill stays
 *   registered as a belt-and-suspenders fuse for the case where the
 *   entry probe ever misses.
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
static unsigned long entry_hits;	/* v11: whole-function skips */
static int armed;

static char state_buf[512];
static int armed_flag;		/* set once the probes are registered */
static int entry_on;		/* v11: kp_entry stays registered */
static int kill_on;		/* kp_kill registered */

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

/* v11.2 EXPERIMENT: prove the return-1 pc-honoring mechanism on a CLEAN
 * address (entry+0xa30 has no co-resident trace kprobe, unlike entry+0).
 * Return non-zero => arm64 kprobe_handler skips setup_singlestep and
 * continues from regs->pc; the x0=0 patch is REMOVED so a failure to
 * honor the pc change falls back to force_sig(9) and kills the ksud
 * children (recoverable, app shows red).  If ksud survives + su works,
 * the mechanism is live and entry+0's non-skip is a trace-aggregation
 * interaction to chase separately. */
static int kill_pre(struct kprobe *p, struct pt_regs *regs)
{
	__sync_fetch_and_add(&hits, 1);
	last_pc = regs->pc;
	regs->pc += 4;			/* skip `bl force_sig` */
	return 1;			/* v11.2: honor pc, no simulation */
}

/* v11: intended as "return immediately as if the detector never ran"
 * (fires at entry+0 before SCS push / stp setup, so x30 is still the
 * caller's return address and NO callee state was touched).
 *
 * Reality (v11.2 verdict): this does NOT redirect control flow on this
 * kernel -- entry_hits and kill-hits stay 1:1, the function body runs
 * to completion every time despite `return 1`.  Root cause narrowed to
 * the aggregation with OPPO's trace kprobe `ocs` parked on the same
 * entry+0 (a clean-address probe at +0xa30 honors return-1 + pc change
 * perfectly -- see kill_pre).  Kept as an inert observer/counter; the
 * enforcer is kp_kill.  Do not remove: if the aggregation quirk ever
 * changes (trace event deleted), this becomes live and skips the whole
 * detector including the printk noise. */
static int entry_pre(struct kprobe *p, struct pt_regs *regs)
{
	__sync_fetch_and_add(&entry_hits, 1);
	last_pc = regs->pc;
	regs->pc = (unsigned long)regs->regs[30];	/* br x30 */
	return 1;			/* v11.1: skip setup_singlestep entirely */
}

static struct kprobe kp_entry = {
	.symbol_name = OCS_SYM,
	.pre_handler = entry_pre,	/* v11: whole-function skip */
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
	emit("ocsk-v11 arm=%s smod=%zu\n",
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
	entry_on = 1;			/* v11: keep it -- entry_pre skips the fn */
	entry_addr = (unsigned long)kp_entry.addr;
	emit("entry=%lx\n", entry_addr);

	/* v10/v11: with our probe parked the word at entry+0 is now a
	 * brk placeholder (ours or OPPO's, aggregated); accept SCS push
	 * OR kprobe placeholder, v9 retry covers pure text-poke races. */
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
			unregister_kprobe(&kp_entry);	/* v11: release for retry */
			entry_on = 0;
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
		unregister_kprobe(&kp_entry);	/* v11: release for retry */
		entry_on = 0;
		armed_flag = 0;		/* v9: allow retry */
		return 0;
	}

	ret = register_kprobe(&kp_kill);
	emit("ret.kill=%d\n", ret);
	if (ret) {
		unregister_kprobe(&kp_entry);	/* v11: release for retry */
		entry_on = 0;
		armed_flag = 0;		/* v9: allow retry */
		return 0;
	}
	kill_on = 1;

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
module_param(entry_hits, ulong, 0444);
MODULE_PARM_DESC(entry_hits, "v11: whole-function skips (br x30 at entry)");
module_param(last_pc, ulong, 0444);
MODULE_PARM_DESC(last_pc, "kaddr of last skipped instruction");
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
	if (entry_on)
		unregister_kprobe(&kp_entry);
	if (kill_on)
		unregister_kprobe(&kp_kill);
}

module_init(ocs_init);
module_exit(ocs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("v11: skip oplus_root_check_succ entirely (br x30 at entry) + force_sig fuse");
