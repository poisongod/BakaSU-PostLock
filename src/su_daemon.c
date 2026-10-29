#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define DEFAULT_SOCK_PATH "/data/local/tmp/su.sock"
#define PID_PATH "/data/local/tmp/su.pid"
#define LOG_PATH "/data/local/tmp/su.log"

static const char *sock_path(void) {
  static char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  const char *env = getenv("SU_SOCK");
  if (env && env[0] &&
      (strncmp(env, "/data/local/tmp/", 16) == 0 ||
       strncmp(env, "/data/local/tmp/", 16) == 0) &&
      strlen(env) < sizeof(path)) {
    snprintf(path, sizeof(path), "%s", env);
    return path;
  }
  return DEFAULT_SOCK_PATH;
}

static void set_root_env(void) {
  setenv("PATH",
         "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
         "/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:"
         "/odm/bin:/vendor/bin:/vendor/xbin",
         1);
  setenv("HOME", "/data/local/tmp", 1);
  setenv("USER", "root", 1);
  setenv("LOGNAME", "root", 1);
}

static void xwrite(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      _exit(111);
    }
    p += n;
    len -= (size_t)n;
  }
}

static int read_full(int fd, void *buf, size_t len) {
  char *p = (char *)buf;
  while (len) {
    ssize_t n = read(fd, p, len);
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

static int connect_daemon_saved_errno;

static int connect_daemon(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    connect_daemon_saved_errno = errno;
    perror("su: socket");
    return -1;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", sock_path());

  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    connect_daemon_saved_errno = errno;
    perror("su: connect daemon");
    close(fd);
    return -1;
  }
  return fd;
}

static void end_half(int fd, int *open_flag) {
  if (shutdown(fd, SHUT_WR) != 0 && errno == ENOTSOCK) {
    close(fd);
    *open_flag = 0;
  }
}

static int pump_pair(int a, int b) {
  char buf[4096];
  int a_open = 1;
  int b_open = 1;

  while (a_open || b_open) {
    struct pollfd pfd[2];
    int nfd = 0;
    if (a_open) {
      pfd[nfd].fd = a;
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    if (b_open) {
      pfd[nfd].fd = b;
      pfd[nfd].events = POLLIN;
      nfd++;
    }

    int pr = poll(pfd, (nfds_t)nfd, -1);
    if (pr < 0 && errno == EINTR) {
      continue;
    }
    if (pr < 0) {
      return 1;
    }

    int idx = 0;
    if (a_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(a, buf, sizeof(buf));
        if (n > 0) {
          xwrite(b, buf, (size_t)n);
        } else {
          a_open = 0;
          end_half(b, &b_open);
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        a_open = 0;
        end_half(b, &b_open);
      }
    }
    if (b_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(b, buf, sizeof(buf));
        if (n > 0) {
          if (a == STDIN_FILENO) {
            xwrite(STDOUT_FILENO, buf, (size_t)n);
          } else {
            xwrite(a, buf, (size_t)n);
          }
        } else {
          b_open = 0;
          end_half(a, &a_open);
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        b_open = 0;
        end_half(a, &a_open);
      }
    }
  }
  return 0;
}

/* Framed multiplex mode 'B': daemon -> client carries [type][len le32][payload]
   type 1 = stdout chunk, type 2 = stderr chunk. stdin flows raw client->daemon. */
#define FRAME_OUT 1
#define FRAME_ERR 2
#define FRAME_MAX 65536

static int write_all(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

static int read_full2(int fd, void *buf, size_t len) {
  char *p = (char *)buf;
  while (len) {
    ssize_t n = read(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return n == 0 ? 0 : -1;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int write_frame(int fd, uint8_t type, const void *buf, uint32_t len) {
  uint8_t hdr[5];
  hdr[0] = type;
  hdr[1] = (uint8_t)(len & 0xff);
  hdr[2] = (uint8_t)((len >> 8) & 0xff);
  hdr[3] = (uint8_t)((len >> 16) & 0xff);
  hdr[4] = (uint8_t)((len >> 24) & 0xff);
  if (write_all(fd, hdr, sizeof(hdr)) != 0) {
    return -1;
  }
  if (len > 0 && write_all(fd, buf, len) != 0) {
    return -1;
  }
  return 0;
}

static int b_client(int fd) {
  char buf[4096];
  int stdin_open = 1;
  int running = 1;

  while (running) {
    struct pollfd pfd[2];
    int nfd = 0;
    if (stdin_open) {
      pfd[nfd].fd = STDIN_FILENO;
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    pfd[nfd].fd = fd;
    pfd[nfd].events = POLLIN;
    nfd++;

    int pr = poll(pfd, (nfds_t)nfd, -1);
    if (pr < 0) {
      if (errno == EINTR) {
        continue;
      }
      return 1;
    }

    int idx = 0;
    if (stdin_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
          if (write_all(fd, buf, (size_t)n) != 0) {
            running = 0;
          }
        } else {
          stdin_open = 0;
          shutdown(fd, SHUT_WR);
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        stdin_open = 0;
        shutdown(fd, SHUT_WR);
      }
    }

    if (running) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        uint8_t hdr[5];
        int r = read_full2(fd, hdr, sizeof(hdr));
        if (r <= 0) {
          break;
        }
        uint32_t len = (uint32_t)hdr[1] | ((uint32_t)hdr[2] << 8) |
                       ((uint32_t)hdr[3] << 16) | ((uint32_t)hdr[4] << 24);
        if (len > FRAME_MAX) {
          break;
        }
        uint32_t got = 0;
        int out_fd = hdr[0] == FRAME_ERR ? STDERR_FILENO : STDOUT_FILENO;
        while (got < len) {
          uint32_t chunk = len - got;
          if (chunk > sizeof(buf)) {
            chunk = sizeof(buf);
          }
          r = read_full2(fd, buf, chunk);
          if (r <= 0) {
            running = 0;
            break;
          }
          xwrite(out_fd, buf, chunk);
          got += chunk;
        }
        if (!running) {
          break;
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        break;
      }
    }
  }
  return 0;
}

static void fallback_system_su(int err, int argc, char **argv) {
  (void)argc;
  static const char sys_su[] = "/system/bin/su";
  int lfd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (lfd >= 0) {
    char line[192];
    int n = snprintf(line, sizeof(line),
                     "client connect failed errno=%d fallback exec %s\n", err,
                     sys_su);
    if (n > 0) {
      ssize_t ign = write(lfd, line, (size_t)n);
      (void)ign;
    }
    close(lfd);
  }
  size_t argv0_len = argv[0] ? strlen(argv[0]) : 0;
  if (argv0_len >= sizeof(sys_su) - 1 &&
      strcmp(argv[0] + argv0_len - (sizeof(sys_su) - 1), sys_su) == 0) {
    return;
  }
  extern char **environ;
  execve(sys_su, argv, environ);
}

static int client_main(int argc, char **argv) {
  int fd = connect_daemon();
  if (fd < 0) {
    fallback_system_su(connect_daemon_saved_errno, argc, argv);
    return 127;
  }

  if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
    char mode = 'C';
    uint32_t len = (uint32_t)strlen(argv[2]);
    xwrite(fd, &mode, 1);
    xwrite(fd, &len, sizeof(len));
    xwrite(fd, argv[2], len);
    shutdown(fd, SHUT_WR);

    char buf[4096];
    for (;;) {
      ssize_t n = read(fd, buf, sizeof(buf));
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n <= 0) {
        break;
      }
      xwrite(STDOUT_FILENO, buf, (size_t)n);
    }
    close(fd);
    return 0;
  }

  char mode = isatty(STDIN_FILENO) ? 'I' : 'B';
  xwrite(fd, &mode, 1);
  if (mode == 'B') {
    int rc = b_client(fd);
    close(fd);
    return rc;
  }
  int rc = pump_pair(STDIN_FILENO, fd);
  close(fd);
  return rc;
}

static void exec_command_client(int conn, const char *cmd) {
  pid_t pid = fork();
  if (pid == 0) {
    dup2(conn, STDIN_FILENO);
    dup2(conn, STDOUT_FILENO);
    dup2(conn, STDERR_FILENO);
    close(conn);
    set_root_env();
    execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
    _exit(127);
  }

  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
}

static void exec_pipe_shell(int conn) {
  int in[2], out[2], err[2];
  if (pipe(in) != 0 || pipe(out) != 0 || pipe(err) != 0) {
    return;
  }

  pid_t pid = fork();
  if (pid == 0) {
    dup2(in[0], STDIN_FILENO);
    dup2(out[1], STDOUT_FILENO);
    dup2(err[1], STDERR_FILENO);
    close(in[0]);
    close(in[1]);
    close(out[0]);
    close(out[1]);
    close(err[0]);
    close(err[1]);
    close(conn);
    set_root_env();
    execl("/system/bin/sh", "sh", (char *)NULL);
    _exit(127);
  }

  close(in[0]);
  close(out[1]);
  close(err[1]);

  int conn_open = 1;
  int out_open = 1;
  int err_open = 1;
  int in_open = 1;
  char buf[4096];

  while (conn_open && (out_open || err_open || in_open)) {
    struct pollfd pfd[3];
    int nfd = 0;
    int conn_idx = -1, out_idx = -1, err_idx = -1;
    if (conn_open) {
      conn_idx = nfd;
      pfd[nfd].fd = conn;
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    if (out_open) {
      out_idx = nfd;
      pfd[nfd].fd = out[0];
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    if (err_open) {
      err_idx = nfd;
      pfd[nfd].fd = err[0];
      pfd[nfd].events = POLLIN;
      nfd++;
    }

    int pr = poll(pfd, (nfds_t)nfd, -1);
    if (pr < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    if (conn_idx >= 0) {
      short re = pfd[conn_idx].revents;
      if (re & POLLIN) {
        ssize_t n = read(conn, buf, sizeof(buf));
        if (n > 0) {
          if (in_open && write_all(in[1], buf, (size_t)n) != 0) {
            in_open = 0;
            close(in[1]);
          }
        } else {
          conn_open = 0;
          if (in_open) {
            in_open = 0;
            close(in[1]);
          }
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        conn_open = 0;
        if (in_open) {
          in_open = 0;
          close(in[1]);
        }
      }
    }

    if (out_idx >= 0) {
      short re = pfd[out_idx].revents;
      if (re & POLLIN) {
        ssize_t n = read(out[0], buf, sizeof(buf));
        if (n > 0) {
          if (write_frame(conn, FRAME_OUT, buf, (uint32_t)n) != 0) {
            conn_open = 0;
          }
        } else {
          out_open = 0;
          close(out[0]);
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        out_open = 0;
        close(out[0]);
      }
    }

    if (err_idx >= 0) {
      short re = pfd[err_idx].revents;
      if (re & POLLIN) {
        ssize_t n = read(err[0], buf, sizeof(buf));
        if (n > 0) {
          if (write_frame(conn, FRAME_ERR, buf, (uint32_t)n) != 0) {
            conn_open = 0;
          }
        } else {
          err_open = 0;
          close(err[0]);
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        err_open = 0;
        close(err[0]);
      }
    }
  }

  if (in_open) {
    close(in[1]);
  }
  kill(pid, SIGHUP);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  close(conn);
}

static int open_pty_master(char *slave, size_t slave_len) {
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0) {
    return -1;
  }
  if (grantpt(master) != 0 || unlockpt(master) != 0) {
    close(master);
    return -1;
  }
  if (ptsname_r(master, slave, slave_len) != 0) {
    close(master);
    return -1;
  }
  return master;
}

static void exec_interactive_client(int conn) {
  char slave_name[128];
  int master = open_pty_master(slave_name, sizeof(slave_name));
  if (master < 0) {
    const char msg[] = "su daemon: failed to open pty\n";
    xwrite(conn, msg, sizeof(msg) - 1);
    return;
  }

  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
      _exit(126);
    }
    ioctl(slave, TIOCSCTTY, 0);
    dup2(slave, STDIN_FILENO);
    dup2(slave, STDOUT_FILENO);
    dup2(slave, STDERR_FILENO);
    if (slave > STDERR_FILENO) {
      close(slave);
    }
    close(master);
    close(conn);
    set_root_env();
    execl("/system/bin/sh", "sh", "-i", (char *)NULL);
    _exit(127);
  }

  pump_pair(conn, master);
  kill(pid, SIGHUP);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  close(master);
}

static int uid_list_contains(const char *p, int client_uid) {
  while (*p) {
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) {
      break;
    }
    if (v == client_uid) {
      return 1;
    }
    p = end;
    while (*p == ',' || *p == ' ' || *p == '\t' || *p == '\n' ||
           *p == '\r') {
      p++;
    }
  }
  return 0;
}

static int client_uid_allowed(int client_uid) {
  const char *list = getenv("SU_ALLOW_UIDS");
  if (list && list[0]) {
    return uid_list_contains(list, client_uid);
  }
  const char *path = "/data/local/tmp/su.allow";
  FILE *f = fopen(path, "r");
  if (!f) {
    return 1;
  }
  int allowed = 0;
  while (!allowed) {
    char line[128];
    if (!fgets(line, sizeof(line), f)) {
      break;
    }
    allowed = uid_list_contains(line, client_uid);
  }
  fclose(f);
  return allowed;
}

static void serve_one(int conn) {
  char mode = 0;
  if (!read_full(conn, &mode, 1)) {
    return;
  }
  struct ucred cred;
  memset(&cred, 0, sizeof(cred));
  socklen_t cred_len = sizeof(cred);
  int have_cred = getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len);
  int client_uid = have_cred == 0 ? (int)cred.uid : -1;
  fprintf(stderr, "su request pid=%d uid=%d mode=%c allow=%d\n", getpid(),
          client_uid, mode >= 32 ? mode : '?',
          client_uid < 0 || client_uid_allowed(client_uid));
  if (client_uid >= 0 && !client_uid_allowed(client_uid)) {
    return;
  }

  if (mode == 'C') {
    uint32_t len = 0;
    if (!read_full(conn, &len, sizeof(len)) || len > 65536) {
      return;
    }
    char *cmd = calloc(1, (size_t)len + 1);
    if (!cmd) {
      return;
    }
    if (!read_full(conn, cmd, len)) {
      free(cmd);
      return;
    }
    exec_command_client(conn, cmd);
    free(cmd);
  } else if (mode == 'I') {
    exec_interactive_client(conn);
  } else if (mode == 'B') {
    exec_pipe_shell(conn);
  }
}

static void stop_old_daemon(void) {
  int fd = open(PID_PATH, O_RDONLY);
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
  if (old <= 1 || old == (int)getpid()) {
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
  unlink(PID_PATH);
}

static void write_pidfile(void) {
  char buf[32];
  int len = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
  int fd = open(PID_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    return;
  }
  (void)write(fd, buf, (size_t)len);
  (void)fchmod(fd, 0666);
  close(fd);
}

static int daemon_main(void) {
  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  prctl(PR_SET_PDEATHSIG, 0);
  setsid();
  set_root_env();
  stop_old_daemon();

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("socket");
    return 1;
  }

  const char *sock = sock_path();
  unlink(sock);
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", sock);

  if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("bind");
    return 1;
  }
  chmod(sock, 0666);
  if (listen(fd, 16) != 0) {
    perror("listen");
    return 1;
  }
  write_pidfile();

  fprintf(stderr, "su daemon ready pid=%d socket=%s uid=%d euid=%d\n",
          getpid(), sock, getuid(), geteuid());

  for (;;) {
    int conn = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0 && errno == EINTR) {
      continue;
    }
    if (conn < 0) {
      perror("accept");
      sleep(1);
      continue;
    }

    pid_t pid = fork();
    if (pid == 0) {
      close(fd);
      serve_one(conn);
      close(conn);
      _exit(0);
    }
    close(conn);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
  }
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "--daemon") == 0) {
    return daemon_main();
  }
  return client_main(argc, argv);
}
