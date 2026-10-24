#pragma once

#define _GNU_SOURCE  
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  
#include <err.h>  
#include <stdio.h>  
#include <sys/mman.h>  
#include <sched.h>
#include <time.h>
#include <string.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#ifdef ANDROID_APP_NO_LKM
#include <android/log.h>
#endif

/* Panic-safe logging: stdout is fully buffered when redirected to a file, so
 * a kernel panic in the middle of the exploit discards everything still in
 * the stdio buffer (and, if not fsync'ed, the page cache).  Set KS_LOG_SYNC=1
 * to flush+fsync every pr_* line. */
static inline void pr_flush(void) {
  fflush(stdout);
  const char *s = getenv("KS_LOG_SYNC");
  if (s && s[0] && strcmp(s, "0") != 0) fsync(fileno(stdout));
}

/* Forked helper children (pipe_prepare, clone_child, leak_child) must not
 * run the parent's inherited atexit handlers on error paths: pr_error's
 * exit(-1) would fire route_pi_release_atexit / ashmem_guard_restore and
 * corrupt the parent's route state.  Set this to 1 in the child right after
 * fork so pr_error uses _exit instead of exit. */
extern int ks_child_no_atexit;

/* Unified log prefix "[b<boot8> <HH:MM:SS>]" -- every pr_* line starts with
 * boot_id (first 8 chars of /proc/.../boot_id, stable for the whole boot)
 * followed by wall-clock time, so a line copied out of context still says
 * which boot and when.  Thread-local because the chain logs from many
 * threads concurrently.  Format sits BEFORE any ANSI color byte (visual
 * line start == boot id) and existing substring greps (root=1, win tick,
 * POSTLOCK-*) keep matching. */
static inline const char *ks_log_prefix(void) {
  static __thread char pfx[24];
  static __thread int boot_ok = 0;
  if (!boot_ok) {
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (fd >= 0) {
      char b[64];
      ssize_t n = read(fd, b, sizeof(b) - 1);
      close(fd);
      if (n >= 8) {
        /* "[bXXXXXXXX " = 11 bytes, time appended from offset 11 each call */
        pfx[0] = '[';
        pfx[1] = 'b';
        memcpy(pfx + 2, b, 8);
        pfx[10] = ' ';
        pfx[11] = 0;
        boot_ok = 1;
      }
    }
    if (!boot_ok) {
      memcpy(pfx, "[b???????? ", 11);
      pfx[11] = 0;
      boot_ok = 1;
    }
  }
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm;
  localtime_r(&ts.tv_sec, &tm);
  snprintf(pfx + 11, sizeof(pfx) - 11, "%02d:%02d:%02d]",
           tm.tm_hour, tm.tm_min, tm.tm_sec);
  return pfx;
}

#ifndef HIDEMINMAX
#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))
#endif

// #define DEBUG
// #define PANIC

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define SYSCHK(x) ({ \
        typeof(x) __res = (x); \
        if (__res == (typeof(x))-1) \
            pr_error("SYSCHK(" #x "): %m\n"); \
        __res; \
    })
#define SYSCHK_pr(x, fmt) ({ \
        typeof(x) __res = (x); \
        if (__res == (typeof(x))-1) \
            pr_error(fmt); \
        __res; \
    })

#ifdef PANIC
#define PR_ASSERT pr_error
#else
#define PR_ASSERT pr_warning
#endif

#define ASSERT(cond) do { \
        if (!!(cond) == 0) \
            PR_ASSERT("[detected] assert(" #cond ")\n"); \
    } while (0)
#define ASSERT_pr(cond, fmt, ...) do { \
        if (!!(cond) == 0) \
            PR_ASSERT("[detected] assert(%s): " fmt, #cond, ##__VA_ARGS__); \
    } while (0)

#ifdef DEBUG
#ifdef ANDROID_APP_NO_LKM
#define pr_error(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_ERROR, "google_poc_app", "[!] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_WARN, "google_poc_app", "[-] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[*] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[+] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#else
#define pr_error(fmt, ...) do { \
        printf("[%s] " COLOR_RED "[!] %s:%d " COLOR_DEFAULT fmt, ks_log_prefix(), __FILE__, __LINE__, ##__VA_ARGS__); \
        pr_flush(); \
        if (ks_child_no_atexit) _exit(-1); else exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        printf("[%s] " COLOR_RED "[-] %s:%d " COLOR_DEFAULT fmt, ks_log_prefix(), __FILE__, __LINE__, ##__VA_ARGS__); \
        pr_flush(); \
    } while (0)
#define pr_info(fmt, ...) do { \
        printf("[%s] " COLOR_YELLOW "[*] %s:%d " COLOR_DEFAULT fmt, ks_log_prefix(), __FILE__, __LINE__, ##__VA_ARGS__); \
        pr_flush(); \
    } while (0)
#define pr_success(fmt, ...) do { \
        printf("[%s] " COLOR_GREEN "[+] %s:%d " COLOR_DEFAULT fmt, ks_log_prefix(), __FILE__, __LINE__, ##__VA_ARGS__); \
        pr_flush(); \
    } while (0)
#endif
#else
#ifdef ANDROID_APP_NO_LKM
#define pr_error(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_ERROR, "google_poc_app", "[!] " fmt, ##__VA_ARGS__); \
        if (ks_child_no_atexit) _exit(-1); else exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_WARN, "google_poc_app", "[-] " fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[*] " fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[+] " fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define PR_TIDP (int)syscall(SYS_gettid)
#define pr_error(fmt, ...) do { \
        printf("[%s] " COLOR_RED "[!][t%d] " COLOR_DEFAULT fmt, ks_log_prefix(), PR_TIDP, ##__VA_ARGS__); \
        pr_flush(); \
        if (ks_child_no_atexit) _exit(-1); else exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        printf("[%s] " COLOR_RED "[-][t%d] " COLOR_DEFAULT fmt, ks_log_prefix(), PR_TIDP, ##__VA_ARGS__); \
        pr_flush(); \
    } while (0)
#define pr_info(fmt, ...) do { \
        printf("[%s] " COLOR_YELLOW "[*][t%d] " COLOR_DEFAULT fmt, ks_log_prefix(), PR_TIDP, ##__VA_ARGS__); \
        pr_flush(); \
    } while (0)
#define pr_success(fmt, ...) do { \
        printf("[%s] " COLOR_GREEN "[+][t%d] " COLOR_DEFAULT fmt, ks_log_prefix(), PR_TIDP, ##__VA_ARGS__); \
        pr_flush(); \
    } while (0)
#endif
#endif

#define wait_input(fmt, ...) do { \
        pr_info(fmt, ##__VA_ARGS__); getchar(); \
    } while (0)

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static inline void pin_to_core(size_t core)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    SYSCHK(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset));
}

static inline void reset_cpu_pin(void)
{
    cpu_set_t cpuset;
    memset(&cpuset, 0xff, sizeof(cpu_set_t));
    SYSCHK(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset));
}

static inline void set_limit(void)
{
    struct rlimit r;
    SYSCHK(getrlimit(RLIMIT_NOFILE, &r));
    r.rlim_cur = r.rlim_max;
    SYSCHK(setrlimit(RLIMIT_NOFILE, &r));
    SYSCHK(getrlimit(RLIMIT_NPROC, &r));
    r.rlim_cur = r.rlim_max;
    SYSCHK(setrlimit(RLIMIT_NPROC, &r));
}

static inline void set_unbuffer(void)
{
    SYSCHK(setvbuf(stdin,  NULL, _IONBF, 0));
    SYSCHK(setvbuf(stdout, NULL, _IONBF, 0));
    SYSCHK(setvbuf(stderr, NULL, _IONBF, 0));
}

static inline void set_proc_name(const char *name)
{
    SYSCHK(prctl(PR_SET_NAME, name, 0, 0, 0));
}

static inline size_t gettime_ns(void)
{
    struct timespec t;
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &t));
    return t.tv_nsec + t.tv_sec*1000000000ULL;
}

static void write_file(const char *path, const char *data)
{
    int fd = SYSCHK(open(path, O_WRONLY));
    if (write(fd, data, strlen(data)) != (ssize_t)strlen(data))
        pr_error("write(%s): %m\n", path);
    close(fd);
}


static inline void set_user_namespace(void)
{
    uid_t uid = getuid();
    gid_t gid = getgid();

    SYSCHK(unshare(CLONE_NEWUSER | CLONE_NEWNET));

    write_file("/proc/self/setgroups", "deny");

    char map[128];
    snprintf(map, sizeof(map), "0 %d 1\n", uid);
    write_file("/proc/self/uid_map", map);

    snprintf(map, sizeof(map), "0 %d 1\n", gid);
    write_file("/proc/self/gid_map", map);
}

static inline void hexdump(const void* data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

static inline unsigned long parse_ul(const char *s, const char *name)
{
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 0);
    if (!(errno == 0 && end && *end == '\0'))
        pr_error("invalid %s: %s\n", name, s);
    return v;
}

static inline unsigned long parse_xl(const char *s, const char *name)
{
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 16);
    if (!(errno == 0 && end && *end == '\0'))
        pr_error("invalid %s: %s\n", name, s);
    return v;
}
