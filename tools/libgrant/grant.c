#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <dlfcn.h>

#define GRANT_LOG   "/data/local/tmp/grant.log"
#define PROFILE_F   "/data/local/tmp/su_profiles.dat"
#define FEATURES_F  "/data/local/tmp/su_features"
#define ALLOW_F     "/data/local/tmp/su.allow"
#define VERBOSE_F   "/data/local/tmp/grant_verbose"

#define VER          35193
#define UAPI_VER     4
#define FEATURES_MAX 5
#define MGR_UID      10282
#define KSU_UID      10283
#define SHELL_UID    2000
#define STORE_MAGIC  0x5055534B
#define PROF_SZ      784
#define KEY_SZ       256
#define REC_SZ       (KEY_SZ + PROF_SZ)
#define MAX_RECS     64

#define OFF_KEY      4
#define OFF_UID      0x104
#define OFF_ALLOW    0x108
#define OFF_RP_DEF   0x110
#define OFF_NRP_DEF  0x110
#define OFF_NRP_UMT  0x111

#define FEAT_SU      0
#define FEAT_UMOUNT  1

static int g_verbose;

static void glog(const char *fmt, ...) {
  FILE *f = fopen(GRANT_LOG, "a");
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  fclose(f);
}

struct rec {
  char key[KEY_SZ];
  unsigned char blob[PROF_SZ];
};

static struct {
  int n;
  struct rec r[MAX_RECS];
} g_store;

static int64_t g_feat[8];

static int find_key(const char *key) {
  for (int i = 0; i < g_store.n; i++)
    if (memcmp(g_store.r[i].key, key, KEY_SZ) == 0) return i;
  return -1;
}

static void save_store(void) {
  FILE *f = fopen(PROFILE_F, "wb");
  if (!f) { glog("save_store fail\n"); return; }
  uint32_t hdr[2] = { STORE_MAGIC, (uint32_t)g_store.n };
  fwrite(hdr, 4, 2, f);
  fwrite(g_store.r, REC_SZ, (size_t)g_store.n, f);
  fclose(f);
}

static void load_store(void) {
  FILE *f = fopen(PROFILE_F, "rb");
  if (!f) return;
  uint32_t hdr[2] = {0, 0};
  if (fread(hdr, 4, 2, f) == 2 && hdr[0] == STORE_MAGIC) {
    uint32_t n = hdr[1];
    if (n > MAX_RECS) n = MAX_RECS;
    g_store.n = (int)fread(g_store.r, REC_SZ, n, f);
  }
  fclose(f);
  glog("store loaded n=%d\n", g_store.n);
}

static int uid_granted(uint32_t uid) {
  for (int i = 0; i < g_store.n; i++) {
    if (g_store.r[i].blob[OFF_ALLOW]) {
      uint32_t u;
      memcpy(&u, g_store.r[i].blob + OFF_UID, 4);
      if (u == uid) return 1;
    }
  }
  return 0;
}

static int granted_uids(uint32_t *out, int max) {
  int n = 0;
  for (int i = 0; i < g_store.n && n < max; i++) {
    if (g_store.r[i].blob[OFF_ALLOW]) {
      uint32_t u;
      memcpy(&u, g_store.r[i].blob + OFF_UID, 4);
      out[n++] = u;
    }
  }
  return n;
}

static void update_allow_file(void) {
  uint32_t seeds[3] = { MGR_UID, KSU_UID, SHELL_UID };
  uint32_t uids[80];
  int n = granted_uids(uids, 64);
  for (int i = 0; i < 3; i++) {
    int dup = 0;
    for (int j = 0; j < n; j++) if (uids[j] == seeds[i]) dup = 1;
    if (!dup && n < 80) uids[n++] = seeds[i];
  }
  FILE *f = fopen(ALLOW_F, "w");
  if (!f) { glog("allow write fail\n"); return; }
  for (int i = 0; i < n; i++) fprintf(f, "%u\n", uids[i]);
  fclose(f);
  chmod(ALLOW_F, 0666);
  glog("su.allow rewritten n=%d\n", n);
}

static void load_features(void) {
  for (int i = 0; i < 8; i++) g_feat[i] = -1;
  g_feat[FEAT_SU] = 1;
  g_feat[FEAT_UMOUNT] = 1;
  FILE *f = fopen(FEATURES_F, "r");
  if (!f) return;
  int id;
  long long v;
  while (fscanf(f, "%d %lld", &id, &v) == 2)
    if (id >= 0 && id < 8) g_feat[id] = v;
  fclose(f);
}

static void save_feature(int id, int64_t v) {
  g_feat[id] = v;
  FILE *f = fopen(FEATURES_F, "w");
  if (!f) return;
  for (int i = 0; i < 8; i++)
    if (g_feat[i] >= 0) fprintf(f, "%d %lld\n", i, (long long)g_feat[i]);
  fclose(f);
  chmod(FEATURES_F, 0666);
}

static void set_profile(const unsigned char *blob) {
  const char *key = (const char *)blob + OFF_KEY;
  int idx = find_key(key);
  if (idx < 0) {
    if (g_store.n >= MAX_RECS) { glog("store full\n"); return; }
    idx = g_store.n++;
  }
  memcpy(g_store.r[idx].blob, blob, PROF_SZ);
  memset(g_store.r[idx].key, 0, KEY_SZ);
  memcpy(g_store.r[idx].key, key, KEY_SZ);
  glog("SET profile key=%.100s uid=%d allow=%d\n", key,
       *(int32_t *)(blob + OFF_UID), blob[OFF_ALLOW]);
  save_store();
  update_allow_file();
}

__attribute__((constructor))
static void grant_init(void) {
  g_verbose = !access(VERBOSE_F, F_OK);
  load_store();
  load_features();
  update_allow_file();
  glog("== grant v3 init pid=%d verbose=%d ==\n", getpid(), g_verbose);
}

static int get_profile(unsigned char *blob) {
  const char *key = (const char *)blob + OFF_KEY;
  int idx = find_key(key);
  if (idx < 0) {
    static char seen[32][KEY_SZ];
    static int nseen;
    int rep = 0;
    for (int i = 0; i < nseen; i++)
      if (memcmp(seen[i], key, KEY_SZ) == 0) rep = 1;
    if (!rep && nseen < 32) { memcpy(seen[nseen++], key, KEY_SZ);
      glog("GET profile miss key=%.100s\n", key); }
    return -1;
  }
  memcpy(blob, g_store.r[idx].blob, PROF_SZ);
  if (g_verbose) {
    static char seen[32][KEY_SZ];
    static int nseen;
    int rep = 0;
    for (int i = 0; i < nseen; i++)
      if (memcmp(seen[i], key, KEY_SZ) == 0) rep = 1;
    if (!rep && nseen < 32) {
      memcpy(seen[nseen++], key, KEY_SZ);
      glog("GET profile hit key=%.100s allow=%d\n", key, blob[OFF_ALLOW]);
    }
  }
  return 0;
}

static int handle_ioctl(unsigned long request, void *arg) {
  unsigned nr = request & 0xff;
  unsigned sz = (request >> 16) & 0x3fff;

  if (!arg) return 0;

  switch (nr) {
  case 0x01:
    return 0;
  case 0x02: {
    uint32_t *v = arg;
    v[0] = VER;
    v[1] = (1u << 1) | (1u << 2);
    v[2] = FEATURES_MAX;
    v[3] = UAPI_VER;
    return 0;
  }
  case 0x03:
  case 0x04:
    return 0;
  case 0x05:
    ((uint8_t *)arg)[0] = 0;
    return 0;
  case 0x06:
  case 0x07: {
    int deny = (nr == 0x07);
    if (sz == 0) {
      uint32_t *uids = arg;
      uint32_t *count = (uint32_t *)((char *)arg + 512);
      uint8_t *allow = (uint8_t *)((char *)arg + 516);
      uint32_t tmp[64];
      int n = 0;
      if (*allow && !deny) n = granted_uids(tmp, 64);
      for (int i = 0; i < n && i < 128; i++) uids[i] = tmp[i];
      *count = (uint32_t)n;
      return 0;
    }
    uint16_t *count = arg;
    uint16_t *total = (uint16_t *)((char *)arg + 2);
    uint32_t *uids = (uint32_t *)((char *)arg + 4);
    uint32_t tmp[64];
    int n = deny ? 0 : granted_uids(tmp, 64);
    int cap = *count;
    *total = (uint16_t)n;
    int w = n < cap ? n : cap;
    for (int i = 0; i < w; i++) uids[i] = tmp[i];
    *count = (uint16_t)w;
    return 0;
  }
  case 0x08: {
    uint32_t uid;
    memcpy(&uid, arg, 4);
    ((uint8_t *)arg)[4] = uid_granted(uid) ? 1 : 0;
    if (g_verbose) glog("UID_GRANTED uid=%u -> %d\n", uid, ((uint8_t *)arg)[4]);
    return 0;
  }
  case 0x09: {
    uint32_t uid;
    memcpy(&uid, arg, 4);
    ((uint8_t *)arg)[4] = uid_granted(uid) ? 0 : 1;
    return 0;
  }
  case 0x0a:
    *(uint32_t *)arg = MGR_UID;
    return 0;
  case 0x0b:
    return get_profile(arg);
  case 0x0c:
    set_profile(arg);
    return 0;
  case 0x0d: {
    uint32_t id;
    memcpy(&id, arg, 4);
    uint64_t val = 0;
    uint8_t sup = 0;
    if (id < 8 && g_feat[id] >= 0) { val = (uint64_t)g_feat[id]; sup = 1; }
    if (id == 2 || id == 3 || id == 4) { val = 0; sup = 0; }
    memcpy((char *)arg + 8, &val, 8);
    ((uint8_t *)arg)[16] = sup;
    if (g_verbose) glog("GET_FEATURE id=%u v=%llu sup=%d\n", id,
                         (unsigned long long)val, sup);
    return 0;
  }
  case 0x0e: {
    uint32_t id;
    uint64_t val;
    memcpy(&id, arg, 4);
    memcpy(&val, (char *)arg + 8, 8);
    if (id < 8) {
      save_feature(id, (int64_t)val);
      glog("SET_FEATURE id=%u v=%llu\n", id, (unsigned long long)val);
    }
    return 0;
  }
  case 0x64:
    strncpy(arg, "v4.2.0-rc3 (35193/4)", 254);
    return 0;
  case 0x65:
    strncpy(arg, "manual", 31);
    return 0;
  case 0x67:
    if (((uint8_t *)arg)[0] == 1) {
      memset(arg, 0, 72);
    }
    return 0;
  case 0x69: {
    uint16_t *count = arg;
    uint16_t *total = (uint16_t *)((char *)arg + 2);
    struct { uint32_t uid; uint8_t sig; } __attribute__((packed)) *ents =
        (void *)((char *)arg + 4);
    static const uint32_t mgrs[2] = { MGR_UID, KSU_UID };
    int n = 2;
    *total = (uint16_t)n;
    int w = *count < n ? *count : n;
    for (int i = 0; i < w; i++) { ents[i].uid = mgrs[i]; ents[i].sig = (uint8_t)i; }
    *count = (uint16_t)w;
    if (g_verbose) glog("GET_MANAGERS in_count -> w=%d\n", w);
    return 0;
  }
  case 0x6a:
    ((uint8_t *)arg)[0] = 0;
    return 0;
  default:
    if (g_verbose || (nr != 0x0f && nr != 0x10 && nr != 0x11 &&
                      nr != 0x12 && nr != 0x13 && nr != 0x14 && nr != 0x15))
      glog("IOCTL unknown nr=0x%x req=0x%lx\n", nr, request);
    return 0;
  }
}

static int fd_is_ksu_driver(int fd) {
  char path[64], link[80];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
  ssize_t n = readlink(path, link, sizeof(link) - 1);
  if (n <= 0) return 0;
  link[n] = '\0';
  return strstr(link, "ksu_driver") != NULL;
}

static int any_ksu_driver_fd(void) {
  DIR *d = opendir("/proc/self/fd");
  if (!d) return 0;
  int found = 0;
  struct dirent *e;
  char path[64], link[80];
  while ((e = readdir(d))) {
    if (e->d_name[0] == '.') continue;
    snprintf(path, sizeof(path), "/proc/self/fd/%s", e->d_name);
    ssize_t n = readlink(path, link, sizeof(link) - 1);
    if (n > 0) {
      link[n] = '\0';
      if (strstr(link, "ksu_driver")) { found = 1; break; }
    }
  }
  closedir(d);
  return found;
}

int ioctl(int fd, int request_, ...) {
  unsigned long request = (unsigned)request_;
  static int (*real_ioctl)(int, unsigned long, void *);
  if (!real_ioctl) real_ioctl = dlsym(RTLD_NEXT, "ioctl");
  va_list ap;
  va_start(ap, request_);
  void *arg = va_arg(ap, void *);
  va_end(ap);

  if (((request >> 8) & 0xff) == 0x4b) {
    if (fd_is_ksu_driver(fd)) {
      unsigned nr = request & 0xff;
      int ret = real_ioctl(fd, (int)request, arg);
      if (g_verbose || nr == 0x01 || nr == 0x0c)
        glog("IOCTL passthrough nr=0x%x ret=%d\n", nr, ret);
      if (ret == 0 && nr == 0x0c && arg)
        set_profile((const unsigned char *)arg);
      return ret;
    }
    return handle_ioctl(request, arg);
  }
  return real_ioctl(fd, (int)request, arg);
}

static void legacy_fill_list(int *uids, int *count_out) {
  uint32_t tmp[64];
  int n = granted_uids(tmp, 64);
  for (int i = 0; i < n && i < 64; i++) uids[i] = (int)tmp[i];
  if (count_out) *count_out = n;
}

static int legacy_magic_done(unsigned long a5) {
  if (a5) *(int32_t *)a5 = 0xdeadbeef;
  return -1;
}

static int handle_legacy(unsigned long cmd, unsigned long a3,
                         unsigned long a4, unsigned long a5) {
  switch (cmd) {
  case 0: {
    uint32_t uid = a3 ? (uint32_t)a3 : (uint32_t)getuid();
    uint8_t blob[PROF_SZ] = {0};
    snprintf((char *)blob + OFF_KEY, KEY_SZ, "legacy.uid.%u", uid);
    blob[OFF_ALLOW] = 1;
    memcpy(blob + OFF_UID, &uid, 4);
    set_profile(blob);
    return legacy_magic_done(a5);
  }
  case 2:
    if (a3) *(uint32_t *)a3 = VER;
    if (a4) *(uint32_t *)a4 = (1u << 1) | (1u << 2);
    return legacy_magic_done(a5);
  case 3: {
    uint32_t uid = (uint32_t)a3;
    uint8_t blob[PROF_SZ] = {0};
    snprintf((char *)blob + OFF_KEY, KEY_SZ, "legacy.uid.%u", uid);
    blob[OFF_ALLOW] = 1;
    memcpy(blob + OFF_UID, &uid, 4);
    set_profile(blob);
    return legacy_magic_done(a5);
  }
  case 4: {
    uint32_t uid = (uint32_t)a3;
    for (int i = 0; i < g_store.n; i++) {
      uint32_t u;
      memcpy(&u, g_store.r[i].blob + OFF_UID, 4);
      if (u == uid && g_store.r[i].blob[OFF_ALLOW]) {
        g_store.r[i].blob[OFF_ALLOW] = 0;
        glog("legacy DENY uid=%u\n", uid);
      }
    }
    save_store();
    update_allow_file();
    return legacy_magic_done(a5);
  }
  case 5:
    if (a3 && a4) legacy_fill_list((int *)a3, (int *)a4);
    return legacy_magic_done(a5);
  case 6:
    if (a4) *(int *)a4 = 0;
    return legacy_magic_done(a5);
  case 9:
    return -1;
  case 10:
    if (a3) {
      if (get_profile((unsigned char *)a3) == 0)
        return legacy_magic_done(a5);
    }
    if (a5) *(int32_t *)a5 = 0;
    return -1;
  case 11:
    if (a3) set_profile((unsigned char *)a3);
    return legacy_magic_done(a5);
  case 12:
    if (a3 && a4) *(uint8_t *)a4 = uid_granted((uint32_t)a3) ? 1 : 0;
    return legacy_magic_done(a5);
  case 13:
    if (a3 && a4) *(int *)a4 = uid_granted((uint32_t)a3) ? 0 : 1;
    return legacy_magic_done(a5);
  case 14:
    if (a3) *(int *)a3 = g_feat[FEAT_SU] ? 1 : 0;
    return legacy_magic_done(a5);
  case 15:
    if (a3) save_feature(FEAT_SU, (int64_t)a3 ? 1 : 0);
    return legacy_magic_done(a5);
  case 0xC0FFEE1A:
    if (a3) strncpy((char *)a3, "v4.2.0-rc3 (35193/4)", 254);
    return legacy_magic_done(a5);
  case 101:
    if (a3) strncpy((char *)a3, "manual", 15);
    return legacy_magic_done(a5);
  case 103:
    if (a3) memset((void *)a3, 0, 72);
    return legacy_magic_done(a5);
  case 104: {
    if (a3) {
      uint16_t *count = (uint16_t *)a3;
      uint16_t *total = (uint16_t *)(a3 + 2);
      struct { uint32_t uid; uint8_t sig; } __attribute__((packed)) *ents =
          (void *)(a3 + 4);
      static const uint32_t mgrs[2] = { MGR_UID, KSU_UID };
      *total = 2;
      int w = *count < 2 ? *count : 2;
      for (int i = 0; i < w; i++) { ents[i].uid = mgrs[i]; ents[i].sig = (uint8_t)i; }
      *count = (uint16_t)w;
    }
    return legacy_magic_done(a5);
  }
  default:
    if (a5) *(int32_t *)a5 = 0;
    if (g_verbose) glog("PRCTL legacy unsupported cmd=%lu\n", cmd);
    return -1;
  }
}

int prctl(int option, ...) {
  static int (*real_prctl)(int, unsigned long, unsigned long, unsigned long,
                           unsigned long);
  if (!real_prctl)
    real_prctl = dlsym(RTLD_NEXT, "prctl");
  va_list ap;
  va_start(ap, option);
  unsigned long a2 = va_arg(ap, unsigned long);
  unsigned long a3 = va_arg(ap, unsigned long);
  unsigned long a4 = va_arg(ap, unsigned long);
  unsigned long a5 = va_arg(ap, unsigned long);
  va_end(ap);

  if (option == 0xdeadbeef) {
    if (any_ksu_driver_fd()) {
      if (g_verbose) glog("PRCTL legacy passthrough driver fd present\n");
      return real_prctl(option, a2, a3, a4, a5);
    }
    return handle_legacy(a2, a3, a4, a5);
  }
  return real_prctl(option, a2, a3, a4, a5);
}
