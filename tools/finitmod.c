/* Minimal finit_module(2) launcher for the kernelsu.ko bootstrap.
 * Usage: finitmod <path/to.ko> [flags] [param=val ...]
 * flags must be passed explicitly (default 0): a bare `finitmod file`
 * invocation returns ENOEXEC on this kernel.
 * Extra args after flags are joined with spaces into the finit_module
 * param_values string (round: prove whether ocs_init runs by loading
 * with a pre-set param and checking whether init overwrites it).
 * Build (static, like the on-device copy):
 *   aarch64-linux-android31-clang -static -O2 -o build/embed/finitmod tools/finitmod.c
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: finitmod <ko> [flags]\n");
    return 2;
  }
  long flags = 0;
  if (argc >= 3) {
    char *end = NULL;
    flags = strtol(argv[2], &end, 0);
    if (!end || *end) {
      fprintf(stderr, "bad flags: %s\n", argv[2]);
      return 2;
    }
  }
  int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  char params[1024];
  params[0] = '\0';
  for (int i = 3; i < argc; i++) {
    if (i > 3) strncat(params, " ", sizeof(params) - strlen(params) - 1);
    strncat(params, argv[i], sizeof(params) - strlen(params) - 1);
  }
  long rv = syscall(__NR_finit_module, fd, params, (int)flags);
  int saved = errno;
  close(fd);
  if (rv != 0) {
    errno = saved;
    perror("finit_module");
    return 1;
  }
  return 0;
}
