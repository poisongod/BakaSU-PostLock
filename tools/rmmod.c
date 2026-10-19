/* Minimal delete_module(2) launcher -- Android toybox has no rmmod.
 * Usage: rmmod <module_name>
 * Needed to reload ocsk.ko with pre-set params (prove whether ocs_init
 * actually runs: load with state=PREINIT, read back whether init's
 * emit() overwrote it).
 * Build (static):
 *   aarch64-linux-android31-clang -static -O2 -o /tmp/opencode/rmmod tools/rmmod.c
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: rmmod <name>\n");
    return 2;
  }
  long rv = syscall(__NR_delete_module, argv[1], 0);
  if (rv != 0) {
    fprintf(stderr, "delete_module %s: %s\n", argv[1], strerror(errno));
    return 1;
  }
  printf("delete_module %s: ok\n", argv[1]);
  return 0;
}
