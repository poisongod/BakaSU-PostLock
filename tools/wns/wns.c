/*
 * wns — SUVTZ 「W 世界」mount namespace helper
 *
 * 为什么需要它（C7，2026-11-09 实测）：
 *   toybox 0.8.4 的 mount 不支持 --make-rprivate / -o rprivate
 *   （当成 fstab 解析，报 "bad /etc/fstab"），而本设备 / 是 shared:1。
 *   只做 unshare(CLONE_NEWNS) 的话，新 ns 的 root mount 仍是 shared:1
 *   的成员 —— 在新 ns 里 mount 会按 shared 语义传播回 peer group 的
 *   所有成员（初始 ns / zygote / app），等于把 W 的对象泄漏给 N。
 *   实测：unshare -m 里 mount tmpfs 后退出，outer ns 里 mountpoint
 *   仍在、marker 文件可见，且 rmdir 删不掉（EBUSY）。
 *
 * 所以顺序必须是：
 *   unshare(CLONE_NEWNS) -> mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)
 *   -> 建挂载
 *
 * 子命令：
 *   wns private            只把当前 mount ns 的 / 设为 rprivate（诊断/前置）
 *   wns hold <dir>         unshare + rprivate + mkdir -p + tmpfs + 子目录
 *                          + 写 holder.pid + 常驻（pause 循环）
 *   wns run <pid> <cmd>... setns 到 /proc/<pid>/ns/mnt + chdir("/") + execvp
 *                          （为什么不用 toybox nsenter：`nsenter -t P -m sh
 *                          -c "..."` 会报 `Unknown option 'c'`——getopt
 *                          permute 把 -c 当自己的选项；而 `nsenter -t P -m
 *                          <cmd> <args>` 又能用，行为随参数形态变化，不可靠。
 *                          自带 exec 入口 = 零引号地狱。）
 *   wns stat <path>...     逐个 lstat 打印（N/W 对照诊断）
 *
 * 退出码：0 成功 / 1 系统调用失败 / 2 用法错误
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PROG "wns"

static void fail(const char *what)
{
	fprintf(stderr, PROG ": %s: %s\n", what, strerror(errno));
	exit(1);
}

static void read_mnt_ns(char *buf, size_t n)
{
	ssize_t r = readlink("/proc/self/ns/mnt", buf, n - 1);
	if (r < 0) {
		snprintf(buf, n, "?");
		return;
	}
	buf[r] = '\0';
}

static void mkdir_p(const char *path, mode_t mode)
{
	char tmp[512];
	size_t len = strlen(path);

	if (len == 0 || len >= sizeof(tmp)) {
		errno = ENAMETOOLONG;
		fail("mkdir_p");
	}
	memcpy(tmp, path, len + 1);
	for (char *p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode) != 0 && errno != EEXIST)
			fail("mkdir_p");
		*p = '/';
	}
	if (mkdir(tmp, mode) != 0 && errno != EEXIST)
		fail("mkdir_p");
}

static int cmd_private(void)
{
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
		fail("mount(MS_REC|MS_PRIVATE)");
	printf(PROG ": private ok\n");
	return 0;
}

static int cmd_hold(const char *dir)
{
	static const char *const subs[] = { "stage", "log", "state" };
	char ns[64];
	char p[512];
	FILE *f;

	if (unshare(CLONE_NEWNS) != 0)
		fail("unshare(CLONE_NEWNS)");
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
		fail("mount(MS_REC|MS_PRIVATE)");

	mkdir_p(dir, 0755);
	if (mount("tmpfs", dir, "tmpfs", 0, "mode=0700") != 0)
		fail("mount(tmpfs)");

	for (size_t i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
		snprintf(p, sizeof(p), "%s/%s", dir, subs[i]);
		if (mkdir(p, 0755) != 0 && errno != EEXIST)
			fail("mkdir(sub)");
	}

	snprintf(p, sizeof(p), "%s/holder.pid", dir);
	f = fopen(p, "w");
	if (f) {
		fprintf(f, "%d\n", (int)getpid());
		fclose(f);
	}

	read_mnt_ns(ns, sizeof(ns));
	printf(PROG ": hold ok dir=%s pid=%d ns=%s\n", dir, (int)getpid(), ns);
	fflush(stdout);

	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	for (;;)
		pause();
	return 0;
}

static int cmd_run(int argc, char **argv)
{
	char path[128];
	char ns[64];
	int fd;

	if (argc < 4) {
		fprintf(stderr, "usage: " PROG " run <holder_pid> <cmd> [args...]\n");
		return 2;
	}
	snprintf(path, sizeof(path), "/proc/%s/ns/mnt", argv[2]);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		fail("open(/proc/<pid>/ns/mnt)");
	if (setns(fd, CLONE_NEWNS) != 0)
		fail("setns(CLONE_NEWNS)");
	close(fd);

	/*
	 * setns 只换挂载视图；进程的 root/cwd 仍指向旧 ns 的 dentry。
	 * chdir("/") 让后续相对/绝对路径解析都落在新 ns 的根上。
	 */
	if (chdir("/") != 0)
		fail("chdir(/)");

	read_mnt_ns(ns, sizeof(ns));
	fprintf(stderr, PROG ": run ns=%s cmd=%s\n", ns, argv[3]);
	fflush(stderr);

	execvp(argv[3], &argv[3]);
	fail("execvp");
	return 1;
}

static int cmd_stat(int argc, char **argv)
{
	int rc = 0;

	for (int i = 2; i < argc; i++) {
		struct stat st;

		if (lstat(argv[i], &st) == 0) {
			printf("%s: exists=1 mode=%o uid=%u size=%lld\n", argv[i],
			       (unsigned)st.st_mode, (unsigned)st.st_uid,
			       (long long)st.st_size);
		} else {
			printf("%s: exists=0 errno=%d(%s)\n", argv[i], errno,
			       strerror(errno));
			rc = 0; /* 诊断命令：ENOENT 是有效结果，不算失败 */
		}
	}
	return rc;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr,
			"usage: " PROG " private | hold <dir> | run <pid> <cmd>... | stat <path>...\n");
		return 2;
	}
	if (!strcmp(argv[1], "private"))
		return cmd_private();
	if (!strcmp(argv[1], "hold")) {
		if (argc < 3) {
			fprintf(stderr, "usage: " PROG " hold <dir>\n");
			return 2;
		}
		return cmd_hold(argv[2]);
	}
	if (!strcmp(argv[1], "run"))
		return cmd_run(argc, argv);
	if (!strcmp(argv[1], "stat"))
		return cmd_stat(argc, argv);

	fprintf(stderr, PROG ": unknown subcommand: %s\n", argv[1]);
	return 2;
}
