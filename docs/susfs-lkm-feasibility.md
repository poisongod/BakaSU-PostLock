# SUSFS LKM 化可行性评估与实施记录

日期：2026-11-01（初稿 2026-10-31，本节为按 GKI 基线订正后的版本）
基线：`ShirkNeko/susfs4ksu` 分支 **`gki-android12-5.10`**（SuSFS v2.3.0）
目标设备：PFUM10 / Android 12 / 5.4.254-qgki（回锁，无 fastboot 刷写能力）

## 0. 基线的重新选定（订正初稿的错误）

初稿以 `susfs4ksu` 的 `kernel-5.4` 分支（v1.5.5）为基线，**这是错的**，理由：

| 候选 | 结论 |
|---|---|
| `simonpunk/susfs4ksu` master | API 已重构：缺 `susfs_show_version` / `susfs_add_sus_path_loop` / `susfs_add_sus_map` / `susfs_set_avc_log_spoofing`，与 BakaSU `dispatch.c` 的命令表**对不上** |
| `kernel-5.4` 分支（v1.5.5） | 缺 8 个 BakaSU 需要的函数；`git log --all -S` 证明这些符号在该分支**从未存在过** |
| **`gki-android12-5.10`（v2.3.0）** | **全部命中**：`susfs.h` 的函数签名清一色 `void f(void __user **user_info)`，与 `dispatch.c` 逐字匹配；命令码与 `userspace/ksud/src/android/susfs/api/magic.rs` 一致；结构体成员**零改动** |

所谓「5.10 分支」只是**上游维护的分支名**，它打的是「GKI 通用补丁」，
不绑定 5.10 的任何内核内部 API。真正的版本敏感面（`inode->i_state` 位、
`task_struct` 字段、`vfsmount` 字段）见 §3.2，均可在 5.4 上用替代方案实现。

**结论：`gki-android12-5.10` 的 `include/linux/susfs.h` 就是 ABI 唯一权威**，
原样拷贝进仓库（`kernel/susfs/include/linux/susfs.h`，253 行，一字未改）。

## 1. 为什么只能走 LKM，以及为什么不拆独立 ko

上游 SUSFS 是**内核补丁**：GKI 补丁 2816 行，编辑 `fs/namei.c`、`fs/namespace.c`、
`fs/proc/*`、`security/selinux/*` 等约 25 个文件，并新落 `fs/susfs.c`（1948 行）。
本设备回锁，无法刷入自编译 boot.img，唯一可用的内核代码注入通道是 **`insmod`**
（链提权后 `finitmod` late-load）。因此 SUSFS 必须：

- 内核补丁点用 **kprobe/kretprobe** 替代；
- 上游新增的 per-inode / per-task 字段用**位标记 + 哈希表**替代；
- 复用现有字段（`inode->i_mapping->flags` 高位）不改结构体。

**架构定案：SUSFS 集成进 `kernelsu.ko` 单模块**，不拆独立 `susfs_lkm.ko`：

| 拆分方案的问题 | 单模块的收益 |
|---|---|
| 跨模块 UND 解析：5.4 `kallsyms_lookup_name` 只查内核镜像**不查模块符号**（`infra/symbol_resolver.c` 注释自证），`EXPORT_SYMBOL_GPL` 需要 Module.symvers 而我们无（modpost no-op 放行靠加载器解析 ksymtab，脆弱） | 无跨模块依赖，直接函数调用 |
| 加载顺序依赖：susfs 必须先于 kernelsu，否则 `dispatch.c` 的 susfs 分发指向未解析符号 | 无顺序问题 |
| 双重 kprobe：两个模块各自注册 `__arm64_sys_reboot` pre_handler，语义互相覆盖 | 复用 `kernelsu.ko` 已有的 `reboot_handler_pre` kprobe |

`kernelsu.ko` 已经有 `ksu_handle_sys_reboot()`（`supercall/supercall.c`）+
`reboot_handler_pre`（kprobe on `__arm64_sys_reboot`），天然承接 SUSFS magic 分发。

## 2. ABI 契约（双端逐项核实）

### 2.1 调用链

```
userspace: syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, cmd, &mut info)
    ↓
kprobe pre_handler on __arm64_sys_reboot  (supercall/supercall.c: reboot_handler_pre)
    ↓
ksu_handle_sys_reboot(magic1, magic2, cmd, arg)
    arg = &PT_REGS_SYSCALL_PARM4(regs)        ← 用户指针的指针
    ↓  (magic2 == SUSFS_MAGIC 且 current_uid()==0)
ksu_handle_susfs_cmd(cmd, arg)                (supercall/dispatch.c:1008)
    ↓
susfs_show_version(user_info) 等             ← copy_from_user(&info, *user_info, ...)
```

### 2.2 命令码（与 `magic.rs` 一致）

`ADD_SUS_PATH 0x55550`、`ADD_SUS_PATH_LOOP 0x55553`、`HIDE_SUS_MNTS_FOR_NON_SU_PROCS 0x55561`、
`ADD_SUS_KSTAT 0x55570`、`UPDATE_SUS_KSTAT 0x55571`、`ADD_SUS_KSTAT_STATICALLY 0x55572`、
`SET_UNAME 0x55590`、`ENABLE_LOG 0x555a0`、`SET_CMDLINE_OR_BOOTCONFIG 0x555b0`、
`ADD_OPEN_REDIRECT 0x555c0`、`SHOW_VERSION 0x555e1`、`SHOW_ENABLED_FEATURES 0x555e2`、
`SHOW_VARIANT 0x555e3`、`ENABLE_AVC_LOG_SPOOFING 0x60010`、`ADD_SUS_MAP 0x60020`。
`SUSFS_MAGIC 0xFAFAFAFA`、`KSU_INSTALL_MAGIC1 0xDEADBEEF`。

### 2.3 结构体布局（与 `magic.rs` 的 `#[repr(C)]` 一致）

| 结构体 | 布局 | 尺寸常量 |
|---|---|---|
| `st_susfs_log` | `bool enabled; int err;` | — |
| `st_susfs_version` | `char[16]; int err;` | `SUSFS_MAX_VERSION_BUFSIZE 16` |
| `st_susfs_variant` | `char[16]; int err;` | `SUSFS_MAX_VARIANT_BUFSIZE 16` |
| `st_susfs_enabled_features` | `char[8192]; int err;` | `SUSFS_ENABLED_FEATURES_SIZE 8192` |
| `st_susfs_avc_log_spoofing` | `bool; int` | — |

`SUSFS_MAX_LEN_PATHNAME` = 256，与 `magic.rs` 一致。

### 2.4 错误语义

`err` 字段的**初值**即「未支持」：`dispatch.c` 对未识别的命令返回 0 且**不写用户
结构体**，用户侧 `err` 保持调用前填入的 `ERR_CMD_NOT_SUPPORTED`（126）→
`parse_err()` 打出 `Unsupported SuSFS command: 0x...`。内核写 0 才算成功。
`ERR_CMD_NOT_SUPPORTED` 定义在 `susfs_def.h`（值 126）。

### 2.5 管理器判据链

`SuSFSConfigHelper.loadStatusInfo()` → `ksud susfs show version`
（`android/cli.rs:170`）→ `show.rs::version()` 要求 `err==0` **且字符串以 `v` 开头**，
否则返回 `"Unsupported"`。主页无 SUSFS 卡，展示在 `SuSFSConfigStatusTab.kt`。

## 3. 架构与约束

### 3.1 `CONFIG_KSU_SUSFS` 只能 per-file 定义

上游 `Kbuild:189` 的 `else ifdef CONFIG_KSU_SUSFS` 与 `CONFIG_KSU_TRACEPOINT_HOOK`
**互斥**（`else if` 链）。若全局 `ccflags-y += -DCONFIG_KSU_SUSFS`：

| 文件 | 后果 |
|---|---|
| `feature/sucompat.h:17` | `ksu_handle_faccessat` 签名变为 `struct filename **`，与 TRACEPOINT 调用点不匹配 → **编译失败** |
| `feature/sucompat.c:343` | 激活 `do_ksu_handle_execveat_sucompat` 死块 |
| `feature/kernel_umount.c:143` | `susfs_extra_works` / `susfs_set_current_proc_umounted` 未定义 |

**实际接线**（`Kbuild:39-64`，宏范围已逐文件核实）：

```makefile
ccflags-y += -I$(src)/susfs/include
kernelsu-objs += susfs/susfs.o
CFLAGS_susfs/susfs.o       += -DCONFIG_KSU_SUSFS -DCONFIG_KSU_SUSFS_ENABLE_LOG
CFLAGS_supercall/dispatch.o  += -DCONFIG_KSU_SUSFS -DCONFIG_KSU_SUSFS_ENABLE_LOG
CFLAGS_supercall/supercall.o += -DCONFIG_KSU_SUSFS
CFLAGS_core/init.o           += -DKSU_SUSFS_LKM
```

- **不传 make 变量 `CONFIG_KSU_SUSFS=y`**：那会走 `Kbuild:189` 分支
  `$(error You should integrate susfs in your kernel)` 并要求 `$(srctree)/fs/susfs.c`。
  宏只走 per-object `CFLAGS_*`。
- 已核实 `dispatch.c` / `supercall.c` 都**不调用** `is_zygote_next` /
  `susfs_get_sid_from_name` / `susfs_get_current_sid` /
  `susfs_is_current_zygote_domain`，且不经 `internal.h` 包含 `feature/sucompat.h`
  → **无签名/链接失配风险**。
- `dispatch.c` 内部所有 `#elif defined(CONFIG_KSU_SUSFS)` 都在
  `#if defined(CONFIG_KSU_TRACEPOINT_HOOK)` **之后**（:541、:916），TRACEPOINT 优先
  → 行为不变；只有 `:175`（`susfs_start_sdcard_monitor_fn`）与 `:1008+`
  （`ksu_handle_susfs_cmd`）真正激活。

### 3.2 上游 per-inode / per-task 字段的替代

| 上游字段（补丁新增） | LKM 替代 | 说明 |
|---|---|---|
| `inode->i_state` BIT24-27 | **直接复用** | 5.4 `i_state` 仅用 bit0-17，BIT24-27 空闲 |
| `inode->i_mapping->flags` BIT33-39 | **直接复用** | `AS_FLAGS_SUS_PATH 33` … `AS_FLAGS_SUS_MAP 39`，`unsigned long` 有富余 |
| `task_struct->susfs_task_state` | 复用 `TIF_*` 位 33-35 | `TIF_PROC_UMOUNTED 33` / `TIF_PROC_NO_SU 34` / `TIF_PROC_UMOUNTED_FOR_ZYGOTE_NEXT 35`，5.4 的 `TIF_` 编号 0-32 已用，33+ 空闲 |
| `vfsmount->susfs_mnt_id_backup` | `struct vfsmount *` → u64 哈希表 | mount 释放时清理（kretprobe `alloc_vfsmnt` / `mntput`） |
| `mount->mnt_id` 伪造 | **直接写字段**（kretprobe `alloc_vfsmnt`） | 字段现成 |

### 3.3 日志开关：普通 bool，不用 static key

`DEFINE_STATIC_KEY_TRUE` 语义更优雅，但 SuSFS 命令**全部从 `__arm64_sys_reboot`
的 kprobe pre_handler（debug-exception 上下文）进来**，而切换 static key 要取
`jump_label_mutex` + `cpus_read_lock()` 并跨 CPU 打补丁。改用普通 `bool` +
`READ_ONCE/WRITE_ONCE`：userspace 语义完全一致，且不取锁。

### 3.4 `susfs_init()` 必须自己调

`core/init.c:121` 的 `susfs_init()` 调用位于 `#elif defined(CONFIG_KSU_SUSFS)`
（inline-hook 分支），我们走 TRACEPOINT 分支 → 永不执行。
已在 `ksu_hook_init()` 的 TRACEPOINT 分支加
`#ifdef KSU_SUSFS_LKM susfs_init(); #endif`（配 `CFLAGS_core/init.o += -DKSU_SUSFS_LKM`
+ 局部 `extern void susfs_init(void);`）。

### 3.5 `susfs_start_sdcard_monitor_fn()` 在 late 模式永不调用

`dispatch.c:175` 该调用位于 `else`（`ksu_late_loaded == false`）分支。真协议修复后
我们**真实**走 late 分支 → 永不调用。阶段 1 实现为空实现 + 日志；阶段 3 起由
`susfs_init()` 自行启动监控。

### 3.6 子功能宏只对「已实现且已验证」的特性定义

`susfs_get_enabled_features()` 的列表**完全由 `#ifdef CONFIG_KSU_SUSFS_*` 驱动**
→ 天然诚实上报。未实现命令统一回 `ERR_CMD_NOT_SUPPORTED`(126)，userspace 显示
`Unsupported SuSFS command: 0x...`。这是本项目「真协议」红线在内核侧的直接体现。

## 4. 符号存在性验证（离线 kallsyms，实测）

工具：`build/work/query_syms{,2,3}.py` / `build/work/harvest_ocs.py`
数据源：`build/work/bootdump.img`（原厂 boot dump，`link base = 0xffffffc010080000`）
校准：`sig_enforce == 0x2b89d20`（与 `target.h` 一致，parser 漂移会 assert 失败）
规模：188404 条 kallsyms / 183768 唯一符号

### 4.1 可直接 kprobe 的符号（存在且为 text）

| 功能 | 符号 | 类型 | offset |
|---|---|---|---|
| readdir 隐藏 | `filldir64$51ab165f5837f477524e9ebb077c85c5` | t | 0x004ca910 |
| kallsyms 隐藏 | `s_show$80702cd9ac3638c742d93a67d4b2ce56` | t | 0x00355ec4 |
| /proc/mounts | `show_vfsmnt$55b24370bfac44f0022045815b5292f1` | t | 0x0050d6cc |
| /proc/self/mountinfo | `show_mountinfo$55b24370bfac44f0022045815b5292f1` | t | 0x0050da94 |
| uname 伪造 | `__arm64_sys_newuname` | T | 0x0029455c |
| open 拦截 | `may_open` | t | 0x004c6fa4 |
| unlink 拦截 | `may_delete` | t | 0x004c2610 |
| create 拦截 | `may_create` | t | 0x006bfc90 |
| lookup 拦截 | `__lookup_hash` | t | 0x004bf4ac |
| lookup 慢路径 | `__lookup_slow` | t | 0x004bfaac |
| dcache 快路径 | `__d_lookup` / `__d_lookup_rcu` | T | — |
| 路径遍历 | `link_path_walk` | t | 0x004c4ca4 |
| stat 伪造 | `generic_fillattr`（void → **kretprobe**） | T | — |
| statx | `vfs_statx` / `vfs_getattr` | T | — |
| statfs | `vfs_statfs` / `user_statfs` / `fd_statfs` | T | — |
| 挂载创建 | `alloc_vfsmnt` / `vfs_create_mount` / `clone_mnt` / `attach_recursive_mnt` | t/T | — |
| 挂载移动 | `do_move_mount` | t | — |
| kallsyms 值 | `kallsyms_show_value` | T | 0x00355d24 |
| devpts | `devpts_get_priv` | T | — |

**CFI 哈希后缀说明**：Android 内核 `CONFIG_CFI_CLANG` + LTO 会给 `static`
函数加 `$<file-hash>` 后缀（同一 `.c` 文件共享一个哈希）。该哈希对**固定内核镜像
稳定**，但对内核升级不稳定 —— 模块需要「编译期硬编码 + 运行时 `/proc/kallsyms`
前缀匹配」双路解析（`infra/symbol_resolver.c` 的
`find_kernel_symbol_exact()` / `ksu_resolve_symbol_for_functable_hook()`）。

### 4.2 被 inline 掉的符号（改用其调用者）

| 缺失符号 | inline 到 | 替代方案 |
|---|---|---|
| `may_linkat` / `may_follow_link` / `may_o_create` / `may_create_in_sticky` | `link_path_walk` / `do_filp_open` | 靠 `may_open` + `__lookup_*` 覆盖 |
| `lookup_open` / `do_open` / `open_last_lookups` | `path_openat` | kprobe `path_openat` / `do_filp_open` |
| `mnt_alloc_id` / `mnt_free_id` / `mnt_alloc_group_id` | `alloc_vfsmnt` / `vfs_create_mount` | kretprobe `alloc_vfsmnt` 改 `mount->mnt_id` |
| `do_reconfigure_mnt` | `do_mount` 内 | 放弃（影响面小） |
| `do_execveat_common` / `bprm_execve` | `__arm64_sys_execve*` | kprobe syscall 入口 |
| `override_release` | `__arm64_sys_newuname` 内 | 直接改用户缓冲区 |

### 4.3 结论

**所有 SUSFS 核心 hook 点都可达**（直接或经调用者），不存在「做不到」的功能，
只有「语义不完全等价」的功能（见 §5）。

### 4.4 GKI 实现的 7 个真 extern（后续阶段需自实现）

`susfs_is_current_ksu_domain()`、`susfs_get_non_sus_mnt_id_from_mnt()`、
`susfs_get_non_sus_vfsmnt_from_vfsmnt()`、`calculate_f_flags_wrapper`、
`statfs_by_dentry_wrapper`（`ksu_cred` / `setup_selinux` BakaSU 已有）。
这些在上游是「内核树内已有符号」，LKM 里必须自己写（用 kprobe 抓到的数据）。

## 5. 覆盖率矩阵

这一节按**实际 ABI**（`ShirkNeko/susfs4ksu` 分支 `gki-android12-5.10`，SuSFS v2.3.0）
的 9 个 feature 位来列，而不是初稿里那张按「上游补丁文件」想象的表格
（初稿把 `SUS_READDIR`/`SUS_KALLSYMS` 当成独立 feature、把 `TRY_UMOUNT`/`SUS_SU`
当成 SUSFS feature，都不对：本 ABI 里 readdir/kallsyms 隐藏**内嵌在**
`CONFIG_KSU_SUSFS_SUS_PATH` 与 `HIDE_KSU_SUSFS_SYMBOLS` 里，`SUS_SU` 属于
BakaSU 的 kernel_umount，`TRY_UMOUNT` 由 userspace 发 `umount2` 完成）。

| feature 位 | 上游挂点 | LKM 实现 | 状态 |
|---|---|---|---|
| `SUS_PATH` | `fs/namei.c` 13 处 + `fs/readdir.c` 1 处 | inode 标记位 `AS_FLAGS_SUS_PATH` + 12 个 choke-point kprobe（`may_open`/`may_delete`/`vfs_mkdir`/`vfs_mknod`/`vfs_symlink`/`vfs_link`/`notify_change`/`inode_permission`(instruction-level)/`filldir64`/`filldir`/`compat_filldir`/`vfs_getattr_nosec` 系）| **完成**，偏差见 §11.1 |
| `SUS_MOUNT` | `fs/namespace.c` 8 处 + `fs/proc_namespace.c` 1 处 | 真 IDA 伪 id（kretprobe `alloc_vfsmnt`/`clone_mnt` 打标）+ 三个 `show_*` 整行跳过 + `__lookup_mnt` 按 `TIF_PROC_UMOUNTED` 拦 | **完成**，偏差见 §11.5 |
| `SUS_KSTAT` | `fs/stat.c` 1 处（+ `task_mmu.c` 2、`fs/statfs.c` 1、`fs/notify/fdinfo.c` 1） | kretprobe `vfs_getattr_nosec` + kprobe `show_vma_header_prefix` + kretprobe `vfs_statfs` + kprobe `seq_printf`（`fs/proc/fd.c` 无 `ino:` 行，mnt_id 由 SUS_MOUNT 伪 id 覆盖，见 §11.6） | **完成** |
| `SPOOF_UNAME` | `fs/utsname.c` 1 处 | syscall 表钩 `__NR_uname`（先调 orig 再 `copy_from_user` 回读覆写） | **完成** |
| `ENABLE_LOG` | `fs/susfs.c` 自身 | `bool` + `READ_ONCE/WRITE_ONCE` | **完成**（阶段 1 已验） |
| `HIDE_KSU_SUSFS_SYMBOLS` | `kernel/kallsyms.c` 1 处 | kprobe `s_show` 真身，命中前缀即整行吞掉 | **完成** |
| `SPOOF_CMDLINE_OR_BOOTCONFIG` | `fs/proc/cmdline.c` + `fs/proc/bootconfig.c` | kprobe `cmdline_proc_show` 函数替换（`regs->pc`） | **完成**（本内核无 bootconfig，见 §11.3） |
| `OPEN_REDIRECT` | `fs/namei.c` 1 处 + `task_mmu.c` 1 处 | syscall 表钩 `__NR_openat` + kretprobe `prepend_path` + kprobe `show_vma_header_prefix` | **完成**，偏差见 §11.2 |
| `SUS_MAP` | `fs/proc/task_mmu.c` 3 处 + `fs/proc/base.c` 1 处 + `fs/proc/task_mmu.c`(pagemap) 1 处 | inode 标记位 `AS_FLAGS_SUS_MAP` + 6 个挂点：kprobe `show_map_vma`（整函数跳过）/ `show_smap`（返回 0）/ `walk_page_vma`（`smaps_walk_ops`·`smaps_shmem_walk_ops`，覆盖 smaps_rollup）/ `walk_page_range`（`pagemap_ops`，覆盖 pagemap）/ `__access_remote_vm`（`/proc/pid/mem`、ptrace）+ kretprobe `shmem_swap_usage`（rollup 的 Swap） | **完成**，偏差见 §11.4 |

**没有任何一项是「只报位不做事」**：`susfs_get_enabled_features()` 的每一项都由
运行时可用性门控（`susfs_*_available()`）包裹，钩子装不上就不报。九个 feature 位
全部有实现，`SUS_MOUNT` 因为打标钩子必须在模块加载期装上，额外用
`mark_ok && hide_ok` 双门控（§11.5）。

## 6. 关键设计取舍

### 6.1 SUS_PATH：inode 标记位 + choke-point kprobe（定案，已与初稿不同）

初稿设想走 master 分支的「syscall 入口级字符串匹配」（`__arm64_sys_openat` +
`kern_path_at` 之类）。实测**这条路在本内核走不通**：`kern_path_at` 不存在、
`filename_lookup` / `user_path_at` / `getname` 都不导出，而 kprobe 只能拿到
用户态 `const char __user *`，在 kprobe 上下文（见 §6.2）既不能 `copy_from_user`
也不能 `kern_path()`。

定案改成**上游 v2.3.0 原样的 inode 标记位** + 一批 choke-point：

* add：`kern_path(LOOKUP_FOLLOW)` 解析一次，`set_bit(AS_FLAGS_SUS_PATH,
  &inode->i_mapping->flags)`，并把 basename / ino / d_type 存进链表（表项永不 free）；
* 隐藏判定：`susfs_path_inode_hidden()` = 位测试 + `susfs_is_current_proc_umounted_app()`
  + `uid != i_uid`（与上游逐字一致）；
* 拦截：`may_open` / `may_delete` / `vfs_mkdir` / `vfs_mknod` / `vfs_symlink` /
  `vfs_link` / `notify_change` 返回 `-ENOENT`；`do_faccessat` 的
  `bl inode_permission` 用 instruction-level kprobe（返回地址必须
  `kp->addr + 4`，不能 `regs->regs[30]`）；readdir 走 `filldir64`/`filldir`/
  `compat_filldir` 真身（`.cfi_jt` 先解桩），pre 语义 `x0=0; pc=lr; return 1`。

**门控语义是上游原样**：只有「走过 KSU umount 的进程（`TIF_PROC_UMOUNTED`）
且 uid 不是文件属主」才看不见——**shell(2000)/root(0) 永远看得见**。验收必须用
app 进程（uid≥10000，且由其 `Runtime.exec` 出的子进程继承该线程标志）。

已接受的偏差（写在 `susfs_path.c` 文件头）：`open(O_CREAT)` 返回 `-ENOENT` 而不是
创建诱饵 inode；隐藏目录内新建名字会先落地空文件再 `may_open` 失败；已存在子文件
按精确路径仍可打开；`readlink` 不覆盖。

### 6.2 kprobe 上下文：**不能睡眠**（订正初稿的错误结论）

初稿写「`kprobe_handler()` 没有 `preempt_disable()`，pre_handler 可睡眠」——**错**。
`arch/arm64/kernel/probes/kprobes.c` 的 `kprobe_handler()` 在 BRK 异常上下文执行，
`kcb->kprobe_saved_dbg_ctl`/`kprobes_restore_local_irqflag()` 成对恢复 **DAIF.I**，
也就是说 pre_handler 全程**关中断**：

```c
	} else {
		/* Probe hit */
		set_current_kprobe(p);
		kcb->kprobe_status = KPROBE_HIT_ACTIVE;
		if (!p->pre_handler || !p->pre_handler(p, regs)) {
			setup_singlestep(p, regs, kcb, 0);
		} else
			reset_current_kprobe();
	}
```

所以 pre_handler 里只能做纯整数/字符串比较、`test_bit()`、`atomic_read()`。
`kmalloc(GFP_KERNEL)`、`kern_path()`、`copy_from_user()`、`register_kprobe()`
**一律非法**（会 BUG）。

这条约束直接决定了架构分工：

* **需要睡眠的事**（解析路径、分配表项、注册探针）→ 放在 syscall 表钩
  （`ksu_syscall_table_hook`）或 `susfs_add_*()` 命令处理里，它们跑在正常的
  系统调用上下文；
* **热路径判定**（maps 打印、readdir、open 拦截）→ 只做位测试/整数字符串比较。

`show_map_vma`/`show_smap`/`filldir64`/`prepend_path` 之所以能整函数跳过或改
`regs->pc`，也是因为 pre_handler 只需要读 `regs`，不需要任何分配。

### 6.3 返回 void / 需要回填的函数 → kretprobe

`generic_fillattr()` 返回 void，无法用「改返回值」的办法拦截，且本内核
`vfs_getattr_nosec()` 是 `struct kstat` 的汇聚点 —— 因此 SUS_KSTAT 用
**kretprobe `vfs_getattr_nosec`**：entry_handler 把 `struct kstat *` 存进
`ri->data`，ret_handler 里改内容。

`filldir64` / `s_show` / `show_map_vma` / `show_smap` / `cmdline_proc_show`
返回 int 或 void 但语义是「整函数跳过」→ pre_handler 直接
`regs->pc = regs->regs[30]`（void 的不设 `x0`，int 的设 `x0 = 0`），
`return 1` 抑制单步。**不能返回 `-EINVAL`**：那会让 kprobe 报错并放行原函数。

**kretprobe 的 `maxactive` 必须显式保留**：`susfs_register_kretprobe()` 内部会
`memset` 结构体，调用点必须在**注册前**把 `krp->maxactive` 预置好
（`vfs_getattr_nosec`=128、`vfs_statfs`=64、`prepend_path`=64），否则 `maxactive`
= 0 → 注册成功但每次命中都不会调 ret handler（静默失效）。

`__d_lookup` / `__d_lookup_rcu` 的 kprobe 只能整函数返回 NULL → 走慢路径 →
语义安全、性能略损。

### 6.4 一个容易反复踩的坑：`static` 函数没有 `.cfi_jt`

本内核开了 kCFI，带 CFI 哈希的全局函数在 `kallsyms` 里是
`name$<32 hex>`，并且会有一个 `.cfi_jt` 跳转桩。`susfs_lookup_symbol()` 走
BakaSU 的 `ksu_resolve_symbol_for_functable_hook()`，它**优先返回桩**，所以
挂探针前必须 `susfs_unwrap_jump_table()` 解到真身——否则 kprobe 打在 4 条
指令的桩上，`regs->regs[30]` / 参数寄存器全是桩的语义，行为必然错。

反过来，`static` 函数（`show_map_vma`/`may_open`/`may_delete`/`prepend_path`/
`cmdline_proc_show`）**没有 CFI 哈希也没有桩**，裸名直接就是真身，unwrap 是 no-op。
`show_smap`/`filldir64`/`vfs_getattr_nosec`/`vfs_mkdir` **有**桩，必须解。
这条已经收拢成共享 helper `susfs_register_kprobe_at()`（`susfs_probe.c`），
新挂点一律走它，不要各写一份。

## 7. 分阶段实施计划与进度

| 阶段 | 内容 | 验证判据 | 状态 |
|---|---|---|---|
| **1** | ABI 骨架：`show_version` / `show_variant` / `show_enabled_features` / `enable_log` / `set_avc_log_spoofing`（诚实 126）/ `start_sdcard_monitor_fn`（空）/ `init`；supercall 从 kprobe 改 syscall 表钩 | `ksud susfs show version` → `v2.3.0`；`show variant` → `GKI`；管理器 SuSFS 页显示已启用 | **已完成并验收**（boot `5394a404`） |
| **2** | `SUS_KSTAT` / `SPOOF_UNAME` / `HIDE_KSU_SUSFS_SYMBOLS` / `SPOOF_CMDLINE` | 各命令 `ret: 0` + 效果可见 | **代码完成**，待装机验收 |
| **3** | `SUS_PATH`（inode 位 + 12 choke point + 懒注册 + `susfs_extra_works` 循环解析） | app 进程 `ls`/`stat`/`open` 目标路径 → `ENOENT`，shell 仍可见 | **代码完成**，待装机验收 |
| **4** | `OPEN_REDIRECT`（syscall 表钩 openat + kretprobe `prepend_path` + `show_vma_header_prefix`） | app 打开 target 拿到 redirected 内容；`maps`/`smaps` 显示 target 路径 | **代码完成**，待装机验收 |
| **5** | `SUS_MAP`（inode 位 + 6 挂点：`show_map_vma`/`show_smap`/`walk_page_vma`(rollup)/`walk_page_range`(pagemap)/`__access_remote_vm`(/proc/pid/mem) + kretprobe `shmem_swap_usage`） | app 的 `maps`/`smaps`/`smaps_rollup` 里无该 so 路径、rollup 计数与 Swap 不涨、`pagemap` 无 present 位、`/proc/pid/mem` 读 0 字节 | **代码完成**，待装机验收（缺口见 §11.4） |
| **6** | `SUS_MOUNT`（真 IDA 伪 id：kretprobe `alloc_vfsmnt`/`clone_mnt` 打标；`show_vfsmnt`/`show_mountinfo`/`show_vfsstat` 整行跳过；`__lookup_mnt` 按 `TIF_PROC_UMOUNTED` 拦） | `/proc/self/mounts`/`mountinfo` 无目标条目、mnt_id 为伪 id 区间 | **代码完成**，待装机验收（见 §11.5） |

**阶段 1 是唯一必须先做的**：验证分发链路（`SUSFS_MAGIC` →
`ksu_handle_susfs_cmd` → `susfs_*`）是否贯通。若这一环不通，后续全部无意义。

宏的纪律（§3.6）：**feature 串里出现的每一项都必须有实际实现**。九个 feature 位
全部已实现；未实现的命令（`ENABLE_AVC_LOG_SPOOFING` 等本 ABI 之外的旧命令）
userspace 打过去会自然拿到 `ERR_CMD_NOT_SUPPORTED`(126)，这是真话而不是谎报。

## 8. 风险与限制

| 风险 | 影响 | 缓解 |
|---|---|---|
| CFI 哈希后缀随内核升级变化 | kprobe 挂点解析失败 | `susfs_lookup_symbol()` 前缀匹配 + `susfs_unwrap_jump_table()` 解桩；失败即 `available()=false`，不报该 feature |
| kprobe 热路径开销 | `may_open`/`filldir64`/`show_map_vma` 每次调用都触发；`walk_page_range` 还会被 `madvise`/`mprotect`/`memcg` 调用 | 每个 pre_handler 首行是 `atomic_read()` / `test_bit()` / ops 指针比较，非目标立即返回 0；kprobe 自身固定开销需实测 |
| 表项永不 free | 反复 add 会累积内存 | 与上游一致（上游也不释放）；add 重复路径则原地刷新 |
| 上游版本漂移 | 命令码/结构体不匹配 | 锁定 v2.3.0（`gki-android12-5.10` 分支），管理器侧已有对应 UI |
| `susfs_start_sdcard_monitor_fn` 在 late 模式下被跳过 | sdcard 监控不启动 | SUS_PATH 的 loop 项改由 `susfs_extra_works`（`TIF_PROC_UMOUNTED` 触发）周期重解析 |
| 未实现功能被误报为可用 | 违反真协议红线 | `get_enabled_features()` 逐项 `available()` 门控 + 未实现命令回 126 |
| kprobe 挂点上下文不能睡眠（§6.2） | 误用即 BUG | 需要睡眠的操作全部放 syscall 表钩 / `susfs_add_*`；详见 §6.2 |

## 9. 附：验证脚本

```bash
# 符号存在性（三批）
python3 build/work/query_syms.py    # 分组精确名
python3 build/work/query_syms2.py   # 子串探测（找 inline 项）
python3 build/work/query_syms3.py   # CFI 哈希组枚举
# 任意符号地址提取（带 sig_enforce 校准断言）
python3 build/work/harvest_ocs.py build/work/bootdump.img out.txt
```

均以 `sig_enforce == 0x2b89d20` 校准，parser 漂移会 assert 失败。

## 10. 阶段 1 实现摘要

文件：

- `kernel/susfs/include/linux/susfs.h` —— GKI 分支原样拷贝（253 行，ABI 唯一权威）
- `kernel/susfs/include/linux/susfs_def.h` —— 命令码 + `ERR_CMD_NOT_SUPPORTED 126`
  + `TIF_`/`AS_FLAGS_` 位定义 + inline helpers
- `kernel/susfs/susfs.c` —— 阶段 1 实现（版本/variant/features/enable_log/
  avc_log_spoofing 诚实回 126/sdcard 空实现/init）
- `kernel/Kbuild` —— 接线（§3.1）
- `kernel/core/init.c` —— TRACEPOINT 分支调 `susfs_init()`（§3.4）

静态验证（`llvm-nm` / `llvm-objdump` / `strings`）：

- 无新增未决符号（`llvm-nm -u` 差集仅 `kmalloc_order_trace`，
  `EXPORT_SYMBOL` 于 `mm/slab_common.c:1378`，可解析）
- `__param_` 仍 45 个（未新增模块参数）
- 版本串未漂移：`v4.2.0-rc3-8450dd28-dirty@BakaSU`（`../BakaSU` HEAD 未动，rev-list 4520）
- `susfs_init` 被 LTO 内联进 `ksu_hook_init`（反汇编：`bl ksu_syscall_hook_init`
  → `bl ksu_syscall_hook_manager_init` → 3 参数 printk，`adrp/add` 取
  `v2.3.0` / `GKI`）
- `ksu_handle_susfs_cmd` 的 reloc 全指向 `susfs_*.cfi_jt`（CFI 正常）

ko sha1：见 `build/embed/kernelsu.ko`。

## 11. 各 feature 实现清单与已知偏差

每个文件开头的注释都写了「上游怎么做的 / 我们为什么只能这么做 / 哪些做不到」。
这里只做索引 + 偏差汇总，细节以源文件头注释为准。

### 11.1 `SUS_PATH` —— `susfs_path.c`

| 挂点 | 类型 | 语义 |
|---|---|---|
| `may_open` | kprobe（裸名 static） | 隐藏路径 open → `-ENOENT` |
| `may_delete` | kprobe（裸名 static） | 隐藏路径 unlink/rmdir/rename 源 → `-ENOENT` |
| `vfs_mkdir` / `vfs_mknod` / `vfs_symlink` / `vfs_link` | kprobe（有 `.cfi_jt`） | 在隐藏目录内创建 → `-ENOENT` |
| `notify_change` | kprobe | chmod/chown/truncate 隐藏路径 → `-ENOENT` |
| `do_faccessat` + `bl inode_permission` | **instruction-level** kprobe | `access()`/`faccessat()` → `-ENOENT` |
| `filldir64` / `filldir` / `compat_filldir` | kprobe（真身） | readdir 条目隐藏，匹配 `ino + basename + d_type` |
| `vfs_getattr_nosec` 等 | 复用 SUS_KSTAT 的 stat 钩 | `stat` 隐藏路径 → `-ENOENT` |

注册模型：**懒注册**。`susfs_path_init()` 只解析符号并试注册/立即注销判断可用性；
首次真正 `add` 时 `susfs_path_arm()` 才注册全部 12 个钩子，任一失败则整体回滚 +
`available()=false`。

已接受偏差：`open(O_CREAT)` 不创建诱饵 inode；隐藏目录内新建名字会先落地空文件；
已存在子文件按精确路径仍可打开；`readlink` 不覆盖。

### 11.2 `OPEN_REDIRECT` —— `susfs_open_redirect.c`

三个钩子**全部视为 core**（缺一个就整体 `available()=false`）：

1. syscall 表钩 `__NR_openat`：`strncpy_from_user` 256B 快路径 strcmp，命中后
   `kern_path()` 解析比对 inode，再 `filp_open` 真文件并用 `fd_install` 换掉；
2. kretprobe `prepend_path`：改写 `d_path` 输出的路径字符串（覆盖
   `maps`/`smaps`/`fdinfo`/`cwd` 全部路径显示）；
3. kprobe `show_vma_header_prefix`：`maps` 每行的 `dev:inode` 字段伪装。

已接受偏差（文件头逐条写明）：调用者必须逐字拼出注册时的 target 路径；
32 位进程走 `compat_sys_call_table` 不重定向；`fsnotify_open` 未导出 →
重定向 open 不发 `IN_OPEN`/`IN_ACCESS`；bind mount/第二硬链接受①限制；
表项与 `AS_FLAGS_OPEN_REDIRECT` 位永不释放（这也是能用 spinlock 而非 SRCU 的前提）；
目标不存在时回落 orig；**本内核无 `openat2`**（`__NR_openat2` 不存在）；
相对 dirfd 的名字不重定向；`O_NOFOLLOW` 被尊重。

### 11.3 `SPOOF_CMDLINE_OR_BOOTCONFIG` —— `susfs_cmdline.c`

kprobe `cmdline_proc_show`（裸名 static）**函数替换**：`regs->pc = 替换函数`、
`return 1`（不单步）。替换函数只用 `seq_puts` 写假串。

**为什么不改 `saved_command_line` 指针**：OPPO 的 `qti_gadget` /
`oplus_secure_common` 在运行时解析它，改了会连带影响它们。

偏差：本内核 `CONFIG_BOOT_CONFIG=n`，没有 `/proc/bootconfig`，所以只覆盖
`/proc/cmdline`。这是真实的（上游也是「两个面按配置各自覆盖」）。

### 11.4 `SUS_MAP` —— `susfs_map.c`

inode 标记位 `AS_FLAGS_SUS_MAP` + 6 个挂点。上游 5 处源码站点全部有对应实现：

| 上游站点 | 我们的挂点 | 语义 |
|---|---|---|
| `show_map_vma()` 顶部 `return` | kprobe `show_map_vma` | `pc=lr; return 1`，整行（含 smaps 的头行）消失 |
| `show_smap()` 顶部 `return 0` | kprobe `show_smap`（带 `$` 哈希，已解桩） | `x0=0; pc=lr` |
| `show_smaps_rollup()` 里两处跳过 `smap_gather_stats()` | kprobe `walk_page_vma`，按 `ops == smaps_walk_ops \|\| smaps_shmem_walk_ops` 过滤 | 返回 0，`mss` 一分不加；`show_numa_ops` 等其它 walk 表不受影响 |
| `pagemap_read()` 的 `goto bypass_orig_flow` | kprobe `walk_page_range`，按 `ops == pagemap_ops` 过滤 + `susfs_map_vma_at(mm,start)` | 返回 0 ⇒ `pm.pos` 保持 0 ⇒ `pagemap_read()` 拷出 `PM_ENTRY_BYTES*pm.pos == 0` 字节，与上游 skip 该 chunk 逐字节等价 |
| `__access_remote_vm()` 循环内 `break` | kprobe `__access_remote_vm`（`x1=mm`、`x2=addr`） | 返回 0 = 「一个字节都没搬」，等价上游 break 后 `return buf-old_buf` |

另外补一个 **kretprobe `shmem_swap_usage`**：`smap_gather_stats()` 对 shmem 映射
先取 `shmem_swap_usage(vma)` 累加进 `mss->swap`，再（可能）走
`smaps_shmem_walk_ops` 那条分支。跳过 walk 只挡掉第二条分支的 swap 计入，第一条
的 `mss->swap +=` 仍会发生，所以 hidden VMA 的返回值在这里被清零。

**为什么 `smap_gather_stats` 没有直接挂点**：本内核里它被 inline 掉、kallsyms 无
该符号；但它对外的两个副作用（`walk_page_vma`、`shmem_swap_usage`）都是真符号，
两个都拦掉后 `mss` 一分不加，与「整段不调用」等价。

**`__access_remote_vm` 每调用只判一次 vma**（上游是在每页循环里再判）：所有调用方
（`mem_rw()` 的 `/proc/pid/mem`、`access_process_vm()` 的 ptrace、coredump 读取、
`/proc/pid/cmdline|environ`）单次最多传一页，而一页不会跨两个 VMA，故两者等价。

**all-or-nothing**：`susfs_map_core_ok` 只在 init 期 6 个挂点全部 trial-register
成功、且 3 个 walk 表数据符号（`smaps_walk_ops`/`smaps_shmem_walk_ops`/
`pagemap_ops`）全部解析成功时置真；首次 `ADD_SUS_MAP` 才真正 arm，任一步失败即
逆序回滚并 `available()=false` + `err=-EOPNOTSUPP`，绝不「按了一半的开关」。

**刻意缺口（2 处，均有理由，不是遗漏）**

1. `/proc/<pid>/map_files`：`proc_map_files_readdir()` 两趟 —— 先把候选收进
   genradix，再遍历输出。单条丢弃只能靠 `genradix_ptr_alloc`/`map_files_get_link`
   （二者在本内核都不在 kallsyms、也不导出）或者把整个目录截断；而该目录的条目名
   只是 `start-end` 十六进制串（无 inode/路径），跳过反而引入「目录里有空洞」这种
   更响的异常。上游在这里跳过的也只是这些地址串。
2. `/proc/<pid>/numa_maps`：走 `walk_page_vma(vma, &show_numa_ops, ...)`，已被
   ops 过滤排除。它只报 NUMA 统计，不报路径/PFN。

`/proc/pid/maps`、`/proc/pid/smaps`、`smaps_rollup`、`pagemap`、`/proc/pid/mem`、
ptrace 六个面全部覆盖 —— 凡能「指名」或「按页反查」隐藏映射的路径都已拦住。

### 11.6 `SUS_KSTAT` —— `susfs_kstat.c`

上游 4 个站点全部有对应探针：`vfs_getattr_nosec`（kretprobe，覆盖
`generic_fillattr` → `stat`/`fstatat`/`fstat`）、`show_vma_header_prefix`
（maps/smaps 行首的 inode 号）、`vfs_statfs`（`statfs`/`fstatfs`）、
`seq_printf`（`inotify_fdinfo` 里的 `ino:` 行，按 `inotify_fdinfo` 内首条
`bl seq_printf` 的返回地址精确过滤）。

**本内核没有 `/proc/pid/fdinfo` 的 ino 面**：`fs/proc/fd.c:seq_show()` 只打印
`pos / flags / mnt_id`，没有 `ino:` 行（`5.10` 才有）。所以上游那份
`fs/proc/fd.c` 补丁在这里无对应物；而 `mnt_id` 已经由 SUS_MOUNT 的伪 id 天然
覆盖，不需要 SUS_KSTAT 再插手。这条差异已写进 `susfs_kstat.c` 头注释。

`inotify_fdinfo` 属可选增强：`seq_printf`/`inotify_fdinfo` 任一解析失败只关掉
这一项（`SUS_KSTAT hooks registered` 之前会打 `inotify spoof disabled`），
其余三个站点照常工作 —— 与上游「四个站点互相独立」的语义一致。

### 11.5 `SUS_MOUNT` —— `susfs_mount.c`

上游是源码 patch，改 `fs/namespace.c`（`mnt_alloc_id()` 给 ksu 进程建的 mount
发伪 id、`copy_mnt_ns()` 给克隆续 id）和 `fs/proc_namespace.c`（三个 `show_*`
在非 ksu 域跳过伪 id 条目）+ `__lookup_mnt()`（带 `TIF_PROC_UMOUNTED` 的任务
查不到伪 id 的 mount）。我们是模块，所以全部改成探针。

**打标（常驻，模块加载即生效，不可事后补标）**

| 探针 | 位置 | 作用 |
|---|---|---|
| kretprobe | `alloc_vfsmnt`（static，裸名即真身） | 唯一 `struct mount` 来源；`current` 为 ksu 域时把真 id 换成伪 id |
| kretprobe | `clone_mnt`（static） | entry 记源 mount 的 id；源是伪 id 则克隆体也打标（app `unshare(CLONE_NEWNS)` 克隆隐藏 mount 时也要跟着隐藏） |

伪 id 分配走内核对同一个 ida 的公开 API：

```c
fake = ida_alloc_range(&mnt_id_ida, DEFAULT_KSU_MNT_ID, 0x7fffffff, GFP_ATOMIC);
WRITE_ONCE(mnt->mnt_id, fake);
ida_free(&mnt_id_ida, real);
```

这样与内核的 `mnt_free_id()` 天然配平（卸载时释放的是伪 id），也不需要改
`free_vfsmnt()`。`mnt_id_ida` 未导出 → `kallsyms_lookup_name` 解析（`d` 符号）。

**为什么真 id 必须当场还给 ida**：不还，真 id 就永久泄漏（`mnt_free_id` 只释放
mount 当前携带的那一个 id）；还了之后内核 `ida_alloc()` 从最低位重新分配，20 亿
以下的空间永远取不到伪 id 区间，所以伪 id 释放后不会被当成真 id 用掉。

**隐藏（`CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS` 打开后才装，关闭即卸）**

| 探针 | 语义 |
|---|---|
| kprobe `show_vfsmnt` / `show_mountinfo` / `show_vfsstat`（三者都带 `$55b2…` kCFI 哈希，`susfs_unwrap_jump_table()` 解到真身） | `x0=0; pc=lr; return 1` —— 整行跳过，等价上游回调里的 `return 0` |
| kretprobe `__lookup_mnt`（`T` 符号） | 任务带 `TIF_PROC_UMOUNTED` 且结果是伪 id mount 时把返回值置 NULL |

`__lookup_mnt` 这一半是可选模块参数 `lookup_hook`（默认 1）。它是本 feature
唯一落在**每次跨挂载点路径解析**上的陷阱，所以留了免重编的逃生阀；关掉只丢
「被 umount 的 app 走不进 sus mount」，`/proc` 三个面的隐藏保留。

**域判定**只用 `security_task_getsecid(current,&sid)` 与 init 期
`security_secctx_to_secid("u:r:ksu:s0")` 缓存的 sid 比较（纯字段读，零睡眠；
BakaSU 的 `is_ksu_domain()` 回退路径会拼 secctx 字符串，不能在探针上下文用）。

**`struct mount` 布局**直接编译内核自己的 `<fs/mount.h>`（`real_mount()` +
`mnt_id`），并在 init 期双字段校验：`real_mount(current->fs->root.mnt)->mnt_ns
== current->nsproxy->mnt_ns` 且 `mnt_id` 落在真 id 区间（`fs->pwd.mnt` 兜底）。
不符则整个 feature 关闭（`available()=false`，不上报）。

**可用性门控**：`susfs_mount_available() = mark_ok && hide_ok`，其中 `hide_ok`
在 init 期对四个隐藏探针做「试注册 + 立即注销」得出（装不上就整体关，绝不
上报一个按了没反应的开关）；打标两个探针是真注册，失败即回滚并整体关闭。

**已知偏差**（相对上游，均不弱化隐藏强度）

1. `mnt_group_id` 不虚拟化（`group_ida` 是另一套 ida，伪化会牵连
   `propagate_mount_*` 的 peer group 语义）→ peer group 关系仍可见；
2. `__lookup_mnt` 返回 NULL 而不是「下一个合法 mount」——8 个调用点
   （`fs/namei.c`×2、`fs/namespace.c`×2、`fs/pnode.c`×4）逐个核对全部 NULL-safe；
3. `copy_mnt_ns()` 不复用旧 id，每个克隆都新取伪 id（上游会续用同一个）；
   效果等价（都是伪 id 区间），只是浪费 id；
4. 打标永不停止（上游在 `/sdcard/Android/data` 解密后会停）——我们的行为是
   「更久地隐藏」，不是更少；
5. **`kernel:s0` 建的 mount 不打标**：restore 脚本从该域建 `/product/bin`
   overlay，打标会让 shell 域里的 `su` 解析回原厂只读目录。这是「只对 ksu 域
   产生的 mount 打标」的直接结果，不是特例代码；
6. 伪 id 从区间底部顺序分配（`ida_alloc_range`），上游是 `ida_alloc_min` 从
   低位先取——两者都在同一区间内唯一，不产生可观测差异。
