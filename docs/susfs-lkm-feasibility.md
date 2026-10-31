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

| SUSFS 功能 | 上游补丁点 | LKM 实现 | 覆盖率 | 语义差异 |
|---|---|---|---|---|
| `SUS_PATH` | dcache 2 + namei 13 | **syscall 入口级**（`__arm64_sys_openat`/`openat2`/`mkdirat`/`unlinkat`/`renameat2`/`linkat`/`symlinkat`/`mknodat` + `vfs_statx`）+ `filldir64` | **95%** | 见 §6.1 |
| `SUS_MOUNT` | namespace 8 + proc 1 | `show_vfsmnt` + `show_mountinfo` + `vfs_statfs` + kretprobe `alloc_vfsmnt` 改 mnt_id | **85%** | `mnt_group_id` 无法伪造（inline） |
| `SUS_KSTAT` | stat.c 1 | kretprobe `generic_fillattr` 改 `struct kstat` | **100%** | 无 |
| `SUS_READDIR` | readdir.c 1 | `filldir64` pre 设 `pc=lr` + `x0=0` 跳过条目 | **100%** | 无 |
| `SUS_KALLSYMS` | kallsyms.c 1 | `s_show` pre 同上跳过 | **100%** | 无 |
| `SPOOF_UNAME` | sys.c 1 | `__arm64_sys_newuname` kprobe 改用户缓冲区 | **100%** | 需 `copy_to_user` |
| `OPEN_REDIRECT` | namei 1 | kprobe syscall 入口改路径字符串 | **70%** | 无法在 `open_last_lookups` 内重定向 |
| `TRY_UMOUNT` | namespace 1 | 用户态实现（`umount2` 调用） | **100%** | 无（susfs 本身就是循环调 `ksys_umount`） |
| `SUS_SU` | exec.c + devpts | 复用 `kernelsu.ko` 的 execve hook | **100%** | 依赖 `ksu_handle_execveat_sucompat` |
| `SUS_MAP` | task_mmu.c | `show_map_vma` kprobe 跳过 | **90%** | — |
| `SPOOF_CMDLINE` | proc/bootconfig | `bootconfig` seq_show kprobe | **100%** | — |

**综合覆盖率 ~92%**，无「完全做不到」的功能。

## 6. 关键设计取舍

### 6.1 SUS_PATH：采用 master 的 syscall 入口级策略，而非 GKI 的 dentry 级

GKI 补丁在 `fs/namei.c` 的 13 个内联点（`link_path_walk` 循环体内、`lookup_open`、
`may_o_create` 等）做检查。**kprobe 的 pre_handler 只在函数入口触发**，无法拦截
`link_path_walk` 的中间迭代，也无法插进 inline 掉的函数。

master 分支改走**系统调用入口**：`__arm64_sys_openat` / `openat2` / `mkdirat` /
`unlinkat` / `renameat2` / `linkat` / `symlinkat` / `mknodat` + `vfs_statx`
的 `susfs_sus_path_by_filename()`。这条路对 kprobe **天然友好**（每个都是独立
导出函数、入口即可拿到 `filename` 指针），且语义等价（任何路径操作都经过这些
syscall 入口）。

代价：内核内部路径操作（不经 syscall 的，如模块自己调 `filp_open`）不受保护。
对本项目用途（对抗检测 app 的用户态扫描）足够。

### 6.2 kprobe 上下文实测

`work/kernsrc/sm6375-v15/arch/arm64/kernel/probes/kprobes.c` 的
`kprobe_handler()` **没有 `preempt_disable()`**，pre_handler 在 `el1_dbg`
恢复 DAIF 后执行 → **上下文可睡眠**（与 `ksu_install_fd()` 一直可用一致）。
但仍是 debug-exception 上下文，**避免取锁/打补丁更稳**（§3.3）。

### 6.3 `generic_fillattr` 返回 void → 必须 kretprobe

entry_handler 把 `stat` 指针存到 `kretprobe_instance->data`，return_handler 里改
内容。`filldir64` / `s_show` / `show_vfsmnt` 返回 int → pre_handler 设
`regs->pc = regs->regs[30]` + `x0 = 0` 跳过条目。

`__d_lookup` / `__d_lookup_rcu` 的 kprobe 只能整函数返回 NULL → 走慢路径 →
语义安全、性能略损。

## 7. 分阶段实施计划与进度

| 阶段 | 内容 | 验证判据 | 状态 |
|---|---|---|---|
| **1** | ABI 骨架：`susfs_show_version` / `show_variant` / `show_enabled_features` / `enable_log` / `set_avc_log_spoofing`（诚实回 126）/ `start_sdcard_monitor_fn`（空）/ `init` | `ksud susfs show version` → `v2.3.0`；`show variant` → `GKI`；`show enabled_features` 仅 `CONFIG_KSU_SUSFS_ENABLE_LOG`；管理器 SuSFS 状态页由「未启用」→「已启用」 | **已完成，待装机验收** |
| **2** | 纯 kprobe 项：`SUS_KSTAT`（kretprobe `generic_fillattr`）/ `SUS_READDIR`（`filldir64$51ab…`）/ `SUS_KALLSYMS`（`s_show$8070…`）/ `SPOOF_UNAME`（`__arm64_sys_newuname`） | 每完成一项才定义对应 `CONFIG_KSU_SUSFS_*` 宏；`ksud susfs add-sus-kstat` 生效 | 待做 |
| **3** | `SUS_PATH`（§6.1 syscall 入口级 + `filldir64`） | 加入 sus_path 后目标路径 `open`/`stat`/`unlink` 全失败、`ls` 不可见 | 待做 |
| **4** | `SUS_MOUNT`（`show_vfsmnt$55b2…` / `show_mountinfo$55b2…` / `vfs_statfs` + kretprobe `alloc_vfsmnt`）+ 哈希表 `mnt_id_backup` | `/proc/self/mounts` 无目标条目；`mountinfo` mnt_id 为伪值 | 待做 |
| **5** | `SUS_MAP` / `OPEN_REDIRECT` / `SPOOF_CMDLINE` / `AVC_LOG` | 各命令生效 | 待做 |

**阶段 1 是唯一必须先做的**：验证分发链路（`SUSFS_MAGIC` →
`ksu_handle_susfs_cmd` → `susfs_*`）是否贯通。若这一环不通，后续全部无意义。

## 8. 风险与限制

| 风险 | 影响 | 缓解 |
|---|---|---|
| CFI 哈希后缀随内核升级变化 | kprobe 挂点解析失败 | 编译期硬编码 + 运行时 `/proc/kallsyms` 前缀匹配双路 |
| kprobe 热路径开销 | `__d_lookup` 等每次 lookup 都触发 | 用 `bool` 开关做早期返回；kprobe 本身固定开销需实测 |
| `task_struct` 哈希表泄漏 | task 退出未清理 | `release_task` kprobe 清理 + 惰性过期双保险 |
| 上游版本漂移 | 命令码/结构体不匹配 | 锁定 v2.3.0（GKI 分支），管理器侧已有对应 UI |
| `susfs_start_sdcard_monitor_fn` 在 late 模式下被跳过 | sdcard 监控不启动 | 阶段 3 起由 `susfs_init()` 自行启动 |
| 未实现功能被误报为可用 | 违反真协议红线 | `get_enabled_features()` 纯 `#ifdef` 驱动 + 未实现命令回 126 |

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
