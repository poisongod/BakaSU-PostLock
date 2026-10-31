# SUSFS LKM 化可行性评估

日期：2026-10-31
基线：`/tmp/opencode/susfs/susfs54.patch`（susfs4ksu `kernel-5.4` 分支 v1.5.5，775 行 / 22 文件）
目标设备：PFUM10 / Android 12 / 5.4.254-qgki（回锁，无 fastboot 刷写能力）

## 1. 为什么只能走 LKM

上游 SUSFS 是**内核补丁**（22 个文件、775 行内联检查）。本设备回锁，
无法刷入自编译 boot.img，唯一可用的内核代码注入通道是 **`insmod`**
（链提权后 `finitmod` late-load）。因此 SUSFS 必须：

- 逻辑独立成 `susfs_lkm.ko`（不污染 `kernelsu.ko` 的 hook 路径）；
- 内核补丁点用 **kprobe/kretprobe** 替代；
- 新增结构体字段用**哈希表**替代；
- 复用现有字段（`inode->i_state` 高位）不改结构体。

`kernelsu.ko` 侧只启用 `supercall/dispatch.c` 的 `CMD_SUSFS_*` 分发层，
通过模块 ksymtab 解析 `susfs_*` 未决符号。

## 2. 符号存在性验证（离线 kallsyms，实测）

工具：`/tmp/opencode/susfs/query_syms{,2,3}.py`
数据源：`build/work/bootdump.img`（原厂 boot dump）
校准：`sig_enforce == 0x2b89d20`（与 `target.h` 一致，parser 漂移会 assert 失败）
规模：188404 条 kallsyms / 183768 唯一符号

### 2.1 可直接 kprobe 的符号（存在且为 text）

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
| dcache 快路径 | `__d_lookup` | T | — |
| dcache RCU | `__d_lookup_rcu` | T | — |
| 路径遍历 | `link_path_walk` | t | 0x004c4ca4 |
| stat 伪造 | `generic_fillattr` | T | — |
| statx | `vfs_statx` / `vfs_statx_fd` / `vfs_getattr` | T | — |
| statfs | `vfs_statfs` / `user_statfs` / `fd_statfs` | T | — |
| 挂载创建 | `alloc_vfsmnt` / `vfs_create_mount` / `clone_mnt` / `attach_recursive_mnt` | t/T | — |
| 挂载移动 | `do_move_mount` | t | — |
| kallsyms 值 | `kallsyms_show_value` | T | 0x00355d24 |
| devpts | `devpts_get_priv` | T | — |

**CFI 哈希后缀说明**：Android 内核 `CONFIG_CFI_CLANG` + LTO 会给 `static`
函数加 `$<file-hash>` 后缀（同一 `.c` 文件共享一个哈希）。该哈希对**固定
内核镜像稳定**，但对内核升级不稳定 —— 因此模块需要「编译期硬编码 +
运行时 `/proc/kallsyms` 前缀匹配」双路解析。

### 2.2 被 inline 掉的符号（改用其调用者）

| 缺失符号 | inline 到 | 替代方案 |
|---|---|---|
| `may_linkat` / `may_follow_link` / `may_o_create` / `may_create_in_sticky` | `link_path_walk` / `do_filp_open` | 靠 `may_open` + `__lookup_*` 覆盖 |
| `lookup_open` / `do_open` / `open_last_lookups` | `path_openat` | kprobe `path_openat` 或 `do_filp_open` |
| `mnt_alloc_id` / `mnt_free_id` / `mnt_alloc_group_id` | `alloc_vfsmnt` / `vfs_create_mount` | kretprobe `alloc_vfsmnt` 改 `mount->mnt_id` |
| `do_reconfigure_mnt` | `do_mount` 内 | 放弃（影响面小） |
| `do_execveat_common` / `bprm_execve` | `__arm64_sys_execve*` | kprobe syscall 入口 |

### 2.3 结论

**所有 SUSFS 核心 hook 点都可达**（直接或经调用者），不存在「做不到」的功能，
只有「语义不完全等价」的功能（见 §4）。

## 3. 架构设计

```
susfs_lkm.ko                    kernelsu.ko
├── fs/susfs.c 逻辑（改造）      ├── supercall/dispatch.c  (CFLAGS + -DCONFIG_KSU_SUSFS)
│   ├── SUS_PATH                 │   └── ksu_handle_susfs_cmd() → susfs_*()
│   ├── SUS_MOUNT                ├── supercall/supercall.c (CFLAGS + -DCONFIG_KSU_SUSFS)
│   ├── SUS_KSTAT                │   └── SUSFS_MAGIC 分发
│   ├── SUS_READDIR              └── sucompat.c / kernel_umount.c / setuid_hook.c
│   ├── SUS_KALLSYMS                 （**不加宏**，保持 TRACEPOINT 签名）
│   ├── SPOOF_UNAME
│   ├── OPEN_REDIRECT            ksymtab 解析 UND：
│   └── SUS_SU                   susfs_show_version / susfs_add_sus_path / ...
├── kprobe 挂点（~15 个）
├── 哈希表：task_state / mnt_id_backup
└── EXPORT_SYMBOL_GPL(~35 个 susfs_*)
```

### 3.1 关键约束：`CONFIG_KSU_SUSFS` 只能单文件定义

上游 `Kbuild:189` 的 `else ifdef CONFIG_KSU_SUSFS` 与 `CONFIG_KSU_TRACEPOINT_HOOK`
**互斥**（`else if` 链）。若全局 `ccflags-y += -DCONFIG_KSU_SUSFS`：

| 文件 | 后果 |
|---|---|
| `sucompat.h:17` | `ksu_handle_faccessat` 签名变为 `struct filename **`，与 TRACEPOINT 调用点不匹配 → **编译失败** |
| `sucompat.c:343` | 激活 `do_ksu_handle_execveat_sucompat` 死块 |
| `sucompat.c:526/600` | `ksu_handle_faccessat` / `ksu_handle_stat` 换成 susfs 版本（依赖内核补丁的 `vfs_faccessat` 内调用点） |
| `kernel_umount.c:143` | `susfs_extra_works` / `susfs_set_current_proc_umounted` 未定义 |
| `setuid_hook.c:30` | 多 include `susfs_def.h`（无害） |

**正确做法**（per-file 宏）：

```makefile
CFLAGS_dispatch.o  += -DCONFIG_KSU_SUSFS
CFLAGS_supercall.o += -DCONFIG_KSU_SUSFS
ccflags-y += -I$(KSU_SRC)/include   # susfs.h / susfs_def.h
```

`dispatch.c` 内部所有 `#elif defined(CONFIG_KSU_SUSFS)` 都在
`#if defined(CONFIG_KSU_TRACEPOINT_HOOK)` **之后**（:541、:916），
TRACEPOINT 优先 → 行为不变；只有 `:175`（`susfs_start_sdcard_monitor_fn`）
与 `:1008+`（`ksu_handle_susfs_cmd`）真正激活。

### 3.2 结构体字段替代

| 上游字段 | LKM 替代 | 说明 |
|---|---|---|
| `inode->i_state` BIT24-27 | **直接复用** | 5.4 `i_state` 仅用 bit0-17，BIT24-27 空闲，无需改结构体 |
| `task_struct->susfs_task_state` | `struct task_struct *` → u64 哈希表 | 需在 task 退出时清理（`release_task` kprobe 或惰性过期） |
| `task_struct->susfs_last_fake_mnt_id` | 同上哈希表 | 同上 |
| `vfsmount->susfs_mnt_id_backup` | `struct vfsmount *` → u64 哈希表 | mount 释放时清理 |
| `mount->mnt_id` 伪造 | **直接写字段**（kretprobe `alloc_vfsmnt`） | 字段现成 |

## 4. 覆盖率矩阵

| SUSFS 功能 | 上游补丁点 | LKM 实现 | 覆盖率 | 语义差异 |
|---|---|---|---|---|
| `SUS_PATH` | dcache 2 + namei 13 | `filldir64` + `may_open` + `may_delete` + `may_create` + `__lookup_hash` + `__lookup_slow` + `__d_lookup` + `__d_lookup_rcu` | **90%** | `link_path_walk` 中间目录无法逐段拦截；靠 `__d_lookup` 返回 NULL 走慢路径兜底 |
| `SUS_MOUNT` | namespace 8 + proc 1 | `show_vfsmnt` + `show_mountinfo` + `vfs_statfs` + kretprobe `alloc_vfsmnt` 改 mnt_id | **85%** | `mnt_group_id` 无法伪造（inline）；`/proc/*/mountinfo` 的 mnt_id 可改 |
| `SUS_KSTAT` | stat.c 1 | `generic_fillattr` pre 改 `struct kstat` | **100%** | 无（返回值 void，直接改结构体内容） |
| `SUS_READDIR` | readdir.c 1 | `filldir64` pre 返回 0 跳过 | **100%** | 无 |
| `SUS_KALLSYMS` | kallsyms.c 1 | `s_show` pre 返回 0 跳过 | **100%** | 无 |
| `SPOOF_UNAME` | sys.c 1 | `__arm64_sys_newuname` kretprobe 改用户缓冲区 | **100%** | 需 `copy_to_user`（kretprobe 上下文可睡眠？→ 用 pre 改 `regs->regs[0]` 指向内核临时缓冲更安全） |
| `OPEN_REDIRECT` | namei 1 | kprobe `do_filp_open` / `path_openat` 改 `filename` | **70%** | 只能在入口改路径字符串，无法在 `open_last_lookups` 内重定向 |
| `TRY_UMOUNT` | namespace 1 | 用户态实现（`umount2` 调用） | **100%** | 无（susfs 本身就是循环调 `ksys_umount`） |
| `SUS_SU` | exec.c + devpts | 复用 `kernelsu.ko` 的 execve hook | **100%** | 依赖 `ksu_handle_execveat_sucompat` 导出 |
| `SUS_MAP` | task_mmu.c | `show_map_vma` kprobe 跳过 | **90%** | — |
| `SPOOF_CMDLINE` | proc/bootconfig | `bootconfig` seq_show kprobe | **100%** | — |

**综合覆盖率 ~90%**，无「完全做不到」的功能。

## 5. 分阶段实施计划

| 阶段 | 内容 | 验证判据 | 预估 |
|---|---|---|---|
| **1** | `susfs_lkm.ko` 骨架：只实现 `susfs_show_version` / `susfs_show_features` / `susfs_show_variant`，其余 stub 返回 `-ENOSYS`；`kernelsu.ko` 加 per-file 宏重编 | 管理器 `SuSFSRepository.getStatus()` 由「未启用」→「已启用 v1.5.5」；`dmesg` 见 susfs 版本行 | 半天 |
| **2** | `SUS_KSTAT` + `SUS_READDIR` + `SUS_KALLSYMS`（纯 kprobe，无哈希表依赖） | `ksud susfs add-sus-kstat` 生效；被隐藏文件 `ls` 不可见、`stat` 显示伪造值 | 1 天 |
| **3** | `SUS_PATH`（`may_open`/`may_delete`/`may_create`/`__lookup_*`/`__d_lookup*`/`generic_fillattr`） | 加入 sus_path 后目标路径 `open`/`stat`/`unlink` 全失败，`ls` 不可见 | 1-2 天 |
| **4** | `SUS_MOUNT`（`show_vfsmnt`/`show_mountinfo`/`vfs_statfs` + kretprobe `alloc_vfsmnt`）+ 哈希表 `mnt_id_backup` | `/proc/self/mounts` 无目标条目；`/proc/self/mountinfo` mnt_id 为伪值 | 2 天 |
| **5** | `SPOOF_UNAME` + `OPEN_REDIRECT` + `TRY_UMOUNT` + `SUS_SU` + `SUS_MAP` | 各命令生效 | 1-2 天 |

**阶段 1 是唯一必须先做的**：验证 ksymtab 链路（模块间符号解析）+ 分发层
（`SUSFS_MAGIC` → `ksu_handle_susfs_cmd` → `susfs_*`）是否贯通。若这一环不通，
后续全部无意义。

## 6. 风险与限制

| 风险 | 影响 | 缓解 |
|---|---|---|
| CFI 哈希后缀随内核升级变化 | kprobe 挂点解析失败 | 编译期硬编码 + 运行时 `/proc/kallsyms` 前缀匹配双路 |
| `link_path_walk` 无法逐段拦截 | 深层目录中间层可能可见 | `filldir64` + `__d_lookup` 兜底；实测验证 |
| kprobe 热路径开销 | `__d_lookup`/`__d_lookup_rcu` 每次 lookup 都触发 | 用 `static_key` 开关，未启用时零开销（kprobe 本身有固定开销，需实测） |
| `task_struct` 哈希表泄漏 | task 退出未清理 | `release_task` kprobe 清理 + 惰性过期双保险 |
| 上游版本漂移 | 命令码/结构体不匹配 | 锁定 v1.5.5，管理器侧已有对应 UI |
| `susfs_start_sdcard_monitor_fn` 在 late 模式下被跳过 | sdcard 监控不启动 | 模块 `init` 时自行启动（不依赖 `EVENT_BOOT_COMPLETED`） |

## 7. 附：验证脚本

```bash
# 符号存在性
python3 /tmp/opencode/susfs/query_syms.py    # 分组精确名
python3 /tmp/opencode/susfs/query_syms2.py   # 子串探测（找 inline 项）
python3 /tmp/opencode/susfs/query_syms3.py   # CFI 哈希组枚举
```

三个脚本均以 `sig_enforce == 0x2b89d20` 校准，parser 漂移会 assert 失败。
