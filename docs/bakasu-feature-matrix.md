# 完整 BakaSU 功能矩阵与我们的实现状态

> 核查日期：2026-10-31
> 来源：bakasu.org 官方文档（llms.txt 10 页）+ 本地 `../BakaSU`（HEAD 8450dd28，fork dirty）
> + susfs4ksu 上游仓库（`kernel-5.4` 分支，2025-02-23 / v1.5.5）+ 本地 `build/embed/kernelsu.ko` 符号实证

## 一、BakaSU = 三层

```
内核侧 kernelsu.ko  ←→  userspace ksud  ←→  管理器 APK（21 路由）
   (hook + feature)        (命令行后端)         (UI 前端)
```

## 二、内核侧（kernelsu.ko）

### 2.1 Hook 方式：三选一，Kbuild 里 `else if` 互斥

| 开关 | 说明 | 我们 |
|---|---|---|
| `CONFIG_KSU_TRACEPOINT_HOOK` | syscall tracepoint 重定向（`hook/syscall_hook_manager.c` + `syscall_event_bridge.c` + `tp_marker.c`） | **✅ 使用** |
| `CONFIG_KSU_MANUAL_HOOK` | 手工在 `fs/exec.c` 等内核源码插调用点 | ❌ |
| `CONFIG_KSU_SUSFS` | inline hook（susfs 集成路径） | ❌ 需内核补丁 |

Kbuild 原文（`kernel/Kbuild:150-200`）：
```make
ifdef CONFIG_KSU_TRACEPOINT_HOOK
  ...
else ifdef CONFIG_KSU_MANUAL_HOOK
  ...
else ifdef CONFIG_KSU_SUSFS
  include $(KSU_SRC)/tools/susfs_compat.mk
  ifeq ($(shell test -e $(srctree)/fs/susfs.c; echo $$?),0)
    ...
  else
    $(error You should integrate susfs in your kernel.)
```
**结论：SUSFS 与 TRACEPOINT 互斥，不能叠加。**

### 2.2 Feature（无条件编译，7 个）

| 模块 | 功能 | 我们符号实证 |
|---|---|---|
| `feature/sucompat.c` | su 兼容（`su` 命令重定向） | ✅ |
| `feature/kernel_umount.c` | 模块 umount | ✅ |
| `feature/sulog.c` | su 日志 | ✅ |
| `feature/adb_root.c` | adb root | ✅ `ksu_adb_root` |
| `feature/selinux_hide.c` | SELinux 隐藏（对非 su 进程伪装 permissive） | ✅ |
| `feature/module_load_filter.c` | 模块加载过滤（`ksu_block_modules`） | ✅ |
| `feature/dynamic_manager.c` | 动态管理器（随 `DISABLE_MANAGER` 开关） | ✅ |

### 2.3 Manager 组（`CONFIG_KSU_DISABLE_MANAGER` 未定义时）

| 模块 | 功能 |
|---|---|
| `manager/apk_sign.c` | 管理器 APK 签名校验 |
| `manager/throne_tracker.c` | 管理器追踪（appId 加冕） |
| `manager/manager.c` / `pkg_observer.c` | 管理器进程观察 |

我们：✅ 全部编译（`CONFIG_KSU_DISABLE_MANAGER` 未定义）。

### 2.4 基础设施（全部无条件）

`policy/{allowlist,app_profile,feature}`、`infra/{su_mount_ns,seccomp_cache,file_wrapper,event_queue,symbol_resolver}`、
`runtime/{boot_event,ksud_integration,hotload}`、`selinux/{selinux,sepolicy,rules}`、
`sulog/{event,fd}`、`supercall/{dispatch,perm,supercall}`、
`compat/{kernel_compat,unexported_shim,apatch_conflict}`

### 2.5 可选开关（BakaSU 提供，我们未开）

| 开关 | 语义 | 我们 |
|---|---|---|
| `CONFIG_KSU_MULTI_MANAGER_SUPPORT` | 同时认 KernelSU Official / KOWSU / BakaSU 三种管理器签名 | ❌ 未开（只认 BakaSU） |
| `CONFIG_KSU_FULL_NAME_FORMAT` | 版本串格式，默认 `"%TAG_NAME%-%COMMIT_SHA%@%REPO_NAME%"` | 用默认 |
| `CONFIG_KSU_DISABLE_MANAGER` | 完全禁用管理器观察（无 apk_sign/throne_tracker） | 未开（保留） |

## 三、userspace（ksud）

### 3.1 基础子命令
模块管理（install/remove/enable/disable/action/list）、`su`、`debug su`、`late-load`、
`sepolicy {apply,check,patch}`、`post-fs-data` / `services` / `boot-completed`、`soft-reboot`。

### 3.2 SUSFS 子命令（15 + 8）

```
add_sus_path / add_sus_path_loop        路径隐藏（umounted app，uid>=10000）
hide_sus_mnts_for_non_su_procs          非 su 进程隐藏 sus 挂载
add_sus_kstat / update_sus_kstat         kstat 伪装
update_sus_kstat_full_clone              完整克隆 kstat
add_sus_kstat_statically                 静态 kstat
set_uname                                uname 伪装
enable_log                               susfs 日志开关
set_cmdline_or_bootconfig                cmdline/bootconfig 伪装
add_open_redirect                        open 重定向
add_sus_map                              mmap 映射隐藏
enable_avc_log_spoofing                  AVC 日志伪装
slot_info / enabled_features             状态查询
config {list_all|cmdline_or_bootconfig|avc_log_spoofing|
        hide_sus_mnts_for_non_su_procs|sus_path|sus_kstat|
        open_redirect|sus_map}           持久化配置
```

我们：ksud 二进制含全部命令，但**内核无 susfs → 命令返回错误**。

## 四、管理器 UI（21 路由，`ui/navigation/Routes.kt`）

```
Main(主页) Home(状态) SuperUser(超级用户) Module(模块) ModuleRepo(模块仓库)
ModuleRepoDetail Settings(设置) AppProfile(应用配置) AppProfileTemplate
TemplateEditor Install(安装) Flash(刷写) KernelFlash(内核刷写)
ExecuteModuleAction UmountManager(卸载管理) DynamicManager(动态管理)
SuSFSConfig(SUSFS 配置) Sulog(su 日志) ThemeSettings(主题) About
OpenSourceLicense
```

**SuSFSConfig 内含 7 个 tab**（`ui/screen/susfs/subpages/`）：
`Status` / `StandardFeatures` / `OpenRedirect` / `Kstat` / `Map` / `Path` / `Config`

我们：管理器 APK 就是 BakaSU 官方构建（v4.2.0-rc3 35252/6），**21 路由全在**，
SuSFS 页面存在但 `SuSFSRepository.getStatus()` 走 `ksud susfs show version` 失败 →
`enabled=false` → 显示「未启用」。

## 五、SUSFS 专项：可行性核查

### 5.1 上游支持面（实测仓库）

susfs4ksu 分支（GitLab API 实测）：
```
kernel-4.9   kernel-4.14   kernel-4.19   kernel-5.4      ← 原生非 GKI
gki-android12-5.10  gki-android13-5.15  gki-android14-6.1
gki-android15-6.6   gki-android16-6.12   master(冻结 1.3.8)
```
**我们需要的 `kernel-5.4` 有原生分支**（最后提交 2025-02-23，v1.5.5）。
低版本（4.9 分支）补丁可向前移植 → 覆盖「4.3+」的说法。

### 5.2 补丁规模（`50_add_susfs_in_kernel-5.4.patch` 实测）

- 46935 字节，**775 行新增**，改 **22 个内核文件**：
  `fs/{exec,open,stat,statfs,readdir,namei,namespace,dcache}.c`、
  `fs/proc/{task_mmu,fd,bootconfig}.c`、`fs/proc_namespace.c`、`fs/notify/fdinfo.c`、
  `fs/overlayfs/{super,readdir,inode}.c`、`fs/devpts/inode.c`、`fs/Makefile`、
  `kernel/{sys,kallsyms}.c`、`include/linux/{sched,mount}.h`
- 新增源码：`fs/susfs.c` **916 行** + `fs/sus_su.c` 140 行 +
  `include/linux/susfs.h` 186 行 + `susfs_def.h` 62 行 ≈ **1300 行**

### 5.3 硬约束

1. **必须重编内核**：susfs 是内核源码补丁，不是可加载模块。
   上游 README 原文：*"The ksu_susfs userspace tool and ksu module requires a
   susfs patched kernel to work."*
2. **与 TRACEPOINT hook 互斥**：启用 `CONFIG_KSU_SUSFS` 必须改 inline hook，
   而 inline hook 需要 manual-integrate 的全部内核 hook 点（同样要重编）。
3. **刷 boot.img 需要解锁 BL**：AVB 验签，回锁状态下 `fastboot flash boot` 被拒。
4. BakaSU 官方警告：*SUSFS 官方已放弃 NonGKI 支持，如需在 NonGKI 使用 SUSFS，
   请自行从 `gki-android12-5.10` 移植* —— 即 5.4 分支（v1.5.5）与 BakaSU 期望的
   susfs API（跟随 gki-android12-5.10）可能有版本差，需现场对齐
   （`susfs_compat.mk` 检查 `ksu_selinux_hide_running` / `ksu_install_su_fd`）。

### 5.4 LKM 化替代评估

susfs 775 行补丁中约 60% 是「在已有内核函数体内插入判断」
（`if (susfs_xxx()) return ...`），kprobe 只能改入口寄存器/返回值，
**无法等效插入函数中段逻辑**（尤其 `filldir64` 过滤、`generic_fillattr` 伪装、
`show_map_vma` 隐藏）。可近似实现子集：
`set_uname` / `set_cmdline_or_bootconfig` / `add_open_redirect`（kretprobe 改返回值）。
**完整 susfs 不可能 LKM 化。**

## 六、我们的实现状态汇总

| 层 | 项 | 状态 |
|---|---|---|
| 内核 | TRACEPOINT hook | ✅ 已在 5.4 Non-GKI 打通（自研 gate 解除） |
| 内核 | 7 feature | ✅ 全在（401 个 `ksu_*` 符号实证） |
| 内核 | manager 组 | ✅ |
| 内核 | hotload api（自研） | ✅ 导出仍在；companion 模块已降为 **legacy 可选**（late 分支自给） |
| 内核 | prctl 主动驱动发现（自研） | ✅ `ksu_current_has_driver_fd` |
| 内核 | PT_REGS_PARM4 shim（自研修复） | ✅ |
| 内核 | `ksu_late_loaded` 真实值 + 真走 late 分支（2026-10-31） | ✅（旧的强制 `=false` 已推翻——谎报加载时机违反真协议；越狱徽章出现属真实状态） |
| 内核 | `ksu_enforce_on_load` 参数（自研，默认 0） | ✅ 恢复链在 Permissive 期装 overlay/daemon，尾部才 flip enforce=1 |
| 内核 | UAPI 6 bump（自研） | ✅ |
| 内核 | **SUSFS** | ❌ **0 符号，需重编内核+解锁** |
| 内核 | MULTI_MANAGER_SUPPORT | ❌ 未开（可选） |
| userspace | ksud 全命令 | ✅（susfs 命令存在但内核不支持） |
| 管理器 | 21 路由 | ✅ 官方 APK |
| 管理器 | SuSFS 7 tab | ✅ UI 在，显示「未启用」 |

**「完整 BakaSU」达成度：非 susfs 部分 100%，susfs 部分 0%。**

## 七、若要做 susfs：唯一路径与代价

```
解锁 BL（fastboot flashing unlock，清数据）
  → 用 work/kernsrc/sm6375-v15（5.4.254-qgki 源码）
  → 打 susfs kernel-5.4 补丁（或从 gki-android12-5.10 移植）
  → 改 CONFIG_KSU_TRACEPOINT_HOOK → CONFIG_KSU_SUSFS + 内核 hook 点
  → 编 boot.img + 禁用 AVB（或自签名 vbmeta）
  → fastboot flash boot
```

代价：
- 失去「原厂内核 + 回锁」的验证状态（AGENTS 记录的回锁实验成果作废）
- 首次解锁清空 /data
- 自编内核 = 失去 OPPO 原厂签名/完整性，且 5.4.147 源码树 vs 设备 5.4.254 的差异需大量适配
- 我们的 exploit 链（依赖原厂内核偏移 target.h）需重新验证

**不做的代价**：SUSFS 的隐藏能力缺失（反检测场景），但链本身与 root 功能不受影响。
