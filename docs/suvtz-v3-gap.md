# SUVTZ v3 差距清单（四维）

> **定位**：这是「离 TrustZone 结构还差什么」的清单，**不是验收报告**。
> 判定标准来自 [`suvtz-v3-design.md`](suvtz-v3-design.md) §2.2.3（入口单点性）
> 与 §4.1（三层实现）。观测面完整性的实测结论在
> [`suvtz-p0-baseline.md`](suvtz-p0-baseline.md)，本文件不重复。

---

## 0. 一句话结论

| 维度 | 现状 | 离 TrustZone 还差 |
|---|---|---|
| **世界标记** | 有（per-task flag + per-inode flag），但**软件变量**、打标时机敏感、跨 boot 不持久 | 硬件 NS bit 不可得（§2.2.1）；软件侧只能收敛写入点 + 承认可伪造 |
| **世界隔离** | **结构性 0 项**；可见性全靠过滤层（DAC/MAC/SUSFS） | `W` 的挂载落在 `N` 从不进入的 mount namespace；对象从「N 里路径可达但被拒」变成「N 里路径不存在」 |
| **唯一入口** | 文件入口已收敛为 1（sucompat）；**协议入口仍 4 条各自为政** | 单一分发点 + 单一准入判定表 |
| **入口监控** | 只有 `printk`/`dmesg` 级记录 | 结构化、可离线核验、不可否认（T1 才补，§6.4） |

**当前交付等级 = T0 的过滤层基本可用 + 入口收敛第 1 项完成 + 世界隔离未开始 + 审计缺失。**
准确的自我描述是「T0 的过滤层基本可用，入口收敛刚起步，世界隔离还没开始」，
不是「SUVTZ 已实现」（§4.1 末段原文）。

---

## 1. 世界标记

### 1.1 现有实现

| 标记 | 粒度 | 写入点 | 作用 |
|---|---|---|---|
| `TIF_PROC_UMOUNTED` | per-task（thread flag） | `setuid_hook.c:163` `is_zygote(current_cred())` 通过后 → `ksu_handle_umount` → `susfs_set_current_proc_umounted()` | SUS_PATH / SUS_MAP / OPEN_REDIRECT(uid_scheme=3) / SUS_MOUNT `__lookup_mnt` 全部门控 |
| `AS_FLAGS_SUS_PATH` / `AS_FLAGS_SUS_MAP` | per-inode（`address_space` flags） | `susfs_add_sus_path` / `susfs_add_sus_map`（`ksud susfs` 命令） | 单个 inode 的隐藏/重定向 |
| 伪 `mnt_id >= 2000000000` | per-mount | `alloc_vfsmnt` / `clone_mnt` kretprobe，仅 `u:r:ksu:s0` 触发 | `show_vfsmnt` / `show_mountinfo` / `show_vfsstat` 过滤 |

### 1.2 差距

| # | 差距 | 性质 |
|---|---|---|
| M1 | **标记是软件变量，不是硬件位**。任何 EL1 代码都能改 `task_struct->thread.flags` 与 `address_space->flags`。TrustZone 的 NS bit 由总线携带、Normal World 无法修改 | **不可消除**（§2.2.1：`Obs(W) ⊄ Trusted(W)`） |
| M2 | **打标时机敏感**。`TIF_PROC_UMOUNTED` 只在 `setresuid` 那一刻打；模块加载**之前**完成 setuid 的进程终生不带标志 → 路径拦截对它永久失效。本 boot 的 app 进程启动于模块加载之后，故带标志（实测），但这不是保证 | 可缓解（模块更早加载 / 补充打标路径），不能消除（进程可能先于任何内核模块存在） |
| M3 | **跨 boot 不持久**。所有标记都在内存，重启归零。TrustZone 的 NS 属性随内存内容持久 | 可缓解（restore 内重放），成本随对象数增长 |
| M4 | **`run-as` 域结构性不可观测**。`run-as` = shell fork + setuid，域为 `u:r:runas_app:s0`，`is_zygote` 恒 false → 永远不带标记。这不是缺陷，是**探针方法论边界**（`B4` 的 FAIL 由此而来） | 已定案：不改代码，改判据（`accepted.tsv` 与设计文档 §4.1 已记录） |

### 1.3 可做的收敛

- **写入点已收敛**：`susfs_set_current_proc_umounted()` 只有一个调用者（`ksu_handle_umount`）。
  这是「标记只能由 W 写」的软件版；但没有机制**强制**它，只能靠代码审查。
- **读侧不收敛**：任何代码都能读 flag，且 flag 影响行为 → 侧信道。TrustZone 里
  Normal World 根本读不到 NS bit（除了自己那次访问的）。

**结论**：标记维度已经做到软件层能做到的程度。再往前需要硬件，不在 T0 范围。

---

## 2. 世界隔离（当前的主战场）

### 2.1 现状：结构性隔离 0 项

| 层 | 手段 | 强度 | 失效模式 |
|---|---|---|---|
| 结构性 | 无 | — | — |
| 过滤 · DAC | `/data/local/tmp` `0711`、`ksu_boot` `0700`、日志 `0600` | 中（P1-1 已落地） | 权限写错一个目录 = 全部可见 |
| 过滤 · MAC | SELinux 策略 | 中 | 策略写错 = 一条路径可达 |
| 过滤 · SUSFS | 九项 hook | 中 | 漏一个观测面 = 一条 `grep` 定性 |

**三个 namespace 的事实**（本机实测 inode）：app `4026534122` / zygote64 `4026533851` /
shell `4026533362`，app 的是全局 `shared:65` 的 **slave**（`master:65`）。
这些是 Android 原生分割，**不是我们建的**，也不提供对 `W` 的隔离。

### 2.2 为什么现在做不到（关键约束）

结构性隔离的定义是：`W` 的挂载落在 `N` **从不进入**的 mount namespace 里。
实现它需要 `ksu` 域 `unshare(CLONE_NEWNS)`。而进入 `ksu` 域的唯一方式是 `su`。
这里有一条硬因果链：

```
链必须在 shell 域跑（app 域 perf_event_open 被 SELinux 拒 + tracefs/configfs 不可用）
  → 链成功 → restore（kernel:s0）
  → restore 里 finitmod kernelsu.ko + oplus_check_suppress.ko
  → ocsk 装上 do_group_exit 的 kill 探针
  → 此后 `su -c` 触发 OPLUS_ROOT_CHECK 时进程才不被杀
  → 只有到这一步，ksu 域才真正可用
```

**实测证据**：每次 `su` 提权都会打
`[OPLUS_ROOT_CHECK]:Kill the process of escalation...`；ocsk v14 的
`kill.scan sites=2` + `ret.kill ret=0` ×2 是它存活的唯一原因。fresh boot 上
ocsk 未加载 → `su -c` 必死 → **链的 bootstrap 必须留在 shell 域**。

**这不是缺陷，是顺序约束**：链是引导，`W` 是引导的产物。所以：

> `W` 的 namespace 化只能在「链成功 + restore 加载 ocsk 之后」执行。
> 它属于 restore 的后续阶段，不属于链本身。

### 2.3 目标形态（原语已实测，2026-11-09）

```
restore 尾部（ocsk 已加载；W 的消费者就是 restore 自己 = kernel:s0）
  └─ $STAGE/wns hold /data/local/tmp/.w   ← 见 C7：必须自带 helper 关传播
       │  direct 优先：restore 的 kernel:s0 有 CAP_SYS_ADMIN（同域挂 tmpfs 已实测），
       │  unshare 失败才回落 /system/bin/su -c（ksu 域）。判据行 by=kernel|ksu。
       └─ holder 进程持有 W 的 mount namespace
            ├─ .../stage     ← 链物料（从 N 侧中转区拷入，拷完删中转）
            ├─ .../log       ← 链/restore 日志（N 侧经受限通道读）
            └─ .../state     ← ksu_kaslr / ksu_payload / skbdelta / lock slots

N 侧（app / zygote / shell）的 mount namespace 里：
  /data/local/tmp/.w 存在（普通空目录），但其下 stage/log/state/holder.pid 全部 ENOENT
```

> **顺序不能省**（C7 实测）：`unshare(CLONE_NEWNS)` → `mount(NULL, "/", NULL,
> MS_REC|MS_PRIVATE, NULL)` → 建挂载。少了第二步，`W` 的 tmpfs 会按 `shared:1`
> 传播回 `N` 的 ns，`N` 侧 mountinfo 出现该挂载、`rmdir` 删不掉 —— 比不做更糟。
> `wns hold <dir>` 就是这三步的封装（外加 `stage/log/state`、`holder.pid` 与
> `pause` 常驻）。

> **挂载点必须已存在**：`/` 是 erofs 只读，`mkdir /w` 会 `EROFS`。所以 `W` 的
> tmpfs 挂在已存在且可写的目录上（`/data/local/tmp/.w`，`mkdir_p` 在 unshare
> 之后创建）。目录本身是普通目录（`N` 侧可见，这是挂载点不是内容），`W` 的
> 内容只存在于 tmpfs 里。

**判据（按实测调整）**：

- `N` 侧 `stat <mountpoint>` → `exists=1`（空目录）—— 这不是泄漏，是挂载点本身；
- `N` 侧 `stat <mountpoint>/stage` → `ENOENT`（**不是** `EACCES`）—— 结构性隔离
  与 DAC 的唯一可区分特征（路径都不存在 vs 存在但被拒）；
- `N` 侧 `grep <mountpoint> /proc/self/mountinfo` → 0 行（无挂载、无传播）；
- `N` 侧 `/proc/<holder_pid>/root/<mountpoint>/stage` → `EACCES`（`root` 穿越被
  DAC/SELinux 拒；实测 uid 2000 访问 uid 0 的 ksu 域进程）；
- `W` 侧（`nsenter -t <holder_pid> -m`）`stat <mountpoint>/stage` → `exists=1`，
  mountinfo 显示 `tmpfs`。实测 `mnt_id` 是 SUS_MOUNT 伪 id，但**不依赖**它：
  `hide_sus_mnts_for_non_su_procs=0` 时隔离照样成立（namespace 层，不是过滤层）。

**实测记录（2026-11-09，boot `13b5a48a`，测量用的是 helper 中间版
`498dc60e…` / 419136B；入库终版是 `08af3e91…` / 419776B，差别只是多了
`run`/`stat` 两个诊断子命令，`hold` 的三步序列逐字未变）**：

| 观测点 | `N`（shell, `mnt:[4026533362]`） | `W`（`mnt:[4026534158]`） |
|---|---|---|
| `stat <mp>` | `exists=1 mode=40755`（空目录） | `exists=1 mode=40700`（tmpfs） |
| `stat <mp>/stage` | `exists=0 errno=2(ENOENT)` | `exists=1 mode=40755` |
| `stat <mp>/holder.pid` | `exists=0 errno=2(ENOENT)` | `exists=1 size=6` |
| mountinfo | 0 行 | `tmpfs ... mode=700`，`mnt_id=2000000150` |
| 写 `<mp>/stage/probe.txt` | 失败 `ENOENT` | 成功 |
| `/proc/<holder>/root/...` | `Permission denied` | — |
| holder 退出后 | `mountpoint=no`，目录可删，无残留 | ns 销毁，tmpfs 内容随之释放 |

> **holder 是 `W` 的生命周期**：holder 死 = ns 销毁 = `W` 里的对象全部消失
> （这是「W 的状态不落在 N」的代价，也是它的证明）。所以 holder 必须常驻，
> 且 `W` 里只放可再生对象（stage 从 `build/embed` 重推、state 由链重写）。

### 2.4 对象分类（决定谁迁移）

| 对象 | 消费者 | 归属 | 迁移方式 |
|---|---|---|---|
| `preload.so` / `kernelsu.ko` / `finitmod` / `oplus_check_suppress.ko` | 链 + restore | **W only** | 中转区 → `/w/stage` |
| `restore.sh` / `sep_enforce1.txt` / `ksud` | restore | **W only** | 同上 |
| `ksu_kaslr` / `ksu_payload` / `skbdelta` / `.ks_lock_slots` | 链 | **W only** | 直接在 `/w/state` |
| `postlock_chain.log` / `postlock_restore.log` | app 读（诊断） | W 写 / N 读 | 写 `/w/log`，N 侧经 adb `cat`（现有 `ShellChain` 兜底通道已具备） |
| `tailscaled` / `ts.state` / `tshealth` / `wan_watch.sh` | shell 域 WAN 通道 | **N**（不属于 SUVTZ） | **不迁移**（WAN 是通道，不是 `W` 能力） |
| `/data/adb/ksud` / `/data/adb/ksu/bin` | sucompat 改写目标 | **W**（已被 `0700 root` 保护） | 可保留；真正的入口是内核改写，不是文件 |

### 2.5 迁移的代价

| 代价 | 说明 |
|---|---|
| `su` 每次多一跳 | W 侧操作需要 `nsenter -t <holder_pid> -m` 或经 holder 的 shell |
| holder 是单点 | holder 死 = `W` 的 namespace 消失（`W` 里的对象随之不可达）→ 需要 watchdog |
| stage 部署多一跳 | N 侧 shell 部署到 media 中转 → W 侧拷入 `/w` → 删中转。比现在多一次拷贝 |
| 诊断路径变长 | app 读日志要经 adb（已有实现）或 W 侧导出 |

### 2.6 为什么不迁移 `/product/bin` overlay 而是删掉

已定案（§4.2）：`/product/bin` 的全部价值是「让 `su` 出现在 `PATH` 里」，而 `PATH`
是 `N` 侧概念——迁进 `W` 的 ns 后 `N` 里连 `PATH` 都走不到，等价于删掉。
**真正需要 ns 隔离的是 `N` 与 `W` 都要用的对象**，即 §2.4 的 stage/state/log。

---

## 3. 唯一入口

### 3.1 现有：文件入口已收敛为 1

| 入口 | 形态 | 状态 |
|---|---|---|
| `sucompat` | 内核 `sys_enter` 改写 allow-listed uid 的 `execve("/system/bin/su")` → `ksud` | ✅ 唯一文件入口。`stat` 解析到 ksud inode、`open` 回 `ENOENT`、`exec` 成功 |
| ~~`/product/bin/su`~~ | 412B wrapper（overlay） | ✅ **2026-11-09 退役**（§4.2） |

**判据来自 §2.2.3**：TrustZone 的唯一入口是**指令级**的（`smc #0`），在 Normal World
的命名空间里不占位置。`sucompat` 的入口同样是「内核改写」而不是「文件存在」——
这正是它比 overlay 更接近硬件结构的地方。

### 3.2 差距：协议入口分散（4 条）

| # | 入口 | 使用者 | 鉴权 | 审计 |
|---|---|---|---|---|
| E1 | `ksud debug su` 管道 | 本项目的 restore / wrapper / host 脚本 | allowlist + `ksu_is_manager_uid` | 无（只有 `ksud` 自己的日志） |
| E2 | `libksud.so` 的 `reboot(0xdeadbeef, 0xcafebabe)` | 管理器 app 自取 fd | uid 判定（`ksu_is_manager_uid`） | `dmesg` 的 `install ksu fd: N` |
| E3 | `ksu_debug_manager_appid` 参数写 | restore（兜底） | 文件权限 `0644` + 参数 `module_param_cb` | 无 |
| E4 | SUSFS `reboot` 命令族（`SUSFS_MAGIC`） | `ksud susfs` CLI / 管理器 | `ksu_handle_sys_reboot` 的 uid 检查 | `dmesg` 的 `susfs:[uid][pid][func] CMD_... -> ret: N` |

**问题不是「有 4 条」，而是「4 条各自判定、各自记录、没有统一策略表」**：
- 同一件事（谁是 manager）在 E1/E2/E3 里用三种方式判定（allowlist / uid / 参数）
- 记录格式不统一（E1 无记录、E2/E4 各一种 printk 格式、E3 无记录）
- 新增能力（如未来的 `W` syscall）会变成第 5 条

### 3.3 收敛方向（未实施）

```
单一分发点：ksu_dispatch(cmd, args)
  ├─ 准入：一张表 {cmd → 允许的域/uid/能力}
  ├─ 执行：按 cmd 路由到实现
  └─ 记录：结构化审计条目（cmd / uid / 域 / 参数摘要 / 结果）
```

**为什么现在不做**：它需要改 `kernelsu.ko` 的 supercall 分发层，影响面覆盖
管理器全部功能（`getVersion` / `getAllowList` / `getAppProfile` / `setAppProfile` /
`getFeature` / SUSFS 全部命令）。这是独立于 namespace 化的一项工程，
且**不产生隔离**——它产生可归因性（§4.1 末段：入口审计不产生隔离）。

---

## 4. 入口监控

### 4.1 现有：`printk` 级

| 记录 | 位置 | 可离线核验 |
|---|---|---|
| `susfs:[uid][pid][func] CMD_... -> ret: N` | `susfs.c` | 否（pstore 环形，会被覆盖） |
| `install ksu fd: N` / `install fd for ksu manager(uid=N)` | `supercall.c` / `setuid_hook.c` | 否 |
| `[OPLUS_ROOT_CHECK]:Kill the process of escalation...` | OPPO 原生 + ocsk 拦截计数 | 否 |

### 4.2 差距

| # | 差距 | T0 能否补 |
|---|---|---|
| A1 | 无结构化格式（自由文本，字段位置不稳定） | ✅ 能（改 `printk` 为固定字段） |
| A2 | 无持久化（pstore 环形，重启/时间推移丢失） | ⚠️ 部分（可写文件，但文件可被 `N` 侧特权用户态删改） |
| A3 | 无不可否认性（内核可以伪造/删除自己的记录） | ❌ **只有 T1 能补**（§6.4：TEE 会签） |
| A4 | 无「拒绝」语义（现在只能记录，不能按策略拒绝） | ⚠️ 部分（E1-E4 已有 uid 判定，但不是统一策略） |

**诚实结论**：T0 的「入口监控」只是**观测**，不是**强制**。TrustZone 的 EL3
每次 `SMC` 都会检查且可以拒绝——SUVTZ 的对应物在 T0 里不存在。
这一条不能靠改代码补齐，只能靠 T1（§6.4）。

---

## 5. 硬约束汇总（做任何设计前先读这一节）

| # | 约束 | 证据 | 影响 |
|---|---|---|---|
| C1 | **链必须在 shell 域跑** | app 域 `perf_event_open` 被 SELinux 拒（errno=13）；tracefs 写不进；configfs read 需 route 劫持（鸡生蛋） | `W` 的 bootstrap 不能迁进 `ksu` 域 |
| C2 | **`ksu` 域可用性依赖 ocsk** | 每次 `su` 打 `OPLUS_ROOT_CHECK` → 只有 ocsk 的 `do_group_exit` 探针能拦 | `W` 的 namespace 化只能在 restore 之后 |
| C3 | **`ksu` 域可跑链但无意义** | 实测：`u:r:ksu:s0` + `CapEff 0x3fffffffff` + `NoNewPrivs=0 Seccomp=0`，`SLIDE_ONLY` 与完整链都能跑 | 技术上可行，但 bootstrap 仍是 shell 域 → 多一层无收益 |
| C4 | **N 的 mount namespace 是 boot 早期定的** | app ns 是 zygote ns 的 slave，zygote ns 在 boot 早期建立 | 无法「事后」把对象移出 app 的 ns，只能「从一开始就不放进去」 |
| C5 | **`TIF_PROC_UMOUNTED` 打标唯一路径** | `setuid_hook.c:163` `is_zygote` 门控 | `run-as` 域结构性不可观测（M4） |
| C6 | **`hide_sus_mnts_for_non_su_procs=1` 会害死 restore** | 非 `ksu` 域（含 `kernel:s0`）看不到伪 id 挂载 → 同 boot 重跑时 `mountpoint -q` 失效 → overlay 被 bind 到自己 lower 上（实测叠层） | 该开关**不再打开**；结构性隔离不能依赖它 |
| C7 | **`unshare`/`nsenter` 有，但 `toybox mount` 不会关传播** | 实测（2026-11-09，boot `13b5a48a`）：toybox 0.8.4 有 `unshare`/`nsenter` applet（`/system/bin` 有 symlink）；shell 域 `unshare -m` → `Operation not permitted`（无 `CAP_SYS_ADMIN`）；`ksu` 域 `unshare -m` 成功（`mnt:[4026533362]`→`mnt:[4026534131]`）+ `mount -t tmpfs` 成功。**但** `/` 是 `shared:1`，toybox `mount` 不认 `--make-rprivate` / `-o rprivate`（当 fstab 解析 → `bad /etc/fstab`）→ 新 ns 里的 mount **传播回全局 ns**（实测：退出 unshare 后 outer ns 里 `mountpoint` 仍在、marker 可见） | 必须自带 helper 调 `mount(NULL,"/",NULL,MS_REC\|MS_PRIVATE,NULL)`；**naive 的 `unshare -m; mount` 会把 `W` 的挂载泄漏给 `N`，比不做更糟** |

> **C7 的坑值得单独记住**：`unshare(CLONE_NEWNS)` 只是「复制一份挂载树」，新 ns
> 的 root mount **仍是 `shared:1` 的成员**，所以在新 ns 里 `mount` 会按 shared
> 语义传播给 peer group 的所有成员（包括初始 ns / zygote / app）。
> 顺序必须是 `unshare → mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL) → 建挂载`，
> 中间不能省。toybox 缺这一步，所以 `W` 的 ns 需要一个自带的静态 helper
> —— **已实现**：`tools/wns/wns.c`（`build.sh` 用 NDK r29 静态编译，
> 419776B，sha1 `08af3e91…`），四个子命令：`private`（只关传播）、
> `hold <dir>`（unshare+rprivate+tmpfs+`stage/log/state`+`holder.pid`+
> `pause` 常驻）、`run <pid> <cmd>...`（setns + execvp，绕开 toybox
> `nsenter -c` 的 getopt 陷阱）、`stat <path>...`（N/W 对照诊断）。
> 实测还顺带证明：**泄漏出去的挂载 `rmdir` 删不掉（EBUSY），必须 `umount`**，
> 而 `umount` 又只有 `ksu` 域（`CAP_SYS_ADMIN`）能做——清理成本不低，
> 更说明这一步不能靠试错。

---

## 6. 优先级

按「结构性 > 过滤层 > 入口审计」的既定顺序（§4.1）：

| 序 | 项 | 类型 | 依赖 | 状态 |
|---|---|---|---|---|
| **1** | `W` 独立 mount namespace + stage/state/log 迁移 | **结构性隔离**（第 1 项） | C1/C2/C4/C7 | 原语已实测（`wns` 已编，N 侧全 `ENOENT` / W 侧全 `exists` / holder 退出无残留）；集成进 restore 待做 |
| **2** | `ksu_kaslr` / `ksu_payload` 移入 `/w/state` | 结构性 | 1 | 待做 |
| **3** | 协议入口统一分发点 + 策略表 | 入口收敛（第 2 项） | 无 | 待做（影响面大） |
| **4** | 结构化审计条目（固定字段） | 入口监控 | 3 | 待做 |
| 5 | TEE 三实验 → T1 | 审计强度 | 无 | 未开始（§6.2） |

**不做**（已写死在设计里）：T1b/T2 对手隐藏、可用性保证、服务端证明伪造、
物理侧信道（§2.4 / §5.4）。

---

## 7. 与扫描器的关系

`tools/suvtz/scan.sh` 的 35 个探针测的是**边界完整性**（「有没有绕过入口的观测
路径」），不是「结构性隔离做到没有」。两者不能互相替代：

- 结构性隔离的判据是 `N` 侧 `stat <mountpoint>/stage` → `ENOENT`（路径不存在；
  挂载点本身在 `N` 侧是空目录，见 §2.3）
- 扫描器的判据是 `PASS`（app 域看不到某个具体对象）

当前口径（2026-11-09 退役后）：`FAIL=0 (另有已接受 3) PASS=32 INFO=0`。
其中 A1/A2/D1 是**过滤层**的已接受暴露面，不是结构性缺口。
`B4` 转 PASS 是「对象不存在」的直接结果——如果将来重新引入 overlay，
它会自动转 FAIL，`accepted.tsv` 的登记行保留作回归兜底。

**新增结构性隔离后，扫描器应新增探针**（不是替换现有探针）：
- `W1`：app 域 `stat /data/local/tmp/.w/stage` → 期望 `ENOENT`（挂载点本身存在是正常的）
- `W2`：app 域 `ls /data/local/tmp/.w` → 期望空目录（`stage/log/state` 均不可见）
- `W3`：app 域 `grep '/data/local/tmp/.w' /proc/self/mountinfo` → 期望 0 行
- `W4`：`ksu` 域（经 `nsenter -t <holder_pid> -m`）`stat /data/local/tmp/.w/stage/kernelsu.ko`
  → 期望 `exists=1`（`W` 侧能力保留）
- `W5`：app 域 `/proc/<holder_pid>/root/data/local/tmp/.w/stage` → 期望 `EACCES`
  （`root` 穿越被拒；实测 shell 域即 `Permission denied`）
