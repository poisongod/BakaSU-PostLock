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
| **世界隔离** | **结构性 1 项**（`W` 独立 mount namespace，已落码并于 fresh boot 端到端验收通过）；其余可见性仍靠过滤层（DAC/MAC/SUSFS） | `W` 的挂载落在 `N` 从不进入的 mount namespace；对象从「N 里路径可达但被拒」变成「N 里路径不存在」——`W` 已做到，物料迁入未开工 |
| **唯一入口** | 文件入口已收敛为 1（sucompat）；**协议入口仍 4 条各自为政** | 单一分发点 + 单一准入判定表 |
| **入口监控** | 只有 `printk`/`dmesg` 级记录 | 结构化、可离线核验、不可否认（T1 才补，§6.4） |

**当前交付等级 = T0 的过滤层基本可用 + 入口收敛第 1 项完成 + 世界隔离已起步（1 项落码）+ 审计缺失。**
准确的自我描述是「T0 的过滤层基本可用，入口收敛刚起步，世界隔离刚起步（1 项落码且已验收）」，
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

### 2.1 现状：结构性隔离 1 项（已落码，fresh boot 端到端验收通过）

| 层 | 手段 | 强度 | 失效模式 |
|---|---|---|---|
| 结构性 | `W` = restore 的独立 mount namespace（holder 常驻 + `MS_REC\|MS_PRIVATE` + 自有 tmpfs） | 高（namespace 层：`N` 侧路径**不存在**，不是被拒） | holder 死 = `W` 消失（tmpfs 内容随之释放，无残留） |
| 过滤 · DAC | `/data/local/tmp` `0711`、`ksu_boot` `0700`、日志 `0600` | 中（P1-1 已落地） | 权限写错一个目录 = 全部可见 |
| 过滤 · MAC | SELinux 策略 | 中 | 策略写错 = 一条路径可达 |
| 过滤 · SUSFS | 九项 hook | 中 | 漏一个观测面 = 一条 `grep` 定性 |

**落码位置与验收状态**：`tools/wns`（helper，`08af3e91…`）+ `tools/postlock.sh`
holder 段（`3150d75f`）+ 扫描器 `W1`-`W5`（`08cdacc6`）。真机原语（`hold`/`run`/
`stat`）与扫描器三态已在 boot `13b5a48a` 验过；**生产路径 = restore 在
`kernel:s0` 起的 holder + restore 自己消费**，已于 fresh boot `194c5414`
端到端验收通过（`by=kernel` + `mountpoint=yes` + `n-side-absent`，零
`WARN-suvtz-w-*`；扫描器 `PASS=37 INFO=0`），故本行强度标「高」是**已验收结论**，
不再只是设计强度。取证全文：`docs/forensics/suvtz-w-194c5414/`（含 `README.md`
判读表、`verdict.txt`、`check.txt`、40 探针产物、链/restore 日志、蓝卡截图）。

**覆盖范围仅限 restore 世界**：受 SELinux 域墙约束（见 §2.4），链（`shell:s0`）
无法进入 `kernel:s0` 的 holder，且链是引导、`W` 是引导的产物 —— 所以 `W` 的
消费者只有 restore 自己。这不是实现缺口，是顺序 + 域的硬约束。

**三个 namespace 的事实**（本机实测 inode）：app `4026534122` / zygote64 `4026533851` /
shell `4026533362`，app 的是全局 `shared:65` 的 **slave**（`master:65`）。
这些是 Android 原生分割，**不是我们建的**，也不提供对 `W` 的隔离。

### 2.2 为什么 `W` 只能由 restore 建（关键约束）

结构性隔离的定义是：`W` 的挂载落在 `N` **从不进入**的 mount namespace 里。
实现它需要 `CAP_SYS_ADMIN` + `unshare(CLONE_NEWNS)`。**restore 自己
（`kernel:s0` = init 域）就有 `CAP_SYS_ADMIN`**，`unshare` 能力面已有历史实测
（P1-2 之前 restore 长期成功在 `shell_data_file` 下挂 tmpfs/overlay）。
`by=kernel` 这条判据行**已于 fresh boot `194c5414` 取得**：生产 restore 在
`kernel:s0` 里 direct 起 holder 成功（`suvtz-w: holder pid=5970
ns=mnt:[4026534144] mp=/data/local/tmp/.w by=kernel` + `mountpoint=yes` +
`n-side-absent stage=ENOENT`），**未走 `su -c` 回落**。此前的顾虑（本 boot 无法
自造 `kernel:s0` 进程，`su -c "runcon u:r:kernel:s0 id"` → `Permission denied`）
只说明「不能预演」，不影响生产路径本身。`su -c`（`ksu` 域）保留为
**回落路径**（`by=ksu`），其 `unshare -m` + tmpfs + 写 marker 已实测（C7），
因为 `ksu` 域可用性本身依赖 ocsk 先加载，见下面这条硬因果链：

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
       │  unshare 失败才回落 /system/bin/su -c（ksu 域）。判据行 by=kernel|ksu|reused。
       └─ holder 进程持有 W 的 mount namespace
            ├─ .../stage     ← 仅「纯 restore 消费」的物料（ocsk/hotload ko、
            │                   pp_adb_tcp.bin、postlock_adbkey.pub、sep_enforce1.txt），
            │                   从 N 侧 stage 拷入。链关键集**不进** W（域墙，见 §2.4）
            └─ .../state     ← restore 自己的状态（预留槽位）。
                                ksu_kaslr / ksu_payload 由链（shell）写 → 留 N

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

**先摆硬约束（实测，2026-11-09）**：**一个 `W` 只能服务一个 SELinux 域**。
`W` 的 holder 由谁 fork，它就是哪个域；别的域 `open(/proc/<pid>/ns/mnt)` 被
SELinux 拒（shell→ksu、shell→kernel 均实测 `Permission denied`）。而链必须在
`shell:s0` 跑（bootstrap 早于 ocsk），`W` 只能在 restore（`kernel:s0`）里建 ——
所以：

> **`W` 的消费者只有 restore 自己。链（`shell:s0`）既不能创建 `W`
> （`unshare -m` 实测 `EPERM`），也不能进入 `W`。**

据此分类（与上一版「链 + restore 都归 W」的设想不同，那一版与域墙矛盾）：

| 对象 | 消费者（域） | 归属 | 依据 |
|---|---|---|---|
| `preload.so` / `kernelsu.ko` / `finitmod` / `restore.sh` / `ksud` / `ksu_payload` / `skbdelta` / `.ks_lock_slots` | 链（`shell`） | **必须留 `N`** | 链跑在 `W` 存在之前，且 `shell` 进不了 `W` |
| `oplus_check_suppress.ko` / `kernelsu_hotload_init.ko` / `pp_adb_tcp.bin` / `postlock_adbkey.pub` / `sep_enforce1.txt` | 仅 restore（`kernel`） | **可迁 `W`** | holder 提前到消费点之前即可；消费侧 `wns run <holder> ...`，失败回退 `N` 副本（WARN-only） |
| `ksu_kaslr` | 链写（`shell`）；当前无消费者（app 自派发已冻结） | **留 `N`** | 写者进不了 `W` |
| `postlock_chain.log` / `postlock_restore.log` | restore 写、app 读 | **必须留 `N`** | app 无法进 `W`（`/proc/<pid>/root` 也 `Permission denied`）→ 写进 `W` 就等于不可读 |
| `tailscaled` / `ts.state` / `tshealth` / `wan_watch.sh` | shell 域 WAN 通道 | **`N`**（不属于 SUVTZ） | WAN 是通道，不是 `W` 能力 |
| `/data/adb/ksud` / `/data/adb/ksu/bin` | sucompat 改写目标（内核按路径打开，解析在**调用者**的 ns = `N`） | **`N`**（`0700 root`） | 迁进 `W` 会让 sucompat 找不到目标 |

**结论**：结构性隔离的真实收益面 = 「纯 restore 消费的物料」+（将来）restore
自己的状态。链关键集留在 `N` 不是妥协，是域墙的必然结果 —— 除非将来让链
本体跑在 `W` 里，而那要求 `W` 先存在，与 bootstrap 顺序矛盾。

**迁移的执行前提（2026-11-10 实测）**：迁移要让 restore 在 `W` 里跑
`finitmod` 载入模块。这里有个容易想错的点 —— **命令本体不必在 `W` 里**：
`wns run <pid> <cmd>...` 是「进 `W` 的 ns 后 exec」，所以 `finitmod` 可以留在
`N`（`/data/local/tmp/ksu_boot/finitmod`），只有它的 `.ko` 参数需要解析到 `W`
（进 ns 后 `/data/local/tmp/.w/stage/x.ko` 就指向 tmpfs）。于是前提收敛成一句：
**`kernel:s0` 能否 `setns` 进 `W` 并 exec**。

这个前提**无法从外部探测**（实测三条）：

| 探测方式 | 结果 |
|---|---|
| `su -c 'runcon u:r:kernel:s0 /system/bin/id'` | `runcon: exec /system/bin/id: Permission denied` —— ksu 域连 `kernel` 域都进不去，与 `W` 无关 |
| `su -c 'runcon u:r:kernel:s0 $WNSBIN run 5970 /system/bin/true'` | 同上 `Permission denied`（失败在 runcon 的 exec 转换，不是 `setns`） |
| `su -c '$WNSBIN run 5970 /system/bin/true'`（ksu 域） | ✅ 成功（与 W4 判据一致） |

即 `u:r:kernel:s0` 的唯一实例就是 restore 自己，只能在 restore 内部观测。
故在 holder 段 mountpoint 检查之后加了一条 WARN-only 探针
（`tools/postlock.sh`，2026-11-10）：

```
suvtz-w: exec=yes           restore 自己进了 W 并 exec —— 迁移可行
suvtz-w: exec=yes-via-su    只有 ksu 域能进（迁移得走 ksu 而非 restore）
WARN-suvtz-w-exec           都进不去 —— 迁移按现形态不可行
```

探针结果决定下一轮是否按 §2.4 的「可迁 `W`」清单动手；在拿到 `exec=yes`
之前**不把迁移补丁应用到真实文件**。

**迁移补丁（干跑已通过，未应用、未装机）**：`tools/postlock.sh` 的迁移改动
已完成并在**副本**上验证，真实文件保持原样（等 `exec=yes` 实测）。补丁形态：

- **holder 段整体上移**到模块加载之前（原位置在 overlay 段之后），否则
  「消费点在 holder 之前」的矛盾无法解决。
- **`su` 回落必须门控**：上移后 holder 段执行时 `oplus_check_suppress` 尚未
  加载，此时跑 `su` 会触发 OPLUS_ROOT_CHECK → `kevent_send_to_user:execve`
  上报 → 弹窗 → 15s 强制重启。故新增 `WSUOK=1` 仅当
  `[ -x /system/bin/su ] && [ -d /sys/module/oplus_check_suppress ]`，
  holder 回落 / mountpoint 回落 / exec 回落三处一律走它。
- **`WSUOK` 在本设备上恒为 0（源码 + 实测定案，取代旧说法「uid 0 恒允许」）**：
  `../BakaSU/kernel/policy/allowlist.c:271` `__ksu_is_allow_uid()` 先过
  `forbid_system_uid()`（`:129`，`uid < 2000 && uid != 1000`）——**对 uid 0 为真**；
  `:301` `__ksu_is_allow_uid_for_current(0)` 返回 `is_ksu_domain()`。
  `../BakaSU/kernel/feature/sucompat.c:194` 的 stat 假象与 execve 改写**都**以
  它为门控 ⇒ **uid 0 只在 `u:r:ksu:s0` 内被放行**。restore 永远跑在
  `u:r:kernel:s0`，于是 `test -x /system/bin/su` 看到真实缺失的文件（实体不存在）
  → 恒假；即便绕过 `-x`，`su -c` 也会 ENOENT。
  dmesg 里 22 条 `newfstatat ... su -> /data/adb/ksud` 来自 **shell uid 2000**
  （`allow_shell=true`，`CONFIG_KSU_DEBUG=y`），不是 restore。
  **因此「同 boot 重跑时 ocsk 已加载 → 门控自然放行」不成立**（restore 永远是
  `kernel:s0`），旧注释与判据里基于该假设的分支已订正。
- **门控必须 in-band 可观测**（否则判据永远是 UNKNOWN）：三条日志
  `suvtz-w: su-gate closed (domain=$WCTX su-visible=no; sucompat excludes uid 0
  outside ksu domain)` / `suvtz-w: su-gate open (domain=ksu ocsk=yes)` /
  `suvtz-w: su-fallback-skipped (ocsk not loaded)`。三者都表示「门控确实 firing」
  → 判据一律 PASS。`WCTX` 由 `grep -q 'ksu:s0' /proc/self/attr/current` 判定。
- **填充 = 读 `N`、写 `W`**：`wns run $WPID /system/bin/cp -f <N 路径>
  $WMP/stage/<名>`，不需要改 `wns.c`（W 是 N 的完整视图 + `.w` 上叠 tmpfs，
  所以 `cp` 的源在 N 侧可见、目标落在 tmpfs）。每个文件填充后立刻用
  `wns run … /system/bin/test -f` 回验，成功才置 `WMIG_*=1`。
- **消费 = `W` 优先、`N` 兜底**（Phase B 保留 N 副本，WARN-only 可逆）：
  ocsk/hotload 用 `timeout 30 $WNSBIN run $WPID $TMP/finitmod
  $WMP/stage/<ko> 0 [arm=1]`；pubkey / protobuf 用 `wns run … cat` 且
  重定向由 `N` 侧 shell 打开真文件（子进程继承 fd1 → 二进制无损）。
  判据行：`suvtz-w: staged ocsk=1 pub=1 pp=1`、`hotload-finitmod-ok-w`、
  `oplus_check_suppress-finitmod-ok-w`、`adb-keys-from-w`、`pp-from-w`。
- **`sep_enforce1.txt` 不迁**：`ksud sepolicy apply <file>` 在 `N` 执行，
  先拷出来再删等于瞬时暴露，不构成边界。

**Phase B 已应用（2026-11-10，主仓 `0c0704ba` / app `cebb2e5`）**：
`tools/postlock.sh` 61508 → 65860 字节（6 个 hunk：块上移 + 迁移填充、4 处
消费点改写、旧位置删除），sha1 `c9099617…`；`bash -n` 与
`tools/check_restore_heredoc.sh` 均通过；生成器产出的 assets `restore.sh`
35042 字节 / 592 行 / sha1 `979a284f…`（`sh -n` 由生成器内部校验），
`PAYLOAD_VERSION` = `v35-w-migrate-phaseb-20261110`，APK 已装机（vc84/1.84）。

**Phase B 已验收（2026-11-10，fresh boot `c0a9c70b`，host 驱动一轮）**：
`tools/suvtz/check_phaseb.sh` = **PASS=3 FAIL=0 UNKNOWN=3 / 6**；主判据
`check_accept.sh` = **PASS=17 FAIL=0 UNKNOWN=0 → OK**；40 探针
`FAIL=0（另有已接受 3）PASS=37 INFO=0 runas=ok`。实测 in-band 证据：
`staged oplus_check_suppress.ko` / `staged postlock_adbkey.pub` /
`staged pp_adb_tcp.bin` / `staged ocsk=1 pub=1 pp=1 hotload=0` /
`oplus_check_suppress-finitmod-ok-w`（ocsk 真从 `W` 里消费）+
`hotload-skipped-late-init-selfsufficient`。三个 UNKNOWN 全部是**预期内
观测不到**：`PB-PUB`/`PB-PP`（两个 append 块因已 provisioned 而整体跳过）与
`PB-SUGATE`（旧版 restore 的静默门控；in-band 版已在本轮之后落地，待下一轮
fresh boot 复验）。传输保真用 out-of-band `cksum` 补证：
`RESULT=PASS（三个 W 副本与 N 原件逐字节一致）`。取证
`docs/forensics/suvtz-w-phaseb-c0a9c70b/`。
核对器：`bash tools/suvtz/check_phaseb.sh <outdir>`（6 行，全部是「W 路径真的
被走到」的正向信号；FAIL = 静默回退 N，boot 仍可用但迁移未验证）。它与
`tools/suvtz/check_accept.sh` 的 17 项分开计数，不改变验收项总数。

**判读纪律：`PB-PUB` / `PB-PP` 预期是 in-band UNKNOWN，不是失败。** 这两项对应
`adb-keys-from-w` / `pp-from-w`，而它们的宿主块是幂等的「缺失才写」：设备一旦
provisioned（`/data/misc/adb/adb_keys` 含 `postlock_bootstrap`、
`/data/local/tmp/ksu_boot/pp_adb_tcp.bin` 的内容早写进
`persistent_properties`），restore 里整个 append 块被跳过，这两行**永远不会
出现**。此时唯一诚实的记法是 UNKNOWN，不能为了凑绿去改判据或强写。

补证走 **out-of-band 传输保真校验**：以 `ksu` 域（`su -c`，实测可进
`kernel:s0` holder 的 ns，W4 `value:yes`）对**活着的** holder 执行
`timeout 20 $STAGE/wns run <holder_pid> /system/bin/cksum $WMP/stage/<f>`，与
N 侧 `cksum < $STAGE/<f>` 比对 crc 与字节数。这一步验的是「W 里的副本与 N 原件
逐字节一致」，比 `test -f` 强，也不依赖 append 块是否被跳过。判据是 crc **和**
字节数都相等；两者任一不等即 FAIL（拷贝被截断或转义破坏）。

注意 `adb shell` 会把 stderr 并进 stdout，而 `wns run` 的诊断行
（`wns: run ns=... cmd=...`）就打在 stderr 上，解析 cksum 输出前必须
`grep -v '^wns:'` 过滤，否则 `$1 $2` 取到的是诊断行。

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
| ~~`$STAGE/su`~~ | 自研 su daemon 二进制（app payload / stage 目录里的可执行文件） | ✅ **2026-11-10 退役**：daemon 早已下岗，`restore.sh` 全文只用 `/system/bin/su`，该文件从未被 exec —— 属死文件入口。app `PAYLOAD`/`EXEC` 清单移除 + `assets/postlock/su` 删除 + deploy/`postlock.sh` 幂等 `rm -f $STAGE/su` |

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
| **1** | `W` 独立 mount namespace（+ restore-only 物料迁入 `/w/stage`） | **结构性隔离**（第 1 项） | C1/C2/C4/C7 | 原语已实测（`wns` 已编，N 侧全 `ENOENT` / W 侧全 `exists` / holder 退出无残留）；restore 集成已落码 `3150d75f`（holder 段 + `wns` stage push + 判据行 `suvtz-w:`），并已 **fresh boot `194c5414` 端到端验收通过**（`by=kernel` / `mountpoint=yes` / `n-side-absent` / 零 `WARN-suvtz-w-*`；扫描器 `PASS=37 INFO=0`）；扫描器 `W1`-`W5` 已落码（见 §7）；`exec` 探针已实测 `exec=yes`（`1e3e4ef1`，boot `9101e66c`）；**Phase B 物料迁移已验收**（`0c0704ba` / `cebb2e5`，fresh boot `c0a9c70b`：`staged ocsk=1 pub=1 pp=1` / `oplus_check_suppress-finitmod-ok-w` / out-of-band `cksum` 三件逐字节一致；取证 `docs/forensics/suvtz-w-phaseb-c0a9c70b/`），**Phase C（删 N 副本成真隔离）待做** |
| **2** | ~~`ksu_kaslr` / `ksu_payload` 移入 `/w/state`~~ | ~~结构性~~ | — | **被域墙阻塞（不可做）**：这两个文件由链（`shell:s0`）写，而 `shell` 进不了 `kernel:s0` 的 `W`（§2.4）。`/w/state` 槽位保留给「restore 自己产生的状态」 |
| **3** | 协议入口统一分发点 + 策略表 | 入口收敛（第 2 项） | 无 | 待做（影响面大） |
| **4** | 结构化审计条目（固定字段） | 入口监控 | 3 | 待做 |
| 5 | TEE 三实验 → T1 | 审计强度 | 无 | 未开始（§6.2） |

**不做**（已写死在设计里）：T1b/T2 对手隐藏、可用性保证、服务端证明伪造、
物理侧信道（§2.4 / §5.4）。

---

## 7. 与扫描器的关系

`tools/suvtz/scan.sh` 的 40 个探针测的是**边界完整性**（「有没有绕过入口的观测
路径」），不是「结构性隔离做到没有」。两者不能互相替代：

- 结构性隔离的判据是 `N` 侧 `stat <mountpoint>/stage` → `ENOENT`（路径不存在；
  挂载点本身在 `N` 侧是空目录，见 §2.3）
- 扫描器的判据是 `PASS`（app 域看不到某个具体对象）

当前口径（2026-11-10，fresh boot `c0a9c70b` Phase B 验收轮复核后）：共 40 项。

- 无 `W` holder（未跑恢复流程）：`FAIL=0 (另有已接受 3) PASS=32 INFO=5`
  —— 5 个 `W` 探针全 INFO（**没有 W 就没有可验证的事实，给 PASS 属于 vacuous PASS**）
- 有 `W` holder（fresh boot `194c5414` / `c0a9c70b`，`by=kernel` 生产 holder
  实测，两轮同口径）：`FAIL=0 (另有已接受 3) PASS=37 INFO=0`

两轮原始产物：`docs/forensics/suvtz-w-194c5414/scan_194c5414.{txt,tsv}` 与
`docs/forensics/suvtz-w-phaseb-c0a9c70b/scan_c0a9c70b.txt`（均有 holder）；
无 holder 口径见 boot `13b5a48a` 三态验证记录。

其中 A1/A2/D1 是**过滤层**的已接受暴露面，不是结构性缺口。
`B4` 转 PASS 是「对象不存在」的直接结果——如果将来重新引入 overlay，
它会自动转 FAIL，`accepted.tsv` 的登记行保留作回归兜底。

**结构性隔离的探针**（`W` 类，已落码；与现有探针并列，不替换）：

`WMP=/data/local/tmp/.w`。holder 探测走两条路径（`^/data/local/tmp/ksu_boot/wns hold `
→ `^/data/local/tmp/wns hold `，**`^` 锚定是必须的**：`su -c "setsid ... &"` 的
`sh -c` 命令行也含该串，不锚定会自匹配得到假 pid）。

| ID | 视角 | 命令 | 期望 |
|---|---|---|---|
| `W1` | runas（app 域） | `ls $WMP/stage` | `absent`（`ENOENT`）——挂载点目录本身在 `N` 侧存在是正常的 |
| `W2` | **shell** | `ls $WMP` | `empty` —— 必须是空目录（`stage/log/state` 均不可见）。**不能用 runas**：`/data/local/tmp` 是 `0711`，app 域连 `ls` 都拿不到，空输出与「拒绝」不可区分 |
| `W3` | runas | `grep -c $WMP /proc/self/mountinfo` | `zero` —— app 域 mountinfo 里没有这个挂载 |
| `W4` | **root**（ksu 域） | `wns run <holder> /system/bin/mountpoint -q $WMP && echo yes \|\| echo no` | `value:yes` —— `W` 侧仍可用 |
| `W5` | runas | `ls /proc/<holder>/root$WMP/stage` | `absent` —— 经 `/proc/<pid>/root` 也不可穿越（实测 `Permission denied`） |

三个设计约束（都是实测逼出来的）：

1. **`W4` 必须经 `wns run` 而不是 toybox `nsenter`**：toybox `nsenter` 没有 `-c`
   （`Unknown option 'c'`），且**跨域 setns 被拒**（shell 域 `open
   /proc/<ksu_pid>/ns/mnt` → `Permission denied`）。只有创建 `W` 的域能进去，
   所以 `W4` 的视角是 `root`（`/system/bin/su -c`）。
2. **`W4` 有安全门控**：`su` 在 `oplus_check_suppress` 未加载时会触发
   `OPLUS_ROOT_CHECK` → 上报 → 安全弹窗 → 15s 强制重启。所以先 `test -d
   /sys/module/oplus_check_suppress`，再验 `su -c id` 含 `uid=0`，任一不满足
   记 `INFO`（绝不冒险跑）。自检钩子 `SUVTZ_W4_GATE_FAIL=<原因>` 可强制走该分支
   以验证分支本身（无需真卸模块）。
3. **无 holder → 五项全 `INFO`**（不是 PASS）。「没有 W」时五项断言在逻辑上都
   成立，但那是 vacuous PASS，违反诚实口径。

实测（boot `13b5a48a`，ksu 域 holder）：`W1`-`W5` 全 PASS；
kill holder 后重跑 → 5×INFO；`SUVTZ_W4_GATE_FAIL=...` → 仅 `W4` INFO、其余 4 项
照常 PASS。
