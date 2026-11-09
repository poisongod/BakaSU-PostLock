# SUVTZ v3 — 分层信任域设计

> 副标题：为什么这个名字配得上它，以及哪一部分配不上（诚实边界）

---

## 摘要

`SUVTZ` 三次迭代，靶子换了三次：

| 版本 | 定义 | 判定 |
|---|---|---|
| v1（用户提交） | 内核内存隔离：授权表放在预留物理页，普通内核代码读不到 | **证伪**。同特权级无 MMU 隔离；`iomem_resource` 枚举 + `vmap()` 即可重建映射 |
| v2（我的上一版） | 隐藏 + 探针验证 | **不合格**。只是"隐藏的验收报告"，没有信任根、没有边界、没有攻击模型，名字是挂上去的 |
| v3（本文） | **分层信任域**：T0 观测边界 / T1 TEE 密码学锚 / T2 硬件隔离，强度随信任根升级 | 本文论证 |

v3 的核心主张有两句，一句是能力，一句是自限：

1. **SUVTZ 是"用软件构造的 TrustZone 结构"，不是"更强的隐藏"**。它的定义照抄硬件结构，不是照抄 anti-detection：

   | TrustZone 要素 | 硬件 | Virtual 对应 |
   |---|---|---|
   | 两个执行世界 | Secure / Normal | 特权执行世界 `W`（`ksu` 域、`su` 通道、模块与隐藏策略、`W` 自己的文件树与挂载视图）/ 默认世界 `N`（未 root 的 Android 用户态 + 内核中不涉及 root 的路径） |
   | 世界标记 | NS bit | per-task / per-inode flag（`TIF_PROC_UMOUNTED`、`AS_FLAGS_SUS_*`） |
   | 隔离 | TZASC + MMU | namespace / 挂载 / 文件树 + 权限域 |
   | 唯一入口 | `SMC` → EL3 | 固定协议（su socket / `ksud` supercall） |
   | 入口监控 | EL3 每次检查、可拒绝、可记录 | 入口鉴权 + 审计（T1 用 TEE 加强） |

   **关键推论**：TrustZone 里 Secure World 的状态"不可观测"，不是因为被过滤，而是因为 Normal World 没有"读它"的接口——唯一的跨界动作是 `SMC`，而 `SMC` 是**请求服务**，不是**读取状态**。所以正确的工程动作是"让 `W` 的状态不出现在 `N` 的数据结构里"（结构性隔离），而不是"数据在、过滤在"（出口过滤）。过滤层永远漏，漏一个就是一条 grep 定性——这正是「已接受」暴露面里 A1/A2/D1 三个的性质（§5.3；原先第 4 个**扫描器** `B4`（`/product/bin/su`）已于 2026-11-09 随 overlay 退役转为 PASS，见 §4.2；扫描器编号与设计表编号的对应见 §5.3.1）。**边界不画在特权级上**——EL1 里既有 `W` 的守卫（`ksu` 域、SUSFS、`oplus_check_suppress`），也有 `W` 的敌人（ocs 的 `force_sig` 与 `kevent_send_to_user`），所以承诺对象是默认世界 `N` 里我们真正承诺的那部分（§2.2.1）。
2. **在本设备的硬件与启动链条件下，T2 不可达，T1 受限于 3 个未验证前提，T0 是唯一可交付的级别**。任何声称做到 T1/T2 的软件方案都是假的——这一条本身是设计的一部分。

**当前交付状态（诚实标注，2026-11-09 第三轮）**：T0 的三层实现（§4.1）里，过滤层较完整（SUSFS 九项 + DAC/MAC）、**结构性隔离第 1 项已落码**（`W` 的独立 mount namespace：`tools/wns` holder 已接入 restore，设备原语实测通过、fresh boot 端到端验收待跑）、**入口收敛完成第 1 项**（`/product/bin` overlay 已退役，`su` 入口从「overlay 文件 + sucompat 伪造」双路径收敛为 sucompat 单点，见 §4.2）、**审计缺失**。三处必须拆开说清楚：

- **退役 ≠ 结构性隔离**。退役是把对象**删掉**（`N` 与 `W` 都没有），不是把对象迁进 `W` 的独立 namespace。它消除的是「`/product/bin/su` 对 `shell` / `run-as` / 模块加载前 `setuid` 的进程可达」这个过滤层兜不住的缺口（见下方易错点），代价是 `W` 侧也失去该文件入口——这正好符合「入口应收敛到指令级」的判据（§2.2.3）。
- **有了 `W` 的 namespace ≠ 迁移完成**。第 1 项交付的是「世界存在」：`W` 的 tmpfs
  挂在自己的 mount namespace 里，`N` 侧看 `<mountpoint>/stage` 是 `ENOENT`（路径不存在，
  不是被拒）。但 `W` 里目前只有 `stage`/`log`/`state` 三个空骨架——**物料迁入**（`kernelsu.ko` /
  `finitmod` / `oplus_check_suppress.ko` / `ksud` / `restore.sh` / `sep_enforce1.txt`）是下一个
  提交，消费侧同步改完之前 `W` 不产生实际隔离收益。判据与实测见 `docs/suvtz-v3-gap.md` §2.3。
- **P1-2 已随对象消失而失去意义**。原先的「在 `ksu` 域建 overlay + 伪 mnt_id + `__lookup_mnt` 拦截」是过滤层手段（挂载对象仍在 app 的 mount namespace 里，靠进程标志过滤解析）；现在没有 overlay 要隐藏，`hide_sus_mnts_for_non_su_procs` 也不再打开（它会让非 `ksu` 域看不到伪 id 挂载，反而害死同 boot 重跑的 restore——本 boot 实测叠层 bug）。

`tools/suvtz/scan.sh` 的 40 个探针（含 5 个 `W` 类世界隔离探针，见 `docs/suvtz-v3-gap.md` §7）是**边界完整性审计**（验证"有没有绕过入口的观测路径"），不是产品。退役的实测影响面：扫描器 `B4`（`/product/bin/su` 存在）由 FAIL\* 转 PASS（探针实测 `absent`），`B9` / `E2` / `E3` / `X3` 保持 PASS，`B5`（`/system/bin/su` 在 `run-as` 视角）退役前后均 PASS（sucompat 的 `stat` 伪造只对 allow-listed uid 生效，`run-as` 域实测 `ENOENT`）。

---

## 1. 三次迭代的判定

### 1.1 v1 的靶子错了

v1 §3 假设"普通内核代码会主动来读授权表"，于是要把表藏进预留物理页。三个硬伤在上一轮已逐条证伪：

| v1 假设 | 证伪方式 |
|---|---|
| 预留页对普通内核不可见 | 预留页在 `memblock`/`iomem_resource` 里登记；`for_each_mem_range()` 枚举 + `vmap()`（`EXPORT_SYMBOL`）就能重建可读映射 |
| token 是不可转移的能力 | token 与 PID/UID 无绑定，`sendmsg`/共享文件/`process_vm_readv` 都能搬；MAC 随 token 走 |
| 凭证伪装可防检测 | status 显示 caller uid → caller 拿到 ptrace 权限 → 读 `attr/current` 见 `u:r:ksu:s0`，伪装当场破功 |

比这三条更根本的问题是：**检测方根本不读内核内存**。见 §3 实测。

### 1.2 v2 的框架缺了

v2 把结论退成"我们做有证据的隐藏吧"，然后列了 14 项探针。它的问题是**没有回答"为什么这是 TrustZone"**——没有信任根、没有攻击者模型、没有边界定义、没有可达性分级。一份好的测试计划不等于一份安全架构。

### 1.3 v3 要补的四样东西

1. **攻击者模型**（T0/T1a/T1b/T2，见 §4）
2. **边界的形式定义**（观测表面 S 与等价关系，见 §5.1）
3. **可达性分级**（每一级承诺什么、靠什么兜底、什么条件下失效，见 §4/§6/§7）
4. **实现分层**（同一个 T0 内，结构性隔离 / 过滤层 / 入口审计的强度差异，见 §4.1）——v2 把这三者混为一谈，是它「只是隐藏」的根因

---

## 2. 名字的正当性

### 2.1 TrustZone 的不可达性结构

ARM TrustZone 做的事情可以抽象成一句话：

> **存在一个世界 W，Normal World NW 里的任何代码（包括最高特权级）都无法观测或影响 W，除非通过一个固定的、受监控的入口。**

这个"无法"由三样东西强制：NS bit（总线级标记）、TZASC（内存控制器分区）、Secure 中断分组（GIC）。

### 2.2 SUVTZ 的不可达性结构

**先把 `W` 定义对：`W` 是一个执行世界，不是一个状态事实。**

初版把 `W` 写成「rooted 的真实状态」，于是整个设计滑向「如何把状态藏好」——那是 anti-detection，不是 Virtual TrustZone。**状态的可见性只是世界隔离的副产品，不是它的定义。** 一旦把它当成定义，工程动作就会退化成「加 hook、加过滤、加一致性检查」，而结构性隔离永远不会被提出（这正是本项目前期的实际轨迹）。

正确的映射：

| 要素 | 内容 |
|---|---|
| 特权执行世界 `W` | `ksu` 域、`su` 通道、模块与隐藏策略、`W` 自己的文件树与挂载视图 |
| 默认世界 `N` | 未 root 的 Android 用户态，以及内核中不涉及 root 的路径 |
| 边界 | 一切「从 `N` 触及 `W`」的路径：挂载视图、文件树、`procfs`/`sysfs` 输出、符号表、状态查询 |
| 入口 | 固定协议（su socket / `ksud` supercall）——`N` 只能通过它**请求服务**，不能通过它**读取状态** |
| 检测域 `D` | `N` 里真正会做检测的那部分：EL0 应用态，以及内核中向 EL0 输出观测值的路径。`D ⊆ N`，精确枚举见 §5.1 的 `S` |

> **`N` 里的任何代码，除非经过一个固定的、受监控的入口，都无法观测或影响 `W`。**

「影响」这一半只承诺完整性（`W` 的状态标记只有 `ksu` 域能写），不承诺可用性（§2.2.2）。

`N` 比 `D` 大：`N` 里还有不关心 root 的普通代码，`D` 是其中做检测的子集。**把承诺对象写成 `N` 是保守的**——若 `N` 都观测不到，`D` 必然观测不到；验收时只需枚举 `D`（可枚举）而不必枚举 `N`（不可枚举）。

初版照抄 TrustZone 句式时写的是「（**包括**最高特权级）」。**这个括号在本设备上是错的**，理由见 §2.2.1。正确的边界不按特权级划，而按**域与所有权**划：承诺对象是默认世界 `N` 里我们真正承诺的那部分（精确枚举见 §5.1 的 `S`）。

#### 出口过滤 ≠ 世界隔离

这是本项目最容易混淆的一对概念，必须写死在设计里：

| | 出口过滤（当前大部分实现） | 世界隔离（Virtual TrustZone） |
|---|---|---|
| `/proc/modules` 里的 `kernelsu` | 数据在，SUSFS 把行过滤掉 | 模块不出现在 `N` 可见的链表里 |
| overlay 挂载 | **已退役（2026-11-09）**：不再建。此前的 P1-2 形态（`ksu` 域建 + 伪 mnt_id + `__lookup_mnt` 按 `TIF_PROC_UMOUNTED` 拦截）只是挂载视图过滤——挂载对象仍在 app 自己的 mount namespace 里，`shell` / `run-as` / 模块加载前 `setuid` 的进程路径照常可达 | overlay 建在 `N` 之外的独立 mount namespace，`N` 里连路径都不存在 |
| `su` 二进制 | **入口已收敛（2026-11-09）**：`/product/bin/su`（412B wrapper）退役，只剩 `/system/bin/su`——它不是文件，是 sucompat 在 `sys_enter` 把 allow-listed uid 的 `execve` 改写成 `ksud`（`stat` 解析到 ksud inode、`open` 回 `ENOENT`、`exec` 成功）。`run-as` 视角实测 `ls /system/bin/su` → `ENOENT` | 在 `W` 的文件树里，`N` 没有这个路径 |
| 保证来源 | 枚举完整性（漏一个就失效） | 结构（`N` 里根本没有这个对象） |
| 检测方视角 | 「被藏起来了」 | 「不存在」 |
| 失效模式 | 漏一个观测面 = 一条 `grep` 定性 | 漏一项迁移 = 该对象仍属 `N`（可被探针发现） |

容器是活例子：`ps` 看不到另一个 pid namespace 的进程，不是因为 `ps` 被过滤，是因为**那个 namespace 里根本没有它**。所以工程优先级是：**能 namespace 化的先做结构性隔离，不能的才用过滤层兜底，最后把跨界收敛到入口并加审计**（§4.1）。

命题自带三条自限，**它们是定义的组成部分，不是脚注**：

| # | 自限 | 内容 | 见 |
|---|---|---|---|
| 1 | **只承诺机密性与完整性** | `N` 可以通过重启、杀进程、抢占资源破坏 `W` 的**可用性**，本方案不承诺 | §2.2.2 |
| 2 | **不把 EL1 视为可信集合** | `W` 的守卫与其他 EL1 代码同特权级，对「完全控制内核的对手」无任何保证 | §2.2.1 |
| 3 | **单点性由枚举保证，非硬件保证** | 「只有一个入口」这句话的强度 100% 取决于覆盖率 | §2.2.3 |

区别只在「触及」的含义：

| | TrustZone | SUVTZ |
|---|---|---|
| 受保护对象 | 内存内容 | `W` 的内部状态与存在性 |
| 触及方式 | 物理地址访问 | 系统调用观测值 / 跨界协议 |
| 强制手段 | 硬件（NS/TZASC/GIC） | 软件（namespace 化 + 过滤层 + 入口收敛） |
| 边界坐标 | 世界标记（NS bit） | 域 + 所有权（§2.2.1） |
| 单点入口 | 物理强制（`SMC` → EL3） | 协议收敛 + 枚举审计（§2.2.3） |

**结论**：两者保护的对象不同，但「世界 + 入口 + 审计」的结构同构。名字的正当性来自这个同构，而不是来自「我们也隔离了内存」——后者是假的，我们不声称。**同样地，「数据在、过滤在」也不足以叫世界隔离**——那是 §4.1 里的第二层，不是第一层。

### 2.2.1 边界为什么不按特权级划（EL1 非同质）

「不包括最高特权级」这个改法**方向是对的**（把不可达性从**能力声明**降级为**范围声明**），但坐标选错了。它隐含一个假设：**同一特权级 = 同一立场**。本项目的工程实践已经证伪：

| 实体 | 特权级 | 立场 |
|---|---|---|
| `ksu` 域、SUSFS 九个 hook | EL1 | W 的守卫 |
| `oplus_root_check_succ` → `force_sig` | EL1 | **敌人**（回滚提权） |
| `oplus_exec_block` → `kevent_send_to_user` | EL1 | **敌人**（上报 → 弹窗强制重启） |
| `oplus_check_suppress.ko` | EL1 | 我们派去 EL1 战场对抗上面两个的 |
| `com.oplus.exsystemservice` | EL0 | 敌人 |

也就是说，豁免「最高特权级」等于把 ocs 那套内核检查一起豁免掉——而它们**不是理论威胁，是每轮链都在跑的东西**。豁免最现实的对手，威胁模型就自我阉割了。

更根本的问题：这个豁免等于承认命题不成立。定义

```
Obs(W)     = 能观测 W 的实体集合
Trusted(W) = 可信实体集合
```

不可达性命题成立的条件是 `Obs(W) ⊆ Trusted(W)`。

- **TrustZone**：硬件把 `Obs(W)` 压到 `{EL3}`，而 EL3 受信 → **成立**。
- **SUVTZ**：EL1 同特权级无 MMU 隔离（这正是 v1 §3 被证伪的那条），所以
  `Obs(W) ⊇ {我们的内核代码} ∪ {所有其他 EL1 代码}`。只要承认存在不可信的 EL1 实体，
  `Obs(W) ⊄ Trusted(W)` → **严格意义的不可达性直接为假**。

因此「排除最高特权级」不是给命题加个括号，**是在括号里承认了命题为假**。诚实的做法是换坐标：把承诺对象从「所有特权级」收窄到 **默认世界 `N` 中的检测域 `D`**（`D ⊆ N`，§2.2），并把「其他 EL1」单列为风险面——用 `oplus_check_suppress` 这类**同特权级对抗**手段压制，但不做「不可达」承诺。

### 2.2.2 观测与影响的拆分

TrustZone 承诺「无法观测**或影响**」。两个动词的强度完全不同，SUVTZ 只能兑现前者：

| 面 | 能否承诺 | 理由 |
|---|---|---|
| **机密性**（观测不到） | ✅ T0 范围内 | 等价性可枚举验证 |
| **完整性**（改不了状态） | ✅ 状态标记只有 ksu 域能写 | 与 §6.1 的 TEE 结论一致 |
| **可用性**（影响不了） | ❌ | `N` 里的特权用户态（`system_server` 等）可以重启设备（marker 不持久）、杀进程、耗尽资源 |

这与 §6.1「T1 只给完整性/不可否认性，不给机密性或可用性」是**同一条边界**。两处结论对齐，说明它不是偷懒，是这类方案的共同天花板。

### 2.2.3 单点性是枚举的，不是物理的

TrustZone 的「那个固定入口」由硬件强制：只有 `SMC` 指令能进 Secure World，且 EL3 每次都会检查、可以拒绝、可以记录。

SUVTZ 的入口是软的：它靠「我们不给第二个入口」来保证单点。所以**覆盖率不是验收指标，而是定义的一部分**——漏掉一个观测面，入口就不再是单点，`Obs(W) ⊆ Trusted(W)` 的弱化版也会跟着失效。这就是为什么 §5.2 把「覆盖」放在三个完备性条件之首。

**当前实现与这条要求的差距（诚实标注，2026-11-09）**：

| 要求 | 现状 |
|---|---|
| 入口存在 | ✅ sucompat（`execve("/system/bin/su")` → `ksud`，内核改写，无文件载体）、`ksud` supercall |
| 入口收敛 | ❌ 入口事实上不止一个：`ksud` 的 `debug su` 管道、`libksud.so` 的 `reboot` magic、`ksu_debug_manager_appid` 参数写、SUSFS 的 `reboot` 命令族各自独立，没有统一的分发点与准入判定 |
| 入口鉴权 | ⚠️ 分散在 `ksu_is_manager_uid` / allowlist / SELinux 域判定，没有单一的「谁能跨界、跨界做什么」的策略表 |
| 入口审计 | ❌ 只有 `dmesg`/`printk` 级记录（`susfs:[uid][pid][func] CMD_... -> ret`、`install fd for ksu manager`），没有结构化、可离线核验、不可否认的审计链（T1 才补得上，§6.4） |

也就是说：**入口「在」，但既不「单」也不「被监控」**。这是 T0 里最欠的一层，比过滤层漏几个观测面更根本——过滤层的缺口是「看到了」，入口的缺口是「被用掉了」。

### 2.3 三要素映射（含诚实强度）

| TrustZone 要素 | 硬件实现 | SUVTZ 对应 | 实际强度 |
|---|---|---|---|
| 世界隔离 | NS bit | 结构性隔离（namespace / 挂载 / 文件树）+ 过滤层（§4.1） | **弱**：结构性隔离是强保证但当前仅 1 项落码（`W` 独立 mount ns，物料未迁入）；其余可见性全靠过滤层（枚举），漏一个就失效 |
| 状态机密 | Secure RAM | TEE 不可导出密钥（T1） | **强**，但仅限密钥本身 |
| 单向入口 | SMC | 窄协议（socket / 私有 syscall） | **弱**：协议存在但**未收敛**（§2.2.3），多个 magic 各自为政 |
| 入口监控 | EL3 每次检查、可拒绝、可记录 | 入口鉴权 + 审计（T1 用 TEE 会签） | **弱**：T0 下只有 `printk` 级记录；T1a 才给不可否认性 |
| 判定自主 | S-EL1 独立执行 | TEE MAC 会签 + 用户态 Gate（T1） | **中**：T1a 成立，T1b 不成立 |
| 中断隔离 | GIC 分组 | 无对应 | **无** |
| 内存完整性 | TZASC | 无对应 | **无** |

表里三个「无」、三个「弱」就是这套方案的代价。**把它们写出来，比藏起来更对得起名字。** 注意「弱」不是「没做」——单向入口与入口监控都有实现，弱在**结构性**：它们靠约定与枚举，不靠强制。

### 2.4 硬边界（明确不做承诺的部分）

§2.2 的三条自限是**定义的组成部分**，本节把它们落成具体清单。以下四件事，本设备上**任何软件方案都做不到**，包括本设计：

1. **对完全控制内核的对手（T1b）隐藏**。内核可以读任何内存、改任何用户态进程、伪造任何返回值。没有 EL3/Secure-EL2 的强制，用户态 + TEE 也救不了（内核可以让 broker 根本不运行）。**论证见 §2.2.1：`Obs(W) ⊄ Trusted(W)` —— 这不是实现不足，是命题前提不成立。**
2. **保证可用性**。D 可以重启设备、杀进程、耗尽资源——本方案只承诺机密性与完整性（§2.2.2）。
3. **对服务端证明（Play Integrity / SafetyNet / 银行私有风控）伪造**。它验证的是 Google 签名链与硬件密钥证明，密钥不可导出。
4. **对物理/侧信道隐藏**。启动时间、CPU 频率、内存带宽、功耗曲线都不在我们的控制面内。

**这是「EL1 同特权级」与「软件方案没有硬件信任根」的双重数学事实。** 承认它，是设计质量的一部分。

---

## 3. 实测：检测面到底长什么样（2026-11-03，boot `5394a404`）

这一节的数据全部来自设备实测，不是推演。它决定了 v3 的全部优先级。

| # | 观测面 | 检测方能否执行 | stock 值 | 当前值 | 判定 |
|---|---|---|---|---|---|
| 1 | `getprop persist.adb.tcp.port` | 任何 app | 空 | **`5555`** | **泄漏** |
| 2 | `pm list packages` | 任何 app（`QUERY_ALL_PACKAGES`） | — | **`com.resukisu.resukisu`** | **泄漏（最致命）** |
| 3 | 同上 | 同上 | — | **`com.postlock.boot`** | **泄漏** |
| 4 | 同上 | 同上 | — | **`com.postlock.privateapp`** | **泄漏** |
| 5 | `getprop ro.debuggable` / `ro.secure` | 任何 app | 0 / 1 | 0 / 1 | 正常 |
| 6 | `getprop ro.boot.verifiedbootstate` | 任何 app | green | green | 正常（回锁后为真） |
| 7 | `getprop sys.oem_unlock_allowed` | 任何 app | 0 | 0 | 正常 |
| 8 | `run-as <app> ls /sys/module` | app uid | 无 kernelsu | 待复测（见注） | 待定 |
| 9 | `run-as <app> cat /proc/kallsyms` | app uid | 无 `ksu_` | 待复测 | 待定 |
| 10 | `run-as <app> ls /data/local/tmp/ksu_boot/` | app uid | 不存在 | **可读，列全套物料** | **泄漏（已实锤）** |

> 注：第 8/9/10 项都在 `u:r:runas_app:s0` 域下执行（`run-as` = shell fork + `setuid`，不走 zygote 路径）。该域**结构性不带** `TIF_PROC_UMOUNTED`（`setuid_hook.c` 的 `is_zygote` 门控，见 §4.1 易错点），所以依赖该标志的 SUSFS 隐藏对它一律不生效——它属 §5.1 承诺范围外的观测面，结果不能当作 `untrusted_app` 结论。真值需用 app 自身代码（`SusfsSelfTest`）复测，见 P0。

**排序结论**：泄漏的严重性依次是 **包名 ≫ 物料目录 > 属性 > 模块目录 > 符号名**。原因很简单——包名是"一个 grep 就定性"的证据，而 `persist.adb.tcp.port=5555` 只是"可疑"（大量正常用户开无线调试）。

**这直接决定 P0 的顺序**：包面为零内核代码可解（管理器自带 Hide），物料目录用现成 SUS_PATH，属性面需要新机制，模块目录需要新 kernfs hook。

---

## 4. 分层信任域

T0/T1/T2 分的是**信任根**（谁在背后强制），不是**实现手段**。同一个 T0 内部，隔离的强度取决于用哪种手段实现——这一层容易被忽略，却是本项目最实际的差距所在（§4.1）。

| 级别 | 信任根 | 承诺 | 设备可达性 | 依赖 |
|---|---|---|---|---|
| **T0** | 我们自己的内核代码（诚实假设） | 用户态检测方无法区分 rooted 与 stock | ✅ **可达** | 现有链 + SUSFS + 包改名 |
| **T1a** | TEE KeyMint HMAC（密钥不可导出） | 即使内核**只读**被攻破，也无法伪造"用户授权过"或篡改隐藏策略 | ⚠️ **待验证**（3 个前提实验） | §6.2 |
| **T1b** | 无 | — | ❌ **不可达** | 需 EL3（`Obs(W) ⊄ Trusted(W)`，见 §2.2.1） |
| **T2** | EL3 / Secure-EL2 / RME | 真正的内存隔离 | ❌ **不可达** | 需 boot.img 自由 + 硬件 |

**关键取舍（必须写清楚）**：

T1 的前提是"内核只读不可信"。但如果内核完全可控（T1b），它可以让 broker 不运行、可以伪造进程身份、可以改任何用户态内存——**T1 也会塌**。

这正是 §2.2.1 的同一个事实在另一处的投影：**T1 提高的是 `Trusted(W)` 的强度，压不下 `Obs(W)` 的大小**。所以 T1 不能把 T0 的边界往外扩一寸——它只是让边界内的授权变得不可抵赖。

所以 **T1 的价值不是"更强的隔离"，而是"更强的可归因性"**：T1 让"是谁授权的"变成不可抵赖的事实，而不是内核的一面之词。这一点在**审计**与**多用户场景**里有真实价值，在"对 T0 隐藏"这件事上没有增量。

v3 诚实的定位：**T0 是产品，T1 是审计能力，T2 是未来**。而 T0 内部也不是一个强度——它的实际强度取决于 §4.1 三层各做到什么程度。

### 4.1 T0 的三个实现层（工程落点）

T0 承诺「`N` 观测不到 `W`」，但这句话可以靠三种完全不同的手段去兑现，强度与失效模式各不相同：

| 层 | 手段 | 保证来源 | 失效模式 | 当前覆盖（2026-11-09） |
|---|---|---|---|---|
| **结构性隔离** | namespace（mount / pid / fs 视图）、独立文件树、独立挂载点 | `N` 里根本不存在该对象 | 漏一项迁移 = 该对象仍属 `N` | **1 项（已落码）**：`W` 的独立 mount namespace（`tools/wns hold` = `unshare(CLONE_NEWNS)` → `/` 设 `MS_REC\|MS_PRIVATE` → 已存在目录上 tmpfs），2026-11-09 设备原语实测通过（`N` 侧 `<mp>/stage` = `ENOENT`、`W` 侧 tmpfs 可写）；**物料迁入仍待办**，故 `W` 现在只有空骨架。P1-2 常被误记为已做结构性隔离，实际只做到挂载视图过滤；**该对象已于同日退役**（删掉而非迁走，见 §4.2） |
| **过滤层** | ① SUSFS 九项 hook（输出过滤，靠枚举完整性）② DAC / SELinux（访问控制：对象在，访问被内核拒） | 枚举完整性（①）/ 内核权限模型（②） | ① 漏一个观测面 = 一条 `grep` 定性；② 策略写错 = 一条路径可达 | **较完整**：九项 feature 全部实现并实测；~~P1-2 属此层~~（**2026-11-09 随 overlay 退役消失**——没有对象可过滤）；「已接受」暴露面 4 → **3 项**（A1/A2/D1），**扫描器** `B4`（`/product/bin/su`）退役后实测转 PASS、登记行仅作回归兜底（§4.1 易错点） |
| **入口 + 审计** | su socket / `ksud` supercall 收敛 + 鉴权 + 记录 | 协议设计 + 调用点唯一 | 多一个 magic = 多一个绕过入口的通道 | **部分收敛**：文件入口已收敛到 sucompat 单点（2026-11-09）；协议入口仍分散（`ksud debug su` 管道 / `libksud.so` reboot magic / `ksu_debug_manager_appid` 参数 / SUSFS reboot 命令族），**审计缺失**（§2.2.3） |

**优先级 = 结构性隔离 > 过滤层 > 入口审计。** 理由：结构性隔离的失效模式是「漏了一项」，过滤层的失效模式是「漏了一个观测面」，而观测面的数量随内核版本与厂商定制增长（本项目实测 35 项还不够，见 §5.3）。入口审计本身不产生隔离，它产生**可归因性**——那是 T1 的真实收益（§6.4）。

**为什么过滤层不能替代结构性隔离**：过滤是「数据在、看不见」，结构隔离是「数据不在这个世界」。前者靠枚举完整，后者靠对象归属。枚举永远不完备（内核每加一个 `/proc` 节点、厂商每加一个 sysfs 属性，都要重新枚举一次），而对象归属只需要在创建时决定一次。这就是容器用 namespace 而不是 `LD_PRELOAD` 隐藏进程的原因。

**当前交付的真实等级**：结构性隔离 **1 项起步**（`W` 的独立 mount namespace 已建，但物料迁移未做，`W` 目前是空骨架）、过滤层较完整、入口**部分收敛**（文件入口 1 项已收敛，协议入口未收敛）、审计缺失。所以准确的说法是「**T0 的过滤层基本可用，入口收敛刚起步，世界隔离刚起步——有世界，还没有东西搬进去**」——不是「SUVTZ 已实现」。

**为什么 P1-2 不算结构隔离（易错点，2026-11-09 复核 + 实测修正；该机制已于同日随 overlay 退役，以下为历史归因，保留作将来重启 P1-2 时的判据）**：它用 `runcon u:r:ksu:s0` 建挂载，只是换了**建挂载时的域**（打上伪 mnt_id 的前提），mount namespace 并未分裂——`app` / `zygote64` / `shell` 是三个不同的 mount namespace（本机实测 inode `4026534122` / `4026533851` / `4026533362`），app 的那个是全局 `shared:65` 的 **slave**（`master:65`），overlay 经**挂载传播**进入它。所以 overlay 对象确实在 app 自己的 namespace 里（`ksu` 域读 `/proc/<app_pid>/mountinfo` 可见 `2000000003 … /product/bin … overlay`），`N` 侧只是**看不见 / 打不开**它。可见性的改善来自两处**过滤**：`show_vfsmnt`/`show_mountinfo`/`show_vfsstat` 三个 kprobe 按伪 id 隐藏（开关 `hide_sus_mnts_for_non_su_procs`，对全体非 `ksu` 域生效），以及 `__lookup_mnt` 按 `TIF_PROC_UMOUNTED && uid>=10000` 拦截路径解析（**只对带标志的进程生效**，`lookup_hook` 可关）。

两层事实必须分开（2026-11-09 实测，boot `13b5a48a`）：

- **真实 `untrusted_app` 域：拦截生效**。zygote fork 的 app 进程（`u:r:untrusted_app:s0`，uid 10286）经 `SusfsSelfTest` 广播自检，`stat /product/bin/su` → `exists=0`；同轮 `ksu` 域读该进程 `/proc/<pid>/mountinfo`，overlay 确实在它自己的 namespace 里 → `ENOENT` 只能来自 `__lookup_mnt` 拦截，这同时证明该进程带 `TIF_PROC_UMOUNTED`。
- **`run-as` 近似域：结构性不可观测**。`run-as` 是 shell fork + `setuid`，域为 `u:r:runas_app:s0`；`setuid_hook.c` 的 `if (!is_zygote(current_cred())) return 0` 使它**永远不带** `TIF_PROC_UMOUNTED` → 拦截永不适用 → 恒见 `/product/bin/su`（412 字节）。`B4` 探针跑的就是这个视角，它的 FAIL 是**探针方法论缺陷**，不是「隐藏失效」；同理 `run-as` 对 `SUS_PATH` / `SUS_MAP` / `OPEN_REDIRECT`(`uid_scheme=3`) 这些同样依赖该标志的功能一律不可观测。

**仍是真的覆盖缺口（不是探针问题）——已于 2026-11-09 随 overlay 退役消失**：`TIF_PROC_UMOUNTED` 只在 `setresuid` 那一刻打；若某个 app 进程在模块加载**之前**就完成 `setuid`，它终生不带标志，路径拦截对它失效（本 boot 的当前 app 进程启动于模块加载之后，故带标志）。退役后不存在需要拦截的挂载对象，这个缺口自然闭合——**同时也失去了 P1-2 提供的「`W` 侧文件入口」**，那正是入口收敛的代价。注意这仍不是结构性隔离：真正的结构性隔离得让 `W` 的挂载落在独立 mount namespace 里（由 restore 的 `kernel:s0` 自己 `unshare(CLONE_NEWNS)` 后建，且 `N` 的进程从不进入该 namespace）——那一步是独立的第 2 项，已落码、待 fresh boot 端到端验收（`docs/suvtz-v3-gap.md` §2.1/§2.3）。

### 4.2 入口收敛第 1 项：`/product/bin` overlay 退役（2026-11-09）

**判据来自 §2.2.3**：TrustZone 的唯一入口是**指令级**的（`smc #0`），在 Normal World 的命名空间里不占任何位置——没有文件、没有设备节点、没有 `/proc` 条目。所以「`W` 的入口是一个可被 `ls` 看到、可被 `execve` 直接调用的文件」本身就是与硬件结构不一致的设计。`/product/bin/su` 是这样一个文件入口，它带来两个代价而只换来一个便利：

| | 退役前 | 退役后 |
|---|---|---|
| 入口数量 | 2（overlay 里的 `/product/bin/su` 412B wrapper + sucompat 的 `/system/bin/su` 伪造） | **1**（只有 sucompat） |
| `shell` / `run-as` 可见性 | 可见（属主 root:root 0755，DAC 谁都能 exec） | **不可见**（对象不存在） |
| `untrusted_app` 可见性 | `ENOENT`（靠 `__lookup_mnt` + `TIF_PROC_UMOUNTED` 拦截） | `ENOENT`（**对象不存在**，不靠过滤） |
| 保证来源 | 进程标志（枚举/时序敏感） | **结构**（没有对象） |
| `W` 侧能力 | 有独立 `su` 文件（wrapper 可做鉴权/日志） | 无（鉴权/日志归 sucompat + `ksud`） |

**退役了什么**（`tools/postlock.sh` 与 app `assets/postlock/restore.sh` 两处同源改动）：

1. 原「建 `/product/bin` overlay」整块 → 换成**退役块**：先 `ksud susfs hide_sus_mnts_for_non_su_procs 0`（best-effort），再对 `/product/bin`、`$TMP/ovl/lower`、`$TMP/ovl/tmp` 做**多轮**（3 轮）`mountpoint -q` + 普通 `umount`（`umount -f` 兜底；toybox 0.8.4 无 `-l`），只有三处都不再是挂载点才 `rm -rf $TMP/ovl`，否则打 `WARN-suvtz-overlay-residual`。多轮是必需的：同 boot 重跑时 lower 上会叠两层 bind（实测）。
2. **删 P1-2 的 hide 段**：不再 `ksud susfs hide_sus_mnts_for_non_su_procs 1`。原因不只是「没有对象」——该开关让非 `ksu` 域（**包括 restore 自己的 `kernel:s0`**）看不到伪 id 挂载，于是同 boot 重跑时 `mountpoint -q` 判否，退役块会把 overlay **bind 到自己的 lower 上**（本 boot 实测到的叠层 bug）。
3. **删 DAC ovl 段**（原 `chmod`/`chcon` 那个 overlay 目录树）。
4. verify 段与所有 host 侧 root 通道：`/product/bin/su` → **`/system/bin/su`**。

**退役后实测影响面（boot `13b5a48a`，同一 boot 内手动执行 + 验证）**：

| 项 | 结果 |
|---|---|
| `/product/bin` | 回原厂 4 文件（`init.oplus.nandswap.sh` / `init.qti.display.sh` / `nandswap_tool` / `qvirtmgr`），**无 `su` / `ksud`** |
| `/data/local/tmp/ovl` | 不存在 |
| 三挂载点 | `mountpoint -q` 全 `not-mount` |
| root 通道 | shell 默认 `PATH` 与干净 `PATH` 均 `/system/bin/su -c id` → `uid=0 context=u:r:ksu:s0` |
| `mountinfo` | shell 与 `ksu` 域均无 `product/bin` 条目 |
| 管理器蓝卡 | 不受影响：root 域全扫确认管理器进程（pid 25450）**持有 `ksu_driver` fd**，`ksu_debug_manager_appid=10277` == `pm` 实读 uid |
| SUSFS | 九项 feature 全部仍列出（`ksud susfs show enabled_features`） |
| 扫描器 | `B4` FAIL\* → **PASS**；`B9`/`E2`/`E3`/`X3` 保持 PASS；`B5` 退役前后均 PASS |

**这不是结构性隔离**（重复强调，因为最容易在这里自我欺骗）：结构性隔离的定义是「对象属于另一个世界」——即 `W` 的挂载在 `N` 从不进入的 mount namespace 里。退役是「对象不存在于任何世界」。两者在 `N` 侧的观测结果相同（都看不到），但：

- 退役**失去**了 `W` 侧的对应能力（没有独立 `su` 文件，wrapper 的鉴权/日志点消失，这些职责回到 sucompat + `ksud`）；
- 结构性隔离**保留** `W` 侧能力（对象在 `W` 的 namespace 里正常存在、正常使用）；
- 所以退役是「以能力换纯净」，结构性隔离是「以工程换纯净」——前者可以立刻做且零风险，后者需要 restore 自己 `unshare`（`kernel:s0` 有 `CAP_SYS_ADMIN`，实测 `by=kernel`）+ stage 迁移 + bootstrap 重排（已落码，`docs/suvtz-v3-gap.md` §2.3/§6）。

**为什么不干脆把 overlay 迁进独立 namespace 而是删掉**：因为 `/product/bin` 这个挂载点的全部价值就是「让 `su` 出现在 `PATH` 里」。而 `PATH` 是 `N` 侧的概念——把它迁进 `W` 的 namespace 后，`N` 里的进程连 `PATH` 都走不到它，等价于删掉。真正需要 namespace 隔离的是**只由 `W` 消费的对象**（纯 restore 物料：`oplus_check_suppress.ko`、`pp_adb_tcp.bin`、`postlock_adbkey.pub`、`sep_enforce1.txt`）；链关键集（`preload.so`/`ksud`/`ksu_kaslr` 等）由 `shell:s0` 写读，进不了 `kernel:s0` 的 `W`，必须留 `N`（域墙实测，见 `docs/suvtz-v3-gap.md` §2.4）。

---

## 5. Tier 0：观测等价性

### 5.1 形式定义

§2.2 的命题需要一个可检验的落点。**「不可达」在 EL1 同特权级下无法自证**（§2.2.1），而「等价」可以拿 stock 状态做对照逐条比对——所以形式化落在等价性上：**句子用来配得上名字，公式用来接受检验。**

**注意等价性的地位**：它是**边界完整性的检验落点**，不是 SUVTZ 的定义。定义在 §2.2（两个执行世界 + 入口），实现在 §4.1（三层）。等价性回答的问题是「我们声称的边界有没有漏」，不回答「边界是不是结构性的」——后者要靠 §4.1 的归类与 §2.2.3 的入口清单。

定义观测表面

```
S = { s | s 是 untrusted_app 域可发起的系统调用/API 调用及其返回值 }
```

> **承诺范围声明**：本设计的 `S` 只枚举 `untrusted_app` 域，这是 §2.2 的 `D` 里我们**真正承诺**的那部分。`shell` / `system` / `runas_app` 域**不在 T0 承诺范围内**——能拿到 shell 已经意味着设备开了 adb 调试且用户授权，威胁模型从「普通 app 静默探测」升级为「开发者主动观测」。这一点必须写死，否则「覆盖」条件会永远无法闭合（shell 天然能 `perf_event_open`、能读 `/proc/modules`，这些面在 shell 域就是不可覆盖的）。
>
> 当前扫描器 `tools/suvtz/scan.sh` 的视角分级据此设计：`runas`（app uid + `runas_app` 域）视角的 `PASS` 是**必要条件而非充分条件**（SELinux 域不等价于 `untrusted_app`），脚本在输出里显式标注这一点；探针本身执行不了时一律记 `INFO`，绝不判 `PASS`。真正的 `untrusted_app` 域结论需由 app 自身代码复测（缺口见 P0 文档 §4）。

定义两个设备状态（前缀用 `Dev_`，字母 `D` 保留给 §2.2 的检测域，避免符号冲突）：

```
Dev_stock  = 未 root 的设备状态
Dev_rooted = 本项目的设备状态
```

**T0 的目标**：

```
∀ s ∈ S :  s(Dev_rooted) ≡ s(Dev_stock)
```

其中 `≡` 表示"检测方能观测到的一切属性相同"（值、类型、错误码、时间量级）。

检测方的判定函数 `detect: S → {rooted, clean}` 在 `≡` 成立时只能返回 `clean`。

**注意这个定义的好处**：它不要求"隐藏"，只要求"等价"。等价比隐藏更容易证明——我们可以拿一台 stock 设备（或 stock 状态）做对照，逐条比对。

### 5.2 三个完备性条件

等价性要成立，三个条件缺一不可：

| 条件 | 含义 | 失败模式（项目历史） |
|---|---|---|
| **覆盖（Coverage）** | S 中每个面要么等价、要么被证明不可观测 | 漏掉 `pm list packages` → 一条 grep 定性 |
| **一致（Consistency）** | 不同面的取值不能互相矛盾 | `/proc/modules` 隐藏了，但 `/sys/module/kernelsu` 还在——正是本项目 `moduleLoaded()` 踩过的坑（app 域读 `/proc/modules` 被拒 → 改 stat `/sys/module` 绕过，说明两个面不同步） |
| **持久（Persistence）** | 等价性在时间维度稳定 | 标记不持久，重启后失效；或 boot 后 5 分钟才生效 |

**"一致"是最容易翻车的一条**，因为观测面之间存在隐含的交叉验证关系。检测方的常见手法就是"用两个独立通道问同一个问题，看答案是否一致"。设计时必须成对考虑。

### 5.3 观测表面清单

按检测方的实际能力分 7 类。状态列：✅ 正常 / ❌ 泄漏 / ⚠️ 待测 / 🚫 不可覆盖。

> **时效声明**：以下 A/B/C/D/E 表是 2026-11-03（boot `5394a404`）的实测快照，包名与状态保留当时真值。其后有三处变化：① app 于 2026-11-07 合并为单应用 `com.postlock`（`com.postlock.boot` / `com.postlock.privateapp` 已不存在）；② **扫描器** `A1/A2/B4/D1` 于 2026-11-07 被显式裁决为「已接受暴露面」（`tools/suvtz/accepted.tsv`），**状态仍记 ❌，判定不变**——接受是威胁模型取舍，不是事实改变（注意：本表的设计项 `B4` 是 `/sdcard/chain*.log`，与扫描器 `B4` 不是同一项，见 §5.3.1）；③ **扫描器 `B4` 的定性于 2026-11-09 修正**：它跑在 `run-as`（`u:r:runas_app:s0`）视角，该域结构性不带 `TIF_PROC_UMOUNTED`（§4.1 易错点），因此它的 FAIL 是**探针方法论缺陷 + 承诺范围外**（§5.1），不是 `untrusted_app` 边界的缺口——真实 app 域实测 `/product/bin/su` `exists=0`。④ **同日 `/product/bin` overlay 退役**（§4.2）：`B3`（`/product/bin/su`）与 `E3`/`E4`（overlay 的 `mountinfo`/`mounts` 视图）因对象删除而闭合，扫描器 `B4` 实测转 PASS。可执行探针与编号以扫描器为准（§5.3.1）。

#### A. 包与进程（优先级最高：一条命令定性）

| # | 面 | 当前 | 覆盖手段 | 状态 |
|---|---|---|---|---|
| A1 | `pm list packages` → 管理器包 | `com.resukisu.resukisu` | 管理器内置 Hide（改包名重装，删原包） | ❌ |
| A2 | 同上 → 工具包 | `com.postlock.boot` | 改 `applicationId` 重编 | ❌ |
| A3 | 同上 → 私有包 | `com.postlock.privateapp` | 同上 | ❌ |
| A4 | `PackageManager.getPackageInfo` 反查 | 同 A1-A3 | 随 A1-A3 | ❌ |
| A5 | `ps -A` / `/proc/<pid>/cmdline` | ksud/su 短命进程 | 天然短命；长驻的 tailscaled 需改名 | ⚠️ |
| A6 | `dumpsys package <pkg>`（需 DUMP 权限） | 普通 app 无 | 无需处理 | ✅ |

> A1 是**官方方案零内核代码**（KernelSU 的 "Hide Manager App"），优先级最高、成本最低、收益最大。

#### B. 文件系统（SUS_PATH 覆盖）

| # | 面 | 当前 | 覆盖手段 | 状态 |
|---|---|---|---|---|
| B1 | `/data/local/tmp/ksu_boot/*` | **可读全套物料** | `add_sus_path` | ❌ |
| B2 | `/data/adb/ksu`、`/data/adb/modules` | app 域 DAC 拒（0700 root） | SUS_PATH 补强（防 shell/其他 uid） | ✅ |
| B3 | ~~`/product/bin/su`（overlay 上层）~~ **已退役（2026-11-09）** | — | 对象删除（入口收敛到 sucompat） | ✅ |
| B4 | `/sdcard/chain*.log` | 已清 | 纪律性清理 | ✅ |
| B5 | `/data/local/tmp/ksud`、`preload.so` | 同 B1 | 同 B1 | ❌ |

> SUS_PATH 语义：**属主 ≠ 当前 uid 才隐藏**，且进程须带 `TIF_PROC_UMOUNTED`（非 root app 天然带）。marker 不持久 → 每 boot restore 时重放。

#### C. 内核符号与模块（需要新代码）

| # | 面 | 当前 | 覆盖手段 | 状态 |
|---|---|---|---|---|
| C1 | `/proc/modules` | app 域 SELinux 拒 | 已天然隐藏（但 shell 可读） | ⚠️ |
| C2 | `/sys/module/kernelsu/` | **app 域可 stat/ls** | **需新增 kernfs hook**（`kernfs_iop_lookup` / `kernfs_fop_readdir` / `kernfs_dop_revalidate`，三符号离线已确认可 resolve） | ❌ |
| C3 | `/sys/module/oplus_check_suppress/` | 同上 | 同上 | ❌ |
| C4 | `/sys/module/kernelsu/parameters/ksu_debug_manager_appid` | app 域可读？ | 随 C2 | ❌ |
| C5 | `/proc/kallsyms` 的 `ksu_*` 符号名 | 待测 | SUFS `HIDE_KSU_SUSFS_SYMBOLS`（只挂 `s_show`） | ⚠️ |
| C6 | `/sys/kernel/tracing/kprobe_events` | app 域拒 | 无需处理 | ✅ |

> **一致性陷阱**：C1 已隐藏但 C2 没隐藏 → 检测方用 C2 就能定性。这正是项目 `moduleLoaded()` 的翻版，必须成对处理。

#### D. 系统属性（读路径不经内核，最难改）

| # | 面 | 当前 | 覆盖手段 | 状态 |
|---|---|---|---|---|
| D1 | `persist.adb.tcp.port` | **`5555`** | ①用完置空 ②SELinux policy 拒 app 读 | ❌ |
| D2 | `wrap.<pkg>`（LD_PRELOAD） | 当前空 | 不设置；若必须设，用完清除 | ✅ |
| D3 | `ro.debuggable` / `ro.secure` / `ro.build.type` | 正常 | 不动（真值） | ✅ |
| D4 | `ro.boot.verifiedbootstate` | green | 回锁后为真值，不伪造 | ✅ |
| D5 | `sys.oem_unlock_allowed` | 0 | 不动 | ✅ |

> **属性读不经内核**：属性区是 init 创建的 shared memory，进程 `mmap` 后直接读，无 syscall。能拦的只有 `mmap` 或 SELinux 的 `properties_*` class 权限。所以 D1 的正确解法是 ①（用完清）或改 policy，不是 hook。
>
> **不伪造属性**：D3/D4/D5 保持真值。回锁后 `verifiedbootstate` 本来就是 green——伪造反而会引入新的不一致（如 `ro.boot.flash.locked` 与 `verifiedbootstate` 打架）。

#### E. SELinux 与挂载

| # | 面 | 当前 | 覆盖手段 | 状态 |
|---|---|---|---|---|
| E1 | `/sys/fs/selinux/enforce` | `1`（严格） | 不降级（改了反而更可疑） | ✅ |
| E2 | `getenforce` | Enforcing | 同上 | ✅ |
| E3 | ~~`/proc/self/mountinfo` 里的 overlay~~ **已退役（2026-11-09）** | — | 对象删除 | ✅ |
| E4 | ~~`/proc/mounts` 中的 `tmpfs`（overlay upper）~~ **已退役（2026-11-09）** | — | 对象删除 | ✅ |

#### F. 行为侧信道（部分不可覆盖）

| # | 面 | 覆盖可能性 | 状态 |
|---|---|---|---|
| F1 | `su` 首次调用延迟（提权窗口） | 部分（预热） | ⚠️ |
| F2 | CPU 频率/功耗 | 🚫 | 🚫 |
| F3 | 链运行期的系统卡顿 | 🚫 | 🚫 |

#### G. 服务端证明（完全不可覆盖）

| # | 面 | 状态 |
|---|---|---|
| G1 | Play Integrity API | 🚫 |
| G2 | SafetyNet 后继 | 🚫 |
| G3 | 银行/反作弊私有风控 | 🚫 |
| G4 | 硬件序列号与设备指纹比对 | 🚫 |

#### X. 成对交叉验证（方法，不是新观测面）

单点探针的 PASS 可能来自「这条通道恰好被挡住」，而不是「对象真的不可见」。
所以每个可多路读取的事实用**两条独立通道**各测一次，要求同向：

| 组合 | 通道 A | 通道 B | 同向含义 |
|---|---|---|---|
| 模块面 | `grep -c kernelsu /proc/modules` | `ls /sys/module/kernelsu` | 两者都不可见 = 一致 |
| 符号面 | `grep -c -e ksu_ -e susfs_ /proc/kallsyms` | `grep -c kernelsu /proc/modules` | 同上 |
| 挂载视图 | `grep product/bin /proc/self/mountinfo` | `grep -c product/bin /proc/self/mounts` | 同上 |
| 物料目录 | `ls /data/local/tmp` | `ls /data/local/tmp/ksu_boot` | 同上 |
| 进程面 | `ps -A -o NAME` | 直接枚举 `/proc/*/comm` | 同上 |

判据：两通道同向 = PASS；**分歧 = FAIL**（存在未建模的读取路径，必须定案）；
任一侧测不出 = INFO。分歧是最有价值的信号——它比单项 FAIL 更能指出「哪条路
没堵住」。

#### 5.3.1 编号对照（**以扫描器为准**）

上面的 A/B/C/D/E 表是**设计意图清单**（写于 2026-11-03，含当时未验证的手段），
`tools/suvtz/scan.sh` 里的 ID 是**可执行探针**。两者编号已漂移，以扫描器为准；
下表给出对照，未列出者表示该设计项没有独立探针（原因见表后）。

| 设计项 | 扫描器 ID | 说明 |
|---|---|---|
| A1 管理器包 | A1 | 同义 |
| A2 工具包 / A3 私有包 | A2 | 合并为一条 `grep -i postlock` |
| A4 `getPackageInfo` 反查 | — | 需在 app 内跑，扫描器只测 `pm list` |
| A5 `ps`/`cmdline` | A4 + A5 + X5 | 拆成 ksud / tailscaled 两条，并加进程面双通道 |
| A6 `dumpsys package` | — | 普通 app 无 DUMP 权限，恒 ✅ |
| B1 `/data/local/tmp/ksu_boot` | B1 + X4 | 加物料目录双通道 |
| B2 `/data/adb/ksu` | B3 | `/data/adb` 整体测 |
| B3 `/product/bin/su` | B4 | 同义。**2026-11-09 对象已退役**（§4.2）：`B4` 探针保留作回归兜底，实测 `absent` → PASS |
| B4 `/sdcard/chain*.log` | — | 已清理，属纪律项不设探针 |
| B5 `/data/local/tmp/ksud`、`preload.so` | B2 + B7 | 目录可枚举 + 单文件可读 |
| — | B5 / B6 / B8 / B9 / B10 / B11 | 设计里没有的补充面（`/system/bin/su`、物料 ko、链日志、overlay upper、`ksu_kaslr`、`restore.sh`）。其中 `B9` 测的 `ovl/tmp/upper` 随 overlay 退役（§4.2）恒 `absent` → PASS |
| C1 `/proc/modules` | C3 + X1 | 同义 + 双通道 |
| C2 `/sys/module/kernelsu` | C1 + C5 | 同义（C5 测 `parameters` 子目录） |
| C3 `/sys/module/oplus_check_suppress` | C2 | 同义 |
| C4 `parameters/ksu_debug_manager_appid` | C5 | 同义 |
| C5 `/proc/kallsyms` 符号名 | C4 + X2 | 同义 + 双通道 |
| C6 `kprobe_events` | — | app 域天然拒，恒 ✅ |
| D1 `persist.adb.tcp.port` | D1 | 同义 |
| D2 `wrap.*` | D2 | 同义（扩展到任意 `wrap` 属性） |
| D3 `ro.debuggable`/`ro.secure`/`ro.build.type` | D3 + D4 | 拆两条 |
| D4 `verifiedbootstate` | D5 | 同义 |
| D5 `sys.oem_unlock_allowed` | D6 | 同义 |
| E1 `/sys/fs/selinux/enforce` | E1 | 同义 |
| E2 `getenforce` | — | 与 E1 同源（同一份 selinuxfs 值），不重复测 |
| E3 mountinfo overlay | E2 + X3 | 同义 + 双通道 |
| E4 mounts tmpfs upper | E3 + X3 | 同义 + 双通道 |

> 设计表里 C2/C3/C4/C5 的「覆盖手段」写着「需新增 kernfs hook」——**该结论已被
> P0 实测推翻**（见 `docs/suvtz-p0-baseline.md` §4.1：`/sys/module/*` 由
> `module_kobj` 的 sysfs 属性暴露，不在 kernfs 目录项层可控，且实际泄漏路径
> 是 DAC/SELinux 而非 kernfs）。表里保留原文只作历史记录，**不要照它去写代码**。

### 5.4 不可覆盖清单（写死在设计里）

1. **T1b / T2 对手**（§2.2.1 的 `Obs(W) ⊄ Trusted(W)`，§2.4）
2. **可用性**（重启 / 杀进程 / 资源耗尽，§2.2.2）
3. **G 类全部**（服务端证明）
4. **F2/F3**（物理侧信道）
5. **`shell` / `system` / `runas_app` 域的观测面**（§5.1 承诺范围声明）

> 一份安全设计如果不说"哪里防不住"，它就不是安全设计，是广告。

---

## 6. Tier 1：TEE 审计锚

### 6.1 TEE 能做什么、不能做什么

Android 12 设备上可用的硬件信任根是 **KeyMint（QTEE）**。它能给的是：

| 能力 | 有/无 | 说明 |
|---|---|---|
| 不可导出的 HMAC 密钥 | ✅ | key 绑定 uid + APK 签名，`getKey` 后无法读出明文 |
| 计算/验证 MAC | ✅ | `Mac.getInstance("HmacSHA256")` |
| 密钥使用需用户认证 | ✅ | `setUserAuthenticationRequired` |
| **存任意状态机** | ❌ | KeyMint 只做密码学算子，不是 KV 存储 |
| **证明调用者是"诚实内核"** | ❌ | 无法区分 |
| **防止内核杀掉调用者** | ❌ | DoS 不可防 |

**这就是为什么 T1 只能给"完整性/不可否认性"，不能给"机密性"或"可用性"。**

### 6.2 三个前提实验（不做完不立项）

| # | 实验 | 判据 | 失败后果 |
|---|---|---|---|
| E1 | 在管理器进程（`untrusted_app`）里创建 HMAC key 并签名 | `KeyStore.containsAlias` + `Mac.doFinal` 成功 | T1 整体不可行 |
| E2 | 该 key 在 **`Enforcing`** 下可用（不需降级 SELinux） | 同上，`getenforce=1` | 需回到"降级换可用"，T1 价值打折 |
| E3 | key 不可被其他 uid 使用 | 另一 uid 调用 `getKey` 抛 `KeyStoreException` | 证明信任根绑定成立 |

E1/E2/E3 都**不需要 root、不需要重启**，可以立即用现有 APK 加一段测试代码验证。

### 6.3 协议（T1a 下成立的形态）

```
用户意图（在管理器 UI 里"授权 uid X"）
   ↓
Gate(app uid, 持 keystore 会话)
   ticket = HMAC(K, uid || pkg_sig || boot_id || nonce || exp)
   ↓ 窄通道
Keeper(root, ksu 域)
   校验 ticket（无 K）→ 向 Gate 提交 ticket，Gate 用 TEE 验 MAC
   ↓ 通过
执行 su
```

**可证明的保证**：任何一次提权都可以在事后被审计——"这次提权有 Gate 签发的 ticket"，而 ticket 的 MAC 只有 TEE 能算。内核无法凭空捏造一张 ticket。

**不可证明的部分**：内核可以无视 ticket 直接放行，或干脆不执行。所以 **这是审计，不是强制**。

### 6.4 T1 的真实收益

| 场景 | T0 | T1a |
|---|---|---|
| 用户被恶意 app 骗授权 | 无法事后证明 | ✅ 可证明"这次授权是用户签的" |
| 内核被只读攻破 | 无法察觉 | ✅ 篡改策略会破坏 MAC |
| 内核完全被控 | 无 | 无 |
| 对检测方隐藏 | 相同 | 相同（无增量） |

**所以 T1 的产品价值是"可归因"，不是"更难被攻破"**。这一点在设计里必须说清楚，否则就是又一次谎报。

---

## 7. Tier 2：为什么不可达

| 路径 | 需要什么 | 本设备状态 |
|---|---|---|
| EL2 stage-2（VTTBR_EL2） | 内核在 EL1、hypervisor 在 EL2 | ❌ VHE 已开，内核在 EL2，stage-2 闲置；启用它只能隔离 EL0，而 EL0 之间的隔离 Android 已有 |
| Secure EL2 | Armv8.4 + EL3 配置 | ❌ SM6375 是 Armv8.2 |
| RME（Realm） | Armv9 | ❌ |
| Secure World 自建 TA | 厂商签名 key | ❌ 闭源 ATF + 无 OEM key |
| `memfd_secret()` | Linux 5.14+ | ❌ 本内核 5.4；且它本身不防有 `struct page` 的内核代码 |

**结论**：T2 需要 "boot.img 自由 + 硬件支持 + 厂商密钥"，三者当前一个都没有。

---

## 8. 实施路线

> **本表已被 P0 实测取代**（2026-11-03 第二轮 30 探针基线，见
> [`suvtz-p0-baseline.md`](suvtz-p0-baseline.md) §4/§5）。下表保留为设计期原案，
> 现行路线以 P0 文档的 **P1-1 ~ P1-4** 为准。

| 阶段 | 内容 | 内核代码 | 依赖 | 预估 | 现状态 |
|---|---|---|---|---|---|
| **P0** | 观测面扫描器：7 类清单固化为可执行探针，输出 `PASS/FAIL/INFO`，建 stock 基线对照 | 零 | 无 | 1 天 | ✅ 已完成（`tools/suvtz/scan.sh`，30 探针） |
| **P1a** | 包面：管理器 Hide + 工具改名 | 零 | APK | 0.5 天 | ⏸ 待裁决（A1 上游 `applicationId` 不能换；A2 与「工具包可见」冲突） |
| **P1b** | 物料面：SUS_PATH 标记（B1/B3/B5），restore 内重放 | 零 | 现有 SUSFS | 0.5 天 | ❌ 路线作废：真根因是 DAC `0777`，`chmod` 即可；`SUS_PATH` 会把管理器一起隐藏 |
| **P1c** | 模块面：`susfs_kernfs.c`（C2/C3/C4），三 hook 成对处理 | ~90 行 | 需重编 ko + 重启 | 1 天 | ❌ 路线作废：`/sys/module`、`/proc/modules`、`/proc/kallsyms` 对 app 域本来全 `Permission denied`，这段代码不需要写 |
| **P1d** | 属性面：D1 使用后清理 + policy 收紧 | 零 | 需验证 | 0.5 天 | ⏸ 待裁决（D1 通道 bootstrap 依赖） |
| **P2** | 探针全量接入 P0 的扫描器，每 boot 自跑，结果落盘 | 零 | P1 | 0.5 天 | ⚠ 部分落地（2026-11-07）：**每 boot 自跑已挂在 `tools/postlock.sh` 尾部**（旁路、WARN-only、`SUVTZ_SCAN=0` 关闭、台账 `history.tsv`）；「app 自身代码自跑同一套探针」随 PostLock-Boot 冻结而未做，判据仍是 `runas_app` 近似 |
| **P3** | TEE 三实验（E1/E2/E3）→ 过了才做 T1 | 零 | APK 测试代码 | 0.5 天 | 未开始 |
| **P1-5** | **入口收敛第 1 项：退役 `/product/bin` overlay**（§4.2）——`su` 入口从「overlay 文件 + sucompat 伪造」双路径收敛为 sucompat 单点 | 零 | 无 | 0.5 天 | ✅ 已完成（2026-11-09）：`tools/postlock.sh` + app `assets/postlock/restore.sh` 同源改动，退役块设备端 no-op 实测通过，本 boot 手动执行影响面全通 |
| **P1-6** | **结构性隔离第 1 项：`W` 独立 mount namespace**（`docs/suvtz-v3-gap.md` §2.3）——restore 在 `kernel:s0` 起 holder（`unshare(CLONE_NEWNS)` + `MS_REC\|MS_PRIVATE` + 自有 tmpfs），`N` 侧路径不存在 | 零（helper `tools/wns` 419776B） | 无 | 1 天 | 🟡 已落码（2026-11-09，`3150d75f` + 扫描器 `08cdacc6`）：真机原语 + 扫描器三态（无 holder / 有 holder / W4 门控失败）已验，**fresh boot 端到端验收待跑**；物料迁入 `/w/stage` 未开工（域墙约束，§2.4） |

**P0 必须先行**：没有基线，"修好了"和"本来就正常"分不清。这也是项目历史上多次"假绿"的根源（verify 被上一轮遗留撑绿）。

### P1c 的接口决策（历史记录，路线已作废）

> **2026-11-03 实测推翻**：app 域 `ls /sys/module`、读 `/proc/modules`、
> 读 `/proc/kallsyms` 全部被 SELinux 拒（`kernfs` `read` 与 proc 权限），
> 模块面对普通 app 本来就是不可达的（T2）。**`susfs_kernfs.c` 不需要写**；
> 只有当检测方换到 `shell`/`system` 域时才需要，而那已不在「普通 app」
> 威胁模型里。以下为设计期原案，仅作记录。

`/sys/module` 隐藏**不在标准 SUSFS 的 9 个 feature 位里**（本 ABI 无 module hiding）。所以：

- **不新增 `CONFIG_KSU_SUSFS_*` 宏**（否则 `show enabled_features` 会多报一个不存在的标准功能 = 谎报）
- 新增**私有命令** `CMD_SUVTZ_MODULE_VEIL`（自行分配的 magic，不与 SUSFS 命令段冲突）
- 文档与 UI 里明确标注"SUVTZ 扩展，非标准 SUSFS 功能"

---

## 9. 验收定义

**先明确这一节在验收什么**：验收的是「**边界完整性**」——`N` 到 `W` 的每条路径都被识别、归类、给出结论；**不是**「世界隔离已成立」。前者是审计，后者是架构事实。把审计结论当架构事实汇报，就是本项目此前把判据层当成果的偏差（§4.1 末段）。

一个阶段算"做到"，必须同时满足：

| 判据 | 内容 |
|---|---|
| 覆盖率 | 该阶段清单内的面 **100%** 有结论（PASS 或 INFO，不允许"没测"） |
| 一致性 | 成对的面（C1/C2、B1/B5、A1/A4）**结论相同** |
| 持久性 | 重启后再测，结论不变 |
| 诚实性 | INFO 不得被写成 PASS；不可覆盖项必须出现在输出里 |
| 范围 | 结论必须标注观测域；`shell` / `runas_app` 视角的结果不得冒充 `untrusted_app` 结论（§5.1） |
| 回归 | 上一阶段的探针**仍全 PASS** |
| **边界归类** | 每个探针必须能回答「它属于结构性隔离、过滤层、还是入口」三者之一（§4.1）。靠过滤层兜底的项必须登记为已知缺口，**不得计入「已隔离」** |
| **入口收敛** | 该阶段结束时，`N` 到 `W` 的跨界动作必须能列出**完整**的入口清单，且每个入口有鉴权判定与记录点；出现未登记的新 magic = 该阶段不算做到（§2.2.3） |

**为什么加后两条**：前六条只能保证「我们测过的面等价」，不能保证「我们没漏的面不存在」。边界归类把「等价」翻译成「这一项是靠结构还是靠过滤」，入口收敛把「单点」从口号变成清单——两者都是 T0 里唯一可检验的架构性判据。

---

## 附录 A：v1 → v3 逐条对照

| v1 主张 | v3 判定 |
|---|---|
| §3 预留物理页隔离授权表 | 证伪（`iomem_resource` + `vmap`） |
| §4 token 能力不可转移 | 证伪（无 PID/UID 绑定） |
| §5 凭证伪装 | 证伪（ptrace + `attr/current`） |
| §6 MAC 完整性 | **保留并升级**：变成 T1 的 TEE 审计锚 |
| §7 声称 SUSFS 有 module hiding | **事实性错误**：`HIDE_KSU_SUSFS_SYMBOLS` 只挂 `kallsyms` 的 `s_show`，不隐藏 `/sys/module` |
| 全篇未提 SELinux 域切换 | 已补：域是观测面的一部分 |

## 附录 B：v2 → v3 的差异

| 维度 | v2 | v3 |
|---|---|---|
| 定义 | 隐藏 + 探针 | **Virtual TrustZone**：两个执行世界 + 入口收敛 + 边界完整性审计（形式化落在观测等价，§5.1） |
| 信任根 | 无 | 分层：T0 无 / T1 TEE / T2 硬件 |
| 攻击者模型 | 隐含"用户态" | 显式 T0/T1a/T1b/T2 |
| 边界坐标 | 隐含"特权级"（照抄 TrustZone） | 域 + 所有权（§2.2.1），并拆分观测/影响（§2.2.2） |
| 隔离手段 | 未区分 | 三层：结构性隔离 / 过滤层 / 入口审计（§4.1） |
| 单点入口来源 | 未提 | 枚举而非硬件（§2.2.3），并标注当前未收敛 |
| 清单 | 14 项探针 | 7 类 33 项设计清单，落地为 35 项可执行探针（30 单点 + 5 成对），含实测状态 |
| 不可覆盖清单 | 无 | 有（§5.4 + §2.4） |
| 名字正当性论证 | 无 | §2 |

## 附录 C：本设计不再做的事

- 不声称内核内存隔离
- 不伪造系统属性（`ro.debuggable` / `verifiedbootstate` / `oem_unlock_allowed` 保持真值）
- 不把 TEE 说成"Secure World"（它只是 MAC 算子）
- 不用 INFO 冒充 PASS
- **不把"出口过滤"叫"世界隔离"**（§2.2 对比表：数据在、过滤在 ≠ 数据不在这个世界）
- **不把扫描器的 `PASS` 当作"隔离已成立"**——扫描器验收的是边界完整性，不是架构事实（§9）
