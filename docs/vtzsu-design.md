# VtzSU 设计（NL-2）

> **定位**：把 SUVTZ 的「双世界」结构用在 SU 本身上，而不是继续在 SU 外面叠检测层。
> **前置**：`docs/suvtz-v3-definition.md`（NL-1，SUVTZ 的判定标准）、
> `docs/suvtz-v3-design.md`（DL-1，论证）。
> **关系**：SUVTZ 定义「一个世界怎么算成立」；VtzSU 定义「一个 SU 怎么建在这个世界上」。
> **状态**：设计为主。**V0a 代码已落地并设备冒烟（2026-11-11，boot `59eeb053`）**——
> 冒烟证实的是 §7 的第 1–5 行（会话真在 W、W 侧记录产生、N 侧 `ENOENT`），
> 第 6–8 行与 D4/D5 状态仍待正式轮。**冒烟 ≠ 判据全绿**：本文只有明确标注
> boot 号的行才算实测，其余仍是设计口径。

---

## 0 一句话

> VtzSU 把「root 会话」从 **N 里一个 uid=0 的进程**，改造成 **W 里的一个进程；
> N 只能通过协议与它交互，不能观测它的内部**。

---

## 1 为什么需要它：现有 SU 的结构缺口

当前 SU 的形态（实测证据取自 boot `13b5a48a` / `59eeb053`）：

| 事实 | 证据 |
|---|---|
| SU 会话 = uid 0 + `u:r:ksu:s0` | `su -c id` → `uid=0 … context=u:r:ksu:s0` |
| 会话的 mount ns = **调用者的** ns | `ksud/src/android/su.rs` `root_shell()` 只在 `-M` 时 `switch_mnt_ns(1)`，默认不动 |
| W 存在，但只被 restore 消费 | `tools/postlock.sh`：`wns hold $TMP/.w`，消费者是 restore 自己的 copy/cksum |

⇒ **W 与 SU 是两个不相交的东西。**

W 是一个私有 mount namespace（holder 持有，`$TMP/.w` 下 tmpfs）；
SU 是一个 uid 0 的进程。两者从不重合。app 拿到 root 之后，**仍然是 N 的居民**，
只是权限等级从 10xxx 变成 0。

这正是 NL-1 §2.2.1 那条结论的直接体现：**权限等级不是世界边界**。
在 N 里把 uid 变成 0，等于在同一个世界里换了一件更高的制服，
而不是搬到了另一个世界。N 侧的检测域依然能：

- 通过 `/proc/<pid>/{maps,fd,mountinfo,cgroup}` 观测这个进程的一切；
- 通过 `kill`、`ptrace`（若 SELinux 允许）、写它的 `/proc/<pid>/mem` 影响它；
- 在它 `exec` 之前/之后注入。

**这就是 VtzSU 要修的东西，且是唯一要修的东西。**

---

## 2 定义

沿用 NL-1 的四元组 `(W, N, E, M)`，把「SU 会话」定为 W 的成员：

| 条款 | VtzSU 的表述 |
|---|---|
| **D1′ 双世界** | 存在 W（私有 mount ns + 私有文件树）与 N（其余一切）。SU 会话 ∈ W。 |
| **D2′ 世界标记** | `proc ∈ W ⟺ mnt_ns_inode(proc) == mnt_ns_inode(W)` |
| **D3′ 隔离** | W 的客体在 N 里无路径（`ENOENT`，非 `EACCES`） |
| **D4′ 唯一入口** | 「把进程放进 W」只有一个代码点 + 一张准入表 |
| **D5′ 入口监控** | 每次进入在 W 侧留一条记录；N 侧无路径可读写它 |

### 2.1 标记为什么必须换成 ns inode

NL-1 的 D2 允许任意「不可伪造的世界标记」。SUVTZ 现在用的是 `TIF_PROC_UMOUNTED`
（内核在 `setresuid` 那一刻打上）。它有一个已记录的结构性缺陷：

- `run-as`（`u:r:runas_app:s0`）**不带**这个标记 → 在它看来 SUSFS 的隐藏对象全部可见；
- 于是 SUVTZ 的 B4 探针（app 域 `/product/bin/su` 是否存在）在 run-as 视角下永远是
  `exists=1`，只能靠「真实 app 域」取证，扫描器无法自证。

换成 **mount namespace inode** 之后：

- 归属由内核记账（`nsproxy->mnt_ns` 指针），任何进程不可自报、不可伪造；
- `run-as` 不在 W 的 ns 里 → **它就不是 W 成员**。这不是缺陷，是**正确判定**；
- 标记的判定成本 = 一次 `readlink` / 一次 `stat`，无需特权。

**NL-1 的 B4 难题在这里自然消失，不需要额外机制。**

### 2.2 单点性

「进入 W」的物理动作只有一个：`setns(fd_of_mnt_ns, CLONE_NEWNS)`。
它需要一个 fd 指向 W 的 mnt ns，而该 fd 只能来自 `/proc/<holder>/ns/mnt`。
holder 的 pid 是 W 的唯一句柄 → **入口的可达性天然收敛到一个 pid**。

剩下的工作是把「谁能拿这个 pid 去 setns」收敛到一个代码点（见 §4 L2）。

---

## 3 架构

三层，与 NL-1 的 D1~D5 一一对应。

### L1 世界层（W 的存在）

| 项 | 内容 | 状态 |
|---|---|---|
| holder | `wns hold $TMP/.w`：`unshare(CLONE_NEWNS)` → `mount / MS_REC\|MS_PRIVATE` → tmpfs | **已有**（Phase B） |
| 内容 | `stage/ log/ state/` + tmpfs 根（`mode=0700`） | **已有** |
| 生命周期 | per-boot（reboot 即消失，ns 无持久化） | 已知，见 §5.1 |
| 持有域 | `u:r:kernel:s0` 直起优先，`su -c`（ksu 域）回落 | **已有** |

### L2 入口层（E 的唯一性）

**现状**：`wns run <pid> <cmd>` 是用户态工具，任何能执行它的进程都能进 W。
`u:r:ksu:s0` 域可以，`u:r:kernel:s0` 域可以——**没有准入检查**。这不满足 D4。

**V0（用户态收敛，不改内核）**：

```
ksud root_shell()
  ├─ -M / --mount-master  → switch_mnt_ns(1)      （显式要求：进 init ns，覆盖默认）
  ├─ --vtz                → vtz_enter()           （V0a：显式请求）
  ├─ 默认（V0b 之后）      → vtz_enter()           （默认进 W）
  └─ --no-vtz             → 不动                  （逃生口，V0b 之后才有意义）
```

**先 V0a 后 V0b，不直接翻默认**：`root_shell()` 是**所有** app/管理器的 root 会话
的唯一通道，默认进 W 一旦与某个场景（§5.1 的快照视图、`/data/local/tmp` 同名目录、
cgroup/ns 相关工具）冲突，爆炸半径是全量 root 而不是单一功能。所以先用显式开关
把「在 W 里跑 root」这件事验证透（判据见 §7），再决定是否翻默认。

D1 的表述随之分档：V0a 成立 = **「存在一条能把 root 会话放进 W 的路径」**；
V0b 成立 = **「root 会话默认在 W 里」**。前者不蕴含后者。

`vtz_enter()`：

1. 读 sidecar `/data/local/tmp/vtz_w.pid`，格式 `<pid> <mnt_ns_inode>`；
2. 校验 `/proc/<pid>/ns/mnt` 存在，且其 inode == 记录的 inode（防 pid 复用）；
3. 校验它 != `/proc/self/ns/mnt`（已经在 W 里就不重复 setns）；
4. `switch_mnt_ns(pid)`（复用现有函数，它已经是 `open` + `setns` + `chdir("/")`）；
5. 在 W 侧写一条 access 记录（L3）。

sidecar 由 restore 在 holder 起来后写（N 侧，`0644`；ksud 在 ksu 域读，无 MAC 障碍）。

**为什么这一版能叫「收敛」**：入口从「任何进程 + 一个通用工具」变成
「`ksud root_shell()` 里一个分支」，准入条件 = ksud 已经通过内核 supercall 校验过的
allowlist。`wns` 仍然存在（restore 自用），但它不再是第一公民入口。

**V1（内核收敛）** 见 §6。

### L3 监控层（M 的记录）

进入 W 之后、`exec` shell 之前，向 **W 侧**写一行：

```
<epoch> uid=<u> pid=<p> ns=<inode> op=enter result=ok
```

写到 `$WMP/log/access.log`，即 `/data/local/tmp/.w/log/access.log`。

**这一条的物理意义**：在 N 里，`/data/local/tmp/.w` 是一个**空目录**
（tmpfs 挂在 W 的 ns 里，N 的 ns 里没有这个 mount）。
所以 N 侧写不进、读不到、删不掉这三件事同时成立。

这就是 NL-1 里 D5 的 **T0 上限**：

- ✅ 记录由 W 侧产生，N 侧不可篡改（D5 的完整性一半成立）；
- ❌ N 侧也无法**验证**记录没被动过——验证需要 T1a（TEE 背书的密钥 / 计数器），
  不属 T0。所以 VtzSU 的 D5 只能是「弱成立」，与 SUVTZ 的当前定性一致。

**为什么不用 printk**：printk 是事后日志，拒绝发生时它不能阻断任何东西；
而且 N 侧（有 `dmesg` 权限的域）读得到、也能刷。W 侧文件满足「N 不可读写」。

---

### 3.1 V0a 实现清单（代码已落地；哪几条冒烟过了见下）

| 位置 | 内容 |
|---|---|
| `../BakaSU/userspace/ksud/src/android/su.rs` | `opts.optflag("", "vtz", …)`；`let vtz = matches.opt_present("vtz")`；`if mount_master { … } else if vtz { vtz_enter()? }`（失败即**硬错误**，不回落 N）；`vtz_enter()` + `ns_inode(pid)` |
| `tools/postlock.sh`（restore heredoc，holder 段） | 写完 `suvtz-w: holder pid=…` 后写 `/data/local/tmp/vtz_w.pid` = `<pid> <ns_inode>`，`chmod 644`；holder 缺失时 `rm -f` 该 sidecar（保证错误文案是「没有 W」而不是「W 掉了」）；ns 读不出数字时 `WARN-suvtz-w-sidecar-no-ns` |
| `build/embed/ksud` | 换成本版（`sha1 bbc7afcd…`），stage push 清单已含 |
| `tools/postlock.sh`（ksud 供给） | `/data/adb/ksud` 由「不存在才装」改为「sha1 不同即装」：cp 到 `.tmp` + `chmod 755` + 原子 `mv`（运行中的 exec 留在旧 inode，不打断管理器）；相同只记 `unchanged`；失败仅 WARN 保留旧二进制 —— 因为 `su --vtz` 只在本仓构建里存在，管理器那份 release 会让入口静默失效 |
| app assets | `assets/postlock/ksud` 同步同 sha1 + `restore.sh` 重新生成（`tools/gen_app_restore.sh`）+ `PAYLOAD_VERSION` bump |

**失败语义**（为什么必须硬失败）：sidecar 缺失 / pid ≤ 1 / ns inode 不匹配 /
`setns` 被拒 —— 任一命中都直接退出。**静默回落 N 会让「我以为在 W 里」成为
一个不可观测的假象**，而这恰好是本设计要消灭的东西。

**两条前置假设 → 已实测成立（boot `59eeb053`，2026-11-11）**：

1. `switch_mnt_ns(holder)` 在 `root_shell()` 的 `u:r:ksu:s0` 路径上可复现
   —— 实测 `su --vtz -c 'readlink /proc/self/ns/mnt'` = `mnt:[4026534152]`
   = holder 的 ns；对照 `su -c` 同一时刻 = `mnt:[4026533362]`（N）。同 uid、
   同域，唯一差异是 `--vtz`。
2. `u:r:ksu:s0` 能写 holder 的 tmpfs（`mode=0700` 且**没有** `context=` 选项，
   inode 标签由 tmpfs 默认策略决定）—— 实测 W 侧 `log/access.log` 正常追加
   `kind=enter`；把 `log/` 删空后再跑 `su --vtz`，`create_dir_all` 重建目录并
   写入成功，而同一时刻 N 侧 `ls .w/log/access.log` 仍是
   `No such file or directory`。

> 第 2 条只证明「写得进去」，**不证明「只有 W 写得进去」**——后者要靠内核侧
> 收敛（V1）与 T1a，本阶段不承诺。

---

| 条款 | V0 状态 | 成立的依据 | 仍然缺的 |
|---|---|---|---|
| D1′ 双世界 | ✅（`--vtz` 会话进 W） | 实测：会话与 holder 同一个 ns inode（boot `59eeb053`） | 默认仍 N（V0b 才翻） |
| D2′ 世界标记 | ✅ | ns inode 相等性，内核记账不可伪造 | — |
| D3′ 隔离 | ✅（单向） | 实测：W 的 tmpfs 在 N 里无路径（`ENOENT`），W 侧写入后 N 侧仍 `ENOENT` | 反向不隔离（见 §5.1） |
| D4′ 唯一入口 | ⚠️ 弱成立 | 收敛到 `ksud` 单点 + allowlist | `wns` 仍是通用工具；内核 supercall 未收敛（V1） |
| D5′ 入口监控 | ⚠️ 弱成立 | W 侧文件，N 不可读写（实测：W 可写 + N 侧不可见） | N 侧不可验证（需 T1a）；「只有 W 能写」未证 |

> D1′/D3′ 的「实测」**只覆盖 §7 第 1–5 行**在 boot `59eeb053` 跑过的部分；
> 第 6–8 行（功能未退化 / `-M` 优先级 / SUVTZ 回归）尚未跑，
> 因此不得据此把等级从 T0 往上抬。

**判定顺序**（NL-1 §4）：先 D3 → 再 D4 → 最后 D5。
V0 在 D3 上是**结构性**的（不是过滤层），所以即使 D4/D5 弱，这个体系的等级
也不会掉回 T0 以下——它只是**停在 T0**。

---

## 5 四条硬取舍（诚实清单）

### 5.1 W 的挂载视图是**快照**，不跟随 N 的运行期挂载

mount namespace 是**创建时刻的副本**。holder 在 restore 期（boot 后约 2–4 分钟）建立时，
`/system`、`/product`、`/vendor`、`/apex`、`/data` 都已挂好，所以 W 里能看到完整文件系统。

但**之后**新挂上去的东西（应用运行期 mount、某些模块的 overlay、SUSFS 的 sus_mount）
**不会传播进 W**。

后果：W 里的 root shell 可能在极少数场景下看不到某个后期挂载。
缓解：`-M` 指定进 init ns（放弃世界隔离，换回完整视图）；或重建 W。

**这是用真实边界换来的代价，不是缺陷。** 写在这里是为了避免将来把它当 bug 追。

### 5.2 不做 pid ns

pid ns 会让 W 里的进程看不到 N 的进程——听起来更「世界」，但会破坏几乎所有
root 工具（`ps`、`kill`、`top`、崩溃排查）。收益远小于代价。

⇒ **D3 只承诺文件树 / 挂载面，不承诺进程面。** W 里的进程能看到 N 的进程列表，
这一点在文档里必须写明，不能让读者以为 VtzSU 是一个完整的沙箱。

### 5.3 不做 T1（信任根不升级）

T0 = 信任根是内核 EL1。T1a = TEE。T1b = 独立的更高特权级。
本设备的硬件信任根（QCOM TEE）没有可编程接口给第三方用，
所以 **VtzSU 的上限就是 T0**，D5 不可验证、D4 只到「无内核外的入口」。

这与 NL-1 §5 的等级表完全一致：**VtzSU 不试图把自己说成 T1**。

### 5.4 用户原句的括号

用户的原句是：

> 存在一个世界 W，Normal World 里的任何代码（**不包括最高特权级**）都无法观测或影响 W…

这个括号在本设备上是**不成立的**：

- EL1 里有与 W 敌对的部分（OPPO 的 `oplus_root_check_succ`、`kevent_send_to_user`）；
- 它们与 W 的守卫**同特权级**，只能用同特权级的对抗手段压制（ocsk 的 kprobe 改写），
  而不能承诺「无法观测或影响」。

所以 VtzSU 承诺的对象必须显式收窄：

> ∃ W，使得 ∀ d ∈ **D ⊆ N**（N 的检测域），d 无法观测或影响 W，
> 除非经过一个固定的、受监控的入口。

EL1 里敌对的部分用 ocsk 压制，**列为已知风险面，不列进「不可达」承诺**。
这就是 NL-1 §2.2.1「边界不按特权级划」的实际含义。

---

## 6 实施阶段

| 阶段 | 内容 | 改了哪里 | D4 状态 |
|---|---|---|---|
| **V0a** | `--vtz` 显式进 W；W 侧写 access 记录；`-M` 覆盖 | `ksud/src/android/su.rs`（约 30 行）+ `tools/postlock.sh` 写 sidecar（约 10 行） | 弱（`wns` 仍在） |
| **V0b** | 翻默认（`--no-vtz` 逃生口） | 同上，改一处分支 | 弱 |
| **V1** | 内核 supercall 新增 `VTZ_REGISTER_W` / `VTZ_ENTER`；legacy 入口转发或关闭 | `../BakaSU/kernel/supercall/{dispatch.c,supercall.c}` | 强 |
| **V2** | W 侧 ring buffer（而非追加文件）+ N 侧只读快照 | `../BakaSU/kernel` + `tools/` | 强 |

### V0 是最小可行切片

它只回答一个问题：**「在 W 里跑一个 root shell」这件事成立吗？**

成立之后，D1/D2/D3 在 SU 层面就有实证；D4/D5 的强化才有意义。
不成立（比如 ksu 域进不去 holder 的 ns），整个 VtzSU 都要重做——
所以先做这一刀。而这一刀本身分两步（V0a 开关 → V0b 默认），理由见 §3 的 L2。

**V0 的确切改动点（已核对源码，非推测）**：

- `su.rs::root_shell()` 的 `getopts` 选项表加 `opts.optflag("", "vtz", "...")`；
  该表已支持长选项（`--ksu-no-new-privs`），无需改解析逻辑。
- `-c` 的预处理块只在「`-c` 之前有自由参数」时才重排；`su --vtz -c 'cmd'`
  三个 token 都不命中重排条件 → `--vtz` 原样到达 `getopts`（已逐条件核对）。
- `if mount_master { utils::switch_mnt_ns(1) }`（`su.rs` :345 附近）之后加
  `else if vtz { vtz_enter()? }`；V0b 改为 `else { vtz_enter()? }` 并新增
  `--no-vtz` 逃生口。
- `vtz_enter()` 直接复用 `utils::switch_mnt_ns(pid)`——它已经是
  `open("/proc/<pid>/ns/mnt")` + `setns` + `chdir` 回原目录，**不需要新写系统调用**。

**V0 提到的 3 个未经实测的假设**：

1. ksu 域进程 `setns` 到 `u:r:kernel:s0` holder 的 mnt ns 成功
   —— SUVTZ Phase B 已实测「ksu→kernel holder ns 可进」，但那是 `wns run`
   在 ksu 域里跑；ksud 内部 `switch_mnt_ns` 是同一系统调用，预期一致，**需复验**。
2. 会话进 W 后，`/system/bin/sh` 仍可执行（W 的 ns 里 `/system` 存在）——预期成立。
3. 进 W 不破坏 libsu 的会话语义（app 只看到 stdin/stdout/stderr）——预期成立。

### V1 的三个内核假设（未验证）

1. `switch_task_namespaces()` / `nsproxy` 在 5.4 可解析（有 `compat/unexported_shim.c`
   的 kallsyms 机制兜底）。
2. supercall 上下文改当前进程的 nsproxy 安全（无锁竞争）。
3. W 的 `struct mnt_namespace *` 可由 restore 通过 `/proc/<holder>/ns/mnt` 的 fd
   传入内核并长期持有（需要 `get_mnt_ns()`）。

---

## 7 V0 的可验证判据

一次冷 boot + `tools/postlock.sh` 之后：

| 判据 | 期望 | 取法 | 状态（boot `59eeb053`） |
|---|---|---|---|
| sidecar 存在 | `<pid> <inode>`，且 `/proc/<pid>/ns/mnt` 的 inode 与之相等 | `cat /data/local/tmp/vtz_w.pid` | ✅ 实测 `26603 4026534152`，holder ns 同值 |
| 会话在 W 里 | `su --vtz -c 'readlink /proc/self/ns/mnt'` == `readlink /proc/<holder>/ns/mnt` | 两次 `readlink` | ✅ 实测两边 `mnt:[4026534152]` |
| 对照：不带开关仍在 N | `su -c 'readlink /proc/self/ns/mnt'` **不相等**（V0a 阶段这是正确结果） | 同上 | ✅ 实测 `mnt:[4026533362]` ≠ W |
| W 侧记录产生 | `su --vtz -c 'cat /data/local/tmp/.w/log/access.log'` 有本次行 | 该路径在 W 里可见、在 N 里不可见 | ✅ 实测追加 `kind=enter`；删空 `log/` 后自动重建再写 |
| N 侧不可见 | **N 侧**（shell 域）`ls /data/local/tmp/.w/log` → `ENOENT` | shell 域执行 | ✅ 实测 `No such file or directory`（W 侧写入后仍如此） |
| 功能未退化 | `su --vtz -c 'ls /system /data /apex'` 正常 | — | ⬜ 未跑 |
| `-M` 优先级 | `su -M --vtz -c …` 走 init ns（`-M` 覆盖） | 对照 | ⬜ 未跑 |
| SUVTZ 回归 | 扫描器仍 `FAIL=0（已接受 3）PASS=37 INFO=0` | `tools/suvtz/scan.sh -q` | ⬜ 未跑（上次口径见 Phase C 轮） |

**判定口径**：V0a 成立 = 前 7 行全绿。第 8 行是回归门。
V0b（翻默认）之后再补一条：不带开关的 `su -c` 也读到 W 的 ns inode。

> **2026-11-11 冒烟只跑了第 1–5 行**（人工逐条，非脚本），第 6–8 行留待
> 正式轮（reboot + `tools/postlock.sh`）。若正式轮里「W 侧记录产生」失败而
> 其余全绿，那是 §3.1 假设 2 命中（tmpfs 标签），记为**D5 记录缺失**，
> 不是 D1 失败——两件事分开写。

---

## 8 与现有实现的差异清单

| 项 | 现在 | V0a 之后 | V0b 之后 |
|---|---|---|---|
| SU 会话的 mnt ns | 调用者的（N） | `--vtz` 时 W，默认仍 N | 默认 W |
| 世界标记 | `TIF_PROC_UMOUNTED`（run-as 打不上） | `mnt_ns` inode（内核记账） | 同左 |
| 进入 W 的方式 | `wns run <pid> <cmd>`（无准入） | `ksud root_shell()` 的 `--vtz` 分支（allowlist 准入） | 同左，且为默认 |
| 入口记录 | 无 | W 侧 `access.log` | 同左 |
| `-M` 语义 | 进 init ns | 不变，且优先于 W | 同左 |
| `wns` 的地位 | 通用入口 | restore 内部工具（不再是第一公民入口） | 同左 |
| D1 | 不成立（SU 在 N） | 「存在一条进 W 的路径」 | 「SU 默认在 W」 |
| D4 | 不成立 | 弱成立 | 弱成立 |
| D5 | 弱 | 弱（记录点从 N 移到 W） | 同左 |

---

## 9 一句话版本

> SUVTZ 说的是：N 里看不见 W。
> VtzSU 说的是：**N 里看不见的这个世界，才是 root 真正住的地方。**
