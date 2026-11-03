# SUVTZ v2：超级用户安全世界

> **已被 `docs/suvtz-v3-design.md` 取代（2026-11-03）。**
> 保留本文仅作演进记录：v2 的问题是"有测试计划、没有安全架构"——缺信任根、缺攻击者
> 模型、缺边界定义，因此不配 `Virtual TrustZone` 之名。v3 用「分层信任域
> （T0 观测等价 / T1 TEE 审计锚 / T2 硬件隔离）」给出形式化定义与可达性分级。

日期：2026-11-03
目标设备：PFUM10 / Android 12 / 5.4.254-qgki（回锁，无 fastboot 刷写能力）
前置材料：仓库根 `SUVTZ.md`（v1，未通过可行性评审，见 §0）
现有内核资产：`kernelsu.ko`（BakaSU fork + SUSFS 九项）、`oplus_check_suppress.ko`

---

## 0. v1 为什么被否：三条硬伤，条条可证伪

v1 的核心假设是「授权表与判定逻辑放在普通内核无映射的私有页里」。这条假设不成立，
不是"上限较低"的问题，而是**被普通内核的合法 API 就能推翻**。

| # | v1 原文 | 证伪路径 | 性质 |
|---|---|---|---|
| 1 | §3.1「普通内核页表不建立映射 → 没有合法路径」 | 预留页必然登记在 `iomem_resource` / memblock 中（否则会被分配出去）。`for_each_mem_range()` 枚举 + `vmap()` 重建映射，全是 `EXPORT_SYMBOL` 的常规调用。**不需要攻击者能力** | 架构性 |
| 2 | §3.3「token 与 PID/UID/包名无关联」+ §5「内核读进程私有内存」 | token 是**可复制凭证**：`sendmsg` / 共享文件 / 同 uid `process_vm_readv`。拿到 token 的一方直接冒用，MAC 随 token 一起搬走，无需密钥 | 协议性 |
| 3 | §5.6「`/proc/PID/status` 保留提权前凭证」 | status 显示 caller uid → caller 与 su 进程**同 uid** → caller 获得 ptrace 权限 → 读 `/proc/PID/attr/current` → 直接看到 `u:r:ksu:s0`。要堵就得伪装 `attr/*` 全家桶 + `SO_PEERCRED` + binder `getCallingUid` + `statx` + `loginuid`，一致性补不全 | 自相矛盾 |

补充两条事实性错误（评审记录，不重复展开）：

- §7 表格「内核符号、模块条目 → SUSFS symbol/module hiding」：SUSFS `HIDE_KSU_SUSFS_SYMBOLS`
  只挂 `kallsyms` 的 `s_show`，管 `/proc/kallsyms` 的**文本**；`/sys/module/kernelsu/`
  目录本身**不隐藏**，且 app 域真实可 `stat`（本项目自己的 `moduleLoaded()` 就是靠这条
  绕过 SELinux 的 `/proc/modules` 拒绝的）。
- 全篇未提 SELinux 域切换。Android 提权 = uid 0 + 切 `u:r:ksu:s0`，切域后进程无法再
  访问自己的 `/data/user/0/<pkg>`，所以提权必须以独立进程发生——这正是 KernelSU 的 `su`
  模型，v1 的"原地提权"前提（§5）与 Android 进程模型冲突。

---

## 1. v2 的第一原则：先定威胁模型，再定架构

任何"安全世界"的设计都是相对于某个对手而言的。v1 的问题是把对手设成了
「能主动遍历物理内存的内核级攻击者」，然后在 §12 承认防不住——**威胁模型与实现目标
不一致**。

v2 显式定义两个模型，架构分层依赖它们：

| 模型 | 对手能力 | 是否默认 |
|---|---|---|
| **T0** | `untrusted_app` / `shell` 域的用户态进程（Play Integrity、银行 App、风控 SDK） | ✅ 默认 |
| **T1** | T0 + 能 `insmod` 任意内核模块的对手（内核完整性保留） | 可选 |

### 1.1 T0 下最重要的一条结论

**v1 想解决的问题在 T0 下不存在。** app 域读内核内存的入口逐项实测如下：

| 入口 | app 域实测结果 | 依据 |
|---|---|---|
| `/dev/mem`、`/dev/kmem` | 不存在 | AGENTS 记录 |
| `/proc/kcore` | `0400 root` | 实测 |
| `/proc/kallsyms` | 地址全 0（`kptr_restrict=2`）+ SUSFS 已隐藏符号名 | 实测 |
| `/proc/modules` | SELinux 拒（`moduleLoaded()` 只能回落 stat `/sys/module`） | 实测 |
| `/sys/kernel/debug` | 不存在（`CONFIG_DEBUG_FS=n`） | 实测 |
| `perf_event_open` | SELinux 拒（`errno=13`，非 seccomp） | 实测 |
| `dmesg` | `dmesg_restrict` | 实测 |

所以 v2 的价值不在"藏得更深"，而在下面三件**真实**的事：

1. **把隐藏变成可测量**——每次 boot 出一份"检测方现在能看到什么"的报告；
2. **补齐真实存在的泄漏面**——不是假想的内核内存，而是 `ls /data/local/tmp` 就能看见的物料；
3. **在 T1 下给出唯一可能成立的信任根**——硬件 TEE，而不是虚构一个软件 TZ。

---

## 2. 架构：三平面

```
┌─────────────────────────────────────────────────────────────┐
│ Verdict（验证平面）   ← v2 的核心产品，唯一能"证明"隐藏有效的层   │
│   suvtz audit：以真实 app 域身份跑探针 → PASS/FAIL/INFO 三态    │
├─────────────────────────────────────────────────────────────┤
│ Veil（遮蔽平面）      ← 有真实活干的地方（§2.1）                │
│   SUSFS 九项 + kernfs 隐藏 + 物料 SUS_PATH + fsuid 归位        │
├─────────────────────────────────────────────────────────────┤
│ Vault（凭证平面）     ← 诚实地做减法（§2.2）                    │
│   T0：uid allowlist（够用，不再复杂化）                        │
│   T1：TEE-backed ticket（KeyMint HMAC，密钥不可导出）          │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 Veil（遮蔽平面）

覆盖清单按"可观测面"组织，每项标 T0 可达性、现状、手段、上限。

#### A. 内核符号与模块

| 面 | T0 可达 | 现状 | 手段 | 上限 |
|---|---|---|---|---|
| `/proc/kallsyms` 中 `ksu_*`/`susfs_*` 符号名 | 可读（地址已抹零） | ✅ SUSFS `HIDE_KSU_SUSFS_SYMBOLS` | kprobe `s_show` | 名称隐藏，地址本就不可见 |
| `/sys/module/kernelsu/` 目录 | **可 stat、可 ls、可读 parameters** | ❌ 裸露 | kprobe `kernfs_iop_lookup` + `kernfs_fop_readdir` | 只对非 `kernel/ksu` 域生效 |
| `/sys/module/oplus_check_suppress/` | 同上 | ❌ 裸露 | 同上 | 同上 |
| `/proc/modules` | SELinux 拒 | ✅ | — | 双保险 |
| `lsmod` 输出 | 可执行（读 `/proc/modules`） | ✅ 被 SELinux 挡 | — | — |

**kernfs 隐藏的技术核实（2026-11-03，设备离线 kallsyms）**：

- `kernfs_iop_lookup$999bdfdc…`、`kernfs_fop_readdir$999bdfdc…`、
  `kernfs_dop_revalidate$999bdfdc…` 均在 `kallsyms`（带 CFI 哈希，需
  `susfs_unwrap_jump_table()` 解到真身，与现有 SUSFS 符号解析同一套代码）；
- `module_kset` 在（`B 2e27b58`，数据符号，走现有 `susfs_lookup_symbol` 解析）；
- 实现要点：`kernfs_iop_lookup` pre_handler 命中隐藏名单时
  `regs->regs[0]=0; regs->pc=regs->regs[30]; return 1`（返回 NULL → negative dentry → ENOENT）；
  `kernfs_fop_readdir` 用 `ctx->pos` 跳到目标节点 id +1；
- **必须对 `u:r:kernel:s0` / `u:r:ksu:s0` 放行**，否则 restore 写
  `ksu_debug_manager_appid` 会失败。

#### B. 文件系统（SUS_PATH）

| 目标 | 属主 | app 域可达 | 说明 |
|---|---|---|---|
| `/data/local/tmp/ksu_boot/`（全套物料） | shell | **可读（实测 `run-as` 成功）** | 最高危 |
| `/data/local/tmp/kernelsu.ko` 等散料 | root/shell | 可读 | 同上 |
| `/data/adb/ksu/`、`/data/adb/modules/` | root | 部分可读 | 模块清单暴露 |
| `/product/bin/su`（overlay） | root | 可 stat | 属主 root ≠ app，SUS_PATH 会隐藏 |
| `/data/local/tmp/postlock_*.log`、`chain_run.state` | shell | **可读** | 日志里有全链细节 |

实施：restore 在每 boot 的 root 窗口用 `ksud susfs add_sus_path` 批量标记，
清单由 `tools/susfs/veil.list` 单一来源维护（host 与 app assets 共用同一份）。

**注意**：SUSFS `SUS_PATH` 的语义是「属主 ≠ 当前 uid 才隐藏」，所以 app 域天然看不到
root/shell 属主的东西；但**必须进程带 `TIF_PROC_UMOUNTED`**（非 root app 天然带），
且标记**不持久**（重启清零），所以这必须是 restore 的固定步骤。

#### C. 进程与产物

| 面 | 现状 | 手段 | 上限 |
|---|---|---|---|
| 被 root 创建的文件 `st_uid=0` | 裸露 | `setfsuid(caller_uid)` + 保留 `cap_effective` | 需改 ksud（Rust），见 §2.2 |
| `su` 进程 `comm`/`cmdline` | 裸露 | 内核写 `task->comm` / 重写 `mm->arg_*` | 需 root 侧 helper |
| `/proc/<pid>/status` 的 `Uid:` | 不构成痕迹 | — | uid=0 进程在系统中大量存在（init/系统服务），不异常 |

**fsuid 归位的技术要点**：Linux 的 `fsuid` 只影响 DAC 的属主判定与**新建文件的 inode 属主**，
`capable()` 看 `cred->cap_effective`，两者正交。所以
`setfsuid(caller) + cap 全开` = **文件属主归位 + 特权操作照常**，是干净的一招。
唯一副作用是 `su -c "chown root ..."` 这类显式改属主的命令语义变化，用环境变量开关。

#### D. 元数据

| 面 | 手段 | 状态 |
|---|---|---|
| `uname` 的 release/version | SUSFS `SPOOF_UNAME` | ✅ |
| `/proc/cmdline`、`/proc/bootconfig` | SUSFS `SPOOF_CMDLINE_OR_BOOTCONFIG` | ✅ |
| `stat` 的 ino/size | SUSFS `SUS_KSTAT` | ✅ |
| mount 的 `mnt_id` | SUSFS `SUS_MOUNT` | ✅ |
| AVC 审计日志 | SUSFS 声明为 126（未实现） | ❌ 如实上报 |

### 2.2 Vault（凭证平面）

**T0 下的结论：不做复杂化。** 理由很直接——授权表在内核里，而 T0 对手读不到内核内存
（§1.1 实测表）。给它"加密"或"哈希化"只是自娱，因为 key 与数据在同一地址空间。
真正有价值的减法只有两条：

1. **不落明文**：`allowlist.txt` 由 SUSFS `SUS_PATH` 隐藏（已有）；
2. **结构不固定**：`kmalloc` 动态 + 布局随机化，避免被 kallsyms 定位全局变量（低成本纵深）。

**T1 下的唯一出路：借用真实 TEE，不虚构"虚拟 TZ"。**

设备 Android 12 必有 KeyMint（`android.hardware.security.keymint`）。它支持
HMAC 密钥且**密钥不可导出**（TEE 内运算）。这正好提供了 v1 §3.2 想要、但软件给不了的
"密钥永不离开安全世界"——只不过那个"安全世界"是**硬件 TEE**，不是 EL1 里的虚构页。

设计：

```
管理器（uid 10277, untrusted_app）
  └─ 生成 HMAC key（KeyMint, TEE 内，不可导出）
       │
       ├─ 用户授权 App X → ticket = HMAC(key, uid_X || pkg_sig_hash || boot_id)
       │                  ticket 写入 X 的私有存储（SUSFS 隐藏）
       │
       └─ Broker（管理器进程内的 root/ksu 域 service）
            ├─ 持 keystore 句柄（key 绑定管理器 uid）
            └─ 内核通过窄通道问：verify(uid, ticket) → bool

内核 su 路径
  └─ setuid hook → 取 ticket → 问 Broker → 放行 / ENOENT
```

**前置实验（不做完这三个，T1 不立项）**：

| # | 实验 | 判据 |
|---|---|---|
| 1 | `KeyProperties.KEY_ALGORITHM_HMAC_SHA256` 在本机生成 + 运算 | `generateKey`/`init`/`update`/`finish` 全通 |
| 2 | 密钥是否绑定调用者 uid | 换 uid/换域调用应失败（决定 Broker 形态） |
| 3 | Broker 在 `u:r:ksu:s0` 域能否访问 keystore2 binder | AVC 放行或需补 sepolicy |

**已知代价（必须写清）**：

- 每次 `su` 一次 binder + TEE 往返（毫秒级，可接受）；
- Broker 随管理器被 HANS 冻结时 `su` 不可用 → 需要 fallback（缓存 ticket 的有效期，但缓存即状态，回到 T0 假设）；
- TEE 自身漏洞不在防御范围。

### 2.3 Verdict（验证平面）—— v2 的核心产品

**这是 v2 相对 v1 和相对现有 KernelSU 的真正增量**：把"隐藏"从信仰变成测量。

`suvtz audit` 以**真实 app 域进程**（zygote fork + setresuid，带 `TIF_PROC_UMOUNTED`）跑一组探针，
输出三态：

- `PASS`：该面已隐藏（探针得到与"无 root 设备"一致的观感）
- `FAIL`：该面仍暴露（可直接定位到具体手段缺失）
- `INFO`：不在威胁模型内 / 无法在 app 域测量（**严禁伪造成 PASS**）

#### 探针清单（与 §2.1 一一对应）

| # | 探针 | PASS 判据 | 对应手段 |
|---|---|---|---|
| 1 | `stat("/sys/module/kernelsu")` | ENOENT | kernfs lookup |
| 2 | `ls /sys/module` 中包含 `kernelsu` | 不含 | kernfs readdir |
| 3 | `stat("/sys/module/oplus_check_suppress")` | ENOENT | 同上 |
| 4 | `open("/data/local/tmp/ksu_boot/kernelsu.ko")` | EACCES/ENOENT | SUS_PATH |
| 5 | `ls /data/local/tmp` 含 `ksu_boot`/`preload.so`/`ksud` | 不含 | SUS_PATH |
| 6 | `ls /data/adb/ksu` | ENOENT | SUS_PATH |
| 7 | `stat("/product/bin/su")` | ENOENT | SUS_PATH |
| 8 | `read("/proc/kallsyms")` grep `ksu_`/`susfs_` | 0 行 | HIDE_KSU_SUSFS_SYMBOLS |
| 9 | `read("/proc/modules")` | EACCES | SELinux |
| 10 | `execve("su")` | ENOENT | 无 su 文件 |
| 11 | `stat` 一个由 root 创建的文件 | `st_uid != 0` | fsuid 归位 |
| 12 | `uname().release` | 固定伪造值 | SPOOF_UNAME |
| 13 | `/proc/cmdline` | 不含 `androidboot.verifiedbootstate=orange` | SPOOF_CMDLINE |
| 14 | `stat` 管理器的数据文件 | ENOENT/309 无权限 | SUS_PATH + kstat |

**运行方式**：

- BOOT_COMPLETED 后由 app 自己跑（`SusfsSelfTest` 已有基础设施，扩成通用探针）；
- 结果写 `files/suvtz_audit_<boot_id>.json` + root-only `dmesg` 一行摘要；
- 管理器 UI 显示"本 boot 暴露面：N 项 PASS / M 项 FAIL / K 项 INFO"；
- **FAIL 项是唯一需要立刻处理的**，INFO 项在文档里标注原因。

#### 为什么这一层最重要

现在项目里所有验证都是"我做了隐藏，所以应该隐藏了"。v2 的观点是：
**没有探针证明的隐藏等于不存在**。一个 boot 里任何一项手段失效（kprobe 没注册、
SUS_PATH 没 add、SELinux 策略变化），探针会当场 FAIL，而不是等到某个检测 App 上线。

---

## 3. 实施路线

| Phase | 内容 | 工作量 | 依赖 |
|---|---|---|---|
| **P0** | Verdict 骨架：探针框架 + 三态输出 + UI 汇总 | 1 天 | 现有 `SusfsSelfTest` |
| **P1** | Veil 三缺口：kernfs 隐藏（~90 行 C）+ 物料 SUS_PATH 清单 + fsuid 归位 | 3 天 | P0 探针 1/2/4/5/11 |
| **P2** | Verdict 全量探针 + 每次 boot 自动跑 + 回归对比 | 1 天 | P1 |
| **P3**（可选） | TEE ticket：3 个前置实验 → 通过才立项 | 2-3 周 | 实验 1-3 |

**P3 的决策点**：实验 1/2 任一失败 → T1 永久搁置，v2 停在 T0，这是**可接受的终态**。

---

## 4. 诚实边界（v2 明确不做的事）

| 不做 | 原因 |
|---|---|
| 私有页 / "内核无映射"隔离 | 证伪（§0 #1），`iomem_resource` + `vmap` 可重建 |
| token 放进程内存 | 可转移（§0 #2），且内核无法可靠判断 token 归属 |
| `/proc/<pid>/status` 凭证伪装 | 与 SELinux 域读取自相矛盾（§0 #3）；补全 `attr/*` 全家桶成本极高且仍有 `SO_PEERCRED`/binder/`statx` 漏点 |
| `getdents64` 过滤 `/proc/<pid>` | `kill(pid,0)` 的 `EPERM`/`ESRCH` 即可枚举，且破坏 AMS/lmkd/hung_task |
| 对抗 Play Integrity STRONG | 服务端 + 硬件证明，纯本地手段无效 |
| 隐藏 CPU 时间 / 内存统计 / 电池 | 物理侧信道，任何软件层做不到 |

**v2 的一句话定位**：不是"更深的隔离"，而是"**有证据的隐藏**"。

---

## 5. 与现有资产的映射

| v2 概念 | 现有实现 | 需要的改动 |
|---|---|---|
| Veil-A（符号） | `susfs_kallsyms.c` | 无 |
| Veil-A（模块） | 无 | 新增 `susfs_kernfs.c`（~90 行） |
| Veil-B（文件） | `susfs_path.c` + restore 未接清单 | 新增 `veil.list` + restore 步骤 |
| Veil-C（产物） | 无 | su 侧 `setfsuid`（或 shell 层 chown 兜底） |
| Verdict | `SusfsSelfTest.kt`（3 项） | 扩成 14 项通用探针 + JSON |
| Vault-T0 | BakaSU allowlist | 不动 |
| Vault-T1 | 无 | 3 个前置实验 |

---

## 6. 验收判据（v2 完成定义）

1. `suvtz audit` 在 fresh boot 后返回 **13 PASS / 0 FAIL / 1 INFO**（#11 在 fsuid 未做前记 INFO）；
2. 每一项 PASS 都有对应的 dmesg 或 app 侧证据，禁止"设置成功即 PASS"；
3. 连续三次 fresh boot 结果一致（回归稳定性）；
4. 管理器 UI 能显示本 boot 的暴露面汇总；
5. 若 P3 立项，ticket 验证失败的 `su` 与无 root 设备**观感一致**（ENOENT、耗时差 < 50ms）。

---

## 7. 与 v1 的关系

v2 不是 v1 的修补。v1 的价值定位是"用软件模拟一个 TrustZone"，v2 的判断是：
**这个 TrustZone 不存在，也不该假装存在**。若将来要真正的信任根，唯一的路是硬件 TEE
（P3）；在 TEE 之外，能做的只有"减少暴露面 + 证明它真的减少了"。

v1 中的两个概念被保留：

- 「窄入口 + 询问式判定」→ 作为 P3 Broker 的接口形态；
- 「拒绝路径与无 root 等价」→ 作为 Verdict 探针 #10 的判据。
