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

1. **SUVTZ 提供的是"世界的不可达性"，不是"内存的不可读性"**。TrustZone 让 Normal World 摸不到 Secure World 的内存；SUVTZ 让检测方摸不到 rooted 世界的事实。两者都是"一个世界对另一个世界的边界"，只是被保护的对象不同（机密数据 vs 状态事实）。这个结构是同构的，所以名字成立。
2. **在本设备的硬件与启动链条件下，T2 不可达，T1 受限于 3 个未验证前提，T0 是唯一可交付的级别**。任何声称做到 T1/T2 的软件方案都是假的——这一条本身是设计的一部分。

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

### 1.3 v3 要补的三样东西

1. **攻击者模型**（T0/T1a/T1b/T2，见 §4）
2. **边界的形式定义**（观测表面 S 与等价关系，见 §5.1）
3. **可达性分级**（每一级承诺什么、靠什么兜底、什么条件下失效，见 §4/§6/§7）

---

## 2. 名字的正当性

### 2.1 TrustZone 的不可达性结构

ARM TrustZone 做的事情可以抽象成一句话：

> **存在一个世界 W，Normal World NW 里的任何代码（包括最高特权级）都无法观测或影响 W，除非通过一个固定的、受监控的入口。**

这个"无法"由三样东西强制：NS bit（总线级标记）、TZASC（内存控制器分区）、Secure 中断分组（GIC）。

### 2.2 SUVTZ 的不可达性结构

SUVTZ 面对的现实是：**检测方 D 是敌对环境，root 的事实需要一个 D 无法触及的立足点。**

把它写成同一句式：

> **存在一个世界 W（rooted 的真实状态），检测方 D 里的任何代码（app、shell、甚至部分内核路径）都无法观测到 W 的存在，除非通过一个固定的、受控的观测面。**

区别只在"触及"的含义：

| | TrustZone | SUVTZ |
|---|---|---|
| 受保护对象 | 内存内容 | 状态事实（"这台设备有 root"） |
| 触及方式 | 物理地址访问 | 系统调用观测值 |
| 强制手段 | 硬件（NS/TZASC/GIC） | 软件（覆盖率 + 一致性 + 持久性） |

**结论**：两者保护的对象不同，但"世界边界"的结构同构。名字的正当性来自这个同构，而不是来自"我们也隔离了内存"——后者是假的，我们不声称。

### 2.3 三要素映射（含诚实强度）

| TrustZone 要素 | 硬件实现 | SUVTZ 对应 | 实际强度 |
|---|---|---|---|
| 世界隔离 | NS bit | 观测面等价（§5） | **弱**：只挡用户态检测方 |
| 状态机密 | Secure RAM | TEE 不可导出密钥（T1） | **强**，但仅限密钥本身 |
| 单向入口 | SMC | 窄协议（socket / 私有 syscall） | **强**：可以设计对 |
| 判定自主 | S-EL1 独立执行 | TEE MAC 会签 + 用户态 Gate（T1） | **中**：T1a 成立，T1b 不成立 |
| 中断隔离 | GIC 分组 | 无对应 | **无** |
| 内存完整性 | TZASC | 无对应 | **无** |

表里三个"无/弱"就是这套方案的代价。**把它们写出来，比藏起来更对得起名字。**

### 2.4 硬边界（明确不做承诺的部分）

以下三件事，本设备上**任何软件方案都做不到**，包括本设计：

1. **对完全控制内核的对手（T1b）隐藏**。内核可以读任何内存、改任何用户态进程、伪造任何返回值。没有 EL3/Secure-EL2 的强制，用户态 + TEE 也救不了（内核可以让 broker 根本不运行）。
2. **对服务端证明（Play Integrity / SafetyNet / 银行私有风控）伪造**。它验证的是 Google 签名链与硬件密钥证明，密钥不可导出。
3. **对物理/侧信道隐藏**。启动时间、CPU 频率、内存带宽、功耗曲线都不在我们的控制面内。

**这不是能力不足，这是 EL1 同特权级的数学事实。** 承认它，是设计质量的一部分。

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

> 注：第 8/9 项本次实测在 `u:r:runas_app:s0` 域下执行（`run-as` 不切换域），非真正的 `untrusted_app`；结果为空但 `2>&1` 可能吞掉了 EACCES。真值需用 app 自身代码（`SusfsSelfTest`）复测，见 P0。

**排序结论**：泄漏的严重性依次是 **包名 ≫ 物料目录 > 属性 > 模块目录 > 符号名**。原因很简单——包名是"一个 grep 就定性"的证据，而 `persist.adb.tcp.port=5555` 只是"可疑"（大量正常用户开无线调试）。

**这直接决定 P0 的顺序**：包面为零内核代码可解（管理器自带 Hide），物料目录用现成 SUS_PATH，属性面需要新机制，模块目录需要新 kernfs hook。

---

## 4. 分层信任域

| 级别 | 信任根 | 承诺 | 设备可达性 | 依赖 |
|---|---|---|---|---|
| **T0** | 我们自己的内核代码（诚实假设） | 用户态检测方无法区分 rooted 与 stock | ✅ **可达** | 现有链 + SUSFS + 包改名 |
| **T1a** | TEE KeyMint HMAC（密钥不可导出） | 即使内核**只读**被攻破，也无法伪造"用户授权过"或篡改隐藏策略 | ⚠️ **待验证**（3 个前提实验） | §6.2 |
| **T1b** | 无 | — | ❌ **不可达** | 需 EL3 |
| **T2** | EL3 / Secure-EL2 / RME | 真正的内存隔离 | ❌ **不可达** | 需 boot.img 自由 + 硬件 |

**关键取舍（必须写清楚）**：

T1 的前提是"内核只读不可信"。但如果内核完全可控（T1b），它可以让 broker 不运行、可以伪造进程身份、可以改任何用户态内存——**T1 也会塌**。

所以 **T1 的价值不是"更强的隔离"，而是"更强的可归因性"**：T1 让"是谁授权的"变成不可抵赖的事实，而不是内核的一面之词。这一点在**审计**与**多用户场景**里有真实价值，在"对 T0 隐藏"这件事上没有增量。

v3 诚实的定位：**T0 是产品，T1 是审计能力，T2 是未来**。

---

## 5. Tier 0：观测等价性

### 5.1 形式定义

定义观测表面

```
S = { s | s 是 untrusted_app 域可发起的系统调用/API 调用及其返回值 }
```

定义两个设备状态：

```
D_stock  = 未 root 的设备
D_rooted = 本项目的设备
```

**T0 的目标**：

```
∀ s ∈ S :  s(D_rooted) ≡ s(D_stock)
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
| B3 | `/product/bin/su`（overlay 上层） | shell 可见 | `add_sus_path` + `add_sus_path_loop` | ❌ |
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
| E3 | `/proc/self/mountinfo` 里的 overlay | `kernel:s0` 建的 mount 不打标 | 需确认 app 命名空间里看不到 | ⚠️ |
| E4 | `/proc/mounts` 中的 `tmpfs`（overlay upper） | 同上 | 同上 | ⚠️ |

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

### 5.4 不可覆盖清单（写死在设计里）

1. **T1b / T2 对手**（§2.4）
2. **G 类全部**（服务端证明）
3. **F2/F3**（物理侧信道）

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
| **P2** | 探针全量接入 P0 的扫描器，每 boot 自跑，结果落盘 | 零 | P1 | 0.5 天 | 未开始 |
| **P3** | TEE 三实验（E1/E2/E3）→ 过了才做 T1 | 零 | APK 测试代码 | 0.5 天 | 未开始 |

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

一个阶段算"做到"，必须同时满足：

| 判据 | 内容 |
|---|---|
| 覆盖率 | 该阶段清单内的面 **100%** 有结论（PASS 或 INFO，不允许"没测"） |
| 一致性 | 成对的面（C1/C2、B1/B5、A1/A4）**结论相同** |
| 持久性 | 重启后再测，结论不变 |
| 诚实性 | INFO 不得被写成 PASS；不可覆盖项必须出现在输出里 |
| 回归 | 上一阶段的探针**仍全 PASS** |

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
| 定义 | 隐藏 + 探针 | 观测等价性（形式化） |
| 信任根 | 无 | 分层：T0 无 / T1 TEE / T2 硬件 |
| 攻击者模型 | 隐含"用户态" | 显式 T0/T1a/T1b/T2 |
| 清单 | 14 项探针 | 7 类 33 项，含实测状态 |
| 不可覆盖清单 | 无 | 有（§5.4 + §2.4） |
| 名字正当性论证 | 无 | §2 |

## 附录 C：本设计不再做的事

- 不声称内核内存隔离
- 不伪造系统属性（`ro.debuggable` / `verifiedbootstate` / `oem_unlock_allowed` 保持真值）
- 不把 TEE 说成"Secure World"（它只是 MAC 算子）
- 不用 INFO 冒充 PASS
