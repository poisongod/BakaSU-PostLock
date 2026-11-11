# TrySU 管理器（TrySU Manager）

> **状态**：设计（2026-11-12）。**本文定义 TrySU 自己的管理器**——一个与 BakaSU
> 管理器（`com.resukisu.resukisu`）无继承关系的新组件。
> 架构结论一律以仓库根目录的 `TrySU.md`（三世界 `W` / `N` / `VN` + 十二公理）为准；
> 本文只回答「管理器在 TrySU 里是什么、不是什么」。

---

## 0 一句话

TrySU 管理器是 **`W` 的用户态控制面**：它运行在 `N` 的 Android 环境里，向 `W`
发服务请求、展示 `W` 的自述、管理 `VN` 的映射与入口与恢复。
**它不持有权限，不执行 Root，不是 `VN` 的一部分。**

---

## 1 为什么不能继续用 BakaSU 管理器

BakaSU 管理器（`../BakaSU/manager`，248 个 Kotlin 文件，namespace
`org.bakasu.bakasu`，applicationId 默认 `com.resukisu.resukisu`）是 KernelSU 的
前端。它的信息架构就是 KernelSU 的，与 TrySU 公理是结构性冲突，不是品牌问题：

| 公理 | BakaSU 管理器的实际做法（代码/部署事实） | 冲突点 |
|---|---|---|
| 公理二 / 七（`N` 不承载 Root、`VN` 不触达 `N`） | 模块经内核 overlay 全局挂载，`/data/adb/modules` 直接在 `N` 视图生效 | `N` 被 `VN` 的内容污染，三层边界不存在 |
| 公理九（唯一入口） | 任一 allow-list app 都能 `scan_driver_fd()` 拿到 `[ksu_driver]` fd（`kernel/supercall/supercall.c` 的 `anon_inode_getfile`） | 入口不唯一，每个客户端各持一个 `W` 句柄 |
| 公理十（单向信任） | 管理器读 `/proc`、系统属性、文件推断 `W` 状态（如 `SysProps.moduleLoaded()`） | `W` 状态不是 `W` 自述，`N`/管理器在观测 `W` |
| 公理一（权限在 `W`） | 授予状态双写：内核 allowlist + app 侧 store；管理器与 ksud 都能改 | 仲裁主体分裂，`W` 不是唯一主体 |
| 命名与定义 | UI 只有「超级用户 / 模块 / App Profile」 | 完全没有 `W` / `N` / `VN` 的概念 |

**结论**：改包名、改图标、改签名只是换皮；BakaSU 管理器的**信息架构**与
**能力路径**必须重写，才能承载 TrySU 的语义。

---

## 2 定位：`W` 的控制面，不是 `N` 的 app，也不是 `VN` 的执行体

三世界的分工决定了管理器的位置：

| 世界 | 管理器与它的关系 |
|---|---|
| `W`（权限安全世界） | 管理器是 `W` 的**用户态控制面**：所有授权、映射、入口、恢复动作都由它**请求** `W` 执行；强制力在内核。 |
| `N`（正常世界） | 管理器**运行在** `N` 的 Android 环境（一个普通 app），但不属于 `N` 的能力主体；它不写 `N` 的受保护部分。 |
| `VN`（虚拟正常世界） | 管理器**不进入** `VN`、不执行 `VN` 内代码、不依赖 `VN` 内任何代码运行（公理十二）。 |

一句话边界：**管理器可以发起一切，但执行一切的是 `W`（内核）；管理器自己什么
权限都没有。**

---

## 3 三层职责

### 3.1 `W` 面：授权仲裁与状态自述

- 展示 `W` 的**自述状态**：驱动版本 / UAPI / 策略摘要 / 当前允许的授权集合。
  数据来源必须是 `W` 的应答（ioctl / 单一入口），**不得**靠读 `/proc`、属性
  或文件推断。
- 发起授权变更（授予 / 撤销 / 超时 / 一次性能力），由 `W` 落账。
- 展示 `W` 自己的审计事件（谁在何时请求了什么、`W` 如何裁决）。

### 3.2 `N` 面：正常完整性

- 展示 `N` 的正常完整性状态（SELinux、启动链、关键分区、系统属性基线）。
- **只读**：管理器不修改 `N` 的受保护部分。
- 明确标注哪些项是「`N` 自己报告的」、哪些是「管理器观测的」，两者不混。

### 3.3 `VN` 面：映射、入口、恢复

- 展示 `VN` 实例：当前映射（mount ns / 视图）、`N`→`VN` 进入开关、活跃会话。
- 发起 `VN` 的建立 / 销毁 / 恢复动作（恢复由 `W` 管理，公理十二）。
- 展示 `VN` 的可破坏性：`VN` 内发生的一切在管理器中只作为**事件**出现，
  不作为 `W` 或 `N` 的状态。

---

## 4 由公理导出的硬约束

1. **不持权**：管理器进程永不 `setuid(0)`、永不执行 root 代码、永不进入 `VN`。
2. **入口收敛**：V0 允许管理器经内核 fd 与 `W` 通信（既有能力），但**只有
   TrySU 管理器**由其签名加冕获得该 fd；V1 起收敛到 TrySU 自己的单一入口
   （daemon / socket），app 不再各自 `scan_driver_fd`。
3. **状态自述**：`W` 面展示的每一项都必须来自 `W` 的应答，不得由管理器侧推断。
   推断得出的一律记 `INFO` 并注明「观测值」。
4. **不改 `N`**：管理器不写 `/data/adb/modules`、不改系统属性、不挂载。
   模块/映射内容归 `VN` 面，由 `W` 执行挂载。
5. **恢复不依赖 `VN`**：恢复入口的代码路径里不得出现 `VN` 内的任何二进制或脚本。
6. **诚实标注**：无法从 `W` 得到的项显示「不可观测」，不得用绿勾冒充。

---

## 5 与内核驱动、ksud 的关系

| 组件 | 角色 | TrySU 下的处置 |
|---|---|---|
| `kernelsu.ko`（`../BakaSU` fork） | `W` 的内核侧强制力（supercall / allowlist / sucompat / SUSFS） | **继续使用**（它是 `W` 的本体），但管理器加冕签名换 TrySU，`manager_sign.h` 增补 TrySU 条目 |
| `ksud`（`../BakaSU/userspace`） | `W` 的 CLI 执行体 + 恢复期动作 | **继续使用**，但 `KSU_PACKAGE_NAME` 默认值改为 TrySU 包名 |
| BakaSU 管理器（`com.resukisu.resukisu`） | KernelSU 前端 | **退役**：不再安装、不再作为验收依据 |
| PostLock（`../PostLock-Boot`） | 恢复链调度 + 观测面自检 | 保持冻结 legacy，与 TrySU 管理器无关 |

**签名加冕**（`kernel/manager/manager_sign.h`）：

```c
// TrySU
#define EXPECTED_SIZE_TRYSU <apk-sign-sha256-prefix-size>
#define EXPECTED_HASH_TRYSU "<sha256-of-signing-cert>"
```

内核 `apk_sign.c` 按「签名证书 SHA-256 + 证书长度」匹配，`track_throne()`
在 `W` 加载时同步扫描已安装包并加冕。**这是 `W` 认管理器的唯一判据**——
不是包名、不是 uid，是签名。因此 TrySU 管理器必须持有**独立的签名密钥**。

---

## 6 V0 最小切片（可执行清单）

目标：一个能装、能跑、能诚实展示三世界的管理器，**不改变 exploit 链与恢复链**。

| 项 | V0 内容 | 判据 |
|---|---|---|
| 应用 | 全新 Android 工程，包名 `io.trysu.manager`（待裁定），Compose UI | `pm path` 可见、冷启动无 ANR |
| 签名 | 独立 keystore（`tools/trysu-manager/keys/`），证书 SHA-256 入 `manager_sign.h` | `W` 侧加冕成功（`W` 自述里 manager uid 命中） |
| 内核 | 重编 `kernelsu.ko`，新增 TrySU 签名条目；`ksu_debug_manager_appid` 由 restore 解析 TrySU uid | `finitmod` 加载成功、`track_throne` 无报错 |
| ksud | `build.rs` / `cli.rs` 默认包名改 TrySU | `ksud` 内嵌串命中新包名 |
| `W` 面 | 状态（版本/UAPI/策略）+ 授权列表 + 审计 | 数据全部来自 ioctl 应答，截图可复核 |
| `N` 面 | SELinux / 启动链 / 关键属性基线（只读） | 每项标注来源「`N` 自报」或「观测」 |
| `VN` 面 | 当前 `VN` 实例 / 入口开关 / 恢复按钮 | 动作由 `W` 执行，管理器不直接 mount |
| 恢复链 | `tools/postlock.sh` 的 manager uid 解析改 TrySU 包名 | 双 OK 原生 + verify 通过 |

**V0 不做**：模块商店、在线更新、App Profile 的高级策略、SUSFS 配置 UI、
守护进程常驻。这些等 V1 单一入口落地后再谈。

---

## 7 现有资产处置

| 资产 | 处置 |
|---|---|
| `com.resukisu.resukisu`（已装 BakaSU 管理器） | 卸载；验收不再依赖它。若需对照，保留一个旧 boot 的截图即可 |
| BakaSU 管理器的 Kotlin 源码（`../BakaSU/manager`） | **不 fork、不复制**。仅作「不要这么做」的参照；如需要某个 ioctl 的调用约定，看 `uapi/` 与 `userspace/ksud` |
| `docs/trysu-implementation.md` §2 判据（V1–V10） | 保留（V0a 的 `su --vtz` 与管理器无关）；旧 `docs/vtzsu-design.md` 已全文作废，仅历史取证 |
| SUVTZ 的 A1 探针（「管理器包可见」） | 语义更新：探针改为「TrySU 管理器包可见」，仍属已接受暴露面 |
| `manager_sign.h` 里的 BakaSU 条目 | **保留**（不删，避免影响既有 `track_throne` 逻辑）；仅追加 TrySU 条目 |

---

## 8 待裁定点（需用户明确）

1. **包名**：`io.trysu.manager` / `com.trysu.manager` / 其他？
2. **签名密钥归属**：仓库内生成并提交 keystore（可复现），还是用户自持不入库？
3. **V0 通信方式**：沿用内核 fd（快，但入口不唯一），还是一开始就做 TrySU
   单一入口 daemon（慢，但符合公理九）？
4. **BakaSU 管理器是否立即卸载**：立即卸（干净，但失去对照）还是留一个 boot 周期？
5. **模块语义**：V0 是否明确「TrySU 不提供全局模块」，把模块推后到 VN 映射层？

以上五项裁定后即可开工；未裁定前，本文档不落代码。
