# 无守护 VN 设计（v2 路线定稿）

> **文档性质**：设计方案，标准以 [`TrySU.md`](../TrySU.md)（v2）为准。
> 本文件回答「移除守护进程后 VN 怎么落地」，并给出可执行判据与改造清单。
> 首版：2026-11-13。状态：**待实施（P1）**。
>
> 相关：冲突审计 [`arch-conflicts-v2.md`](arch-conflicts-v2.md)；历史基线
> [`trysu-implementation.md`](trysu-implementation.md)（V0a 将降级为历史取证）。

## 0 决策前提

用户裁定：**TrySU 不需要守护进程**。依据（v2 坐标）：

- 命题五「执行可弃，正常可复」——holder 让 VN 变成需维持的长期实体；
- 公理四「构造时满足完整性不变量」——holder 形态构造一次、运行期无度量；
- 公理十二「原子重建映射 + 校验度量」——恢复应等价于下一次构造；
- 公理三「W 代码集仅含隔离/仲裁/恢复」——holder 不属于三类。

## 1 设计总览

```
su --trysu-vn -c CMD                 （唯一入口，内核 sucompat 判定后改写而来）
  │
  ├─ ① 内核 gate：allow-list + 域（已有 sucompat；P2 升级为一次性 token）
  ├─ ② unshare(CLONE_NEWNS)          → 新 ns = N 挂载表的复制（忠实映射字面成立）
  ├─ ③ mount("/", MS_REC|MS_PRIVATE) → 切断传播
  ├─ ④ 私有可写层：tmpfs（P1）／overlayfs lower=N+upper=tmpfs（P2）
  ├─ ⑤ 材料注入：/data/adb/trysu/material/ → 私有层，逐文件校验 manifest
  ├─ ⑥ 构造度量：manifest 全符 + mountinfo 断言 + N 侧不可见断言
  ├─ ⑦ 审计：/data/adb/trysu/audit.log（写失败 → 构造失败）
  └─ ⑧ exec CMD                     → 会话退出，ns 引用归零，自动销毁
```

三个取代关系：

| 旧（V0a 守护形态） | 新（无守护） |
|---|---|
| `wns hold` 常驻 + sidecar `<pid> <inode>` 路标 | 会话自建 + 会话自持；sidecar 删除 |
| 材料复制进 holder tmpfs，Phase C 删 N 副本 | 材料权威副本在 `/data/adb/trysu/material/`，VN 内是只读注入 |
| V1（sidecar 一致）/ V8（删 sidecar 硬失败） | N1（无 holder）/ N8（度量不符 fail-closed）等 |

## 2 per-session VN 构造

### 2.1 生命周期

- **创建**：`--trysu-vn` 会话开始时由 tsu 自身构造，无独立进程。
- **持有**：调用会话进程本身（及其子进程）持有 ns 引用。
- **销毁**：最后一个进程退出 → ns 引用归零 → tmpfs/overlay 上层自动释放，无残留。
- **并发**：每个 `su --trysu-vn` 各自一个新 ns（互不可见），符合「执行域」语义。

### 2.2 构造序列（tsu 内，`u:r:ksu:s0` uid 0）

```c
unshare(CLONE_NEWNS);                                  // ② N 视图的复制
mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);     // ③ 切断传播
mount("tmpfs", VN_ROOT, "tmpfs", 0, "mode=0700");      // ④ P1 私有层
// ⑤ 对每个材料：open(src, O_RDONLY) → 校验 sha256 → 写入 VN_ROOT/stage/ → chmod 0555
// ⑥ 断言：mountinfo 含 VN_ROOT tmpfs；N 侧材料路径仍可读；manifest 全符
// ⑦ 审计追加 → 失败即 _exit(2)
setns 不需要：本进程就是新 ns 的第一个成员，直接 exec
```

**注意**：不再需要 `setns`。旧形态是「外部进程进 holder 的 ns」，新形态是「构造者自己就是 VN 的第一个进程」——这是结构简化，也是「执行可弃」的直接体现。

### 2.3 私有可写层选型

| 方案 | 描述 | 优点 | 风险 |
|---|---|---|---|
| **P1：tmpfs-only** | 与现状相同路径 `$TMP/.w`，但只在会话内存在；材料 bind 为只读 | 行为与 V0a 可逐条对照，改动最小 | 「N 的完整视图」只在挂载表层面继承，tmpfs 之外的写仍落 N |
| **P2：overlayfs** | lower=N（只读视图），upper=tmpfs（可弃），VN 根为 merged | 「忠实映射 + 可写可弃」严格成立 | 需实测 GKI `CONFIG_OVERLAY_FS` 与 lower/upper 跨 fs 兼容 |

**推荐**：P1 先行（判据与旧基线可对照），P1.5 实测 overlay 后切 P2。切换点不影响判据 N1–N12 的口径（只影响 I2 的断言形式）。

### 2.4 材料来源（权威副本归 N）

- 路径：`/data/adb/trysu/material/`（0700 root-only）。
- 内容：`oplus_check_suppress.ko`、`kernelsu_hotload_init.ko`（若启用）、`postlock_adbkey.pub`、`pp_adb_tcp.bin` 等 restore-only 资产。
- **反转 Phase C**：旧实现删 N 副本、VN 唯一持有 → 新实现 N 保有权威副本，VN 内是「只读、已度量、可弃」的注入。VN 被毁不影响恢复能力（公理十二）。
- 链关键集（`kernelsu.ko`/`finitmod`/`preload.so`/`ksud`）维持现状留在 N。

## 3 能力式入口

### 3.1 三层现状与目标

| 层 | 现状 | P1 改动 | P2 目标 |
|---|---|---|---|
| 可见性 | stat 门面：非 allow-list 看不到 `/system/bin/su` | 保持 | 保持 |
| 执行 | sucompat 改写 execve → tsu（仅 allow-list） | 保持；tsu 构造前 ioctl 复核 | token 消费 |
| 仲裁 | 无显式能力；进入即长期 root shell | 审计 fail-closed；删除 sidecar | `ISSUE/CONSUME`：nonce + ttl + 单调计数器 |

### 3.2 P1 规则（无内核改动）

1. **唯一入口**：`execve /system/bin/su` → 内核改写 → tsu。禁止其他进入 VN 的路径（`--trysu-ns` 保留但限 allow-list + 审计标记 `via=ns-explicit`）。
2. **fail-closed**：材料缺失、manifest 不符、审计写失败、unshare/mount 失败——一律 `exit 2`，**不降级、不在 N 里执行**。
3. **审计**：`/data/adb/trysu/audit.log`（0700 root）追加一行：
   ```
   ts=<mono> pid=<pid> uid=<uid> domain=<ctx> via=<sidecar|explicit|self> manifest=<ok|mismatch> result=<enter|deny>
   ```
   写入失败 → 构造失败（不再「只告警」）。

### 3.3 P2 内核接口（预留）

```
ioctl(driver_fd, TRYSU_ISSUE_VN, &req)  → { token, ttl_ms, ops_mask }
ioctl(driver_fd, TRYSU_CONSUME_VN, &req) → 0 | -EPERM（单次、过期、计数器回退均拒）
```
- 单调计数器由内核原子递增；跨 boot 持久化在 driver 私有区（P2 再定载体）。
- tsu 构造前必须 `ISSUE` 成功；构造后 `CONSUME` 失败 → 销毁直接退出。

## 4 构造时度量与运行期不变量

### 4.1 manifest

`/data/adb/trysu/manifest.sha256`（0700 root），行格式：

```
<sha256>  <name>  <mode>  <bytes>
```

冷 boot 由 restore 在材料就位后生成。**生成即失败**（材料缺失）→ 记录 `WARN-manifest-incomplete`，P1 允许「关键集必须齐全、可选集缺失降级」——但**被构造消费的每个文件必须在校验清单内**。

### 4.2 不变量（可脚本断言）

| # | 不变量 | 判据 |
|---|---|---|
| I1 | 构造时材料哈希符合 manifest | 逐文件 sha256 比对，任一不符 → 拒构造 |
| I2 | VN 私有层确为 tmpfs/overlay | VN 内 `mountinfo` 查 VN_ROOT |
| I3 | 注入材料只读 | VN 内 `stat -c %a` 为 0555/0444，或重算哈希 |
| I4 | N 保有权威副本 | 构造后 N 侧材料路径仍可读且哈希不变 |
| I5 | 审计落盘 | audit.log 有本次 entry |
| I6 | N 侧不可见 VN 内容 | `ls $TMP/.w/log` → ENOENT（P1 路径语义） |

### 4.3 对手模型（诚实标注）

- 本环境无硬件信任根：度量能防「非 root 篡改」，**不能防 root 级篡改**。
- 与公理十一一致：隔离命题在本机不成立；本设计只把「完整性」从口号变为可执行断言，不宣称结构性保证。

## 5 判据 N1–N12（替代 V1–V10）

| # | 判据 | 期望 | 与旧判据关系 |
|---|---|---|---|
| N1 | 无 holder 进程 | `pgrep -f "wns hold"` 为空 | 取代 V1 |
| N2 | 会话在 VN 且自持 | `--trysu-vn` 内 `readlink /proc/self/ns/mnt` = 本会话 ns；构造者 pid = 会话 pid | 改造 V2 |
| N3 | 对照仍在 N | 不带开关 → N 的 ns | V3 保留 |
| N4 | VN 随会话消亡 | 会话退出后 pid 不存在；下一次构造 inode 全新 | 新增 |
| N5 | N 侧不可见 | `$TMP/.w/log` ENOENT（P1） | V5 保留 |
| N6 | 无文件路标 | `/data/local/tmp/vtz_w.pid` 不存在 | 取代 V1/V8 |
| N7 | 构造度量通过 | manifest 逐文件 PASS | 新增 |
| N8 | 度量不符 fail-closed | 篡改材料副本 → rc=2，无 VN 产出 | 取代 V8 |
| N9 | 入口 fail-closed | 非 allow-list 进程：stat ENOENT / 执行被拒 | 新增 |
| N10 | 审计记录 | audit.log 有本次 `via=self` entry；模拟写失败 → 构造失败 | 取代 V4 |
| N11 | 功能未退化 | `/`、`/system`、`/data`、`/apex` 可读；模块视图正常 | V6 保留 |
| N12 | 观测面回归 | `scan.sh -q` FAIL=0（W 类探针改 INFO 或新语义） | V10 改造 |

V7（-M 优先）/V9（inode 对照）保留为 N11/N3 的子项。

## 6 改造清单

### 6.1 代码

| 文件 | 动作 |
|---|---|
| `TrySU/cli/src/main.zig` | `--trysu-vn` 改为**构造器**（unshare/rprivate/tmpfs/材料校验/度量/审计/exec）；删除 sidecar 读取（`vnHandle`/`VN_SIDECAR`）；审计落点改 `/data/adb/trysu/audit.log`；`--trysu-ns` 限 allow-list + 审计 |
| `tools/wns/wns.c` | `hold`/`run` 退役（保留 `private`/`stat` 诊断）；文档标注历史 |
| `tools/postlock.sh` | 删 holder/sidecar 段（373–541）、Phase C（769–807）改「保留 N 权威副本」；新增 manifest 生成段；`SUVTZ_W_PURGE` 默认改 0 |
| `tools/suvtz/rows.sh`、`v0a_rows.sh` | 新判据 N1–N12 脚本；V0a 脚本标记历史基线 |
| `tools/suvtz/scan.sh` | W 类探针语义从「holder 存在」改为「无 holder 亦成立」 |
| `src/su_daemon.c`（Rust ksud 遗留） | 标记 deprecated；fail-open（`su.allow` 缺失放行）与 `su.allow` 判据随主链迁移 tsu 退场 |

### 6.2 内核（P2）

- `kernelsu` 模块 driver：`TRYSU_ISSUE_VN` / `TRYSU_CONSUME_VN` ioctl、单调计数器、审计 ring。

### 6.3 文档

- 本文件为 v2 设计权威；`trysu-implementation.md` 的 V0a 章节标注「历史基线（守护形态已废弃）」；`suvtz-*.md` 保持历史记录不改。

## 7 阶段

| 阶段 | 内容 | 上机验证 |
|---|---|---|
| **P1** | per-session 构造、删 holder/sidecar/Phase C、manifest 度量、fail-closed 审计、N 判据 | 一次冷 boot 即可验 N1–N12 |
| P1.5 | overlayfs 可行性实测（I2 断言切换） | 同轮顺带 |
| P2 | 内核 token/nonce/计数器 + 审计 ring | 需要 ko 换代 |
| P3 | 强虚拟化/硬件隔离域 | 超出本机范围 |

## 8 待定决策（实施前确认）

1. **私有层**：P1 用 tmpfs-only（推荐，行为可对照）还是直接上 overlay（风险高、收益大）？
2. **材料注入者**：P1 由 tsu 注入 + 度量（可立即做）→ P2 内核校验清单，是否接受这个两段式？
3. **`--trysu-ns <pid>`**：保留（限 allow-list + 审计）还是删除（更严格但失去调试通道）？
4. **manifest 位置**：`/data/adb/trysu/`（推荐，0700 root）还是沿用 `$STAGE`（N 侧 0700 shell 属主，权限更弱）？

## 9 风险

| 风险 | 缓解 |
|---|---|
| overlayfs 不可用/兼容差 | P1 用 tmpfs-only；实测后决定 P2 是否切换 |
| tsu 内 mount 需 CAP_SYS_ADMIN | 已具备（root + ksu 域）；失败 fail-closed |
| 每会话开销 | unshare+mount+材料复制实测（材料约 MB 级，预计 ms 级）；大材料改 bind 只读替代复制 |
| 兼容性：旧 `--vtz` 语义变化 | 无 sidecar 时自建而非报错；文档与 `--help` 同步 |
| 审计写失败阻断启动 | 这是设计选择（fail-closed）；若影响可用性，登记为「可接受降级」需显式批准 |
