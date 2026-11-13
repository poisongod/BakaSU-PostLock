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

### 0.1 已决事项（2026-11-13）

| 决策 | 结论 |
|---|---|
| 私有可写层 | **直接上 overlayfs**（lower=N 只读视图 + upper=tmpfs 可弃） |
| `--trysu-ns <pid>` | **删除**（入口唯一：只留 `su --trysu-vn`） |
| 材料注入 | 接受两段式：P1 tsu 注入+度量，P2 内核校验清单 |
| manifest 位置 | `/data/adb/trysu/`（0700 root-only） |

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
unshare(CLONE_NEWNS);                                  // ② N 视图的复制（新 ns 继承 N 挂载表）
mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);     // ③ 切断传播
// ④ overlay 私有层（P1 已决）：
//    upper/work 建于 tmpfs（可弃），lower 指向 N 的当前视图（只读）
//    形态 A：单 overlay on / → pivot_root 进 merged（边界最彻底）
//    形态 B：per-mount overlay → 仅对声明可写路径建 overlay（兼容性更好）
//    形态在 P1 首个实测闸门选定（见 2.3），选定前不写死代码
// ⑤ 对每个材料：open(src, O_RDONLY) → 校验 sha256 → 写入 upper 对应路径 → chmod 0555
// ⑥ 断言：mountinfo 中 VN 关键路径为 overlay；N 侧材料路径仍可读；manifest 全符
// ⑦ 审计追加 → 失败即 _exit(2)
setns 不需要：本进程就是新 ns 的第一个成员，直接 exec
```

**注意**：不再需要 `setns`。旧形态是「外部进程进 holder 的 ns」，新形态是「构造者自己就是 VN 的第一个进程」——这是结构简化，也是「执行可弃」的直接体现。

### 2.3 私有可写层：overlayfs（P1 已决）

目标形态：**lower = N 的只读视图，upper/work = tmpfs（可弃），VN 根 = merged**。
这是「忠实虚拟映射」的直接实现：N 提供只读基底，VN 的写全部落在可弃上层。

P1 首个闸门先实测三种候选形态，择一写死：

| 候选 | 描述 | 优点 | 风险 |
|---|---|---|---|
| **A：单 overlay on `/`** | lower=`/` 的只读 bind，upper=tmpfs，`pivot_root` 进 merged | 边界最彻底，VN 根即 merged | Android 根挂载点结构复杂（/system、/data 为独立挂载），需递归处理 |
| **B：per-mount overlay** | 只对声明可写路径（如 `/data/adb`、模块视图路径）建 overlay | 与现有模块 overlay 共存性好 | 「N 的完整视图」只对声明路径成立，需维护路径清单 |
| **C：tmpfs 兜底** | 仅在 A/B 均不可行时启用（需回报批准） | 保底可交付 | 偏离「忠实映射」，回到 V0a 语义 |

**实测闸门**（P1 第一步，不过闸不写构造代码）：

1. `cat /proc/filesystems | grep overlay` 与 `zgrep CONFIG_OVERLAY_FS /proc/config.gz`；
2. 在私有 ns 内最小复现：tmpfs upper/work + lower 指向现行根，检查 mount 成功与 `mountinfo` 形态；
3. 嵌套检查：VN overlay 的 lower 若本身是模块 overlay（Android 模块机制），验证 stacked overlay 行为（`xino`/`index` 需求）；
4. 记录结论到 `docs/forensics/overlay-vn-<boot>.md`，A/B/C 择一后回填本文件。

### 2.3.1 实测结论（2026-11-13，boot `11e3bdc8`）

| 项 | 结果 |
|---|---|
| overlayfs | 可用（builtin，`CONFIG_OVERLAY_FS=y`） |
| tmpfs 作 upper | **不可行**（`CONFIG_TMPFS_XATTR` 未开，dmesg 明确报错） |
| `/data`(f2fs) 作 upper/lower | **不可行**（`inline_data/inline_dentry/inlinecrypt`，overlayfs 报 not supported） |
| `/metadata`(ext4) 作 upper | **可行，但仅 11MB**（容量闸门必需） |
| loop ext4 镜像作 upper | 不可行（`losetup` 成功但 `mke2fs` I/O error、ext4 mount EINVAL） |
| `lowerdir=/system` 的 merged 根 | 是 `/system` 内容，**不是 N 完整根**（chroot 失败的原因） |

**结论：形态 B 具体化为**「tmpfs 骨架（VN 根）→ 分区 bind（/system /vendor /product /apex /data /proc /sys /dev）→ per-mount overlay 覆盖需要可写的系统分区（upper 在 `/metadata/trysu/<sess>`）→ `chroot` 进骨架」。

**新增硬约束**：

1. **容量闸门**：构造前检查 `/metadata` 可用空间 ≥ 阈值（建议 ≥8MB 预留，即 upper 用量上限 3MB），不足 fail-closed；
2. **实验规则**见 `docs/forensics/overlay-probe-leak-11e3bdc8.md` §6（跨连接验证 ns 隔离、umount busy 禁 rm -rf、只在 reboot 可接受窗口实验）。

> 上述结论来自一次探针事故（同一 boot 内挂载泄漏导致 `/system` 不可用，reboot 恢复）；
> 复盘与证据见该 forensics 文档。
>
> **隔离性复核（2026-11-13，boot `ebd7d915`，已完成）**：`unshare -m` 单独使用会因
> root mount 仍属 `shared:1` 而把 mount 传播回初始 ns（已复现）；`unshare` 后紧跟
> `mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)` 则完全隔离（退出后全局 `final-clean`）。
> **构造器硬要求：unshare 与 rprivate 必须成对，禁止任何「只 unshare」路径；
> 构造器内 mount 失败一律 fail-closed。** 记录见 `docs/forensics/ns-isolation-ebd7d915.md`。


## 2.4 材料来源（权威副本归 N）

- 路径：`/data/adb/trysu/material/`（0700 root-only）。
- 内容：`oplus_check_suppress.ko`、`kernelsu_hotload_init.ko`（若启用）、`postlock_adbkey.pub`、`pp_adb_tcp.bin` 等 restore-only 资产。
- **反转 Phase C**：旧实现删 N 副本、VN 唯一持有 → 新实现 N 保有权威副本，VN 内是「只读、已度量、可弃」的注入。VN 被毁不影响恢复能力（公理十二）。
- 链关键集（`kernelsu.ko`/`finitmod`/`preload.so`/`ksud`）维持现状留在 N。
- **P1 第一版只度量、不注入**（2026-11-13 实测）：`tsu` 在构造前逐文件校验
  sha256/mode/bytes，不符即 `deny` + exit 2；材料本身不复制进 VN。注入到
  VN 内目标路径需要先定义「材料 → 目标路径」清单，留到 P1.5。
- **manifest 由 postlock 在 restore 早期生成**（模块加载之前），只列
  material 目录里实际存在的文件；当前 boot 若只剩部分材料，manifest
  就只有对应行。`tsu` 对「缺失/空/不符」分别记 `absent`/`mismatch` 并拒绝。

## 3 能力式入口

### 3.1 三层现状与目标

| 层 | 现状 | P1 改动 | P2 目标 |
|---|---|---|---|
| 可见性 | stat 门面：非 allow-list 看不到 `/system/bin/su` | 保持 | 保持 |
| 执行 | sucompat 改写 execve → tsu（仅 allow-list） | 保持；tsu 构造前 ioctl 复核 | token 消费 |
| 仲裁 | 无显式能力；进入即长期 root shell | 审计 fail-closed；删除 sidecar | `ISSUE/CONSUME`：nonce + ttl + 单调计数器 |

### 3.2 P1 规则（无内核改动）

1. **唯一入口**：`execve /system/bin/su` → 内核改写 → tsu。禁止其他进入 VN 的路径：**`--trysu-ns` 已删除（2026-11-13 裁决）**，`su --trysu-vn` 是唯一入口；tsu 的 `--help` 与 argv 解析同步移除该选项。
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
<sha256>  <mode>  <bytes>  <name>
```

（顺序与 `tools/tsu/n_rows.sh` N7 的解析一致；实现见 TrySU `cli/src/main.zig::verifyEntry`。）

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
| N9 | 入口 fail-closed 且唯一 | 非 allow-list 进程：stat ENOENT / 执行被拒；`--trysu-ns` 不存在（传参即报错） | 新增 |
| N10 | 审计记录 | audit.log 有本次 `via=self` entry；模拟写失败 → 构造失败 | 取代 V4 |
| N11 | 功能未退化 | `/`、`/system`、`/data`、`/apex` 可读；模块视图正常 | V6 保留 |
| N12 | 观测面回归 | `scan.sh -q` FAIL=0（W 类探针改 INFO 或新语义） | V10 改造 |

V7（-M 优先）/V9（inode 对照）保留为 N11/N3 的子项。

### 5.1 脚本落点与当前状态（2026-11-13，boot `ebd7d915`）

| 脚本 | 覆盖 | 用法 |
|---|---|---|
| `tools/tsu/n_rows.sh` | N1–N11（设备侧，含 N8/N10b 的 ARM 门控） | push 后 `sh` 执行；只读默认，破坏性实验需 `N8_ARM=1` / `N10_ARM=1` |
| `tools/tsu/n_accept.sh` | N12（`scan.sh -q`）+ 一键汇总与退出码 | `SERIAL=<serial> tools/tsu/n_accept.sh`（`--no-scan` 可跳过 N12） |

当前实测（2026-11-13，**daemonless 形态已落地**，boot `ebd7d915`）：

```
设备侧 PASS=15 FAIL=0 INFO=2（form=daemonless；N8/N10b 破坏性实验均启用）
  INFO  N4b（两次构造 inode 相同，内核复用编号；真正的判据是 N4c）
  INFO  N12（由宿主 n_accept.sh 执行）
N12 scan.sh -q: FAIL=0（PASS=32 / INFO=5 —— 无 holder 后 W 类探针自动降级为观测）
```

历史对照（P1 未实现，holder+sidecar 形态）：PASS=6 FAIL=7 INFO=4，
红灯 N1/N4b/N4c/N6/N7/N9a/N10a 全部是当时的预期靶子。

判据设计上的两个注意点（均已写进脚本注释）：

1. **N5 的前提是 holder 挂载点完好**。holder 的 tmpfs 挂载点目录若被外部删除，VN 内路径会
   静默回落到 N 侧同名目录，N5 会假红（见 `docs/forensics/holder-mountpoint-deletion-ebd7d915.md`）。
2. **N9a 有副作用**：`--trysu-ns 1` 会把审计写进 N 侧 `.w/log`（旧 tsu 落点固定），脚本在
   N9a 后只清理 `log` 子目录、保留 `.w` 目录本身。

## 6 改造清单

### 6.1 代码

| 文件 | 动作 |
|---|---|
| `TrySU/cli/src/main.zig` | `--trysu-vn` 改为**构造器**（unshare/rprivate/overlay/材料校验/度量/审计/exec）；**删除 `--trysu-ns` 分支与 help 条目**；删除 sidecar 读取（`vnHandle`/`VN_SIDECAR`）；审计落点改 `/data/adb/trysu/audit.log` |
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
| **P1** | **首步 overlay 实测闸门（2.3）** → per-session 构造、删 holder/sidecar/Phase C、manifest 度量、fail-closed 审计、N 判据 | 闸门 + 一次冷 boot 验 N1–N12 |
| P1.5 | 选定形态（A/B）的边界细化与路径清单（若选 B） | 同轮顺带 |
| P2 | 内核 token/nonce/计数器 + 审计 ring | 需要 ko 换代 |
| P3 | 强虚拟化/硬件隔离域 | 超出本机范围 |

## 8 实施顺序（决策已定，2026-11-13）

1. **overlay 实测闸门**（2.3）：确认 `CONFIG_OVERLAY_FS`、最小复现、stacked 行为；A/B/C 择一，写入 `docs/forensics/`。
   → *（2026-11-13 完成）* 结论见 §2.3.1；`unshare -m` 隔离性已实证复核
   （`docs/forensics/ns-isolation-ebd7d915.md`）：**unshare 必须与 rprivate 成对**。
2. **tsu 构造器**：unshare → rprivate → overlay → 材料校验注入 → 度量断言 → 审计 → exec；删除 `--trysu-ns` 与 sidecar 相关代码。
   → *（2026-11-13 完成，有偏差）* TrySU `bfa6db7`，tsu `b183a2d4`。实际序列：
   `unshare → rprivate → 度量 → tmpfs 骨架 → 28 个顶层目录 bind →
   VN 内 /data/local/tmp 换 tmpfs → 审计 → chroot`。
   **偏差一**：overlay 私有可写层未实现，VN 根是 tmpfs 骨架 + 分区只读 bind；
   **偏差二**：材料只度量、未注入（见 §2.4）。两项都记为 P1.5 待办，
   不改变已验收的隔离性结论（N1–N12 全绿）。
3. **postlock.sh 改造**：删 holder/sidecar 段与 Phase C；新增 `/data/adb/trysu/` 的 material 布局与 manifest 生成。
   → *（2026-11-13 完成）* W world 整体退役（不再起 holder、不写 sidecar、
   不从 W 加载 .ko / 读 adb key / pp），Phase C 删除；restore 早期生成
   material + manifest（WARN-only）。
4. **判据脚本**：`rows.sh` 实现 N1–N12；V0a 脚本归档为历史基线。
   → *（2026-11-13 完成）* 落点为 `tools/tsu/n_rows.sh` + `tools/tsu/n_accept.sh`；
   `tools/tsu/rows.sh`（V0b/T0–T7）与 `tools/suvtz/v0a_rows.sh`（V0a）保留为历史基线。
5. **冷 boot 验收**：一次冷 boot 收 N1–N12 + 回归三件套。

## 9 风险

| 风险 | 缓解 |
|---|---|
| overlayfs 不可用/兼容差 | 走 2.3 闸门的 C 兜底，**但须回报批准**（不默认降级） |
| tsu 内 mount 需 CAP_SYS_ADMIN | 已具备（root + ksu 域）；失败 fail-closed |
| **mount 传播泄漏**（`/` 是 shared:1） | **unshare 后必须立刻 `MS_REC\|MS_PRIVATE`**，禁止只 unshare；已实证（`ns-isolation-ebd7d915.md`），构造器里该序列不可省略、不可降级 |
| 每会话开销 | unshare+mount+材料复制实测（材料约 MB 级，预计 ms 级）；大材料改 bind 只读替代复制 |
| 兼容性：旧 `--vtz` 语义变化 | 无 sidecar 时自建而非报错；文档与 `--help` 同步 |
| 审计写失败阻断启动 | 这是设计选择（fail-closed）；若影响可用性，登记为「可接受降级」需显式批准 |
