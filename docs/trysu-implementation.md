# TrySU 实现状态（V0a 基线）

> **文档性质**：本文只记录**实现状态与可执行判据**，不定义架构。
> 架构结论一律以仓库根目录的 [`TrySU.md`](../TrySU.md)（三世界 `W` / `N` / `VN` + 十二公理）为准。
>
> **旧体系文档已统一作废（2026-11-12）**：`SUVTZ.md`、`docs/suvtz-v*.md`、
> `docs/suvtz-p0-baseline.md`、`docs/vtzsu-design.md` 不再作为任何设计、判据、
> 验收或实现的依据，仅作历史取证保留。本文不从它们继承结论，只继承**事实**
> （设备实测数据），并按新坐标重述。

**坐标转换（读代码/旧取证时必用）**：旧体系的 `W`（私有 mount ns、root 执行
处）在新坐标下是 **`VN`**；新 `W` 是权限仲裁者，旧体系没有对应物。代码里的
路径名 `.w`、变量 `vtz_w.pid`、开关 `--vtz` 是历史命名，语义上属于 `VN`。

---

## 1 当前实现做到了什么

一句话：**`VN` 雏形 + 入口雏形 + 事后记录**。

- `VN` 雏形：restore（`u:r:kernel:s0`，uid 0）在 `/data/local/tmp/.w` 建立一个
  私有 mount ns 快照并长期持有，sidecar `/data/local/tmp/vtz_w.pid` 记录
  `<pid> <mnt-ns-inode>`。
- 入口雏形：`su --vtz` 经 `ksud` 的 allowlist 准入后进入该 ns 执行；这是
  `VN` 唯一的跨界入口，带 W/VN 侧访问记录。
- 事后记录：`VN` 侧 `/data/local/tmp/.w/log/access.log` 追加 `kind=enter` 行；
  `N` 侧同一路径不可见。

**没有做到的**（架构级，不是缺 feature）：`W` 尚无独立强制力（加冕、仲裁、
恢复都由既有 KernelSU 驱动 + 用户态脚本拼出）；三层结构性隔离不成立
（见 §4）。

---

## 2 可执行判据（V1–V10）

一次冷 boot + `tools/postlock.sh` 之后，跑 `tools/suvtz/v0a_rows.sh`
（脚本名是历史命名，输出即下表）。**判定口径**：V0a 成立 = 下表全绿，
且 sidecar 必须由 restore 自带路径写出（手工写入只能证明消费侧）。

| # | 判据 | 期望 |
|---|---|---|
| V1 | sidecar 存在且与 holder 一致 | `cat /data/local/tmp/vtz_w.pid` → `<pid> <inode>`，`/proc/<pid>/ns/mnt` 的 inode 相等 |
| V2 | 会话在 `VN` 里 | `su --vtz -c 'readlink /proc/self/ns/mnt'` == holder ns |
| V3 | 对照：不带开关仍在 `N` | `su -c 'readlink /proc/self/ns/mnt'` **不相等**（V0a 阶段这是正确结果） |
| V4 | `VN` 侧记录产生 | `su --vtz -c 'cat /data/local/tmp/.w/log/access.log'` 有本次 `kind=enter` 行 |
| V5 | `N` 侧不可见 | `N` 侧（shell 域）`ls /data/local/tmp/.w/log` → `ENOENT` |
| V6 | 功能未退化 | `su --vtz -c 'ls /system /data /apex'` 正常 |
| V7 | `-M` 优先级 | `su -M --vtz -c …` 走 init ns（`-M` 覆盖 `--vtz`） |
| V8 | 失败语义 | 删 sidecar → 硬失败「no W registered」，rc≠0；恢复后复跑正常 |
| V9 | 世界 inode 对照 | `VN` 侧 root ns vs `N` 侧 root ns 两个不同 inode |
| V10 | 观测面回归 | `tools/suvtz/scan.sh -q` 仍 `FAIL=0（已接受 3）PASS=37 INFO=0` |

### 2.1 已验收轮：boot `11e3bdc8`（2026-11-11，原生轮全绿）

一轮 fresh boot（`MAX_ATTEMPTS=1 FIRST_REBOOT=1`）全通过，无人工介入：

- **生产侧**：restore 自己写出 `suvtz-w: sidecar pid=32510 inode=4026534014 mode=644`，
  无 `WARN-suvtz-w-sidecar-write`；`mountpoint=yes` / `exec=yes` 同轮成立。
- **消费侧**：V1–V10 全绿（`docs/forensics/vtz-v0a-11e3bdc8/rows.log`）：
  V1 `32510 4026534014` 0644 + holder live ns 同值；V2 `mnt:[4026534014]`、
  `uid=0 … context=u:r:ksu:s0`；V3 `mnt:[4026533362]`；V4/V10 `kind=enter` 累计 5 条；
  V5 shell 域 `ENOENT`；V6 `/`、`/system`、`/data`、`/apex` 全 ok、`mods=200`；
  V7 `mnt:[4026533362]`；V8 rc=1 `no W registered` + `os error 2`，恢复后
  `[32510 4026534014]`；V9 `4026534014` vs `4026533362`。
- **链与恢复**：`pipe-physrw-summary done=1 root=1` ×3、`route done calls=1 success=1`、
  `CHAIN_EXIT_DONE`；`SELINUX-STRICT-OK enforce=1` + `POSTLOCK-RESTORE-OK` 双 OK 原生；
  verify `uid=0 … u:r:ksu:s0` / `kernelsu Live`。
- **稳定**：boot_id 自链完成起 ≥5 分钟不变（uptime 536s 复核），`enforce=1`。
- 取证：`docs/forensics/vtz-v0a-11e3bdc8/`（`rows.log`、`restore.log`、
  `postlock.log`、`chain_markers.log`、`boot.txt`、`ui_blue.png`）。

**结论**：`VN` 进入路径在生产侧与消费侧同时成立，可作 V0b（`su` 默认进 `VN`）
的基线。

### 2.2 两条观察侧限制（避免下轮误判）

- shell 域读 `/proc/<pid>/ns/mnt` 与 `/proc/1/ns/mnt` 均被 SELinux 拒
  → holder/init 的 ns 一律经 `su` 读取。
- restore 自己（`u:r:kernel:s0`）裸用 `su` 恒被拒（`suvtz-w: su-gate closed`）
  **是预期**：sucompat 只对 allow-list uid 改写语义，且 uid 0 仅在 `u:r:ksu:s0`
  域内被判 allowed；`kernel` 域两个条件都不满足。`su --vtz` 由 shell 域
  （uid 2000，allowed）发起，不走这条门 —— 与 V2 通过不矛盾。
  日志用 `domain=` 字段区分：`domain=other` 属常态。

---

## 3 差异清单

| 项 | 现在 | V0a（已达成） | V0b（目标） |
|---|---|---|---|
| SU 会话的 mnt ns | 调用者的（`N`） | `--vtz` 时 `VN`，默认仍 `N` | 默认 `VN` |
| 世界标记 | `TIF_PROC_UMOUNTED`（run-as 打不上） | `mnt_ns` inode（内核记账） | 同左 |
| 进入 `VN` 的方式 | `wns run <pid> <cmd>`（无准入） | `ksud root_shell()` 的 `--vtz` 分支（allowlist 准入） | 同左，且为默认 |
| 入口记录 | 无 | `VN` 侧 `access.log` | 同左 |
| `-M` 语义 | 进 init ns | 不变，且优先于 `VN` | 同左 |
| `wns` 的地位 | 通用入口 | restore 内部工具（不再是第一公民入口） | 同左 |

---

## 4 与十二公理的对照（诚实版）

| 公理 | 本环境状态 |
|---|---|
| 一 权限归属 | ❌ `W` 无独立强制力：授权落在既有 KernelSU 驱动的 allowlist，仲裁与恢复由用户态脚本拼出 |
| 二 正常归属 | ❌ `N` 仍承载 Root（`su` 默认会话在 `N`；模块/overlay 直接进 `N` 视图） |
| 三 执行归属 | ⚠️ 部分：`su --vtz` 提供了「Root 在 `VN` 执行」的路径，但默认仍不在 |
| 四 映射关系 | ⚠️ `VN` 是 `N` 的 ns 快照（雏形），不是有独立生命周期的映射层 |
| 五 / 六 / 七 / 八 | ❌ **不成立**——由公理十一缺失直接推出（见下） |
| 九 唯一入口 | ⚠️ `su --vtz` 是唯一入口雏形；但 allow-list app 仍可各自 `scan_driver_fd()` 持 `W` 句柄 |
| 十 单向信任 | ❌ 管理器/观测面仍靠读 `/proc`、属性、文件推断状态 |
| 十一 信任链前提 | ❌ **不成立**：`W`（驱动）是 CVE 提权后 `late-load insmod`，启动链从未逐级验证过 `W` |
| 十二 可破坏与可恢复 | ⚠️ `VN` 可销毁重建（restore 每次冷 boot 新建），但「由 `N` 恢复、由 `W` 管理」尚未分离 |

**按公理十一，隔离命题在本环境不成立**：无可信启动链，则公理五～八（三层结构性
隔离）与公理十一**一律不成立**。这是架构前提缺失，补 feature 不能解决。

---

## 5 与工具的关系

| 工具 | 状态 |
|---|---|
| `tools/postlock.sh` | 恢复链入口（冷 boot 一条命令）；V0a 判据的生产侧就在它的 restore 段里 |
| `tools/suvtz/scan.sh` | 观测面 40 探针（`PASS` / `FAIL` / `INFO` + 已接受登记），与架构坐标无关，继续使用 |
| `tools/suvtz/v0a_rows.sh` | §2 判据的可执行版（脚本名历史命名） |
| `tools/suvtz/accepted.tsv` | 已显式裁决接受的暴露面登记表；接受不改判 `PASS` |
