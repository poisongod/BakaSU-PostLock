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

一句话：**`VN` 雏形 + `N`→`VN` 进入通道 + 事后记录**（`W` 侧尚无实现）。

- `VN` 雏形：restore（`u:r:kernel:s0`，uid 0）在 `/data/local/tmp/.w` 建立一个
  私有 mount ns 快照并长期持有，sidecar `/data/local/tmp/vtz_w.pid` 记录
  `<pid> <mnt-ns-inode>`。**文件名里的 `w` 是历史命名，它记录的是 `VN` holder**。
- `N`→`VN` 进入通道：`su --vtz` 先由**内核驱动**（sucompat 的
  `ksu_is_allow_uid_for_current`）判定准入，再由 `ksud` 做 mnt ns 切换后执行，
  并在 `VN` 侧写记录。这属于**公理一**（`W` 控制 `VN` 的映射与入口）的雏形，
  **不是公理九的 `VN`→`W` 入口**——两者方向相反，勿混。
- 事后记录：`VN` 侧 `/data/local/tmp/.w/log/access.log` 追加 `kind=enter` 行；
  `N` 侧同一路径不可见。

**没有做到的**（架构级，不是缺 feature）：

- **`W` 没有世界边界**。权限判定确实落在内核驱动里（可视为 `W` 的内核载体），
  但：`ksud`（做切换、写记录）跑在 `N`；`VN` 的建立与恢复由 restore
  （`u:r:kernel:s0`）执行，既不属于 `W` 也不属于不持权的 `N`；**任意
  allow-list 进程都能自行 `scan_driver_fd()` 拿到同一个 `W` 内核 fd 并调用
  全命令集**（含 `GET_INFO` 这类观测面）——这正是公理九/十要排除的形态。
- **`VN` 只有 mount ns 一个维度**（缺 pid/net/user/ipc/uts），不具备 `N` 的
  「一切性质」，也没有任何完整性校验。
- 三层结构性隔离不成立（见 §4）。

---

## 2 可执行判据（V1–V10）

一次冷 boot + `tools/postlock.sh` 之后，跑 `tools/suvtz/v0a_rows.sh`
（脚本名是历史命名，输出即下表）。**判定口径**：V0a 成立 = 下表全绿，
且 sidecar 必须由 restore 自带路径写出（手工写入只能证明消费侧）。

> **编号说明**：`V0a` / `V1`–`V10` 是**实施编号**，不是架构坐标（架构坐标只有
> `W` / `N` / `VN`）。判据里的历史路径名（`.w`、`vtz_w.pid`、`--vtz`）语义上都
> 属于 `VN`，见文首坐标转换。

| # | 判据 | 期望 |
|---|---|---|
| V1 | sidecar 存在且与 holder 一致 | `cat /data/local/tmp/vtz_w.pid` → `<pid> <inode>`，`/proc/<pid>/ns/mnt` 的 inode 相等 |
| V2 | 会话在 `VN` 里 | `su --vtz -c 'readlink /proc/self/ns/mnt'` == holder ns |
| V3 | 对照：不带开关仍在 `N` | `su -c 'readlink /proc/self/ns/mnt'` **不相等**（V0a 阶段这是正确结果） |
| V4 | `VN` 侧记录产生 | `su --vtz -c 'cat /data/local/tmp/.w/log/access.log'` 有本次 `kind=enter` 行 |
| V5 | `N` 侧不可见 | `N` 侧（shell 域）`ls /data/local/tmp/.w/log` → `ENOENT` |
| V6 | 功能未退化 | `su --vtz -c 'ls /system /data /apex'` 正常 |
| V7 | `-M` 优先级 | `su -M --vtz -c …` 走 init ns（`-M` 覆盖 `--vtz`） |
| V8 | 失败语义 | 删 sidecar → 硬失败「no W registered」，rc≠0；恢复后复跑正常。该报错串是**历史命名**，语义是「`VN` holder 未注册」（代码未改名） |
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

**结论**：`N`→`VN` 的进入通道在生产侧与消费侧同时成立，可作 V0b（`su` 默认进
`VN`）的基线。**这不等于公理九成立**——`VN`→`W` 的服务入口仍不存在（见 §4）。

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
| 世界标记（判定会话所在世界） | `TIF_PROC_UMOUNTED`（旧体系标记，run-as 打不上） | `mnt_ns` inode（内核记账） | 同左 |
| 进入 `VN` 的方式 | `wns run <pid> <cmd>`（无准入） | `ksud root_shell()` 的 `--vtz` 分支（准入在内核驱动 sucompat，`ksud` 只做 mnt ns 切换） | 同左，且为默认 |
| 入口记录 | 无 | `VN` 侧 `access.log` | 同左 |
| `-M` 语义 | 进 init ns | 不变，且优先于 `VN` | 同左 |
| `wns` 的地位 | 通用入口 | restore 内部工具（不再是第一公民入口） | 同左 |

---

## 4 与十二公理的对照（诚实版）

| 公理 | 本环境状态 |
|---|---|
| 一 权限归属 | ❌ 权限判定落在内核驱动（`W` 的内核载体），但 `W` 没有世界边界：`ksud` 在 `N` 里做切换、restore（`u:r:kernel:s0`）在 `W`/`N` 之外重建 `VN`，且任意 allow-list 进程可自取 `W` 内核 fd 调全命令集 |
| 二 正常归属 | ❌ `N` 仍承载 Root（`su` 默认会话在 `N`；模块/overlay 直接进 `N` 视图） |
| 三 执行归属 | ⚠️ 部分：`su --vtz` 提供了「Root 在 `VN` 执行」的路径，但默认仍不在 |
| 四 映射关系 | ⚠️ 只有 mount ns 一个维度（缺 pid/net/user/ipc/uts），不具备 `N` 的「一切性质」，且无完整性校验 |
| 五 / 六 / 七 / 八 | ❌ **不成立**——由公理十一缺失直接推出（见下） |
| 九 唯一入口 | ❌ **不存在 `VN`→`W` 的服务入口**。现状是 allow-list 进程各自持 `W` 内核 fd、可调全命令集（含 `GET_INFO` 观测 `W` 状态）。`su --vtz` 是 `N`→`VN` 的进入通道（公理一范畴），不是本条入口 |
| 十 单向信任 | ❌ 无「只接受服务请求」的边界：任意 allow-list 进程持 fd 后可调全命令集（`GET_INFO`/`GET_ALLOW_LIST` 等读取面）；管理器靠读 `/proc`、属性、文件推断 `W` 状态 |
| 十一 信任链前提 | ❌ **不成立**：`W`（驱动）是 CVE 提权后 `late-load insmod`，启动链从未逐级验证过 `W` |
| 十二 可破坏与可恢复 | ⚠️ `VN` 可销毁重建（restore 每次冷 boot 新建，且不依赖 `VN` 内任何代码 ✓），但恢复执行者 = restore（`u:r:kernel:s0`），既非 `N` 也非 `W`，「由 `N` 恢复、由 `W` 管理」尚未分离 |

**按公理十一，隔离命题在本环境不成立**：无可信启动链，则公理五～八（三层结构性
隔离）与公理十一**一律不成立**。这是架构前提缺失，补 feature 不能解决。

---

## 5 与工具的关系

| 工具 | 状态 |
|---|---|
| `tools/postlock.sh` | 恢复链入口（冷 boot 一条命令）；V0a 判据的生产侧就在它的 restore 段里 |
| `tools/chain/entry.sh` | **shell 域全链唯一入口**（device-side）：`postlock.sh` 与 PostLock app 的「执行恢复链」共用同一份；两边只负责部署 stage + 写 `chain.env` |
| `tools/suvtz/scan.sh` | 观测面 40 探针（`PASS` / `FAIL` / `INFO` + 已接受登记），与架构坐标无关，继续使用 |
| `tools/suvtz/v0a_rows.sh` | §2 判据的可执行版（脚本名历史命名） |
| `tools/suvtz/accepted.tsv` | 已显式裁决接受的暴露面登记表；接受不改判 `PASS` |

### 5.1 shell 域全链的唯一入口

`tools/chain/entry.sh` 是设备侧**唯一**实现，版本标记 `CHAIN_ENTRY_VERSION=1`。

调用方（主仓 `tools/postlock.sh`、PostLock app 的 `ShellChain`）只做三件事：

1. 把 stage 物料放到 `/data/local/tmp/ksu_boot/`（`preload.so` / `ksud` / `finitmod` /
   `kernelsu.ko` / `restore.sh` …）；
2. 写 `$STAGE/chain.env`（**只放本次覆盖项**，如 `SUVTZ_CHAIN_LOG_MODE`、
   `KS_RUN_KSUD_EVENTS`、`KS_LAYOUT_PVO/VM`）；
3. 执行 `sh $STAGE/chain_entry.sh start`，等 stdout 出现 `DETACHED`。

基线环境、日志权限、现场清理、`nohup` detach、`KS_COLDSTART` 载体全部在入口脚本里，
两边不再各写一份 `trigger.sh` 生成逻辑。两侧都会断言 `CHAIN_ENTRY_VERSION`，
一边新一边旧时直接失败而不是带病起链。

app 侧副本在 `PostLock-Boot/postlock-app/app/src/main/assets/postlock/chain_entry.sh`，
是主仓文件的逐字节副本：**改动必须先改主仓再复制**，并在两仓同时 bump 版本。
