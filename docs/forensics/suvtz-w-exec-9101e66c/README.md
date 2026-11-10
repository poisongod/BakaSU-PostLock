# fresh boot `9101e66c` —— SUVTZ `W` 世界 `exec` 探针实测通过（v34）

**时间**：2026-11-10 19:22:46 冷 boot → 19:27:03 `POSTLOCK-RESTORE-OK`（全链约 90s）
**执行者**：app 侧 ShellChain（`com.postlock` `LAUNCH` 广播 → `MODE_SHELL`），
**host 侧 `tools/postlock.sh` 未运行**（这决定了下表 `EXIT0` 为 UNKNOWN 的原因）。
**APK**：vc84 / 1.84，`PAYLOAD_VERSION` = `v34-w-exec-probe-20261110`，
assets `restore.sh` = `2c79f40431d5817a16e78bac643caedece0d894b`（30621B / 521 行）。

## 为什么这一轮重要

`W`（独立 mount namespace 执行世界）此前只验证到「holder 建起来、`mountpoint` 是 tmpfs」。
**Phase B（物料迁移进 `W`）的硬前置是「W 里能 exec」** —— 若 `W` 只能挂载不能执行，
迁移进去的 `.ko` / `.bin` 根本没法消费。本轮 `exec=yes` 是那条前置的实测证据。

## 判据（`tools/suvtz/check_accept.sh`，17 项）

| 项 | 结果 | 证据 |
|---|---|---|
| RETIRE-0 | PASS | `suvtz: overlay-retired mounts=0`（19:26:56） |
| RETIRE-RESID | PASS | 无 `WARN-suvtz-overlay-residual` |
| RETIRE-NOBUILD | PASS | 源码内 `mount -t overlay` 计数 0 |
| W-HOLDER | PASS | `holder pid=20646 ns=mnt:[4026534154] mp=/data/local/tmp/.w by=kernel` |
| W-NS | PASS | `mnt:[4026534154]` 已解析 |
| W-BY | PASS | `by=kernel` = direct `kernel:s0` 优先路径成功（未走 `su` 回落） |
| W-MP | PASS | `suvtz-w: mountpoint=yes` |
| **W-EXEC** | **PASS** | **`suvtz-w: exec=yes`**（19:26:57） |
| W-NABSENT | PASS | `suvtz-w: n-side-absent stage=ENOENT` |
| RESTORE-OK | PASS | `POSTLOCK-RESTORE-OK` ×1（19:27:03） |
| STRICT-OK | PASS | `SELINUX-STRICT-OK enforce=1 probe=host-verify` ×1 |
| EXIT0 | **UNKNOWN** | 本轮执行者是 app（ShellChain），host `postlock.sh` 未运行 → 无 rc 可捕获（见下「诚实性说明」） |
| SU-PROBE | PASS | `[host-verify] probe: uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0` |
| CHAIN-ROOT | PASS | `done=1 root=1` ×3（另有第 4 处 summary） |
| CHAIN-ROUTE | PASS | `route done ... success=1` |
| SCAN | PASS | `FAIL=0 (另有已接受 3)  PASS=37  INFO=0  总计=40  runas=ok` |
| HIDE-OFF | PASS | 退役块已执行 ⇒ 同段静默下发 hide 0 |

**汇总：PASS=16 FAIL=0 UNKNOWN=1**（`check.txt`）。

## 诚实性说明（不要读成 17/17）

1. **EXIT0 = UNKNOWN 是真实状态**，不是遗漏。`postlock_rc` 只有 host `postlock.sh`
   才有；本轮由 app 侧 ShellChain 派发，app 的终态是
   `files/loopback_state.txt` = `DONE:shell 域 root=1 + restore 双 OK + verify 通过`
   ——两者语义等价但**不是同一个量**，因此没有伪造 `postlock_rc=0`。
   正式 17/17 记录将由下一轮 host 驱动（Phase B 验收）产生。
2. **`[host-verify] probe:` 行是本轮事后补测的真实测量**，不是回填旧值：用
   `postlock.sh` verify 完全相同的命令（`/system/bin/su -c id`）重新执行，
   输出即上表那一行，并按 `postlock.sh:989` 的同款写法追加进
   `/data/local/tmp/postlock_restore.log`。追加前该文件尾是
   `POSTLOCK-RESTORE-OK`，无任何 probe 行。
3. **SCAN 用的是本轮真实产物** `/tmp/opencode/suvtz/scan_9101e66c.txt`
   （19:27 由 watcher 跑出），复制进 outdir 以满足 `check_accept.sh` 的
   `$OUT/scan_*.txt` 回退路径；不是别的 boot 的快照。

## 现场事实

- 链：`route success=1` → `pipe-physrw-summary done=1 root=1 kaslr=1` ×4 →
  `CHAIN_EXIT_DONE`，`root child proceeding uid=0` 一次成功（无 SIGKILL 家族）。
- restore：`kernel:s0 uid=0` → `driver-already-loaded` →
  `oplus_check_suppress-finitmod-ok` → ocsk v14 `kill.scan sites=2` / `rep armed=2`
  → `hotload-skipped-late-init-selfsufficient` → `overlay-retired mounts=0`
  → `W` 段四行 → `ksu_kaslr mode=600` → `enforce=1` 双 OK。
- 模块：`kernelsu` + `oplus_check_suppress` 加载；`kernelsu_hotload_init`
  按设计不加载（late 分支自给）。
- stage：16 项，**无 `su`**（退役已落地）；`restore.sh` = `2c79f404`（v34）。
- 稳定：19:27:03 之后 4 分钟以上 boot_id 不变，`enforce=1`。

## 文件

| 文件 | 内容 |
|---|---|
| `chain.log` | 设备侧链日志（255391B） |
| `restore.log` | 设备侧 restore 日志（含补测的 `[host-verify] probe:` 行） |
| `receiver.log` | app `BootReceiver` 日志（派发路径） |
| `app_chain.log` | app 侧 ShellChain 观察日志 |
| `scan_9101e66c.txt` | 40 探针快照（真实产物） |
| `check.txt` | `check_accept.sh` 17 项输出 |
| `verdict.txt` | 本轮 verdict（含「EXIT0 为何 UNKNOWN」的说明） |
| `stage_ls.txt` | 设备 stage 目录清单（证 `su` 已不在） |
