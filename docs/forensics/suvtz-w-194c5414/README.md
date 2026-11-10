# SUVTZ v3 fresh-boot acceptance — boot `194c5414`（通过）

2026-11-10 06:16:17 → 06:18:05（约 108 秒，零人工），执行者 = host 侧
`tools/postlock.sh`（`SERIAL=100.120.155.127:5555`），APK 侧 vc84/1.84 仅提供
WAN 通道。本轮验收对象 = **入口收敛第 1 项（`/product/bin` overlay 退役）**
+ **结构性隔离第 1 项（`W` 独立 mount namespace：holder + 边界断言 + 扫描器
`W1`-`W5`）**。

## 结果

| 项 | 实测 |
|---|---|
| stage | 全 `unchanged`（含 `wns`），`quiet after 5s (load=3.07) -> GO`，`DETACHED` 06:16:22 |
| 链 | `pipe-physrw-summary pid=15287 done=1 root=1 kaslr=1 base=ffffffe711a80000 slide=0000002701a00000`（×3）+ `CHAIN_EXIT_DONE` |
| 退役块 | `suvtz: overlay-retired mounts=0`（fresh boot 期望值）；无 `WARN-suvtz-umount` / `WARN-suvtz-overlay-residual` |
| holder | `suvtz-w: holder pid=5970 ns=mnt:[4026534144] mp=/data/local/tmp/.w by=kernel` + `mountpoint=yes` + `n-side-absent stage=ENOENT`，零 `WARN-suvtz-w-*` |
| restore | `SELINUX-STRICT-OK enforce=1 probe=host-verify` + `POSTLOCK-RESTORE-OK` 各 1 次**原生** |
| verify | `OK:` `uid=0 context=u:r:ksu:s0` + `kernelsu Live` + `manager uid=10277` + `wrap=空` |
| SUVTZ scan | `FAIL=0 (另有已接受 3) PASS=37 INFO=0 总计=40 runas=ok`（有 holder 口径） |
| check.sh | `PASS=16 FAIL=0 UNKNOWN=0` / `RESULT: OK（无 FAIL）` |
| 稳定性 | boot `194c5414` 全程未变（120s+） |
| 管理器 | 蓝卡 `工作中` / `Built-in` / `越狱模式` / `1 个超级用户, 0 个模块`；驱动 `(35222/6)` == 管理器 `(35252/6)`；`SELinux 强制执行`；`SuSFS v2.3.0` |

**`by=kernel` 是本轮的关键判据**：生产 restore（`kernel:s0`）自己
`unshare(CLONE_NEWNS)` 成功，**未走 `su -c` 回落**（回落会依赖 ocsk 先加载）。
这也补上了此前「本 boot 无法自造 `kernel:s0` 进程预演」留下的唯一未验证路径。

**「已接受」由 4 降为 3**：扫描器 `B4`（`/product/bin/su`）退役后对象不存在，
自然转 PASS；`accepted.tsv` 的登记行保留作回归兜底。

## 文件

| 文件 | 说明 |
|---|---|
| `postlock.log` | host 侧 `postlock.sh` 完整输出（含退役块、holder 段、verify） |
| `postlock_chain.log` | 链日志全文（374983B） |
| `postlock_restore.log` | restore 日志（`kernel:s0`，双 OK 原生） |
| `verdict.txt` | 判读主入口（`postlock_rc=0`、`boot_before/after`、计数、`suvtz-w lines`、`overlay-retire lines`） |
| `check.txt` | `tools/suvtz/check_accept.sh` 16 项判据输出 |
| `scan_194c5414.txt` / `.tsv` / `stdout.txt` / `stderr.txt` | 40 探针扫描产物（有 holder 口径） |
| `watch.log` / `watch.sh` | 后台验收编排日志与脚本 |
| `ui2.xml` / `ui_blue.png` | 管理器状态卡 dump（文本判据）与截图（视觉证据） |

## 相关前序轮

同批次的第 1 轮（boot `07fd47ff`）= panic，属已知 **`filp_close` fail amplifier**
家族（`Comm: pipe_prepare` / `pc:0x0` / `lr:filp_close+0x54` / `Oops:86000005` /
NULL deref at 0）：`restore` 从未 fork，退役块与 holder 段完全未执行 →
**非本轮代码回归**。取证在 `/tmp/opencode/accept_watch/boot07fd47ff/`（未入库，
pstore 264802B）。处置 = fail amplifier reboot 重抽。

## 复现

```bash
SERIAL=100.120.155.127:5555 timeout 1800 bash tools/postlock.sh
bash tools/suvtz/check_accept.sh /tmp/opencode/accept_watch/boot<boot8>
```
