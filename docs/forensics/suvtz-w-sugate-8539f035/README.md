# fresh boot `8539f035` —— su-gate in-band 判据验收（`PB-SUGATE` UNKNOWN → PASS）

**时间**：2026-11-11 06:09:18 起 → 06:13:14 `POSTLOCK-RESTORE-OK`（链 06:12:58 打出
`pipe-physrw-summary done=1 root=1` ×3 + `pselect route done calls=1 success=1`）；
06:15:33 判 `PASS (boot 稳定 120s)`
**执行者**：host 侧 `tools/postlock.sh`（`/tmp/opencode/accept_watch/run4.sh` 驱动，
本轮第 2 次尝试）
**主仓 HEAD**：`64995cc2`；restore heredoc 生成物 = 35989B / 610 行 / sha1 `78ff1235…`
**boot reason**：`reboot`（attempt 1 判失败后主动 reboot 换 fresh boot，**不是 panic**）

## 为什么这一轮重要

上一轮（`c0a9c70b`）Phase B 物料迁移验收通过，但 `PB-SUGATE` 判 UNKNOWN——旧版
restore 的 su 门控是**静默**的：`test -x /system/bin/su` 在 `kernel:s0` 域看到真实缺失
的文件（`su` 实体已于 2026-11-09 退役），门控恒假，一行日志都不打，核对器无从取证。

本轮验证的是**门控改造后 in-band 可观测**：恢复流程里第一次打出

```
suvtz-w: su-gate closed (domain=other su-visible=no; sucompat excludes uid 0 outside ksu domain)
```

——与源码定案一致（`../BakaSU/kernel/policy/allowlist.c:129` `forbid_system_uid`
对 uid 0 为真；`feature/sucompat.c:194` 的 stat 假象与 execve 改写都以
`__ksu_is_allow_uid_for_current(0)` = `is_ksu_domain()` 门控 ⇒ **uid 0 只在
`u:r:ksu:s0` 内被放行**；restore 永远是 `u:r:kernel:s0`）。判据从「观测不到」变成
「观测到它确实是关的」。

## 判据（三套核对器，全部跑真产物）

### 1. 主判据 `tools/suvtz/check_accept.sh`（17 项）

```
PASS    RETIRE-0 [8539f035 06:13:08] suvtz: overlay-retired mounts=0
PASS    RETIRE-RESID no WARN-suvtz-overlay-residual
PASS    RETIRE-NOBUILD overlay 创建块已删除（mount -t overlay 计数 0）
PASS    W-HOLDER [8539f035 06:13:00] suvtz-w: holder pid=28006 ns=mnt:[4026534130] mp=/data/local/tmp/.w by=kernel
PASS    W-NS     ns 已解析（非 unknown）
PASS    W-BY     by=kernel（direct kernel:s0 优先路径成功）
PASS    W-MP     [8539f035 06:13:01] suvtz-w: mountpoint=yes
PASS    W-EXEC   [8539f035 06:13:01] suvtz-w: exec=yes
PASS    W-NABSENT [8539f035 06:13:01] suvtz-w: n-side-absent stage=ENOENT
PASS    RESTORE-OK POSTLOCK-RESTORE-OK x1
PASS    STRICT-OK SELINUX-STRICT-OK x1
PASS    EXIT0    postlock.sh rc=0
PASS    SU-PROBE [host-verify] probe: uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
PASS    CHAIN-ROOT done=1 root=1 x3
PASS    CHAIN-ROUTE route done success=1
PASS    SCAN     FAIL=0 (另有已接受 3)  PASS=37  INFO=0  总计=40  runas=ok
PASS    HIDE-OFF 退役块已执行 ⇒ hide 0 已静默下发（同段，无独立日志）

== summary: PASS=17 FAIL=0 UNKNOWN=0 ==
RESULT: OK（无 FAIL）
```

完整输出见 `check_accept.txt`。

### 2. Phase B 判据 `tools/suvtz/check_phaseb.sh`（6 项）

```
PASS    PB-STAGE   [8539f035 06:13:02] suvtz-w: staged ocsk=1 pub=1 pp=1 hotload=0
PASS    PB-OCSK    [8539f035 06:13:02] oplus_check_suppress-finitmod-ok-w
UNKNOWN PB-PUB     adb_keys 已含 postlock_bootstrap，本轮未走 append 路径
UNKNOWN PB-PP      persistent_properties 已含该键，本轮未走 append 路径
PASS    PB-SUGATE  [8539f035 06:13:00] suvtz-w: su-gate closed (domain=other su-visible=no; sucompat excludes uid 0 outside ksu domain)
PASS    PB-HOTLOAD [8539f035 06:13:02] hotload-skipped-late-init-selfsufficient

PASS=4 FAIL=0 UNKNOWN=2 总计=6
```

**`PB-SUGATE` 本轮由 UNKNOWN 转 PASS**（上一轮 PASS=3）。剩余两个 UNKNOWN 是
**幂等跳过的必然结果**：`adb_keys` 与 `persistent_properties` 上一轮已写好，append
块整体跳过，因此没有 `suvtz-w: appended …` 行——它们由 out-of-band `cksum` 覆盖。

### 3. 传输保真（out-of-band `cksum`，`phaseb_oob.sh`）

```
boot=8539f035…  holder_pid=28006  holder_ns=mnt:[4026534130]
n_side_stage=ENOENT  ocsk=loaded
OK oplus_check_suppress.ko  cksum=1995826726 238160
OK postlock_adbkey.pub      cksum=2123509450 719
OK pp_adb_tcp.bin           cksum=2332106405 30
RESULT=PASS (W copies byte-identical to N originals)
```

即 `W` 里的三件物料与 `N` 原件逐字节一致，而 `N` 侧 `stage` 目录本身是 `ENOENT`
（消费真发生在 `W`，不是回落到 `N`）。

## 本轮 attempt 1 失败（已知家族，判明即 reboot）

boot `18f3eac7`（fresh，未跑过链）05:59:55：

```
pipe-physrw-summary done=0 root=0 read_ok=0 write_ok=0 uid=4294967295->4294967295
cfgfs write set-fail errno=25 (ENOTTY) ×N
ks_neutralize … owner=-1 tail=-1 ok=0 verified=0
exit tail: neutralize FAILED (no pipe child); fd-hold containment, guard -> real-table recovery
fd-hold daemon pid=29560 holding all chain fds … reboot before any re-run
CHAIN_EXIT_DONE
```

= **payload 页死 → fail path 写不进 → fd-hold 收容**（AGENTS 记录的结构性抽签家族）。
该 boot 带 fd-hold 残留，按规则判明即 reboot；attempt 2 fresh boot 一次过。
本存档只保留 attempt 2 的产物（`a1/` 原件在 `/tmp/opencode/accept_watch4/a1/`）。

## 稳定性

- 链后 boot_id 始终 `8539f035-d22f-42ab-b860-54c741990656`；取证时 uptime **631s**，
  收尾复核 uptime **942s** / `Enforcing` 仍是同一 boot（链 06:12:58 跑完，即链后 10 分钟以上）。
- `modules=/sys/module/kernelsu /sys/module/oplus_check_suppress`；
  `kernelsu_hotload_init` = absent（late-init 自给，legacy 按设计不加载）。
- ocsk v14：`kill.scan sites=2`（`do_group_exit` 判据）、`ret.kill ret=0` ×2、
  `rep armed=2`，零 `WARN-…-rep-not-armed-popup-risk`。

## 状态卡（uiautomator 文本，截图 `ui_blue.png`）

```
工作中 / Built-in / 越狱模式
1 个超级用户, 0 个模块
SuSFS 版本 v2.3.0
管理器版本 v4.2.0-rc3 (35252/6)
内核驱动版本 v4.2.0-rc3-5b76b884-dirty@BakaSU (35222/6)
Android 版本 12 / 内核版本 5.4.254-qgki-g977b99b1fbb9
```

驱动 UAPI 6 == 管理器 UAPI 6 ⇒ 无红条；「越狱模式」是**真实状态**（模块确实
late load，真协议修复后的应有表现）。「0 个模块」= `/data/adb/modules` 为空
（用户侧早已卸载全部模块），不是驱动问题。

## 通道

本轮唯一可用 adb = **私有 server `adb.exe -P 5038`**（`/tmp/opencode/adb5038.sh`），
Windows 侧 5037 server 对本设备的 tailnet transport 已坏（`connect` 报成功但数秒
后 transport 消失）。attempt 2 reboot 后通道 **94s** 恢复（06:07:33 → 06:09:07）。
`adb devices` 同时列出 `401e909a`（非本项目，勿动），所有命令都带 `-s`。

## 文件清单

| 文件 | 内容 |
|---|---|
| `chain.log` | 链完整日志（238756B，attempt 2） |
| `restore.log` | restore 完整日志（suvtz-w / ocsk state / strict flip） |
| `postlock.log` | host 侧 postlock.sh 输出（stage / quiet gate / verify） |
| `verdict.txt` | 本轮判决（`postlock_rc=0` 独立行 + 各判据计数） |
| `watch.log` | run4.sh 两次尝试的时间线 |
| `check_accept.txt` | 主判据 17 项 |
| `check_phaseb.txt` | Phase B 6 项 |
| `phaseb_transfer.txt` | out-of-band `cksum` 传输保真 |
| `scan.txt` | 40 探针（`FAIL=0（另有已接受 3）PASS=37 INFO=0 runas=ok`） |
| `ui_blue.png` | 管理器官网状态卡截图 |
