# fresh boot `c0a9c70b` —— SUVTZ Phase B（物料迁入 `W` 世界）第 1 轮验收

**时间**：2026-11-10 22:43:54 起 → 22:47:54 `POSTLOCK-RESTORE-OK`（restore 约 4m18s，
其中 2m41s 花在 idle gate 等 load 降到 4.86）
**执行者**：host 侧 `tools/postlock.sh`（本轮不是 app 派发；日志里
`==> check host artifacts` / `==> stage payloads` / `==> wait for restore` 是 host 脚本
自己的阶段标记）
**主仓 HEAD**：`7d0d95c3`；restore heredoc 生成物 = 35042B / 592 行 / sha1 `979a284f`
**boot reason**：`shutdown,battery`（上一轮电池耗尽关机后充电重启，**不是 panic**）

## 为什么这一轮重要

`W`（独立 mount namespace 执行世界）此前验证到「holder 建得起来、`mountpoint` 是
tmpfs、里面能 exec」（v34，见 `docs/forensics/suvtz-w-exec-9101e66c/`）。本轮是
**Phase B 第一轮**：把「纯 restore 消费」的三件物料真的搬进 `W` 并从 `W` 里消费，
同时**保留 N 侧副本作兜底**（可逆，WARN-only）。

## 判据（三套核对器，全部跑真产物）

### 1. 主判据 `tools/suvtz/check_accept.sh`（17 项）

```
PASS    RETIRE-0 [c0a9c70b 22:47:48] suvtz: overlay-retired mounts=0
PASS    RETIRE-RESID  no WARN-suvtz-overlay-residual
PASS    RETIRE-NOBUILD overlay 创建块已删除（mount -t overlay 计数 0）
PASS    W-HOLDER [c0a9c70b 22:47:41] suvtz-w: holder pid=30739 ns=mnt:[4026534126] mp=/data/local/tmp/.w by=kernel
PASS    W-NS     ns 已解析（非 unknown）
PASS    W-BY     by=kernel（direct kernel:s0 优先路径成功）
PASS    W-MP     [c0a9c70b 22:47:41] suvtz-w: mountpoint=yes
PASS    W-EXEC   [c0a9c70b 22:47:42] suvtz-w: exec=yes
PASS    W-NABSENT [c0a9c70b 22:47:42] suvtz-w: n-side-absent stage=ENOENT
PASS    RESTORE-OK POSTLOCK-RESTORE-OK x1
PASS    STRICT-OK SELINUX-STRICT-OK x1
PASS    EXIT0    postlock.sh rc=0
PASS    SU-PROBE [host-verify] probe: uid=0(root) ... context=u:r:ksu:s0
PASS    CHAIN-ROOT done=1 root=1 x3
PASS    CHAIN-ROUTE route done success=1
PASS    SCAN     FAIL=0 (另有已接受 3)  PASS=37  INFO=0  总计=40  runas=ok
PASS    HIDE-OFF 退役块已执行 ⇒ hide 0 已静默下发（同段，无独立日志）

== summary: PASS=17 FAIL=0 UNKNOWN=0 ==
RESULT: OK（无 FAIL）
```

### 2. Phase B 判据 `tools/suvtz/check_phaseb.sh`（6 项）

```
PASS    PB-STAGE   suvtz-w: staged ocsk=1 pub=1 pp=1 hotload=0
PASS    PB-OCSK    oplus_check_suppress-finitmod-ok-w
UNKNOWN PB-PUB     adb_keys 已含 postlock_bootstrap，本轮未走 append 路径
UNKNOWN PB-PP      persistent_properties 已含该键，本轮未走 append 路径
UNKNOWN PB-SUGATE  旧版 restore（静默门控，无 su-gate 行）：kernel:s0 看不到
                   /system/bin/su，门控结构性关闭但无 in-band 证据
PASS    PB-HOTLOAD hotload-skipped-late-init-selfsufficient

PASS=3 FAIL=0 UNKNOWN=3 总计=6
```

**三个 UNKNOWN 的成因（全部是「预期内观测不到」，不是失败）**：

- `PB-PUB` / `PB-PP`：`/data/misc/adb/adb_keys` 与
  `/data/property/persistent_properties` 早已 provisioned（含目标键），restore 里
  那两个 append 块是幂等的 `grep -qF ... || append` 形式，键已存在 ⇒ 整块跳过 ⇒
  `adb-keys-from-w` / `pp-from-w` 两行**根本不会打印**。用 out-of-band `cksum`
  补证（见下）。
- `PB-SUGATE`：本轮的 restore（`979a284f`）门控是**静默版**——它只写
  `if [ -x /system/bin/su ] && ...`，false 分支没有任何日志。而
  **在本设备上那个条件结构性为假**（见下节），所以日志里不可能有门控行。
  该行已在**本轮之后**改为 in-band 可观测（`suvtz-w: su-gate closed|open`），
  需要下一轮 fresh boot 复验才能转 PASS。

### 3. out-of-band 传输保真 `phaseb_oob.log`

```
boot=c0a9c70b-00aa-4e90-866a-20c618ebe72a
holder_pid=30739
holder_ns=mnt:[4026534126]
n_side_stage=ENOENT
ocsk=loaded

OK    oplus_check_suppress.ko  cksum=1995826726 238160
OK    postlock_adbkey.pub      cksum=2123509450 719
OK    pp_adb_tcp.bin           cksum=2332106405 30

RESULT=PASS (W copies byte-identical to N originals)
```

用 `nsenter` 进 holder 的 mount ns 直接对 `W` 里的副本算 `cksum`，与 N 侧原文件
逐字节相等 ⇒ 迁进 `W` 的三个文件**传输无损**（这正是 `PB-PUB`/`PB-PP` 两个
in-band UNKNOWN 的替代证据）。

## restore 实测（Phase B 段全文）

```
[c0a9c70b 22:47:41] suvtz-w: holder pid=30739 ns=mnt:[4026534126] mp=/data/local/tmp/.w by=kernel
[c0a9c70b 22:47:41] suvtz-w: mountpoint=yes
[c0a9c70b 22:47:42] suvtz-w: exec=yes
[c0a9c70b 22:47:42] suvtz-w: n-side-absent stage=ENOENT
[c0a9c70b 22:47:42] suvtz-w: staged oplus_check_suppress.ko
[c0a9c70b 22:47:42] suvtz-w: staged postlock_adbkey.pub
[c0a9c70b 22:47:43] suvtz-w: staged pp_adb_tcp.bin
[c0a9c70b 22:47:43] suvtz-w: staged ocsk=1 pub=1 pp=1 hotload=0
[c0a9c70b 22:47:43] driver-already-loaded
[c0a9c70b 22:47:43] hotload-skipped-late-init-selfsufficient
wns: run ns=mnt:[4026534126] cmd=/data/local/tmp/finitmod
[c0a9c70b 22:47:43] oplus_check_suppress-finitmod-ok-w
```

关键点：

- `by=kernel` —— holder 走的是 **direct `kernel:s0`** 路径（不是 `su -c` 回落）。
  这是设计里的首选路径，因为 `kernel:s0` 才能 `unshare -m`；`su` 回落路径
  现在被门控（`WSUOK`），而该门控在本设备上恒关（下一节）。
- `n-side-absent stage=ENOENT` —— `W` 里的 `stage` 目录是 holder 自建的
  tmpfs 子目录，N 侧同名路径不存在 ⇒ 确认读到的是 `W` 的私有文件树，
  不是 N 的 bind。
- `oplus_check_suppress-finitmod-ok-w` —— ocsk 是**从 `W` 里**的副本
  `finitmod` 起来的（`timeout 30 $WNSBIN run $WPID $TMP/finitmod
  $WMP/stage/oplus_check_suppress.ko 0 arm=1`）。这是 Phase B 的第一个
  真实消费点，`-w` 后缀标记路径。
- ocsk state 判据与迁移前一致（`kill.scan sites=2` / `rep armed=2`），
  证明「从 W 消费」没有改变模块行为。

## `sucompat` 对 uid 0 的域门控（本轮源码+实测订正的结构性事实）

此前文档把「holder 段的 `su` 回落」写成「uid 0 恒允许，只是 ocsk 未加载时不安全」。
**这个说法是错的**，本轮读源码 + 实测订正：

- `../BakaSU/kernel/policy/allowlist.c:271` `__ksu_is_allow_uid(uid)` 先过
  `forbid_system_uid(uid)`（`:129`，`uid < 2000 && uid != 1000`）→ **对 uid 0 为真**；
- `:301` `__ksu_is_allow_uid_for_current(uid)` 对 uid 0 返回
  `is_ksu_domain()`；
- `../BakaSU/kernel/feature/sucompat.c:194` 的 stat 假象与 execve 改写，
  **都**以 `ksu_is_allow_uid_for_current` 为门控。

⇒ **uid 0 只在 `u:r:ksu:s0` 内被放行**。restore 跑在 `u:r:kernel:s0`，所以：

- `test -x /system/bin/su` 看到的是**真实缺失**的文件（实体不存在）→ 恒假；
- 即使绕过 `-x`，`su -c` 也会 ENOENT（execve 改写不发生）。

dmesg 里那 22 条 `newfstatat ... su -> /data/adb/ksud` 来自 **shell uid 2000**
（`allow_shell=true`，`CONFIG_KSU_DEBUG=y`），不是 restore。

**因此「同 boot 重跑时 `WSUOK=1`」这个假设也不成立**（restore 永远是 `kernel:s0`）。
旧注释与判据里基于该假设的分支已一并订正。

**处置**：把门控改成 in-band 可观测（本轮之后落地），三条日志：

| 行 | 含义 |
|---|---|
| `suvtz-w: su-gate closed (domain=$WCTX su-visible=no; sucompat excludes uid 0 outside ksu domain)` | 门控触发并拒绝（fresh boot 的正常结果） |
| `suvtz-w: su-gate open (domain=ksu ocsk=yes)` | 门控触发并放行（只有 restore 真跑在 ksu 域才可能） |
| `suvtz-w: su-fallback-skipped (ocsk not loaded)` | 门控触发并拒绝，原因是模块未加载 |

三者都是「门控确实 firing」，判据一律 PASS。**本轮日志里三者都没有**
（旧版 restore），所以 `PB-SUGATE` 仍是 UNKNOWN —— 这是诚实的口径，
不把「结构性关闭但无证据」写成 PASS。

## 顺带确认的事实

- 链：`pipe-physrw-summary done=1 root=1` ×3 + `route done success=1`，链退出干净
  （无 fail amplifier 残留）。
- 模块：`kernelsu` + `oplus_check_suppress` 加载；`kernelsu_hotload_init` 按设计
  不加载（late 分支自给）。
- `enforce=1`；`POSTLOCK-RESTORE-OK` 之后 boot_id 稳定（`verdict.txt` 的
  `boot_before == boot_after == c0a9c70b-00aa-4e90-866a-20c618ebe72a`）。
- 管理器 appid `10277` 与 `pm` 实读一致；蓝卡「工作中 Built-in」（`ui.png` 181032B）。
- SUVTZ 扫描 40 探针：`FAIL=0（另有已接受 3）PASS=37 INFO=0 runas=ok`。

## 本轮未覆盖 / 待下一轮

1. **`suvtz-w: su-gate closed` 判据行**：本轮之后才加入 restore，需下一轮
   fresh boot 复验（`PB-SUGATE` 才会转 PASS）。
2. **`PB-PUB` / `PB-PP` 的 in-band 化**：需在迁移填充段加 `cksum` 传输保真自检
   （目前靠 out-of-band 脚本补证）。
3. **Phase C（删 N 副本成真隔离）**：推迟。已知风险 = `for f in ...; do cp
   $STAGE/$f $TMP/$f; done` 在文件缺失时会被 `set -e` 杀掉，需先改成
   `|| log WARN-` 形式。

## 文件

| 文件 | 内容 |
|---|---|
| `postlock.log` | host `tools/postlock.sh` 全程输出（含 idle gate 等待、verify） |
| `postlock_restore.log` | 设备侧 restore 日志（3042B，含 Phase B 段全文） |
| `chain.log` | 设备侧链日志（211731B） |
| `receiver.log` | app `BootReceiver` 日志（本轮非 app 派发，仅作旁证） |
| `check.txt` | `check_accept.sh` 17 项输出（`PASS=17`） |
| `check_phaseb.txt` | `check_phaseb.sh` 6 项输出（`PASS=3 UNKNOWN=3`，用**订正后**的判据器重跑，故 `PB-SUGATE` 原因文案是新版） |
| `phaseb_oob.log` | out-of-band `cksum` 传输保真（`RESULT=PASS`） |
| `phaseb_transfer.txt` | 同上（原始产物，与本轮同一时刻） |
| `scan_c0a9c70b.txt` | 40 探针快照（真实产物） |
| `verdict.txt` | 本轮 verdict（rc / boot / enforce / modules） |
| `ui.png` | 管理器状态卡截图（181032B，蓝卡「工作中 Built-in」） |
