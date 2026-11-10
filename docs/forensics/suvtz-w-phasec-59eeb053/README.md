# fresh boot `59eeb053` —— Phase C（删 `N` 副本，真隔离）验收

**时间**：06:37 由 host `reboot` 起 fresh boot → 06:40:02 起轮 → 06:41:47 静默门放行
（`quiet after 100s (load=4.82)`，起轮时 load 10.90 属开机风暴）→ 06:43:06 链打出
`pipe-physrw-summary done=1 root=1` ×3 → 06:43:23 `SELINUX-STRICT-OK` +
`POSTLOCK-RESTORE-OK` → 06:43:41 扫描器自跑完 → 06:43:59 判 PASS（boot 稳定）。
**执行者**：host 侧 `tools/postlock.sh`（本轮 supervisor = 单 owner 3 轮上限脚本，
`/tmp/opencode/sup4.sh`；第 1 轮一次过，**未 reboot 重试**）
**boot**：`59eeb053-8fd8-4c64-b980-b5591c45c09f`，`ro.boot.bootreason=reboot,shell`
（host 命令重启，非 panic）
**主仓 HEAD**：`cd0da528`；app 仓 `4728081`；restore 生成物 = **39713B / 682 行 /
sha1 `1585c9850e3e849162afb5a71ccdbf90c65e3ef3`**（app assets 同 sha1）

## 为什么这一轮重要

Phase B 解决的是「谁来消费物料」（`W` 优先、`N` 兜底），但 `N` 里的副本仍在——
**隔离不成立**，因为 `N` 侧仍然存在一份完整可用的对象，任何走 `N` 路径的消费都绕过
`W`。Phase C 把 `N` 副本删掉，`W` 成为**唯一**存放位置，这一项才从「可逆形态」变成
真隔离。

本轮首次真机验证 Phase C 的三段语义：

1. **填充期 in-band 校验**：`W` 侧写完立刻用 `cksum` 比对 `N` 源，不一致的文件不进
   候选集（`WCKO`），后续不会被误删；
2. **restore 尾部 purge**：只删 `WCKO` 里校验通过的三件（`oplus_check_suppress.ko` /
   `postlock_adbkey.pub` / `pp_adb_tcp.bin`），`N` 的 stage 与 `$TMP` 两处同时清；
3. **保留集自证**：purge 后立刻打 `n-side-kept`，链关键集（`kernelsu.ko` /
   `finitmod` / `preload.so` / `ksud` / `sep_enforce1.txt`）必须**仍在 `N`**。

## 判据（四套核对器 + 设备侧独立复核）

### 1. `tools/suvtz/check_phasec.sh`（本轮新增，4 项）

```
PASS    PC-CKSUM   cksum 一致文件数=3（ocsk/pub/pp 至少三项）
                   [59eeb053 06:43:10] suvtz-w: cksum ok oplus_check_suppress.ko 1995826726 238160
PASS    PC-PURGE   [59eeb053 06:43:18] suvtz-w: n-side-purged oplus_check_suppress.ko postlock_adbkey.pub pp_adb_tcp.bin
PASS    PC-VERIFY  无 purge/cksum 告警
PASS    PC-KEEP    [59eeb053 06:43:18] suvtz-w: n-side-kept kernelsu.ko finitmod preload.so ksud sep_enforce1.txt

PASS=4 FAIL=0 UNKNOWN=0 总计=4
```

restore 侧原文（`restore.log`，**零 `WARN-suvtz-w-*`**，实测 `grep -c` = 0）：

```
06:43:09 suvtz-w: n-side-absent stage=ENOENT
06:43:10 suvtz-w: staged oplus_check_suppress.ko
06:43:10 suvtz-w: cksum ok oplus_check_suppress.ko 1995826726 238160
06:43:10 suvtz-w: staged postlock_adbkey.pub
06:43:10 suvtz-w: cksum ok postlock_adbkey.pub 2123509450 719
06:43:11 suvtz-w: staged pp_adb_tcp.bin
06:43:11 suvtz-w: cksum ok pp_adb_tcp.bin 2332106405 30
06:43:11 suvtz-w: staged ocsk=1 pub=1 pp=1 hotload=0
…
06:43:18 suvtz-w: n-side-purged oplus_check_suppress.ko postlock_adbkey.pub pp_adb_tcp.bin
06:43:18 suvtz-w: n-side-kept kernelsu.ko finitmod preload.so ksud sep_enforce1.txt
```

`hotload=0` 是设计（late-init 自给，`kernelsu_hotload_init.ko` 只有
`KS_HOTLOAD_LEGACY=1` 才进候选）。

### 2. 主判据 `tools/suvtz/check_accept.sh`（17 项）

```
PASS RETIRE-0 / RETIRE-RESID / RETIRE-NOBUILD
PASS W-HOLDER  holder pid=26603 ns=mnt:[4026534152] mp=/data/local/tmp/.w by=kernel
PASS W-NS / W-BY / W-MP / W-EXEC / W-NABSENT
PASS RESTORE-OK x1 / STRICT-OK x1 / EXIT0 rc=0
PASS SU-PROBE  uid=0 … context=u:r:ksu:s0
PASS CHAIN-ROOT done=1 root=1 x3 / CHAIN-ROUTE route done success=1
PASS SCAN      FAIL=0 (另有已接受 3)  PASS=37  INFO=0  总计=40  runas=ok
PASS HIDE-OFF

== summary: PASS=17 FAIL=0 UNKNOWN=0 ==
RESULT: OK（无 FAIL）
```

### 3. Phase B 判据 `tools/suvtz/check_phaseb.sh`（6 项）

```
PASS PB-STAGE   staged ocsk=1 pub=1 pp=1 hotload=0
PASS PB-OCSK    oplus_check_suppress-finitmod-ok-w
PASS PB-PUB     append 幂等跳过；W 副本 cksum ok postlock_adbkey.pub 2123509450 719
PASS PB-PP      append 幂等跳过；W 副本 cksum ok pp_adb_tcp.bin 2332106405 30
PASS PB-SUGATE  su-gate closed (domain=other su-visible=no …)
PASS PB-HOTLOAD hotload-skipped-late-init-selfsufficient

PASS=6 FAIL=0 UNKNOWN=0 总计=6
```

上一轮 `PB-PUB` / `PB-PP` 是 UNKNOWN（幂等跳过无 append 行），本轮已由 Phase C 的
in-band `cksum` 证据转 PASS —— 这也是 Phase C 的一个附带收益：**校验行同时充当
传输保真的 in-band 证据**。

### 4. 传输保真 `tools/suvtz/phaseb_oob.sh`（`ref=in-band`）

```
boot=59eeb053-8fd8-4c64-b980-b5591c45c09f  holder_pid=26603  holder_ns=mnt:[4026534152]
n_side_stage=ENOENT   ocsk=loaded
OK oplus_check_suppress.ko  ref=in-band cksum=1995826726 238160
OK postlock_adbkey.pub      ref=in-band cksum=2123509450 719
OK pp_adb_tcp.bin           ref=in-band cksum=2332106405 30
RESULT=PASS (live W copies match their references)
```

Phase C 之后 `N` 源已不存在，所以参照系从「`N` 原件」改成「in-band `cksum ok` 记录」
（本轮实测 W 里的活字节仍等于该记录，不是只信日志）。

### 5. 设备侧独立复核（不依赖核对器）

`N` 侧 stage 目录（purge 后）：

```
drwx------ … ksu_boot/ 只剩：finitmod kernelsu.ko kernelsu_hotload_init.ko ksud
                              preload.so restore.sh sep_enforce1.txt
                              skbdelta trigger.b64 trigger.sh ksud.log wan_deploy.sh wns
（三件 ocsk / pub / pp 已不在列表中）
```

`/data/local/tmp` 三件单独探测：`ABSENT oplus_check_suppress.ko` /
`ABSENT postlock_adbkey.pub` / `ABSENT pp_adb_tcp.bin`。

`W` 侧从 shell 域直读被拒（`wns: open(/proc/<pid>/ns/mnt): Permission denied`）——
这是**预期的域墙方向**（shell→kernel:s0 holder ns 拒），不是故障；`W` 侧的存活与
字节一致性由上面第 4 节的 out-of-band 核对器（走 ksu 通道）负责。

## 稳定性

- 链后 boot_id 始终 `59eeb053-…`，120s 判据通过；收尾时 `enforce=1`。
- 模块：`kernelsu=YES` + `oplus_check_suppress=YES`，`kernelsu_hotload_init=NO`
  （legacy 按设计不加载）。
- ocsk v14：`kill-armed` / `rep-armed` 各 1 行，零 `WARN-…-rep-not-armed-popup-risk`
  ⇒ 本 boot 无安全弹窗。
- 仅两条已知无害 WARN：`WARN-no-omk-bak`（OMK 已卸载无备份）与
  `WARN-phantom-settings`（旧 su 残留设置项）。

## 状态卡（uiautomator 文本，截图 `ui_blue.png`）

```
工作中 / Built-in / 越狱模式
1 个超级用户, 0 个模块
```

「越狱模式」= `ksu_late_loaded=true` 的**真实状态**（真协议修复后的应有表现，不谎报）。
宿主侧同时记录了 `driver version 35222 / v4.2.0-rc3-5b76b884-dirty@BakaSU`，与管理器
`35252 / UAPI 6` 的 UAPI 6==6 ⇒ 无红条。

## 通道

唯一可用 adb = **私有 server `adb.exe -P 5038`**（`/tmp/opencode/adb5038.sh`）。
`adb devices` 同时列 `401e909a`（非本项目，勿动），全部命令带
`-s 100.120.155.127:5555`。reboot 前 `screen_off_timeout` 临时抬到 600000、轮次结束
由 supervisor 的 EXIT trap 恢复 60000。

## 文件清单

| 文件 | 内容 |
|---|---|
| `check_phasec.txt` | **Phase C 4 项**（`PC-CKSUM`/`PC-PURGE`/`PC-VERIFY`/`PC-KEEP`） |
| `check_accept.txt` | 主判据 17 项 |
| `check_phaseb.txt` | Phase B 6 项（本轮 6/6，无 UNKNOWN） |
| `phaseb_oob.log` | out-of-band `cksum`（`ref=in-band`） |
| `restore.log` | restore 完整日志（3576B / 43 行，含 `suvtz-w:` 全段） |
| `chain.log` | 链日志**裁剪版**：头 120 行 + 关键行 + 尾 300 行；文件头记录了全文行数/字节数/sha1（全文 `b5117170…`，1848240B） |
| `postlock.log` | host 侧 postlock.sh 输出（stage / quiet gate / verify） |
| `verdict.txt` | `postlock_rc=0` / `boot_before` / `boot_after` / `enforce=1` / `p6: modules=…` |
| `scan.txt` | 扫描器汇总行（`FAIL=0（另有已接受 3）PASS=37 INFO=0 runas=ok`） |
| `scan_full.txt` | 40 探针逐项报告 |
| `ui_blue.png` / `ui.xml` | 状态卡截图 / uiautomator 文本（判据以文本为准） |
