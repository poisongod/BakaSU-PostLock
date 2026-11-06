# SUSFS 九项功能验收（LKM edition v2.3.0 / GKI ABI）

脚本：`tools/susfs/accept.sh`（adb 通道由 `tools/susfs/adb1.sh` 选择，绝不落到错设备
`401e909a`）。原始数据归档在 `docs/forensics/susfs-accept-r{2,3,4}-*/`。

**当前状态：九项全部通过（r4，boot `1e831bc4`）= 37 PASS / 0 FAIL / 3 INFO。**
三处 INFO 是 app 域观测不到（`/proc/cmdline`、`/proc/kallsyms` 被 SELinux 拒；
本内核无 `/proc/bootconfig`），对应能力已由 root 侧等价证据覆盖，未伪造成 PASS。

## 两级判据

| 级别 | 判据 | 权威来源 |
|---|---|---|
| Level 1 命令受理 | 内核侧出现 `CMD_SUSFS_xxx -> ret: 0` | dmesg（shell 域跑 ksud 根本进不到内核） |
| Level 2 语义生效 | 真实 app 进程「标记前 / 标记后」自检对照，唯一变量是内核标记命令 | app 侧 `files/susfs_selftest_<tag>.txt` |

语义验收只能在 app 进程里做：SUS_PATH / SUS_MAP / SUS_MOUNT / OPEN_REDIRECT 的隐藏
判定门控在 `TIF_PROC_UMOUNTED`（只有 zygote fork 出来的 app 才带），shell(2000)、
`run-as`、`su` 看到的永远是未隐藏的世界。

脚本一律用 root 通道（`RR`）读设备——不是因为 shell 会被隐藏，而是因为
`ksud susfs` 走 `reboot()` magic，非 root 上下文根本到不了内核
（userspace 会照原样报 `Unsupported SuSFS command`，dmesg 里零 susfs 行）。

## 用法

```bash
adb push build/embed/ksud /data/local/tmp/ksud && adb shell chmod 755 /data/local/tmp/ksud
./tools/susfs/accept.sh </dev/null        # 输出默认落 /tmp/opencode/susfs/out
```

- **一次 boot 只跑一次**（脚本用 `<out>/.marked_boot` 守住）：本 ABI 没有 `DEL_*`
  命令，SUS_PATH / SUS_MAP / SUS_KSTAT / OPEN_REDIRECT / CMDLINE 的标记只能靠重启
  清除。脚本末尾只复原 uname、mount 隐藏开关与 bind mount。
- 结果中 `INFO` 表示「app 域无法观测」（例如 `/proc/kallsyms`、`/proc/cmdline`
  在 untrusted_app 下被 SELinux 拒），**不伪造成 PASS**。

## 目标选型原则

1. **SUS_PATH / 对照项**必须是「app 能列出的目录下的普通文件」：`/system/bin` 对
   app 是 `Permission denied`，在那里判 `listed 1 -> 0` 必然假失败。现用
   `/system/etc/NOTICE.xml.gz`（1.7 MB、无运行期读取者）与对照 `/system/etc/gps_debug.conf`。
2. **SUS_KSTAT** 必须是普通文件（非符号链接）：`/system/etc/hosts`；伪造
   `ino=777001 / size=123456`（真实 size 56，389 与 4096 都不足以区分）。
3. **SUS_MAP** 用进程真的映射了的实际路径：`/apex/com.android.runtime/lib64/bionic/libc.so`
   （`/system/lib64/libc.so` 是符号链接，`kern_path` 会解析到 apex）。
4. **OPEN_REDIRECT** 用 `/system/etc/security/otacerts.zip` ← `/system/etc/hosts`
   （`uid_scheme=3` = UnmountedApp），并额外验证**第二种拼写**
   （`readlink -f` → `/my_engineering/etc/security/otacerts.zip`）。
5. **SPOOF_CMDLINE / HIDE_KSU_SUSFS_SYMBOLS** 改 root 侧观测：两项钩子都**没有
   uid 门控**（全局生效），root 与 app 看到的一致，因此这是等价证据而非降低标准；
   app 侧如实记 INFO。

## 本轮（r2）定位的 5 项 FAIL——全部是脚本 / 语义问题，不是内核缺陷

| 项 | 表象 | 根因 | 处置 |
|---|---|---|---|
| `add_sus_path`（负向） | 不存在的路径照样 `ret: 0` | userspace `sus_path.rs` 的 `ensure_path_exists!` 在 syscall 前拦下，内核从未被调用（dmesg 无 `ret: -` 行） | 去掉该预检：内核是权威（普通项 `-ENOENT` 由内核返回；loop 项路径本可尚不存在） |
| `SUS_PATH listed` | 1 -> 0 恒失败 | 目标选在 `/system/bin`，app 无法列该目录 | 目标/对照移到 `/system/etc` |
| `OPEN_REDIRECT 内容` | 前后同为 `504b0304…` | `otacerts.zip` 是符号链接；userspace `fs::canonicalize` 把规则注册到 `/my_engineering/...`，app 按 `/system/etc/security/otacerts.zip` 打开 miss | 双管齐下：内核额外保存 `d_path` 规范名做**别名**（命中/去重/替换三处双拼写比较）；userspace 不再 canonicalize，原拼写直传 |
| `SPOOF_CMDLINE` | app 域 `FileNotFoundException` | untrusted_app 读 `/proc/cmdline` 被 SELinux 拒 | root 侧观测（钩子无门控） |
| `HIDE_KSU_SUSFS_SYMBOLS` | app 域 `/proc/kallsyms` 不可读 | 同上 | root 侧观测，要求 `susfs_`/`ksu_`/`__ksu_` 计数全 0 且 `_stext`/`do_exit` > 0 |

负向测试已在本 boot 上实证（userspace 修复后）：

```
(3)[8180:ksud]susfs:[0][8180][susfs_path_add] CMD_SUSFS_ADD_SUS_PATH -> ret: -2
SuSFS error: -2
```

## 轮次记录

| 轮 | boot | 结果 | 说明 |
|---|---|---|---|
| r1 | `5394a404` | 31 PASS / 5 FAIL / 1 INFO | Level 1 九项全部 `ret: 0`；5 FAIL 见上表 |
| r2 | `261cfe5f` | 31 PASS / 5 FAIL | 三路冗余 su / v27 wrapper 全绿；app 侧已可跑（uid=10287），5 FAIL 全是上表那 5 个脚本/语义问题 |
| r3 | `e7b53e30` | 19 PASS / 1 FAIL | ko `e78ec0c6`（别名）+ ksud `e27988f3`（原拼写直传 / 去预检）。**设备处于 `RUNNING_LOCKED`**：CE 未解锁 → `am broadcast` 返回 `result=0` 但 receiver 不执行、`/data/data/<pkg>` 不存在 → 自检文件无法生成，唯一 FAIL = `selftest[before]`；Level 1 与 root 侧 19 项全 PASS（内核侧修复已被证实） |
| r4 | `1e831bc4` | **37 PASS / 0 FAIL / 3 INFO** | 用户解锁后 fresh boot 重跑（`OUT=/tmp/opencode/r4/susfs4`）。app 侧主体 `uid=10287 ctx=u:r:untrusted_app:s0:c31,c257,c512,c768`（真实 untrusted_app），九项语义全部 `1 -> 0` 或值比对成立；3 INFO 见下 |

r3 前置条件：新 ko 必须由重启后的 `tools/postlock.sh` 加载（链 staging 里的
`kernelsu.ko`），新 wrapper 与 `/data/adb/ksud` provision 同样在那一轮 restore 生效。

## r4 结论（九项全绿）

| feature | 证据（r4 summary） |
|---|---|
| `SUS_PATH` | `exists 1->0`、`listed 1->0`；LOOP 同；对照组 `gps_debug.conf` 未受影响；内核侧 `hiding ino` `0->2` |
| `SUS_KSTAT` | `ino 9608777->777001`、`size 56->123456`；对照 ino 未受影响 |
| `SUS_MAP` | `/apex/.../bionic/libc.so` 在 maps 中行数 `4->0` |
| `SUS_MOUNT` | 内核侧 `mnt_id=2000000000`（≥2e9 伪 id）+ app 侧 `mounts 1->0`（mountinfo 同） |
| `OPEN_REDIRECT` | 目标内容由 zip 头变为 `hosts` 内容；**别名路径** `/my_engineering/etc/security/otacerts.zip` 同样命中；源文件未受影响 |
| `SPOOF_UNAME` | release/version 均被替换 |
| `SPOOF_CMDLINE` | root 侧整串替换（app 域不可读 → INFO） |
| `HIDE_KSU_SUSFS_SYMBOLS` | root 侧 `susfs_`/`ksu_`/`__ksu_` 计数全 0，`_stext`/`do_exit` 可见（app 域不可读 → INFO） |
| `ENABLE_LOG` | 九项 feature 位全上报，命令全程 `ret: 0`；`avc_log_spoofing` 诚实 126 |

**三处 INFO 的诚实边界**：`SPOOF_CMDLINE(app)` 与 `HIDE_SYMBOLS(app)` 因
untrusted_app 读 `/proc/cmdline`、`/proc/kallsyms` 抛 `FileNotFoundException`；
`SPOOF bootconfig` 因本内核 `CONFIG_BOOT_CONFIG=n`（无 `/proc/bootconfig`）。
前两项的钩子**无 uid 门控**（全进程一致），root 侧 PASS 是等价证据；第三项
能力在本内核上客观不可观测，不算未实现（`set_cmdline` 命令 `ret: 0` 已证受理）。

## r4 之后的收尾：干净重启 + 冷 boot 恢复复验

SUSFS 的 `SUS_PATH` / `SUS_MAP` / `SUS_KSTAT` / `OPEN_REDIRECT` /
`SPOOF_CMDLINE` 都**没有 DEL 命令**，r4 留下的伪造 `uname -r`、对 app 隐藏的
`/system/bin/toybox`、被重定向的 `otacerts.zip` 只能靠重启清除。r4 之后做过
一次干净重启（`1e831bc4` → `898d3136`），判据全绿：

- `uname -r` 回到真实的 `5.4.254-qgki-g977b99b1fbb9`，`/system/bin/toybox`
  对 app 域重新可见（证明标记确已清除，不是「隐藏恰好失效」）
- 冷 boot 恢复：链 `pipe-physrw-summary done=1 root=1` ×3 + `CHAIN_EXIT_DONE`
  + `ks_neutralize ok=1 verified=1`；restore `SELINUX-STRICT-OK` /
  `POSTLOCK-RESTORE-OK` 双 OK、`enforce=1`；`kernelsu` + `oplus_check_suppress`
  加载、`kernelsu_hotload_init` 按 legacy 设计不加载
- suvtz 复测 **6 FAIL / 24 PASS / 0 INFO**（与上一轮同值，无回退；6 个 FAIL
  全部是设计内暴露面：管理器包、工具包、`/product/bin/su`、`ksu_kaslr`、
  `persist.adb.tcp.port`、`/product/bin` overlay）

原始数据：`docs/forensics/coldboot-898d3136/`。
