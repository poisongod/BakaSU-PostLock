# SUVTZ P0 基线 —— 观测面实测（2026-11-03）

> 设计文档: [`suvtz-v3-design.md`](suvtz-v3-design.md) §3 观测面清单 / §5 观测等价判据
> 扫描器: `tools/suvtz/scan.sh`
> 设备: PFUM10 / 192.168.137.10:5555 / boot `5394a404`

## 0. 为什么先做这一步

v3 §5 的判据是形式化的：

```
∀ s ∈ S（观测面）: s(D_rooted) ≡ s(D_stock)
```

这句话要能用，**S 必须是可枚举、可执行的集合**。否则"修好了"与"本来就正常"分不清，
"还剩几项"也永远只是估计。

P0 的产出就是这份可执行基线：7 类观测面收敛成 30 条探针，每条有判定与实测值。
它同时也是 P1 的验收前置——P1 每改一处，重跑本表看 FAIL 是否下降、PASS 是否被打破。

> **2026-11-03 第二轮扫描（30 探针）**：首轮只覆盖"按设计该藏什么"，
> 漏了"检测方只要猜路径就能读到什么"。补 B7–B11 五项后 FAIL 从 7 涨到 12，
> 并且**新发现的 5 项全部是纯 DAC 泄漏**（B 类），全都可以零内核改动修掉。
> 首轮 25 项结论未变，仅 §3 的 B1/B6 根因修正（不需要 chown 到 app uid）。

## 1. 方法：视角分级与诚实原则

检测方 = 任意第三方 app（`untrusted_app` 域）。但 host 侧拿不到 app 域，只能用两个代理：

| 视角 | 构成 | 与真实检测方的关系 |
|---|---|---|
| `shell` | uid 2000 + `u:r:shell:s0` | 能力**远超**检测方，只作对照 |
| `runas` | app uid + `u:r:runas_app:s0`（`run-as <pkg>`） | DAC 精确，**SELinux 域不等价**于 `untrusted_app` |

推论（写进脚本输出）：`runas` 的 PASS 是**必要条件不是充分条件**——`runas_app` 若某权限
比 `untrusted_app` 宽，会给出假 PASS；反之若更严，会给假 FAIL。
真正的判据需 app 自身代码复测（`SusfsSelfTest`，P2 扩充）。

三条判定纪律：

1. **`Permission denied` / `No such file` = 观测不到 = PASS**，不是 INFO。
   检测方看不到就是看不到，不管是被谁挡的。
2. **命令本身跑不起来（exec 被拒 / 命令缺失 / rc 126/127）= INFO**，绝不判 PASS。
   "观测不到"与"没法观测"是两件事。
3. 期望值来自 v3 §5.3 的 stock 期望定义，**不是实测对照机**（手头没有同型号 stock 设备）。

## 2. 结果：30 项，12 FAIL / 18 PASS / 0 INFO

```
A1  FAIL  管理器包可枚举          package:com.resukisu.resukisu
A2  FAIL  工具包可枚举            package:com.postlock.boot; package:com.postlock.privateapp
A3  PASS  其它 root 工具包        -
A4  PASS  app 可见 ksud 进程      0
A5  PASS  app 可见 tailscaled     0
B1  FAIL  物料目录 ksu_boot       finitmod; kernelsu.ko; kernelsu_hotload_init.ko; ksud; ksud.log; ...
B2  PASS  /data/local/tmp 可枚举  Permission denied（目录 0771）
B3  PASS  /data/adb 可枚举        Permission denied
B4  FAIL  /product/bin/su         -rwxr-xr-x root root 915B（wrapper）
B5  PASS  /system/bin/su          No such file
B6  FAIL  物料 ko 可读            -rw-rw-rw- shell shell 13759256B
B7  FAIL  ksud 二进制可读         4107512B（全文可读；只有 exec 被 SELinux 拒）
B8  FAIL  链日志可读              431002B（KASLR/pvo/静态 fallback 明文）
B9  FAIL  overlay upper 可列      ksud;su
B10 FAIL  KASLR 参考可读          kaslr boot=... text=ffffffeeb8880000 slide=0000002ea88000
B11 FAIL  restore.sh 可读         #!/system/bin/sh（整套恢复流程明文）
C1  PASS  /sys/module/kernelsu    Permission denied
C2  PASS  /sys/module/oplus_check_suppress  Permission denied
C3  PASS  /proc/modules 含 kernelsu          Permission denied
C4  PASS  /proc/kallsyms 含 ksu_/susfs_      Permission denied
C5  PASS  ksu 参数文件可读        Permission denied
D1  FAIL  persist.adb.tcp.port    5555
D2  PASS  wrap.* 注入属性         0
D3  PASS  ro.debuggable           0
D4  PASS  ro.build.type           user
D5  PASS  verifiedbootstate       green
D6  PASS  sys.oem_unlock_allowed  0
E1  PASS  SELinux enforce 可读    Permission denied
E2  FAIL  mountinfo 暴露 overlay  1
E3  PASS  mountinfo 暴露 tmpfs upper  0
```

原始输出：`/tmp/opencode/suvtz/scan_5394a404.{txt,tsv}`

**B7–B11 是同一类东西**：探针名都以"猜路径"为前提——检测方只要知道
`/data/local/tmp/<名词>` 的形状（而这个形状在多个公开 kernelSU/susfs 讨论里都在传），
就能直接读到整套链。它们的价值在于证明 **B2 的 PASS 是假安慰**：
目录 0771 只挡住了"列目录"，挡不住"按名字取"。B8/B10 是其中信息量最大的两项
（KASLR 基址 + pvo + 整套恢复脚本）。

## 3. 12 项 FAIL 的根因（逐项）

### A1 / A2 —— 包名（PMS 层）

`pm list packages` 走 Binder → `PackageManagerService`，**完全不经文件系统**。
SUSFS 的任何钩子都在 VFS / syscall 层，改不了 PMS 的返回结果。

能改它的只有：

- 改包名（真名，非伪造）→ 与"真协议"不冲突，但**只能改我们自己的两个包**
  （`com.postlock.boot`、`com.postlock.privateapp`）；`com.resukisu.resukisu`
  是上游 `applicationId`（`managerPackageName`，换它会断升级路径）
- 管理器层过滤（谎报）→ **红线禁止**
- SELinux 限制 `QUERY_ALL_PACKAGES` → 不现实（影响所有 app 的正常功能，且该权限由
  PackageManager 内部判定，不是 SELinux class）

**结论：A1 属 T1b（当前不可达）**，A2 可通过改包名缓解（但改包名会让
`ksu_debug_manager_appid` / `postlock` 的 uid 解析链全部要重走，收益 vs 成本需评估）。

### B1 / B6 / B7 / B8 / B9 / B10 / B11 —— 物料面（**纯 DAC，host 脚本自己造成**）

实测权限（`/data/local/tmp` = 0771，所以逐个文件测，不靠列目录）：

```
drwxrwx--x  shell shell  /data/local/tmp              ← 0771，不可列可穿越
drwxrwxrwx  shell shell  /data/local/tmp/ksu_boot     ← 0777，完全开放   ← B1
-rw-rw-rw-  shell shell  ksu_boot/kernelsu.ko         ← 0666            ← B6
-rw-r--r--  shell shell  ksu_boot/ksud                ← 0644
-rwxr-xr-x  root  root   /data/local/tmp/ksud         ← 0755            ← B7
-rwxr-xr-x  root  root   /data/local/tmp/preload.so   ← 0755
-rw-rw-rw-  shell shell  postlock_chain.log           ← 0666            ← B8
drwxrwxrwx  root  root   /data/local/tmp/ovl/tmp/upper ← 0777           ← B9
-rw-r--r--  shell shell  ksu_kaslr                    ← 0644            ← B10
-rwx (在 0777 目录里)     ksu_boot/restore.sh                            ← B11
```

`postlock.sh` stage 时为了让 app 域能读 `preload.so` 而 `chmod 777 $TMP`、
`chmod 777 $STAGE`、`chmod 666` ko —— 结果 `$TMP` 变成 0771（可穿越），
**于是任何一个猜得到文件名的 app 就能读全套**：13.7MB 的 ko、4107512B 的 ksud、
431002B 的链日志（KASLR 基址 + pvo + 静态 fallback 明文）、
`ksu_kaslr`（`text=ffffffeeb8880000 slide=0000002ea88000` 直接给出内核 text 基址）、
以及 `restore.sh` 全文。

这一项**不需要内核改动，也不需要 chown 到 app uid**（首轮的推断是错的，见 §4.2）：

- `ksu_boot` → `chown 2000:2000` + `chmod 0700`（`shell` 属主即可：host adb push
  是 shell，链也是 shell；restore 是 root，CAP_DAC_OVERRIDE 无视权限位）
- `/data/local/tmp` → `chmod 0711`（stock 值；app 仍需 `x` 才能读到 `ksu_kaslr`）
- 物料 `kernelsu.ko`/`oplus_check_suppress.ko`/`kernelsu_hotload_init.ko` → 0600
- `finitmod` → 0700；`ksud`/`preload.so` → `chown 2000:2000` + 0700
  （shell 要 exec 它们；app 域 exec 本来就被 SELinux 拒）
- 运行残留 `postlock_chain.log`/`postlock_restore.log`/`chain_run.state`/
  `pstore_dump`/`ts.state`/`tsd.log`/`.ks_lock_slots`/`.cfgfslock` → 0600 shell
- overlay 骨架 `ovl`/`ovl/tmp`/`ovl/tmp/work` → 0700 root；
  **`ovl/tmp/upper` 必须留 0755**——实测它的 mode 就是挂载后 `/product/bin` 的 mode
  （0777 → `/product/bin` 也是 0777），收成 0700 会让 shell 失去 `/product/bin` 的
  `x` 位 → su wrapper 不可达；**`ovl/lower` 绝不能 chmod**（它是 `/product/bin` 的 bind）

**`ksud` 收 0700 的安全性已实测**（2026-11-03，改前 0755 root）：
app 域 `run-as com.postlock.boot /data/local/tmp/ksud --version`
→ `can't execute: Permission denied`、`rc=126` —— **SELinux 本来就拒
`untrusted_app` exec `shell_data_file`**，DAC 收紧不改变任何现有行为；
而内核侧 su 路径（sucompat）在 exec 前 `commit_creds(ksu_cred)`，
DAC 检查用 uid 0（`CAP_DAC_OVERRIDE`）照样通过。
shell（owner）与 root 各自不受影响，链与 restore 无回归。

**唯一有争议的两项**：`ksu_kaslr` / `ksu_payload` 停留在 0644 —— 它们是 app 域自己
跑链时的 gate/paste 输入（app 无法自行算内核地址），收成 0600 等于永久关掉
"BOOT_COMPLETED 自派发"。这两项与 B8 一起列为待决策项（§5 P1-3）。

### B4 —— `/product/bin/su`（overlay wrapper）

```
-rwxr-xr-x 1 root root 915  /product/bin/su
```

915 字节 = restore 生成的 wrapper 脚本。`root:root 0755` 是**必须的**：
su 要给任意被授予的 app exec，属主不能是某个 app uid。

因此 DAC 层解决不了（chmod 会同时挡住合法调用）。能覆盖它的只有：

- `SUS_PATH` 打标 → 属主 `root(0) ≠ app uid` → 对**所有** app 隐藏
  → 但**被授予 su 的 app 也会被隐藏**，它的 su 就坏了
- `SUS_PATH` + 把已授予 uid 的文件属主改成该 uid → 一个文件只能有一个属主，
  无法满足"多个被授予 app 都能 exec"的语义

**结论：B4 与 su 的可用性直接冲突，属设计级取舍**（要么暴露、要么牺牲 su 的多 app 支持）。
留到 P1 与"su 是否必须常驻 `/product/bin`"一起决策。

### D1 —— `persist.adb.tcp.port = 5555`

属性区是 init 映射的共享内存，进程 `mmap` 后直读，**不经任何 syscall**。
内核钩子碰不到，SELinux 只能按 `properties_*` class 控制按域的读权限，
而 `persist.*` 属 `properties_serial` / `properties_core`，app 域有读权限。

唯一可行方向是**用完清除**：该属性只在 WAN 通道 bootstrap 时需要，
通道建立后能改回空（`setprop persist.adb.tcp.port ''`）。但下一次冷启动
adbd 就又不监听 5555 → WAN 通道断 → 需要重新写入。**这是持久性 vs 可检测性的直接冲突。**

### E2 —— overlay 挂载在 app 的 mountinfo 里

实测原文（app 域读自己的 `/proc/self/mountinfo`）：

```
3425 113 0:126 / /product/bin rw,relatime shared:65 - overlay overlay
  rw,context=u:object_r:system_file:s0,
  lowerdir=/data/local/tmp/ovl/lower,
  upperdir=/data/local/tmp/ovl/tmp/upper,
  workdir=/data/local/tmp/ovl/tmp/work
```

一条 `grep overlay /proc/self/mountinfo` 就拿到整套链物料路径。
**这是全部 FAIL 项里信息量最大的一项**——它一次性泄漏了 overlay 机制、物料目录、upper 目录。

根因：SUS_MOUNT 的打标钩子只对**ksu 域**发起的 mount 生效
（`susfs_mount.c` 里 `security_task_getsecid()` vs `u:r:ksu:s0`），
而 restore 建 overlay 时是 `kernel:s0`（`POSTLOCK-RESTORE` 诊断头自证 `context=u:r:kernel:s0`）
→ 不打标 → 不隐藏。

修法有两条，都要动 restore：

- (a) 让 overlay 在 ksu 域建（`runcon u:r:ksu:s0` 或经 ksud 代建）
- (b) 根本不挂 overlay：su 用别的载体（但要解决 PATH 劫持与多 app 支持）

## 4. 三个被本次实测推翻的预设

这一节是 P0 的主要价值：**避免做无用功**。

### 4.1 ❌ "需要新增 `susfs_kernfs.c` 来隐藏 `/sys/module/kernelsu`"

原计划：离线已确认 `kernfs_iop_lookup$999bdfdc…` / `kernfs_fop_readdir$999bdfdc…` /
`kernfs_dop_revalidate$999bdfdc…` 三个符号可 resolve（带 CFI 哈希，现有
`susfs_unwrap_jump_table()` 能解），准备写一个 kprobe 模块做模块面隐藏。

**实测：C1/C2/C3/C4/C5 全 PASS。** app 域读 `/sys/module/kernelsu`、
`/proc/modules`、`/proc/kallsyms` **全部 Permission denied**。

原因：`/sys/module/*` 的 `ls` 需要 `kernfs` 的 `read` 权限，app 域没有；
`/proc/modules`、`/proc/kallsyms` 同样被 SELinux 拒。

**结论：模块面对 app 域本来就是不可达的（T2），这一段内核代码不需要写。**
如果将来某个检测方换到 `shell` 或 `system` 域（例如通过某个漏洞），那才需要补——
但那时它已经不在"普通 app"的威胁模型里。

### 4.2 ❌ "物料面必须靠 SUS_PATH 隐藏" / "必须 chown 到管理器 uid"

原计划：用 `SUS_PATH` 给 `/data/local/tmp/ksu_boot` 打标。

**实测：根因是目录 `0777`，pure DAC 问题**，且 `SUS_PATH` 的语义
（属主 ≠ 当前 uid 才隐藏）在这里会造成死锁——它会连**管理器自己**一起隐藏，
而管理器必须能读触发链物料。

首轮由此推出"必须 chown 到管理器 uid"，**第二轮扫描后该推断被推翻**：
app 主进程根本不读 `/data/local/tmp/ksu_boot`——
`ChainTrigger.kt` 走 `PayloadRepo.ensure(ctx)`，即 app 私有
`filesDir/postlock/`；`PayloadRepo.STAGE_DIR` 那个常量是死声明（零引用）。
而 app 侧 `restore.sh` 虽然读 `ksu_boot`，但它由链 root 后 fork（uid 0）。

**结论：`chown 2000:2000` + `chmod 0700` 即可，零内核改动，也不必跟着 app 重装换 uid。**
（B4 是例外，见 §3。）

### 4.3 ❌ "先做 P1c（模块面）再做 P1b（物料面）"

原路线按"实现难度"排序。实测表明应改为按**收益/成本比**排序：

| 项 | 收益 | 成本 | 结论 |
|---|---|---|---|
| B1/B6/B7/B8/B9/B10/B11 物料面 | 高（整套链物料路径 + KASLR 明文） | **零内核改动**，只改脚本权限 | **先做（P1-1）** |
| E2 overlay | 最高（一条 grep 定性） | 中（改 restore 挂载域） | 次之（P1-2） |
| A2 工具包名 | 中 | 中（改包名 + 全链 uid 解析重走） | 后（P1-4） |
| B4 su | 中 | 高（与 su 可用性冲突） | 需设计决策（P1-3） |
| D1 adb port | 中 | 高（持久性 vs 可检测性冲突） | 需设计决策（P1-3） |
| A1 管理器包名 | 中 | 极低收益（上游 applicationId 不能换） | 放弃 |

## 5. 修正后的 P1 路线

按实测重排（原 P1a/P1b/P1c/P1d 作废）：

- **P1-1（零内核，已落地 `ec7f6194`，boot `4c069829` 验收）**：DAC 收敛，见 §3
  B1/B6 小节的清单。插入点 = overlay 建好、ksud 拷完之后（root/kernel:s0 上下文）。
  **只改 `tools/postlock.sh` 一处**——原计划要同步 app `assets/postlock/restore.sh`
  （"两份必须一致"），但 `PostLock-Boot` 已于 2026-11-06 冻结为 legacy
  （不再演进、不再 bump `PAYLOAD_VERSION`、不再同步 assets），恢复流程唯一权威
  就是 host 侧 `tools/postlock.sh`。以后改恢复语义不必再动 app。
  **验收**：B1/B6/B7/B8/B9/B11 转 PASS、`/data/local/tmp` 保持可穿越、
  触发链与 restore 全链无回归（这是关键——不能为了隐藏把链弄坏）。
  **shell 侧已验收（boot `4c069829`）**：restore.log `suvtz-p1-1: dac hardened
  (tmp 0711 / stage 0700 / materials 0600-0700 / logs 0600)`；实测
  `/data/local/tmp` = `711 shell:shell`、`/data/local/tmp/ksu_boot` =
  `700 shell:shell`、`/data/local/tmp/ksud` = `700`，链与 `su -c id` 无回归。
  **app 侧（B1/B6…B11）待解锁复测**——`run-as` 在锁屏休眠下
  `couldn't stat /data/user/0/<pkg>`（CE 存储不可用），扫描器只能记 INFO，
  见 §6「锁屏限制」。
- **P1-2（中）**：overlay 改在 ksu 域建 → E2 转 PASS 且 SUS_MOUNT 打标生效
  （可顺带验证 SUS_MOUNT，一石二鸟）。
  **已实现并验收（2026-11-06，`92ad9a2a` + 竞态修复 `14391245`，boot `4c069829`）**：
  - `runcon u:r:ksu:s0 true` 探针成功才把 `OVLMNT="runcon u:r:ksu:s0"` 作为三个
    mount（lower bind / tmpfs upper / overlay）的命令前缀，任一 mount 失败回落
    kernel 域原行为（P1-2 是加固，不是启动前置条件）。
    restore 此时仍在 Permissive 窗口（fix81 的 flip 是最后一步），所以
    `setcurrent` 不需要额外策略。
  - **打标机制实测（boot 898d3136）**：ksu 域 `mount --bind` 得到
    `mnt_id=2000000000`（=`DEFAULT_KSU_MNT_ID`）；当轮 restore 以 kernel:s0 建的
    `/product/bin` overlay 是 `mnt_id=12520`（真实 ida 值）——这就是 E2 仍 FAIL
    的物理原因。
  - **隐藏开关实测（同一 boot）**：`susfs_mount_hide_enabled` 内核默认 0
    （`susfs_mount.hide_sus_mnts_for_non_su_procs` 未开时伪 id 是惰性的）。
    对同一条 ksu 域 bind mount：开关 0 → shell 域 `grep`=1（可见）；开关 1 →
    shell 域 `grep`=0（隐藏）。所以 restore 在 overlay 建好后显式调用
    `ksud susfs hide_sus_mnts_for_non_su_procs 1`。
  - **不影响 su**：隐藏判据只排除 ksu 域进程，路径解析不受影响；shell(2000)
    与「被授予 su 的 app」都不带 `TIF_PROC_UMOUNTED`，`__lookup_mnt` 那半边
    不会拦住它们，`/product/bin/su` 照常可 exec。被隐藏的只是「普通 app 的
    /proc/self/{mounts,mountinfo,mountstat} 视图」。
  - **排障注意**：开关打开后 shell 域也看不到伪 id 挂载行；临时排查用
    `ksud susfs hide_sus_mnts_for_non_su_procs 0` 关掉再看。
  - **⚠ 首轮踩到的坑 = restore 与 `module_init()` 的竞态（`14391245` 修）**：
    链在**同一秒**fork 出 insmod helper 与 coldstart restore，而
    `/proc/modules` 在 `module_init()` 跑完**之前**就已经列出 `kernelsu` →
    restore 的 `driver-already-loaded` 判定毫无意义。boot `acdebd41` 实测：
    overlay 在 kernel t+204s 挂上，`susfs_mount_init()` 到 t+213s 才 ready →
    `alloc_vfsmnt()` 打标探针还不存在 → 拿到真实 `mnt_id=5361`，且 hide 命令
    回 `-EOPNOTSUPP`（dmesg 里连一条 susfs 行都没有）。修法 = 在 mount 之前
    轮询 `$STAGE/ksud susfs show enabled_features` 直到出现
    `CONFIG_KSU_SUSFS_SUS_MOUNT`（该位由 `susfs_mount_available()` 门控，
    等价于「全部 `susfs_*_init()` 已跑完、mount 探针已装」），上限 45s，
    超时只打日志降级、不 die。顺带给 hide 命令加 3 次重试 + 一条独立回读
    `hide-view-check kernel-domain-sees=` —— restore 自己就是 `u:r:kernel:s0`
    （非 ksu 域），打标+隐藏成功时它必须看不见那行挂载。
  - **验收判据**：restore.log 出现 `suvtz-p1-2: product-bin-mnt-id=2xxxxxxxxx`
    （≥2000000000）+ `suvtz-p1-2: hide_sus_mnts_for_non_su_procs=1`；
    `tools/suvtz/scan.sh` 的 E2/E3 转 PASS；触发链 + `su -c id` 无回归。
  - **实测结果（boot `4c069829`，全绿）**：
    ```
    suvtz-p1-2: susfs-ready=1 after 6s          <- 就绪门（模块 init 确实滞后 6s）
    suvtz-p1-2: ovl mounts built in ksu domain
    suvtz-p1-2: product-bin-mnt-id=2000000088   <- 假 id，已在 ksu 域打标
    suvtz-p1-2: hide_sus_mnts_for_non_su_procs=1
    suvtz-p1-2: hide-view-check kernel-domain-sees=0 (expect 0)
    ```
    shell(2000) 域 `grep -e product/bin -e /ovl/ -e 2000000088
    /proc/self/mountinfo` → 无匹配（rc=1）；ksu 域仍见
    `2000000088 ... / /product/bin ... lowerdir=/data/local/tmp/ovl/lower`；
    `/product/bin/su -c id` → `uid=0 ... u:r:ksu:s0`（路径解析不受影响）。
    **注意**：shell 域 `grep -c overlay` 仍是 7——那是 OPPO 系统自带的
    `product/app`、`product/priv-app` 等 overlay，不是我们的，别误判成泄漏。
  - **探针坑**：`su 2000 -c ...` **不能**当「非 su 进程」可见性探针——
    KernelSU 的 su 会进独立 mount namespace（umount-modules 语义），它看到的
    永远是自己那份 ns；app 域可见性只能用真实 `adb shell`(uid 2000) 或
    `run-as` 测量。
- **P1-3（需决策，见 §5.1）**：B4 / B8 / B10 / D1 四项冲突点，不擅自取舍。
- **P1-4（后）**：A2 包名。

### 5.1 待决策的四项冲突

| 项 | 冲突 | 三个选项 |
|---|---|---|
| **B4** `/product/bin/su` | su 要给**任意**被授予的 app exec，属主不能是某个 app uid | ① 接受"名字可见、内容不可读"（现状）② SUS_PATH 打标（被授予的 app 也一起被隐藏，su 坏）③ 放弃 `/product/bin` 载体，su 只经 ksud wrapper |
| **B8** 链日志 | 431KB 含 KASLR/pvo 明文；但 PostLock 面板要 tail 它做实时日志 | ① 默认 0600（已实现，`SUVTZ_CHAIN_LOG_MODE=0644` 可回退）→ 面板只见 app 域链 ② 0644 保留面板，接受泄漏 ③ 日志脱敏（打码 text/slide 字段）后 0644 |
| **B10** `ksu_kaslr`/`ksu_payload` | app 域自己跑链的唯一输入端；无法由 app 自行计算 | ① 保持 0644（现状）② 收 0600 = 放弃 app 自派发（生产路径本来就是 host 触发）③ 只在考试轮临时放宽 |
| **D1** `persist.adb.tcp.port=5555` | WAN 通道 bootstrap 需要 adbd 常驻监听 5555 | ① 保持常驻 ② 通道建立后清空（下次冷启动断链，需重新写）③ 换非持久通道（每 boot host/链写一次） |

## 6. 复跑方法

```bash
tools/suvtz/scan.sh                    # 完整输出
tools/suvtz/scan.sh -q                 # 只出汇总
SERIAL=<ip>:5555 tools/suvtz/scan.sh
```

**锁屏/休眠限制（2026-11-06 实测）**：`run-as` 依赖 CE 存储，设备锁屏休眠时
报 `couldn't stat /data/user/0/<pkg>`（对 `com.postlock.boot`、`com.termux`、
`com.postlock.privateapp` 全都一样）→ 扫描器 `runas_ok=0 runas_exec=0`，
A4/A5/B*/C*/D*/E* 全部记 `INFO`（30 项里只剩 A1~A3 能判）。**app 域测量必须
先解锁**，而这恰恰是最需要 app 域的那批判据（B1/B6/E2/E3 的隐藏语义都门控在
`TIF_PROC_UMOUNTED && uid>=10000`，shell 域永远看不到被隐藏的世界）。

输出落 `/tmp/opencode/suvtz/scan_<boot8>.{txt,tsv}`。**换 boot 后重跑**即可验证：

- **持久性判据**：上一 boot 的 FAIL 项是否在本 boot 仍为 FAIL（该 FAIL 是"每 boot 重犯"
  还是"一次性"）
- **回归**：原本 PASS 的项是否变 FAIL（改动引入的新泄漏）

注意：本表的 PASS 是 `runas_app` 视角的必要条件，不是 `untrusted_app` 的充分条件。
真正的终局判据在 P2——app 自身代码跑同一套探针。
