# SUVTZ P0 基线 —— 观测面实测（2026-11-03）

> **已作废（2026-11-12）** — 本文属旧的「两世界 + (W,N,E,M) 四元组 / SUVTZ /
> VtzSU」文档体系，现**全文作废**：不再作为任何设计、判据、验收或实现的依据。
> **一切以仓库根目录的 [`TrySU.md`](../TrySU.md)（三世界 W / N / VN + 十二公理）为准**；
> 实现状态见 [`trysu-implementation.md`](trysu-implementation.md)。
> 本文件保留作历史取证与实现细节参考。坐标转换：旧文的 `W`（私有 mount ns、
> root 执行处）在新坐标下是 `VN`；新 `W` 是权限仲裁者，旧体系无对应物。

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

> 本节的 30 项是 P0 的**单点探针基线**。扫描器在 2026-11-07 追加了 5 条 X 类
> 成对交叉验证（见 §7），因此当前 `scan.sh` 一次跑出 **35 项**（30 + 5）。
> 下表的编号与数值保持 P0 原样不改，便于与本文档其它章节和历史归档对照。

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
  **app 侧已复测（2026-11-07，同一 boot `4c069829`，解锁态）**：B1/B6/B7/B8/
  B9/B11 六项全部 **PASS**（逐项实测值见 §5.2）。
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
- **P1-3（需决策，见 §5.1）**：B4 / B10 / D1 三项冲突点，不擅自取舍。
  （**B8 已由 P1-1 落地并实测转 PASS**：链日志 0600，app 域 `head` 直接
  `Permission denied`。副作用 = PostLock 面板只能看 app 域链日志，不再是判据项。）
- **P1-4（后）**：A1 / A2 包名。

### 5.2 P1 后差分复测（2026-11-07，boot `4c069829`，解锁态）

条件：`SERIAL=5bf5bf85 PKG=com.postlock.boot tools/suvtz/scan.sh -q`，
`runas_ok=1 runas_exec=1`，35 项（30 单点 + 5 X 类）。

```
FAIL=5  PASS=30  INFO=0  总计=35        # P0 同口径 30 项时为 12 FAIL / 18 PASS
```

> 这是**裁决前**的差分结果。同 boot 完成 §5.1.3 的裁决后（B10 收 + 四项登记），
> 现口径是 **`FAIL=0 (另有已接受 4) PASS=31 INFO=0`**，输出存
> `/tmp/opencode/suvtz-p1verify/rooted3/`。

**零参数复现（2026-11-07，boot `a877caaf`，解锁态）**：`tools/suvtz/scan.sh -q`
→ `FAIL=0 (另有已接受 4)  PASS=31  INFO=0  总计=35  runas=ok`（72s，自动选 adb /
设备 / 载体）。**同一 boot 冷 boot 后仍锁屏时的自动 P2 快照是
`runas=no  PASS=1  INFO=32`**——那是如实记录（CE 存储不可见，`dumpsys user` =
`RUNNING_LOCKED`），不是回归，解锁后重跑即恢复 31 PASS。输出
`/tmp/opencode/suvtz/scan_a877caaf.txt`，台账 `/tmp/opencode/suvtz/history.tsv`。

**转 PASS 的 7 项**（P0 FAIL → 现 PASS），全部落在 P1-1 / P1-2 的设计目标上：

| 项 | P0 实测 | 现实测（app 域代理） | 由谁解决 |
|---|---|---|---|
| B1 物料目录可列 | `finitmod; kernelsu.ko; ...` | `ls: /data/local/tmp/ksu_boot: Permission denied` | P1-1（stage 0700） |
| B6 物料 ko 可读 | `-rw-rw-rw- ... 13759256B` | `ls: .../kernelsu.ko: Permission denied` | P1-1（0600） |
| B7 ksud 可读 | `4107512B 全文可读` | `can't open /data/local/tmp/ksud: Permission denied` | P1-1（0700） |
| B8 链日志可读 | `431002B（KASLR/pvo 明文）` | `head: .../postlock_chain.log: Permission denied` | P1-1（logs 0600） |
| B9 overlay upper 可列 | `ksud;su` | `ls: .../ovl/tmp/upper: Permission denied` | P1-1 |
| B11 `restore.sh` 可读 | `#!/system/bin/sh（整套流程明文）` | `head: .../restore.sh: Permission denied` | P1-1 |
| E2 mountinfo 暴露 overlay | `1` | `0` | P1-2（ksu 域建 + 伪 id + hide 开关） |

**剩余 5 项 FAIL**（裁决前口径；其中 4 项已于 2026-11-07 登记为「已接受」，
B10 已收 —— 见 §5.1.3）：

| 项 | 实测 | 归属 |
|---|---|---|
| A1 管理器包可枚举 | `package:com.resukisu.resukisu` | **已接受**（不立项，见 §5.1.3） |
| A2 工具包可枚举 | `package:com.postlock.boot; package:com.postlock.privateapp` | **已接受**（保留两包为验收基础设施） |
| B4 `/product/bin/su` 存在 | `-rwxr-xr-x root root 412B` | **已接受**（§5.1 B4 三选项均不免费） |
| B10 `ksu_kaslr` 可读 | `kaslr boot=4c069829... text=ffffffed22a80000 slide=0000002d12a000` | **已收**：`SUVTZ_KASLR_MODE` 默认 `0600` |
| D1 `persist.adb.tcp.port` | `5555` | **已接受**（唯一救回通道，§5.1.3） |

**X 类五对全同向**（无一例通道分歧），说明当前没有「某条读取路径漏堵」：

```
X1 PASS  A=grep /proc/modules: Permission denied | B=ls /sys/module/kernelsu: Permission denied
X2 PASS  A=grep /proc/kallsyms: Permission denied | B=grep /proc/modules: Permission denied
X3 PASS  A=0 | B=0                      (mountinfo vs mounts 都看不到 product/bin)
X4 PASS  A=ls /data/local/tmp: Permission denied | B=ls .../ksu_boot: Permission denied
X5 PASS  A=0 | B=0                      (ps 与直接枚举 /proc/*/comm 都找不到 ksud)
```

原始输出：`/tmp/opencode/suvtz-p1verify/rooted/scan_4c069829.{txt,tsv}`；
同 boot 的 stock 参照 `/tmp/opencode/suvtz-p1verify/stock/`（未解锁/未 P1 时）。

### 5.3 P1-1 盖不住的那一类：`/data/local/tmp` 的历史遗留文件

复核权限时发现（同一 boot）：`0700`/`0600` 只覆盖了**本轮恢复流程自己写的**文件，
`/data/local/tmp` 里还躺着几十个历史调试产物，其中一批是 `0644 root`：

```
-rw-r--r--  root root  2787  r2.log            <- 上一轮 restore.log 的副本（整套恢复流程）
-rw-r--r--  root root  3090  ksu_dbg_params.txt <- ksu_dbg_* 参数名与命中计数
-rw-r--r--  root root    96  ksu_su_asroot.txt
-rw-r--r--  root root  ...    agent.log / probe*.log / listen.log / abs.log / scrcpy.log
```

目录是 `0711`（`--x` 只给穿越、不给枚举），所以 app **列不出来**，但只要知道名字
就能读——这正是 P0 §2 里 B2 PASS / B7 FAIL 的那对矛盾。已清理（`rm` 掉 13 个
调试日志 + 2 个空测试目录 + 2 个自建 APK；Termux 遗留 `app.apk`/`dryrun.sh`/
`install-tekl2.sh` 按约定保留）。

**结论写进纪律**：P1-1 的 DAC 收敛只在「每轮结束清场」的前提下成立。遗留文件不
是代码问题，是卫生问题——扫描器也测不出来（它不知道有哪些名字）。复跑前若发现
`/data/local/tmp` 有新的 `0644` 调试文件，先当成泄漏处理。

> 附：`/data/local/tmp/dalvik-cache`（`0777` shell）与 `d5s`/`dh153`/`nr`/`hls`
> 等 11-03/11-04 的网页与截图调试目录仍在。它们不含 root 证据（截图/HTML/MP4），
> 属可读噪音而非检测信号，暂留待用户处置。**`ovl/`（0700 root）与 `ksu_boot/`
> （0700 shell）才是敏感面，均已不可穿越**。

### 5.1 待决策的冲突（B8/B10 已落地，A1/A2/B4/D1 已接受 —— 见 §5.1.3）

| 项 | 冲突 | 三个选项 |
|---|---|---|
| **B4** `/product/bin/su` | su 要给**任意**被授予的 app exec，属主不能是某个 app uid | ① 接受"名字可见、内容不可读"（现状）② SUS_PATH 打标（被授予的 app 也一起被隐藏，su 坏）③ 放弃 `/product/bin` 载体，su 只经 ksud wrapper |
| ~~**B8** 链日志~~ | ~~431KB 含 KASLR/pvo 明文；但 PostLock 面板要 tail 它做实时日志~~ **已按选项①落地（P1-1，logs 0600），app 域实测 PASS** | ① 默认 0600（已实现，`SUVTZ_CHAIN_LOG_MODE=0644` 可回退）→ 面板只见 app 域链 ② 0644 保留面板，接受泄漏 ③ 日志脱敏（打码 text/slide 字段）后 0644 |
| **B10** `ksu_kaslr`/`ksu_payload` | app 域自己跑链的唯一输入端；无法由 app 自行计算 | ① 保持 0644 ② 收 0600 = 放弃 app 自派发（生产路径本来就是 host 触发）**已落地为默认：`SUVTZ_KASLR_MODE` 默认 `0600`，`0644` 可回退** ③ 只在考试轮临时放宽 |
| **D1** `persist.adb.tcp.port=5555` | WAN 通道 bootstrap 需要 adbd 常驻监听 5555 | ① 保持常驻 ② 通道建立后清空（下次冷启动断链，需重新写）③ 换非持久通道（每 boot host/链写一次） |

#### 5.1.1 裁决登记机制：`tools/suvtz/accepted.tsv`

「已裁决接受」的暴露面**不能改判成 PASS**（那会把未解决说成已解决），但每次都
在报告里占一行 FAIL 也不利于收敛观察。所以加一层**纯标注**机制：

```tsv
# ID<TAB>裁决日期<TAB>理由（单行），# 开头的行忽略
B10	2026-11-07	生产路径改由 host 触发，app 自派发已随 PostLock-Boot 冻结
```

`scan.sh` 的行为（`ACCEPTED_FILE` 默认 `$(dirname $0)/accepted.tsv`）：

| 输入 | 输出 |
|---|---|
| 文件不存在 / 全注释（**默认状态**） | 与引入前**逐字一致**（`FAIL=5`） |
| 文件含 `B10` | `B10` 行标记 `FAIL*`，汇总写 `FAIL=4 (另有已接受 1)`，并单列「已接受暴露面」段落列出 ID+理由 |
| `ACCEPTED_FILE=` （空） | 打印 `<disabled>`，等同未启用 |

要点：

- **判定仍是 FAIL**，`PASS` 计数不变，`FAIL*` 只表示「已裁决、不再作为待办」。
- 只匹配第 1 列 ID；ID 写错（拼写/大小写）静默不命中，避免误吞真正的回归。
- 汇总行 `FAIL=N (另有已接受 M)` 里 `N + M` = 原始 FAIL 数，便于和 P0 表对账。
- tsv 第 3 列理由会原样回显，**不要写敏感信息**（该文件进 git）。

离线三态验证（假 adb + `pm`/`getprop` stub，`/tmp/opencode/fk/`）：
默认 `FAIL=5 PASS=27 INFO=3`（与本轮真机的 5 项一致）→ 接受 `A1` 后
`A1 FAIL*` + 汇总 `FAIL=4 (另有已接受 1)` + 单列「已接受暴露面」段落 →
`ACCEPTED_FILE=` 打印 `<disabled>` 并回到 `FAIL=5`。真机复测同一台设备
（`SERIAL=5bf5bf85`）在默认全注释表下仍是 `FAIL=5 PASS=30 INFO=0`，
**逐项与引入前一致**。

#### 5.1.2 三个待裁项的落地成本实测（2026-11-07）

> 本节是**裁决前的成本实测**记录，保留原样。裁决结论见 §5.1.3（B10 已翻默认，
> A1/A2/B4/D1 已登记为「已接受」）。

**B10 `ksu_kaslr` — 选项② 已实现（2026-11-07 裁决后已是默认）**

- 现状：文件由链（`src/main.c` 的 `ks_persist_kaslr_file`）以 **shell uid + umask 022**
  写出 = `0644`；`/data/local/tmp` 是 `0711 shell:shell`（other 可穿越）→ app uid
  按名字直接可读。实测 app 域（`run-as com.postlock.boot`）读到
  `kaslr boot=4c069829… text=ffffffed22a80000 slide=0000002d12a00000`。
- 收 0600 后同一命令：`cat: /data/local/tmp/ksu_kaslr: Permission denied`，rc=1
  （实测后已 `chmod 644` 回滚，设备状态复原）。整轮扫描实测
  **`FAIL=4 PASS=31 INFO=0`，B10 转 PASS**（其余四项不变；
  输出存 `/tmp/opencode/suvtz-p1verify/rooted2_b10off/`）。
- `tools/postlock.sh` 的 `SUVTZ_KASLR_MODE` 当时默认 `0644`（= 裁决前行为）；
  restore 尾部（`kernel:s0`）对 `ksu_kaslr`/`ksu_payload` 做 `chown 2000:2000` +
  `chmod $KASLR_MODE`。owner 仍是 shell，下一轮链重写不受影响（`O_TRUNC` 不改权限）。
- **唯一代价**：app 自派发路径失去 KASLR 输入。该路径已随 PostLock-Boot 冻结
  （生产恢复走 host `postlock.sh`），所以代价 ≈ 0；但这仍是**威胁模型决定**，
  不是 bug 修复 —— 裁决结果见 §5.1.3（已翻为默认 `0600`）。

**D1 `persist.adb.tcp.port=5555` — 选项② 的代价是「冷启动失去网络通道」**

- 实测本机当前状态：**无 Wi-Fi**（`ip -4 addr` 只有 `rmnet_data3 10.22.105.208/27`），
  `adbd` 监听 `[::]:5555`，但 host 用 `192.168.137.10:5555` / `192.168.8.10:5555`
  都连不上（`device not found`），唯一通道是 USB `5bf5bf85`。
- 该项写入路径 = `/data/property/persistent_properties` 里的 30 字节 protobuf 条目
  （`postlock.sh` stage 的 `pp_adb_tcp.bin`），由 init 在 boot 时应用到
  `persist.adb.tcp.port`。`setprop persist.adb.tcp.port` 本身被 SELinux 死拒
  （即使 Permissive），所以「清空」也只能改同一个文件。
- 选项② 的真实后果：清空后**下一次冷启动 adbd 不再监听 5555**，而本机 LAN/tailnet
  本身就不是每 boot 可达的（本次实测连 IP 都没有）——一旦 USB 不在手边，
  失去的是**唯一的救回通道**（历史上多次靠它复联）。故倾向①保持。
- 若最终选②，改法就是一行的开关（restore 段跳过 `pp_adb_tcp.bin` 追加）；但
  **已写入的条目需要显式删除 + 一次 reboot** 才生效，不做「只对未来生效」的半态。

**B4 `/product/bin/su` — 三个选项都不免费**

- ① 接受现状：`-rwxr-xr-x root root 412B`，app 域 `ls` 可见、内容不可写。
  语义上 su **必须**能被任意「被授予」的 app exec，属主只能是 root；
  任何「对某类 app 隐藏」的方案都会命中同一批被授予的 app。
- ② `SUS_PATH` 打标：P0 实测已推翻——隐藏门控是
  `TIF_PROC_UMOUNTED && uid>=10000`，被授予 su 的 app 恰恰**不带**该标记，
  但同一 inode 的属主判定会让 `su` 在普通 app 世界里消失的同时**也影响
  su 自身的调用方一致性**（同 inode 同属主），收益是「少一个名字」，代价是
  可能把正常 su 调用打成偶发失败。不做。
- ③ 放弃 `/product/bin` 载体：su 只能经 `ksud debug su`（管道式，
  `printf '%s\n' "$*" | ksud debug su`）。功能可用，但每个走 PATH 的第三方脚本
  （YH_YC WebUI 等）都要改，且 `ksud` 的 execve 本身是 OPPO `oplus_exec_block`
  的上报源（会触发安全弹窗，靠 `oplus_check_suppress` 拦）。
  这是「用一个更大的可检测面换一个小名字」，不做。

#### 5.1.3 裁决落地（2026-11-07）

裁决口径：**B10 收（改默认）**，**A1 / A2 / B4 / D1 接受**（登记进
`tools/suvtz/accepted.tsv`，判定仍是 `FAIL*`，不伪造 PASS）。

| 项 | 裁决 | 落地 |
|---|---|---|
| B10 `ksu_kaslr` | **收** | `tools/postlock.sh` 的 `SUVTZ_KASLR_MODE` 默认 `0644` → **`0600`**；`0644` 可回退 |
| A1 管理器包名 | 接受（不立项） | `accepted.tsv` A1 行：套壳需换证书重签 + `manager_sign.h` 加自签 hash+size 重编 ko + ksud 带 `KSU_PACKAGE_NAME` 重编，且此后不能覆盖安装上游新版 |
| A2 工具包 | 接受（保留两个包） | `accepted.tsv` A2 行：`com.postlock.boot` 是 SUSFS app 域自检唯一载体（隐藏门控 `TIF_PROC_UMOUNTED && uid>=10000`，只有 zygote fork 的真 app 进程可观测），`com.postlock.privateapp` 是私有包对照组，都是验收基础设施 |
| B4 `/product/bin/su` | 接受 | `accepted.tsv` B4 行：属主只能 root；`SUS_PATH` 会把被授予 app 一起隐藏（su 直接失效）；改走 `ksud debug su` 会放大 execve 上报面 |
| D1 `persist.adb.tcp.port` | 接受（保持） | `accepted.tsv` D1 行：属性服务拒 `setprop`（即使 Permissive），只能预写 `/data/property` 且下次 boot 生效 → 不可「按需临时开」；当前无 Wi-Fi，USB 是唯一通道 |

**真机复测（同一 boot `4c069829`，仅 `chmod 600 ksu_kaslr` + 换表，无 reboot）**：

```
FAIL=0 (另有已接受 4)  PASS=31  INFO=0  总计=35     # rc=0
B10   PASS   cat: /data/local/tmp/ksu_kaslr: Permission denied
A1/A2/B4/D1  FAIL*  (已接受, 理由随行打印)
```

输出存 `/tmp/opencode/suvtz-p1verify/rooted3/`。收敛后的口径：
**未裁决 FAIL = 0**；剩余 4 项全部是显式裁决过的威胁模型取舍，
且每一项都保留可撤销路径（B10 换 env；其余删 `accepted.tsv` 对应行）。

**注意两点**：

1. B10 的代码改动要**下一轮 `tools/postlock.sh` / restore** 才会自动生效
   （restore 尾部 chmod）。本轮是手工 `chmod 600` 让设备状态与默认值一致。
2. 裁决是**当时的威胁模型判断**，不是永久结论。`accepted.tsv` 头部已写明：
   若登记项的实际数值变了（如 D1 换成别的端口、A2 多了第三个包），
   必须重新裁决而不是沿用旧理由。

## 6. 复跑方法

```bash
tools/suvtz/scan.sh                    # 完整输出（载体自动探测）
tools/suvtz/scan.sh -q                 # 只出汇总（一行 FAIL=/PASS=，落盘同名 .txt/.tsv）
SERIAL=<ip>:5555 tools/suvtz/scan.sh
PKG=com.postlock.boot tools/suvtz/scan.sh   # 显式指定 runas 载体
PKG= tools/suvtz/scan.sh                    # 强制不用载体（runas 段全 INFO）
```

**载体自动探测（2026-11-07 起）**：`PKG` 不设时，扫描器自己取第一个**已安装**的
验收载体（顺序 `com.postlock.boot` > `com.postlock.privateapp`，都会打一行
`carrier: <pkg> (auto)`）；一个都没装才退化成「无载体」（runas 段全 `INFO`）。
此前默认是「不设 = 不用载体」，等于零参数跑出来 32 项 `INFO`——那不算「能用」。
两个候选包是 §5.1.3 裁决保留的验收基础设施（A2 行），PostLock-Boot 冻结只是
「不再演进/不再同步 assets」，不是「不能用」。

**锁屏/休眠限制（2026-11-06 实测，2026-11-07 补原因归因）**：`run-as` 依赖 CE 存储，
设备锁屏休眠时 `dumpsys user` 报 `State: RUNNING_LOCKED`、`/data/data/*` 全是密文名，
`run-as` 一律 `couldn't stat /data/user/0/<pkg>`（对 `com.postlock.boot`、`com.termux`、
`com.postlock.privateapp` 全都一样）→ 扫描器 `runas_ok=0 runas_exec=0`，
A4/A5/B*/C*/D*/E* 全部记 `INFO`（30 项里只剩 A1~A3 能判；「另有已接受」也会从 4 掉到
2，因为 B4/D1 落在 runas 段）。**app 域测量必须先解锁**，而这恰恰是最需要 app 域的那批
判据（B1/B6/E2/E3 的隐藏语义都门控在 `TIF_PROC_UMOUNTED && uid>=10000`，shell 域永远
看不到被隐藏的世界）。

为了让「锁屏」不被误读成「扫描器坏了」，报告现在自带归因：

| 字段 | 含义 |
|---|---|
| `device_locked=0/1` | `dumpsys user \| grep -m1 "State:"` 命中 `RUNNING_LOCKED` |
| `runas_ok=0/1` `runas_exec=0/1` | runas 通道可用 / 可 exec |
| 提示行 | `device_locked=1` ⇒ 「设备锁屏未解锁…解锁屏幕后重跑同一命令即可」 |
| 逐条 reason | `$RUNAS_WHY`：设备未解锁(CE 存储不可用) / 载体无数据目录 / 载体不可调试 / 无 app 域载体 / run-as 失败(<原始错误>) |
| 汇总 `runas=ok\|no` | 台账一行看不出来时才最要命——`INFO` 多到底是视角退化还是新泄漏 |

输出落 `/tmp/opencode/suvtz/scan_<boot8>.{txt,tsv}`。**换 boot 后重跑**即可验证：

- **持久性判据**：上一 boot 的 FAIL 项是否在本 boot 仍为 FAIL（该 FAIL 是"每 boot 重犯"
  还是"一次性"）
- **回归**：原本 PASS 的项是否变 FAIL（改动引入的新泄漏）

### 6.1 每 boot 自动跑（P2 落地部分，2026-11-07）

`tools/postlock.sh` 尾部（verify 之后）新增一段旁路扫描，**恢复流程跑到尾就自动
产出一份观测面快照 + 台账**：

| 项 | 值 |
|---|---|
| 开关 | `SUVTZ_SCAN=0` 关闭（默认开） |
| 载体 | `SUVTZ_SCAN_PKG=<pkg>` 指定；不设则扫描器自动探测 |
| 输出 | `/tmp/opencode/suvtz/auto_<boot8>/scan_<boot8>.{txt,tsv}` + `stdout.txt` / `stderr.txt` |
| 台账 | `/tmp/opencode/suvtz/history.tsv`（`boot8 <TAB> 日期 <TAB> 汇总`，同一 boot 重跑整行替换） |
| 失败语义 | 只 `WARN` + 打 `scan:` 原因两行，**不影响恢复脚本退出码**；注意 `scan.sh` 的 `rc=1` 是「跑完了但有未裁决 FAIL」（扫描成功、结果不好），照样记账，只有拿不到汇总行才算失败 |
| 耗时 | 实测 71.5s（35 探针，USB，解锁态） |
| 锁屏补扫 | `SUVTZ_SCAN_DEFER=0` 关闭（默认开）；上限 `SUVTZ_SCAN_DEFER_TIMEOUT`（默认 10800s）、轮询 `SUVTZ_SCAN_DEFER_INTERVAL`（默认 30s） |

**诚实口径（重要）**：这**不是 boot hook**。PostLock-Boot 已于 2026-11-06 冻结，
设备上没有任何开机自跑通道；这段挂在**恢复流程**上——即「每次冷 boot 跑一次
`tools/postlock.sh`」= 「每次产出一份快照」。真正的「app 自身代码自跑同一套探针」
（设计期 P2 的终局形态）随该 app 冻结而未做，现行判据仍是 `runas_app` 视角的
必要条件，不是 `untrusted_app` 的充分条件。

台账的用法：跨 boot 看两件事——`FAIL` 计数是否变化（回归）、`INFO` 计数是否变化
（视角退化，多半是设备锁屏导致载体不可用，不是新泄漏）。**汇总行尾部带
`runas=ok|no`**：冷 boot 时设备常还在锁屏（`State: RUNNING_LOCKED`），那时
`runas=no PASS=1 INFO=32` 是**如实记录**（不是回归）。同一 boot 解锁后重跑，
台账同一 boot8 的行会被整行替换为完整快照。

**锁屏补扫（2026-11-07）**：`runas=no` 时 `postlock.sh` 会 `setsid nohup` 拉起
`tools/suvtz/wait_unlock_scan.sh`——后台轮询直到设备真正解锁（有载体时判据就是
`run-as <pkg> true` 成功，这正是 app 域测量需要的那项能力；无载体时看
`dumpsys user` 的 `RUNNING_UNLOCKED`），然后自动补跑一次 `scan.sh -q`、把完整
快照写进同一 `auto_<boot8>/` 目录（**覆盖前先把锁屏那份另存
`scan_<boot8>_locked.txt`**）、更新台账，并在 `defer.log` / `defer_status.txt`
留痕。它不阻塞恢复流程、不写设备（`scan.sh` 全是只读探针），退出码语义：
`0` 已补跑（`defer_status.txt` = `OK`）/ `2` 等解锁超时（`TIMEOUT`）/ `3` boot
已变（`BOOT_CHANGED`，下一轮恢复会覆盖）/ `4` adb 连续 6 次不可用（`ADB_LOST`，
拔线/断网）/ `5` 补跑本身失败（`SCAN_FAILED`）。这样「冷 boot 一次 = 一份快照」
在设备锁着时也不会只留下 32 条 INFO。

只在**确实锁着**时挂补扫：报告头 `device_locked=1` → 挂；`device_locked=0` 说明
设备已解锁，此时仍 `runas=no` 是「没有可调试载体」，等也等不来，只打一句提示；
报告头**没有**该字段（旧版 `scan.sh` 产物）按「可能锁着」处理并照样挂——后台补扫
无害，漏挂才会留下一份只测了 3 项的废快照。同一输出目录只允许一个补扫
（`defer.pid` 活着就直接退出），重复跑 `postlock.sh` 不会叠出两个 70 秒扫描；
补跑完仍然 `runas=no` 会在 `defer.log` 里额外记一行提示。

## 7. X 类：成对交叉验证（2026-11-07 新增）

单点探针的 PASS 有可能来自「这条读取通道恰好被挡住」，而不是「对象真的不可见」——
例如 `ls /data/local/tmp` 被 0711 挡住，但 `cat /data/local/tmp/ksud` 按名字直接能读
（P0 里 B2 PASS / B7 FAIL 就是这一对）。单点探针看不出这种不一致。

所以追加 **5 条成对探针（X1–X5）**：同一个事实用两条**独立通道**各测一次，要求同向。

| ID | 事实 | 通道 A | 通道 B |
|---|---|---|---|
| X1 | 模块是否可被枚举 | `grep -c kernelsu /proc/modules` | `ls /sys/module/kernelsu` |
| X2 | 内核符号面 | `grep -c -e ksu_ -e susfs_ /proc/kallsyms` | `grep -c kernelsu /proc/modules` |
| X3 | 挂载视图 | `grep product/bin /proc/self/mountinfo` | `grep -c product/bin /proc/self/mounts` |
| X4 | 物料面 | `ls /data/local/tmp`（父目录可枚举） | `ls /data/local/tmp/ksu_boot`（子目录可列） |
| X5 | 进程面 | `ps -A -o NAME`（工具抽象） | 直接枚举 `/proc/*/comm`（原语通道） |

判定规则（`pair_side` + 主循环）：

| A | B | 判定 | 含义 |
|---|---|---|---|
| 都不可见 | | PASS | 两条通道一致，可信 |
| 都可见 | | FAIL | 一致泄漏（单项探针也会报，X 不给更宽松的结论） |
| 一可见一不可见 | | **FAIL** | **通道分歧**：存在未建模的读取路径，必须定案 |
| 任一侧测不出 | | INFO | 不猜 |

分歧比单项 FAIL 更有信息量：它指出「哪条路没堵住」，而不是「某个对象能看见」。

### 7.1 顺带修掉的一个假阳性

X5 的通道 A 用 `ps -A -o NAME`，而 toybox `ps` 的 `-o` 支持随版本变化。实测
（host 版 toybox）不支持的写法会返回**用法文本**，文本里带数字（`Try 'ps --help
simple|list'`）→ `judge zero` 数到数字 → 判成 **FAIL（假泄漏）**。

这是诚实性缺陷：命令**跑起来了但参数不被支持**，属于「没法观测」，不是「观测到了」。
已在 `judge()` 增加 `broken` 识别（`unknown .*format specifier` / `try '...--help` /
`usage:` / `^用法`），命中后在 `absent` / `empty` / `zero` / `value:*` 四个分支一律记
`INFO`（原因「命令能力不足(参数/工具不支持)」）。这条对 A4/A5 同样生效。

### 7.2 离线验证（无设备时先跑通链路）

用假 adb（把 `shell` 的实参交给本机 `sh -c`，并补 `getprop` stub）跑完整扫描：

```
FAIL=2  PASS=30  INFO=3  总计=35          # 假环境里 D1/D6 值不对属预期
A4/A5  INFO  (命令能力不足)                # broken 识别生效
```

三个判定分支逐一验证过：

- 同向不可见 → `X3 PASS A=0 | B=0 (两通道同为不可见)`
- 通道分歧 → `X3 FAIL A=1 | B=0 (通道分歧 A=可见 B=不可见)`（注入一条假
  `mountinfo` overlay 行触发）
- 一侧测不出 → `X5 INFO (至少一侧测不出(A=测不出 B=不可见))`

真机结果待解锁后重跑补齐（锁屏时 runas 段全 INFO，见 §6）。
