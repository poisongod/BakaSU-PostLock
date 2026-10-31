# 新设备全链适配方案（untrusted_app + shell 双域）

> 目标：在一台**全新 Android 设备**上把链（CVE-2026-43499 提权）+ KernelSU
> 恢复链在 **shell 域**与 **untrusted_app 域**两条路径全部打通，终态 =
> BakaSu 蓝卡「工作中 Built-in」（真驱动真 store，SELinux enforce=1）。
>
> 基准参照：OPPO A96 (PFUM10 C.48, SM6375, 5.4.254-qgki)——本文把它的经验
> 拆成「通用层」与「设备层」，新设备只需重做设备层。
> target.h 生成命令细节见 README「生成 target.h / 添加新 target」，本文不重复。

## 0. 分层模型（谁通用、谁要重做）

| 层 | 内容 | 新设备动作 |
|---|---|---|
| 链本体 | LD_PRELOAD 构造器触发、KASLR slide、collision、mm leak、pselect route、pipe physrw、CFI | **不改代码**，纯参数/抽签 |
| target | `src/targets/<p>/target.h`（168 宏：符号地址 + 结构偏移） | **必重生成**（同内核镜像的同型号可复用） |
| 模块 | kernelsu.ko / hotload / ocsk / ksud / finitmod / su | kernelsu+hotload **重编**（vermagic）；ocsk 仅 OPPO |
| 厂商墙 | 反 root 探测、后台冻结、自启动拦截、sepolicy | 按厂商逐项替换（§8） |
| 域差异 | shell:s0 vs untrusted_app（seccomp+SELinux 墙） | **AOSP 通用**，绕过方案已落地（§5） |
| 恢复链 | postlock.sh / restore.sh / sepolicy_enforce1.txt | sepolicy **必重推**；其余改路径即可 |
| app | PostLock:Boot（gate/staging/UI） | 设备无关，PAYLOAD_VERSION 幂等 |

链对厂商的唯一硬依赖 = OPPO `oplus_root_check_succ`（`root.c patch_oplus_root_check`
查 kallsyms，**查不到安全跳过**）——非 OPPO 设备链照常 root，只是没有 ocsk
这层「app 提权回滚拦截」。

## 1. 层0 前置侦察（gate，全程只读）

新设备到手先跑这张清单，产出 GO/NO-GO：

```bash
adb shell getprop ro.product.model; getprop ro.build.version.release
adb shell uname -r                          # 内核版本（决定源码树路线）
adb shell cat /proc/cmdline                 # BL 状态只认这里（vbmeta.device_state）
adb shell 'zcat /proc/config.gz | grep -E "CONFIG_MODULES=|MODULE_SIG|IKHEADERS|IKCONFIG|DEBUG_INFO_BTF"'
adb shell cat /proc/sys/kernel/modules_disabled        # 0 才能 insmod
adb shell ls /dev/ashmem                    # 链 route 载体；不存在 = 链死（见下）
adb shell 'ls /sys/kernel/btf/vmlinux'      # BTF 在 = 结构偏移可精修
adb shell getenforce
adb shell 'cat /proc/sys/kernel/perf_event_paranoid'   # app 域 KASLR 泄题依赖 ≤0
```

判据：

- **`/dev/ashmem` 不存在** → 链的 fops route 载体缺失（ASHMEM_* 宏族），
  需要找替代 misc 驱动重做 route（大改，建议先判 NO-GO）。ashmem 自 5.4 后
  的 GKI/新内核逐步移除——**5.4 系厂商内核基本都在，6.x+ 必查**。
- **`MODULE_SIG_FORCE=y`**：本机实测 APatch 内核运行时未强制（finitmod 仅
  taint）；原生强制设备 → finitmod EKEYREJECTED，模块路线死，只剩裸链 root
  （无 KernelSU 持久化），回来与需求方重新对齐。
- **BL 锁状态**：解锁 = 可 fastboot 取 boot.img；回锁 = 链是唯一自举路径
  （对齐本仓回锁 SOP）。
- **厂商反 root 特征**：`getprop | grep -iE 'miui|oplus|vivo|sar'`、
  `/system/bin/su` 是否伪造 stat、kpatch/APatch 残留——决定 §8 厂商墙清单。
- **内核源码树可用性**：同厂同 SoC（如 oppo-source sm6375 树）最佳；GKI
  设备可用通用 android-mainline/common 树；都没有 → kernelsu.ko 编不了，
  模块路线 NO-GO。

## 2. 层1 target.h 生成

三样输入：`boot.img` + `profile.json`（物理地址）+ BTF/kallsyms。

1. **取 boot.img**：解锁设备 `adb pull`（A/B 设备拉活动 slot：`boot_a`/`boot_b`），
   或 `fastboot boot` 临时引导。
2. **取 profile**（`p0_phys_offset` / `p0_kernel_phys_load`）：
   - 已有任意 root 通道（APatch/KSU 残留）→ `make detect-profile`（读
     `/proc/iomem`）最准；
   - 全新未 root 高通设备 → xbl_config 路线
     （`tools/generate_target.py --boot boot.img --xbl-config xbl_config.img`）；
   - MTK → vendor_boot 路线。
3. **生成**：`make generate-target PROJECT=<p> BOOT=boot.img PROFILE=profile.json`。
   BTF 缺失走 fallback（符号仍准、结构偏移继承模板）——header 顶部有
   warning 标注，此时 §4 首跑要格外盯结构相关死点。
4. **编译**：`make PROJECT=<p> -j$(nproc)` → `build/<p>/bin/preload.so`。

生成后必查的 per-device 高危宏（fallback 轮或首跑失败的第一批怀疑对象）：

| 宏 | 语义 | 失败特征 |
|---|---|---|
| `MM_STRUCT_SZ` | mm cache 对象大小 | mm_struct scan `found=0` 连败（§4） |
| `PSELECT_*_SHIFT` / simple layout | route 内核栈布局 | pselect `_raw_spin_trylock` panic 家族 |
| `KMALLOC_CACHES` | kmalloc slot | prepare/convert 全程 `sc` 异常 |
| `SELINUX_BLOB_SIZES` / `SECURITY_HOOK_HEADS` | SELinux 写路径 | root 写段 selinux flip 失败 |
| `WAITER_*` | rt_mutex waiter 布局 | route 后 PI 链 oops |
| `BSS_LOCK_PAD_OFF` | fake rt_mutex pad | route fault 地址计算错 |

## 3. 层2 模块三件套重编

| 产物 | 依赖 | 新设备动作 |
|---|---|---|
| `kernelsu.ko` | 同 vermagic 内核源码树 + clang | 建树（厂商树升级 LTS 或 GKI 通用树），`vermagic` 覆盖为目标 `uname -r`；UAPI 对齐管理器版本（红条判据） |
| `kernelsu_hotload_init.ko` | BakaSU fork 导出符号 | 跟随 kernelsu 重编（vtable `struct_size` 双侧同步） |
| `oplus_check_suppress.ko` | OPPO `oplus_root_check_succ`/`do_group_exit` 锚点 | **仅 OPPO 系**；其他厂商跳过（§8） |
| `ksud` / `finitmod` / `su` | aarch64 userspace | **通用**（`build/embed/` 现成），不动 |

kernelsu.ko 编译命令与四坑（`CONFIG_KSU=m` 必传等）见 AGENTS「kernelsu.ko
重编」节；fork 版本纪律 = dirty 不 commit（rev-list 恒定）。

## 4. 层3 shell 域链适配（老师卷路径）

**硬前置：fresh boot**（SLUB 干净，boot 后 uptime < ~10min 或刚重启完）。

首跑即按考试判据链验收，逐段归因：

```text
KASLR perf leak → collision(5) → mm_struct scan(found≥1) → payload gate
→ route attempt=1 → fix52 cfi ok → win tick dead=0 → convert owned=1
→ pipe-physrw-summary done=1 root=1 → CHAIN_EXIT_DONE → restore OK
```

per-device 调参入口（全部 env，见 AGENTS 运行节）：

- **route 段 pselect panic**（`_raw_spin_trylock` / rt_mutex 栈）：
  fdset 布局是内核源码级差异（`core_sys_select` 栈/堆分界 = `sizeof(stack_fds)/6`，
  本机 5.4 是 nfds≤320 走栈）。新内核先确认该分界，再试
  `SLIDE_PSELECT_SHIFTS=<n,...>` 扫布局；错误 shift = panic，不可自适应循环。
- **mm_struct scan 连败**：`--mm-struct-sz` 覆盖重生成，或 KSNITCH_* 调线程/碰撞数。
- **payload 捕获弱**（gate 强放行后 cfi garbage）：`KS_PIPE_SLABS` 档位适配
  （未提权时受 `pipe-user-pages-soft=16384` 硬上限，15 档安全）。
- **owned=0 满页**：SLUB 环境抽签，`KS_WAVE_FLAT_MAX=24` + fresh boot 缓解。
- 已知**通用抽签家族**（与设备无关，靠 fail amplifier 重考）：δ 相位
  `opening ashmem` ~1/6、win 段页死、fake 表槽污染、root child SIGKILL。

链超时/安全失败判据与处置照 AGENTS 考试轮纪律：判明即 reboot 换 fresh boot。

## 5. 层4 untrusted_app 域链适配（学生卷路径）

**三个 app 域死原语是 AOSP 通用行为，不是厂商墙**——绕过方案已全部落地且
设备无关，新设备直接复用：

| 死原语 | 机制 | 绕过（泄题，合法辅助） |
|---|---|---|
| `perf_event_open` | seccomp/SELinux 拒 untrusted_app | shell 泄题轮 `KS_KASLR_ONLY=1` → `/data/local/tmp/ksu_kaslr` 共享文件 |
| tracefs kprobe | DAC 拒 app 写 | shell 泄题轮 `KS_PREPARE_HALT=1800` 持页 → `ksu_payload` → app `KS_PAYLOAD_PASTE=1` |
| configfs 读通道 | route 前鸡生蛋 | 同上 paste；`KS_SLIDE_SKIP=1` 跳 pselect slide（app 域必 panic 家族） |

app 域链 = 上述三 env + public app `triggerChain` direct（BOOT_COMPLETED 自启）。

**新设备差异点只有厂商后台行为**：

- **后台冻结**（OPPO HANS / 小米 / vivo 各异）：保活三保险（前台 activity +
  全屏 intent + `setAlarmClock`）是 AOSP 通用组合，已验证免疫 HANS；新厂商
  首跑盯 `wchan=__refrigerator` 判据（冻结 = 线程 D 状态在冰箱）。
- **BOOT_COMPLETED 拦截**：OPPO 实测不拦；小米/华为有自启动管理白名单，
  需用户一次性授权引导（app 内已留提示位）。
- **force-stop 铁律**：exclude-stopped 是 AOSP 行为，装机后必须 am start 解锁。
- **adb 回环 AUTH**：adbd 拒 loopback 源授权是本机 AOSP 12 实测；新版本
  行为可能变（回环通道仅供公共 app 探测，链不依赖它）。

## 6. 层5 恢复链适配（root 后持久化）

链 root=1 后 `KS_COLDSTART` fork restore.sh（uid0 kernel:s0）：

1. `setenforce 0` 临时窗口 + cp 三件套（preload/ksud/su）到工作目录；
2. finitmod **kernelsu.ko**（链已写 `sig_enforce 1→0`，否则 EKEYREJECTED）；
3. finitmod **hotload**（依赖 kernelsu 导出符号，反序必 ENOENT）；
4. finitmod **ocsk**（仅 OPPO；WARN-only）；
5. `ksu_debug_manager_appid=<MUID>`（运行时 `pm list -U` 动态解析）；
6. overlay `/product/bin`（必须带 `context=u:object_r:system_file:s0`，
   否则 ENOTSUP）+ wrapper（ksud 走 `/data/local/temp` 本体，链接 system_file
   在 shell 域 exec 被拒——fix76）；
7. **sepolicy 注入**（Permissive 期）：`ksud sepolicy apply <file>`；
8. fix81 翻 `enforce=1` + 纯内建写双 OK marker。

**sepolicy 必重推**：`tools/sepolicy_enforce1.txt` 的 18 条（shell↔ksud↔su
数据通路、socket、temp 读写）是 OPPO C.48 policy 下逐条实测的——新设备
policy 不同（版本号/policydb 差异），照「shell 域数据访问被拒 → audit2allow
拟规则 → ksud sepolicy check 验证」流程重推，判据不变（check rc=0 + 蓝卡
数据功能全通）。

ksud 三事件默认关（fix59：boot 后期重放打崩 zygote）；模块脚本激活另立
安全路径，不随适配范围。

## 7. 层6 验收判据（双域 × 四阶矩阵）

| 阶段 | shell 域判据 | app 域判据 |
|---|---|---|
| 链 root | `pipe-physrw-summary done=1 root=1` + `uid=2000->0 selinux=1->0` | 同行 + `uid=<appid>->0` |
| 恢复 | `POSTLOCK-RESTORE-OK` + `SELINUX-STRICT-OK`（双 OK 原生，无人工） | 同左（restore 由链内 KS_COLDSTART 跑，与触发域无关） |
| 稳定 | restore OK 后 120s+ boot_id 不变（无延迟 panic） | 同左 |
| 终态 | `enforce=1` + `ksud debug su` → uid=0 + BakaSu 蓝卡「工作中 Built-in」无红条 | 同左 |

连续三次独立 fresh boot 合格（连续计数制，失败归零）才算适配完成。

## 8. 厂商墙清单（逐项替换）

| 墙 | OPPO 实现 | 通用/替换 |
|---|---|---|
| 提权回滚探测 | `oplus_root_check_succ`（syscall exit 检 euid 翻转） | 链 root 不经它（安全跳过）；app 侧 ksud 提权会被拦 → ocsk 拦截。**其他厂商先 pstore/dmesg 定位同类探测**，无同类则跳过 |
| 安全弹窗/强制重启 | `kevent_send_to_user` → exsystemservice 15s 重启 | ocsk v12 探针；无同类跳过 |
| 后台冻结 | HANS（uid 级 cgroup freezer） | 三保险保活通用；wchan 判据通用 |
| 自启动 | 不拦 BOOT_COMPLETED | 拦截型厂商 → 用户白名单引导 |
| SELinux 数据通路 | sepolicy_enforce1.txt 18 条 | **必重推**（§6.7） |
| 无线调试 UI | OPPO 设置 UI 路径 | 各厂设置路径不同，仅影响 adb 引导文案 |

## 9. 执行顺序总表（新设备从零到 3/3）

```text
Day 0  gate 侦察（§1）→ GO/NO-GO
       取 boot.img + profile → generate-target → make（§2）
Day 1  建内核树编 kernelsu.ko + hotload（§3），vermagic 实测加载
       fresh boot shell 域首跑（§4），调 target 高危宏至 root=1
Day 2  restore.sh 路径适配 + sepolicy 重推（§6）
       shell 域连续 3 次合格（§7）
Day 3  app 域泄题轮 + BOOT_COMPLETED 轮（§5），连续 3 次合格
       厂商墙逐项复核（§8），文档回填（本文 + AGENTS 厂商差异节）
```

host 依赖：NDK r29（链）、clang + 内核树（模块）、llvm-objdump（target 生成）、
adb（WSL 场景用 adb.exe + Windows 路径，见 AGENTS 本机环境节）。
