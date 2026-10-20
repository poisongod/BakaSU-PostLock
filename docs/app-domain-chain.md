# untrusted_app 域链路设计（app-domain chain design）

状态：v1 设计稿（2026-10-20），分支 `untrusted_app`。
前置定案：链全程在 untrusted_app 域自跑（用户约束「提权链禁走 shell 域」）；
shell/adb 辅助仅限代读写文件（共享 KASLR 文件，第七轮定案）；不 setenforce、
不改 perf_event_paranoid；前台 activity 保活（HANS 已解，v1.5+）。

## 0. 结论摘要

app 域缺的不是单一原语，而是**「payload 落地证据」三件套**（perf tracepoint、
kprobe/tracefs、watchpoint 全死）+ **slide/route 的 pselect 栈布局**。
KASLR 已有共享文件方案（实测 ✓）；KernelSnitch 是纯用户态 timing（不依赖
perf/tracefs），失败属调参问题而非权限墙；pipe physrw → root 段原语在 app 域
无已知拒绝。设计 = 重修 gate 证据链 + 稳定 timing + 实测 route。

## 1. 归因修正（先于设计）

| 旧归因（AGENTS 第七轮） | 修正后（代码级，2026-10-20 调研） |
|---|---|
| `fix36 phase2 tp ctrl=-1 n=0` = tracefs 被拒 | **tp 窗口完全不碰 tracefs**：实现是 `perf_event_open(PERF_TYPE_TRACEPOINT)` + `SET_FILTER`（`util.c:2121` 注释明言 "neither touches tracefs"）。`ctrl=-1 n=0` = tp 打开全部失败（`util.c:2341` `id<=0` 早退）= **seccomp 拒 perf_event_open** |
| tracefs 被拒杀掉 tp 窗口 | tracefs 被拒杀的是 **kprobe fetch**（payload content verify / layout pvo 探测），不是 tp |

其余归因不变：kprobe 内容读死于 tracefs SELinux；watchpoint 死于内核地址
EINVAL（shell 同死）；slub shrink errno=13 非致命（shell 同拒）。

## 2. app 域原语现状总表

| 原语 | 依赖 | app 域 | 说明 |
|---|---|---|---|
| KASLR 共享文件 | 读 `/data/local/tmp/ksu_kaslr` | ✓ 实测 | shell 轮 `KS_KASLR_ONLY` 写文件；boot_id + 范围校验 |
| KASLR perf 泄漏 | perf_event_open | ✗ | seccomp |
| KASLR slide（pselect 栈） | pselect fake lock | ✗ | app uid 必 panic（第六轮实测）→ 共享文件绕开 |
| fix36 tp 窗口 | perf_event_open(TRACEPOINT) | ✗ | seccomp（本设计的核心死点之一） |
| kprobe fetch | tracefs | ✗ | SELinux |
| watchpoint | perf HW breakpoint | ✗ | 内核地址 EINVAL，shell 同死 |
| configfs 内容读（ashmem deputy） | /dev/ashmem + pread | ✗ 已定性 | **M1 完成（2026-10-20）**：原语依赖 misc.fops 已被 route 劫持——pre-route 新 ashmem fd 的 `->read` 是真 `ashmem_read`（未 mmap 恒返回 0），`r1=0 r2=0` 与 payload 落地无关；page/pos 回绕算术一直正确。**verify 时点不可用是时序死锁**，非 bug 可修 |
| KernelSnitch mm_struct | cntvct_el0 + futex PI | ✓ 实测 | 纯用户态 timing；boot a56430b0 `found=0`×3 后，c631fae8/c9f7af69 各轮 8/8 `found=1` 稳定（D3 降级为观察项） |
| /proc/&lt;child&gt;/mem | SELinux ptrace | ✗→已修 | untrusted_app 读任何其他进程 mem 被拒（同 uid 同 domain 也拒）→ **child self-open `/proc/self/mem` + SCM_RIGHTS 传父**（fd open 后无限制，FMODE_UNSIGNED_OFFSET 语义等价），commit ffec4212 |
| Phantom process killer | AMS | ✗→已关 | app 派生子进程超 32 配额被 `Trimming phantom processes` 批杀（round1/2/4 静默死根因）→ `settings put global settings_enable_monitor_phantom_procs false`（持久跨 reboot；已写入） |
| collision / futex PI | futex | ✓ 实测 | |
| bruteforce / prepare storm | /proc、mmap、clone | ✓ 实测 | 前台保活下推进 i=8489+ |
| /proc/slabinfo、buddyinfo | procfs | ✓ | |
| slub shrink | /sys/kernel/slab/…/shrink root 600 | ✗ | 非致命 warning（shell 同拒），接受 |
| pipe / F_SETPIPE_SZ / SIOCINQ | pipe | ？ | 无 app 域拒绝记录，待 route 走通后实测 |
| pselect fake-lock route | pselect 栈布局 | ？ | 与 slide 同机制，**app 域未实测**（链从未走到）→ 主风险 D4 |

## 3. 死点设计

### D1 KASLR —— 已解决，保持现状

共享文件路径不动：shell/回环轮 `KS_KASLR_ONLY=1`（无需 root）写
`ksu_kaslr`（boot_id + 范围校验），app 轮 `kaslr_from_shared_file()` 消费
（`main.c:547`）。slide 的 pselect 路由在 app 域永不可用（布局错位 panic），
不投入修复——它的存在只为 shell 域兜底。

### D2 payload gate 证据链重修（核心）

**现状**：gate 三级（`util.c:3930` 附近）——
`fv>=0`(content) → `wp_armed`(watchpoint) → `drain_capture`(tp 证据)。
app 域：content 的 kprobe 分支死（tracefs）、watchpoint 死（EINVAL）、
tp 分支死（perf）→ 三级全灭 → `pass=0` → prepare 72 次耗尽、链死在 route 之前。
configfs content 分支（`util.c:3842`）是第四希望但实测 `r1=0 r2=0`。

**设计（按优先级）**：

1. **M1 先修 configfs content 分支**——它不需要 perf/tracefs，机制是
   ashmem `SET_NAME` 混淆 deputy + `pread`（`util.c:1459`），全部接口 app 域
   理论可用。`r1=0 r2=0`（pread 返回 0 字节而非 -1）的根因未知，取证动作：
   app 域轮带 `KS_CFGFS_LOG=1`，看 `cfgfs read … fill/pos/page/set/rd/errno`
   全参数（`util.c:4127`），区分三种可能：
   - a) **payload 真没落地**（上游 prepare 问题 → 上游修，gate 没错）；
   - b) **deputy 状态没建立**（SET_NAME 语义在该 boot/该 uid 下差异 → 修原语）；
   - c) **skb_payload_base 本身错**（布局 pvo 依赖 tracefs 探测，app 域拿到
     的是静态 target → 校准 layout fallback）。
   修通后 `content_ok` 即恢复，gate 回到第一优先级，**不再需要 tp**。
2. **行为证据 gate（fallback，待评估）**：不读内核内存，用受害者 fd 的
   ioctl 返回值差异判定 fake fops 是否接管。fix35 注释称该路 `capture=0,
   rv=-1` 曾不可靠——需重评估当时失败是「capture 真没发生」还是「行为判定
   设计缺陷」；若前者，行为证据在 payload 真落地时是可用的 Tier-0 判据。
3. **放弃** tp oracle（perf 无替代：tracepoint/HW breakpoint 全走
   perf_event_open，seccomp 不可绕——`patch_task_seccomp` 是 root 后步骤，
   鸡生蛋）与 kprobe 分支（tracefs 无 app 域访问路径）。
4. **兜底策略**：若 1、2 均不可行，app 域接受「无证据直进 route」——
   沿用 shell 域 run24/25 的 fail→panic→reboot 换 boot 放大器定性
   （见 AGENTS），代价是每失败轮一次 reboot，成功率取决于 payload 自然
   落地率。仅作最后手段。

### D3 KernelSnitch timing 稳定化（M2）

**定性**：不依赖 perf/tracefs（`cntvct_el0` 指令 + futex PI），syscall 层
已被 collision 通过实测证明可用 → 失败是 **timing 噪声/范围问题**，不是墙。

动作（按代价排序，全部是 env 调参，先测后改码）：
1. `KSNITCH_IDENTITY_START/END`（`kernelsnitch.h:274`）收窄 identity 窗口
   ——共享 KASLR 文件给了正确 base，window 已知，扫描范围可压到最小；
2. `KSNITCH_COLLISIONS` / `KSNITCH_THRESHOLD_MULT`（默认 10）调参——
   app 域前台+亮屏下重测 `approx_time` 分布，阈值随噪声底重标定；
3. 绑核与提频：确认 `pin_to_core(CORE)` 在 app 域生效（sched_setaffinity
   无权限墙）；wakelock + 前台已保 CPU 不睡，若仍抖则加大样本数
   （`KSNITCH_SAMPLES` 类旋钮，若无则加）；
4. 若仍不稳 → 定位 mm_struct 的**消费点**，评估能否用 prepare 阶段已有的
   bruteforce 结果直接喂下游（bruteforce 与 leak 是两次独立测量还是同源）。

### D4 pselect route 的 app 域风险（M3 实测后再定）

**风险**：slide 与 `do_pselect_fake_lock_route`（`fops.c:994`）同用 pselect
栈 fake-lock 机制。slide 在 app uid 必 panic 已实测；route 在 app 域**从未
被走到**（链死在更早阶段），同机制推断大概率同样 panic——这是修通 D2/D3 后
的下一个硬墙。

**设计（若实测 panic）**：
1. **静态预计算 app 域 shift**：栈布局差异 = SELinux 检查帧（app uid 每 fd
   多帧）。差异是确定性的（同 uid、同 fd 集合 → 同布局），从内核源码树
   （`/home/yang1/opencode-work/kernsrc/sm6375-v15`）反汇编 pselect 路径的
   security/avc 调用链，算出帧深差，**一次性**写入 `SLIDE_PSELECT_SHIFTS`
   单值——不是运行时试错（错误 shift = panic，不可循环）。
2. **owner 哨兵安全化**：fake lock 的 owner 指针字段填哨兵使 walk 安全失败
   ——仅当哨兵值能让「错布局」在 deref 前被识别时可行；若 walk 必 deref 则
   此路不通，需与 1 配合（先算对再进）。
3. 判据：M3 轮链日志走到 `main cmp_requeue` 后不 panic 且
   `route=pselect ... uid=10xxx` 行完整 → 通过；panic → pstore 取证 + 走 1。

### D5 tracefs/kprobe 依赖的旁路收敛

layout 的 pvo/VM 探测依赖 kprobe fetch（app 域死）→ app 轮一律走
**静态 target fallback**（target.h 静态偏移）+ env 注入
`KS_LAYOUT_PVO/KS_LAYOUT_VM`（由 shell 轮写文件传递，属 D1 同类文件辅助）。
`KS_TRACEFS_SUDO` 在 app 域无 su，不存在代写路径，代码保持现状（安全失败）。

### D6 明确不投入

- slide pselect 路由的 app 域适配（共享文件已覆盖）；
- watchpoint / tp oracle / kprobe 的 app 域恢复（各有不可绕的权限或硬件墙）；
- slub shrink（非致命，shell 同拒）。

## 4. 实施里程碑

| 里程碑 | 动作 | 通过判据 |
|---|---|---|
| **M1 configfs 根因** ✅ | ~~取证 `r1=0` 根因 → 对症修~~ | **结论**：原语 pre-route 结构性不可用（时序死锁，见 §2）；gate 改 faith 分支（§6 M1 报告），commit 252b4672 |
| **M2 timing 稳定** ✅ | KSNITCH env 收窄/调参轮测 | 现状 8/8 `found=1` 已稳定（观察项保留） |
| **M3 route 实测** | M1+M2 后链推进到 route | `main cmp_requeue` 后无 panic、走完 CFI；若 panic → shift 静态预计算。**2026-10-20 首测：faith gate 生效、链进 route、app 域 pselect route panic（BOOT_COMPLETED 循环三 boot）**→ 当前阻塞点 |
| **M4 physrw→root** | 全链 | `pipe-physrw-summary … root=1` + DONE rc=0 + 120s 无 reboot |

每轮失败照 fail 放大器定性处理（reboot 换 fresh boot）；取证走
`run-as org.postlock.boot` / 新包名 `com.postlock.boot`。

## 5. 风险登记

- **R1（高）**：D4 route 布局——D2/D3 修通后才检验得到，静态预计算工作量
  未知（内核源码在手，可做，但 security 帧深分析要细致）。
- **R2（中）**：configfs `r1=0` 若归因为 (c) layout，pvo 静态值在不同 boot
  可变（pvo 每 boot 滚动已实测 5 值）→ 需文件辅助传递当轮 pvo。
- **R3（中）**：KernelSnitch 若调参后仍不稳 → 需要动码加采样或换测量设计，
  工期不可控。
- **R4（低）**：pipe/F_SETPIPE_SZ 在 app 域受 `pipe-user-pages-soft` 上限
  约束（默认 16384 页 = 512 根），历史解法 `KS_PIPE_SLABS=15` + prep 提
  soft——app 域无 root 写不了 sysctl，须沿用降根数参数（15 根档位在
  shell 域 fresh boot 已验）。
- **R5（低）**：HANS 保活依赖前台 activity（v1.7 已验），用户若手动切后台
  或熄屏且系统策略变化，链会静默停——已在 app 层兜底（KEEP_SCREEN_ON）。

## 6. M1 完成报告（2026-10-20，rounds 1-6，boot c631fae8/c9f7af69）

### 根因链（按发现顺序）

1. **`/proc/<child>/mem` SELinux 拒**（round3）：`open_memfd()` 父进程打开
   子进程 mem，untrusted_app 的 ptrace 检查连同 uid 同 domain 的子进程都拒
   → `SYSCHK(open(path,O_RDONLY)): Permission denied` 静默杀链。修 = child
   self-open `/proc/self/mem` + socketpair SCM_RIGHTS 传父（fd open 后不受
   限，FMODE_UNSIGNED_OFFSET 不 pin mm 语义等价），commit `ffec4212`。
2. **Phantom process killer**（round1/2/4「静默死」实锤）：`am_kill …
   Trimming phantom processes`——app 派生子进程超 32 配额被 AMS 批杀。
   修 = `settings put global settings_enable_monitor_phantom_procs false`
   （一次写入跨 reboot 持久；部署脚本须含此步）。
3. **configfs read 原语 = 时序死锁**（round5 `r1=0 r2=0` 定案）：`cfgfs_read`
   的 pread 只在 misc.fops 已被 route 劫持后才走 `configfs_read_file`；
   pre-route 新 ashmem fd 的 `->read` 是真 `ashmem_read`（未 mmap 恒返 0）。
   ashmem_area/configfs_buffer overlay 布局与 page/pos 回绕算术逐字节核对
   全部正确——**原语在 verify 时点结构性不可用**，不是 payload 落地问题。
   `g_fops_probe_fd` 只在 route 阶段存在（fops.c:1558/1687），换 fd 无解。
4. **gate 四判据全灭 → faith 分支**：tracefs 拒（fv=-1）、configfs 时序
   死锁、watchpoint EINVAL、tp 窗口 seccomp 死（tpw2.n=0 → hit_evidence
   恒 0 → **无限 prepare-retry 风暴**，round5 的 pid 阶梯）。修 = gate 加
   「无 oracle 可用 + base/drain 行为证据 → fail-amplifier 放行」，commit
   `252b4672`。生效实证：faith 后链首次进 route（round6 t22365 打出
   `main cmp_requeue`）。
5. **slide pselect probe = app 域卡死/panic**（rounds 3/6 + panic 循环）：
   fake rt_mutex 落在带 SELinux per-fd 检查帧的 pselect 内核栈上，轻则
   child 永不泄漏（parent 永等 `read()`，round6 停 `slide attempt 1
   using shift=0` 200s），重则 deref 栈垃圾 panic。产物全有 fallback
   （KASLR=共享文件、pvo=静态）→ `KS_SLIDE_SKIP=1` 拒绝探测（fail
   closed），commit `3911eaec`。
6. **BOOT_COMPLETED panic 循环**：无 gate 的 BootReceiver 在每次 reboot
   自动触发链 → route/slide panic → reboot → ……（c9f7af69→da8e128c 连续
   三 boot 实测）。修 = `PostLock.readyToTrigger()`（共享 KASLR 文件
   boot_id 匹配才放行 BOOT_COMPLETED；LAUNCH 调试入口免 gate）+
   KS_SLIDE_SKIP，app commit `8509e56`。

### 里程碑状态

- M1 ✅（本节）、M2 ✅（8/8 found=1 已稳）
- **M3 进行中**（2026-10-20 第二轮取证，boot da8e128c）：faith gate +
  KS_SLIDE_SKIP 部署后重跑——**链推进史上最远**：
  `text-base-ok (shared file)` → slide skip ✓ → prepare → **CFI baseline
  `cfgfs read rd=8`**（route 时点 configfs 原语经 hijacked fops 正常工作，
  推翻「route 段 configfs 也死」的担忧）→ **`main cmp_requeue`** →
  **pipe convert wave[20]**（physrw window 波次推进）→ **panic**。
  死点修正：**不在 pselect cmp_requeue（round6 t22365 的日志停在那里只是
  未及 flush），而在 physrw window 阶段或其后**。
  工具确认：**`KS_PSELECT_SHIFT` env 已存在**（fops.c:185，range -32..64，
  runtime 覆盖 `PSELECT_WAITER_WORD_SHIFT`=0/target.h）——若定罪 pselect
  栈布局错位，shift 可直接 env 试值（注意错值=panic，不可自适应循环）。
  下一步：拉死前日志（chain.log panic 前最后行）+ pstore 归因。
  **设备离线中**（2026-10-20 深夜，双地址 100% 丢包 2h+，疑电量耗尽——
  链跑数小时 KEEP_SCREEN_ON + 多次 panic reboot）。恢复后行动序：
  1. `adb connect 192.168.8.10:5555`；
  2. 拉 `run-as com.postlock.boot cat files/postlock/chain.log`（panic 前
     最后行，文件跨 reboot 保留）+ `logcat -d -L`（last reboot logcat）；
  3. 重建 KASLR（shell `KS_KASLR_ONLY=1` 轮）→ LAUNCH 重跑 → 若再 panic
     则按 chain.log 死点归因（physrw window 的 dangling-PI walk 时序 vs
     pselect 栈布局——若定罪后者用 `KS_PSELECT_SHIFT` env 试值，错值
     =panic 不可自适应循环，每值需 fresh boot）；
  4. 注意充电状态——设备离线前可能正在关机。
- M4 待 M3。

### 部署注意

- `settings_enable_monitor_phantom_procs` 是 persist 的，但**恢复出厂/新
  设备**需要重新写（部署脚本步骤）。
- app APK 须 ≥ 含 gate+KS_SLIDE_SKIP 版本（8509e56），否则 reboot 后
  panic 循环风险回归。

---

## 附录：架构角色定义（2026-10-21 用户裁决）

**shell 域 = 老师，untrusted_app 域 = 学生。**

- shell 域的全部辅助（KS_KASLR_ONLY leak 轮、共享 KASLR 文件、代读写文件）
  **仅限开发/练习期**——那是老师帮学生备考，不是考试的一部分。
- **考场 = BOOT_COMPLETED 独立触发那一刻**：没有 shell、没有预跑文件、
  没有 host。app 必须自己完成包括 KASLR 在内的每一个环节。
- 共享 KASLR 文件（`kaslr_from_shared_file`）在考场上不存在——依赖它的
  路线**不是终态方案**，只是脚手架。

### 终态自足路线（app 域原语，零 shell 依赖）

运行时随机量只有两块砖，且互为先决（physmap 通道需要 slide 定位目标；
pvo oracle 需要 slide；slide 自举 `leak_kernel_base()` 又需要 physmap 通道）：

1. **打破鸡生蛋 = cfgfs confused read 暴力扫 physmap 候选**：
   arm64 5.4 `page_offset_base` 随机熵有限（数百~数千候选）。对每个候选
   pvo 计算 `P0_DATA_ALIAS_CONST(ASHMEM_FOPS)`，confused read open 槽，
   `is_kernel_ptr()` 校验读回值——命中即真实 fops 表。纯用户态 syscall，
   app 域实测可用（round11 fix52 dump 走的就是这条通道），seccomp/SELinux
   均不拦。
2. **slide 自举**：`leak_kernel_base()`（fops.c:1427）从 fops 表
   `open` 指针反推 `kaslr_base`——已有实现，physmap 通了即可用。
3. pvo 由 physmap 推导（`ks_layout_apply` 反向），kprobe/kallsyms 泄漏
   路线全部退役。

剩余考试内容：mm_struct 泄漏 app 域退化（第七轮）、tracefs 依赖点
（kprobe fetch 的 content verify，考虑 cfgfs read 替代）、prepare/wave
（M3，frozen 页已定罪）。
