# Git 历史全量（399 提交，2026-07-26 ~ 11-12）

> **两手准备之文件侧**：本文是全仓提交历史的完整快照（hash + 日期 + 主题），
> 记忆侧对应 `projects/CVE-2026-43499-root-KernelSU` 空间的 `git-history-1..7` 七段 + `git-history-index`。
> 生成命令：`git log --format='%h %ad %s' --date=short`（生成日期 2026-11-13，HEAD=a9df15f3）。
> 问题与解决细节不在本文，在记忆 `process-history-a/b/c/rules`（底账 AGENTS.md.bak-440k 提炼）。

## 按日提交统计

| 日期 | 提交数 | | 日期 | 提交数 |
|---|---|---|---|---|
| 2026-07-26 | 4 |
| 2026-10-19 | 12 |
| 2026-10-20 | 14 |
| 2026-10-21 | 31 |
| 2026-10-22 | 32 |
| 2026-10-23 | 21 |
| 2026-10-24 | 32 |
| 2026-10-25 | 42 |
| 2026-10-26 | 15 |
| 2026-10-27 | 23 |
| 2026-10-28 | 18 |
| 2026-10-29 | 13 |
| 2026-10-30 | 4 |
| 2026-10-31 | 10 |
| 2026-11-01 | 6 |
| 2026-11-02 | 5 |
| 2026-11-03 | 9 |
| 2026-11-05 | 6 |
| 2026-11-06 | 18 |
| 2026-11-07 | 22 |
| 2026-11-08 | 7 |
| 2026-11-09 | 13 |
| 2026-11-10 | 17 |
| 2026-11-11 | 13 |
| 2026-11-12 | 12 |

## 全量提交（新 → 旧）

```
a9df15f3 2026-11-12 tools/tsu: 修正 rows.sh 的 --trysu-status 解析（假 FAIL）
3e0747fd 2026-11-12 tools: 落点换成 tsu 后 accept.sh 的 ksud 候选加大小闸门
c6ab1c19 2026-11-12 tools(tsu): 补 argv[0]=su 前置验证取证
5c0cc441 2026-11-12 tools(tsu): 加落点/直调两层判据脚本与直调实测取证
233fd93c 2026-11-12 feat: tsu 执行体镜像 + stage push + restore 优先装 /data/adb/ksud
2e36e12e 2026-11-12 docs: 记录纯 Zig 管理器本轮两个已实测缺陷与证书链路闸门
80abac24 2026-11-12 embed: TrySU 加冕条目 + ksud 默认包名 io.trysu.manager
5afdebf7 2026-11-12 docs: 订正 N→VN 进入通道与公理九入口的混用
4baa42ef 2026-11-12 docs: trysu-manager 的资源处置改指新实现状态文档
9401aa75 2026-11-12 docs: 旧文档统一作废，实现状态另立新体系文档
fba976d6 2026-11-12 docs(readme): 指向独立仓 poisongod/TrySU + 修算术（十公理 -> 十二公理）
de77bc42 2026-11-12 docs(trysu): 用户重写十二公理 + 新增 TrySU 管理器设计
6bd93d72 2026-11-11 docs(vtzsu): V0a 原生轮全绿（boot 11e3bdc8）
48231fba 2026-11-11 suvtz: fix V0a sidecar write (TMP undefined in restore heredoc)
e5fd728c 2026-11-11 docs(trysu): 订正两处取证坐标与一处方向错误
23b36929 2026-11-11 docs: 以 TrySU.md 统一架构哲学，旧两世界文档全部废弃
57c0aabe 2026-11-11 forensics(vtz): 归档 V0a 正式轮首次尝试失败（boot dff8df35，payload 页死家族）
2b90fc31 2026-11-11 docs(vtzsu): 回填 V0a 冒烟实测（boot 59eeb053，§7 第 1-5 行）
bdd2bffc 2026-11-11 vtzsu V0a: /data/adb/ksud 改为「我们说了算」+ 同步含 dirfix 的 ksud
85158346 2026-11-11 suvtz-w: V0a 落地 —— ksud --vtz 进 W + restore 写进入权威 sidecar
bbe5a5a4 2026-11-11 docs: VtzSU 设计（NL-2）——把 SU 会话放进 W
dd3427d6 2026-11-11 docs: 新增 SUVTZ 标准定义 NL-1（四元组 + D1~D5 + 符合性判据）
1a2aac6f 2026-11-11 suvtz: Phase C 验收取证归档（fresh boot 59eeb053）+ 文档翻转
cd0da528 2026-11-11 suvtz: Phase C —— 删 N 副本，纯 restore 物料只存于 W
3fc36842 2026-11-11 suvtz: su-gate in-band 判据验收（fresh boot 8539f035）
64995cc2 2026-11-10 docs: 熄屏断网与 WifiLock 实测（boot c0a9c70b）
e40e956f 2026-11-10 suvtz: Phase B 验收归档 + su-gate in-band 判据
7d0d95c3 2026-11-10 postlock: reconnect the transport before the very first device check
6cb709d1 2026-11-10 fix(postlock): reconnect the adb transport in the restore wait loop
9889db9c 2026-11-10 fix(suvtz): make PB-SUGATE tell the two legitimate gate-absent causes apart
e0a3f055 2026-11-10 docs(suvtz): document Phase B in-band UNKNOWN and out-of-band cksum check
f2d3d09e 2026-11-10 docs(suvtz): bring the design doc's delivery status up to 2026-11-10
00999385 2026-11-10 docs(suvtz): point the Phase B criteria at tools/suvtz/check_phaseb.sh
f4a3647a 2026-11-10 tools(suvtz): add Phase B (W material migration) criteria checker
353fad04 2026-11-10 docs(suvtz): Phase B material migration is applied and installed, not dry-run only
0c0704ba 2026-11-10 suvtz: Phase B material migration into W + v34 exec-probe forensics
1cfced2e 2026-11-10 suvtz: acceptance checker gains W-EXEC row (16 -> 17 criteria)
2b77218e 2026-11-10 docs(suvtz): record Phase B migration patch state (dry-run only)
ec56758b 2026-11-10 docs(suvtz): record why the W exec prerequisite cannot be probed from outside
1e3e4ef1 2026-11-10 suvtz: probe whether restore can exec inside W (migration prerequisite)
957e3a28 2026-11-10 Retire the staged su binary: entry convergence follow-up
8c7a7dce 2026-11-10 suvtz v3: fresh boot 194c5414 验收通过 + 取证归档 + 判据核对器入库
a77f168e 2026-11-09 suvtz: holder 失败时保留 direct 尝试日志
43cc3814 2026-11-09 docs(suvtz): 补齐 by= 判据取值 + 去掉 design 里未实测的断言
549a5f76 2026-11-09 docs(suvtz): 订正 §2.2 未实测断言 -- by=kernel 尚未取得
c8198b13 2026-11-09 suvtz: holder 的 ns 从 procfs 读，消除 pgrep/print 竞态
899df5cf 2026-11-09 docs(suvtz): align world-isolation status with landed W namespace
463b1b07 2026-11-09 docs(suvtz): 按域墙实测订正 gap §2.1/§2.2/§2.3/§2.4/§6 与 design §4.2/§8
08cdacc6 2026-11-09 suvtz: 扫描器新增 W 类世界隔离探针 (W1-W5) + 文档口径对齐
f81c17d7 2026-11-09 suvtz docs: W 世界落地后的诚实口径（结构性隔离 1 项起步）
3150d75f 2026-11-09 suvtz: W 世界 holder 接入恢复流程（结构性隔离第 1 项）
1d9d158a 2026-11-09 suvtz: W 世界 ns helper wns（private/hold/run/stat）+ gap §2.3 实测改写
0fe797e7 2026-11-09 suvtz: 四维差距清单（世界标记/隔离/入口/监控）+ C7 实测修正
c59aa3c7 2026-11-09 suvtz: 入口收敛第 1 项 —— /product/bin overlay 退役
b1023cc0 2026-11-09 docs(suvtz): v3 定位口径全面改写 + P1-2/B4 归类与归因实测修正
cd4be11c 2026-11-08 AGENTS: ShellChain vc84 reboot end-to-end re-verify (app-side DONE, no false FAIL)
f20b8de5 2026-11-08 AGENTS: ShellChain end-to-end first pass + restore.log DAC defect + device self-unlock / HANS foreground
34acf3e8 2026-11-08 restore: honour SUVTZ_CHAIN_LOG_MODE for postlock_restore.log
f2fcc64f 2026-11-08 app 内驱动 shell 域全链：CHAIN_LOG_MODE 参数化 + restore 生成器 + 自启定案
f5c47d88 2026-11-08 docs: Tailscale 持久化 adb 通道架构与边界（L0-L4 分层 + 判据 + 失效清单）
0e4b5c09 2026-11-08 docs(agents): WAN 通道抗 wedge —— tshealth 三态判据 + watchdog 健康重启
991277fd 2026-11-08 docs(agents): SELinux verdict on app->shell abstract socket + WAN probe hardening
7ec9a45f 2026-11-07 docs(agents): Direct Boot 出货版端到端（boot ca0bb40d）+ install 不改 stopped 状态
4df58504 2026-11-07 docs(agents): 状态指示用胶囊不用 Switch（adbd 卡视觉歧义定案）
db31e2da 2026-11-07 docs(agents): Direct Boot 落地——锁屏不解锁也能起 tailnet + 纯 IPv6 hairpin 教训
bbe0a018 2026-11-07 docs(agents): Tailscale 持久通道实测闭环（自启/tailnet adb/HANS 免疫）+ 解锁前置与两个归因坑
a1deb73f 2026-11-07 docs/tools: 跟进 PostLock 单应用化（com.postlock）
2d672590 2026-11-07 fix(suvtz): 锁屏状态三态判定（缺字段时按可能锁屏处理）
541cd590 2026-11-07 fix(suvtz): 有未裁决 FAIL 的扫描也算成功（rc=1 不许丢台账）
0fb0d294 2026-11-07 fix(suvtz): 补扫单飞 + 补扫后仍 runas=no 时记提示
51740450 2026-11-07 fix(suvtz): 只在确实锁屏时挂补扫，补齐退出码 5 语义
119cbccb 2026-11-07 feat(suvtz): 锁屏时后台等解锁再补扫（wait_unlock_scan.sh）
0396a1d0 2026-11-07 docs(suvtz): §5.2 补零参数复现（boot a877caaf 解锁态 PASS=31 / 锁屏态 runas=no 如实记录）
8f3363e4 2026-11-07 fix(suvtz): 锁屏未解锁时写明原因（device_locked / RUNAS_WHY / runas=）
e13a1fca 2026-11-07 postlock: SERIAL 支持 + 按「能看到设备」选 adb
bb6a1ae7 2026-11-07 suvtz: 零参数可用（载体自动探测）+ P2 每 boot 扫描挂到恢复流程
418ee7b6 2026-11-07 docs(suvtz): §5.1.3 裁决落地记录 + §5.2 差分表更新 + AGENTS 批次记录
1a892fdf 2026-11-07 fix(suvtz): B10 收(SUVTZ_KASLR_MODE 默认 0600) + A1/A2/B4/D1 登记为已接受
4c3d4611 2026-11-07 docs(README): 补「观测面等价(SUVTZ)」入口 + tools 目录条目
b3e5f0ca 2026-11-07 fix(postlock): suvtz-b10 取证行的命令替换必须转义 + 加 heredoc 守卫脚本
385d8011 2026-11-07 docs(suvtz): B10 选项② 真机实测数据(0600 => FAIL=4 PASS=31, B10 转 PASS)
1c8c8f2a 2026-11-07 AGENTS: SUVTZ accepted.tsv 机制 + SUVTZ_KASLR_MODE + 三项待裁成本结论
a8bcd4c2 2026-11-07 suvtz: 已接受暴露面登记表(accepted.tsv) + B10 权限开关 + 三项待裁评估
ffe9cbab 2026-11-07 suvtz: 加 X 类成对交叉验证(5 对) + judge 命令能力不足识别 + P1 后真机差分复测
a5154dd7 2026-11-06 docs(suvtz): P1-1/P1-2 验收结果 + module_init 竞态与锁屏测量限制
14391245 2026-11-06 suvtz P1-2: wait for SUSFS to finish initialising before building the overlay
3e6c54fa 2026-11-06 docs(suvtz): 边界改为按域划分，拆分观测/影响，单点性归因枚举
1b27abed 2026-11-06 docs(suvtz): reconcile v3 design route with the P0 measurements
c018a1e7 2026-11-06 AGENTS: SUVTZ P1-2 mechanism (ksu-domain tagging + explicit hide switch)
92ad9a2a 2026-11-06 suvtz P1-2: build the /product/bin overlay in the ksu domain + enable SUS_MOUNT hiding
a3d01703 2026-11-06 docs(AGENTS): HMA-OSS 前端 app 一并卸载，模块残留复扫零命中
9aaca10d 2026-11-06 docs(AGENTS): 用户 5 个功能模块彻底卸载（含清理清单与遗留物）
d4c4e964 2026-11-06 docs(agents): /data/adb/modules 为空≠正常 + 模块备份禁删
7d7d85c4 2026-11-06 docs(agents): WSLInterop recovery command + postlock stage-push dedupe verified
15714b39 2026-11-06 perf(postlock): skip stage pushes whose sha1 already matches on device
b07bdf13 2026-11-06 docs(agents): SUSFS acceptance must reboot to clear marks + two operational traps
ef11b67b 2026-11-06 docs(forensics): SUSFS page screenshot + CLI evidence (boot 898d3136)
0f96ed87 2026-11-06 docs(susfs): record post-r4 clean reboot + cold boot revalidation
49ca420d 2026-11-06 docs(forensics): cold boot restore + suvtz rerun (boot 898d3136)
bd194f7b 2026-11-06 docs: SUSFS 九项验收 r4 全绿归档（37 PASS / 0 FAIL / 3 INFO）
1821f334 2026-11-06 docs: PostLock-Boot 冻结为 legacy，仅保留 SUSFS app 域自检载体
f2ec8897 2026-11-06 tools/susfs/adb1.sh: 修 Windows adb.exe get-state 带回车导致空转
36b4a206 2026-11-05 docs: SUSFS 验收方法与 r2 轮 5 项 FAIL 定因归档
08183c1d 2026-11-05 susfs: open_redirect 双拼写别名 + 验收脚本五处判据修正 + ko/ksud 重编
84c3a095 2026-11-05 su wrapper: 非 root 交给驱动 sucompat，并 provision /data/adb/ksud（v27）
0369282b 2026-11-05 evidence: 归档 v17(bc35c90a) su 回归现场日志
21cfbce4 2026-11-05 docs: /product/bin/su 回归分析闭环——v17 表 hook 单点无兜底
0589e06a 2026-11-05 ko: 三路冗余修复 su 驱动 fd 回归（kprobe 备份 + exec 钩子放宽）
ec7f6194 2026-11-03 SUVTZ P0 第二轮：30 探针基线（12 FAIL）+ P1-1 DAC 收敛
efe09095 2026-11-03 feat(suvtz): P0 观测面扫描器 + 首轮基线 (7 FAIL / 18 PASS)
a335287a 2026-11-03 docs(suvtz): v3 分层信任域设计 —— 从「内存隔离」重新定位为「观测边界」
114da569 2026-11-03 docs: 归档 SUVTZ v1 原始方案 + v2 重新设计
8ec30583 2026-11-03 chore(susfs): ko 更新 185e7dfb（SUS_MAP 持锁修复）+ PAYLOAD_VERSION v25
a1d47baa 2026-11-03 susfs accept: 目标/对照按设备实际内容选择（去掉会白丢一轮的硬编码）
c7957ee6 2026-11-03 tools/susfs: adb 探测先 connect + 验收脚本 pidof/NS/对照 inode 修正
2f7d34fc 2026-11-03 susfs: SUS_KSTAT 诚实上报（trial 试注册 + 降级）+ 九项验收脚本入库
9b2b3a99 2026-11-03 susfs: label KSTAT result line with the command actually issued
e989b5f2 2026-11-02 SUSFS: SUS_MAP 六挂点全实现（ko 6683047d）+ 文档同步
46ac0c81 2026-11-02 docs(agents): ko 产物 e1d6d977 三端同步 + fork main a71a957e + SUS_MOUNT 门控原子性
2500dbed 2026-11-02 build(susfs): embed kernelsu.ko e1d6d977（SUS_MOUNT 原子性收尾版）
8ee552a3 2026-11-02 docs(susfs): SUS_MOUNT 实现落地——九个 feature 位全部有真实现
2de83d20 2026-11-02 docs(susfs): SUS_MAP 落地记录 + 覆盖率矩阵/进度按下真实 ABI 与代码订正
1ba58412 2026-11-01 fix(bakasu): 恢复 selinux_hide 的 ksu_g_* 间接层 + 新增 ko UND 符号校验脚本
ee6cd6c4 2026-11-01 feat(ko): 驱动版本对齐管理器 v4.2.0-rc3/35252 + verify 加 driver 行
2313b252 2026-11-01 AGENTS: 补记 ksud susfs 需 root 上下文的验收判读陷阱
a9cd76ad 2026-11-01 AGENTS: 记录 SUSFS LKM 阶段 1 落地与验收、ksud 二进制一致性坑
ed1ffe78 2026-11-01 ksud: 更新为含 susfs CLI 的构建（025823e4）
f324b90c 2026-11-01 feat(susfs): 阶段 1 ABI 骨架落地 + 可行性文档按 GKI 基线订正
ce04958a 2026-10-31 docs(susfs): LKM 化可行性评估（符号验证 + 架构 + 分阶段计划）
d71a8310 2026-10-31 docs(agents): v16 验收通过 + Magica/usap 域权限判死
aad1c3be 2026-10-31 docs(agents): v16 验收前两轮 panic 定案（flush 槽 -5 = 页复用数据；fix70b 对本家族无效）
9a027b5c 2026-10-31 fix(ko): track_throne 判空 —— 堵住 insmod 路径上的 NULL 解引用 panic
794e69ec 2026-10-31 fix(postlock): manager appid 不再猜测 —— 解析不到就不写参数
0f323eba 2026-10-31 docs: 真协议修复耦合点逐项核查 + assets 同步纪律 + 演练开关教训
f80e44a8 2026-10-31 fix: SLIDE_ONLY 兼容 KS_ 前缀 + hotload 降为 legacy 可选 + 新设备移植文档
ff0d849d 2026-10-31 docs(AGENTS): record the ksu_late_loaded truthfulness fix
d32d0a2f 2026-10-31 kernelsu.ko: report real load timing, take the driver's late-load init path
9ec46ec5 2026-10-31 docs: 完整 BakaSU 功能矩阵核查（三层 21 路由 / 7 feature / susfs 可行性）
92b2a262 2026-10-30 AGENTS: BakaSU-PostLock 仓清理记录（删 9 上游分支+19 tag、postlock-app orphan 重建 30 文件、被删 refs bundle 持久化）
cf0f7a55 2026-10-30 AGENTS: 主仓权威远端终审 = poisongod/BakaSU-PostLock (push postlock HEAD:main, 245 commits ff 推成)
a866fcaf 2026-10-30 deploy prctl-hook kernelsu.ko 249b4a69 (arch.h PT_REGS_PARM4 shim fix) + exam4 3/3 record
ed4bed4a 2026-10-30 postlock: stage embedded ksud, restore sources it from $STAGE
e0a58d39 2026-10-29 AGENTS: r9 考试第2轮合格记账(2/3)+appid重装根因+prctl hook实施记录
fbe2942f 2026-10-29 docs: 考试轮（第三批）第 1 轮合格 r8 boot 45900136 → 计数 1/3
cba0a58e 2026-10-29 docs: v14 弹窗修复实战首验通过 + r5-r7 三连轮记录 + moduleLoaded 假阴性修复
65f79c66 2026-10-29 AGENTS: 设备工作目录集中化记录（/data/local/tmp 单一大本营）
adec22e6 2026-10-29 集中化: 设备工作目录 /data/local/temp → /data/local/tmp（单一目录）
f4ea6dbc 2026-10-29 AGENTS: 设备工作目录整洁纪律（每轮主动清理 + 保留清单 + SELinux 拒删处置）
f2b0ddfb 2026-10-29 AGENTS 弹窗节：v13 扫描 0 命中离线定案（bl 目标=do_group_exit 非 force_sig，历史锚点命名错误）+ v14 修复清单/验收判据 + 离线定锚方法（analyze_ocs/harvest_ocs 复用）+ 链轮记录 r5-r7 补全
c3b502ef 2026-10-29 kernelsu.ko: 方案乙（execve 前钩给 ksud 装非 CLOEXEC driver fd）重编——strings 验证 hand driver fd/libksud.so/vermagic 5.4.254/hotload api/版本串 8450dd28 全过
85b49512 2026-10-29 docs: 无按钮 15s 强制重启弹窗根因节（上报链/触发源三轮 pstore/kill 锚 FAIL/布防 SOP/应急坐标作废）
acf3ea3c 2026-10-29 diag(restore): dump oplus_root_check_succ/oplus_exec_block 全部 kallsyms 符号变体（kill 锚 +0xa30 brk #0x80 来源定位——死克隆/CFI 变体 vs 镜像原生）
2d51a147 2026-10-29 chore(restore): 日志串术语纠正 ocsk → oplus_check_suppress 全名（三模块标准名纪律）
8f2bfbcf 2026-10-29 fix(postlock): 触发前 force-stop 管理器（消 libksud.so execve 上报弹窗源）+ restore dump ocsk state 全文
37dc2a9c 2026-10-29 fix(restore): ocsk popup-suppress armed 确认 + arm 重试 + WARN（弹窗根因：rep 探针 best-effort，finitmod-ok ≠ armed=2）
d150108f 2026-10-28 docs: verify 考古修正——Err 定案 could not retrieve driver fd，吞 Err 假说推翻（三 ksud 对照 rc=1），附 ksud 本地重编完整命令与坑
4b2f21fe 2026-10-28 docs: verify 卡点考古结论——ksud debug su 静默失败根因链（吞 Err + Err 来源 + ksud 版本管理缺失教训）
aaf3f136 2026-10-28 postlock.sh: hotload/oplus finitmod 成功路径补日志 + verify 失败自动诊断 dump
bbb86e95 2026-10-28 AGENTS: hotload restore 待办①改已完成（64c9dac4 落地），hl_stage 路径注改名
64c9dac4 2026-10-28 postlock.sh 恢复链补 hotload 段（完成 AGENTS 任务①待办，与 app assets 对齐）
753250ac 2026-10-28 三模块标准名更正：恢复链 stage 改用 oplus_check_suppress.ko / kernelsu_hotload_init.ko
3bed5766 2026-10-28 build/bakasu-work: record gitlink removal (repo migrated to ~/Downloads/PostLock-Boot)
bfee0560 2026-10-28 repo layout: migrate 7 nested git repos to ~/Downloads top-level (BakaSU/PostLock-Boot/hotload/ocsk/ghostlock54/tailscale/android_kernel); AGENTS+RECOVERY_PLAN path rewrite; backup old kernel in-tree integration patch
71d8f478 2026-10-28 AGENTS: final 3-driver x 3-repo mapping (kernelsu.ko->poisongod/BakaSU, ocsk->opus-check-suppress, hotload-init->kernelsu-hotload-init; PostLock-Boot app->PostLock-Boot)
3f3a9436 2026-10-28 AGENTS: BakaSU-PostLock no longer a fork (user confirmed); poisongod/BakaSU is the only fork
11a9abb4 2026-10-28 AGENTS: fix hotload rename record (gh repo rename on GitHub side)
f87252ae 2026-10-28 AGENTS: Plan B execve-hook fd hand-off + ocsk独立仓 + hotload rename
90609128 2026-10-28 AGENTS: poisongod/kernelsu-init-hotload 记录（companion 架构 + BakaSU fork cafc9497 hotload api 导出 + 编译验证）
6b8be2d2 2026-10-28 AGENTS: poisongod/BakaSU fork 记录（kernelsu.ko 源码独立 a765a3e7，commit-tree 推送流程 + 版本纪律红线）
6831b542 2026-10-28 chore: 本地旧仓库清理 + work/ReSukiSU 从 Baka-SU/BakaSU 重建
8cd024c0 2026-10-28 docs(AGENTS): 修正 ReSukiSU 仓库来源记录——已转移为 Baka-SU/BakaSU（301 实测）
841880c1 2026-10-28 任务①完成: apply_kernelsu_rules() 在 ko 加载时跑通 + sep 沉淀补记
02347e53 2026-10-28 restore: inject enforce=1 data-path sepolicy rules (pm/RootService fix)
7d28f341 2026-10-27 🏁 归档 redo62 决胜轮合格，新考试轮连续三次合格 3/3 达成，考试完成
b56d4579 2026-10-27 归档 redo61 第2轮合格（双 OK 原生+蓝卡无红条）计数 2/3，下轮决胜
f72b75c1 2026-10-27 归档 redo60 第1轮合格（双 OK 原生+verify OK+蓝卡无红条）计数 1/3，澄清 redo58 日志读串疑点
4adea26e 2026-10-27 归档 redo59 决胜轮失败（payload 页死+fd-hold）计数归零 0/3
4b604e68 2026-10-27 归档 redo58 第2轮合格（双 OK 原生+蓝卡无红条）计数 2/3，下轮决胜
852d1631 2026-10-27 归档 redo57 第2轮 panic（fake 表 ioctl 槽污染第4次+验槽死锁定案）计数 1/3
89d6040d 2026-10-27 归档 redo56 第2轮失败（payload 页死+fd-hold 收容）计数 1/3
f9ad3c48 2026-10-27 归档 redo55 第1轮合格（uid0 monitor 抽签赢+双 OK 原生+蓝卡无红条）计数 1/3
666a9998 2026-10-27 归档 redo54 失败（root child SIGKILL 第6次+弹窗归因排除两假说+beat_uid 硬矛盾）计数 0/3
737a0ed3 2026-10-27 归档 redo53 决胜轮 panic（ks_owner CPU0 软锁死 round5 同款，kernel_panic,bug）计数归零 0/3
d7f5ba78 2026-10-27 AGENTS: redo52 合格归档 (boot 6da4649c) -> 计数 2/3, fix81 二连 + fix75 首考未触发
0f455de1 2026-10-27 AGENTS: redo51 合格归档 (boot 6ebbfcfb) -> 计数 1/3, fix81 首考通过
e90051fd 2026-10-27 fix75: pipe_prepare in-child watchdog -- sweep fake fds at page-death detection
e2552906 2026-10-27 AGENTS: 归档 redo50 panic (fix70 回滚真空, 孙进程 exit filp_close 踩脏槽, fix70b 修复方向)
b442f893 2026-10-27 AGENTS: 归档 redo49 (payload 页死 tbl=0 + fd-hold 收容 + 深休眠 12h, fix81 四连未检验; poll 脚本两条排障教训)
2f98de6b 2026-10-27 AGENTS: root child SIGKILL 家族归因定案 = 用户手动重启的 shutdown 进程清理, 链是受害者 (redo48 时序铁证 + 用户确认 redo29/44/48)
12f030c6 2026-10-27 AGENTS: 归档 redo48 (root child SIGKILL 第 5 次, fix81 三连未检验)
dc90fa92 2026-10-27 归档 redo48 失败: root child SIGKILL 家族第 5 次 (beat_age=12.8s uid=2000), kill switch 安全介入, init reboot 非链, fix81 三连未检验 -> 维持 0/3
ae83c201 2026-10-27 AGENTS: redo47 archive (payload dead + fd-hold, fix81 untested 2nd round)
a687916c 2026-10-27 AGENTS: redo46 archive (running-script edit incident + fake-table slot panic, fix81 untested)
930ebb13 2026-10-27 fix81b: if-form break in post-flip poll (set -e safety: && short-circuit returns 1)
8eba3ae1 2026-10-27 AGENTS: redo45 archive (4th native child death, manual experiment, fix81)
1077350e 2026-10-27 fix81: drop the runcon strict-child for good -- builtin-only post-flip markers
1c0e67ff 2026-10-26 归档 redo44 失败(维持0/3): root child SIGKILL 家族 fix75 数据首现(0.2s busy-poll 死), 弹窗归因=ocsk 未加载(链失败伴生)
06818459 2026-10-26 归档 redo43 失败归零(0/3): strict-child 三连死结构定性, fix80 落地记录
8eb9e59d 2026-10-26 fix80: strict-child 第三次原生死亡 (redo43, 64 segfault) -> 全面取证 + 零 fork 化 + env -i PROBE
68d4ac79 2026-10-26 fix79: strict-child 双缺陷修复 (redo42 定案)
da63476a 2026-10-26 归档 redo42 合格(计数2/3): fix78 read fallback bug 定案(read rc=1 覆盖真值) + child runcon 污染 101 segfault
9418c724 2026-10-26 archive redo41: root-write-stage kernel pollution, third-party Binder victim panic (g8/round4 family), fix78 untested
78a050ac 2026-10-26 archive redo40: payload-dead neutralize-fail fd-hold containment (redo37 twin), fix78 untested
0fc97af2 2026-10-26 fix78: strict-child harden — builtin read poll (zero forks in flip window), guarded log date, per-10-round builtin print diagnostics, sleep/|| true (redo39 original child burned 202x segfault)
bc14c2c8 2026-10-26 archive redo39: pass count 1/3 — strict flip achieved, original child 202x segfault, marker re-issued by manual child rerun (defect pending fix)
a616fc13 2026-10-26 archive redo38: payload-capture-weak cfi garbage fail (redo36 twin), fix77 still untested
16eee4de 2026-10-26 archive redo37: payload-dead fail-path self-detonation panic (round6/7 family), fix77 still untested
49234846 2026-10-26 archive redo36: chain CFI lottery failure, fix77 untested (root=0, safe exit)
945f9aea 2026-10-26 fix77: strict block delegates post-flip work to a shell:s0 child (redo35 root cause)
b6be5d3c 2026-10-26 build: bump bakasu-work gitlink 9630d5b -> 4bd156d (strict-mode restore 31ac4e6 + fix76)
c0b325fb 2026-10-26 fix76: strict-mode round redo34 root causes (host OK-line only, probe survives set -e, stderr logging, ksud from shell_data_file)
fc2bb347 2026-10-25 postlock: SELinux strict exam criterion — restore flips Enforcing with shell->su runcon probe + permissive fail-safe; tmpfs sb context= fixes upper labels; host verify dies on enforce!=1; sync app assets
6ef17cdd 2026-10-25 AGENTS: redo32 决胜轮失败归零 0/3——mm_struct leak 连败(baseline=6 vs 20) + 链无声死亡(route 前, 无 panic)
30728763 2026-10-25 AGENTS: redo31 合格(bdba7f7e2) 计数 2/3——蓝卡 Built-in 无红条, 决胜轮待考
a1f1b784 2026-10-25 AGENTS: redo30 合格(b8cbf97fa) 计数 1/3——fix75 版首考, 蓝卡 Built-in 35220/6==35252/6 无红条
aaf95bca 2026-10-25 fix75 root child 心跳哨兵(beat_ns/beat_uid)+setpgid; AGENTS: redo29 失败归零 0/3 (root child SIGKILL 第三次, 死亡窗口收窄至 fork→写完成, 排除 seccomp/内核路径/pgid)
8fc409b7 2026-10-25 AGENTS: redo28 合格(b1669f578) 计数 1/3——fix74 版一次过, 蓝卡 Built-in 35220/6==35252/6 无红条
d5680266 2026-10-25 AGENTS: redo27 route pselect panic 第3次同栈归档——L2 translation fault 定位、三轮 delta 恒定、dirty slot 排除、12轮gate风暴上下文差异
7cf73694 2026-10-25 fix74: pin 全 conn + win tick late pin + tee 判别观测（redo26 页死考古）
c25749b3 2026-10-25 redo25 失败维持 0/3：win+7s 页死（pin 3MB 后仍死）×10 重试败，neutralize 写不进 fd-hold 收容，判明即 reboot
d4141b7e 2026-10-25 redo24 失败归零维持 0/3：root child SIGKILL（redo7 同款 wst=9/未 proceeding），kill switch+neutralize 全干净无 panic
f281d799 2026-10-25 redo23 决胜轮 panic 归零 0/3：redo20 同栈复现（do_vfs_ioctl blr 0x693dd100），fix73 1s 轮询对 ks_waiter 毫秒级撞针结构性无效——修复方向改为撞针前物理通道验槽
93498507 2026-10-25 redo22 合格 2/3：gate 305s 放行链 50s 一次过，app 时序天然正确直接蓝卡
ca93c803 2026-10-25 redo21 合格 1/3：fix73 首考零输出蓝卡；红卡根因定案 = shell kill EPERM 致 app 老进程错过 setuid hook fd 装载窗口，root kill+冷启动即蓝（验收 SOP 补条）
12f3af41 2026-10-25 fix73: win tick 每秒校验 ioctl 槽（cfi verify 同址同值语义），被改写即重写+取证行——redo20 do_vfs_ioctl blr 0x742cdf60 时序覆写根因（模型 A 三轮判别实锤，监控盲区补全）；健康路径零写入
74ec722d 2026-10-25 docs: redo20 panic 归档——fake 表 ioctl 槽污染（do_vfs_ioctl blr x20=0x742cdf60，ASHMEM_SET_NAME），flush 污染家族第 3 次砸中 ioctl 槽，归零 0/3
eb71bdcf 2026-10-25 docs: redo19 合格（boot a8f169c3，99 秒全通，蓝卡 Built-in 无红条 35220/6==35252/6）→ 计数 2/3；疑点解析（pid 重现/temp mtime/driver-already-loaded 均正常）
0b121c88 2026-10-25 docs: redo18 合格（boot 37c5d8c9，蓝卡 Built-in 无红条，35220/6==35252/6）→ 计数 1/3；轮询判据教训 + 小pin假说不成立
35637954 2026-10-25 docs: redo17 归档——payload 页死抽签安全失败（root=0，fd-hold 残留）归零 0/3，fix72 仍未被检验
08f481c1 2026-10-25 tools: 修 restore heredoc 注释反引号——unquoted heredoc 把注释里的 `ls /product/bin/su`/`su -c` 当命令替换在 host 提前执行（1+3 行报错污染每轮日志；redo14 合格轮同款实证无功能损伤，仅注释内容被替换成空）
087b1706 2026-10-25 docs: redo16 归档——route pselect 抽签（marathon5b 同款）归零 0/3，fix72 未被检验（链死 route 段）
b88c3f75 2026-10-25 fix72: pipe_prepare 信号阻断（可捕获类致命信号→exit踩fake fd=redo15 panic 栈）+ win tick 周期 sanitize flush 槽（污染窗口<1s+污染值取证）；AGENTS 归档 redo15 归零 0/3
e9a4a6a5 2026-10-25 tools: postlock gate load<2.0 → <5.0——本机稳态底噪 4.5 永远等不到 2.0，每轮白等 20min 超时；用户裁决「不做没有价值的事情」，等长替换保字节不变
650537f8 2026-10-25 docs: redo14 合格 1/3——fix70 回滚对照定案（owned=0 三连 = fix70 回归），fix71 保留
336a4278 2026-10-25 docs: redo13 归档 + fix70 回滚决策依据（owned=0 三连确定性相关，归因已被推翻）
af1bb39f 2026-10-25 rollback fix70: 回滚 clone_child fd sweep——owned=0 三连（redo11/12/13）确定性相关于 fix70，且其归因已被 redo10 推翻；保留 fix71（真炸点修复，fail path 安全三连实证）
2e9f1bc7 2026-10-25 docs: redo12 安全失败归档——owned=0 inuse=31 同型二连（满页家族新形态），fail path 安全二连实证
fc76524b 2026-10-25 docs: redo11 安全失败归档——fix70+71 实证 panic 家族终结（neutralize/close/reap 全安全），owned=0 满页老抽签
7eaacb48 2026-10-25 fix71: close(conv_fd) 与 late sweep 前经 cfgfs 重写 flush/release=0——精确定位 redo8/9/10 炸点 pipe.c:849（页活 flush 污染 blr 垃圾）
617634f0 2026-10-25 fix70: clone_child/clone_leak_child 孙进程 fork 后立即清扫继承 fake-fops fd——修 redo8/9 filp_close blr 0 同栈 panic（exit_files 踩死页竞态）
25b7de5a 2026-10-25 docs: redo8 失败归因——fail path 并发 close 竞态 blr 0 panic（round6/7/8 同族第三栈）
21ea26e4 2026-10-25 docs: redo7 失败归零 0/3——root child SIGKILL 家族（kill switch 按设计安全排雷）
19735fc2 2026-10-25 docs: exam round pass (boot 491738f2, count 1/3) + UAPI 6 red-banner fix verified
9bc89222 2026-10-25 build: migrate opencode-work assets into repo work/ + rebuild kernelsu.ko with UAPI 6
6088d02c 2026-10-25 docs: fix69b 多轮 pin 补漏 + 新考试轮第 1 轮合格（boot 5ff0763d，计数 1/3）
83f7a162 2026-10-25 fix69b: loop the payload pin splice until the hit connection's queue is stably empty
5be5a946 2026-10-25 fix69: splice-pin the capture queue into hold pipes before route consumes it
e6a7c58f 2026-10-25 docs: 新考试轮第 2 轮失败判明（boot 50a2bd5e win 段页死 tbl=0 root=0）——计数归零 0/3
3e566a65 2026-10-25 docs: 新考试轮第 1 轮合格（boot 3046f63f root=1 蓝卡 Built-in）——计数 1/3
3f6aa429 2026-10-25 docs: δ 考古终局——TCP/task_frag 链 p=0 理论 vs p=1 观测、k=KASLR段索引、route 前探测数学死路定案
ca6b75ca 2026-10-25 docs: round2/round2b 两连败判明——fix68 探测结构性无效、δ 相位抽签 p=1 主相位、fd-hold SIGKILL panic
3d98ea4f 2026-10-25 forensics: exam round2 panic (24e39de8) + round2b fail + fd-hold teardown panic (5e6abbe2)
73f034b3 2026-10-25 fix68: payload page view detect -> dynamic fops_voff
554cc7cd 2026-10-24 docs: AGENTS fix64-67 root-cause chain closure + first full-chain pass
63f86571 2026-10-24 fix67: fake fops close-path slots were payload-page residue -- zero them at build time
e3143a60 2026-10-24 fix66: nfds=576 moved the fdset off the kernel stack -- restore 320/shift0/simple (behavior-proven)
44cbcbcc 2026-10-24 fix65: pselect waiter shift=0 + force shifted layout (delta=2 qwords, deterministic)
02f39f96 2026-10-24 fix64: re-derive pselect/futex stack layout from THIS kernel -- shift 0 -> 13, nfds 320 -> 576
7b76fe40 2026-10-24 fix63: pin the payload page for the chain's whole lifetime -- stop closing skb_sv
01a70c1e 2026-10-24 fix62: fail-path containment -- neutralize retry + fd-hold daemon + guard blind real-table restore
01f0efbe 2026-10-24 AGENTS: unified-log verdict (SELinux kills physical single file, read-side unification vc69) + round7 self-detonation recap (route ENOTTY x4, neutralize-fail now deterministic)
147dca46 2026-10-24 AGENTS: round6 kernel-log verdict -- chain detonates its own leftover fake fops via __fput/module_put (neutralize failure = near-certain self-panic, fixable in fail path)
c18b9f3f 2026-10-24 postlock: quiet-gate used 'log' which only exists inside the restore heredoc -- add host-side info()
a98a3e5a 2026-10-24 postlock: gate the trigger on 1-min load < 2.0 (the AM-pass/PM-5-fail split)
6536244f 2026-10-24 AGENTS: round5 hard-lock autopsy (ks_owner CPU0 spin in physrw/wave, no panic, adb reboot ineffective -- power key only)
e4310934 2026-10-24 AGENTS: dangling-fops residual detonates >=38min later (pstore-proven) -- reboot immediately after a failed round
bb5b36d2 2026-10-24 AGENTS: dangling-fops residual detonates >=38min later (pstore-proven) -- reboot immediately after a failed round
6a2a46fd 2026-10-24 postlock/restore: fix three round-defects from the 09b0bf48 round\n\n- pre-trigger rm of /data/local/tmp/postlock_restore.log: stale file\n  survives reboots and false-positived the wait loop on the PREVIOUS\n  boot's RESTORE-OK (chain panicked, restore never ran, verify passed\n  against a day-old log).\n- restore exit-wait: PPID==1 (chain already exited, reparented to\n  init) burned the full 120s -- skip straight through.\n- overlay mount gets '|| log WARN-overlay-mount' (was silent on\n  failure: verify went red with zero forensics) + else-branch marker\n  when the wrapper is already present.
cf9121c2 2026-10-24 AGENTS: events experiment verdict (harmful, gated forever) + double-bracket & panel-order fixes
8657c532 2026-10-24 log prefix: drop the extra brackets (ks_log_prefix already returns '[b.. t..]')
a027283a 2026-10-24 AGENTS: unified log format + white panel rendering (vc66/837aad48)
837aad48 2026-10-24 unified log format: [b<boot8> <HH:MM:SS>] line prefix everywhere
d1c23901 2026-10-24 AGENTS: fix56-61 batch, 5-straight-fail root cause, shell-domain root limits, BakaSU doc notes, prior debt roundup
c7d44ec6 2026-10-24 fix61c: guard gate pass-through against set -euo pipefail
c7d88503 2026-10-24 fix61b: pass KS_RUN_KSUD_EVENTS / KS_BOUNCE_ZYGOTE through to trigger env
c7e97c0f 2026-10-24 fix61: run ksud events BEFORE overlay build in restore
fc9158f9 2026-10-24 fix60: su wrapper -c via pipe-fed ksud shell (ksud has no -c flag)
11e801c8 2026-10-24 fix59: gate ksud events behind KS_RUN_KSUD_EVENTS (default off)
41a43344 2026-10-24 fix57/58: su wrapper fallback via ksud; zygote bounce off by default
f73c3b13 2026-10-24 fix56: retry cfgfs read on rd==0 (transient configfs item state)
98fc605b 2026-10-24 fix(restore): 回滚 OMK injector 配置于 ksud services 之前 — uid:1000 scoop 变体两次 kernel_panic
678fc16b 2026-10-24 refactor(postlock): 退役自研 su daemon 与 coldstart.sh — 真驱动模式下均为历史遗留
6876f6da 2026-10-24 docs(AGENTS): 模块「无法正常工作」根因+late-load模块阶段固化记档
cf99540a 2026-10-24 fix(postlock): restore 补 late-load 模块阶段 — ksud 三事件 + zygote bounce
4afb3851 2026-10-24 docs(AGENTS): 冷boot红卡「版本不匹配」定性与恢复SOP + postlock.sh shell域panic疑案备案
34f52ddb 2026-10-23 AGENTS: route pselect panic signature + archive overwrite incident + panic-guard fail-open root cause
0c688bf0 2026-10-23 exam2_marathon: per-run archive dir + result=panic stamp
1ebb06e5 2026-10-23 fix self-flip panic: disable self-patch write sequence (kill switch)
7d564b0d 2026-10-23 fix root stage re-entry panic: root_stage_dirty fail-fast
3a5d1654 2026-10-23 AGENTS: gate 不消费致同 boot 二次链卡死事故分析 + ran_boot 修复 + 取证教训（NUL段/chain.log截断/开关静默）
8d6f29bc 2026-10-23 tools: exam2_marathon.sh -- untrusted_app 域连续考试循环，panic(链中 boot_id 变化)即停并归档取证
7bc5278e 2026-10-23 AGENTS: exam-2 round 3 PASSED (boot 962fdea8) — 3/3 DONE, both exams complete
ff673cf0 2026-10-23 AGENTS: exam-2 round 2 PASSED (boot fe30e85d, 2/3)
207fa686 2026-10-23 AGENTS: exam-2 round 1 PASSED (boot 2be7494f, 1/3) — paste + live-preference + wave-diagnostics SOP
a245d677 2026-10-23 pipe wave: instrument release_child_handoff take result (rel=ok/total in batch kill line)
cfc3de1a 2026-10-23 reload_payload_base: live globals win before the pvo window check
d2fa8611 2026-10-23 chain: payload-page handoff (KS_PREPARE_HALT persists, KS_PAYLOAD_PASTE consumes)
86b1decf 2026-10-23 AGENTS: restore 考试制度 heading clobbered by previous edit
5891c59e 2026-10-23 AGENTS: WAN channel final root cause (SOCK double-suffix) + hairpin + acceptance
aff8332d 2026-10-23 tools: reboot_and_chain.sh (reboot -> autostart window -> postlock.sh)
b3f13eb3 2026-10-23 tools: WAN 通道恢复后执行预案（2026-10-23 链 panic 失联事故）
c3c7441c 2026-10-23 postlock.sh: file-based detached trigger (run_fops.sh pattern)
03b84eae 2026-10-23 AGENTS: app 内 adb AUTH 三层根因(签名/坏行/loopback)+v1.41.5+链panic事故定案
66bcd320 2026-10-23 postlock.sh: fix keygen call (ab is a function, not a var; set -u would abort)
2aa7bd07 2026-10-23 postlock.sh: canonical adb key + legacy-line repair + detached trigger
a6237ace 2026-10-23 AGENTS: tailscale 常驻(shell uid)+termux adb/pairing 实测+app NO_AUTH 定因
1c88fa7e 2026-10-22 AGENTS: 冻结期 keepalive 机制定案 -- alarm fire 挂起/解冻 flush 延迟自愈 + daemon 解冻秒级恢复 + v1.39 setAlarmClock
8b57c8d1 2026-10-22 AGENTS: HANS cgroup 冻结 = 后台静默总根因（__refrigerator wchan 判据 + 前台解冻实证 + 10s 白名单窗口）
8d28487e 2026-10-22 AGENTS: tailscaled 开机自启通道攻克达成（v1.37 三层自愈 + boot 6e5c0807 零干预终验 + Athena phantom 死因链）
72b36f63 2026-10-22 AGENTS: tailscale autostart truth (v1.34 lacked 9914de8; all fast tailnet recoveries were manual app opens; v1.35 closes the loop)
0a6feef9 2026-10-22 pipe: win-dead probes (MSG_PEEK reclaim queue + fresh ashmem open) for app-domain page-death writer ID
52a62a31 2026-10-22 AGENTS: force-stop device-self-lock lesson (stopped -> no BOOT_COMPLETED -> no tailscaled -> adb unreachable) + exam-2 BOOT_COMPLETED SOP
6329d521 2026-10-22 AGENTS: exam-2 round1-2 forensics (stopped+HANS dual cause, app-domain chain depth under ca1b89bc, win+5s page-death = lottery, attribution lessons)
da1a640d 2026-10-22 AGENTS: 番茄拉回铁律取消(用户裁决)
bc4cd9d7 2026-10-22 AGENTS: 考试一连续三次合格完成(3/3)——三轮 fresh boot 一次过, 转考试二
65075225 2026-10-22 AGENTS: 考试一第2轮合格(boot 446cfc13), 连续计数2/3
20d2e9fa 2026-10-22 AGENTS: 考试规则——连续三次合格才完成(失败归零), 考试一计数1/3
0829ffa6 2026-10-22 AGENTS: 考试一合格(2026-10-22)——ca1b89bc 根因修复实测 owned=1 root=1 + BakaSu 蓝卡 Built-in
ebdb9ddc 2026-10-22 AGENTS: 泄漏回归点定案=ffec4212(handoff引入), chain5反例消解(so构建早于handoff)
6e78e5fc 2026-10-22 AGENTS: 满页终极根因(proc_mem_open mmgrab 泄漏)+release_child_handoff 修复
4a700189 2026-10-22 根因修复: wave 子进程 /proc/pid/mem fd 卡 socket queue 致 mmgrab 永久泄漏
a40eeccd 2026-10-22 AGENTS: convert 路线终审判决(泄漏线四刻度+结构性死锁, mm 页回收证伪)
677a1ec4 2026-10-22 pipe.c: 68 波改两阶段 SIGKILL(live 压 ~50ms, 泄漏线第四个刻度)
f21ca75a 2026-10-22 pipe.c: wave 粒度 34->68(两页), 挤压 deactivate 治 cpu slab 卡位
1b3baf45 2026-10-22 pipe.c: wave 粒度 110->34(恰好一页), 治 mm 永久泄漏的 live-time 根因
fe0bb4ab 2026-10-22 pipe.c: kill 后 inuse 时间序列轮询(10s, 定案延迟free vs 永久泄漏)
2dae070a 2026-10-22 AGENTS: 满页根因判决链闭合(wavepostfork 铁案 + 串行/并发 kill 分水岭)
547ef428 2026-10-22 pipe.c: wave kill 改回串行 kill_child(chain5 完整模式, 满页根治尝试)
9216a74b 2026-10-22 pipe.c: wavepostfork 读数(fork后kill前, 满页终审最后一环)
cc6a6b4b 2026-10-22 pipe.c: 回滚 objprobe(第25次重启嫌疑) + CONVERT_HOLD_WAVES 6->1(per-wave kill)
ca55a742 2026-10-22 Revert "pipe.c: 批 kill 后 objprobe 读对象头 word0(mm_users/mm_count, 满页终审)"
b2011662 2026-10-22 pipe.c: 批 kill 后 objprobe 读对象头 word0(mm_users/mm_count, 满页终审)
fd834b6a 2026-10-22 AGENTS: 第17-20次重启归因 + 满页三段式定案数据链
4f0c7ac5 2026-10-22 pipe.c: wavehead 扩为 slab 五 word 全 dump(+08..+28, 满页定案)
f951ad3a 2026-10-22 pipe.c: 每波 inuse 轨迹 + 批 kill waitpid 计数(满页定案诊断)
c5ac7e02 2026-10-22 AGENTS: cfgfs 对齐校验回归教训(+1 shift 设计, 四轮连败)
29771bdc 2026-10-22 util.c: 回滚 cfgfs 对齐校验(+1 shift 设计冲突, 两轮连败回归)
1f3c9d35 2026-10-22 tools/guard.sh: asleep 门槛 <2.0 -> <7.0(区分恢复风暴与用户 app 稳态 IO)
39ea01d0 2026-10-21 util.c: gate 拒 k_true<0 + cfgfs_read_ex 入口对齐校验(双层防 panic)
72338031 2026-10-21 AGENTS: 12-15次重启归因(恢复期起链连爆+RCU armed暴露)与守护 load<2 门槛
db0c1fc1 2026-10-21 pipe.c: RCU 等待 2s->0.3s(判决已得手, 长等待只喂 PI-chain)
d89dcf77 2026-10-21 tools/guard.sh: asleep 分支加 load<2.0 门槛 + REBOOT 后 90s 冷却
92c5facb 2026-10-21 pipe.c: 满页三处诊断加 head+freelist 交叉判据
bbfc46cc 2026-10-21 tools/guard.sh: 亮屏但1min load<0.5 视为等效闲置起链
2bbc2c45 2026-10-21 tools/guard.sh: 亮屏 idle 不消耗配额, 起链轮才计数(20轮配额曾被10分钟亮屏耗尽)
438ee5bb 2026-10-21 AGENTS: push 403 定性(poisongod 无 woshimaniubi8 仓库写权限)
01801d67 2026-10-21 AGENTS.md: 归档满页根因判决/owner诊断panic教训/11次重启死点/息屏守护
a4834e73 2026-10-21 tools/guard.sh: 息屏守护模式跑链
0088bd1b 2026-10-21 pipe.c: 批 kill 后轮询等 teardown 窗 + 撤 owner 诊断
70bb81bc 2026-10-21 util.c: prep/spray fork 循环加节流削峰，治 fork 起飞瞬间暴毙
72d1d22e 2026-10-21 pipe.c: owner 诊断加 physmap 范围校验，修野指针读致 panic
2eb992b3 2026-10-21 pipe.c: wave stuck 加 owner 归属诊断(采样3槽 mm->owner->comm)
174b1cfb 2026-10-21 pipe.c: sc2 非0->0 转换也记 taken_wave，治 wave[5] 后 16 波白盖页
bef0f86d 2026-10-21 pipe.c: wave 批次 kill 改两阶段(SIGKILL 全发再 waitpid)，缩 buddy 窗口
c0a77be0 2026-10-21 pipe.c: wave 批次 hold-kill，治 frozen 空页深处 partial 死锁
4091dcc9 2026-10-21 pipe.c: wave 前满页预检 fast-fail + owned=0 归因收敛到 leaked 页混居抽签
c5aff67d 2026-10-21 pipe.c: pre+leak 序列前 slab-groom，治 owned=0 满页根因
eb44b154 2026-10-21 pipe.c: wave 轮转防 EINVAL 崩溃(mask 扩到 cpuset 全集 + 非 fatal pin)
265f3f32 2026-10-21 pipe.c: wave sweep 轮转 CPU 修复 owned=0 确定性失败
eaaa871c 2026-10-21 AGENTS: postlock.sh同步触发panic隐患+detached修复 + M3 collision spun-out 失败模式
97c2f1ef 2026-10-21 AGENTS: 考试一 root=1 达成 + 裸驱动红卡归因(appid未配) + kprobe verify回锁恒失效
40e2b81f 2026-10-21 AGENTS: exam regime + v1.32 compliance + 考试一 configfs-fail 定性
95fffc86 2026-10-21 docs: exam regime -- curator(出题人)/teacher/shell exam #1 + student/app exam #2, leak legal, impersonation red line
a870f648 2026-10-21 AGENTS: dispatch loopback unification + home panel reality fixes (v1.28-v1.31)
da70f413 2026-10-21 AGENTS: PostLock panic guard (v1.25-v1.27) + app-uid boot-reason 判据实测
19eb456d 2026-10-21 AGENTS: device Tailscale MagicDNS name now resolves
6bec9e77 2026-10-21 docs: shell=teacher scaffold, app must self-host KASLR for the real exam
dce3ecc3 2026-10-21 pipe: fail fast on wave stall (round11 hang fix)
80a92409 2026-10-21 diagnose+cap: wave-stuck slab meta readout (inuse/objects/frozen) + KS_PIPE_MAX_ATTEMPTS env cap on pipe retry loop (app-domain structural gate miss fails fast instead of burning 8+ rounds to a silent death)
f493a4ec 2026-10-20 postlock.sh: provision phantom-killer off (settings global, persist) in restore.sh; docs: device-offline recovery playbook
21e7544f 2026-10-20 docs: M3 round-2 forensics -- route panic death point moved to physrw window (pipe convert wave), cfgfs rd=8 works post-hijack, KS_PSELECT_SHIFT env confirmed
d4968249 2026-10-20 docs: M1 completion report (configfs timing-deadlock, phantom killer, memfd handoff, faith gate, slide skip, BOOT gate)
3911eaec 2026-10-20 slide.c: KS_SLIDE_SKIP -- refuse the pselect slide probe on demand
252b4672 2026-10-20 util.c: gate faith branch for app-domain (M1 conclusion)\n\nM1 forensics complete (rounds 1-5, boot c9f7af69): the configfs read\nprimitive is inert BEFORE the route -- its pread only walks\nconfigfs_read_file once misc.fops is hijacked; a pre-route fresh ashmem\nfd's ->read is the real ashmem_read which returns 0 on an unmapped area\n(observed: r1=0 r2=0, page/pos arithmetic was always correct).\nSo in the app domain every gate oracle is structurally dead:\ntracefs denied, configfs inert pre-route, HW watchpoints EINVAL, tp\ncapture windows dead (seccomp perf_event_open denial -> tpw2.n==0 ->\nhit_evidence stuck 0 -> infinite prepare-retry storm, the round5 pid\nladder).  Add a faith branch: when tracefs is absent AND tp windows are\nempty AND base+drain evidence exists, pass fail-amplified (route panic\nis absorbed by the reboot loop -- same contract as shell-domain\nrun24/25).  Shell domain untouched: Tier-0 kprobe gives fv>=0.
bdad4fa7 2026-10-20 git: untrack build/bakasu-work (embedded app repo, accidental gitlink)
ffec4212 2026-10-20 util.c: /proc/self/mem fd handoff -- app-domain open_memfd fix (M1 root cause)
32ff8088 2026-10-20 design: untrusted_app 域链路设计 docs/app-domain-chain.md + AGENTS 归因修正
1d527989 2026-10-20 doc: AGENTS.md 留档第九轮 -- PostLock-Boot 独立仓 / Tailscale+adb 异地通道 / AUTH 卡点 / Android 编译坑
c88cd1a7 2026-10-20 docs(agents): adb-loopback bootstrap verified end-to-end (protobuf persist prop, boot listener, single-key AUTH to shell session); provisioning baked into postlock.sh
ce2b9dc9 2026-10-20 feat(postlock): self-regenerating adb-loopback material (protobuf entry + stable adb keypair) under build/work
3a7e57c4 2026-10-20 feat(postlock): persist adb-loopback bootstrap (persist.adb.tcp.port protobuf entry + postlock adb pubkey) into restore script
c164aacf 2026-10-20 docs(agents): app-domain chain final verdict — keep-alive solved, chain body structurally blocked (tracefs/mm_struct-leak/configfs); shell uid required; adb-loopback bootstrap direction
fc5f4a61 2026-10-20 docs(agents): HANS keep-alive triad (startActivity/wakelock/FSI) all fail; only foreground MainActivity works
f54e5fe4 2026-10-19 docs(agents): untrusted_app shared-file slide + OPPO HANS LcdOff freeze root cause
ef007e7a 2026-10-19 docs(agents): postlock app self-start route + untrusted_app slide-pselect panic analysis
8c3ae0d8 2026-10-19 fix: .gitignore images pattern 修正（上一条整行带注释文字导致未生效）
be234a76 2026-10-19 chore: .gitignore 排除 images 原厂固件物料符号链接
aa66e242 2026-10-19 doc: AGENTS.md 弹窗治理段落更新为 v12 已治理（含静态反汇编方法链）
e1c69319 2026-10-19 tools/ocsk: v12 弹窗治理——拦 oplus_exec_block 两处 bl kevent 调用点
b81b174d 2026-10-19 doc: AGENTS.md 留档真实标准模式达成 + ocsk v9-v11.2 归因链与弹窗待办
9c0a5b8d 2026-10-19 tools/ocsk: v11.2 探针 return 1 语义定案——ksud 提权 uid=0，BakaSu 蓝卡达成
7a6bc5be 2026-10-19 doc: AGENTS.md 底账（四五轮收官、ROOT_SCRIPT 载体定案、ocsk 归因）+ Gola.md 目标摘要
27828b31 2026-10-19 build: 嵌入 kernelsu.ko/finitmod + pfum10c48 target 与检测 profile
b33d8688 2026-10-19 tools: postlock/coldstart 恢复体系 + ocsk 探针 + 部署脚本集
a548ec82 2026-10-19 src: 四五轮链修复与 KS_COLDSTART 载体（run24-26、fix46 pin、setprop hook）
f2c26147 2026-07-26 tools: add resilient target generator fallback
8681c010 2026-07-26 doc: Update README.md
14d25b63 2026-07-26 init
8a258e97 2026-07-26 Initial commit
```

## 快照后续（a9df15f3 之后的提交）

> 快照本质是时点截取；此后新增提交追加于此，完整流水以 `git log` 为准。

```
8012334f 2026-11-13 docs: git 历史全量快照(399 提交) — 两手准备之文件侧
b29a9701 2026-11-13 chore: 移除 440KB AGENTS.md 注入源并隔离底账 — 根治配额事故
```
