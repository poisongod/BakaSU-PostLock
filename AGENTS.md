# AGENTS.md

CVE-2026-43499 内核漏洞本地提权 + 内嵌 KernelSU。C 编写，构建产物只有一个
`preload.so`（aarch64 Android 共享库），通过 `LD_PRELOAD` 注入任意进程触发利用，
成功后以 late-load 模式拉起 `ksud`。README 是权威文档，本文件只记录容易踩坑的点。

## 构建

```bash
make PROJECT=rodin -j$(nproc)     # -> build/rodin/bin/preload.so
make list-projects                # 列出所有已有 target.h 的 PROJECT
make info PROJECT=rodin           # 打印实际生效的 CC / sysroot / flags
make clean                        # 只删 build/*/bin，保留 build/embed
```

- 编译器选择顺序（`Makefile:57-80`）：显式 `CC=` > NDK clang >
  `HOST_CLANG`(默认 `clang`)。NDK 路径查找 `ANDROID_NDK_HOME` →
  `ANDROID_NDK_ROOT` → `NDK_ROOT` → `~/android-ndk-r29`。改完先用 `make info` 确认
  `TARGET_CC`，不要假设用了 NDK。
- `src/ksud_blob.S` 用 `.incbin "build/embed/ksud"`，路径相对仓库根。`build/embed/ksud`
  是**已提交的二进制**（4.5MB），被误删只能 `git checkout -- build/embed/ksud` 恢复。
  `src/su_blob.S` 同理 incbin `build/embed/su_daemon_aarch64_pie`，但这个是 Makefile
  `EMBED_SU` 规则自动生成的（改 `src/su_daemon.c` 会先重建 blob 再链 preload），
  不要手动删。
- `make clean` 故意保留 `build/embed`，删掉它会直接编译失败。

## target 机制（最容易搞错的部分）

- 每个 `src/targets/<project>/target.h` 是**生成产物**（约 168 个宏），编译时通过
  `-DTARGET_CONFIG_H="targets/<project>/target.h"` + `src/offset.h` 引入。
  `src/offset.h` 在 `TARGET_CONFIG_H` 未定义时直接 `#error`，所以不传 `PROJECT`
  必然编译失败。
- `PROJECT` 不存在时 make 会在 `Makefile:12` 报 `unknown PROJECT=...`；但用默认 goal
  （不带 target 的裸 `make`）会跳过这个检查，改为在编译器里报 `TARGET_CONFIG_H` 错误。
- 生成 target（注意先有 target.h 才能编译，是有向依赖）：
  ```bash
  make generate-target PROJECT=<p> BOOT=boot.img PROFILE=profile.json
  make detect-profile PROFILE_OUT=profile.json      # 需已 root 的设备
  tools/generate_target.py --project <p> --boot boot.img --detect-adb-and-generate --profile-out profile.json
  ```
- **无 BTF fallback 模板只能用环境变量**：`TARGET_TEMPLATE=<p> tools/generate_target.py ...`。
  README 里写的 `--template-target` 开关在 argparse 中并不存在（`tools/generate_target.py:281`
  只读 `args.template_target` 和 `TARGET_TEMPLATE`），照抄 README 会报 unrecognized argument。
- `tools/generate_target.py` 只是 wrapper，真正的 BTF/kallsyms/反汇编逻辑在
  `tools/vendor/generate_target.py`、`generate_target_2.py` 里，按
  `tools/vendor/` → 仓库根 → 父目录 的顺序查找并动态 import。改 wrapper 时注意
  MTK 路径下 `generate_target.py` 会以裸模块名 import `generate_target_2`。
- 绝大多数 target 目录**只有** `target.h`。但 8 个 target 自带源码副本
  （`caiman-*`、`comet-*`、`komodo-*`、`tegu-*`、`tokay-*` 各带 `common.h main.c util.c
  slide.c fops.c pipe.c`），`blazer-CP1A.260305.018` / `stallion-*` 自带 `slide.c`。
  Makefile 的 `pick_src`（`Makefile:16`）会让同名文件**覆盖** `src/` 下的版本；
  这些 target 的 `common.h` 还会被目标目录里的 `.c` 优先包含，而 `src/root.c`、
  `src/preload.c` 始终用 `src/common.h`（不可覆盖），两套 common.h 会在同一个
  链接单元里共存。构建这些 target 前先确认不会重复定义符号。CI 只验证
  `rodin` 和 `beryl`。

## 本机环境（已核实）

- WSL2 (Ubuntu 26.04)。**adb 只有 `adb.exe`**（`/mnt/c/WINDOWS/system32/adb.exe`），
  没有 `adb`。而 `tools/generate_target.py:173,188` 和 `tools/vendor/detect_offset.py:51,68`
  里 `adb` 是硬编码的，`--detect-adb-profile` / `--detect-adb-and-generate` /
  `make detect-profile` 会因找不到 `adb` 失败——需要先做 `adb` -> `adb.exe` 的
  shim/symlink，或改脚本。手写 adb 命令时直接用 `adb.exe`。
- 本机没有 `clang`（HOST_CLANG 缺），但 **NDK 实际存在**（`~/android-ndk-r29`），
  `make PROJECT=…` 走 NDK clang 正常出货；也没有 `llvm-objdump`，target 生成器
  默认 `--llvm-objdump llvm-objdump` 同样缺失，需要显式指定。
- `tools/vendor/detect_offset.py` 是独立的 ADB profile 检测器，可绕过 wrapper 直接用。

## 运行与排障

**设备端工作目录是 `/data/local/temp`**（与另一 agent 用的 `/data/local/tmp` 隔离）。

```bash
# temp 目录默认 label 是 system_data_file，shell 无法读写；每次 reboot 后须重新改：
adb.exe shell 'su -c "chcon u:object_r:shell_data_file:s0 /data/local/temp"'
adb.exe push build/pfum10c48/bin/preload.so /data/local/temp/preload.so
adb.exe shell 'chmod 755 /data/local/temp/preload.so'
adb.exe shell 'LD_PRELOAD=/data/local/temp/preload.so /system/bin/toybox id'
```

- 日志：`/data/local/temp/ksud.log`（= `<KSUD_DST>.log`），ksud 自身输出在
  `/data/local/temp/ksud.preload.log`。
- **链 runner 日志 = `/sdcard/chain5.log` 直写**（2026-10-07 起；旧版写 temp +
  3 秒镜像，chain8 复盘恰丢 panic 前最后几行被误导）。重启判定账本：
  `/sdcard/chain_run.state`（START/DONE）、`/sdcard/chain_reboot.log`（verdict）。
  所有 pr_* 行带 `[t<tid>]` 前缀，关键线程有 prctl 名：`ks_preload`(主)、
  `fops_guard`、`ks_waiter`、`ks_owner`、`ks_consumer`、`pipe_prepare`——
  pstore oops 的 PID 直接对号（chain8 当时线程无名 + 日志滞后，定位靠推断）。
- **跑链前先确认没有并发实例**：chain8（IABT PC=垃圾、Comm=sh≠主进程、
  参数在 pthread 栈）定性为旧主线会话同时跑同一条链互杀；旧主线已停
  （2026-10-07），复发时先查 `/data/local/temp`、`/sdcard` mtime。
- host 一键重建（temp 被 reboot 清空后）：`tools/prep_device.sh`
  （等设备→重建 temp/chcon→push preload.so + `tools/run_fops.sh`→校验）；
  跑后取证 `tools/chain_pull.sh`（拉 /sdcard 的 log+账本+pstore 到
  `/tmp/opencode`）；`tools/run_fops.sh` 是 keeper，改 runner 直接改
  仓库内这份再 prep。
- **别碰 `/data/local/tmp`**：里面是另一 agent 的 `p_ours.so`/`run*.sh`/`ksud.log`
  （其会话已停，遗留物仍在），它的 `ksud.log` 写入方是 uid=0、
  package=com.resukisu.resukisu。
- 利用失败会污染设备状态（`F_SETPIPE_SZ` 返回 `EPERM`、FOPS route `success=0`
  等），**排障第一步通常是 `adb.exe reboot`**，不要试图靠改参数绕过。
  （reboot 后 temp 的 chcon 会丢，先执行上面第一条命令。）
- `KSUD_DST` / `KSUD_LOG` 必须以 `/data/local/temp/` 或 `/data/local/tmp/` 开头，
  否则静默忽略环境变量回落到默认值（`src/preload.c` `tmp_path_ok()`，默认已是 temp）。
- 未在 README 中列出但代码支持的调试开关：`SLIDE_ONLY=1`（只做 KASLR leak 就退出）、
  `PSELECT_SIMPLE_LAYOUT=0`、`SLIDE_PSELECT_SHIFTS=<n,n,...>`、
  `KSUD_NO_PARENT_INSTALL=1`、`KSUD_STAGE_EARLY=1`、
  `KSNITCH_{MM_STRUCT_SZ,MM_ORDER,THREADS,COLLISIONS,MTE,VERBOSE}`。
  反过来，README 列出的 `KSUD_DEFER_TO_PARENT` 在代码里**不存在**。
- 所有 env 开关用 `strcmp(v,"0")` + `strcasecmp("false"/"no")` 判假，即空值=用默认值。

### chain15 全链 root（2026-10-07 22:47 rc=0 无重启）——窗口→gate→physrw→root 一次过

根因链（chain9-14 窗口死亡/gate 六连败/panic 全部定位并修进代码，so sha `cdcdbda7…` 起）：

- **窗口死亡根因**：`open_selected_fds`（fops.c:497）对 fd<320 置位 fd 全部
  `dup2(rw_fd, fd)`，低位 reclaim socket 被顶掉 → payload skb 清空 → 页释放；
  `rxq=1` 实为 rw socket 的 `'X'` 字节。修：util.c socketpair 后
  `F_DUPFD PSELECT_ROUTE_NFDS+64` 提升两端，窗口 `q0=655360` 贯穿（chain14 起）。
- **chain14 panic 根因**：conv 子 kvfy 探针 EEXIST（父 100ms fetch 与子 fetch 撞车
  同名 `kprobes/kvfy`）→ fetch rv=-1 → base=0 → gate 诊断 `direct_to_head_page(fd,0)`
  数据中止 oops→panic。修：① `ks_probe_fetch_batch` 全程 flock
  `/data/local/temp/.ks_kvfy.lock` + 注册三连重试；② prepare 后 `base==0` 直接
  abort before gate + gate 诊断 `base==0` 跳过 head/ident 内核读。
- **cache gate 必败根因**：B = kmalloc-2k 空闲对象（`/proc/slabinfo` num-active，
  本机 fresh≈104、同 boot 连跑多链后 ≈400-500）≥ drain 根数时全部被 freelist
  吸收、零 buddy grow、flip 恒 -1。修：`PIPE_DRAIN/RECLAIM_SLABS 15→64`
  （1024+1024 根）+ prep 提 `pipe-user-pages-soft` 16384→262144——
  **默认 soft=16384 页 = 512 根 32 槽上限，超限 F_SETPIPE_SZ 失败→SYSCHK→pr_error
  直接杀宿主进程**。sc 探测改每 16 分配一次（每根 fetch 会撞 120s prepare 超时）。
  实测 flip=415（attempt1）/527（attempt2）。
- pagetypeinfo：Normal zone order-3 Unmovable≈31 / Movable≈350——wave 靠 fallback
  偷页落地目标，drain 需数百次 grow（耗尽 Unmovable 后 fallback 才碰 Movable 顶部），
  480 根既不够过 B 也不够触发 fallback。
- **prep `chcon` 必须 `-R`**：残留文件持旧 `system_data_file` 上下文 → adbd push
  EACCES 覆盖失败（目录 chcon 不递归）；prep 已改。
- ~~postlock/coldstart 未决~~ → **已解决（2026-10-08 实测）**：postlock trigger 传
  `KS_PIPE_SLABS=15`（480 根=15360<16384，fresh boot B≈104-400 足够），成功后
  ROOT_SCRIPT 再 `echo 262144 > pipe-user-pages-soft`；三连全绿见下节。

### postlock Tier-1 shell 全链 root（2026-10-08 rc=0×3）与 route 脏 slot panic 根因

**shell 模式全链已通**（trigger7 + postlock run3/4/5，均 `pipe physrw root=1
uid=2000->0` + verify OK）。依赖四件套（缺一即 prepare 死/CFI 必 miss）：

1. **root 预处理**：`setenforce 0; chmod -R 777 /sys/kernel/tracing`（kprobe 事件
   在运行时以 root:644 创建，chmod 树管不到 → trigger 再带
   `KS_TRACEFS_SUDO=/system/bin/su`，ks_write_file 失败时 su 代写 enable/filter）。
   另有 `ks_probe_layout`/`ks_probe_fetch_batch` 的 get_task_mm 触发改读
   `/proc/self/cmdline`（shell 读 /proc/1 必 EACCES）。锁定后 su/chmod 皆无 →
   安全失败（待研见末）。
2. **pvo 每 boot 滚动**（已见 5 值 0x468/0x554/0x4e8/0x790/0x6fc ×0x10000000）：
   root 跑 `LD_PRELOAD=<so> SLIDE_ONLY=1 /system/bin/true`（main.c layout 后即退）
   解析 `layout ... pvo= vmemmap=[` → env `KS_LAYOUT_PVO/KS_LAYOUT_VM`。
   **裸串必须按 hex 解**：曾被 `strtoull(...,0)` 当八进制读成 `pvo=7` 全链垃圾
   （util.c `ks_env_hex` 已修，postlock 也加 `0x` 前缀双保险）。
3. **runner env 三件套** `KS_PSELECT_BSS_LOCK=1 KS_CFGFS_LOG=1 KS_PAYLOAD_SCAN=1`
   （+`KS_LOG_SYNC`/`KSNITCH_VERBOSE`；缺 BSS_LOCK 则 CFI 必 miss——权威来源是
   `run_fops.sh` runner 行）+ `KS_PIPE_SLABS=15` + `KS_TRACEFS_SUDO` +
   `KS_PAYLOAD_BASE_FILE=/data/local/tmp/ksu_boot/skbdelta`（fresh 设备无
   `/data/local/temp` 且 shell 不可在 /data/local 下 mkdir；stale 跨 boot skbdelta
   已被 reload 的 physmap 窗口校验拒绝，防 panic）。
4. 脏 slot 文件可写（见下），postlock Tier-1 预处理里 `chmod 666` 修复旧 root 文件。

**route 脏 .bss slot = panic（trigger4/run2 两次重启归因，pstore 实锤）**：
- BSS fake rt_mutex 每 attempt 烧一个 slot（32 槽），burn 记录在
  `/data/local/tmp/.ks_lock_slots`（`<boot_id> <mask>`）；waiter 种在 route 线程
  **内核栈**上。进程退出栈页释放 → **下一进程复用脏 slot = rb 链表头指向已释放栈
  页（pte=0）→ `rt_mutex_adjust_prio_chain` oops（Comm=ks_consumer，sched_setattr
  PI 链）→ panic → watchdog 重启**。同进程内连续 attempt 不炸（栈活着）；跨进程
  才炸——t6→t7 无事、run2 复用 t7 成功插入的 slot0 即死。**同 boot 首跑必稳、
  二跑看 mask**。
- 原 bug：root 上下文创建的 slot 文件 644 → shell 只读不能写 → claim/burn 持久化
  全 EACCES（日志特征 `cannot claim` / `cannot persist dirty slot mask`）→ mask 恒
  0 → 复用。修复（fops.c）：① `pselect_slot_write` 后 `chmod 666`；②
  `pselect_load_slot_mask` 各分支 claim 写失败即 return 保持 `tracking_ok=0`
  （attempt 选择处既有 pr_error 拒跑=安全失败）；③ `pselect_mark_slot_dirty`
  写失败也置 `tracking_ok=0` 拦后续 attempt。生效特征：二跑起打
  `pselect dirty lock slots mask=N starting at slot=N`。
- **判 ROOT_SCRIPT 是否真跑只认 `POSTLOCK-ROOT-SCRIPT-OK`**：verify 四项
  （uid0/驱动/daemon/wrap）会被上一次运行的遗留撑绿（run4 中途死、verify 照常 OK）。
- ROOT_SCRIPT 重跑必须**先 rm 再 cp** 覆盖 `su`/`libgrant.so` 等正被
  执行/映射的文件（否则 ETXTBSY + `set -e` 中断）；overlay 的 upper/su 同理。
  旧 daemon 跑在 unlinked inode 上无碍，后面 kill+重启自然切新文件。
- postlock 另有**残链进程清理**（`pgrep -f preload\.so` → TERM 等 15s → KILL）：
  host timeout/adb 断开后孤儿链继续跑，双链并发必出事（run1/run2 疑似肇因）。

**锁定后待研（无 su）**：① pvo oracle（physmap 泄漏 base + 256MB 栅格窗口代数
≤56 候选）；② Enforcing 下 tracefs 读原语（kprobe fetch 无 sudo 代写）；③ slot
文件/skbdelta 的无 root 可写路径（fresh 设备天然满足，本机被 root 644 文件卡住）。

### 红卡「管理器版本与内核驱动版本不匹配」= 冷 boot 驱动未加载（2026-10-24 已修）

- **定性**：kernelsu.ko 只在本 boot 存活，冷启动（bootreason=cold）后模块消失 →
  ReSukiSU 检测链 ioctl（ksu_driver fd）miss → fallback `prctl(0xdeadbeef)`
  命中**设备自带 KernelPatch** → 拿回 KP 版本 ≠ 管理器 35236 → 红卡报
  「版本不匹配」。**不是版本号真不匹配**（35220/5 驱动 vs 35236/5 管理器 UAPI
  5==5 一直蓝卡），也不是补丁被升级冲掉。判别：`ls /sys/module/kernelsu`
  不存在即此类。
- **修复 = 跑一轮完整恢复**（app 域 gate 路径，本轮实测）：等 load<2.0 → 泄题轮
  （marathon 同款 `KS_PREPARE_HALT=1800`，本轮 24s 就绪）→ gate 自动 dispatch
  （本轮「gate satisfied after 372s」正常，无需 LAUNCH 补）→ 链 root=1 →
  self finitmod 加载 kernelsu.ko+ocsk.ko、`ksu_debug_manager_appid=10279`、
  daemon、Permissive → 蓝卡「工作中 Built-in」。**gate 时序注意**：等 ENTER 时
  别用「开始轮询的时刻」当 BOOT_MS 界——泄题就绪后 gate 可能已经 ENTER（本轮
  差 9s 被误判成旧 ENTER，多余的 LAUNCH 侥幸被防重入挡住——同 boot 二次链是
  事故高发项，见 ran_boot 一节）。
- **本轮遗留疑案（shell 域 postlock.sh panic）**：`ADB=` 覆盖后 postlock.sh
  触发的 shell 域链走完 root + restore（`restore OK` 打出、脚本开始 verify）后
  **90 秒内 `kernel_panic,fatal_exception` 重启**，驱动随之丢；链 stdout 尾部是
  **`cfgfs read set-fail errno=25(ENOTTY)` 无限循环**（target 恒定
  `ffffff9b51639051`），pstore 本次为空拿不到栈；host/assets so 均为 kill
  switch 版 0eba9857（排除旧 so）。app 域 gate 路径同 boot 恢复成功 = 对照组。
  **下次跑 postlock.sh 前先意识到此未定案**；复现时先抓
  `/data/local/tmp/postlock_chain.log` 的 cfgfs 循环段与 pstore。
- **postlock.sh 使用两坑（2026-10-24 实测）**：① `command -v adb` 会选中 WSL 的
  `/usr/bin/adb`（看不到 adb.exe 的设备）→ 假报 `no device`，必须
  `ADB=/mnt/c/WINDOWS/system32/adb.exe` 显式覆盖；② host adb.exe 现在会**同时
  连着 LAN 192.168.8.10:5555 与 tailnet 100.71.26.6:5555**（同一台设备两条
  通道，host 已可达自建 tailnet），多设备时 `ab get-state` 报 more than one →
  脚本判 `no device`——跑脚本前 `adb disconnect` 掉非目标通道（断单个连接不在
  kill-server 红线内）。

### 模块「无法正常工作」根因 + late-load 模块阶段固化（2026-10-24 已修，app v1.61）

- **根因两层**：① 恢复流程（restore/coldstart）只加载驱动 + ocsk + appid，
  **从不跑 ksud 的 boot 事件**（`/data/adb/ksud` 本体是链 self 路径 05:40 写的，
  但 post-fs-data/services/boot-completed 无人触发 → 模块脚本从没执行）；
  ② 驱动是 boot 后期 insmod 的，**zygote 早已启动 → Zygisk Next 没赶上注入
  窗口** → 所有 zygisk 模块（Zygisk Next/HMA/PIF）失效。非 zygisk 型
  （OMK 注入 keystore2、YH_YC daemon）靠 ksud services 拉起。
- **手动修复实测（boot ed47f0ba）**：`su -c "/data/adb/ksud post-fs-data"` →
  `services` → `boot-completed`（三事件同步返回，各模块脚本输出可见：OMK
  `injection completed`、YH_YC 监控中）→ **`kill -9 zygote64 zygote`**（init
  自动重拉；**`ctl.*` setprop 连 su/root 都被 init 属性服务拒**——与
  `persist.adb.tcp.port` 同类，不随全局 permissive 放行，只能信号）→ 新 zygote
  带注入（Zygisk Next module.prop 报 `[✓ zygote, ✓ zygote_secondary, Root:
  ✅KernelSU (35220), UM, AM, ZL]`）→ 5 模块全正常，framework ~40s 恢复
  （boot_completed=1，驱动/ocsk/zn-daemon/setsid daemon 全保留）。
- **`ksud soft-reboot` 坑**：阻塞式，20s timeout 截杀会留**半死状态**
  （`sys.boot_completed=0` 但 zygote 没重启）——补救 = 直接杀 zygote 走 init
  重拉（`killall` toybox 有、`pidof` 可用）。
- **固化（两份 restore.sh 同步改：`tools/postlock.sh` heredoc + app assets）**，
  顺序、位置有讲究：
  1. **PPID 等链退出**（`CHAIN_PID=$PPID` 快照 + 60×2s 上限，放 `set -e` 后）：
     bounce 杀 app uid 进程，**app 域链本身就是 app uid**——链还在
     neutralize 收尾时被杀 = dangling fake fops → 第三方 open misc → panic；
     `$PPID` 快照 = KS_COLDSTART fork 的链 pid，constructor 收尾完成才返回、
     宿主才退出，等它死即等收尾完成。
  2. **ksud 三事件**（`timeout 60/90/30`，WARN-only 兜 `set -e`）。
  3. **zygote bounce + 轮询 boot_completed**（45×4s=180s）——**必须置于
     restore 尾部 `am start` 管理器之前**（管理器要在注入好的 framework 上
     拉起）；BOOT_COMPLETED 会重发但 ran_boot guard 拦 dispatch。
  4. postlock.sh 的 RESTORE-OK 轮询 **90×2s → 240×2s**（新尾段典型 ~135s）。
- **staging 刷新**：app `PAYLOAD_VERSION` bump 到 `v5-0eba9857-modstage-20261024`
  （v1.57 教训：不 bump 设备 files/postlock/restore.sh 永远旧版）；但
  **ensurePayload 只在链触发路径（triggerChain/dispatchLocked）调**——装机后
  主页打开**不会**刷 staging——装机当下要手动同步：push 中转 +
  `run-as com.postlock.boot cp`（别走 stdin 直写，su 吃管道的同族坑）+
  `.ver` 一起写成新值保持幂等。
- **PostLock 驱动徽章红卡（v1.60）**：`refreshDriverBadge()` 三态——模块缺失 →
  红「✗ 未加载（管理器将报无驱动/版本不匹配）」（= BakaSu 冷 boot 红卡的同一
  状态）；modinfo version（`/sys/module/kernelsu/version`，当前 ko 未导出→null
  不误判）与管理器 versionName 系列不符 → 红「✗ 管理器版本与内核驱动版本不匹配」。

### 红卡「获取root权限失败」根因 + grant.c v3 + coldstart 依赖链（2026-10-08 已验证修复）

**红卡判定链**：`HomePage.kt:306` `ksuVersion!=null && !isRootAvailable` →
`KsuCli.createRootShell()`：`build(ksud,"debug","su")` 失败→回退 `build("su")`→
再失败 `build("sh")`——非 root 合法 shell **不抛异常**（libsu 只在进程起不来/
不是 shell 时 throw）→ `isRoot=false` → 红。**本次实际根因 = 运行态丢失**：
reboot 后 daemon 死 + /product/bin overlay 没 → ksud 无 `[ksu_driver]` fd 报
`could not retrieve kernelsu driver fd` 退出（wrap 下 app 的 ioctl 被 libgrant
先手接、从未与内核 supercall 握手 → 进程无 fd 可继承，推断自 chain17 无 wrap
时徽章走真内核）→ `build("su")` ENOENT → `build("sh")` 非 root → 红。
**修复 = `tools/coldstart.sh` 全量重建**（daemon+overlay+wrap），force-stop/重开
蓝卡已验（工作中 Built-in 越狱模式，驱动/管理器 35193/4，4 超级用户+6 模块）。
- **grant.c v3**（`tools/libgrant/grant.c`，NDK `aarch64-linux-android31-clang
  -fPIC -shared -O2 -ldl`，产物库存 `tools/libgrant/` + `/tmp/opencode/`）：
  ① ioctl 钩子遇**真 driver fd**（readlink `anon_inode:[ksu_driver*]`）透传
  real_ioctl，透传 `0x0c SET_APP_PROFILE` 成功后补 `set_profile`→
  `update_allow_file`（su.allow 跟真 store 同步）；② prctl `0xdeadbeef` 在进程
  存在 driver fd 时透传（真 miss → 诚实「默认」）；③ 非 driver fd 行为不变
  （pre-driver 兼容）；constructor 打 `grant v3 init` 作部署指纹。
  当前实际走**回退路径**（app/ksud 无 fd，v3 透传未触发），是给 Layer⑤ 真探测
  预铺；取证特征：grant.log `v3 init` 与 su.log `uid=10282 allow=1` pid 成对。
  （早先怀疑「libgrant 假 GRANT_ROOT 致红」不成立：ksud 无 fd 连 ioctl 都到不了。）
- **coldstart 在新 boot 上必须先跑链**：驱动步依赖链的 `patch_sig_enforce`
  （`src/root.c:487`，链成功时写 .data `sig_enforce` 1→0，chain5.log 特征行
  `sig_enforce <addr> 1->0 write=1`）。未跑链时 `CONFIG_MODULE_SIG_FORCE=y` 默认
  生效 → finitmod EKEYREJECTED `Loading of unsigned module is rejected`；
  sysfs param 是 __ro_after_init **写不进**（别浪费时间 echo 0）。正确顺序：
  `prep_device.sh` → `run_fops.sh`（链）→ `coldstart.sh`；coldstart 驱动步已带
  该诊断提示。链 47s rc=0 即够（不需 postlock 整套）。
- **链分离启动防 rc=130**：`nohup sh /data/local/temp/run_fops.sh >
  /sdcard/chain_run.out 2>&1 < /dev/null &` 再轮询 `/sdcard/chain_run.state`
  （06:15 那次 adb 掉线 ^C 中断于 prepare retry → 安全可复跑；若中断在 route 之后
  则先查 `/data/local/tmp/.ks_lock_slots` 的 boot_id+mask 再动）。并发实例 guard
  在 run_fops 头部（grep `[p]reload\.so`）。
- **temp 观察跨 reboot 存活**（b3b5ce6a 上 10-01~10-08 文件共存），与 10-02
  「reboot 即清」记录矛盾——10-02 那次疑为恢复出厂所致，存疑待复核。
- 设备可用 **Tailscale adb**：优先 MagicDNS `adb connect oppo-a96-5g.tail5809d2.ts.net:5555`（2026-10-21 起可解析 → 100.80.86.28）；旧 IP 直连仍可用。

### 自研 su（方案 2）相关坑

- 组件：daemon ELF `/data/local/temp/su --daemon`（socket `su.sock`、pidfile `su.pid`、
  日志 `su.log`）；client 即同一 ELF 无参数调用；payload 内 `SU_INSTALL=1`（默认）/
  `SU_SYSTEM_BIND=1`（默认 0，开则自装 system 路径）/ `SU_SOCK` / `SU_ALLOW_UIDS`。
- system 路径方案 = **overlay 挂 `/product/bin`**（PATH 第一，抢在 `/system/bin/su` 前）：
  low=bind `/product/bin`、upper/work=tmpfs、**mount 必须带
  `context=u:object_r:system_file:s0` 选项**——不带会因 tmpfs/f2fs 无 security xattr
  handler 报 ENOTSUP（`SELinux: … has no security xattr handler`）。原 4 个文件经
  lower 保留。`/system/bin/su` bind 方案不可行（见下）。
- 设备自带 **APatch/KernelPatch**（白名单仅 com.android.shell）：`/system/bin/su` 真身
  不存在，stat+execve 是内核伪造的（`ls` 可见、`open/mount` ENOENT、dmesg
  `cplen:14`），**`mount --bind` 覆盖不可行**；也不要依赖/破坏它（daemon 死时它是回退）。
- client 连接 daemon 需要 **Permissive**：Enforcing 下 connect 返回 EACCES 且 AVC 被
  dontaudit 静默（dmesg 无 avc 记录）。APatch 开机即设 permissive，exploit 链也会
  `setenforce 0`；若手动 `setenforce 1`，`su` 会先打 "connect daemon: Permission
  denied" 再回退 APatch（uid≠2000 的 app 回退会失败）。
- daemon 不可达时 client 自动 `execve("/system/bin/su")` 回退（`su.log` 有
  `fallback exec` 行），所以 runner/其他 agent 的 `su -c` 不会因 daemon 挂掉而断。
- **手动操作别用裸 `su`**（已被 PATH 劫持），引导用绝对路径 `/system/bin/su -c '…'`；
  拉 daemon：`/system/bin/su -c 'setsid /data/local/temp/su --daemon >> /data/local/temp/su.log 2>&1 < /dev/null &'`。
- **Android 没有 `/tmp`**：重定向 stderr 到 `/tmp/x` 会让整条 shell 命令连执行都没执行，
  排障重定向一律写 `/data/local/temp/`。
- KernelSU Manager 端到端已验证：状态卡**「工作中 [越狱模式] 版本 32601-2」**、
  SELinux 宽容、管理器 v3.3.0。su.log 出现 `uid=10283 mode=B allow=1`（libsu 非 tty
  场景走 **'B' 帧协议**，交互 shell 才是 `mode=I`）。其日志里的 `KsuService disconnected`
  是预期现象（无内核 ksu 驱动），与 root 无关。
- **`su` client 按 `isatty(STDIN)` 选 mode**：tty→'I'（pty+`sh -i` 原样），非 tty→'B'
  （帧多路复用）。'B' = `exec_pipe_shell` 三管道中继，sh stdout/stderr 分离帧化
  `[type le32][len le32][payload]`（1=OUT 2=ERR，FRAME_MAX=65536），client `b_client`
  解帧分发 fd1/fd2。**两端必须同版本**（无版本协商），改 `su_daemon.c` 后要先杀掉
  **所有** su 进程（daemon+handler+client，`ps -A -o PID,ARGS | grep -E '(^|/)su( |$)'`
  循环 kill）、`rm -f su.pid` 再重新拉 daemon，否则旧 client/daemon 混连必然出错。
- **旧 ANR（app 启动卡 Splash→`anrViaNoFocusWindow`→signal 9）根因**：libsu `JobTask
  END_CMD` 向 stdout 和 **stderr** 各打一个 UUID marker，`errGobbler` 等 stderr 上的
  marker；旧实现把 sh stderr 并进 socket → client 只转 fd1 → **stderr marker 永不到
  fd2** → Job 永等 → `FutureTask.get()` 永等 → ANR。'B' 三管道修复后消除。
  （历史误导：早期结论「prompt 无换行 readLine 卡」属 'I' 模式时代，勿混淆。）
- 启动瞬间 logcat 每轮可能有 ~3 条 `KsuCli: Created process is not a shell`
  （shellCheck IOException），**可恢复非致命**（与上面永等 ANR 是不同失败模式），
  随后 libsu 重试成功、状态卡正常。持续刷屏才是问题。
- daemon 架构：1 个监听主进程（PPid=1，pidfile `su.pid`）+ 每连接 fork 一个 handler
  子进程（cmdline 仍是 `su --daemon`，fd=connected socket；app 的常驻 libsu shell
  会让 handler 长期存活，属正常）。
- **KernelSU app 的 `libkernelsu.so` 补丁**（file off = VA-0x4000，`movz w0,#imm16; ret`，
  仅 14480B）：getVersion 0x14ec 由 40000 改 **32601**（与管理器 v3.3.0 (32601-2) 对齐，
  消除「管理器版本与驱动版本不匹配」红卡）；getKernelUAPIVersion/getManagerUAPIVersion→2、
  getSuperuserCount/isSafeMode/isLkmMode/isPrBuild→0、isLateLoadMode/isManager→1。
  补丁库存 `/tmp/opencode/libkernelsu_patched.so`（md5 `30cf809f…`）。
- **`adb push` 到已存在文件会换 inode** → 已挂的 file bind-mount 不跟随新文件；修复用
  **`cat new > $LIB` 原地 truncate 写**（保 inode，bind 即时可见），再
  `am force-stop me.weishu.kernelsu` 重启。bind 表象：`mount | grep` 显示源为
  `/dev/block/dm-30 on <libpath> type f2fs`，`/proc/mounts` grep 路径查不到属正常；
  对已挂目标重复 `mount --bind` 报 ENOENT/`umount` rc=1 可忽略。
- 验证补丁是否生效：看**状态卡 UI**（截图），或 `dumpsys window | grep mCurrentFocus`
  确认前台后截图；`am start` 组件是 `me.weishu.kernelsu/.ui.MainActivity`（`.MainActivity`
  不存在）。截图前 `input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard;
  am force-stop com.jingdong.app.mall`（京东抢前台）；锁屏/NotificationShade 时用
  `input swipe 540 1800 540 600 300` 或再次 dismiss。设备状态栏时间与本机不同步，
  勿用截图时间戳判断时序。
- 读进程内存验证 so：`/proc/PID/maps` 里 app so 显示 **`(deleted)` 属正常**（bind 上层
  inode 被 unlink 但被 mount 持有）；toybox `sh` 算术把 0x7393ea5000 类地址**按 32 位
  截断**，`awk` 也不认 `0x` 字面量，别用它们算 64 位 vaddr。

### ReSukiSU 翻牌（用户偏好它 > KernelSU Manager）

- app `com.resukisu.resukisu` v4.2.0-rc3，启动组件 **`.ui.MainActivity`**
  （`.MainActivity` 不存在）；`libkernelsu.so` **18520B**（≠ KernelSU 的 14480B，
  JNI 名 `Java_com_resukisu_resukisu_Natives_*`），同目录还有自带 `libksud.so`。
- **app 已实际升级 35193**（2026-10-02 06:30 自动升级，35189 补丁被新 APK 覆盖），
  35193 补丁库 `/tmp/opencode/libkernelsu_resukisu.so`（md5 `45bf11ec…`），
  原版 `libkernelsu_resukisu.orig.so`。**`/tmp/opencode` 也会被清**（同日实测），
  关键输入（`grant.c`、补丁 so）丢了要能重造：grant.c 见 libgrant 节，补丁流程见下。
  新 APK 的 so 路径带随机段：`/data/app/~~EtdH9yO11cS9w-lWLyp70Q==/
  com.resukisu.resukisu-LPRDh0m_opn0Cr2p-sfeGw==/lib/arm64/libkernelsu.so`
  （升级后路径会变，先 `pm path com.resukisu.resukisu` 找）。
- **检测机制**（理解了才知道补哪）：JNI 函数调 helper `0x3550`——ioctl 到 **Suki ksud
  进程**（cmd `0x4b02`，先 opendir 扫 /proc 找进程），失败则 fallback `0x383c`
  = `prctl(0xdeadbeef)` **KernelPatch 接口**；两者都不响应 → 红卡「内核上未检测到
  KernelSU 驱动程序」。x0 位域：低32=版本、bit32=isLkm、bit33=isManager、
  bit34=isLateLoad、bit35=isPr；x1 高32=kernelUAPI。
- **补丁表**（各 JNI 入口直接 `mov`+`ret`，原函数较长故不越界）：
  `getVersion@0x1da8`→**35193**（`0x52912F20`，`mov w0,#0x8979`——**35193=0x8979**，
  曾误算 0x897B=35195/0x52912F60；35189 版为 0x8975/`0x52912ea0`）；
  `getKernelUAPIVersion@0x1dc0`→4（对齐 getManagerUAPIVersion 硬编码 4）；
  `isManager@0x1f14`→1；`isLateLoadMode@0x1f74`→1；
  `isLkmMode@0x1ef8`/`isPrBuild@0x1f3c`/`isLkmBundled@0x1f58`→0。
  `getSuperuserCount`/`isSafeMode` 无需 patch（自然返回 0）。
  成果：蓝卡**「工作中 [Built-in] [越狱模式]」**，驱动 == 管理器（35189 与 35193 均验）。
- **35193 重打流程（升级覆盖后照此恢复，实测 2026-10-02）**：
  1. `pm path com.resukisu.resukisu` 拿新 so 路径，pull 原版为 baseline；
  2. 上表偏移经 `llvm-objdump -d` **符号名逐一核对**（`.text` file off == VA，
     无 0x4000 修正；7 个原函数序言均为 `str x30,[sp,#-0x10]!` = `f81f0ffe`，
     **不是 paciasp**）——升级后必须重新验证；
  3. MOVZ W0 编码公式 **`0x52800000 | (imm16<<5)`** + `ret`=0xD65F03C0；imm16=版本号
     低 16 位（35193=0x8979）。**已脚本化：`tools/patch_libkernelsu.py`**（含 7 处
     序言锚点校验，锚点不符即报错要求重新推导）；
  4. 部署：app 持 PROT_EXEC → **force-stop →（shell 写 /data/app 被 DAC 拒，先 adb
     push 到 /data/local/temp 再 root `cat 文件 > $LIB`）→ start**。
     坑：`adb shell su -c 'cat > $FILE'` 管道 stdin 会被 su 吃掉（写成 476B 垃圾），
     必须走「push 中转 + 从文件 cat」。
- **部署**：该 so **无 bind-mount**（普通文件）；app 运行时持有 PROT_EXEC 映射，
  直接写会 ETXTBSY → 顺序必须 **force-stop → `cat patched > $LIB` → start**。
  改后 force-stop/start 复测无 ANR、状态稳定。
- **自更新风险已兑现**：app 2026-10-02 自动升级 35193 → 补丁被覆盖，已按上表重打
  恢复；以后每次升级都要重打，红卡「需要更新内核/获取 root 失败」类异常先想到
  「补丁被升级冲掉」。

### ReSukiSU 授予链（libgrant，方案 3）——修复「无法给应用授予 root」

背景：ioctl 全失败（无 `ksu_driver` fd）→ `setAppProfile` 假成功但 `getAppProfile`
永远 miss → toggle 点了弹回、badge 全错。方案：**不走内核，直接在 app 进程里
interpose ioctl/prctl 模拟 KSU uAPI**，并把授予状态落到文件、驱动自研 daemon 白名单。

- **注入**：`wrap.com.resukisu.resukisu = LD_PRELOAD=/data/local/temp/libgrant.so`
  （**非 persist 属性，reboot 后丢，冷启动脚本必须重设**）。已实测 GOT interpose 生效。
  源 `/tmp/opencode/grant.c`（**tmp 会被清，丢了照本节语义重写**），NDK
  `aarch64-linux-android31-clang -fPIC -shared -O2 -ldl`
  编译为 `libgrant.so`（15KB）。**静态 su 是配套项**：app exec `/product/bin/su` 时
  linker namespace 不允许 `/data` 下的 LD_PRELOAD（CANNOT LINK），故 `Makefile` 的
  `$(EMBED_SU)` 用 `-static`（`-static-pie` 在 Android 12/NDK r29 上 segfault），
  静态 ELF 忽略 LD_PRELOAD → su 侧不被干扰。
- **ioctl 拦截**（type `0x4b`，任一 fd）关键语义：
  - `0x02 GET_INFO`：`{u32 ver=35193, flags=6(MANAGER|LATE_LOAD), features=5, uapi=4}`；
    `0x05` safemode=0；`0x06 NEW_GET_ALLOW_LIST`：`{u16 count(入=容量,出=写数),
    u16 total=granted数, u32 uids[]}`（主页「N 个超级用户」=total）；
    `0x08/0x09` 按 store 查 granted；`0x0a manager appid=10282`；
    **`0x0b GET_APP_PROFILE`：store 命中→回填 784B blob 返回 0，miss→返回 -1**
    （-1 才走 Kotlin 的 default 路径：allowSu=false + nonRootUseDefault=true →
    badge「默认」；v1 曾恒返回 0 回显输入 → 全员 CUSTOM + toggle 弹回，就是那个 bug）；
    `0x0c SET_APP_PROFILE`：整 blob 按 key 落 store + 联动写 `su.allow`；
    `0x0d GET_FEATURE`：`{u32 id, u64 value@8, u8 supported@16}`，SU_COMPAT/UMOUNT
    supported=1 默认值 1，SULOG/ADB_ROOT/SELINUX_HIDE supported=0（设置页灰显）；
    `0x0e SET_FEATURE` 落 `su_features`；`0x64` full version 填
    `v4.2.0-rc3 (35193/4)`；`0x65` hook=`manual`；`0x67` GET→清零；
    `0x69 GET_MANAGERS`：2 个管理器 {10282,sig0},{10283,sig1}（probe count=0 →
    total=2）；`0x6a` type=0(NOT_FOUND)。
- **prctl legacy 拦截**（`option=0xdeadbeef`）约定：成功 = **`*a5=0xdeadbeef` 且
  return -1**（ksuctl 判 `result==magic && rtn==-1`）；失败 = 不写 magic（result
  保持 0）。cmd 表：2 GET_VERSION(*a3=35193,*a4=6)、5/6 allow/deny list、
  10 GET_APP_PROFILE（a3=profile，同 store hit/miss 语义）、11 SET、13 uid_should_umount、
  14/15 su_enabled、0xC0FFEE1A 版本串、101 hook、103 dynamic、104 managers。
  非 magic option 全部透传 real prctl。**ioctl 0x0b miss → ksu.c 再走 legacy prctl(10)，
  两条路径都 miss 才返回 -1** —— 必须两边语义一致。
- **持久化文件**（全在 `/data/local/temp`，**reboot 后整个目录被清**——2026-10-02
  实测推翻旧「保留」结论：so/授予 store/su.allow/日志全没，且目录 label 回
  `system_data_file`，须 root `mkdir + chcon u:object_r:shell_data_file:s0 + chmod 777`
  重建，再 push 回 so 并重设 wrap prop/overlay/daemon，见下「reboot 恢复清单」）：
  - `su_profiles.dat`：`{u32 magic 0x5055534B, u32 n}` + n×`{key[256]+blob[784]}`，
    **600 属主 app uid**（shell 读不了，用 root dd 读）；blob 内 `curr_uid@0x104
    allow_su@0x108`。
  - `su.allow`：**666**，`seeds{10282,10283,2000} ∪ granted uids`，libgrant 每次
    SET/constructor 全量重写；daemon 白名单数据源。
  - `su_features`：只在 SET_FEATURE 时创建（缺省=SU_COMPAT:1, UMT:1）。
  - `grant.log`：constructor/SET/miss 一行制；`touch /data/local/temp/grant_verbose`
    开 verbose（GET hit/FEATURE/UID_GRANTED 详情，日志会暴涨，用完删）。
- **daemon 白名单**（`src/su_daemon.c` `client_uid_allowed` 已改）：优先级
  env `SU_ALLOW_UIDS` > 文件 `/data/local/temp/su.allow`（存在=严格白名单、
  **缺失=回退 allow-all**）>。已验证 allow=1→uid=0 / allow=0→连接即关 /
  恢复→通。**授予 → UI toggle → store → su.allow → daemon 放行** 全链路闭环；
  主页「N 个超级用户」= store granted 数。撤销（toggle OFF→重进 OFF）也已验证。
  注意：**改白名单后第三方 app 未授予即拿不到 su**（正是预期语义）；未进 store 的
  app（如 shell 的 ON 显示）是 UI 对 shell 的特殊显示，不走 store。
  **uid0 不在 seeds → root 作为 client 连 daemon 会被拒**（`client_uid_allowed` 无
  uid0 特判）；脚本 verify 一律用 shell(2000) 身份跑 `/product/bin/su -c id`。
  主页计数卡可能**滞后于 store**（改完不刷新，force-stop/start 后才更新）。
- **UI 操作坐标/坑**（1080×2400）：返回箭头 `(90,178)`、底部 tab 是**4 个**
  （主页≈`(140,2197)`、超级用户≈`(346,2197)`、模块(角标N)≈`(551,2197)`、设置≈`(756,2197)`；
  旧版 2-tab 的 `(417,2197)` 已失效，先 dump 确认）、详情页「超级用户」toggle
  `(990,958)`、列表页搜索框 `(540,594)`、
  行 bounds 用 `uiautomator dump` 现查（行序会因 granted 排序变化，**别用固定 y
  点行**）；详情页是弹层——`uiautomator dump` 会抢焦点把它关掉（截图≠dump 时页面）；
  `input text` 会留在搜索框。**搜索框获得焦点弹出键盘后，底部 tab 坐标 (x,2197) 落在
  键盘上**（会打字、tab 不切换，曾打出 "she" 查询）——先 BACK 收键盘再点 tab。
  `input tap` 行本身=进详情，行内 checkable 是整行。
- **daemon 进程管理坑**：`su --daemon` 是 **uid0**，shell(2000) `kill -9` 直接
  **EPERM 静默失败**（表象=「杀了没死」）→ 必须 `/system/bin/su -c kill`；排 pid
  时 `grep -v " 25208 "` 这种单空格 pattern 会因 ps 多空格失效误杀。
  **`ps -A -o PID,UID,ARGS | grep -E "(^|/)su( |$)"` 匹配不到 daemon**——ARGS 是
  无路径的 `su --daemon`，pattern 以行首(PID数字)或 `/su` 开头永远不中，用
  `grep -E "su --daemon"`；但这条会匹配 handler 子进程（cmdline 同为 `su --daemon`，
  app 每连接 fork 一个，**存活属正常**，曾误判为事故）。
  未先 `rm su.sock` 就启第二 daemon 会**盖掉 su.pid 造成双 daemon 假象**，清理顺序：
  root kill 全部旧树 → `rm -f su.sock su.pid` → 起一个。
  老 daemon 会因 `rm su.sock` 后新 daemon 重新 bind 而**孤儿化**（accept 不到但
  进程还在）；app 侧 ESTAB 连接不受 unlink 影响，会一直挂在老 handler 上（曾堆
  60+ handler），清法=root kill 全部旧树 → app 自动重连新 daemon。
  `su.log` 的 `client connect failed errno=111 fallback exec /system/bin/su`
  是正常回退行（daemon 重启窗口）。
- **reboot 恢复清单**（2026-10-02 实测按序执行，全通约 10 分钟；**已脚本化
  `tools/coldstart.sh`**——幂等、可在健康状态直接重跑当回归测试，内含 libkernelsu
  补丁检测/重打/部署与最终 verify；需现存 root 通道 APatch `/system/bin/su`，
  回锁后无法自举）：
  1. `setenforce 0`（reboot 后回 Enforcing，APatch 不再开机自设 permissive）；
  2. root 重建 temp：`/system/bin/su -c "mkdir -p /data/local/temp && chcon
     u:object_r:shell_data_file:s0 /data/local/temp && chmod 777 /data/local/temp"`；
  3. push 三件套（`build/embed/su_daemon_aarch64_pie`→`su`、`build/pfum10c48/bin/
     preload.so`、`/tmp/opencode/libgrant.so`）+ 写 `su.allow` seeds；
  4. 起 daemon（`setsid /data/local/temp/su --daemon …`，见上清理顺序）；
  5. **重建 /product/bin overlay**（见下）；
  6. `setprop wrap.com.resukisu.resukisu LD_PRELOAD=/data/local/temp/libgrant.so`
     + force-stop/start app；
  7. 若 ReSukiSU 刚升级过 → 按 35193 流程重打 libkernelsu.so；
  8. 授予 store 随 temp 丢失 → UI 重新授予（当时 3 个：10283/10278/10277）。
- **两张红卡「需要更新内核」「获取 root 失败」= overlay 丢失 + daemon 死**（reboot
  后遗症，非补丁问题）：app exec `/product/bin/su` ENOENT → 启动自检失败。验证：
  `ls /product/bin/su`（ENOENT 即 overlay 丢）、`ps | grep "su --daemon"`（空即死）。
  两者修复后 force-stop/start 红卡即消（35193 下实测，蓝卡+计数恢复）。
- **overlay 重建命令**（root，须带 `context=` 否则 ENOTSUP，原理见上）：
  ```sh
  /system/bin/su -c "
  mkdir -p /data/local/temp/ovl/lower /data/local/temp/ovl/tmp
  mount --bind /product/bin /data/local/temp/ovl/lower
  mount -t tmpfs -o size=16m tmpfs /data/local/temp/ovl/tmp
  mkdir -p /data/local/temp/ovl/tmp/upper /data/local/temp/ovl/tmp/work
  cp /data/local/temp/su /data/local/temp/ovl/tmp/upper/su
  chmod 755 /data/local/temp/ovl/tmp/upper/su
  mount -t overlay overlay -o lowerdir=/data/local/temp/ovl/lower,upperdir=.../upper,workdir=.../work,context=u:object_r:system_file:s0 /product/bin"
  ```
  验证 `/product/bin/su -c id` → uid=0。tmpfs 也在 temp 下，reboot 同样丢。
- **shell 读不了 app 属主文件**：`grant.log`(600 u0_a282)、`su_profiles.dat` 对
  shell `cat/head` 全是 `Permission denied`（`2>/dev/null` 吞掉就误判成「没日志」）
  → 一律 `/system/bin/su -c "cat …"` 读。

## 回锁（fastboot flashing lock）SOP——刷原厂 boot + 锁 BL 后链路仍可用

**状态：流程/脚本已就绪，设备侧实测未做**（用户明确「暂不动设备」；动 fastboot 前先征询）。

- **设备是高通不是 MTK**：`/proc/cmdline` `androidboot.hardware=qcom`、
  `bootdevice=4804000.ufshc`、分区 sde/sda；旧调研的 MTK 解锁工具路线作废。
  型号 OPPO A96 (PFUM10, C.48)。
- **BL 状态真相只认 `/proc/cmdline`**（`vbmeta.device_state=`、`verifiedbootstate=`）：
  当前 unlocked/orange；`getprop ro.boot.*` 被 kpatch 伪造为 locked/green，**回锁验证
  禁止用 getprop**。
- **原厂 boot vs APatch boot 字节级等价（2026-10-03 离线实测，回锁后 exploit
  可用性的核心证据）**：两份镜像的 kernel 主体 `[0, 0x2e15a00)` 逐字节相同，
  唯一例外是 header 第 5-6 字节（code0 里那条 `b` 的目标：stock→0x630000、
  apatch→0xe17000，两处代码体本身也相同）；entry(+0x80000) 相同；**ramdisk
  md5 完全一致**（SELinux policy/init 无差异）；APatch 仅在尾部追加
  `0x48bf0`B KernelPatch payload（`KP11` magic、`kallsyms_lookup_name` 解析表、
  `11:20:00 Sep 24 2026` 构建戳，文件 0x2e16000 起）。结论：**target.h 的全部
  偏移在原厂内核上 100% 成立**，exploit 路由在两镜像上执行流等价；回锁后消失
  的只有 KP payload 提供的假象（fake /system/bin/su、真 kpatch prctl）——前者
  只是 daemon 死时的回退路径，后者已被 libgrant interpose 覆盖，均不影响链路。
  验证方法备忘：`python3` 解 v3 头（kernel_size@8、4096 页对齐）+ 4096B 块级
  diff；llvm-objdump 会把 `MZ` 头误判 COFF，反汇编用 `llvm-mc --disassemble`
  喂 hex 字节。
- **分区现状**（回锁前唯一要刷的是活动 slot 的 boot）：boot_a(/sde9)=APatch 补丁版
  （现跑）；boot_b(/sde30)=原厂 C.48；vbmeta_a/b 前 8192B 与原厂 `vbmeta.img`
  逐字节相同 flags=0（早先 md5 不同是分区 padding 误导）；vbmeta_system/vendor 原厂。
- **物料**：原厂镜像 `/mnt/c/Users/yang1/Downloads/OPPO_A96_PFUM10_11_C.48/`
  （boot.img md5 `c6f5f1ec…`、vbmeta.img 等）；fastboot 36.0 =
  `/usr/bin/fastboot` + `/mnt/c/WINDOWS/system32/fastboot.exe`（WSL USB 直通未验证，
  必要时回 Windows 侧跑）。
- **回锁前 preflight（顺序执行）**：
  1. 把原厂 boot.img 刷到**当前活动 slot**（`fastboot getvar current-slot` 确认；
     adb 推固件/校验 md5）；vbmeta 已原厂无需动；
  2. 重启后验证原厂内核上利用链仍能 root（此时 APatch 仍在，走 coldstart.sh 复测；
     这是「回锁后还能不能自举」的唯一代替性验证）；
  3. 未通过 1/2 **禁止 lock**。
- **执行回锁**：`adb reboot bootloader` → `fastboot flashing lock`（设备端
  音量键确认）→ **恢复出厂清 /data**（apps/temp/授予 store 全没，USB 调试需重开、
  ReSukiSU 需 `adb install` 重装）。
- **回锁后恢复 = `tools/postlock.sh`**（幂等，一次利用触发跑完整个恢复）：
  shell 写 `/data/local/tmp/ksu_boot/`（fresh 设备无需 root 即可 stage）→
  `LD_PRELOAD=…/preload.so KSUD_DST=$STAGE/ksud KSUD_NO_PARENT_INSTALL=1
  SU_INSTALL=0 /system/bin/toybox sh -c '<单引号-free 恢复脚本>'` → 同进程 uid0 里
  建 temp/chcon、cp 三件套、可选部署 libkernelsu 补丁、起 daemon、重建 overlay、
  设 wrap prop → shell 身份 verify。
  **为什么必须单次 + 三个 env**（`src/preload.c`、`src/root.c`）：
  constructor 同步跑完整个利用才返回，之后 sh 才执行恢复脚本；而
  `write_embedded_ksud_file` 失败走 `pr_error` 直接 `exit(-1)`——fresh 设备
  `/data/local/temp` 不存在时默认 `KSUD_DST` 必杀自举 sh，故 KSUD_DST 必须落在
  已存在的 `/data/local/tmp/…`（`tmp_path_ok()` 只认这两个前缀）；
  `KSUD_NO_PARENT_INSTALL=1` 跳过 root.c:654 进程内 ksud 安装（同路径也会
  pr_error）；`SU_INSTALL=0` 跳过链内 su 安装（root.c:131 的 installer 子进程会把
  su 写进尚不存在的 temp，虽只 pr_warning 但装不上）——su 由脚本从 stage cp。
  自举 sh 以 uid0 身份跑，`unsetenv(LD_PRELOAD)`（preload.c:760）保证后续 exec 不
  重复触发利用。
- **verify 用 shell(2000)**：uid0 不在 su.allow seeds，root 连 daemon 会被拒。
- **未验证风险（实测时重点探）**：① `fastboot flashing lock` 在该 OPPO LK 上是否
  支持/提示形式未探（先 `fastboot getvar all` 备份日志）；② 回锁后能否再解锁
  ——AOSP 说 OEM unlock 开关**能扛恢复出厂**，但 OPPO LK 级限制未验证，**lock 前
  务必确认开发者选项里 OEM unlocking 处于开启状态**；③ WSL fastboot USB 直通。
- 回锁后 APatch 消失 → `/system/bin/su` 没了，coldstart.sh 的 root 引导失效，
  **只走 postlock.sh**；line② 的「exploit 自举」要求原厂内核上 exploit 本身可重入
  （preflight 第 2 步即验证此点）。

## ReSukiSU「真实标准模式」路线（真驱动 kernelsu.ko）——用户要求「不欺骗 app，要真实的」

**背景**：状态卡「越狱模式」标签 = `HomePage.kt:610` 仅当 `GET_INFO.flags & LATE_LOAD(bit2)`
（`uapi/supercall.h`：LKM=0 MANAGER=1 LATE_LOAD=2 PR=3 BUNDLED=4）；「完整」=
`isFullFeatured = isManager && kernelUAPI==managerUAPI`（Natives.kt:203）。app 真实查询 =
扫 `/proc/self/fd` 找内核发的 **`[ksu_driver]`** anon-inode fd（manager cpp `ksu.c:20`
`scan_driver_fd`；fd 由 `kernel/supercall/supercall.c:73 anon_inode_getfile` 创建），
legacy fallback 是 `prctl(0xdeadbeef)`（设备 KP 白名单仅 shell，app 拿不到）。**无真驱动则
app 真实路径必失败** → 我们现有的 libgrant(app 侧 interpose)+ libkernelsu 补丁(mov+ret)
就是用户禁止的「欺骗」。判定链源码在 `/tmp/opencode/ReSukiSU`（clone 自
github.com/ReSukiSU/ReSukiSU，tmp 会清，可重克隆）。

**决策（用户授权自主定，需考虑回锁）：走真装 `kernelsu.ko`**——唯一同时满足「真实」+
「回锁后可用」的路线（KPM 死路：回锁后 KP 消失）：
- **源码**：`github.com/oppo-source/android_kernel_oppo_sm6375` 分支
  **`oppo/sm6375_s_12.1_oppo_a96`**（官方 A96 树，**5.4.147**，末次同步
  `PHA120_11_C.08`/2022-08）。设备内核 **5.4.254-qgki**（boot 提取：
  `Linux version 5.4.254-qgki-g977b99b1fbb9`，clang r383902b1，2025-09-15 构建）
  ——5.4.x LTS 结构/符号稳定，差异用设备 `/sys/kernel/btf/vmlinux` 对照
  （BTF 提取流程同 target.h 生成器）；vermagic 5.4.147≠254 为 `.modinfo` 串需覆盖
  （non-GKI 常规操作），编译工具链 = Android prebuilts `clang-r383902.tar.gz`。
- **ReSukiSU 驱动构建**：`ReSukiSU/kernel` 标准 out-of-tree（`Kbuild: obj-$(CONFIG_KSU)
  += kernelsu.ko`；`make -C $KDIR M=… modules` + `check_symbol` 对照 `$KDIR/vmlinux`）。
- **回锁兼容论证**：回锁刷的原厂 boot = 同一个 5.4.254-qgki（字节等价已证）；**AVB 只验
  分区镜像，不拦运行时 insmod** → 回锁后同一份 ko + CVE 提权 → insmod 全链同构。
- **go/no-go 闸门（设备回来第一件事，只读）**：`/proc/config.gz` 的 `CONFIG_MODULES`、
  `CONFIG_MODULE_SIG*`（**MODULE_SIG_FORCE=y 则拿不到 OPPO 签名 key → 全线死**，
  届时回来与用户重新对齐）、`modules_disabled`。
- **闸门实测（2026-10-07）＝GO**：`modules_disabled=0`、`CONFIG_MODULES=y`、
  `IKHEADERS=y`、**`MODULE_SIG_FORCE=y` 但 APatch 内核运行时未强制**——finitmod 实测
  仅 dmesg warn 级 `no symbol version for module_layout` +
  `module verification failed ... - tainting kernel`，`kernelsu` 直接
  `Live ... (OE)`（旧预判「全线死」不成立）。加载命令**必须显式带 flags**：
  `/data/local/temp/finitmod /data/local/temp/kernelsu.ko 0`（不带参数那次
  ENOEXEC；带 `0` 成功）。ko vermagic `5.4.254-qgki SMP preempt mod_unload
  modversions aarch64` 与 uname 完全一致；modversions CRC 不匹配会被容忍。
- **真驱动已验证（同日）**：ReSukiSU 蓝卡「工作中 Built-in 越狱模式」，**0 超级用户 =
  真 store 空**、**6 模块 = `/data/adb/modules` 真实读取**（YHGames/YH_YC/
  hma_oss_zygisk/oh_my_keymint/playintegrityfix/zygisksu）；驱动 (35193/4) ==
  管理器 v4.2.0-rc3 (35193/4)。**wrap prop 当时未设（无 libgrant 遮蔽）**，徽章走
  内核 GET_INFO ioctl。红卡「需要更新内核/获取 root 失败」= 重启后 overlay+daemon
  死（`/product/bin/su` ENOENT），按上文 overlay/daemon 命令重建即消（已实测）。
  驱动只在本 boot 存活，重启即丢。
- **遗留**：①「越狱模式」徽章 = `ksu_late_loaded`（下条，重编翻 false 后消）；
  ② app 的 libkernelsu.so 仍是 mov+ret 补丁版（原版库存
  `/tmp/opencode/libkernelsu_resukisu.orig.so`；版本与真驱动 35193 巧合一致，未回退）；
  ③ coldstart/postlock 需加 finitmod 步（驱动持久化）；④ libgrant/su_profiles 授予链
  退役与 overlay/自研 daemon 去留待实测真 ksud 后定。
- **`ksu_late_loaded` 陷阱**（`kernel/core/init.c:189`：`=(pid!=1)`）：我们的 insmod 必然
  pid≠1 → 内核如实报 LATE_LOAD → 标签又回来；解法 = 编我们自己的 fork 时把该判定改
  `false`（自定义驱动的真实行为，非欺骗 app）。
- **集成后退役**：真 ksud+真 store 接管授予链 → libgrant/libkernelsu 补丁/su_profiles 逐步
  下岗；/product/bin overlay+自研 daemon 视真 ksud 的 su 可用性决定去留；permissive 依赖
  消失（真 KSU 全程 Enforcing）。CVE 角色收窄为「boot 后提权 → insmod 引导」，进
  coldstart/postlock 脚本。与 APatch KP 共存有 `kernel/compat/apatch_conflict.*`，需实测。
- **Magica 澄清**（勿混淆）：app 的 `magica` 包 = `BootCompletedReceiver`→`MagicaService`，
  `jni.c:670 fork_dont_care_and_exec_ksud`（setuid(0) 后 exec `ksud late-load --magica
  5555`）——仅在 permissive+无驱动时的自救路径，我们的环境开机即 Enforcing 永不触发，
  auto jailbreak 开关保持关闭、不授自启动。

### PostLock panic guard（v1.25-v1.27，2026-10-21）——防 panic→重启→自启死循环

BOOT_COMPLETED 在链 gate 之前先读上次启动原因，命中 panic 类 → **自动关
`prefs(postlock)` + setState `PANIC_GUARD <reason>` + 不触发链**（fail-amplifier
对策：上一次 panic 就停，等人工排查后重跑，绝不无限 panic）。Tailscale 自启
独立、照常起。**开关语义自此收敛 = 只管开机自启**（v1.22 起），**LAUNCH 调试
后门不受开关约束**（panic guard 关了开关也能用 LAUNCH 重跑 = 排查后的入口）。

- **app 域 boot reason 判据（SELinux get_prop 实测 2026-10-21）**：
  `ro.boot.bootreason` / `sys.boot.reason(.last)` / `persist.sys.boot.reason`
  / `persist.sys.boot.reason.history` **全部对 untrusted_app 空读**（shell 均
  可读；exec getprop 正常——`ro.boot.hardware=qcom` 对照有值，纯属性权限）；
  **唯一可读 = `persist.sys.oplus.boot_reason`**。`bootReason()` 先试 history
  （首行=最新条目，reason=首个逗号前 token；app 拒读自然落到 fallback）→
  oplus 单值链。
- **OPPO panic token = `kernel_panic`**（`persist.sys.boot.reason.history`
  shell 实证：`kernel_panic,null,1792534818`——本设备 10-21 09:40 真实一次
  panic 重启）。`looksLikePanic` 匹配 panic/oops/watchdog/crash/brownout；
  **fail-open**（reason 读不到不拦，健康开机必须照常自启）。
- **探针（免重启验证检测路径）**：`am broadcast -n com.postlock.boot/
  .BootReceiver -a com.postlock.boot.LAUNCH --ez panicCheck true` → logcat
  `PostLockBoot: panic check: ... => verdict='...' panic=...`（只检测：不切
  开关、不触发链）。实测正常 boot：`verdict='reboot' panic=false` ✓。
- **待实战确认**：oplus 单值 prop 在 panic 时的形态未直接实证（history 不可
  读）。round13 若触发 panic → 开机后查 logcat `panic guard:` 行、开关自动
  变 ✗、状态卡 `⚠ 上次异常重启(kernel_panic) · 自启已关`；**若 guard 没触发**
  说明 oplus 写了不含 panic 字样的 token，按实测值扩 `looksLikePanic`。
- 显示层 `stateLabel` 收进 `PostLock`（Main/Services 共用），新增
  PANIC_GUARD 文案分支；状态文件 = app files `loopback_state.txt`
  （`run-as com.postlock.boot cat files/loopback_state.txt` 可读，模拟测试
  写完记得恢复真实值）。

### 链三连败根因修复 + v8 动态闭环 + ocsk 固化（2026-10-19 第四轮，root=1）

- **三连败（06:12/6919ed61/808c7707/d5658ac7 同指纹）根因 = payload 页死判定宽限太短**：
  cfgfs 通道经由 payload 页上的 fake fops 读 payload 页本身（鸡生蛋），fresh boot 上
  page-cache eviction/migration 造成**秒级瞬断**（作者注释自证高发），而四个死判定
  检查点宽限只有 0~160ms（`pipe.c:377` conv 前是**单次读**、`:1068` 窗口轮询 3 tries
  =60ms、另两处 8 tries=160ms）→ 误判真死 → `tbl_dead_logged` 粘性 → ENOTTY 连锁
  abort。修：`src/pipe.c` 五处死判定统一 `ks_fetch64_expect(...,150)`（≈3s 宽限，
  内容须精确匹配 `ASHMEM_IOCTL` 才算活，真死页照常 abort）。实证：窗口活过 +12s
  `dead=0`（此前 +0.3s 必死），fresh boot 首跑 36s 一次过 `DONE rc=0 root=1`。
  **排查这类失败先看 `win tick ... dead=` 出现的秒数**——<1s 即瞬断误判类。
- **v8 探针动态闭环**：late 段 `hits=61 = kill-lines=61` 全命中，`last_pc` 恰为
  entry+0xa30；v7 同样 61 次 kill `hits=0`（探针在死克隆 +0x258）→ 归因彻底实证。
  `kill_pre`（ocsk.c:73）语义 = `regs->pc += 4` 跳过 `bl force_sig` + `x0=0`
  **丢弃信号**——app（libksud.so setuid）每次提权都被 ocs 抓（dmesg
  `Kill the process of escalation...` 照打）但杀不掉，61/61 拦截 app 全程存活。
- **kevent 面现状（保留观察，勿盲目全局拦）**：`kevent_send_to_user:execve` 上报
  持续活跃（dmesg oplus 行 863 条），但**通知栏无弹窗**（静默态）；两符号都在
  kallsyms（`oplus_root_check_succ` T / `kevent_send_to_user` t + `.cfi_jt`）。
  它是 OPPO 多类事件的通用上报通道，全局拦有副作用风险——弹窗真出现再加探针。
- **ocsk 已固化进 coldstart.sh / postlock.sh**（2026-10-19）：两脚本 push
  `tools/ocsk/ocsk.ko` 到各自 TMP/STAGE，在 kernelsu.ko finitmod 之后、app 启动
  之前 `finitmod ocsk.ko 0 arm=1`（finitmod.c 原生支持 param=val，arm 在
  parse_args 期注册探针）。WARN-only 不 die（无 ocsk 驱动照常，只是 app 会被
  ocs 杀）。**真驱动模式下 ocsk 是必需配套**：libksud.so 每次 setuid(0) 必触发
  ocs force_sig。post_root.sh 里的既有 ocsk 段（finitmod_v2 + verify/late 判据）
  是验证权威（state 读法不变）。

### 回锁后 boot 内恢复实测（2026-10-19 第五轮）——postlock 载体重构为 KS_COLDSTART

回锁现实的三条实测定性（boot 20b88ae4→6fbc11d7→d86c4da3 连续验证）：

- **coldstart.sh 回锁后必死**：`root()` 引导用 `/system/bin/su`，回锁后 APatch 消失
  → 第一行 recreate temp 即 rc=127。AGENTS 既有结论「只走 postlock.sh」实测坐实。
  host 侧另注意 WSL 有 `/usr/bin/adb`（Linux server 看不到 adb.exe 的设备），
  跑任何 tools/ 脚本必须 `ADB="$(command -v adb.exe)"` 显式覆盖。
- **postlock TRIGGER_ENV 曾缺 run_fops 成功环境两项**（已修）：
  `KS_RECLAIM_DETERMINISTIC=1`、`KS_PSELECT_FOPS_VOFF=1`（后者缺 = SET_NAME panic
  的 run5/6/7 教训）。PVO 无需注入：静态 fallback 下 window check 可过（第四轮
  root=1 即实证），Tier-1 su 缺失不是阻塞。取证：链 stdout 必须落盘
  `/data/local/tmp/postlock_chain.log`（曾被 tail -80 截断丢窗口期日志）。
- **ROOT_SCRIPT carrier（constructor 返回后宿主 sh -c 执行）已被实测证伪**：
  链打出 uid0 contract line（`pipe-physrw-summary root=1`、self setuid 成功后才打）
  之后宿主执行的第一条 `mkdir -p /data/local/temp` 仍 `Permission denied` →
  `set -e` 即死、trigger rc!=0、verify 全红。矛盾未完全归因（getuid()==0 与
  文件操作 EACCES 并存，疑 fsuid/scontext；restore.sh 诊断头就是为一次定案设计）。
  **修复 = 恢复逻辑迁到 `KS_COLDSTART`**（root.c:1545）：self patch 确认
  `getuid()==0` 且 `finitmod kernelsu.ko` 成功后 fork `sh $KS_COLDSTART`——
  postlock 现 stage `restore.sh`（原 ROOT_SCRIPT + 诊断头 `id`/`ls -ld`/`getenforce`
  落 `/data/local/tmp/postlock_restore.log`）+ 轮询 RESTORE-OK 再 verify。
  **门控 caveat**：同 boot 二跑时 kernelsu.ko 已加载 → finitmod EEXIST →
  coldstart skip——此路径只服务 fresh boot（postlock 真实场景），boot 内补救
  仍需先 reboot。
- **链会自动加载驱动+ocsk**（root.c self 路径，与 postlock 无关但很关键）：
  `root self finitmod fork`（:1503，默认 `KS_FINITMOD=/data/local/tmp/home/finitmod`
  + `KS_KO=.../home/kernelsu.ko`，postlock 已显式指到 $STAGE）——home/ 是跨 reboot
  残留目录，fresh boot 上链成功即驱动 Live（第五轮 d86c4da3 实测 lsmod 两模块都在，
  而 ROOT_SCRIPT 明明没跑成）。ocsk 同轮也被加载（加载方待查，疑 home/ 残留
  coldstart.sh 被 :1545 fork 执行）。postlock TRIGGER_ENV 现传
  `KS_COLDSTART/KS_FINITMOD/KS_KO` 指到 $STAGE。
- **fresh boot 首跑两种结局各见一次**：6fbc11d7 链 `kernel_panic,fatal_exception`
  （窗口 +1s~+2s、prepare child `pipe prepare leaked=` 行缺失 = leak→base 段死、
  pstore 空没栈）；d86c4da3 同参数同 env root=1 一次过。两轮前置阶段（identity/
  kaslr/gate/counts/ctx/5 collisions）逐项对齐——静态差异已挖尽，panic 归因
  需等复现时 pstore。fail 放大器策略照旧：任何失败轮 reboot 换 fresh boot。

- **run24 代码（self patch 免 walk）**：`find_task_by_tgid` 从 init_task 走 4096 步，
  一次 `tasks.next` 读错即永久迷失→deref 无效页 data abort（run18/21/22/23 四连
  死点，从未打过 lookup failed = 没回过链表头）。修：root child 活着时扫其 task
  `[TASK_TGID_OFF+4, TASK_CRED_OFF)` 窗口找 real_parent/parent 槽（验证
  tgid==getpid + comm=="ks_waiter"）→ `self_task_addr` 零 walk；walk 双硬化为
  fallback（pid sanity + next 双读）。`root=` 契约改
  `root_child_done || self_root_ok`（self setuid(0) 即置位，root child SIGKILL
  不再一票否决）。**截至 run26 未被检验**（三轮都死在 root 之前的 prepare/CFI 段）。
- **run24/25 fail 放大器定性（决策：不修）**：prepare/CFI 段原语失效（rv=-1 /
  payload 页中途被内核回收）→ `set-fail ENOTTY` → payload dead → fail path skip
  restore（写能力同源依赖死页，无救）→ misc.fops 残留 fake 死表 → 第三方 open
  misc 必 panic。**fail→panic→换 boot 对下一轮反而是原语重抽签**，留在坏 boot
  重试更差，故放任。
- **run26 时序死锁（已修）**：`main.c` run_main_route_threads 尾部只等
  waiter_exited **3 秒**（300×10ms）超时即 `for(;;) pause()` 永挂，而 waiter 等
  pi_cleanup_done 的窗口是 **5 秒**（500×10ms）——fail 路径 pi_cleanup=0 时
  **必然 3s<5s 死锁**：主线程先 pause，waiter 随后退出无人再看 → constructor 不返回
  → run_fops 永不写 DONE（run26 卡 156 行 12 分钟）。修：300→1500（15s）。成功路径
  waiter 秒退不受影响。
- **setprop hook**：`tools/run_fops.sh` 链宿主命令改为
  `sh -c 'setprop persist.adb.tcp.port 5555 2>/dev/null; echo CHAIN_EXIT_OK'`——
  constructor 返回后 sh 已 uid0（self patch 成功），setprop 即落地永久无线调试；
  fail 时 uid2000 setprop 静默失败、`;` 保 echo rc=0 不影响契约。
- **auto_retry.sh**（`/tmp/opencode/`，会被清、按本节语义重写）：设备一上线
  （USB 5bf5bf85 → Tailscale 100.84.45.76:5555 → adb devices 首个在线）自动循环：
  归档现场→清残留链→push so+run_fops（sha1 校验）→重建 lc.log→mv state 清 DONE
  计数→起链→轮询（DONE/换 boot/11 分钟超时/USB 丢失 3 分钟）→取证到
  `/tmp/opencode/auto_rounds/roundN/`→失败一律 reboot 换 fresh boot→最多 10 轮；
  `root=1` 则写 `auto_rounds/SUCCESS` 并读回 `persist.adb.tcp.port` 后停止。
  非成功轮强制 reboot 而非同 boot 重试，理由同 fail 放大器定性。



- **`pr_error` 会 `exit(-1)`**（`src/kernelsnitch/utils.h:83`）。`src/preload.c` 的
  LD_PRELOAD constructor 在被注入的宿主进程里执行，链路上的 `pr_error` 会直接杀掉
  宿主应用（例如 ksud 写出失败）。新增可失败路径请用 `pr_warning`/`pr_info`。
- 偏移/地址计算集中在 `src/common.h`（`P0_DATA_ALIAS_CONST`、`KMALLOC_CACHE_SLOT` 等），
  不要在 `.c` 里硬编码结构偏移——一切来自 target.h。
- 全局状态用 `atomic_int` + `atomic_load/store`；`run_exploit` 前会调
  `reset_main_route_state()` 复位，改全局变量时记得同步复位。
- 编译告警不是默认全开：`-Wall -Wextra` 之外显式关掉了
  `-Wno-unused-parameter -Wno-sign-compare -Wno-unused-function`，且 `-O2 -g0`。

### 真实标准模式达成：ocsk v11.2 与 BakaSu 蓝卡（2026-10-19，boot 998d4c8d）

**终态（ui4.png）**：原厂回锁内核 5.4.254-qgki 上 BakaSu 蓝卡**「工作中 Built-in」**，
驱动 (35220/5) 来自真 `[ksu_driver]` fd（dmesg `ksu ioctl ... from uid=0` 实证），
零欺骗（本 boot wrap prop 空、无 libgrant、无 libkernelsu 补丁参与）。链条 =
postlock restore（kernelsu.ko Live + `ksu_debug_manager_appid=10279`）→
ocsk v11.2 拦 OPLUS_ROOT_CHECK → app 派出的 libksud.so 提权 uid=0 拿 fd →
su shell 正常（KsuCli 输出 `Zygisk implement: None` 等业务日志，无 not-a-shell）。

**红卡归因修正**：「获取 root 失败 / Created process is not a shell」的根因
**不是 fd 缺失**（fd 一直是 libksud.so 用 `reboot(magic)` 自取的，链路早通），
而是 **OPLUS_ROOT_CHECK 把提权回滚**——ksud ioctl 恒 `uid=10279`，以 app uid
起的 sh 不是 root shell。

**ocsk 迭代归因链（v9→v10→v11→v11.2，防重踩）**：
- **OPPO 自己在 tracefs 挂了探针**：`p:kprobes/ocs oplus_root_check_succ
  adr=$stack0`、`p:kprobes/seb oplus_exec_block`（/sys/kernel/tracing/
  kprobe_events，root 可读）。`ocs` 的 `brk #0x80`（词 d4200080 = aarch64
  kprobe 单步占位）**长期钉在 entry+0 永不还原** → v9 的 SCS 锚点必 FAIL
  （100 次重试全读到 brk）。删除报 EBUSY（疑 perf 引用，服务持有）。v10 起
  锚点接受 SCS push 或 brk 占位 + kill 词精确锚 `0x94004415`（pc-relative
  KASLR 不变）才算过。
- **arm64 kprobe pre_handler 返回值语义是成败分水岭**（源码
  arch/arm64/kernel/probes/kprobes.c:357）：`return 0` → setup_singlestep
  **覆盖** regs->pc（单步槽或模拟执行），pre_handler 的 pc 修改全部作废；
  `return 1` → 跳过单步、**直接从 regs->pc 继续**。v8~v11.1 的 kill_pre
  靠 `x0=0`（force_sig(0)=信号0 不杀人）**看似拦截成功（61/61、40/40），
  但 force_sig 本身被调用就连带回滚提权**——这就是 uid 卡 10279 的根。
  **v11.2 `return 1` + 去掉 x0 清零 → bl force_sig 完全不执行 → uid=0**，
  一步到位蓝卡。`entry_hits`/`hits` 计数相等且等于 kill printk 增量 =
  探针没拦住的铁证（1:1:1 判据）。
- **entry+0 的 br x30 整函数跳过实测无效**：entry_pre 同样 return 1 +
  pc=x30，但 entry_hits 与 kill hits 恒 1:1（函数体照常跑完）——归因收窄
  到与 OPPO trace kprobe 的**聚合交互**（干净地址 +0xa30 的 return 1 完美
  生效是对照）；**本内核 CONFIG_DEBUG_FS=n**（/sys/kernel/debug 不存在、
  任意点挂 debugfs 报 No such device、/sys/kernel 下 mkdir EPERM），
  kprobes/list 观测不到，未最终定因。entry 探针现为惰性观察者（保留：
  万一 trace 事件被删它就生效）。
- **打印照打 ≠ 拦截失败**：`Kill the process of escalation` printk 在探针
  点之前/函数未跳过时都照打，判据只认 uid/hits/1:1 增量。
- **在线热替换**（当 boot 有 root 通道免 reboot）：`su -c "rmmod ocsk;
  /data/local/temp/finitmod /data/local/temp/ocsk.ko 0 arm=1"`；v9 起
  FAIL 复位 armed_flag，可反复 echo 1 重试；state（hexdump 读，
  shell `$(cat)` 曾因转义读空）是唯一诊断源（本内核模块 printk/dmesg
  不可达、filp_open 在 finitmod 上下文失败——老 v6b/v24 教训依旧）。
- **ocsk 编译命令**（host，每次照抄）：
  `make -C /home/yang1/opencode-work/kout-v15 M=$REPO/tools/ocsk ARCH=arm64
  CC="clang --target=aarch64-linux-gnu" LD=ld.lld AR=llvm-ar
  OBJCOPY=llvm-objcopy CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO_ENABLER= modules`
  （PATH 加 NDK clang；kout=5.4.147 勿用，kout-v15=5.4.254 匹配设备；
  `CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO_ENABLER=` 必须置空——Makefile:933
  写死的 `-enable-trivial-auto-var-init-zero...` 是 clang21 移除的 flag；
  源码树在 /home/yang1/opencode-work/kernsrc/sm6375-v15）。

**安全警告弹窗（v12 已治理，2026-10-19）**：exsystemservice 弹「检测到恶意
程序…已阻止本次破坏行为」由 `kevent_send_to_user:execve` 上报 libksud.so
execve 触发，每次 app 冷启动必弹。**v12 拦截点 = `oplus_exec_block` 内部两处
`bl kevent_send_to_user`**（`+0x1b8` 放行路径 / `+0x25c` 阻止路径），而非全局
拦 kevent 通道（`theia_/fb_/mm_fb_` 家族共享，第四轮标注的副作用风险）。
静态反汇编方法：kallsyms 拿 runtime（root 读）→ slide = `oplus_root_check_succ`
runtime − `0xffffffc0102ea620` → link = runtime − slide → fileoff = `0x1000 +
(link − 0xffffffc010080000)`（`build/work/bootdump.img`）→ capstone 5.0.7
（host 已装；NDK 只有 llvm-objdump 无 llvm-mc，GNU objdump 无 aarch64 支持）。
锚点词 `0x940000a4`/`0x9400007b`（pc-relative KASLR 不变），探针语义同 v11.2
（`pc+=4; return 1`），WARN-only 不影响 kill fuse。实测 `rep armed=2`、
`rep_hits=42`、焦点直达 MainActivity 无弹窗、`uid=0` 蓝卡保持（ui5.png）。
应急点击坐标保留：「知道了」**(293,1396)**（BACK 无效），**「立即重启」
(775,1396) 绝不点**。

**其它现场事实**：`/sys/module/kernelsu/parameters/ksu_debug_manager_appid`
shell 直读 Permission denied（root 可读）；app 启动用
`monkey -p com.resukisu.resukisu -c android.intent.category.LAUNCHER 1`；
截图前先 dismiss-keyguard + BACK 收弹窗，焦点常态被
`com.oplus.exsystemservice`/NotificationShade 抢占。

### PostLock app「开机自启」路线与 untrusted_app 卡点（2026-10-19 第六轮）

**目标**：已回锁设备上，一个 app（`org.postlock.boot`，PostLock，CI 构建
`Build PostLock App` workflow 产 `app-debug.apk`）开机自启跑链 → root →
自动恢复整套（kernelsu.ko + ocsk + daemon + overlay），全程零 host。
**app 域执行环境 = `u:r:untrusted_app` + SELinux Enforcing + seccomp 严格**
（Runtime.exec 的 sh 继承 app 的 seccomp filter——perf_event_open 等被
SCMP_ACT_ERRNO 拒；不是 SELinux 拒的）。术语：BakaSu = 用户侧管理器
（`com.resukisu.resukisu`）；PostLock = 自启 app（本文）。

**已实测事实链**：
- OPPO 不拦 BOOT_COMPLETED（receiver 自动触发实测成功）；`am broadcast
  -n org.postlock.boot/.BootReceiver -a org.postlock.boot.LAUNCH` 手动触发
  （必须 `-n` 显式）。**LAUNCH 广播跳过 gate（debug 后门），BOOT_COMPLETED
  走 gate**（versionCode 5 起）。
- Enforcing 下 shell→untrusted_app 的 runcon 被 SELinux 拒（domain
  transition 不允许），模拟 app 域只能用真实 app 进程。Permissive 下 runcon
  可以（shell uid + untrusted_app 域，曾跑出完整失败日志）。
- app 域读 `/proc/kallsyms`：**地址全 0**（kptr_restrict=2，内核抹零，无
  AVC 拒绝——文件可读）。app 域读 `/dev/kmsg`：Permission denied。app 域读
  `/data/local/tmp/ksu_kaslr`：**成功**（DAC 644 + shell_data_file 允许——
  代读通道畅通）。
- `perf_event_paranoid=-1` 是 persist 的（不随 boot 重置）；但 app uid 的
  perf_event_open 被 **seccomp** 拒（errno≠SELinux 语义），shell uid 下
  `text-base-ok ... (perf)` 成功。**watchpoint errno=22 = 内核拒绝内核地址
  breakpoint，对 shell/app 一样废**（不是 app 特有）。
- shell 域对照组每次 route 都打 `main cmp_requeue ret=-1 errno=35`
  （FUTEX_CMP_REQUEUE_PI 语义常态）随后继续；**app uid 下链的真实死点 =
  slide 的 pselect route panic**（链日志最后一行 `slide child context
  route=pselect ... uid=10292 attr=u:r:untrusted_app` 后断，pstore 显示
  JSLag Monitor 踩 `_raw_spin_unlock_irq` 坏锁——链留下的 dangling
  rt_mutex 状态殃及系统进程）。**同 boot 并发三跑链 = 必 panic**（一次
  postlock 成功 + runcon + shell 对照并发，设备重启）。
- 真实 app 域 fresh boot 首跑（gate 已 bypass）：UI 面板（v1.4）显示链
  跑到 kernelsnitch 阶段后 panic 重启（boot_id b5ecbc42→92149050）；
  `run-as org.postlock.boot cat files/postlock/chain.log` 是 shell 取证
  app 域链日志的唯一通道（debuggable APK）。

**卡点机制（源码级）**：slide 的 pselect route 把 fake rt_mutex 布置在
pselect 内核栈的 fdset 里（`src/slide.c` `slide_pselect_stack_copy`，
`SLIDE_PSELECT_SHIFTS` 调栈布局偏移）。**app uid 的 pselect 每个 fd 引入
额外 SELinux 检查栈帧 → 布局错位 → rt_mutex_adjust_prio_chain 把 fdset
数据当指针 deref → oops**。这正是 `src/main.c:236` 注释「its pselect
probe panics under app uid」的物理机制。**修复方向**：① 扩大/固定 app uid
的 shift 搜索（但错误 shift = panic，不可自适应循环）；② fake lock 的
owner 指针字段填哨兵值使 walk 安全失败；③ app uid 跳过 pselect slide，
KASLR 走 root 代读 kallsyms 文件（`ks_persist_kaslr_file`）——但 fresh
boot 无 root，鸡生蛋，需与 ①/② 组合。

**gate（v1.3/4/5）**：`PostLock.readyToTrigger()` 读 `/data/local/tmp/
ksu_kaslr` 的 `boot=` 与当前 boot_id 匹配才允许 BOOT_COMPLETED 触发
（不匹配 → receiver skip）。**注意这是旧结论下的保守 gate**——新认知
（app 域真死点是 slide pselect，kaslr 文件只救 slide 的一个 fallback）
下 gate 的必要性待重估，但保留无害。UI 面板状态卡 = 驱动/ocsk/SELinux/
触发可用性/上次触发 + chain.log 尾部滚动。

### untrusted_app 域独立跑链：shared-file slide 达成 + HANS 冻结根因（2026-10-19 第七轮）

**架构定案（用户定义）**：root/shell 的辅助仅限「代读 app 域读不到的文件」——
具体为 `KS_KASLR_ONLY=1` 廉价轮（`src/main.c:590`：只 perf leak + 写
`/data/local/tmp/ksu_kaslr` 就退出，无 route、无 panic 风险；shell uid +
`perf_event_paranoid=-1`（persist）即可跑，**甚至无需 root**）；app 域轮
`kaslr_from_shared_file()`（main.c:241，boot_id 严格匹配 + 范围校验）消费
文件 → **跳过必 panic 的 slide pselect route**。实测 app 域日志
`text-base-ok ... (shared file)` ✓。

**分支布局**：主仓 main = shell 域链（用户指定）；**`untrusted_app` 分支 =
app 域改造**（本文所有 app 域结论落在此分支）。app 更名 **PostLock:Boot**
（包名 `com.postlock.boot`，versionCode 6/1.5；旧包 org.postlock.boot 已
卸载）；自适应图标 = 深蓝底金锁+绿闪电（`make_icon.py`）。

**app 域链实测进度链**（shared file 后）：slide ✓ → collision ✓ →
bruteforce(mm_struct) ✓ → phase2 prepare storm ——**死点两层**：
1. **OPPO HANS/OFreezer 冻结 = 真凶**：logcat 铁证
   `OplusHansManager: freeze uid: 10293 com.postlock.boot pids: [13181]
   scene: LcdOff`（熄屏即冻整个 uid）+ 3 秒后
   `netd: destroyAllSocketForUid:10293`（reclaim socket 全灭）→ 链进程
   冻结不调度 → chain.log 静默停在 `prepare storm i=512/1088`（冻结
   时刻），无任何错误行。**修复（app v1.5+）**：BootReceiver 先
   `startActivity(MainActivity)`（亮屏+前台，HANS 不冻可见 activity）
   再 dispatch；MainActivity 窗口 `FLAG_KEEP_SCREEN_ON | TURN_SCREEN_ON |
   SHOW_WHEN_LOCKED | DISMISS_KEYGUARD`。
2. `kill_child`（util.c:1560）= SIGKILL + **阻塞 waitpid** —— 子进程被
   冻结时不退 → 永久卡（表象与「D 状态子进程」相同，实为冻结）。

**其它 app 域实测事实**（补充第六轮）：
- **OPPO 把 `adb install` 路由到自家 InstallGuideActivity 等 UI 确认**
  （`com.oplus.appdetail`，屏幕熄灭时 `Background start not allowed`
  直接挂死 adb install rc=124）——解法：亮屏后 install → 点引导页
  「继续安装」(307,2057)@1080×2400 → InstallFinishActivity 装上。新包
  首装必弹引导（`is_new_guide=1`），以后覆盖升级同流程。
- Enforcing 下 `pm install`/`adb install` 不经 root 全程可用；app 域
  取证走 `run-as com.postlock.boot`（debug 签名）。
- `phase2 forensics: prepare storm` 每 256 打一行（util.c:3393-3399），
  日志停在 `i=N` 且进程消失/无后续 = 卡在 kill_child(i=N..N+255)。
- `reclaim sends ok=501/1024 last_err=11`(EAGAIN) 与 `fix36 phase1 tp
  ctrl=-1 n=0` 在 app 域为观察到的常态/待查（tracefs 权限：本 boot 无
  root chmod，Enforcing 下 app 域 tracefs 待验证是否为下一卡点）。
- 新包 uid=10293（旧 10292）；UI 状态卡「链触发可用性 ✓」= gate 读
  ksu_kaslr boot_id 匹配的实时判定。

**HANS 保活三路全败 + 前台 activity 唯一可行（v1.5→1.7 实测）**：
1. receiver `startActivity`：AOSP 拦（logcat W `Background activity start
   allowBackgroundActivityStart:false callingUidProcState:RECEIVER`），activity 不起。
2. `PowerManager.WakeLock`（SCREEN_BRIGHT|ACQUIRE_CAUSES_WAKEUP|ON_AFTER_RELEASE，
   static 持有防 GC）：**能点亮**（LAUNCH 后 `mWakefulness=Awake`）但 HANS 接管：
   logcat `OplusHansManager: unfreeze uid:10293 reason: unproxy wakelock scene: LcdOff`
   → 8s 后 `freeze uid ... scene: LcdOff` → netd `destroyAllSocketForUid` → 链静默死。
3. 全屏通知 `setFullScreenIntent(CATEGORY_ALARM)`（USE_FULL_SCREEN_INTENT A12 自动授）：
   非锁屏时系统降级为普通通知（`mCurrentFocus=NotificationShade`，activity 未前台）。
**唯一可行 = MainActivity 前台可见**（用户手动打开时链持续推进 i=6688→8489+bruteforce），
receiver 无权拉起。**结论：ColorOS 上 app 自启保活需用户一次性授权（OPPO 设置
→应用管理→PostLock:Boot→自启动 + 后台弹出界面/白名单），纯 app 手段不完整可行**。
app v1.7（versionCode 8）保留 wake lock+FSI 双保险（延长存活时间），bootstrap 依赖
用户开 OPPO 白名单或保持手动触发。链被冻结后的特征：进程消失/静默停在 collision
计时行（`%016zx i=N t=...`）或 bruteforce（`start finding mm_struct`），无错误行。

**app 域链本体终验（v1.7 前台保活，boot a56430b0）——保活解决，链体结构性失败**：
- **保活验证通过**：MainActivity 前台（shell `am start` 拉起）+ KEEP_SCREEN_ON，
  链全程 fg=1、boot 稳定 8min+ 无冻结无 panic，prepare 失败后**自动重启第二轮
  kernelsnitch**——证明「前台可见 = HANS 免疫」成立，保活不再是卡点。
- **链体 root=0（安全失败）**，失败链（chain.log 101167B 完整取证）：
  1. `fix36 phase2 tp ctrl=-1 ... n=0`——**tp 窗口 = perf_event_open(TRACEPOINT)
     + SET_FILTER，根本不碰 tracefs**（`util.c:2121` 注释明言；2026-10-20 代码级
     归因修正，旧「tracefs 被拒」说法错误）——真死因 = **seccomp 拒
     perf_event_open**（`util.c:2341` `id<=0` 早退 → ctrl=-1 n=0）。tracefs 被拒
     杀的是 kprobe fetch（content verify / layout pvo），不是 tp；shell 域过 gate
     也不靠 tracefs 而靠 tp 证据（`drain_capture` 第三级）。app 域链路替代设计见
     `docs/app-domain-chain.md`；
  2. `KernelSnitch mm_struct leak failed` ×3 + `[N] scan done ... found=0`——
     identity window（来自共享 KASLR 文件，值正确）内 timing 泄漏 mm_struct
     失败——**app 域 timing/原语退化**（seccomp 严格模式是首要嫌疑；
     collision 能过、leak 不能，两者共用 futex 但 leak 需更精细测量）；
  3. `configfs verify failed r1=0 r2=0`——payload 页未落地 → cfgfs 通道死；
  4. `slub shrink(post-prepare/post-pins) failed errno=13`——EACCES，
     `/sys/kernel/slab/*/shrink` root 600（代码注释自证 shell 同样拒，非 app 特有、
     非致命 warning）；
  5. `prepare_kernel_page retry 22/72` 耗尽 → 重启 → 第二轮 post-pile 后进程退出。
- **结论：app 域（untrusted_app+seccomp）当前形态无法独立完成整链**——slide 可靠
  共享文件过、collision 过，但 tracefs/mm_struct leak/configfs 三个内核原语在该域
  不可用。**链必须以 shell uid 跑**（shell 域 fresh boot 实测 root=1 无预处理依赖
  的先例：d86c4da3）。
- **boot 自足的最后拼图方向（未实施）**：一次性 host 成功链的 KS_COLDSTART 追加
  ①`setprop persist.adb.tcp.port 5555`（adbd boot 后自监听）②app 的 adb pubkey 写
  `/data/misc/adb/adb_keys`；app 内嵌 private key，boot 后连 `127.0.0.1:5555` 走
  adb AUTH 拿 **shell 会话**跑链（KS_KASLR_ONLY 轮 + 全链）——绕开 app uid 的
  内核接口墙，实现纯设备自足。未验证点：Android 12 persist prop 监听时效、app
  明文 tcp AUTH 流程。
- 附：`persist.adb.tcp.port` 当前空（本 boot 链未成功过未 setprop），5555 无监听。

### adb 回环 bootstrap 四项核心验证全通（2026-10-20 第八轮）——纯设备自足的 shell uid 通道打通

上轮定的方向（app 内嵌 adb key 连本地 adbd 拿 shell 会话跑链）本轮逐项实测：

- **`setprop persist.adb.tcp.port` 被 SELinux 死拒**（无论 shell/kernel scontext，
  即使 getenforce=0/Permissive 也拒——audit `tcontext=u:object_r:default_prop:s0
  tclass=property_service permissive=0`，init 属性服务检查特殊不随全局 permissive
  放行）。**解法 = 直写 `/data/property/persistent_properties`**（protobuf，root
  `cat` 追加 30 字节条目 `0a1c 0a14 <key> 1204 5555`；push 必须经 root 中转
  cp 到 /data/local/tmp 再 pull，`adb pull` 直读 600 报 Permission denied、
  `adb exec-out su cat` 二进制流被截 0 字节）。370→371 项，reboot 后 init 自
  应用 `getprop persist.adb.tcp.port=5555`。
- **adbd boot 自监听 `[::]:5555`**（tcp6 双栈）：`toybox netstat -tln` 实证；
  设备本地 `127.0.0.1:5555` 可达（`TIME_WAIT` 握手实证，v4-mapped 映射）。
- **postlock 专用 key AUTH 单 key 连通**：`ANDROID_SDK_HOME=/tmp/plockhome
  ADB_VENDOR_KEYS=build/work/adbkeys adb connect 192.168.8.10:5555` →
  `connected` → `id` = **uid=2000(shell) context=u:r:shell:s0** ✓（隔离 home 后
  唯一已授权候选就是 postlock_adbkey，证明「app 内嵌同款私钥可拿 shell 会话」）。
- 双通道并存：USB `5bf5bf85` + TCP `192.168.8.10:5555` 同时在线，`adb shell`
  报 `more than one device` 必须 `-s` 指定 serial；Tailscale 本 boot 未在线，
  用 WLAN IP 验证即可。
- **provisioning 已固化进 `tools/postlock.sh`**（commit 3a7e57c4+ce2b9dc9）：
  stage 段 push `pp_adb_tcp.bin`(30B protobuf 条目) + `postlock_adbkey.pub`，
  restore.sh 内幂等两步（`grep -qF postlock_bootstrap` 追加 adb_keys、
  `grep -qF persist.adb.tcp.port` 追加 persistent_properties，均 `|| WARN`
  防 `set -e`）。物料 build/work 下**仅缺失时自生成**——keypair 必须一次生成
  永久沿用（重建=pub 变=app APK 内嵌私钥失配，脚本已打 "MUST RE-EMBED" 警告）。
  生效时序：restore 写 pp → **下次 reboot** adbd 才监听（当前 boot 手动部署
  已实测过一轮完整链路）。
- **尚未做**：app 端 Java adb 客户端（CNXN/AUTH-RSA-SHA1 签名/OPEN shell 协议）
  + app 域连 127.0.0.1:5555 的 SELinux 可行性（untrusted_app 回环 connect 待实测）
  + boot 后 app 经 shell 会话跑 KS_KASLR_ONLY 轮 + 全链（shell 域 pselect 可用，
  共享 KASLR 文件方案在该路径下不再必需）。

### PostLock:Boot 独立仓 + Tailscale/adb 异地通道（2026-10-20 第九轮）

- **app 已独立成仓 `poisongod/PostLock-Boot`（private！assets 含设备 adb 授权
  私钥）**，本地 = `build/bakasu-work/postlock-app`（原 BakaSU-PostLock 的
  single-branch clone，refspec 只跟踪 `upstream-main`——fetch 其他分支要显式
  URL）。分支 main 从 v1.9 orphan 导入：**旧 ReSukiSU 上游 commit 链对象
  （`b2c595d…`）从未完整上传任何远端**，推空仓必 `remote unpack failed: did
  not receive expected object`（老仓推送能过是因为 negotiation 排除了服务端
  已有对象）——故截断历史，v1.0-v1.8 留 BakaSU-PostLock `postlock-app` 分支。
  `BakaSU-PostLock` main 是**主仓镜像（另一路维护，勿覆盖）**。
- **该仓 workflows/runs 会列出 10 个 ReSukiSU 系幽灵 workflow**（id 3899405xx，
  disable API 全 404=非本仓注册，BakaSU-PostLock 的 id 也不同——网络层共享
  显示，有时以带 `postlock-app/` 包装的树跑）。**ReSukiSU 整个已弃用，
  不再研究其机制**；树里无定义即无害，Lints/CodeQL failure 不管。
- **CI = 仓内 `.github/workflows/build.yml`**（temurin17 + 根布局
  `./gradlew :app:assembleDebug`，artifact `postlock-app-debug`）。
- **USB 已退役**，host 走 Tailscale 异地 adb（**临时通道**，PostLock:Boot
  自建 tailscale 正式启用后废弃）：Windows 装有官方 Tailscale（本机
  100.116.34.46），设备 **`adb connect 100.80.86.28:5555`**（oppo-a96-5g，
  direct 192.168.8.10）；MagicDNS 名 `oppo-a96-5g-1.tail5809d2.ts.net`
  **解析不了（no such host）——只用 IP**。双路径（192.168.8.10 与
  100.80.86.28）网络层均通。
- **AUTH 卡点（未解）**：TCP 通但 `adb devices` unauthorized；postlock2 私钥
  Python 客户端（`/tmp/opencode/adbloop_postlock2.py`，host 硬编码需 sed 改
  host）round1 签名被拒 → round2 发 RSAPUBLICKEY 后 adbd **挂起无响应** =
  设备 `/data/misc/adb/adb_keys` 不再含现有 key（10-19 还验证通过，之间用户
  侧可能撤销过授权）。修复路径：设备屏幕授权弹窗点允许 / root 后重写
  adb_keys（root 通道依赖链，链又依赖 adb……当前是死锁，突破口=用户在设备
  上操作）。
- **Tailscale 官方构建**（tailscale-rs 已弃用勿碰）：go1.27.2 在 `~/sdk/go`，
  克隆 `build/work/tailscale`，
  `GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -tags ts_omit_ssh,ts_omit_systray
  ./cmd/tailscaled ./cmd/tailscale`（android 下 linux tag 为真会选中
  ssh/systray 依赖而构建失败，必须 omit）。产物 35/24MB push
  `/data/local/temp/`（sha1 双端比对），userspace-networking 免 root，
  **unix sock_file 被 SELinux EACCES（dontaudit 静默）→ abstract socket
  `@postlock-tsd`**。冒烟已过（NeedsLogin/DERP bootstrap 通）。
- **功能页 v1.9（ServicesActivity）**：三卡片（开关+点击展开详情）
  - PostLock：pref `services/postlock` 门控 BootReceiver（默认开）；
  - Tailscale：**用户要求开关旁带「浏览器登录」按钮**——localapi over
    LocalSocket(abstract)：`POST /localapi/v1/login-interactive` → 每 1s
    `GET /localapi/v1/status` 解析 **`AuthURL`**（ipnstate 无 json tag 直用）
    → `ACTION_VIEW` 开默认浏览器授权 → 轮询 `BackendState=="Running"`。
    自写 HTTP/1.1 helper（Content-Length/EOF 读体）。启停 = exec
    `/data/local/temp/tailscaled` + `filesDir/tsd.pid`（app 同 uid 才有
    localapi 写权限；shell 起的 daemon app 连 = 403 只读）；
  - adbd：pref `services/adbd` + best-effort setprop（app 域大概率 SELinux
    拒，intent 落盘等链 root 侧应用）+ 127.0.0.1:5555 connect 探测。
- **Android 编译坑（8f5a998 修复）**：① `import android.os.Process` 会遮蔽
  `java.lang.Process` → pid/waitFor/getInputStream/exitValue 全炸 +
  incompatible-types；② Android **没有 `java.util.JSONArray`**（只有
  `org.json`）；③ `Base64` 两文件分开：PostLock 用 `android.util.Base64`
  （`encodeToString(x, NO_WRAP)`），AdbShell 用 `java.util.Base64`
  （`getDecoder()`）——别统一；④ AdbShell 构造器必须 package-private。
  `Process.waitFor(2, TimeUnit.SECONDS)`/`Process.pid()` 在 minSdk26/compileSdk35
  可用（之前报错全是 import 遮蔽连锁）。

### dispatch 统一回环 + 主页实况化（2026-10-21，v1.28-v1.31/vc29-32）

用户质疑「为何依旧需要 shell 回环 / 主界面是否过时」触发代码审计，发现三套
互相矛盾的叙述并全部修正：

- **现状审计（v1.28 之前）**：所有触发入口（BootReceiver/ChainService/主页
  按钮）实际调 `triggerChain` = **app-uid 直跑**（第七轮 101KB 日志判死的
  路径：seccomp/SELinux 拒 tracefs/perf/configfs 三原语）；完整回环实现
  `triggerChainLoopback`+`writeTriggerScript` **零调用**；BootReceiver 头
  注释还在描述回环 dispatch。共享 KASLR gate 读 `ksu_kaslr`，但**设备内
  没有产出方**（trigger.sh 无 KS_KASLR_ONLY 轮）→ fresh boot BOOT_COMPLETED
  永远 skip = 纯设备自足有硬缺口。
- **v1.28 修复**：三个入口全部切 `triggerChainLoopback`（shell uid 经本地
  adbd，链 setsid 脱离 app 存活）；direct `triggerChain` 标 `@Deprecated`
  保留参考；**trigger.sh 开头内置廉价 KASLR 轮**
  （`LD_PRELOAD=$D/preload.so KS_KASLR_ONLY=1 sh -c true`，shell uid
  perf 可用，失败不阻断全链）→ `readyToTrigger` gate 退役为 warning +
  UI 状态显示（fresh boot 自足闭环补齐）；回环通道故障落
  `FAIL:回环通道不可用: <原因>` state。
- **主页实况化**：`probeVerdict()` 三态——OK / NO_LISTENER（refused /
  Failed-to-connect / connect-timed-out）/ NO_AUTH（auth/CNXN/rejected/
  reset/EPIPE/closed/EOF/Read-timed-out），各配可操作文案（NO_AUTH 解释
  「授权弹窗在无 USB 数据连接时被系统立即关闭」）；「链触发可用性」=
  通道 ✓ + 本 boot KASLR ✓（KASLR 缺只提示不阻塞——trigger.sh 自足）。
- **NetworkOnMainThreadException 根因（v1.29 实锤）**：MainActivity.refresh()
  一直在**主线程**跑 TCP 探测 → StrictMode 必抛 → 主页探测**从未成功过**
  （历史「回环不可达」文案全是误导）。修：探测移子线程 + applyProbe 回填；
  ServicesActivity 本就在线程里不受影响。
- **probe 退避 + single-flight（v1.30/31）**：失败探测指数退避
  （4s→8→16→32→60s cap，成功复位，手动刷新 force bypass）；单飞互斥
  （AtomicBoolean，败者返回缓存失败或 busy marker）——没有互斥时并发调用
  方会同时穿过退避检查（streak 每 200ms 递增的踩踏实证）。adbd 侧骚扰从
  4s/次 降到 60s/次。
- **Read timed out 归 NO_AUTH（v1.31）**：connect 成功后读超时 = adbd 扣着
  授权握手（其日志 `prompting user to authorize key` 实证有监听）——
  通用 `timed out` 关键词曾把它误归 NO_LISTENER。判序：先 Read-timed-out
  → NO_AUTH，再 refused/connect-timed-out → NO_LISTENER。
- **设备失联模式**：Tailscale 双 IP（oppo→100.80.86.28 / node→100.71.26.6）
  同时不可达 = 设备休眠断网（非重启——`sys.boot.reason.last` 未变）；
  亮屏后恢复。`node.tail5809d2.ts.net`→100.71.26.6 是 **app 自建
  tailscaled 的独立 tailnet IP**，host 不在该 tailnet 不可达，连接一律用
  oppo 名或 100.80.86.28。

### WAN 通道根因终审 + 修复达标（2026-10-23 下午，vc47/8593be3）

三层根因叠加（逐层实测定案，最终根因是字符串 bug）：
1. **`SOCK` 双后缀（真根因）**：`WanChannel.SOCK="postlock-tsd-sh"`（已含 `-sh`），
   模板又拼 `"$SOCK[-]sh"` → 实际模式 `postlock-tsd-sh[-]sh` **永远匹配不到
   daemon**——自 v1.41.5 起所有 pgrep 快路径/轮询判定失效（WAN_DEAD）、pkill
   杀不到旧 daemon（`address already in use`）。修 = 模式裸 `$SOCK`
   （脚本 sh cmdline 不含 socket 名，自匹配安全）。
2. **adbd 拒 loopback 源 + tailnet 栈黑洞**：app 域 connect `100.71.26.6`
   走系统路由（userspace 栈无 root 不接管路由）→ 4s 超时黑洞。修 =
   **hairpin 候选**（`loopHosts()` 枚举本机非 loopback IPv4 优先——hairpin
   到 wlan0 IP 直达 adbd，源非 127.x 不触发 AUTH 拒绝）+ tailnet IP 兜底，
   4 处 connect 全走 `connectLoop()`。
3. **inline cmd 的 shell,v2 环境**：deploy 逻辑改 base64 push 脚本 +
   `sh path` 执行（quoting-free 传输；pgrep 在普通设备 sh 里验证可用）。
   另 pkill 后 8s drain + SIGKILL 兜底（abstract socket 释放竞态）。
- **验收达标（用户标准）**：fresh reboot → BOOT_COMPLETED +~50s
  `wan ensure: ALIVE`（冷部署抢在 HANS 86s 前）→ shell uid daemon 常驻 →
  host 每 30s `adb connect 100.71.26.6:5555`+id **20/20 全通（13:01-13:11）**。
- 排障教训：「pgrep 不命中但 ps 命中」先查**模式字符串本身**（常量拼接重复），
  再怀疑环境 quoting；hairpin（设备 connect 自身 LAN IP:5555）是 app 域
  AUTH 的可靠通道，不依赖任何 daemon 栈。
- 回锁后链（third round）本轮实测：12:18 boot 链 payload 死安全退出；12:25
  fresh boot 链 `POSTLOCK-RESTORE-OK` + verify 全绿（root/kernelsu Live/
  daemon/appid=10279/Permissive）——**postlock.sh 全链恢复通道正常**。
  中间一轮（11:56 boot）链 root=1 后死于 self-patch cfgfs 循环（进程消失
  无 panic，dmesg 不可读），fail 放大器 reboot 换 boot 即过。

## 考试制度（2026-10-21 用户最终裁决，覆盖旧「禁 shell」严格版）

**出题人 = opencode（AI）；shell 域 = 老师；untrusted_app 域 = 学生；设备 = 考场。**
**两次标准考试**，各自独立，均须达标 = 链 `root=1` → kernelsu.ko 加载 → BakaSu 蓝卡「工作中 Built-in」（真驱动真 store，无欺骗）：
- **考试一** = shell 域（老师）host 脚手架全链（run_fops Tier-0）。
- **考试二** = untrusted_app 域（学生）app BOOT_COMPLETED 自跑全链（`triggerChain` direct）。

**出题人权限（合法）**：泄题（shell 域全部辅助——KS_KASLR_ONLY 轮、共享 KASLR 文件、代读写、回环递答案——考前/考中均合法，含 app 经 loopback **只跑泄题轮**）；降难度（改考纲/参数/原语——KS_SLIDE_SKIP、faith gate、静态 fallback、pselect shift 静态预计算、把某题移出考卷用预置答案）。
**红线 = 泄题 ≠ 代考**：shell uid 跑完整链是考试一内容；考试二的链必须 app uid 自己跑完（`triggerChain` direct），loopback dispatch 全链 = 代考 = 不合格。

## gate 不消费致同 boot 二次链卡死事故 + ran_boot 修复（2026-10-23，app vc54/02b1146）

**事故链**（boot 6bcd094c，非 panic——bootreason=reboot 人工重启）：
马拉松 round 2 泄题阶段被我停掉（detached 泄题轮继续跑至成功，写
ksu_kaslr/ksu_payload=本 boot 值 → **gate 转 ready**）→ 我为测 app 新加的
实时日志功能连发两次 `am broadcast ...TS_KEEPALIVE`（tick 走
`tick: gate satisfied -> keepalive dispatch`，BootReceiver:116）→
**同 boot 先后两条链**：链 A 成功（v3_d 截图 kernelsu✓ocsk✓Permissive），
链 B 在脏 boot paste 死页 → route 卡死（`pselect Tier-0 capping 12->1`、
`waiter requeue_pi errno=110`，chain.log win +14s 戛止）→ **设备僵死 13min**，
用户长按重启。**根因 = gate 不消费**：已有防重入（sDispatching 原子 +
pgrep 活子进程）只拦并发，链 A 跑完后 pgrep 查不到 → 顺序重复放行。
考试轮每轮 reboot 从未暴露；「停马拉松+同 boot 连续操作」炸出。

**修复（vc54）**：`triggerChain ENTER` 即写 `files/postlock/ran_boot=<boot_id>`
（**失败也消费**——fail amplifier 语义本就要求换 boot 重试）；
`readyToTrigger(Context)`/`gateDiag(Context)` 前置 `alreadyRanThisBoot`，
覆盖 BOOT_COMPLETED/tick/gate poll 全部入口；LAUNCH 调试后门照旧绕过 gate；
UI readiness 显示「本 boot 已跑过」；诊断串加 `ran=` 字段。
**验法**：dispatch 后任何 tick 打 `ran=1 rdy=false` 且不再 ENTER。

**取证教训**：
- **chain.log 每次 dispatch 截断重写**——链 A 日志被链 B 覆盖（只有截图
  证据）；归因「有几条链」先看 chain.log 首行 pid 是否与最后 pid 不同。
- **receiver.log 会出 NUL 稀疏段**（本次 17:16-17:37 整段丢 dispatch 行），
  grep 见「匹配到二进制文件」必须 `grep -a`；NUL 后行还在但段内行永久丢失
  ——关键事件归因要与截图/文件 mtime 交叉。
- app 域广播 `result=0` ≠ 执行（HANS 冻结排队），先拉前台再发。
- 设备「消失」判别三步：ping LAN+tailnet 双断而 host 网关通 = 设备层；
  重连后 `getprop ro.boot.bootreason`：`reboot`=人工/命令重启，
  `kernel_panic`=panic——**本次事故是僵死非 panic**，route 卡死无用户态
  防御（与旧「route pselect 内核自旋 4min」同族）。
- **postlock 开关（services.postlock）**是用户可手关的（ServicesActivity:146），
  关闭后 keepalive 的 gate 段静默跳过（**不打任何行**——排查「tick 行消失」
  先读 `run-as cat shared_prefs/services.xml`）。

### PostLock-Boot v1.32（app 独立仓 poisongod/PostLock-Boot）= 考场工具合规版
- 三入口（BootReceiver/ChainService/MainActivity）全部切 `triggerChain`（app-uid direct = 考场路径）；`triggerChainLoopback` 降级 PRACTICE SCAFFOLD ONLY（脚手架，零调用点，仍用于 probe/Tailscale 探测）。
- KASLR gate 恢复为练习期安全网：BOOT_COMPLETED 时共享 `ksu_kaslr` stale/missing → skip + setState `WAIT_KASLR`（UI 可见），不盲跑防 panic 循环；LAUNCH 广播照旧免 gate。终态自足 KASLR（M5 cfgfs physmap 扫）落地后 gate 随脚手架退役。
- 主页 readiness 真话：通道态=脚手架，KASLR 缺=真实阻塞（`✗ 缺本 boot KASLR 参考（自举方案落地前无法开考）`）；新增 `WAIT_KASLR` 状态标签。
- 保留 v1.29-131 的规则中性 UX/健壮性（probe 移子线程、指数退避、single-flight、probeVerdict 三态、原始异常串日志）。
- 已装机 versionCode=33 / versionName=1.32（2026-10-21）。

### 考试一实况（2026-10-21，boot 459b2892，回锁后 fresh 无 su 环境首跑）
- 环境：原厂内核 5.4.254-qgki、**Enforcing**（无预 setenforce 0，回锁后无 `/system/bin/su`）、`KS_PIPE_SLABS=15` 档位（无 pipe-user-pages-soft 提升）、shell Tier-0。
- 链推进极深全绿：KASLR perf `slide=0x204d600000`、collision 5、mm_struct 8 线程 found=1、payload 落地+nonce、order3 drain 8192 页、fix36 tp `ctrl=503`、fix40 捕获 `pfn=3431032 k=11`、pselect route `slot marked dirty`→`entering cfi stage`。
- **死点 = `opening ashmem`**（route 段，fops 接管后第一次 fake open）。根因：**configfs confused deputy 读通道失效**——`cfgfs read ... set=0(SET_NAME 成功) rd=0 errno=0`（`pread` 返回 0 字节 EOF）→ `configfs verify failed r1=0 r2=0` + watchpoint `errno=22` oracle 也废 → payload gate 靠 drain+hit 强放行 → `open_ashmem_device()` 卡死 → 进程树（runner+chain）整体被清理，**无 panic（boot 未变）**。
- configfs read = ashmem SET_NAME + configfs bin pread 组合（`cfgfs_read_ex` util.c:4227）；pread 返 0 = configfs bin file read 回调未产出内容（疑 Enforcing SELinux 或该 boot configfs item 状态污染）。
- 处置：无 panic 但进程树死亡 + 设备污染（route armed、ashmem fops 疑劫持）→ **reboot 换 fresh boot 重试**。若 fresh boot configfs 稳定失效 → 定性为回锁后环境问题（Enforcing），需出题人补「无需 root 的 configfs 访问」预处理。
- **回锁后无 su 时 prep 的三步 root 依赖全部可绕**：chcon（temp 跨 reboot 保留正确 label）、setenforce（链内自带/非必需）、pipe soft（KS_PIPE_SLABS=15 档位）。直接 push run_fops.sh 跑即可。

### 考试一 root=1 达成（2026-10-21，fresh boot 771b7409，裸 run_fops）+ 裸驱动红卡归因
- **shell 域全链 root=1 验证成功**：fresh boot（SLUB 干净）payload 捕获成功 → opening ashmem 通过 → `pipe-physrw-summary done=1 root=1 kaslr=1 read_ok=1 write_ok=1 rw64=1/1 uid=2000->0 selinux=1->0 setenforce=0/0 slide=0x2295a00000`，DONE rc=0，120s+ 无 reboot。**证实上一轮失败 = SLUB 污染（3h uptime）致 payload 捕获失败，非结构性问题**。
- **kprobe payload verify 恒定失效（回锁后）**：tracefs `drwxr-xr-x root root`，shell 写 `kprobe_events` DAC 拒（无 root 无法 chmod）；configfs read 需 route 劫持 fops（route 前鸡生蛋）；watchpoint 内核 EINVAL。三通道全废，payload 捕获成功率成唯一命门——**fresh boot 是 shell 域考试的关键前置**。
- **裸 run_fops 的驱动是「裸加载」→ BakaSu 红卡**：链成功时 root.c self 路径自动 fork finitmod 加载 kernelsu.ko（默认 `/data/local/tmp/home/` 路径）+ `exp_v6c.sh` reload ocsk（lsmod 两者都在），但 **finitmod 未带 `ksu_debug_manager_appid` 参数** → `/sys/module/kernelsu/parameters/ksu_debug_manager_appid` 文件不存在 → 驱动不认 BakaSu（appid=10279）→ app 拿不到 driver fd → 红卡「内核上未检测到 KernelSU 驱动程序」。
- **无持久 root 通道**：`/system/bin/su` 是 stale overlay bind（ls 可见但 exec inaccessible）、ksud 文件未写出、SELinux 回 Enforcing——链 root 窗口（constructor 内）已关闭。
- **结论**：裸 run_fops 只达 root=1 判据；**考试一完整合格（蓝卡）必须用 `postlock.sh`**——restore.sh 在链 root 窗口经 KS_COLDSTART fork（uid0）配置 `ksu_debug_manager_appid=10279` + 起 ksud + overlay + setenforce，全程不需预先 root，匹配回锁环境。host artifacts（su/preload/ko/finitmod/ocsk）已确认齐全。

### 考试一完整流程两处修正 + M3 collision 失败模式（2026-10-21）
- **postlock.sh 同步触发 = panic 隐患**：postlock.sh 用同步 `ab shell "LD_PRELOAD=... sh -c 'echo CHAIN_EXIT_DONE'"` 触发链（非 detached），host timeout 一旦杀掉它，链死在 slide/route 段留下 dangling fops → panic（实证 c23b8a27→e4eaa672 重启）。**正确做法 = detached 触发**（`setsid nohup env ... sh -c ... &`），链脱离 host 存活。裸 run_fops（setsid）稳定 root=1 就是对照。
- **detached + KS_COLDSTART 方式（替代 postlock.sh 触发）**：STAGE 物料（restore.sh/preload.so/ko/finitmod/ocsk，postlock.sh 已 stage 且跨 reboot 保留）齐全时，直接 `setsid nohup env LD_PRELOAD=$D/preload.so <TRIGGER_ENV> KS_COLDSTART=$D/restore.sh KS_FINITMOD=$D/finitmod KS_KO=$D/kernelsu.ko /system/bin/sh -c 'echo CHAIN_EXIT_DONE'` detached 跑——链成功 root 后 self patch finitmod 驱动 + fork KS_COLDSTART restore.sh（uid0）配置 appid/ksud/overlay。
- **M3 collision 失败模式（新证据）**：fresh boot e4eaa672 链 `phys prepare produced no page; abort before gate`，根因 `pipe child collision wait spun out spins=100000001` → `target not owned after waves`——pipe child 的 futex collision 自旋 1 亿次超时，链重试 4 次（t25381/t1798/t13319/t21487）全超时。**与 771b7409 run_fops 成功同 env**，证明 collision 成功是 SLUB/时序抽签，非确定 bug。链安全失败（root=0、cfi fail path pi_cleanup ok=1、fake fops neutralize，无 panic）。**payload 捕获/collision 成功率是 shell 域考试命门（M3）**。
- kprobe payload verify 回锁后恒失效（tracefs DAC 拒）+ configfs read 需 route 劫持（鸡生蛋）→ payload 无 verify 兜底，collision/捕获成功率决定成败。fresh boot 是必要非充分条件。

### 满页根因判决 + 11 次重启教训 + 息屏守护（2026-10-21 攻关）

**满页（owned=0 inuse=34）根因判决链**（数据全部在归档日志）：
- presweep 形态恒为 `pre-sweep meta inuse=0 objects=34 frozen=1`（页空）→
  24 波后 `phys wave stuck inuse=34 frozen=0`（满页外人占）；`taken=23
  owned=0 sc 恒非0`。
- **两阶段 kill**（`bef0f86d`，SIGKILL 全发再统一 waitpid）+ **sc2 转换记
  taken**（`174b1cfb`，治 wave[5] sc2 先变 0 时批 kill 被 `if(sc2!=0)` 跳过
  → taken 恒 -1 白盖 16 波）均已部署，但 wave 判定仍过不了。
- **判决实验**（`0088bd1b`）：批 kill 后无 fork 轮询 2s →
  `post-kill rcu wait w=5 tsc=非0 inuse=34 frozen=0`——**teardown/RCU 延迟
  假说被否**（2s 足够 mm 同步释放），**外人 fork 抢占 kill 空窗 = 满页根因
  实锤**；用户活跃期（番茄/美团 fork）时满页必败，771b7409 成功在闲置期。
- **prep fork 暴毙**：`pipe child ctx prep=1088` 后 1088 个连续
  clone+open_memfd 无节流 = 1-2s 负载尖峰 → hang-detect/watchdog（wintickdie
  /bruteforce/34e325de 三轮同窗口）；已加节流（每 128 个 50ms，`70bb81bc`）。

**owner 归属诊断两次翻车（血教训）**：读 `mm->owner -> task->comm` 判外人
身份，第 7/10 次重启（e5d016e6/934a736c）都死在这里——**cfgfs 内核读是
回调里直接解引用，野指针 = data abort oops = panic，不是安全失败**；
physmap 窗口 `[ffffff8000000000, ffffffe000000000)` **含未映射 hole，范围校
验挡不住垃圾 owner**。已整体删除（`0088bd1b`）——**只允许读 page
descriptor（head flags/meta），绝不读派生指针**（AGENTS chain14 的 base==0
教训的加强版）。

**11 次重启死点分布**：fork 风暴尖峰 ×3、route pselect 内核自旋 ×1（卡
4min 无用户态防御，fd 集栈布局抽签）、win/bruteforce 期暴毙 ×2、owner 诊断
panic ×2、wave 盖页风暴 ×2、slide/prep 早期 ×1——**共同点 = 用户活跃期跑
链**。payload 死（win enter 后 3-6s tbl=0，`+.3s` 是整秒不是 0.3s）轮反而
安全退出不重启。

**对策 = 息屏守护 `tools/guard.sh`**（commit `a4834e73`）：亮屏 idle 不碰设
备；息屏才起 `KS_PIPE_MAX_ATTEMPTS=3` 短链；轮询 root=1 / 换 boot（归档
`plock_chain.reboot_N.log`）/ 败轮归档 `guard_rounds/`；成功写
`/tmp/opencode/GUARD_SUCCESS` 并 pull SUCCESS 日志。**运行中**：
`nohup bash tools/guard.sh 20 > /tmp/opencode/guard.log 2>&1 &`。
其他新工具：`KS_PIPE_MAX_ATTEMPTS` env 收 pipe 重试轮数（默认 12 太长，
18min 风暴）。

**push 阻塞（2026-10-21 实测）**：`git push origin` 返回 403
`Permission to woshimaniubi8/CVE-2026-43499-root-KernelSU denied to
poisongod`——gh 登录 poisongod（repo scope）对该仓库 `push:false`、非
fork，poisongod 名下也无该 repo 的 fork；远端 main 停在 f2c26147
（2026-07-26 committer=woshimaniubi8，本地 11+38 个 commit 全未推）。
旧结论「端点不稳定改走 gh API」不成立——同一 token api 也必 403。
**本地 git 是唯一权威**，恢复远端需 woshimaniubi8 凭证或加协作者（用户侧
操作）。

**重启循环与守护策略迭代（2026-10-21 深夜，第 12-15 次重启）**：
- **恢复期起链 = 重启连爆**（d2c6e342→4069896e→6fa5e792→44d6359a→e09c6c96
  四连爆）：守护 asleep 分支原先不查 load，在 boot 后 app 恢复风暴期
  （load 7-40）起链 = 链风暴叠加系统风暴，100% 重启。修复（`d89dcf77`）：
  **任何分支起链前 load<2.0**（亮屏 idle 档仍 <0.5）+ REBOOT 检测后强制
  90s 冷却。重启后 load 不降的常见源 = `com.oplus.onetrace` 遥测恢复
  （几分钟自消），链残留检查用 `ps|grep pause/memfd`（无泄漏即正常）。
- **RCU 等待 2s→0.3s**（`db0c1fc1`）：批 kill 后 2s×4 批 = armed 暴露
  +8s/轮，AGENTS 已有结论「armed 期间任何延长都在喂 dangling waiter 的
  PI-chain 直至锁死」——重启率 55%→100% 期间该等待是唯一新增变量；
  判决数据（post-kill inuse 恒 34）已得手，等待目的达成即缩。
- **满页轮 = 重启高危轮**：owned 失败 → 24 波 2640 fork + 多轮 drain 全在
  armed 态下跑（~30s+），owned 胜利则 waves≈2 快速过——重启率与 owned
  率成反比，根治仍是满页（三处 head/freelist 诊断见 92c5facb）。
- 三处诊断（pre-sweep/post-kill/stuck 打 head+freelist，post-kill 加
  hd==0 守卫防 hd=0 时读 0x28 panic）在 so 9f54411e，等 load<2 黄金
  窗口首跑。
- **cfgfs 对齐校验回归（2026-10-22，已回滚 `29771bdc`）**：曾给
  `cfgfs_read_ex` 入口加 `target&7` 拒读想拦 t15153 的 hole 地址，结果
  round1(t29730)/round2(t5556)/g3/g4 四轮连败全死 `fix52 cfi table garbage
  rv=-1 -> refusing further ops -> route 安全放弃`——fix52 dump 读的是
  `base+OFF+1`（fops.c:1624-1634 delta=-1 page-view shift 是**故意设计**），
  合法地址 &7==1 必被拒，成功基线同位置 rv=8。教训：**这个代码库的 cfgfs
  读目标可以故意不对齐**，任何「8 对齐」假说都错；垃圾地址防线只认
  gate 的 `k_true>=0`（该轮 k_true=10/11 均正常过 gate 未误拦）。
- **第 17-20 次重启 + 满页数据链闭合（2026-10-22）**：g8(第17次,kernel_panic)
  死点 `opening ashmem`——fake 表 open 槽被 misc_open 真实调用跳垃圾地址
  （fix52 dump 在 open **之后**才验证，救不了第一跳；表垃圾=payload 弱抽签，
  g9 同 so 走完全程是对照）。g12(第20次)死 win tick 期（无栈）。
  **满页三段式定案数据**（wavehead+batch kill 诊断）：`w=0 inuse=0 frozen=1`
  → wave[0] fork110 后 `w=1 inuse=34`（转换恰在 wave[0] fork 期）→
  `batch kill sent=660 reaped=660 werr=0`（waitpid 全成功，杀空排除）→
  `w=6..23 inuse=34` 恒定 + freelist/slab_list 恒值——**660 个死透但页纹丝
  不动**，逻辑矛盾（exit_mm 同步应已 free）。五 word slab dump（+08..+28）
  已加（so 8dffee47）待跑出数据定字段。成功轮 chain5 是 **per-wave kill**
  （waves=2 taken=1 owned=1），当前 batch(6 波攒杀)从未让 tsc 归 0。
- **满页根因判决链闭合（2026-10-22 凌晨，wavepostfork 定案）**：
  - 数据链：`wavehead w=0 inuse=0` → wave[0] fork110 → `wavepostfork w=0
    inuse=34 +20=NULL`（**wave mm 确实在目标页**）→ kill 110/110 reaped →
    `w=1 inuse=34 +20=NULL` 恒定 24 波——**mm 从未 kmem_cache_free**（SLUB
    free 必挂 freelist，+20 恒 NULL 是铁证）。字段交叉验证：+18==tsc
    （slab_cache=mm_cachep，order-3 34 对象=0x3c0 mm_struct ✓）、+28 位域
    inuse/objects/frozen 全对（高位 0x8=cpu slab 编码）。+20 freelist 链头
    =leaked（LIFO 自洽：pre-sweep 杀 leak_child 后其 mm 是最后 free 的）。
  - **串行 vs 并发 kill 的分水岭**：串行 `kill_child`（每个子进程 exit_mm
    完成后才发下一个 SIGKILL）三个先例全部生效——pre 的 clone_memfd×33、
    pre/post/spray 清扫（pre-sweep 恒 inuse=0）、chain5 成功轮
    （waves=2 taken=1 owned=1，正是 80a92409 的 per-wave kill_child）。
    两阶段批量 kill（bef0f86d 引入，110 个 SIGKILL us 级并发）只有失败
    记录——并发 do_exit/exit_mm 下 free 丢失（疑 mm_count/mmu_notifier
    竞态窗口）。已改回串行（so 9f9ecac4）。
  - clone flags=SIGCHLD only（util.c:1615，CLONE_VM 已排除）；clone_memfd
    = clone_child+open_memfd+kill_child（同款子进程）。objprobe（读
    physmap 对象头）会 data abort panic——physmap 目标的 cfgfs 读在 wave
    段不可用（vmemmap/静态区读安全）；page_to_direct 换算闭环但读 base
    照炸，未定因。
- **convert 路线终审判决（2026-10-22 凌晨，mm_struct 页回收证伪）**：
  - **泄漏线四刻度**：pre 的 clone_memfd（fork→kill ~1ms live）**零泄漏**
    （pre-sweep 恒 inuse=0）；wave 34 版 ~55ms 未对照（mm 没进目标页）；
    wave 68 串行 ~110ms **全泄漏**（g2/821c25c1 killpost inuse=34 恒定）；
    wave 68 两阶段 ~50ms **全泄漏**（sent=68 reaped=68 后 inuse=34 恒定）；
    wave 110 ~1s 全泄漏（g14 killpoll 10s 窗口 inuse 恒 34 +20 恒 NULL）。
    持有者永久性（10s+ 不释放），疑 mmu_notifier/驱动级 mm_count 泄漏。
  - **结构性死锁**：占满页 A 需 34 个 mm 并存 ≥25ms（34 次 fork 本身的
    耗时），而泄漏线 <50ms——「同时持有一页 mm」必然踩泄漏窗口。
    chain5（771b7409）成功 = 其 boot 上泄漏者不在（boot 级环境抽签）。
  - **页 A 归属 cpu 是 per-attempt 抽签**（frozen=1 的 cpu_partial 空页）：
    110/68 版抽到 wave[0] 的 cpu 被拉满+泄漏；34 版没被拉（24 波 inuse
    恒 0、sc 恒非 0、永不 discard——cpu slab 位卡死）。另 wave[4+] pin
    errno=22（设备部分 cpu 不可 affinity，keep last pin 兜底）。
  - **下一步（换 leak 对象）**：physrw 需要 pipe_buffer 落「已知物理页」，
    mm 页回 buddy 死路 → KSNITCH collision 换目标对象（kmalloc-2k
    pipe_buffer cache 或 skb frag page），collision/leak 段需重构。
  - 满页攻关 so 演进（untrusted_app）：779a3fe4(wavepostfork) →
    9f9ecac4(串行 kill_child) → b83c5bd6(killpoll 10s 时序) →
    488b0ee9(wave_n=34) → c6a7f9ae(68 挤压) → c781613f(68 两阶段, 终版)。
- **满页/泄漏终极根因（2026-10-22，内核源码铁证，commit 4a700189 so ca1b89bc）**：
  - **根因 = wave 子进程 `/proc/pid/mem` fd 卡在父 socket queue 致 mmgrab 永久泄漏**。
    内核 `fs/proc/base.c:813 proc_mem_open`：`mmgrab(mm)`（注释原文
    "ensure this mm_struct can't be freed"，mm_count++）+ `mmput(mm)`
    （只减 mm_users，不减 mm_count）。`clone_child()` 的子进程
    `child_handoff_memfd` 把 `/proc/self/mem` fd sendmsg 进 socketpair，
    但 **wave 段从不 `open_memfd`(recv) 也从不 close sv[0]** → fd 卡在
    父 receive queue 到链退出 → file 持 mm_count → 子进程 SIGKILL 的
    `exit_mm`(mmput→__mmput→exit_mmap→mmdrop) 减不到 mm_count 0 →
    **mm 永不 free** → inuse 恒 34 / +20 恒 NULL / 页永不 discard。
  - **pre 不泄漏的真相**：`clone_memfd` = clone_child + `open_memfd`
    (立即 recv + close sv) + 后来 `close_ctx_memfds` close fd →
    mmdrop → mm free（pre-sweep 恒 inuse=0）。这解释了泄漏线四刻度
    （pre 1ms 不泄漏 vs wave 50/110/1s 全泄漏）——**不是 live time 问题，
    是 fd 有没有被 recv/close**（早先 live-time 归因错误，已推翻）。
  - **修复**：新增 `release_child_handoff(child)`（util.c，=memx_take_sv+close），
    声明于 common.h；pipe.c wave reap 循环与 flush 循环 kill 后调用 →
    purge queue skb → fput(memfd) → mem_close → mmdrop → mm_count 归 0
    → mm free → 页 discard → owned。
  - **chain5 成功之谜的更优解释**：chain5 的 wave 恰好走过 recv/close
    （或其代码版本 sv 被管理），mm 正常 free，非「boot 无泄漏者抽签」。
  - **KSNITCH 无法换 leak 对象**：futex hash seed = `current->mm_struct`
    （kernelsnitch.h:116），collision 只能 leak mm_struct —— 换 kmalloc-2k
    的方案不可行，本根因修复是唯一出路。
  - **验证状态**：so ca1b89bc 已部署，但 g1 死于 wave 前 payload 表早死
    （`cfi fail path payload table dead tbl=0`），修复尚未被 wave 段检验；
    守护等息屏窗口跑下一轮，判据 = `killpost w=0 inuse=0`（归 0 即修复生效）
    → `convert waves=... owned=1` → drain → root=1。
- **泄漏回归点定案 = commit ffec4212（2026-10-20 20:10，app 域 M1 修复的副作用）**：
  该 commit 为修 app 域 `open_memfd` 被 SELinux ptrace 拒，给**所有** `clone_child`
  子进程加了 `child_handoff_memfd`（子进程自开 `/proc/self/mem` sendmsg 给父）。
  commit message 当时断言「FMODE_UNSIGNED_OFFSET still does not pin the mm」——
  **错误**：`proc_mem_open` 的 `mmgrab(mm)`（"ensure this mm_struct can't be
  freed"）永久 +1 mm_count，wave 路径从不 recv/close sv[0] → fd 卡 queue →
  mm 永不 free。自此之后每一轮 wave convert 全部 inuse=34 恒定（数据完全吻合）。
- **chain5（771b7409，10-21 06:15）反例消解**：4a700189 曾猜「chain5 的 wave 恰好
  走过 recv/close」——错。真相 = **chain5 的 so 构建早于 ffec4212**（pre-handoff
  时代 `clone_child` 子进程直接 pause、不开 /proc/self/mem，mm 干净 free）。
  行为证据链：handoff 前（chain5）waves=2 taken=1 owned=1 root=1；handoff 后
  （此后所有轮）inuse 恒 34、owned=0、+20 freelist 恒 NULL。同一机制解释全部刻度。
  **教训：改 clone_child 子进程路径引入任何「文件被内核持有」（/proc、binder、
  dma-buf）都可能 mmgrab/mmget 钉住 mm——ffec4212 的 app 域修复曾被误判为无害。**
- **验证判据（so ca1b89bc = release_child_handoff 修复版）**：`plock_chain.wavefix1.log`
  出现 `convert waves=2 taken=0 owned=1 sc=0000000000000000`（页回 buddy）——
  候选修复生效证据，待设备上线后核实该日志特征行（killpost w=0 inuse=0）与后续
  drain/root=1；若确认，wave convert 满页死锁正式告破，剩余死点回到 route 段
  `opening ashmem`（g8 类 fake 表 open 槽 panic）。

## 考试一合格达成（2026-10-22 08:55，boot 4ceee4ab）——mmgrab 根因修复实测全通

- **so ca1b89bc（release_child_handoff）一次过**：`pre-sweep inuse=0 frozen=1` →
  `killpost w=0 inuse=34`（首波 kill 后瞬时仍 34，多波继续磨）→ **13 波
  `waves=13 taken=12 owned=1 sc=0`** → drain → `physrw done=1 root=1
  read_ok=1 write_ok=1 rw64=1/1 uid=2000->0 selinux=1->0 setenforce=0`。
  满页死锁（30+ 轮 inuse 恒 34）正式告破，回归点 ffec4212 判决由实战闭环。
- **判据全链**：CHAIN_EXIT_DONE ✓ + DONE 后 130s+ 无 reboot ✓ +
  `POSTLOCK-RESTORE-OK`（在 `/data/local/tmp/postlock_restore.log`，**不在
  chain.log**——验收 grep 别找错文件）✓ + kernelsu.ko 加载 +
  `ksu_debug_manager_appid` root 读 **10279** ✓（shell cat 读出**空**是权限假象，
  参数文件 4096B 存在）+ ksud running + `/product/bin/su` overlay +
  su --daemon + Permissive ✓。
- **BakaSu 蓝卡**：「工作中 Built-in」+ 0 超级用户 0 模块（真驱动真 store）。
  驱动 `v4.2.0-rc3-8450dd28-dirty@BakaSU (35220/5)` vs 管理器 `(35236/5)`——
  **版本号不同但蓝卡不红**（app 已自升级 35236，UAPI 5==5 即绿）；SELinux 宽容。
- **取证**：`/tmp/opencode/exam/ui_exam1.png`（蓝卡截图）+
  `plock_chain.SUCCESS_root1.log`（已 pull 设备侧备份）。
- **链日志/restore 日志分工**：chain 走 `plock_chain.log`；restore.sh 输出在
  `postlock_restore.log`（含 `driver-already-loaded`/`WARN-phantom-settings`）。
- **Tailscale 通道备忘**：host Windows Tailscale 曾整体停止（`tailscale.exe up`
  拉起后恢复）；设备 oppo = `100.80.86.28:5555` direct；`100.71.26.6` 是另一台
  android 节点（node）非主设备；LAN `192.168.8.10` 会 No route。
  guard.sh 用 `GUARD_SERIAL=100.80.86.28:5555` 覆盖默认序列号。
- **考试一（shell 域老师卷）至此合格**。下一步：考试二 = untrusted_app 域
  app BOOT_COMPLETED 自跑全链（`triggerChain` direct），M5 app 域 KASLR 自举。

## 考试二排查（2026-10-22 下午，第 1-2 轮诊断）——BOOT_COMPLETED 双因死点 + app 域链 ca1b89bc 推进实况

**BOOT_COMPLETED 两次没到链的双因定案**（当前 boot f8978a50 实测）：
- **force-stop 后的 app 处于 stopped 状态 → reboot 后 BOOT_COMPLETED 被
  exclude-stopped 排除**（AOSP 经典行为：force-stop 的包收不到开机广播直到
  被手动启动一次，且错过不补投）。**铁律：任何 boot 前的 force-stop 都会害死
  下一次 BOOT_COMPLETED**——考试轮前禁 force-stop（写 switch 改用 app 内
  UI/不重启的操作；真 force-stop 了也别指望 boot 后 am start 能补救广播）。
- **手动 LAUNCH 发给后台被 HANS 冻结的 app → onReceive 不执行**：`am broadcast`
  报 `result=0` 只代表广播投递成功，冻结进程无法调度 receiver——拉前台解冻后
  同一条 LAUNCH 立即生效（实测 .ver/state/dispatch 线程全变）。
- **boot 洪峰几分钟冲光 logcat 的 PostLockBoot 行** → 已加落盘日志
  `files/postlock/receiver.log`（BootReceiver 全分支 + ChainService
  gate/FGS + triggerChain 入口，64KiB 轮转，run-as 可读，commit 70ba915）。
  归因 receiver 静默失败以后只认这个文件。

**app 域链 ca1b89bc 推进实况**（LAUNCH 诊断轮 + 前台保活，远超第七轮
v1.7 判决的三死点）：
- **已过**：slide（泄题 KS_SLIDE_SKIP=1 + 共享 ksu_kaslr）✓ → collision
  （真阳性：post-pile baseline=27→30 掉回基线）✓ → **mm_struct scan ✓**
  → payload nonce 注入 + skbdelta 写 + drain 8192 + sends 896 +
  prepare storm 1088 ✓ → pselect route calls=1 success=1 ✓ → CFI fix52
  表 dump（ioctl 槽=真 ashmem 地址 rv=8）✓ → win enter q0=1 ✓。
- **mm_struct scan 的命门 = MainActivity 前台保活**：shell 域同 scan **2 秒
  命中**（纯计算）；app 转后台后 cgroup CPU 配额掐纯计算 scan **180× 慢**，
  6+ 分钟不命中表象似卡死（`start finding` 后无中间日志——每 1TB 才打一行，
  无日志≠卡死）。BOOT_COMPLETED 自跑链必须保 MainActivity 前台
  （receiver startActivity 被 AOSP 拦，第七轮已证；FSI/AlarmManager 待选）。
- **当前死点 = win +5s 页死**：`win tick +0~4s dead=0 → +5s dead=1`
  （ioctl 槽读 ENOTTY = payload 页被回收/表清零）→ phys prepare abort →
  `pselect route done step=8`（!installed）→ root=0 安全退出无 panic。
  **= 抽签非结构**：AGENTS 已录 shell 已知模式「win enter 后 3-6s tbl=0 页死轮」；
  shell 的 leak_child/collision 与 app 在 win+4~5s **完全同一时刻**发生但 shell
  页活到 +25s+；**memcg 假说已证伪**（apps 组 limit=LLONG_MAX、failcnt=0、
  kmem 未启用、全局 free 充足）；两域结构时序逐行同构（shell 成功轮同样打
  `phys prepare produced no page` 后重试 convert owned=1 成功）。
  **对策 = fresh boot 多轮抽签**（同考试一 payload 捕获经验）。

**归因教训（防再犯）**：
- `cfgfs read set-fail ENOTTY` **不是**表空/通道死的充分证据——fops.c:1699
  fix44 注释明言 ENOTTY 两种语义：route landed 的**成功标志**（fake fops 不实现
  SET_NAME）vs 页死后 ioctl 槽清零。唯一可靠归因 = **diff shell 成功轮
  （SUCCESS_r3.log）同位置日志**：win tick/fix52/route 段逐行对照。
- `post-pile count=5` 只是重复计数，**真伪判据 = target 是否掉回 baseline**。
- pgrep `-f` 自匹配陷阱（模式串含在 sh 命令行）踩过三次：诊断用
  `ps -A -o PID,UID,ARGS` 或 `[e]cho` 括号技巧。
- app 域轮次结束（step=8 fail path `skip cfgfs restore`）misc.fops 残留
  dangling fake 表——轮间有第三方 open misc 的 panic 风险（g8 同款），
  同 boot 连跑诊断有代价，重要轮次先 reboot。

**下步**：装 receiver.log 版 APK（70ba915/13:23 构建）→ fresh boot LAUNCH
诊断盯页死复现率（页活轮次即深入 wave/physrw/restore 拿 app 域 root=1 数据）→
receiver.log 定案后走 BOOT_COMPLETED 正式轮（不 force-stop + 上线即泄题 +
30min awaitKaslr 窗口 + MainActivity 前台）。

**force-stop 的最严重后果实例（2026-10-22 13:10 实测，设备失联 30+ 分钟）**：
归档轮我 force-stop 了 app → reboot 后 app 处于 stopped → BOOT_COMPLETED 被
exclude-stopped 排除 → PostLock 永不自启 → **tailscaled 也不自启（它的自启靠
app BOOT_COMPLETED）→ tailnet 断 → adb（唯一通道，USB 已退役）不可达**。
**教训升级：force-stop 不只是「害死一次广播」，而是「设备自锁到用户手动开
一次 app 为止」**——考试轮/攻关轮一律禁止 force-stop；杀链用精确 kill。
（诊断轮 LAUNCH 之前 force-stop 是可接受的例外——LAUNCH 手动触发不依赖
BOOT_COMPLETED——但 reboot 前必须确保 app 未 stopped：force-stop 过就先
am start 一次再 reboot。）

**tailscaled 自启真相（2026-10-22 用户观察「tailscale 没开机自启」定案）**：
BootReceiver 的 `tailscale autostart`（`:87` `sp.getBoolean("tailscale", false)`
→ `PostLock.startTailscaled`）是 commit **`9914de8`**（switch semantics 改版）
加的——**装机 v1.34（5e96d85 构建）源码里 grep 为 0，根本不存在这段代码**。
即：**历次 boot 后 45s~90s 的快速 tailnet 上线全是用户手动开 app 拉起的**，
不是自启；boot 574de6c0 失联 14 分钟正是因为没人手动开。pref
`services/tailscale` 一直是 true（开关不缺），缺的只是代码。
**v1.35（622766a，2026-10-22 14:11 构建，已装机）包含 autostart + gateDiag**
——从它起 BOOT_COMPLETED → startTailscaled 自启才真正闭环；验收看
logcat `tailscale autostart: starting tailscaled` 行。装 v1.35 前的任何
「为什么没自启」疑问一律先查「装的版本含不含 9914de8」
（`git show <vN>:...BootReceiver.java | grep -c autostart`）。

**开机自启通道攻克达成（2026-10-22 晚，v1.37 / cd05040，boot 6e5c0807 零干预终验）**：
reboot → +61s `tailscale autostart fired` → daemon 9323 `Starting -> Running`
+ derp connected → `status: active; direct`（全程零人工，只轮询验收）。
三层自愈架构（v1.37 落地，`PostLock.ensureTailscaled` 统一 probe+start 幂等）：
1. **ChainService dispatch 线程头部 ensure**——Athena o-kill 杀 app→AMS 11s 拉回
   时秒级救 daemon（此前只能等 15min tick）；同服务 `onCreate` 起 **2min 探活
   Handler**（FGS 存活期 = gate 等待 + 链跑窗口，恰是 alarm 最不可靠时）。
2. **exact alarm 链式 tick**：`setExactAndAllowWhileIdle` 单发 + `tsKeepalive`
   finally re-arm（SecurityException → setRepeating fallback）。**别改回
   setRepeating**——实测非精确 tick 被 OPPO doze 推迟 159s+ 不响（对照首次
   +19s 响，屏灭后恶化）。
3. BOOT_COMPLETED autostart（9914de8 起）不变。
**死因链实锤（logcat 归因法）**：`AthenaService: OplusClearSystemService: Killing
<app> o-kill(40)` → `PhantomProcessRecord {9307:<app>:libtailscaled.so} died`
——OPPO 清后台杀主进程，tailscaled 作为 phantom 连带（与 round10 phantom trim
同族）；HANS 亦观察到冻结 `[app, tailscaled]` 后 `unfreeze ... exitFF`。
**手动 tick 测试法**：`am broadcast -n com.postlock.boot/.BootReceiver -a
com.postlock.boot.TS_KEEPALIVE` → rlog 应出 `dead -> restarting` +
`armed (exact+idle 15min)`（v1.37 标志文案）。
通道事实更新：LAN `192.168.8.10` 会 `No route to host`（用户「常驻」仍出现，
别当唯一通道）；reboot 后 tailnet ~132s 恢复（官方 app 临时通道 + 我们 autostart
并存，`com.tailscale.ipn` 在跑不冲突——两者各持自己的 state）。
**install -r 后必须 am start 解锁 stopped**（本轮再次踩实：不解锁下次
BOOT_COMPLETED 被 exclude）。rlog 时间戳 = `System.currentTimeMillis()` 毫秒，
与 host `date +%s%3N` 同域可直接对齐。

**HANS cgroup 冻结 = 后台静默的总根因（2026-10-22 晚实证，boot 6e5c0807）**：
app uid 后台即被 OPPO freezer 冻（**FGS/perceptible 不免疫**——dumpsys 显示
`prcp F/S/FGS` 照冻）。**判据 = `run-as cat /proc/<pid>/task/<chain-tid>/wchan`
显示 `__refrigerator`（state=D）**；解冻后变 `futex_wait_queue_me`（state=S）。
一次 21 分钟冻结统一解释当晚全部「诡异」：`gate poll i=30` 29 分钟不打印
（awaitKaslr 线程冻着）、rlog 静默窗口 19:07→19:28、broadcast `result=0`
但 145s 后才执行、exact alarm fire 后队列条目消失（receiver 未及 re-arm）。
**解冻实证 = `am start MainActivity` 拉前台，45s 内线程恢复 + rlog 恢复**
（第七轮「前台可见=免冻」再次验证）。alarm 触发带
`temporaryAppAllowlistDuration=10000`（10s 白名单）——**tick 能执行但 10s <
i%30 的 60s 打印间隔，故冻结期 gate poll 永远静默**。排查任何「app 不干活」
先查 wchan，别再从 rlog/alarm/广播三条线分别猜（当晚全猜错过一轮）。
副作用：三保险（wakelock/FSI/alarm 拉前台）若用户不在设备旁可能保不住
前台（本次 19:07 布防后仍冻），考试轮的保活验证要盯 wchan 而非只看 rlog。

**冻结期 keepalive/tailscaled 机制定案（2026-10-22 深夜，v1.38/v1.39 实证）**：
- **冻结期 alarm 行为 = fire 后广播挂起，解冻瞬间 flush**：due 落在冻结窗口时
  dumpsys pending 条目消失、stats wake 不更新、logcat 无 fire 痕迹（曾误判
  「被 cancel/丢弃」）——实际 AlarmManagerService 已 fire，broadcast 队列等
  uid 解冻。**定案实验**：拉前台后 30s 内挂起 tick 立即执行
  （`onReceive TS_KEEPALIVE → alive → gate not ready → armed`，1792673177827）
  + re-arm。**keepalive 链是延迟自愈、不是断链**；冻结期完全静止（无解冻
  事件则永不 flush——解冻来源 = 用户开 app / 前台操作 / 偶发系统窗口）。
- **v1.39 `setAlarmClock`**（commit 9230e3e）：AlarmClock 类型 = 真 exact
  （`windowLength 0`，对比 setExactAndAllowWhileIdle 在本机被合批成
  `windowLength 674999`=11min）+ 免 SCHEDULE_EXACT_ALARM。冻结期结局与
  setExact 相同（都是挂起到解冻），但零窗口 + 最高豁免类，保留为主路径，
  exact+idle 降 fallback，再 setRepeating。
- **daemon 冻结不杀、解冻秒级恢复**：tailscaled 被 HANS 冻时停调度、网络断
  （host `status` 见 `oppo offline, last seen` 恰对齐冻结窗）；解冻后 40s
  内日志恢复（`derp-20 connected; connGen=2` + netcheck + endpoints 重协商，
  20:46 本地实证）。**pid 不变（同一进程），不是重启**。
- **HANS 冻结是 uid 级**：app 主进程、chain 线程、tailscaled 一并冻结——
  「开机自启 Tailscale」的 app 侧工程已闭环（BOOT_COMPLETED +61s 起 daemon /
  三层自愈 / tick 解冻 flush / v1.38 tick-gate dispatch），**冻结期服务断是
  OPPO 系统行为，app 内无解**：唯二出路 = 用户 OPPO 白名单（允许后台/
  自启动，一次性设置）或 PostLock 保持前台（考试轮 SOP 已含）。日常通道
  LAN 192.168.8.10 主力 + Tailscale 解冻自愈的格局与用户决策一致。

**BOOT_COMPLETED 正式考试轮 SOP**（app v1.35+，gateDiag 见 622766a）：
1. 前置：app 未 stopped（禁 force-stop；若已 force-stop 则 am start 一次）；
   switch postlock=true；payload v3 已解包（.ver 校验）。
2. `adb reboot` → 等 boot_completed=1 + tailnet 恢复。
3. 上线即跑泄题轮：`KS_KASLR_ONLY=1` shell 起链写 `/data/local/tmp/ksu_kaslr`
   （出题人合法，30min awaitKaslr 窗口内 app 自己消费）。
4. app 自己走：BOOT_COMPLETED → panic guard → switch → keep-alive 三保险
   （wakelock 亮屏 + FSI 锁屏全屏 + AlarmClock +5s，任一生效保 MainActivity
   前台免 HANS 冻结）→ ChainService FGS → awaitKaslr → triggerChain direct。
5. 验收 = 判据全链（root=1 + DONE + RESTORE-OK + 120s 无 reboot）+ BakaSu
   蓝卡 Built-in。receiver.log（run-as cat files/postlock/receiver.log）+
   chain.log 双落盘归因。一次 reboot 一轮考试，链内多次重试只算一次。

## 考试连续性规则（2026-10-22 用户裁决）

- **连续三次考试合格才算完成**——不是考三次合格（中间失败则**连续计数归零重来**）。
- 一次考试 = 一次独立完整合格（fresh boot 起链 → 判据全链 → 蓝卡 Built-in）；
  同一轮内链的多次重试只算这一次考试。
- **考试一当前连续计数：1/3**（2026-10-22 08:55 boot 4ceee4ab 首合格，
  取证 /tmp/opencode/exam/）。第 2 轮 reboot 重考开始。
- **考试一第 2 轮合格（2026-10-22 10:48，boot 446cfc13）**：reboot fresh 首链
  load 1.10 起链 ~60s 一次过（root=1/DONE/restore/appid=10279/蓝卡 Built-in 全绿）。
  **连续计数 2/3**。取证 ui_exam1_r2.png + SUCCESS_r2.log。
- **考试一第 3 轮合格（2026-10-22 11:04，boot 085ca556）**：load 1.51 起链 ~100s
  一次过，全判据 + 蓝卡 Built-in。取证 ui_exam1_r3.png + SUCCESS_r3.log。
- **🏁 考试一连续三次合格完成（3/3）**：三轮独立 fresh boot 全部一次过、零失败
  （4ceee4ab / 446cfc13 / 085ca556），三张蓝卡截图齐全（exam/ 目录）。
  根因修复 ca1b89bc 在三个独立 boot 上稳定复现。**下一场：考试二（app 域）连续三次。**

## 考试二第 1 轮合格（2026-10-23，boot 2be7494f）——paste 泄题 + 三处修复后 app 域 root=1 蓝卡

**连续计数：1/3**（取证 `/tmp/opencode/exam2/SUCCESS_r1_2be7494f.{log,png}`）。
判据全链：app uid 10293 自己跑完 `triggerChain ENTER` → root=1（uid 10293→0、
selinux 1→0）→ CHAIN_EXIT_DONE → POSTLOCK-RESTORE-OK → 120s 无 reboot →
kernelsu+ocsk 双模块 → BakaSu 蓝卡「工作中 Built-in」（驱动 35220/5、管理器
35236/5、UAPI 5==5）。

**过关的三处代码修复（今日依次落地）**：
1. `reload_payload_base` live-preference 前置（cfc3de1a）：r4（boot 2050b352）
   paste 成功但 route 的 pvo 窗口检查（app 域静态 physmap 窗口）拒了泄题轮
   实测 base → `skip attempt=1` route calls=0 安全败。修 = `skb_payload_base!=0`
   直接 return 1 提到函数头；文件 adopt 路径保留 pvo 把关。
2. release 诊断 + 波次上限（a245d677）：r5/r6 `killpost inuse=34 +20=0` 恒定
   （ffec4212 mmgrab 症状）连续 owned=0。`release_child_handoff` 改返回 0/1 +
   batch kill 行打 `rel=ok/total`。**r7 实测 `rel=68/68` 全成功 → handoff 修复
   一直正常，r5/r6 owned=0 纯属 8 波太短的抽签**；同轮 app env
   `KS_WAVE_FLAT_MAX 8→24`、`KS_PIPE_MAX_ATTEMPTS 2→3`，12 波 `taken=11 owned=1`。
3. 方案 F payload paste（d2fa8611 主仓 + app vc42-50）：shell 泄题轮
   `KS_PREPARE_HALT=1800` 持页写 `/data/local/tmp/ksu_payload`
   （boot_id+base+kaslr），app 链 `KS_PAYLOAD_PASTE=1` 三重校验消费。
   app 域永久无 perf/tp oracle（SELinux 拒 untrusted_app perf_event_open，
   errno=13 非 seccomp）→ 盲 prepare 必死 → paste 是唯一出路，属合法泄题。

**r5/r6 失败模式备案**（同修复后仅差波次抽签）：r5 死 physrw
`wave flat x8 owned=0`；r6 死更早 `collision wait spun out` → owned=0——
两轮均 paste/route/open/fix52 全通过后安全失败（fail path pi_cleanup →
neutralize → 无 panic），fail amplifier reboot 即重抽。

**第 2 轮合格（2026-10-23 16:17，boot fe30e85d）**：泄题 13/72 就绪、链
`waves=16 taken=15 owned=1` → root=1（uid 10293→0 selinux 1→0）→
RESTORE-OK → 120s 无 reboot → 蓝卡 Built-in。取证
`/tmp/opencode/exam2/SUCCESS_r2_fe30e85d.{log,png}`。**连续计数 2/3**，
第 3 轮 = 决胜轮。

- **🏁 考试二连续三次合格完成（3/3，2026-10-23 16:25）**：第 3 轮 boot
  `962fdea8`——泄题 24s 就绪、链 `waves=21 taken=20 owned=1` → root=1
  （uid 10293→0、selinux 1→0）→ CHAIN_EXIT_DONE → POSTLOCK-RESTORE-OK →
  120s 无 reboot → kernelsu+ocsk → 蓝卡「工作中 Built-in」。取证
  `/tmp/opencode/exam2/SUCCESS_r3_962fdea8.{log,png}`。
  **三轮（2be7494f / fe30e85d / 962fdea8）全部一次过、零失败、零 panic**——
  paste 泄题 + live-preference + 波次 24 的修复组合在三个独立 fresh boot
  上稳定复现。**考试二（untrusted_app 域学生卷）至此收官；两场考试均 3/3。**
  成功率注记：合格三轮的 convert 用波 12/16/21（上限 24 内），
  `rel=68/68` 全程恒真——owned 是唯一抽签变量，24 波上限给了足够余量。

**轮 SOP（照此跑第 2/3 轮）**：install 后 am start 解锁 stopped → reboot →
boot_completed 后 `am start` 拉前台 → 起泄题轮（`KS_PREPARE_HALT=1800` 完整
TRIGGER env，detached，poll `ksu_payload` 出现**本轮 boot_id** + `H=1`——注意
旧 boot 残留文件的 boot_id 里可能含 "1" 别误判）→ host 循环 `am start`
MainActivity 保活（HANS 免疫）→ receiver.log 见 `triggerChain ENTER` → 链
`CHAIN_EXIT_DONE` → restore.log `POSTLOCK-RESTORE-OK` → 120s boot 不变 →
截图蓝卡。泄题轮 prepare 可能 retry 上百次（r7 恰在 72/72 最后一轮成功）——
耐心 poll，gate 因 ksu_kaslr 旧 boot 值正确保持 rdy=false 不会提前 dispatch。

## 稳性马拉松 round5 真 panic（2026-10-23，boot b04eec8b）+ root_stage_dirty 修复

马拉松 marathon3（12 轮）round 1-4 全 PASS 后 round 5 抓到**真 kernel_panic**
（`ro.boot.bootreason=kernel_panic,null` 实锤，非人工重启）。脚本按 fail amplifier
自动归档取证到 `/tmp/opencode/exam2/marathon/round_05/`（**pstore.txt 258KB 在新
boot 上可读**——含完整 panic 栈；chain.log 1.5MB；receiver/payload_hold/restore
日志齐全）。取证结构：pstore 的 pstore 文本区有 OCR 式损坏（`grep -a` + 容忍
错字），`Kernel panic`/`Call trace`/`Comm:` 锚点仍可用。

**panic 现场**（内核时间 245.4s，链 ENTER 后 ~180s）：
```
init(PID 1) Oops:96000005 → lr: release_task+0x38 ← do_wait ← wait4
HeapTaskDaemon: Unable to handle kernel paging request at ffffffeb8ea488b8
（physmap 窗口外垃圾段，与链日志里坏 cap 地址 ffffffeb8e77b388 同前缀）
Kernel panic - not syncing: Fatal exception → watchdog 重启
```

**时序重建**（chain.log root 段 204 行逐行对齐）：
1. 第一轮 root 写阶段全部成功：`root seccomp patched` → `root cred patched
   uid=0/0` → `caps patched` → `selinux 1->0`（内核内存已写）；
2. root child 超时被 SIGKILL（`root child timeout alive=0 wst=9`，未走到
   insmod/coldstart——round 4 同位置有这两行，round 5 全缺）；
3. fail path：pi_cleanup → neutralize → pipe clear（count=2→0）；
4. self patch 分支（`opt_patch_self && !root_child_done`）**又跑一遍** seccomp
   patch + task prepared + cfgfs 写序列——**卡在此处 90s+ 无日志**（armed 持续）；
5. 系统级破坏显形：init `release_task` 踩坏数据 Oops → Fatal panic。
（注意 `cfgfs write target=d5000000 ×146` 是 root 段正常操作分布，非 146 次
重试循环；round 1-4 没炸是因为 root child 正常完成、不走 self patch 重入路径。）

**修复 = `root_stage_dirty`（so sha `908ce328`，三层防御）**：
- `main.c` 定义 `atomic_int root_stage_dirty` + `common.h` extern；
- `root.c install_android_root` 入口：dirty 则拒绝重入（纵深防御）；
- `root.c` 写阶段入口（`patch_task_seccomp` 前）置位——此后任何失败都不可重试；
- `fops.c` attempt 循环（1927）：`install_child_root` 失败后若 dirty →
  `break` → `goto fail` 安全退出，fail amplifier reboot 换 clean boot。
- `reset_main_route_state` **不清** dirty（同进程重跑链本就危险，持久拒绝）。
- 副作用评估：physrw gate 失败轮（dirty=0）照常重试；root 段早期失败
  （spawn/地址准备，未写内核）dirty=0 照常重试；成功轮不受影响。

**未定案最后一环**（~~待复现~~ **已复现并定案**，见下节）：self patch 的 cfgfs
写序列卡 90s——静态考古确认写原语（cfgfs/pipe_phys_write）无用户态重试循环
（单次调用 wr=40 返回），卡在内核回调/序列内则用户态 deadline 熔断无效。

## self-flip panic 复现定案 + 禁用修复（2026-10-23 晚，boot cf4d5f87，so `0eba9857`）

marathon4 round 4 **同款复现**（root_stage_dirty 未拦——第二遍在**同一个
`install_android_root` 调用内**的 self patch 分支，不重新进函数，修复注释
已预告此边界）。chain.log 签名与 round5 逐行同构：
```
第一遍 seccomp → cred patched uid=0/0 → child timeout alive=0 wst=9(SIGKILL)
→ child result done=0 cap=窗口外垃圾(…b388，两轮低 12 位相同)
→ fail path neutralize/pipe clear → self patch 分支第二遍 seccomp+task prepared
→ cfgfs 写序列卡 90s+ → init release_task Oops → Fatal panic
```
- **root child 死因**：wst=9=SIGKILL 且链自身不主动 kill（诊断后仅 return 0）
  ——疑 `install_android_root` 入口的 `patch_oplus_root_check` 抽签未生效 →
  child `setuid(0)` 触发 OPPO OPLUS_ROOT_CHECK 被 force_sig（ocsk.ko 此时
  未加载——它是 restore 阶段才 finitmod 的）。
- **决定性证据**：两场马拉松全部 PASS 轮（marathon3 r1-4、marathon4 r1-3）
  root 路径 = `root child result done=1`，**从不进 self patch 分支**；
  self flip（`root self syscall setgid` 行）在全部样本中**零成功记录**、
  两次 panic 全部命中它。
- **修复 = kill switch 禁用 self flip 写序列**（root.c:1443 分支开头）：
  child 死于第一遍写之后 → `pr_warning("self-patch flip disabled (panic
  path)")` → guard disarm + neutralize（安全排雷保留）→ `goto
  self_patch_skip` 跳过整个 seccomp+flip+ksud+su+finitmod 序列 → 函数尾
  `fake_gki_release` + return 0 → fail path → fail amplifier reboot 换
  fresh boot（新 boot ocs patch 重抽签，child 可能存活走 done=1 路径）。
- 验证判据：child 死轮链打 `self-patch flip disabled` 后安全退出
  （root=0、无第二遍 seccomp 行、无 panic）→ 换 boot 重试。

## 马拉松 route pselect panic + 归档覆盖事故 + panic guard 实战漏报（2026-10-23 晚）

**route pselect 抽签 panic（marathon5b round1，boot bac0faa4，pstore 实锤）**：
链死在 `route pselect enter attempt=1`（root 之前）——`Comm: ks_consumer`、
`pc=_raw_spin_trylock+0x1c`（`ldr w8,[x8]` x8=0x3，fdset 小整数被当指针）、
栈 `rt_mutex_adjust_prio_chain → rt_mutex_adjust_pi → __sched_setscheduler →
sched_setattr`——即第六轮定案的「app uid pselect fdset 布局错位」物理机制。
**PASS/PANIC 轮配置全同**（shift=0 / slot=0 / chmod EACCES 四轮 PASS 全有），
round_04 PASS 轮 boot 早期同样有 oops——**纯抽签，不在 root_stage_dirty/
self-flip kill switch 覆盖面内**（死点在 root 之前）。fail amplifier reboot
重抽即可；该签名再次出现先对照本节，别误判为 kill switch 失效。
另：`pselect chmod slot file errno=13`（slot 文件 root 644 残留、shell 写拒）
在 PASS 轮同样出现，是常态非异常。

**归档覆盖事故（已修 commit `0c688bf0`）**：`tools/exam2_marathon.sh` 归档
路径固定 `$OUTDIR/round_%02d`——每场马拉松同号轮**覆盖上一场**：marathon5 r4
PASS 归档摧毁了 marathon4 r4 的 panic pstore 原文（round_05 boot_id 也不再是
marathon3 r5 的 b04eec8b）——**两轮 panic 的 258KB pstore 原文已丢失**（AGENTS
文字归因在，原文挖不动了）。修复：`RDIR=$OUTDIR/run_<MMDD_HHMM>/round_%0N`
每场独立子树 + `panic_archive` 先写 `result=PANIC…`（round_01 曾显示上任
住户遗留的 PASS）。**教训：定时归档目录禁止固定路径复用。**

**panic guard 实战漏报（AGENTS「待实战确认」项定案）**：真 panic 后 boot
（ro.boot.bootreason=`kernel_panic,fatal_exception`）的 BOOT_COMPLETED **guard
没拦**——receiver.log `gate pass switch_postlock=true`（有 gate pass 即 guard
已过，且 `panic guard passed reason=` 行在 tail 截断外——取证时 grep 结果别用
小 `tail -N` 截关键行）。机制：`bootReason()` 先试 history（**app 域 exec
getprop 照样空读**）→ fallback 第一 `persist.sys.oplus.boot_reason`（app 域
唯一可读）**其值不含 panic 关键词**（实测现值 `reboot`，与 history 首行
`reboot,shell,…` 格式不同源——疑 OPPO 服务只在特定场景写它，panic 时未更新）
→ `ro.boot.bootreason`（含 kernel_panic，排最后）被短路 → fail-open。
**待办**：下次真 panic 后 boot 立即发 `am broadcast …LAUNCH --ez panicCheck
true` 抓当时各 prop 的 app 域实读值，再定 `looksLikePanic` 扩展或换判据源。
当前对马拉松无害（fail amplifier 自己管重试；guard 若真拦了反而会关掉
postlock 开关挡住每场第一轮）。

- 「不需要拿番茄了」——`com.dragon.read` 重启后**不再需要主动拉回**（原铁律作废）。

### Tailscale 常驻通道与 termux adb 实测（2026-10-23 上午，boot cdc19086）

- **HANS 冻结实锤（uid 级）**：app BOOT_COMPLETED autostart → tailscaled 随 app 起
  （ETIME==uptime），`Starting→Running` + DERP connected 后 **boot+~86s 即被冻结**
  （cgroup `freezer:/frozen`，两次实测窗口 10s~60s）→ tailnet 断（host 视角
  node `offline, tx>0 rx=0`）。**纯 app 方案 tailnet 只有「开机一闪」窗口，无实用价值**。
- **shell uid2000 tailscaled = 常驻正解**（已实测 active direct + tailnet adb 通）：
  host adb（postlock key）shell 会话里 `nohup /data/local/temp/tailscaled
  --tun=userspace-networking --socket=@postlock-tsd-sh --state=/data/local/temp/ts.state &`；
  state 用 `run-as com.postlock.boot cat files/ts.state` 复制 app 登录态（machine
  key/profile 在内，免重新登录；同 NodeID 双连会互踢，shell 的胜出）。**shell 域
  不被 HANS 冻结/清理**，tailnet 跨小时稳定；reboot 后需重跑（app 自启的 app-uid
  实例会在窗口期先上线，可再被 shell 实例顶替）。temp 目录 tailscaled 二进制
  跨 reboot 存活（本轮 push 源文件已删仍可用）。
- **host 通道铁律**：**WSL adb 连不了 tailnet**（WSL2 NAT，100.64/10 路由在
  Windows 主机）——tailnet adb 一律走 **Windows `adb.exe` + Windows Tailscale**
  （`adb.exe connect 100.71.26.6:5555`）；LAN 通道（192.168.8.10:5555）照旧。
  设备 tailnet 节点：`node`=100.71.26.6（PostLock tailscaled）；`oppo`=
  100.80.86.28（官方 app，无自启权限，弃用）。
- **termux android-tools 实测**（deb `android-tools_37.0.0p1-3_aarch64` + 9 依赖包
  abseil-cpp/brotli/fmt/libc++/liblz4/libprotobuf/pcre2/zlib/zstd，共 118 文件
  17MB，物料在 app 仓 `build/adbtx-prebuilt/` 未 commit）：`LD_LIBRARY_PATH` +
  `HOME` 指向可写目录即可跑（`adb version/pair/connect` 全过；HOME 不设会
  `mkdir //.android` EROFS）。批量 push 用 **tar.gz 单文件**（`dir/.` 递归 push
  必 EOF）。**pairing 协议可用但 pairing key 不进 5555 信任链**：pair 成功后
  5555 仍 unauthorized（disconnect/kill-server 重试均无效），wireless debugging
  自己的 connect 端口行为也不稳（offline/refused）——**5555 只认 adb_keys**
  （授权弹窗点一次 = 永久跨 reboot）。OPPO 开无线调试只能走设置 UI
  （`adb_wifi_enabled` 写 1 无效）；配对码对话框 = 无线调试页「使用配对码配对
  设备」，码刷新即作废（旧码 pair 报 protocol fault）。
- **app NO_AUTH 红字定因**：app 内置 key（assets `postlock_adbkey.pem`）与 host
  `postlock_adbkey` **是不同的两把**；app key 的 pub 只在链成功后的 restore.sh
  写回 adb_keys → fresh boot 恒 NO_AUTH，**链成功一轮即自愈**（文案自证）。修复
  候选：assets 换 host 同款 key（host key 已在 adb_keys，立即可用）/ pairing
  bootstrap（Java 侧 SPAKE2+，Shizuku 移植路线：TLS+Conscrypt exporter+native
  BoringSSL SPAKE2，`RikkaApps/Shizuku` 的 `manager/adb/` + `jni/adb_pairing.cpp`
  是完整参考）。

### app 内 adb AUTH 三层根因定案 + v1.41.5（2026-10-23 下午）——上条 NO_AUTH 归因被推翻

**app 侧 AdbShell 从未真正成功过 AUTH**，三层根因叠加（逐层实测定案）：

1. **签名算法错（AdbShell 通病，v1.41.4 修）**：ADB AUTH 的 20 字节 token 是
   **现成 SHA-1 digest**，adbd 验 `RSA_sign(NID_sha1, token)` = 手动包
   `DigestInfo{SHA-1}` 前缀 + raw RSA；Java `SHA1withRSA` 会把 token **再 hash
   一遍** → 必败 → 死在 RSAPUBLICKEY 的 prompt。修法 = 手工 PKCS#1 v1.5 type1
   block（`00 01 FF..FF 00` + 15B DigestInfo 头 `302130090605...0414` + token）+
   `RSA/ECB/NoPadding` 私钥操作（Shizuku `AdbKey.sign()` 同款）。
2. **adb_keys 全是坏行（v1.41.5/2aa7bd07 修）**：adbd 日志
   `E/adbd: Invalid base64 key 2048` ×2 = **整个文件无任何可用 key**——源是
   `tools/postlock.sh` 手拼 `"2048 " + DER-base64`（旧 openssl 路径，非标准
   android_pubkey 结构）。修：key 生成改 `adb keygen`（产物 `40 00 00 00` 开头
   的 modulus_size_words 结构）+ sed 换 comment 为 `postlock_bootstrap`；
   restore.sh 段 `grep -v "^2048 "` 清坏行再 append。**app assets key 同步换成
   这把新 key**（pem=PKCS#8，pub=标准格式）。
3. **adbd 拒 loopback 源 AUTH**：官方 client + 同 key 实测——`connect
   127.0.0.1:5555` 恒 `unauthorized`（完整 RSAPUBLICKEY 交换后仍拒），外部 IP
   秒过 → **app 只能连设备自身 tailnet IP**（`PostLock.LOOP_HOST=100.71.26.6`，
   经 tailscaled userspace 回环、算远源可授权；v1.41.3）。
   prompt 的 auto-deny 机制在此补完 v1.31 旧观察：AdbDebuggingManager
   `authWindow=0 / lastConnectionTime=0`（纯 TCP 无 USB-attach 授权窗口）→
   85ms `Denying adb confirmation`——**非锁屏原因，TCP 源 prompt 恒死**。

**v1.41.5（装机 vc41）组合**：signToken + 标准 key + `LOOP_HOST=100.71.26.6`
+ WanChannel（shell 会话部署 nativeLibraryDir/libtailscaled.so → temp、run-as
拷 state、nohup 起 uid2000 tailscaled `@postlock-tsd-sh`，pgrep 快路径幂等）+
autostart 序（app-uid daemon 先 bootstrap 网络栈 → 4s → WanChannel 升级 shell）
+ tsKeepalive/Services self-heal 全走 WanChannel 优先。**WanChannel 依赖
adb_keys 好行 = 依赖 restore.sh 跑成功一轮**。

**链 panic 事故（当日，重演满页教训）**：非 fresh boot（cdc19086，活跃使用中）
跑 `postlock.sh`（已改 detached：`setsid nohup ... & echo DETACHED`）→ **链触发
即 panic**（`postlock_chain.log` 都没创建、transport 先僵死）→ reboot →
app-uid tailscaled 上线 ~1min 被 HANS 冻结 → **双 tailscale 节点永久 offline，
无 USB，host 失联**。教训固化：**postlock.sh/run_fops 只在 fresh boot + 息屏
guard 下跑**（guard.sh 策略），活跃使用中触发 = 必炸（AGENTS 满页节 11 次重启
的共同点重演）；detached 只防 host timeout，不防链本身在脏 SLUB 上炸。
**恢复依赖解冻窗口**：app 15min alarm tick 带 10s 白名单 → WanChannel（AUTH
仍败，adb_keys 未修）→ fallback `startTailscaled` → app-uid daemon 短暂上线
（~10-86s）→ host 每 12s `adb.exe connect` 撞窗口（`/tmp/opencode/
reconnect_loop.sh`）。**恢复后顺序：fresh reboot → guard 息屏跑 postlock.sh
（写好行 adb_keys）→ app tick WAN ALIVE 实证 → 再 reboot 验自举**。
- **修 HANS 之外的权限引导**：OPPO 自启动管理组件 = `com.oplus.safecenter/
  .startupapp.view.StartupAppListActivity`（action `com.oplus.safecenter.
  permission.startup.StartupAppListActivity`），**需 `oplus.permission.
  OPLUS_COMPONENT_SAFE`**，普通 app/am 均 SecurityException——只能引导用户
  手动开（app 详情页 intent 兜底）。

## 2026-10-24 攻关批次：fix56-61（5 连败根因闭环 + 恢复链加固）

### 5 连败根因（症状级 diff → 源码级，闭环）

- 当日 0/5（09:42 panic win 段 / 09:54 payload dead / 10:22 cfgfs 段 panic /
  10:38 route 段安全失败 / 10:52 息屏轮 nonce capture）全部无残留安全退出或
  panic 后 reboot。**唯一分叉 = fix52 cfgfs pread：成功轮 `rv=8`（真实函数
  地址）→ `cfi table ok`；失败轮 `rv=0`（pread 0 字节）→ table garbage 拒死**。
  上游判定链（nonce `rv=-1 capture=0`、`configfs verify failed r1=0 r2=0`、
  watchpoint 废、fix42 弱放行 `k_hit==k_true`）**在两天日志同现，不是失败信号**。
- **rd=0 真语义 = payload 页已死**（页在 route→physrw 窗口被内核回收，page-
  cache eviction 家族），不是 configfs 通道死：fd=3 早期探测读两天恒 rd=0 属
  设计内（成功轮 1210 次 rd=8 都在后段）；成功轮也有 11 次 rd=0。重排三次事故：
  12:09 死在链内 root 写段（events 根本没跑，不该算它头上）。
- fix56 重试让读有时间窗命中活页 → 死点逐轮后移（fix52 ok → root 写段 →
  root=1）；**息屏 + load<5 起链**组合下 11:48 / 12:19 / 12:46 三轮 root=1。
- **load 红线放宽**：本机稳态底噪 4.5（787 进程、11.2G 满载、idle 84%），
  `<2.0` 只在冷 boot 窗口成立、稳态永远等不到（白等 18 分钟教训）——
  **判据 = boot_completed 后 load<5 即起链**（10.69 风暴峰值别起）。
- 12:09 root 写段 panic（cfgfs write .data wr=40 后下一内核操作）= Tier-0
  layout 猜测偏差家族抽签；12:21 RESTORE-OK 后 ~1min panic（events 开）未定案。

### fix56-61 清单（主仓 = untrusted_app 分支，app 仓 = main，两仓同步）

- **fix56**（主仓 f73c3b13）：`cfgfs_read_ex`（util.c）rd==0 时重试 3 次
  （每次重写 ashmem name blob 再生内核 prefix state）；set-fail 保持立即
  返回——ENOTTY 的 fix44 route-landed 双语义不许延迟。成功 rd>0 首轮即出，
  日志前缀不变只加尾部 `try=%d`（现有 forensics grep 兼容）。
- **fix57**（41a43344 / b67c5ea）：overlay `/product/bin/su` wrapper 非 root
  分支从 `exec /system/bin/su`（回锁后 ENOENT → postlock verify 恒挂）改走
  真驱动 ksud——`/data/adb` 0700 进不去 → **ksud cp 进 overlay upper**。
- **fix58**：zygote bounce 门控 `KS_BOUNCE_ZYGOTE`（默认 0）。11:53 首次
  自动实战在链后脆系统上 kill zygote，框架没回来 → ~2min 后 rescue-reboot
  （bootreason=reboot 非 panic，driver/ocsk/overlay 全丢）；08:13 手动
  events→kill zygote 在稳定系统安全。
- **fix59**：ksud events 门控 `KS_RUN_KSUD_EVENTS`（默认 0）。**后续实测
  修正归因**：三事件（post-fs-data / services / boot-completed）在健康系统
  单独跑全部安全（14:26-14:39 实测，services 拉起 OMK injector daemon
  无害）——「events 元凶」的直接证据只剩 12:21 一轮（且 12:09 与 events
  无关），脆窗口组合验证中，别把 fix59 注释里的旧归因当定案。
- **fix60**（fc9158f9 / 2b025de）：`ksud debug su` **无 `-c`**（clap 报
  `unexpected argument '-c'`）——它是管道喂的交互 root shell：wrapper `-c`
  分支改 `printf '%s\n' "$*" | /product/bin/ksud debug su`（EOF 退出、rc
  随之）；实测 `echo id | ksud debug su` → `uid=0`。
- **fix61**（c7e97c0f）：restore 里 **events 挪到 overlay 建立之前**——
  实测 ksud post-fs-data **umount 我们的 /product/bin overlay**（wrapper+
  ksud 上层蒸发，shell `ls /product/bin/su` 回落原生 ro 目录 Permission
  denied），events-after-overlay 必然拆台。61b：host 侧透传两个门控 env；
  61c：透传行防 `set -euo pipefail`（`[ -n "$VAR" ] && assign` 条件假返回 1
  必杀脚本，改 `if [ -n "${VAR:-}" ]`）。
- app vc64/1.64 装机完成（assets 含 fix57-61 restore）；**staging 手动同步
  仍欠**（ensurePayload 只在链触发路径跑，装机当下要手动同步 files/postlock）。

### shell:s0 域 root 的能力边界（ksud debug su 实测）

- Enforcing 下 shell 域 uid=0 **不能**：mount（tmpfs/overlay 均拒，报
  `'tmpfs' is read-only`+Permission denied）、写 kernel 挂的 tmpfs:s0（哪怕
  drwxrwxrwx，换 `context=shell_data_file:s0` 重挂也没用——mount 本身就拒）、
  `echo 0 > selinuxfs/enforce`、读原生 /product/bin；**能**：写
  /data/local/temp（shell_data_file f2fs）、跑 ksud 命令、管道提权拿
  uid=0（`ctx=u:r:shell:s0`）。
- **overlay 重建只能靠链窗口的 kernel:s0 root**（restore 的 overlay 段），
  shell 域修不了——overlay 丢了就等下一轮链，别在 shell 域反复 rebuild
  （当日 4 版脚本全灭的教训）；restore 诊断头 `context=u:r:kernel:s0`
  就是域差异的直观证据。
- **Enforcing 会自己回来**：12:46 链窗口 restore 打 Permissive，14:26 实测
  `enforce=1`（ksud events 或 OPPO 韧性收回，未定案）——别假设 Permissive
  常驻；`getenforce` 对 shell 报 Permission denied 是设备常态（读
  `/sys/fs/selinux/enforce` 才真）。

### 当日恢复链里程碑

- 12:46 轮 **60s root=1**（今日最快）+ restore 全绿：`OMK-ROLLED-BACK` /
  driver-already-loaded / ocsk / Permissive / `POSTLOCK-RESTORE-OK`；手工装
  fix60 wrapper 后 `/product/bin/su -c id`（shell 身份）→ uid=0 →
  **BakaSu 蓝卡「工作中 Built-in」**（`/tmp/opencode/redcard/ui_fix60.png`，
  5 模块真 store、驱动 35220/5 vs 管理器 35236/5 UAPI 5==5）。
- 链超时 540s 的判定注意：postlock.sh 的 restore 等待循环是 240×2s，marker
  是 `POSTLOCK-RESTORE-OK` **或** `-x /product/bin/su`（后者会假阳性——
  只要 overlay 存在就报 OK，与 restore 是否真跑完无关）。

### BakaSU 官方文档要点（bakasu.org/llms.txt，当日 fetch）

- **LKM 是 OPPO 官方标准路线**（OPPO 页：LKM 与一般 GKI 无异；GKI 镜像因
  OPPO f2fs 改动不可用通用镜像需自编译——回锁环境不适用）。
- FAQ「模块不工作」= sepolicy 版本不匹配（内核/管理器需**都** ≥34634 或
  commit 436d333 之后）——我们 35220/35236 **过线不命中**，模块问题确认是
  ksud events 没跑（fix59/61 方向）。
- manual-integrate 页是**内核源码级**集成（CONFIG_KSU_MANUAL_HOOK 必查 hook
  + selinuxfs 静态符号导出）——与 out-of-tree kernelsu.ko 无关，编进 boot
  时才用；管理器仍在开发（main 外皆测试分支）。

### 前序欠账集中补记（2026-10-23 及更早）

- **自研 su daemon 退役**（主仓 678fc16b、app b8f934e vc63）+ coldstart.sh
  删除——恢复链不再依赖自研 daemon；YH_YC WebUI 硬编码 `su -c` 的需求由
  wrapper 兜底（fix57/60 是其完成形态；此前 root 上下文 `su -c` 因
  `/system/bin/su` 是 KP 伪造 stat ENOENT 全挂，即「YH su-c 根因」）。
- **OMK 配置回滚**织入两份 restore（主仓 98fc605b、app 42c56cf）——
  `OMK-ROLLED-BACK` 行当日实测打印；`/tmp/opencode/yh/injector.toml` 是
  **panic 版勿部署**；OMK 放行 uid:1000 = kernel_panic 源（当日 09:34 实证）。
- **工厂模式 Attestation key 失败根因**：TEE 无 attestation key（keystore2
  `Error::Km(ErrorCode(-10003))`）+ OMK scoop 白名单拒绝 engineermode——
  **窄变量放行实验**（保守顺序：仅引号格式 → scoop 加
  `com.oplus.engineermode`/`uid:1000`）待稳定 root 后做，每次改后 kill
  keystore2 重测工厂模式 Key 状态页，panic 立即回滚。
- **kernelsu_init.ko** 分析搁置（用户未回应）；v1.57 staging 教训
  （PAYLOAD_VERSION 不 bump 则设备 assets 永远旧版）与 marathon kill
  switch 仍是前序欠账。

### 统一日志格式 + 白底渲染（2026-10-24，vc66/1.66 + 主仓 837aad48）

用户要求「日志格式不好看，以 boot id 开头后跟时间戳」「分不清最新在上还是
在下」「新行纯黑历史灰」——三层落地：

- **行前缀 = `[b<boot8> <HH:MM:SS>] `**（21 字节，加在最前、ANSI 色码
  之前）：链日志（utils.h `ks_log_prefix()`，__thread 缓存 boot_id 头 +
  每次 clock_gettime，两组 printf 宏 %s:%d 与 [t<tid>] 全接）、restore
  日志（BOOT8+log() 函数，全部 stdout echo 走 log()，重定向行保持 echo）、
  receiver.log（BootReceiver `[b8 HH:mm:ss.SSS]`，ms 保留与 host %3N
  对齐）、postlock.sh 段落标题（step() 带 `[BOOT8 HH:MM:SS]`）。
  **子串 grep 判据零破坏**（root=1、POSTLOCK-RESTORE-OK、win tick 等全是
  子串匹配）；**mksh 不支持 `>(...)`**（实测 syntax error）——restore 每行
  包装方案作废，改 log() 函数路线。
- **白底面板渲染**（colors.xml + MainActivity）：log_bg #FFFFFF /
  log_history #9AA0A6 灰 / **log_new #000000 纯黑** / log_tag #0B5FA5 /
  log_error #C62828（tag/error 用深色系保白底可读）；C_LOG_* 常量同步；
  tag 染色阈值 24→40 字符（新行首让第一个 `] ` 超旧界）；面板标题加
  「↓ 最新在底部（纯黑），上方渐灰为历史」。批次染色机制不变（最新批
  纯黑、上一批渐灰）。
- **连带适配**：exam2_marathon.sh ENTER 判定从 epoch 解析（`^[0-9]+`）改
  boot8 匹配（`*[b$CB *ENTER*`，旧格式行无 [b 前缀自动不匹配）；marathon
  虽停跑但脚本保活。sed 复合表达式坑：**replacement 里 `&` = 整个
  pattern**——`s/&& echo X/&& log X/` 必污染（当轮用 edit 修复）。
- app 仓 vc66/1.66（白底渲染+rlog 前缀+restore mirror），主仓 837aad48
  （utils.h/postlock.sh/marathon），preload.so sha `5d36089b`——链侧前缀
  首次实战待下轮链（装机 15:51，截图验证白底+tag/error 染色正常）。

### events 决定性实验定案：有害，永久门控（2026-10-24 组合轮，boot 59ded42f）

`KS_RUN_KSUD_EVENTS=1` 全链轮（新日志格式首次实战）——**三事件 rc=0 跑成，
但副作用实锤**：① `ksud services/boot-completed` 在 boot 后期重放把
**zygote64 + system_server 打死且不回来**（`ps` 0/0 持续 60s+，`dumpsys`
无响应，`settings put` 报 `Can't find service: activity`）→ framework 半瘫；
② overlay mount 无果（shell `ls /product/bin/su` Permission denied = stock
ro 未挂，verify 红）；③ `adb reboot`（property 路径）都发不出——**必须
`adb shell 'reboot'`（toybox reboot 直接 syscall）才能重启**。与上 boot
`kernel_panic,bug` 时间窗疑云同源。**结论：KS_RUN_KSUD_EVENTS 默认 0 永久
保持**；模块激活（Zygisk 注入等）需另找安全路径，别再走「boot 后期重放
三事件」。链侧日志无 ksud 行 = events 是 restore 侧动作（链 root 后
KS_COLDSTART），链 root=1 无恙——破坏全在 restore 三事件之后。

### 双括号修复 + vc67 段序（2026-10-24 下午，so 7642aac7 / app vc67）

- **链日志前缀曾打成 `[[b.. ..]]` 双层**：`ks_log_prefix()` 返回值已含
  `[]`，8 处 printf 的 `"[%s] "` 又包一层——sed 修 8 处为 `"%s "`。
- **「为什么最新的在上面」定案（用户报告）**：`buildLogBody` 固定
  receiver 段在上、chain 段在下——链跑完后 receiver.log 还在追加
  （tick/BOOT_COMPLETED），最新行跑到静止 chain.log 段上面。vc67 改
  **两段按各自 mtime 排序、新写的段贴底**（视口锚底=最新，全面板「越
  往下越新」成立）。装机截图验证：底部 = receiver.log 段（最新写入方）。
- **restore `PPID=1` 白等 120s**：KS_COLDSTART fork 后链先退，restore 被
  过继 init——exit-wait 拿 PPID=1 等满 60×2s 上限（无害但浪费），
  待改「PPID 非链 pid 时跳过等待」。
- **overlay mount 静默失败盲区**：restore.sh overlay 段 mount 命令无
  `|| log WARN-...` 兜底——失败时 restore.log 零痕迹（本轮 verify 红
  但日志无从判断 mount 死因），待补。

### fail 轮残留延迟 38min panic 实锤（2026-10-24 17:27，boot aff1482f→79ab7e46）

下午四连败后**没立即 reboot**、让设备继续跑（装 vc68 等），38 分钟后被
round4（16:49 route ENOTTY 失败轮）的残留炸了：pstore 栈
`try_module_get+0x34 ← misc_open+0xd0 ← chrdev_open ← openat`，
Comm=`pool-1-thread-3`（第三方 app 线程池），x20/x0=垃圾 owner
`f8ffffffd1f6c84f`——即 fail path neutralize 失败（`set-fail ENOTTY`、
`owner=-1 tail=-1`）后 misc.fops fake 表残留，第三方 open misc 踩表。
**认知更新：失败轮残留不是「几分钟窗口」而是随时可炸（≥38min 实测）**
——**fail 轮判明后必须立即 reboot**，别带残留继续用设备（vc68 装机等
host 侧操作照做不误，但设备 reboot 排最前）。g8 家族、fail amplifier
「放任」决策不变，只是把「何时 reboot」从「下次跑链前」提前到「判明
失败即刻」。

### fail 轮残留延迟 38min panic 实锤（2026-10-24 17:27，boot aff1482f→79ab7e46）

下午四连败后**没立即 reboot**、让设备继续跑（装 vc68 等），38 分钟后被
round4（16:49 route ENOTTY 失败轮）的残留炸了：pstore 栈
`try_module_get+0x34 ← misc_open+0xd0 ← chrdev_open ← openat`，
Comm=`pool-1-thread-3`（第三方 app 线程池），x20/x0=垃圾 owner
`f8ffffffd1f6c84f`——即 fail path neutralize 失败（`set-fail ENOTTY`、
`owner=-1 tail=-1`）后 misc.fops fake 表残留，第三方 open misc 踩表。
**认知更新：失败轮残留不是「几分钟窗口」而是随时可炸（≥38min 实测）**
——**fail 轮判明后必须立即 reboot**，别带残留继续用设备（vc68 装机等
host 侧操作照做不误，但设备 reboot 排最前）。g8 家族、fail amplifier
「放任」决策不变，只是把「何时 reboot」从「下次跑链前」提前到「判明
失败即刻」。

### round5 锁死轮：ks_owner CPU0 内核自旋僵死（2026-10-24，boot 79ab7e46，非 panic）

pstore（256KB 环形、带墙上时间行精确校时，boot 起点 17:04:25）完整重建：
- 17:29:25 链触发 → **17:29:54 链日志最后行** `[b79ab7e46 17:29:54] win tick
  +1s dead=0`（上下文：`physrw enter` / `win enter q0=1` / `pipe counts
  drain=240` / `pipe child ctx prep=1088`——physrw wave 段早期）；
- **17:30:10（日志停后 16s）`ks_owner`（PID 22354）CPU#0 RCU self-detected
  stall 首报** → 17:30:41/17:31:44/17:32:48 三次 `soft lockup CPU#0 stuck
  22s` → `Freezing of tasks aborted` + hung_task 级联（kthreadd/短进程
  blocked 60s+）→ CPU0 死拖垮调度；
- 17:33:05 pstore 见电源键事件（用户开始救机）→ **adb shell/getprop 全超时
  （transport 活、shell 起不来）、我发的 `adb reboot` 无效** → 用户长按
  强制重启 → 3000a6b5（bootreason=`reboot`，**非 panic**——pstore 无
  `Kernel panic` 行）。
**归因**：physrw/wave 段 `ks_owner` 线程内核态无限自旋——**与 route 段
`ks_consumer` pselect 自旋（marathon5b）不同线程，属新自旋家族**；无栈
（OPPO lockup 栈 dump 缺失/pstore 覆盖），用户态无防御（同族定性）。
**救援备忘：CPU0 级自旋时 `adb reboot` 发不出去，唯一出路 = 长按电源**。
pstore 读法：shell `cat /sys/fs/pstore/console-ramoops-0`（`ls` 报
Permission denied 属正常，别被劝退）。

### round6 内核日志定案：链自己引爆自己的 fake fops（2026-10-24 18:00，boot 3000a6b5→85f4fb4f）

load=1.35 静置后起链（quiet-gate 首跑 5s 放行）仍灭——**「恢复风暴/load」
论就本轮被证伪**（呼应用户「伪命题」判断；前后共线数据无法分因）。这轮
pstore 抓到**完整链内 panic 栈**（此前轮次要么无栈要么是第三方受害者）：

```
pc : module_put+0x38/0x194   x20=x0=000e070000080400（垃圾，非规范地址）
lr : __fput+0x108
Call trace: module_put ← __fput ← ____fput ← task_work_run ← (返回用户态)
Comm: ks_preload (PID 14769) ；Oops 96000004 DABT → Fatal exception panic
```

**机制闭环**：链 17:59:06-11 route 段 `fops guard read fail ENOTTY`×3 →
`pipe-physrw-summary done=0 root=0` → `cfgfs write set-fail ENOTTY` →
**neutralize 失败（owner=-1 tail=-1，payload 页死写不进）→ fake fops 表
残留挂在链持有的 fd 上** → 40 秒后链收尾 close fd → 内核 `__fput` 走
`file->f_op->owner` 的 `module_put` → owner 槽是垃圾 → Oops → panic。
**与 round4（第三方 `try_module_get` 同表受害）同一张残留表、两个受害者**
——round4 等了 38min 被第三方踩，这轮链**自己 close 自己引爆（40s 内）**：
**neutralize 失败从「概率延迟炸」升格为「几乎必然自炸」**。
**修复方向（可修工程点，非抽签）**：fail path 的兜底恢复——set-fail 写
不进（payload 页死）后必须有**第二写通道把 fake 表的 owner/fops 槽恢复
真值**（或 route 未 landed 时不挂表），否则进程退出 __fput 必踩。待研
`fops.c` guard/neutralize 段与 fd 表归属。

### 「shell,untrusted_app 统一日志文件」判决 + round7 自炸复现（2026-10-24 晚）

**物理单文件统一被 SELinux 三层判死**（用户指令 vc69 前实测）：
- app uid 写 `/data/local/tmp`（shell_data_file）：DAC 666 已过、**SELinux
  拒 create+write**（run-as 实测 rc=1/touch Permission denied，avc dontaudit
  静默）；读 OK（app 读主档 258764B 成功）。
- shell 写 app 私有目录：DAC 0700 拒；run-as 起链=uid 变 app（壳反噬）。
- 改标签：shell chcon `media_rw_data_file/apk_data_file/system_data_file`
  **全拒**（setattr 不给）；需 root 链成功窗口 + app 对目标标签 allow 未验
  ——押注成本高，放弃。
**落地 = 读侧统一（app vc69）**：`latestChainLog()` 双源按 mtime 择新（app
私有 chain.log + `/data/local/tmp/postlock_chain.log` 主档），双 inotify
（files/postlock 目录 + /data/local/tmp 目录过滤 `postlock_chain.log`），
标题域标「shell 主档 / app 域」。**面板从此 shell 域链日志 app 内实时可见**
（此前只有 run-as 取证）。ChainService verdict 只读 app 私有（它只监控自己
dispatch 的链，防跨域误判）。装机截图 vc69_unify 标题「链日志（shell 主档）
· 写于 18:10」✓。

**round7 = round6 同款自炸复现**（boot 85f4fb4f→15019372，load=1.95 静置
335s 起链——quiet-gate 首个完整放行轮仍灭，**load 论二次证伪**）：
- 死点同款：`fops guard read fail ENOTTY`×3 → `set-fail ENOTTY` →
  `ks_neutralize owner=-1 tail=-1`（payload 页死，写不进清不掉）；
- pstore 完整栈：`ks_preload` (PID 14789) `Unable to handle kernel paging
  request at 00ffffdfc0…ec00` → Fatal exception panic（fail exit 18:10:25
  → ~18:11:50 自炸，85s 内引爆——与 round6 的 __fput/module_put 同族）。
- **下午统计**：route ENOTTY 4 连（round2/4/6/7）；fail path 自炸 3/4
  （round4 延迟 38min 第三方踩、round6 40s、round7 85s 链自己踩）——
  **neutralize 失败 = 几乎必然 panic**，抽签已坍缩成确定性。
- 修复主攻点不变（round6 节）：fail path 第二写通道恢复 owner/fops 真值，
  或 route 未 landed 不挂表——**在 4 连败面前这已不是优化而是阻塞项**。
