# Gola.md — 最终目标 / 完成路径 / 全部要求

> 更新：2026-10-14。设备**已回锁**（`verifiedbootstate=green`，原厂内核，APatch root 通道已消失）。
> 本文件是任务权威摘要；细节仍以 AGENTS.md 为技术底账。

## 一、最终目标

在 OPPO A96 PFUM10（adb `-s 5bf5bf85`，uid=2000 Tier-0，回锁 + 恢复出厂 + 已升级系统，
**无 root 无 su**）上，通过 CVE-2026-43499 跑通完整利用链拿到 root：

- 链**在 uid=2000 直跑**（静态 target layout + `perf_leak_text_base` 拿 text slide）；
- 成功标准：**boot_id 不变**（全程不 panic 重启）+ **干净退出**（rc=0）+ uid 2000→0；
- 拿到 root 后第一件事：`setprop persist.adb.tcp.port 5555`，实现永久无线调试。

## 二、完成路径

1. **修掉当前的确定性 panic（唯一拦路虎）**
   - 三次复现（boot 05a1d471 / e21a502c / c4f2464d）全部死在
     `open("/dev/ashmem")` → `misc_open` 跳 payload 页 fake 表 open 槽；
   - 每次 route `success=1` 后同点 panic，每次自动重启换 boot_id。
2. **静态取证定根因（完全基于 boot.img，不靠运行时猜）**
   - 已实锤内核 `CONFIG_CFI_CLANG=y` 且非 permissive → open 槽值错位 1 字节
     CFI 校验即 panic（日志 `at6f=ffffeb1b5e2f3800` 正是错位形态）；
   - 从 `/tmp/opencode/kernel.bin`（原厂 boot.img 提取，回锁后与设备字节级一致）
     提取 kallsyms（`extract_kallsyms2.py`，尚在调试）→ 拿 `misc_open`、
     `rt_mutex_adjust_prio_chain` 真实符号地址；
   - 反汇编 `misc_open`：确认 CFI 检查点 + open 槽加载偏移 0x70；
   - 反汇编 `rb_erase` / route store：静态判定写入 misc.fops 的值是否带 +1
     （VOFF 理论，`KS_PSELECT_FOPS_VOFF` 当前 =0；boot6 证据 VOFF=+1 曾成功）；
   - 结合仓库代码：`fops.c:734-753`（VOFF env）、`fops.c:1575+`（fix45 probe）、
     `util.c` fdset 构造。
3. **修复 → 构建 → 部署 → 复跑**
   - `make PROJECT=pfum10c48 -j$(nproc)`；
   - push 前后 **sha1 比对**；
   - 链分离启动：`nohup sh /data/local/tmp/run_fops.sh > /sdcard/chain_run.out 2>&1 < /dev/null &`
     + 轮询 `/sdcard/chain_run.state`；跑前确认无并发实例
     （`ps -A -o PID,ARGS | grep -E "[r]un_fops|[p]reload\.so"`）；
   - 日志：`/sdcard/chain5.log`（`KS_LOG_SYNC=1` 每行落盘，尾部即 panic 前动作）。
4. **root 达成后**
   - `setprop persist.adb.tcp.port 5555` 并验证 `adb connect`；
   - 验证身份：uid0（用 shell 2000 身份 `/product/bin/su -c id` 或直接 `id`）。

## 三、用户全部要求

| # | 要求 | 备注 |
|---|------|------|
| 1 | **回锁由用户自己刷，我不要管回锁，只考虑现状** | 现状=已回锁 green、无 root |
| 2 | 链只能 uid2000 Tier-0 直跑 | 静态 target layout + `perf_leak_text_base` |
| 3 | 构建 `make PROJECT=pfum10c48 -j$(nproc)`；adb push 必须 sha1 比对 | |
| 4 | 工作目录 `/data/local/tmp`；`KSUD_DST`/`KS_LOG` 前缀必须是 `/data/local/temp/` 或 `/data/local/tmp/` | |
| 5 | root 后先设 `persist.adb.tcp.port=5555` | 永久无线调试 |
| 6 | **完全基于 boot.img 确保稳定性** | 静态分析优先，不依赖运行时猜测/不可用原语（pstore/kallsyms/kprobe 均读不了） |
| 7 | 回复/思考全程简中；代码、命令、路径、配置键、专有名词保留原文 | 中文模式 + 防漂移 |

## 四、当前进度快照（2026-10-14）

- fix55 so 已在设备：`/data/local/tmp/preload.so`，sha1 `e7a97ac483bd001bcfcfa7a8d3928785a4902e22`；
- boot_id `c4f2464d-00f9-406d-8cd0-c65ddac7b20c`（第三次 panic 后未再重启）；
- 第三次 panic 日志已拉到 `/tmp/opencode/chain5_third.log`（136 行）；
- kallsyms 提取脚本 `extract_kallsyms2.py` 布局求解未中（relative_base 未命中），
  备选：独立 token_index 全图搜索，或直接按 fops.c fdset 构造 + 5.4 rb_erase 语义分析；
- 下一步：确认 route store 写入值是否 +1 → 定修复（VOFF 实验 / fdset 构造修正）→ 复跑。
