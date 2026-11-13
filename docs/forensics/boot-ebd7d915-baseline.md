# 冷 boot 基线：`ebd7d915`（事故恢复 boot + 新 ko 首次上机）

> 设备 PFUM10 / `100.120.155.127:5555`，内核 `5.4.254-qgki-g977b99b1fbb9`。
> 本 boot 由 `docs/forensics/overlay-probe-leak-11e3bdc8.md` 的探针事故触发
> （用户手动 reboot），因此同时是**恢复验证**与**新 ko 首次冷 boot** 两个事件的合体。

## 1 恢复验证（事故后）

| 项 | 观测 | 结论 |
|---|---|---|
| boot_id | `ebd7d915-4e41-4ff4-b4bb-7b28d4f6c424`（旧 `11e3bdc8`） | 已重启 |
| 挂载污染 | `grep -cE "vn_probe6\|ovltest" /proc/mounts` = 0 | 清零 |
| `/system` | `ls /system/build.prop /system/bin/sh` 可读 | 正常（erofs 原样） |
| `/metadata` | 11MB 可用，临时目录已清 | 正常 |
| `postlock.sh` 首轮 | verify 报 `sucompat entry` 失败（21:02），但 restore 实际在 21:04 完成 | 见 §4 |

## 2 T0/T1 与判据

| 项 | 观测 | 结论 |
|---|---|---|
| T0 落点 | `/data/adb/ksud` sha1 `05d486e6…c2c2d`（tsu 0.3.0），与 `/system/bin/su` **同 inode 614862**、14816B、`root:root 0755` | **PASS** |
| T1 VN 进入 | `su --trysu-vn -c 'readlink /proc/self/ns/mnt'` → `mnt:[4026534120]`；N 侧对照 `mnt:[4026533362]` | **PASS** |
| tsu 自述 | `tsu 0.3.0`，`uid=0`，`context=u:r:ksu:s0`，`CapEff=0000003fffffffff`，`Seccomp=0` | 符合 |
| VN holder | pid 10857，`mnt:[4026534120]`，comm `wns`，sidecar `[10857 4026534120]` | 有效 |
| `tools/tsu/rows.sh` | `PASS=12 FAIL=0 INFO=4 RESULT: OK`（T0–T7） | **全绿** |

## 3 驱动（新 ko 首次上机）

| 项 | 观测 |
|---|---|
| stage ko | `/data/local/tmp/ksu_boot/kernelsu.ko` sha1 `b2a3f1667ebf79981ee7f2c5e29fbe469496401f`（15,494,152B） |
| 已加载 | `/proc/modules`: `kernelsu 458752 0 - Live (OE)`、`oplus_check_suppress 20480 0 - Live (OE)` |
| 新增调试面 | `/sys/module/kernelsu/parameters/ksu_dbg_*` 共 20+ 项（`ksu_dbg_kp_*`、`ksu_dbg_stage`、`ksu_dbg_noallow`、`ksu_dbg_exec_fd` 等），另有 `enforce_on_load`、`ksu_debug_manager_appid`、`lookup_hook` |
| 版本标识 | `/sys/module/kernelsu/version` 不存在 → `tools/susfs/accept.sh` 的 `driver:` 字段为空（**非缺陷**，仅观测） |

> **结论：`b2a3f166` 从"未上机"转为"已冷 boot 验证"**。这是 T0 之后第一次用新 ko 跑完整判据，
> 结果与旧 ko `e78ec0c6` 的 baseline 一致（`rows.sh` 12 PASS）。

## 4 `postlock.sh` 首轮"假失败"

- 21:01:57 触发 exploit，chain log 出现 `payload did not land` / `prepare_kernel_page retry 3/72`
  （KASLR 碰撞概率性未命中），21:02:29 poll 判定 `restore OK` 后 verify 失败退出。
- 但 21:04 落点实际完成（`/system/bin/su` 出现、`su -c id` 正常）。
- **教训**：`postlock.sh` 的 verify 窗口早于落点最终生效（restore 是 detached + 后台 fork），
  首轮 verify FAIL **不等于**恢复失败；重试前应先 `su -c id` 实测，避免重复触发 exploit。
- 建议（P1 一并改）：verify 改为「轮询 `su -c id` 至超时」，而非单次检查。

## 5 回归

| 脚本 | 结果 |
|---|---|
| `tools/suvtz/scan.sh -q` | `FAIL=0（另有已接受 3） PASS=37 INFO=0 总计=40 runas=ok` |
| `tools/susfs/accept.sh` | `PASS=37 FAIL=0`（注意：`SUS_PATH/SUS_MAP/SUS_KSTAT/OPEN_REDIRECT/CMDLINE` 标记不可撤销，需重启清除） |
| `tools/suvtz/v0a_rows.sh`（设备侧） | R1–R10 观测全部符合预期；R8 `rc=2` + `no W registered` 为设计语义 |

> `v0a_rows.sh` 是 `#!/system/bin/sh` 设备侧脚本，**必须在设备上跑**；
> 在 host 用 bash 跑会调到 host 的 `su`（报「无效的选项 -- M」「密码：认证失败」），非脚本缺陷。

## 6 当前设备状态（基线快照）

- 可用通道：WiFi `100.120.155.127:5555`；USB serial 在 reboot 后未出现。
- root：`su -c id` → `uid=0` / `u:r:ksu:s0`（sucompat 路径，`driver_fd=<none>` 属预期）。
- VN：holder `wns` 10857 + sidecar 就位（**旧守护形态**，P1 将退役）。
- 未完成：`--trysu-ns` 仍存在；per-session 构造器未实现。
