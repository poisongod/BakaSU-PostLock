# 冷 boot 恢复 + suvtz 复测（boot `898d3136`，2026-11-06）

## 背景

`docs/susfs-acceptance.md` 的 r4 验收（boot `1e831bc4`，37 PASS / 0 FAIL / 3 INFO）
跑完后设备处于「带 SUSFS 标记」状态：`uname -r` 被伪造、`/system/bin/toybox` 对
app 域隐藏、`/system/etc/security/otacerts.zip` 被重定向。SUSFS 的
`SUS_PATH` / `SUS_MAP` / `SUS_KSTAT` / `OPEN_REDIRECT` / `SPOOF_CMDLINE` 都没有
DEL 命令，**只能靠重启清除**。本轮即为此后的重启 + 冷 boot 恢复 + suvtz 复测。

## 结果

| 项 | 结果 |
|---|---|
| 干净 boot | `uname -r` = `5.4.254-qgki-g977b99b1fbb9`（真实，非伪造） |
| | `/system/bin/toybox` 对 app 可见（SUSFS 标记已清） |
| 链 | `pipe-physrw-summary done=1 root=1` ×3，`CHAIN_EXIT_DONE` |
| | `ks_neutralize ... ok=1 verified=1`，exit tail 干净（无 fd-hold 残留） |
| restore | `SELINUX-STRICT-OK enforce=1 probe=host-verify` + `POSTLOCK-RESTORE-OK` 双 OK 原生 |
| | `enforce=1` |
| 内核模块 | `kernelsu`=YES / `oplus_check_suppress`=YES / `kernelsu_hotload_init`=NO（legacy 按设计不加载） |
| ocsk v14 | `kill.scan sites=2` + `ret.kill off=268/+a30 ret=0` + `rep armed=2` |
| su 通道 | `/product/bin/su -c id` → `uid=0 … context=u:r:ksu:s0` |
| 管理器 appid | 动态解析 = `10277` |
| suvtz | **6 FAIL / 24 PASS / 0 INFO**（与上轮同值，无回退） |

## suvtz 6 个 FAIL（均为已知、设计内暴露面）

| 探针 | 值 | 说明 |
|---|---|---|
| A1 管理器包可枚举 | `com.resukisu.resukisu` | 管理器必须可被用户启动 |
| A2 工具包可枚举 | `com.postlock.boot`、`com.postlock.privateapp` | PostLock-Boot 已冻结但仍在设备上（SUSFS 自检载体） |
| B4 `/product/bin/su` 存在 | 412B wrapper | su 通道本身 |
| B10 KASLR 参考可读 | `ksu_kaslr` | app 域 gate 输入；本轮已手写回占位值，防同 boot 二跑链 |
| D1 `persist.adb.tcp.port` | `5555` | 恢复通道 |
| E2 mountinfo 暴露 overlay | 1 | `/product/bin` overlay |

## 本轮踩到的两件事

1. **`postlock.sh` 的 900s 超时切在「等 restore」段**：stage push 15MB
   `kernelsu.ko` 经 tailnet relay 耗时 ~14 分钟，脚本被 `timeout` 杀死在
   `wait for restore` 之后。链本身是 detached 的，继续跑完并成功；但脚本末尾
   的步骤（含把 `ksu_kaslr` 写回占位）没有执行，故另用手动写入补上。
   **教训：tailnet 通道下 stage push 时间不可忽略，超时预算需 ≥ 25 分钟。**
2. **设备熄屏休眠会同时断掉 tailnet 与 LAN 的 adb**：restore 完成 ~4 分钟后
   设备 `offline`，`adb connect` 超时；唤醒屏幕后 Wi-Fi 以新的 DHCP 地址
   (`192.168.137.10`) 回连，`adb connect` 立即成功。期间跑的 suvtz 首轮
   整段 `INFO`（runas 域不可用）实为**设备断网导致 adb 命令失败**，非
   `run-as` 本身问题 —— 通道恢复后 `run-as com.postlock.boot id` 正常
   (`uid=10287 … runas_app`)，重跑 suvtz 得 6 FAIL / 24 PASS。

## 文件

- `chain.log` — 本轮链日志（1540 行）
- `restore.log` — restore 全量日志（含 ocsk v14 state dump 与双 OK）
- `suvtz_scan_898d3136.txt` — suvtz 30 探针原始输出
- `ui_main.png` — 管理器主页状态卡（蓝卡「工作中 Built-in 越狱模式」、
  驱动 `(35222/6)` ↔ 管理器 `(35252/6)`、SuSFS `v2.3.0`）
