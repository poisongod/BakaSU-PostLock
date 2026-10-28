# WAN 通道恢复后执行预案（2026-10-23 事故）

## 事故摘要
- 非 fresh boot（cdc19086，活跃使用中）跑 `tools/postlock.sh` → 链触发即 panic（chain.log 未创建）
  → reboot → tailnet 双节点（node/oppo）offline 停在 panic 时刻（07:22）→ host 失联 ~1h+。
- 设备端 app = v1.41.5；BOOT_COMPLETED autostart/tick 未能恢复 tailnet（v1.41.5 tick 先跑
  WanChannel 12s 吃光 HANS 10s 白名单，startTailscaled 永远轮不到；不排除 install -r 后
  am start 静默失败致 app stopped → BOOT_COMPLETED 被 exclude）。

## 已备好（全部已 commit，待装机）
- app 仓 3 commits：
  - `336b7df` v1.42：tsKeepalive local-first（先 startTailscaled <2s，再 WanChannel）
  - `a0551fe` AdbShell 握手预算（TCP 4s / 首读 5s，CNXN 后回 12s）
  - assets：标准 key（adb keygen 格式，`40 00 00 00` 结构 + postlock_bootstrap comment）
  - APK: `../PostLock-Boot/postlock-app/app/build/outputs/apk/debug/app-debug.apk`（vc42）
- 主仓 commits：
  - `2aa7bd07` postlock.sh: adb keygen 标准 key + restore 清 `^2048 ` 坏行 + detached trigger
  - `c3c7441c` postlock.sh: 文件化 trigger（base64 push trigger.sh + nohup sh，run_fops 模式）
  - `03b84eae` AGENTS 三层根因定案
- host key 对：`build/work/adbkeys/postlock_adbkey(.pub)`（与 app assets 同源）

## 恢复步骤（通道一恢复立即执行）
1. `adb.exe install -r app-debug.apk`（vc42）→ **am start 显式看输出**（组件确认见 manifest）
   → `run-as com.postlock.boot cat shared_prefs/services.xml` 确认 `tailscale=true`。
2. 查 receiver.log 定案上次 BOOT_COMPLETED 到没到：
   `run-as com.postlock.boot tail -30 files/postlock/receiver.log`。
3. **fresh reboot**：`adb reboot` → 轮询撞 autostart 窗口（app-uid daemon 上线 10-86s）
   → `adb.exe connect 100.71.26.6:5555`（host reconnect_loop 已挂 4h）。
4. fresh boot + 息屏下跑 `ADB=/tmp/opencode/abw.sh bash tools/postlock.sh`
   （文件化 detached trigger 已修）→ 等 `POSTLOCK-RESTORE-OK` + adb_keys 好行
   （adbd 不再打 `Invalid base64 key 2048`）。
5. 验 app 内闭环：app tick/LAUNCH → rlog `ts keepalive: WAN alive (shell uid)`；
   `tailscale.exe status` node=active。
6. **验收 reboot**：再次 `adb reboot` → app autostart（startTailscaled→4s→WanChannel
   →shell daemon，boot+~20s，HANS 86s 冻结线之前）→ host 连续 10 分钟
   `adb.exe connect 100.71.26.6:5555` + shell id 全通。
7. 达标 → 回主线**考试二**（app 域全链 0/3，失败归零）。

## 铁律（本轮事故再确认）
- 链只在 **fresh boot + 息屏** 跑（postlock.sh/run_fops.sh），活跃使用中 = 必 panic。
- 禁 force-stop PostLock（自锁）；install -r 后必须 am start 且**看输出**。
- 通道：唯一 tailnet `adb.exe connect 100.71.26.6:5555`（node=shell/PostLock、oppo=官方 app）。
- 用户回来开一次屏幕/PostLock app 也能救（app 解冻 → tick flush → v1.41.5 下 daemon
  有机会上线；装 vc42 后 local-first 逻辑更稳）。

## 轮询
- `/tmp/opencode/reconnect_loop.sh`（4h，15s 间隔）→ 成功写 `/tmp/opencode/RECOVERED`。
- 查看：`cat /tmp/opencode/RECOVERED; TS="/mnt/c/Program Files/Tailscale/tailscale.exe"; "$TS" status`
