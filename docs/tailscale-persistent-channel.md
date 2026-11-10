# Tailscale 持久化 adb 通道：架构与边界

> 状态：**已具备替代 USB 的条件**（2026-11-08 实测，多 boot 验证）
> 适用设备：OPPO A96 / PFUM10（Android 12，ColorOS）
> 配套实现：`PostLock-Boot` 仓 `com.postlock.wan` 包 + `tshealth` 探针
> 时间线式排障记录见 `AGENTS.md`「Tailscale 持久通道」与「WAN 通道抗 wedge」两节；
> 本文只讲**为什么这样设计**与**什么时候它会失效**。

---

## 1. 结论先行

USB 退场后，host 仍能拿到一个 `uid=2000(shell)`、`Enforcing` 的 adb 会话，
条件是同时成立四件事：

| # | 条件 | 由谁保证 | 失效表现 |
|---|---|---|---|
| 1 | `persist.adb.tcp.port=5555`，adbd 监听 `[::]:5555` | root 窗口里 `restore` 写 `/data/property/persistent_properties` | 端口不通 |
| 2 | `/data/misc/adb/adb_keys` 含 app 内嵌私钥对应的公钥 | 同上（restore 幂等 append） | `unauthorized` / `no auth` |
| 3 | 设备在 tailnet 上在线 | shell 域 `tailscaled` + watchdog | tailnet 侧 `offline` |
| 4 | host 侧 Tailscale 在跑 | 桌面端 | `adb connect` 超时 |

**四条里 1、2 是「一次性写入、跨 boot 持久」的**；3、4 是运行时状态，由自愈层兜。
因此日常使用不需要碰 USB，但**恢复出厂 / 刷机 / 清 `/data` 之后仍需要一次 USB**
把 1、2 写回去（写入动作本身依赖 root 窗口，而 root 窗口只能由 exploit 链打开）。

---

## 2. 为什么不能只做「app 起个 tailscaled」

最初的做法是 app 自己在 `BOOT_COMPLETED` 里拉起 `tailscaled`，结果稳定失败，
两次定因：

1. **HANS 冻结是 uid 级**。ColorOS 的 `OplusHansManager` 对整 uid 下
   `freezer:/frozen`，前台服务（FGS）、perceptible 状态都不免疫。app 域
   `tailscaled` 作为 phantom 进程连带被冻 → 冻结期不调度、socket 全断
   （`netd: destroyAllSocketForUid`），tailnet 掉线。
   → 观测判据：`/proc/<pid>/cgroup` 是否含 `freezer:/frozen`。
2. **app 域读不到 / 连不上它自己该连的东西**。`untrusted_app` 域对
   `@postlock-tsd-sh`（shell 域 abstract socket）`connect` 被 SELinux 拒
   （`dontaudit` 静默，只有 `Permission denied` 这一行），对 `perf_event`、
   `tracefs`、`/proc/modules` 也全部无权限。

所以 daemon 必须**跑在 shell 域（uid 2000）**：该域不被 HANS 冻结
（`cgroup 5:freezer:/` 恒为空），且具备 adb 回环能力。app 的职责从「当 daemon」
退化为「当启动器 + 当看门狗的外部监督者」。

---

## 3. 分层架构

```
L4  观测      tsd_health.log / tsd_watch.log / receiver.log / private.log
                 ↑ 只读，不参与控制
L3  自愈      wan_watch.sh (shell 域, 20s tick)
                 ├─ daemon 消失      → start_daemon
                 ├─ 地址集合变化     → restart_daemon net-change
                 └─ 每 3 tick 跑 tshealth health → 连续 2 次不健康且距上次重启 ≥300s → restart
L2  自举      LOCKED_BOOT_COMPLETED
                 → BootReceiver (directBootAware) → AutoStartService
                 → WanService → WanChannel.ensure
L1  承载      tailscaled --tun=userspace-networking
                 --socket=@postlock-tsd-sh --state=/data/local/tmp/ts.state
                 (uid 2000, PPID 1, 无 root, 无 TUN 设备)
L0  底座      adbd 监听 [::]:5555  +  /data/misc/adb/adb_keys 里的 app 公钥
                 ↑ 只在 root 窗口写入，跨 boot 持久
```

### L0 底座：为什么是「写文件」而不是 `setprop`

`setprop persist.adb.tcp.port 5555` 在**任何** SELinux 上下文下都被
`property_service` 拒（`tcontext=u:object_r:default_prop:s0`，
`permissive=0`——属性服务的检查不随全局 permissive 放行）。
可行路径只有直写 `/data/property/persistent_properties`（protobuf，30 字节条目），
由 init 在下次 boot 读取并应用。同理 `adb_keys` 是普通文件，root 可直接 append。

**这就是「一次 USB、长期无线」的物理来源**：两个跨 boot 持久物只需写入一次。

### L1 承载：`userspace-networking` 的取舍

| 选择 | 理由 |
|---|---|
| `--tun=userspace-networking` | 不建 TUN 设备 → 不需要 root / CAP_NET_ADMIN，shell 域即可 |
| `--socket=@postlock-tsd-sh`（abstract） | unix **sock_file** 被 SELinux EACCES（dontaudit 静默）；abstract 命名空间不受此限 |
| `--state=/data/local/tmp/ts.state` | 跨 boot 保留（`/data/local/tmp` 不随 boot 清），登录态免重登；CE 封存时也能读到 |
| 不带 `--socks5-server` | 健康判据已不需要 SOCKS5，留着等于多开一个本地代理端口（攻击面） |
| 单 daemon 策略 | app 域 daemon 只在「浏览器登录」时显式启动；生产 daemon 永远是 WAN（shell）那一个，避免双连互踢（同 NodeID） |

**代价**：userspace 栈不接管系统路由，所以设备上**其他 app** 不能通过 tailnet
访问内网；它只服务「本机 tailscaled ↔ tailnet 对端」这一条通路，对 adb 够用。

### L2 自举：Direct Boot 是必需项

`ts.state` 在 CE 存储（`files/`），锁屏未解锁时 `/data/user/0/com.postlock`
不可见、`BOOT_COMPLETED` 不投递。所以：

- manifest **只给三个组件**加 `directBootAware="true"`：
  `BootReceiver`、`platform.AutoStartService`、`wan.WanService`。
  **不加在 `<application>` 上**——否则链相关组件（`ChainService` 等）也会在锁屏被拉起，
  而链在 CE 封存时必失败，失败残留还可能在解锁后引爆。
- `LOCKED_BOOT_COMPLETED` 分支**只点火服务后 return**：不查 gate、不读开关、
  不跑 panic guard——那些都是链的事。
- 锁屏期禁跑链：`chainAllowed() = UserManager.isUserUnlocked`（探测异常 fail-open），
  `LAUNCH` 调试后门同样不破例。
- 开关读取必须**三态**：`flagOrNull()` 返回 `null` = CE 封存读不到，
  **绝不能当「用户关掉了」**（升级后第一次锁屏必然「DE 空 + CE 封存」，
  按 false 处理会让锁屏自启永远起不来）。`setFlag` 双写 DE（权威）+ CE（镜像）。

### L3 自愈：判据必须是端到端 ping

这是本文最重要的一条，也是踩坑最深的一条。

**错误判据（全部实测过，都会误判）**：

| 判据 | 健康态 | wedge 态 | 问题 |
|---|---|---|---|
| 进程存在（`pgrep tailscaled`） | 在 | **在** | 无法识别假死 |
| `BackendState` | `Running` | `Running`（陈旧） | 同上 |
| `Self.Online` | `true` | `true`（陈旧） | 同上 |
| peer `LastSeen` | **零值** `0001-01-01` | 陈旧时间 | 方向相反，用它会反向误判 |
| `ss -tn` 有 ESTAB | 有 | 有（含永不消失的陈旧连接） | 恒真 |

**正确判据**：`/localapi/v0/ping`（disco）——直接问 daemon「能不能 ping 通对端」。
健康态 `"Err":""` + 有 `LatencySeconds`；wedge 态 10s 超时无响应。

`tshealth` 三态退出码（`/data/local/tmp/tshealth`，静态 aarch64）：

| rc | 含义 | watchdog 处置 |
|---|---|---|
| 0 | 健康 | 清零 fail 计数 |
| 10 | 不健康（有响应但 `Err` 非空） | 计入 fail |
| 12 | 无法判定（无匹配 peer / 指定 peer 离线 / 无在线对端） | **按健康算**（防误杀重启循环） |
| 3 | localapi 打不通（daemon 卡死/超时） | 并入「不健康」 |

重启门控：**连续 2 次不健康 且 距上次重启 ≥300s**（`GAP=300`）。
健康检查本身 10s 超时 + daemon 冷启 ~40s，太密会连环杀。

**为什么不带 SOCKS5**：健康判据从「能否走代理访问外网」降级为「daemon 能否 ping
对端」后，SOCKS5 只增攻击面不增信息。`tshealth dial` 仅人工调试用（需自带 socks
参数起临时 daemon）。

---

## 4. 冷 boot 时序（实测，锁屏不解锁）

```
t+0s    reboot
t+?s    adbd 读 persist.adb.tcp.port → 监听 [::]:5555
t+?s    LOCKED_BOOT_COMPLETED → BootReceiver → AutoStartService → WanService
t+38s   WanChannel.ensure：回环 adb 拿 shell 会话 → 部署 tailscaled/ts.state
        → 启动 daemon（uid 2000, PPID 1）→ 部署并启动 wan_watch.sh
t+55s   tailnet 上线；host 侧 status 见节点 active
t+~60s  首个 tshealth rc=0
之后    每 20s watchdog tick，每 60s health 一行
```

首次尝试可能因网络未就绪失败（`ENETUNREACH`），`WanService` 有 30s / 90s 重试。
实测常见形态是 `attempt=1` FAIL → `attempt=2 -> ALIVE`。

**回环 adb 的两个硬约束**：

1. adbd **拒 127.x 源**的 AUTH（完整 RSAPUBLICKEY 交换后仍 `Denying adb confirmation`，
   85ms 内 auto-deny，因为纯 TCP 无 USB-attach 授权窗口）。所以必须走
   **hairpin**：连设备自身的非 loopback 地址。
2. `loopHosts()` 不能假设 IPv4 存在。实测有 boot 是**纯 IPv6 网络（零 IPv4）**，
   旧代码只枚举 IPv4 + 硬编码一个历史 tailnet IP，必败。现策略：
   非 loopback IPv4 在前（hairpin，源非 127.x）→ 全局 IPv6 在后（adbd 双栈）
   → 跳过 link-local（需 scope id）→ `LinkedHashSet` 去重。

---

## 5. 验收判据（可复现）

| 项 | 命令/位置 | 期望 |
|---|---|---|
| 通道 | `adb devices` / `adb -s <ip>:5555 shell id` | `device`（非 `unauthorized`），`uid=2000(shell)` `Enforcing` |
| 锁屏自举 | `dumpsys user \| grep -m1 "State:"` + `ps -A -o PID,PPID,UID,ARGS \| grep [t]ailscaled` | 仍 `RUNNING_LOCKED`，daemon `2000 1` |
| HANS 免疫 | `cat /proc/<pid>/cgroup` | `5:freezer:/`（不含 `frozen`） |
| 健康 | `tail -1 /data/local/tmp/tsd_health.log` | `rc=0 ... pong from ...` |
| daemon 崩溃自愈 | `kill -9 <tailscaled>` → 观察 `tsd_watch.log` | ≤20s `daemon gone -> start`，通道 ~55s 恢复 |
| wedge 自愈 | `kill -STOP <tailscaled>` | `health fail n=1 rc=3` → 106s 后 `n=2 -> restart` → 下一轮 `rc=0` |
| 持久性 | `uptime` + `ps -o ETIME` | 5h+ 单 daemon 不重启，health 99% `rc=0` |

---

## 6. 边界：什么时候仍然需要 USB

诚实清单。以下场景 Tailscale 通道**不能**替代 USB：

1. **恢复出厂 / 刷机 / 清 `/data`**——L0 的两个持久物被清空，需要 root 窗口重写，
   而 root 窗口要靠 exploit 链，链的 stage 与触发都依赖 host 侧脚本（USB 最稳）。
2. **设备完全断网**——无 Wi-Fi 且无蜂窝（飞行模式 / 无 SIM / 欠费）。
   tailnet 是应用层网络，物理断网无从谈起。
3. **系统级僵死**——内核 CPU0 自旋（`ks_owner` 家族）、panic 循环、zygote 死锁。
   此时 adbd 起不来，`adb reboot` 也发不出去，唯一出路是长按电源。
4. **首次配网**——新设备/新 Wi-Fi 需要人工在 UI 上连网，host 无法代劳。
5. **host 侧 Tailscale 不可用**——桌面端退出登录、tailnet 控制面故障、
   或设备被从 tailnet 移除。
6. **需要 fastboot 的操作**（刷 boot、回锁）——adb 通道与此无关。

**结论表述**：Tailscale 通道覆盖「设备已 root 过一轮、且系统活着、且能上网」的
全部日常运维场景（跑链、取证、装 APK、改配置、看日志）；它替代的是
**日常 USB 插拔**，不是**救砖 USB**。

---

## 7. 运维 SOP

### 7.1 通道不通的排查顺序

```
1. host: tailscale.exe status --json | 看节点 Online
   └ offline → 设备侧网络问题（或 HANS 冻结，见 4）
2. adb devices → 有 <ip>:5555 但 offline/unauthorized
   ├ offline      → adb disconnect <ip>:5555 && adb connect <ip>:5555
   └ unauthorized → adb_keys 丢了（需 root 窗口重写，即需 USB）
3. 设备可达但 daemon 不在
   → 跑一次 WanService（app 前台打开服务 tab 点「立即重建通道」）
   → 或等 watchdog（它只在 shell 域，app 冻结不影响它）
4. daemon 在但通道假死
   → /data/local/tmp/tshealth health ；rc≠0 时 watchdog 会自己重启（≤5min）
5. 全都不行 → USB（若物理可达）或长按电源
```

### 7.2 关键「不要做」

- **不要 `adb kill-server`**（本项目红线，会打断其他设备的会话）。
- **不要 `am force-stop com.postlock`**——会把包置为 stopped，害死下一次
  `BOOT_COMPLETED`（且 `LOCKED_BOOT_COMPLETED` 同样被 exclude），设备自锁到
  用户手动开一次 app 为止。要重启进程用 `kill -9 <pid>`。
- **不要杀/停 `com.tailscale.ipn`**（官方 app，节点 `oppo-a96-5g`）——它是
  锁屏/异常时的唯一外部生命线。
- **不要在跑着的 daemon 上直接覆盖 `ts.state`**——daemon 会用内存里的 prefs
  反向覆盖文件。顺序必须是 `pkill` → 复制 → 启动。
- **不要用 `setprop persist.adb.tcp.port`**——必被 property_service 拒，
  且失败是静默的（`permissive=0`）。

### 7.3 多设备现实

本机常年同时挂着 `401e909a`（PD2020，**非本项目，勿动**）与目标设备的
USB / tailnet 两条通道，裸 `adb` 一律报 `more than one device`。
所有命令必须 `-s`；`tools/postlock.sh` 用 `SERIAL=`，
`tools/suvtz/scan.sh` 自动枚举并排除 `401e909a`。
`ANDROID_SERIAL` 在 WSL 调 `adb.exe` 时**不生效**，只能显式 `-s`。

---

## 8. 已知限制与后续

| 限制 | 影响 | 后续方向 |
|---|---|---|
| 通道带宽受 DERP relay 影响（实测 relay 下推 15MB ko ≈14 分钟） | stage 全量推会超时 | 已修：`postlock.sh` 按 sha1 跳过未变文件（USB 0.42s vs relay 14min） |
| `tshealth` 依赖固定健康对端（默认 `desktop`，可 `/data/local/tmp/ts_health_peer` 覆盖） | 对端离线时退化为 rc=12 | 可扩为「任一在线对端 ping 通即健康」 |
| tailnet 上有历史僵尸节点（`node`/`node-1`/`postlock`/`oppo-a96-5g`） | 管理台噪音 | 需在 tailscale 管理台网页删除（无 CLI 凭证） |
| 锁屏期 app 域读不到 `ts.state` | 节点名迁移（`hostname=boot`）在锁屏期不生效 | 部署时已把 Hostname 烘进 `/data/local/tmp/ts.state`，故无实际影响 |
| 无 tailnet 凭证轮换机制 | 设备私钥长期不变 | 如需轮换，重跑 install 覆盖 `ts.state` |
| ~~熄屏后 Wi-Fi 休眠 → 节点整体 offline~~ | 熄屏即断通道 | 已修并实测，见 §8.1 |

### 8.1 熄屏断网与 WifiLock（2026-11-10 实测）

**失效模式**：屏幕熄灭后设备 Wi-Fi 进入休眠，tailnet 节点 `boot` 整体
`offline`（不是 daemon wedge——`tailscaled` 进程健康、`cgroup` 也不在
`frozen`），host 侧 adb 直接 `error: closed`。`svc power stayon true` 在
**未充电时不生效**，历史上只能靠「`screen_off_timeout` 拉到
2147483647 + 定期 `KEYCODE_WAKEUP`」硬顶，副作用是长时间亮屏耗电到
`shutdown,battery`。

**产品侧对策**：`WanChannel.ensure` 在服务开关检查通过后 acquire
`WIFI_MODE_FULL_HIGH_PERF` 的 `WifiLock`（tag `postlock:wan`），
`stop`/`uninstall` 时 release。WifiLock 是系统服务侧的登记（binder token），
**app 进程被 HANS 冻结不影响它**——这正是它能盖住熄屏窗口的原因。

**实测（boot `c0a9c70b`，vc86/1.86，`screen_off_timeout=60000`、
`svc power stayon false`、按 HOME 退到后台）**：

| 观测 | 结果 |
|---|---|
| `dumpsys wifi` 锁登记 | `WifiLock{postlock:wan type=3 uid=1000 workSource=WorkSource{10286}}`（type=3 = HIGH_PERF） |
| 采样（30 次 × 30s ≈ 15 min） | **`adb get-state` 30/30 = `device`，零掉线** |
| 屏幕状态 | 28 次 `wake=Asleep`、2 次 `Awake`（切灭屏前后） |
| `tailscaled` | pid 5382 恒定、`5:freezer:/`（**未被冻结**） |
| app 进程 | pid 23948 恒定、`5:freezer:/frozen`（**HANS 照常冻结，属预期**） |

即「app 被冻 + 屏幕熄灭」同时成立时通道仍在——说明保住 Wi-Fi 的不是 app 活着，
而是系统侧的 WifiLock 登记。收尾仍需把 `screen_off_timeout` 与
`svc power stayon` 恢复常规值（长亮屏会耗电）。

**未覆盖的边界**：app 进程被 o-kill **杀掉**（不是冻结）时 binder token 失效、
锁会被系统释放——那时只剩 Direct Boot 的 `LOCKED_BOOT_COMPLETED` 重新部署，
期间窗口内仍会掉线。

---

## 9. 一句话总结

**L0 用「写文件」绕开属性服务的硬限制拿到 adb 底座，L1 用 shell 域 daemon 绕开
HANS 冻结，L2 用 Direct Boot 绕开 CE 封存，L3 用端到端 ping 绕开「进程在≠通道在」
的假活判据。** 四层都只解决一个具体的、实测出来的失效模式，没有一层是「以防万一」。
