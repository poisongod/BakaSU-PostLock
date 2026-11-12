# tools/tsu —— TrySU 执行体镜像（预编译产物）

这里的 `tsu` 是 **TrySU 执行体的镜像二进制**，不是源码。权威源码在体系自有仓
`../TrySU/cli/`（纯 Zig，`zig build`）。本仓保留镜像的唯一理由是**恢复链需要它**：
`tools/postlock.sh` 的 restore 段跑在 `u:r:kernel:s0` + Enforcing 窗口里，没有 Zig
工具链，stage 必须自带可执行文件。

## 它装到哪里

内核常量 `KSUD_PATH = "/data/adb/ksud"`（`../BakaSU/kernel/runtime/ksud.h:7`）是
sucompat 的契约落点：任何 allow-list 进程 exec `su` 时，内核完成提权后执行
**这个路径**，并把 `argv` 原样透传。所以 `tsu` 的部署位置就是 `/data/adb/ksud`
（覆盖 BakaSU 的 Rust ksud）。

restore 段做两件事，互不干扰：

| 目标 | 内容 | 使用者 |
|---|---|---|
| `/data/adb/ksud` | `stage/tsu`（优先）或 `stage/ksud`（回落） | 内核 sucompat 落点 → 所有 `su` 会话 |
| `/data/local/tmp/ksud` | `stage/ksud`（BakaSU Rust 版） | restore 自身、host 排障、`/product/bin/su` wrapper |

即：**`su` 会话走 `tsu`，restore/host 的调试 CLI 仍用 Rust ksud**。两者都不改内核。

## 为什么不用 Rust ksud 当执行体

`tsu` 只做四件事：解析 `argv` →（可选）进 VN → exec 目标 shell →（`--trysu-status`）
自述。它不提权、不装 fd、不判 allowlist（准入是内核 sucompat 的职责），也不带
boot patch / 模块管理 / SUSFS CLI / magica 这些无关越权面。契约见
`../TrySU/docs/trysu-implementation.md` §2.3。

## 构建（改完 `cli/` 必须重跑）

```sh
tools/tsu/build.sh          # 内部 cd ../TrySU/cli && zig build check-cli，然后镜像
```

校验两端一致：

```sh
sha1sum ../TrySU/cli/zig-out/bin/tsu tools/tsu/tsu    # 两行必须相同
```

`build.sh` 会先跑 `zig build check-cli` 的六道闸门（source-residue /
artifact-size / binary-trace / elf-type / elf-interp / elf-needed），任一不过
就不会镜像。

## 当前产物

| 项 | 值 |
|---|---|
| 版本 | `0.3.0` |
| size | 14816 B |
| sha1 | `05d486e6fff01817caafa9f8f35f44812d5c2c2d` |
| 类型 | `ELF 64-bit LSB pie executable, ARM aarch64, static-pie linked, stripped` |
| INTERP | 无 |
| NEEDED | 无 |

## 判据脚本（两层，别混用）

| 脚本 | 前提 | 覆盖 | 现状 |
|---|---|---|---|
| `rows.sh` | **冷 boot + `postlock.sh`**（落点已是 `tsu`、ko 已加冕） | T0–T7：落点 sha1、内核 `manager pkg:`、`su -c id`、`--vtz` 进 VN、`-M` 优先级、`access.log`、回归 | 待冷 boot。当前落点仍是 Rust ksud / 旧 ko，按设计会判 T0/T2/T4/T5 FAIL——**那是诚实结果，不是脚本缺陷** |
| `direct_probe.sh` | 只要本 boot 有 root（`su -c`） | D1–D8：以 `uid=0` + `u:r:ksu:s0` 直调 `tsu`，验自述/权能/argv/真进 VN/`-M`/`access.log`/fail-closed | **已跑通，PASS=22 FAIL=0 INFO=2**（boot `11e3bdc8`） |

为什么分两层：T0/T1 是「部署 + 内核加冕」，只有冷 boot 能给；T2–T6 是「`tsu`
收到契约凭证后是否做对」，而 `su -c` 直调给的就是同一套凭证（`uid=0`、
`u:r:ksu:s0`、`CapEff` 非零、`Seccomp=0`）。所以先用直调把语义钉死，冷 boot
只验交付链路。

```sh
# 落点模式（冷 boot 后）
su -c 'sh /data/local/tmp/tsu_rows.sh'

# 直调模式（任意有 root 的 boot）
adb push tools/tsu/direct_probe.sh /data/local/tmp/
adb shell "su -c 'sh /data/local/tmp/tsu_direct_probe.sh'"
```

**直调模式验证了什么（实测，boot `11e3bdc8`）**：`--vtz` 真进 `VN`
（`mnt:[4026534014]` == sidecar inode，`via=sidecar`）、`--trysu-ns <pid>`
第二条入口（`via=ns-explicit`）、`-M` 优先于 `--vtz`（回到 init ns）、
`access.log` 两行 `kind=enter`、四条 fail-closed（参数冲突 / `-l` / 无 sidecar
`no W registered` / sidecar inode 不符）全部 exit 2 且不假装成功。

**直调模式不能声称的**：① 未经内核 `KSUD_PATH` 交付 argv（T0/T1 才验）；
② 直调进程 `driver_fd=<none>`（本版 `tsu` 不读驱动 fd，但落点处 fd 就位仍属 T1）；
③ `access.log` 在 VN 侧 tmpfs，随 holder 销毁——设计如此。
取证：`docs/forensics/tsu-direct-11e3bdc8/`。

## 纪律

- **不要手改这个二进制**，也不要手改 `build.sh` 里的镜像来源。
- 改了 `tsu` 就同时提交 `../TrySU`（源码）与主仓（镜像）；两边 sha1 必须一致。
- 设备侧换二进制需要一次冷 boot + `tools/postlock.sh`（restore 窗口才能写
  `/data/adb`，它 0700 root 属主）。
- **不要为了「验一下」直接替换 `/data/adb/ksud`**：它同时是唯一 root 入口
  （`/system/bin/su` 与之同 inode），`tsu` 若有问题会连回滚通道一起丢
  （`/data/adb` 0700 root）。要验语义用 `direct_probe.sh` 直调 `/data/local/tmp/tsu`。
