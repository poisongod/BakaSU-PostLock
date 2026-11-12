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

## 纪律

- **不要手改这个二进制**，也不要手改 `build.sh` 里的镜像来源。
- 改了 `tsu` 就同时提交 `../TrySU`（源码）与主仓（镜像）；两边 sha1 必须一致。
- 设备侧换二进制需要一次冷 boot + `tools/postlock.sh`（restore 窗口才能写
  `/data/adb`，它 0700 root 属主）。
