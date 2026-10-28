# verify 卡点考古：ksud debug su 静默失败（2026-10-28）

## 症状

严格判据考试轮（exam3, boot 32f5e04c）链/restore/双 OK 全过，host verify
的 `/product/bin/su -c id`（= wrapper → `printf | /data/local/temp/ksud debug su`）
**rc=0 零输出**——su 管道无 uid=0 输出 → verify 红 → 轮判失败。

实测形态（全部 shell uid，enforce=1，三模块已载）：
- `ksud debug su` rc=0、<0.3s 退出、零输出（stdout/stderr 均空）；
- stdin 喂 `exit 42` → rc=0（对照 `sh < 同文件` rc=42）；
- stdin 喂 `sleep 30` 文件 → 立即退不执行；
- 密采样 /proc 无 sh 进程留存、无 uid0 进程。

## 决定性实验

**PATH 前置 mybin/sh**（echo 标记 + exit 77）：
- 对照 `env PATH=mybin:/system/bin sh` → MY_SH_EXECUTED + rc=77 ✓；
- `env PATH=mybin:/system/bin ksud debug su` → 零输出 rc=0（mybin/sh 未执行）。

→ **`Command::new("sh")` 的 exec 从未发生**（若 exec 必经 PATH 命中 mybin/sh）。

## 根因链（当前最优解释）

1. **设备 ksud 二进制版本吞 Err**：当前 BakaSU 源码（8450dd28 工作树）
   `su::grant_root` 无 Ok 路径（尾部 `Err(command.exec().into())`）；所有
   失败路径 Err → main → rc=1 + stderr "Error: ..."。实测 rc=0 无 Error
   = **设备 ksud 的 cli 是 `Debug::Su => { grant_root(); Ok(()) }` 类结构
   （吞 Err）**——版本行为与当前源码不符。
2. **Err 本身来源**：kevent 实锤 `reboot(magic)` fallback 已发生
   （`sys_call_number@@29`、`old_euid@@2000`、`curr_uid@@0`、
   `curr_name@@ksud`）——init_driver_fd 的 scan 无 fd → fallback 走了；
   之后 fd 装载或 GRANT_ROOT ioctl 阶段失败（具体未定，见下）。
3. **设备 ksud ≠ 任何本地已知产物**：
   - 设备 `/data/local/temp/ksud` 5955504B sha `1a45cddd`（restore cp 自
     /data/adb/ksud）；
   - `build/embed/ksud` 4556352B sha `5f71a2a0`（Sep 26 老版）；
   - ../BakaSU 本地无 ksud 编译产物（target/ 空）。
   - 版本串 `v4.2.0-rc3-8450dd28-dirty@BakaSU` 与工作树 dirty 自洽，但
     行为差异证明是**更早 dirty 状态的编译产物**（userspace/ksud/src 现为
     clean，mtime 09:51 checkout 时间）。

## 排除清单（确定性，全部实测/代码验证）

- PATH 劫持：env -i 干净 PATH 依旧 rc=0 零输出；
- allowlist/profile：`allow_shell && uid==SHELL_UID` 短路 → shell 恒用
  default_root_profile（uid=0/gid=0/full caps/ksu:s0）；
- `ksu_boot_completed`：仅 allowlist prune 使用，不在 su/exec 路径；
- run() 吞 Err：尾部直接 `result`（Err 必 rc=1）——**但设备 ksud 版本可能
  不同（见根因链 1）**；
- with_svc_call：仅 TLS 标记不动 stdio；
- pre_exec closure：global_mnt=false 时空操作不动 stdio；
- exec 的 sh 候选：assets 无 `sh` 有 busybox（extract-binary 实测）→
  /data/adb/ksu/bin/sh 不存在（PATH 查找跳过）→ 必落 /system/bin/sh；
  /product/bin/sh 假说被 env -i PATH 实验排除；
- `KSU_IOCTL_GRANT_ROOT_RUST`：宏 `DEFINE_KSU_UAPI_CONST` 同时生成
  `_RUST` 后缀（同值 _IO('K',1)），内核 dispatch 有 GRANT_ROOT handler；
- `allowed_for_su()`：`is_manager() || ksu_is_allow_uid_for_current(uid)`；
- 内核 reboot kprobe（reboot_handler_pre）：正常调 handler，无 uid 拒绝。

## kevent curr_uid=0 之谜（未定案）

OPLUS_KEVENT 的 reboot 监控记录 `curr_uid=0`（syscall 29 时刻）——若可信
则 GRANT_ROOT ioctl 时 uid=0 → allowed_for_su(0) = false（0 非 manager 非
allow）→ ioctl -EPERM → Err——**与吞 Err 后 rc=0 完全自洽**。但
`ksu_handle_sys_reboot` 只装 fd 不改 cred，kevent hook 记录 curr_uid=0 的
时机/语义未定（可能 hook 在 cred 读取上有特殊处理，不可全信）。

## 下一步（分辨实验）

1. **重编当前源码 ksud**（rustup target aarch64-linux-android + NDK
   linker，.cargo/config.toml）→ push 设备测 `debug su`——当前源码不吞
   Err，**rc=1 + "Error: ..." 内容即定案 Err 来源**（fd bail vs ioctl EPERM）。
2. 若 Err = fd 阶段 → 深挖 reboot fallback 装 fd 在 shell uid 下的失败点；
   若 Err = ioctl EPERM → allowed_for_su/kevent uid=0 方向。
3. 下轮 fresh boot 实验 A 对照：restore 跳过 hotload finitmod → 测 su
   （hotload 是早上成功轮与现在的唯一实质环境变量——若新 ksud 显示 Err
   与 hotload 无关则此实验可省）。

## 教训

- **ksud 二进制版本管理缺失**：/data/adb/ksud 由历史轮链 self 路径写入，
  版本不可追溯——恢复链应校验 ksud sha 与预期一致（或统一从 build/embed
  / 明确产物部署）。
- rc=0 ≠ 成功：Rust 吞 Err 的版本行为会把失败伪装成成功——verify 探针
  必须验输出内容（uid=0）而非只看 rc。
