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

## 根因链（22:22 修正版——「吞 Err」假说被推翻）

**决定性对照（22:22 同分钟三连测）**：新编当前源码 ksud、设备旧 ksud、
mybin PATH 版——**全部 `Error: could not retrieve kernelsu driver fd`
rc=1**。旧 ksud 与当前源码行为一致（不吞 Err）——**吞 Err 假说作废**。

1. **直接根因 = `could not retrieve kernelsu driver fd`**（ksucalls.rs
   `init_driver_fd`：scan 无 fd → reboot(magic) fallback 后 fd 仍 <0 →
   ksuctl bail）。fd 拿不到 → GRANT_ROOT 从未发生 → 无提权无 exec。
2. **fd 获取状态同 boot 内变化（未定案的核心疑点）**：
   - 20:36-21:19：info 输出 `Kernel Version: 35220`（ioctl 成功=fd 成功）；
     期间 su 实验 rc=0 无 Error（fd 成功 + GRANT_ROOT 后行为仍未完全定案，
     见「21:19 矛盾」）；
   - 22:22 起：`debug info` 全 0（get_info 失败返零结构——rc=0 不代表成功）
     + su 固化报 fd fail——**多次 reboot(magic) 后进入固化失败状态**；
   - 变化期间设备无操作（host 编译），候选：多次 magic reboot 被 OPLUS
     收紧/reboot kevent hook 不再记录（22:24 只有 execve 记录、无 syscall 29
     记录）/kprobe 状态变化。
3. **「21:19 rc=0 矛盾」（部分残留）**：当时 fd 成功（无 fd Error）但
   mybin/sh 未执行（exec 未发生或被跳过）——候选解释：execvp 对 mybin/sh
   的 open EACCES（SELinux 拒 ksu 域 exec shell_data_file）**继续 PATH 下一
   候选**落 /system/bin/sh、sh 起来后立即退出（sh 死因本身仍未定案）。
4. **设备 ksud 版本不可追溯教训不变**（5.9MB vs embed 4.5MB，非本地产物）。

## ksud 本地重编（2026-10-28 建立，可复用）

产物 `userspace/ksud/target/aarch64-linux-android/release/ksud` 4105064B
sha `20373464`。完整命令（全部坑已踩平）：
```bash
export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
rustup toolchain install nightly --profile minimal   # main.rs 用 feature(decl_macro)
rustup target add aarch64-linux-android --toolchain nightly
cd userspace/ksud && export \
  ANDROID_NDK_HOME=~/android-ndk-r29 \
  LIBCLANG_PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/lib \
  CC_aarch64_linux_android=.../bin/aarch64-linux-android31-clang \
  CXX_aarch64_linux_android=.../bin/aarch64-linux-android31-clang++ \
  AR_aarch64_linux_android=.../bin/llvm-ar \
  BINDGEN_EXTRA_CLANG_ARGS="-I/usr/include/x86_64-linux-gnu" \
  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=.../bin/aarch64-linux-android31-clang
cargo +nightly build --release --target aarch64-linux-android
```
坑：① stable 不够（nightly feature）；② nightly 需单独 target add；
③ bindgen 缺 host asm 头（BINDGEN_EXTRA_CLANG_ARGS）；④ **linker 必须用
env**（CARGO_TARGET_..._LINKER）——.cargo/config.toml 曾因命令超时截断没
建成，host ld.bfd 链接 aarch64 报 EM:183；⑤ crates.io 走 USTC sparse
镜像（~/.cargo/config.toml source replace）。

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

## 下一步

1. **fd 获取固化失败是当前阻塞**（22:22 起三 ksud 全 fd fail）——先判
   kprobe/OPLUS 状态：logcat kevent 对比（21:13 有 syscall 29 记录、22:24
   只有 execve 记录）→ reboot syscall 在 OPLUS hook 层的拦截状态是首要
   嫌疑。
2. **下轮 fresh boot 实测 fd 时间线**：boot 后立即 `ksud debug info` 看
   35220 持续多久、多少次 reboot(magic) 后转固化失败——定位 magic reboot
   的「额度/拉黑」机制（若存在）。
3. 若 fresh boot 上 fd 窗口短 → 修复方向 = 让 scan 继承 fd（方案乙 hand_fd
   非 manager uid 不触发——或 KSUD 不用 reboot fallback 而用别的通道）。
4. 「21:19 rc=0 矛盾」（fd 成功但 exec 未生效）待 fd 可用后重放 mybin
   实验分辨（execvp EACCES 跳过假说）。
5. 修复后 reboot fresh boot 重考（计数 0/3 起算）。

## 教训

- **ksud 二进制版本管理缺失**：/data/adb/ksud 由历史轮链 self 路径写入，
  版本不可追溯——恢复链应校验 ksud sha 与预期一致（或统一从 build/embed
  / 明确产物部署）。
- rc=0 ≠ 成功：Rust 吞 Err 的版本行为会把失败伪装成成功——verify 探针
  必须验输出内容（uid=0）而非只看 rc。
