# `/product/bin/su` 回归分析：v17 表 hook 单点无兜底（v26 修复）

> 状态：静态分析完成（结论闭环），设备侧验证待一轮 fresh boot 链。
> 最后更新：2026-11-05

## 1. 现象

boot `bc35c90a`（ko = v17 `185e7dfb`）上 `tools/postlock.sh` 全链一次过：

- 链 3× `pipe-physrw-summary done=1 root=1 kaslr=1`
- restore `SELINUX-STRICT-OK` + `POSTLOCK-RESTORE-OK` 双 OK **原生**出现
- `sepolicy enforce1 rules applied`、`manager-appid=10277`
- overlay 健康：`/product/bin/su` 915B、`/product/bin/ksud` 4107512B

但 host verify 在 `postlock.sh:776` 的 `/product/bin/su -c id` 失败：

```
Error: could not retrieve kernelsu driver fd
```

即 **su 在 restore 结束时就坏**，不是运行期退化。无 root ⇒ 无 dmesg ⇒ 无法定位。

## 2. 回归定位

| 版本 | ko sha1 | reboot magic 的 fd 安装通道 | SUSFS | su |
|---|---|---|---|---|
| v16 | `bae4f3cd` | kprobe `__arm64_sys_reboot` 入口 | 无 | **正常** |
| v17 | `185e7dfb` | 只剩 **`sys_call_table[142]` 表 hook** | 九项全量 | **坏** |
| v26 | `e721c47d` | 表 hook + kprobe 备份 + exec 前钩 | 九项全量 | 待验证 |

`llvm-nm` 实证：v17 的 `ko_prev_193706.ko` 里 `reboot_kp` 相关符号 **0 个**。

⇒ **回归点 = 表 hook 成为唯一路径，且该路径在本机失效。**

## 3. 表 patch 机制本身是好的（历史实证）

`build/work/round30_killctx_dmesg.txt`（2026-10-18，`finitmod` 上下文）：

```
reboot kprobe registered successfully
found variant: sys_call_table
sys_call_table=0xffffffd2b2a36e38
sys_ni_syscall: 0xffffffd2b1d38b1c
patch syscall 42, 0xffffffd2b1d38b1c -> 0xffffffd2a7d9ea54
dispatcher installed at slot 42
patch syscall 63, 0xffffffd2b1d38b98 -> 0xffffffd2a7d9ea50
patch syscall 80, 0xffffffd2b1d39030 -> 0xffffffd2a7d9ea58
```

- `sys_call_table` 解析成功、`ksu_patch_text`（fixmap + memcpy + memcmp）写入成功。
- slot 42/63/80 三个 patch 全过（其中 63/80 已跨到该表第二页，说明跨页也 OK）。
- **但历史从无 slot 142 的直接表 hook 先例**（那时 reboot 走 kprobe）。

## 4. 已排除的假说（逐项实证）

| # | 假说 | 排除依据 |
|---|---|---|
| 1 | ksud 侧 magic 值/参数顺序错 | 反汇编 `init_driver_fd` 0x262a9c–0x262ac8：`w0=0xdeadbeef` / `w1=0xcafebabe` / `x2=0` / `x3=&fd` / `w8=142` / `svc`，与内核一致 |
| 2 | `ksu_syscall_table_hook` 内部是 dispatcher 模式 | 它只 `patch_syscall_table` + 记录 `hooked_entries`，不注册 dispatcher → readback 同址同值 |
| 3 | `ksu_install_fd` 有 uid 门控 | fd 分支在 `ksu_handle_sys_reboot` 最前，`!TOOLKIT && !SUSFS` 才 return；SUSFS 分支在其后且带 `uid != 0` 门控（ksud 传 magic2=`0xcafebabe` 命中 fd 分支即返回，走不到） |
| 4 | `ksu_syscall_hook_init` 的 ni 槽 early-return 清了表 | 早退只跳过 dispatcher 安装，不影响 `ksu_supercalls_init` 独立 patch 142 |
| 5 | `ksu_supercalls_init` 未被调用 | `init` reloc 顺序：`0x288 ksu_syscall_hook_init` → `0x28c ...manager_init` → `0x290 susfs_init` → `0x294 ksu_supercalls_init` |
| 6 | kprobe 注册被表检查前置阻断（v26） | reloc：`0x924 R_AARCH64_CALL26 register_kprobe` **在** `0x95c cbnz x8` 表检查**之前** |
| 7 | `ksu_reboot_kp_pre` 有条件早退（v26） | 反汇编 0x13bf0：仅校验 magic 与 fd 去重，**无 `ksu_dbg_kp_rc` 早退** |
| 8 | `ksu_handle_sys_reboot` 的 fd 分支被改坏 | 分支顺序与上游一致，`copy_to_user((int __user *)*arg, &fd, 4)` |
| 9 | `ksu_get_uid_t` 类型 bug | 上游 manager_identity.h / throne_tracker.c / selinux_hide.c / sucompat.c 广泛使用 |
| 10 | SUSFS `susfs_init` 死锁阻断后续 init | 链能成功 ⇒ `finitmod` 返回 ⇒ init 全跑完 |
| 11 | SUSFS 的 openat/uname 表钩把表搞坏 | `susfs_uname_init` 永久 hook 160（pass-through）、`susfs_open_redirect_init` hook→验证→unhook 56，均自洽；链成功证明文件系统未受损 |
| 12 | `ksu_patch_text` 对 slot 142 跨页失败 | 页内偏移 `0x6e38+0x470=0x72a8`，`len=8` 不跨页；且 63/80 已实证跨页成功 |

## 5. 剩余两条物理路径（v26 均已兜底）

- (a) `ksu_syscall_table == NULL` ⇒ `ksu_syscall_hook_init` 早退、dispatcher（execve/setresuid/prctl）全不装、142 也无法 patch。
- (b) `ksu_patch_text` 对 slot 142 失败（会打 `patch syscall 142 failed`）。

两条都在 v26 有 kprobe 兜底：`reboot(0xdeadbeef, 0xcafebabe)` 即使没被表拦，也会进 `__arm64_sys_reboot` 触发 `ksu_reboot_kp_pre`，后者 `ksu_handle_sys_reboot(magic1, magic2, regs[2], &regs[3])` 装 fd。

**注意**：exec 钩子（`ksu_hand_fd_for_ksud_exec`）本身依赖 dispatcher，**不独立于表 hook**；真正独立兜底的只有 kprobe 路。

## 6. v26 三路冗余设计

1. **主路**：`sys_call_table[142]` 表 hook（保留原有语义，SUSFS 命令也走这里）。
2. **备份路**：`kprobe __arm64_sys_reboot` → `ksu_reboot_kp_pre`，**无条件**执行 fd 分支（靠 `ksu_current_has_driver_fd()` 去重，不用 `ksu_dbg_kp_rc` 早退）。
3. **第三条**：`ksu_hand_fd_for_ksud_exec` 门控放宽到 `allowed_for_su()` + basename 匹配 `libksud.so`/`ksud`；**exec 钩子内绝不做 fd 去重**（管理器继承的 fd 是 `O_CLOEXEC`，sys_enter 时仍在表里、exec 时被关闭；去重会让 ksud 拿不到 fd）。

不用 `pc = x30` 整函数跳过（ocsk 实测该技巧无效）。

## 7. 判据清单（新 ko 上设备后唯一权威源 = dmesg）

成功侧：

- `sys_call_table=0x...`
- `patch syscall 142, 0x... -> 0x...`
- `reboot syscall hook installed at nr 142`
- `reboot kprobe backup installed`
- `install ksu fd: N`
- `hand driver fd N to exec'ing ...`
- `KSUDBG reboot_pre`（表 hook 命中）/ `KSUDBG reboot_kp`（kprobe 路）

失败侧：

- `patch syscall 142 failed`
- `reboot syscall hook failed (kprobe backup only)`
- `reboot hook: sys_call_table unavailable (kprobe backup only)`
- `reboot kprobe backup failed: N`

参数快照：`ksu_dbg_sysent` / `ksu_dbg_disp` / `ksu_dbg_patch` / `ksu_dbg_kp_rc` / `ksu_dbg_kp_reg` / `ksu_dbg_kp_hits` / `ksu_dbg_exec_fd`。

**最终判据**：双 OK 原生 + `/product/bin/su -c id` 得 `uid=0 context=u:r:ksu:s0`。

## 8. 关键约束备忘

- `rmmod` 不可用（`ksu_observer_exit+0x7c` 会 panic）⇒ 换 ko **必须 reboot**。
- post-flip（`setenforce 1`）后 `kernel:s0` 丧失 exec ⇒ triage 只能在 pre-flip 抓 dmesg（v26 的 triage 块已置于 restore 前段）。
- `ksud susfs ...` 必须 root 上下文；shell 直跑会报 `Unsupported SuSFS command: 0x555e1` 且 dmesg 零 susfs 行。
- SUSFS 命令与 fd 安装**共用** `reboot()` 表 hook ⇒ 表 hook 若真坏，SUSFS 验收同样做不了（kprobe 只救 fd 安装）。
