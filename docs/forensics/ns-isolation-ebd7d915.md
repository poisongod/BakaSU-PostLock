# `unshare -m` 隔离性实证（boot `ebd7d915`）

> 目的：复核第一起事故（`overlay-probe-leak-11e3bdc8.md`）的根因，为 P1 per-session
> 构造器定死「mount 前必须 rprivate」这一硬要求。
> 设备 PFUM10，`u:r:ksu:s0` uid 0，`/` 的 propagation = `shared:1`。

## 1 方法

挂载点固定为专用空目录 `/data/local/tmp/ns_iso_probe`（不碰 `/system`、不碰 holder 的 `.w`）。
两组实验的差别只有「mount 前是否把 root mount 设为 rprivate」：

- **A（对照组，复现事故）**：`unshare -m sh -c 'mount -t tmpfs ...'`
- **B（正确序列）**：`unshare -m sh -c 'wns private; mount -t tmpfs ...'`
  （`wns private` = `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)`）

判定口径：子进程退出后，在**初始 ns**（另一次 `su -c`）读 `/proc/mounts`，
看挂载点是否仍在。若在 → 传播泄漏；若不在 → 隔离成立。
任何泄漏都立即 `umount` 清理（不 `rm`，遵守事故规则）。

## 2 结果

```
== STEP1-A: unshare -m + mount（不 rprivate）==
mount-rc=0
tmpfs /data/local/tmp/ns_iso_probe tmpfs rw,seclabel,relatime,size=1024k 0 0
== STEP1-A 退出后，全局视角 ==
tmpfs /data/local/tmp/ns_iso_probe tmpfs rw,seclabel,relatime,size=1024k 0 0
LEAK-DETECTED
UMOUNT-OK
CLEAN-AFTER-UMOUNT

== STEP2-B: unshare -m + wns private + mount ==
wns: private ok
mount-ok
tmpfs /data/local/tmp/ns_iso_probe tmpfs rw,seclabel,relatime,size=1024k 0 0
== STEP2-B 退出后，全局视角 ==
NO-LEAK（rprivate 生效）
== 收尾 ==
final-clean
```

| 实验 | 子进程内 mount | 退出后全局 | 结论 |
|---|---|---|---|
| A：仅 `unshare -m` | 成功 | **仍在**（泄漏） | 不安全 |
| B：`unshare -m` + rprivate | 成功 | **不在** | 安全 |
| 收尾 | — | `final-clean` | 无残留 |

## 3 结论

1. **第一起事故的根因确认**：`unshare(CLONE_NEWNS)` 只创建新 ns，新 ns 的 root mount
   仍是 `shared:1` 的 peer；在其中 `mount` 会按 shared 语义**传播回初始 ns**。
   probe6 的 `tmpfs`/`bind`/`overlay` 就是这样泄漏到全局的，与「清理时 `rm -rf`」
   叠加后形成 `/system` 自指 overlay。**两个因素缺一不可**：
   - 传播泄漏（根因，A 组复现）；
   - 清理失败后仍删挂载点/upper（放大器，见两起事故复盘）。
2. **正确序列**（已由 `wns hold` 长期验证，本次再用 B 组独立复核）：
   ```
   unshare(CLONE_NEWNS)
   mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)
   ... 此后所有 mount 都是 ns 私有的 ...
   ```
3. toybox 的 `mount` **不支持** `--make-rprivate` / `-o rprivate`（当成 fstab 解析），
   所以设备侧不能用 shell 拼出正确序列；构造器必须自己发 `mount(2)`（tsu 是纯 Zig，
   直接 syscall，正好满足）。
4. 子进程退出后 ns 销毁、挂载随之消失（B 组 `final-clean`），这就是 N4
   「VN 随会话消亡」可以成立的机制前提。

## 4 对 P1 构造器的硬要求

tsu 构造器的最小序列必须是：

```
unshare(CLONE_NEWNS)                                  # syscall 97
mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)       # syscall 40, flags=MS_REC|MS_PRIVATE
  → tmpfs 骨架 / bind 分区 / per-mount overlay
  → chroot + exec
```

**禁止**任何「只 unshare 不 rprivate」的路径；构造器里 `mount` 失败一律 fail-closed
（不得降级为「在 N 里挂」）。这条要求已写入设计文档 §2.3.1 与 §9 风险表。

## 5 清洁性

- 实验只用 `/data/local/tmp/ns_iso_probe` 一个临时挂载点，A 组泄漏后 `umount` 成功；
- 终态 `grep ns_iso_probe /proc/mounts` 为空；
- holder（pid 10021）与 `.w` 挂载未受影响（实验前后 `rows.sh` T0–T7 仍 OK）。
