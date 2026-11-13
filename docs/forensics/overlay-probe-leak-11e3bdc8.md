# 事故复盘：overlay 探针挂载泄漏污染 `/system`

> boot `11e3bdc8`（2026-11-13 约 20:47–20:52），恢复于 boot `ebd7d915`
> （同日，用户手动 reboot）。严重度：高（`/system` 不可用、`adb shell`/`su` 失效）；
> 数据损失：**无**（`/system` 为 erofs 只读 + overlay whiteout 语义，真实系统文件未被删除）。

## 1 背景

为验证「无守护 VN」设计的 overlayfs 闸门（见 `docs/trysu-daemonless-vn-design.md` §2.3），
在设备上执行 7 个探针脚本（`/data/local/tmp/ovl_probe*.sh`），均以
`su -c "unshare -m /system/bin/sh <script>"` 形式运行。

## 2 探针发现（价值保留）

| 发现 | 证据 |
|---|---|
| overlayfs 可用（builtin，`CONFIG_OVERLAY_FS=y`） | `/proc/filesystems`、`/proc/config.gz` |
| **tmpfs 不能做 upper**（`CONFIG_TMPFS_XATTR` 未开） | dmesg `upper fs does not support xattr` |
| **`/data`(f2fs) 不能做 upper/lower**（`inline_data/inline_dentry/inlinecrypt`） | dmesg `filesystem on '...' not supported` |
| **`/metadata`(ext4) 可做 upper，但仅 11MB** | probe2/3 挂载成功；`df -h /metadata` |
| loop ext4 镜像方案不可行 | `losetup` 成功但 `mke2fs` I/O error、ext4 mount EINVAL |
| `lowerdir=/system:/product:/vendor` 时 merged 根 = `/system` 的内容（不是 N 完整根） | probe5 `chroot` 失败、`ls` 无 `system/` 子目录 |
| 可行形态 = tmpfs 骨架 + 分区 bind + per-mount overlay + chroot | probe6 步骤 1–3 全 OK |

## 3 泄漏机制（按现有证据）

1. probe6 执行 `tmpfs 骨架 → bind /system → overlay on $VNROOT/system`，全部输出 OK。
2. 清理阶段 `umount` 部分失败，脚本继续执行 `rm -rf $VNROOT $OVLUP`。
3. `rm -rf` 先删了 `$OVLUP`（overlay 的 upper），随后全局挂载表出现：
   ```
   overlay /system overlay rw lowerdir=/system upperdir=/metadata/ovltest6/up workdir=/metadata/ovltest6/wk
   tmpfs   /data/local/tmp/vn_probe6
   bind    /data/local/tmp/vn_probe6/system (erofs ro)
   overlay /data/local/tmp/vn_probe6/system
   ```
4. 结果：`/system` 被「自指 + upper 已删」的 overlay 覆盖，`/system/*` 全部 `Permission denied`。

**待复现确认的根因**（reboot 后必须验证）：`su -c "unshare -m ..."` 在该设备上
是否真正创建了独立 mount namespace。若挂载在全局可见，则 `unshare -m`
（toybox）与 Rust ksud `su -c` 的组合不可信，所有挂载实验必须改为
「先验证隔离，再操作」。

## 4 影响与未损证明

- `/system`：erofs 只读；overlay 的 unlink 语义为 whiteout（write to upper），
  且 upper 删除后只造成「视图不可读」，未触及真实只读分区。
- `/data`：未参与任何探针（仅 bind 挂载观察，无写入删除）。
- `/metadata`：探针临时目录已清理，恢复 11M 可用。
- 恢复后（boot `ebd7d915`）：`grep -cE "vn_probe6|ovltest" /proc/mounts` = 0。

## 5 恢复

- 唯一路径 = reboot（init 重挂 `/system`）。`adb pull` 可在 shell 失效时取证。
- reboot 后 root 通道（Rust ksud 热插）按设计丢失，需 `tools/postlock.sh` 重建。

## 6 硬规则（新增，立即生效）

1. **挂载实验前必须验证 ns 隔离**：在 `unshare -m` 内挂一个标记 tmpfs，
   然后在**另一个连接**读 `/proc/mounts` 确认不可见；不可见才继续。
2. **清理失败禁止 `rm -rf` 挂载点**：`umount` 返回 busy 时必须停在原地、
   列出残留挂载并交人工判断（或直接 reboot），不得继续递归删除。
3. **挂载/namespace 实验只在「reboot 可接受」窗口执行**，且实验脚本
   预置 `trap` 清理 + 残留检测。
4. 探针脚本一律先 `set -e` 并把 `umount`/`mount` 返回值纳入判断，
   不得用 `2>/dev/null` 吞错。

## 7 后续

- [ ] reboot 后复现 `unshare -m` 隔离性，结论回填本文 §3。
- [ ] 把上述硬规则并入 `docs/trysu-daemonless-vn-design.md` §9 风险与实施顺序。
- [ ] overlay 闸门结论（upper=/metadata 11MB、per-mount + chroot）回填设计文档 §2.3。
