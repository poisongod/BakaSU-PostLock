# P1 无守护 VN 实施记录（boot `ebd7d915`，2026-11-13）

> 设计权威：`docs/trysu-daemonless-vn-design.md` v2。
> 本文只记录**实际落到设备上的形态**与验收数据，以及和设计的偏差。
> 代码：TrySU `bfa6db7`（tsu `b183a2d4`，23,000B）；本仓 `95ca021d`。

## 1 结论

- **无守护形态成立**：`su --trysu-vn` 由 tsu 进程自己在会话内构造 VN，
  不存在 holder 进程、sidecar 文件或常驻 namespace。
- **N1–N12 全绿**：`PASS=15 FAIL=0 INFO=2`（N8 篡改、N10b 审计写失败
  两个破坏性实验均启用并通过）；N12 `scan.sh -q` `FAIL=0`（PASS=32 / INFO=5）。
- 旧的 holder + sidecar 形态在本 boot 已手工退役，并已从 `postlock.sh`
  中删除，下次冷 boot 不会再出现。

## 2 实际构造序列（`cli/src/main.zig::constructVn`）

```
unshare(CLONE_NEWNS)
mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)
verifyManifest()                      # 失败: deny 审计 + exit 2
mkdir /data/local/tmp/trysu-vn-<pid>
mount("tmpfs", <root>, "tmpfs", 0, "mode=0755")
for d in 28 个顶层目录:                # 缺失的跳过
    mkdir <root>/<d>
    mount(<d>, <root>/<d>, NULL, MS_BIND|MS_REC, NULL)
mount("tmpfs", <root>/data/local/tmp, "tmpfs", 0, "mode=0777")
writeAudit("self", "ok"|..., "enter")  # /data/adb/trysu/audit.log，失败 exit 2
chroot(<root>); chdir("/")
execve(shell)
```

要点：

- **unshare 与 rprivate 必须成对**。本设备 `/` 是 `shared:1`，只 unshare
  会把 ns 内的 mount 传播回初始 ns（实证 `ns-isolation-ebd7d915.md`）。
  构造器里两步紧邻，任一步失败都 exit 2，没有降级分支。
- 构造者自己就是 VN 的第一个成员，**不需要 setns**；最后一个进程退出时
  ns 引用归零，tmpfs/bind 全部自动释放。
- 绑定的 28 个顶层目录：`/system /system_ext /vendor /product /odm /oem
  /apex /data /metadata /dev /proc /sys /storage /mnt /sdcard /config
  /acct /d /linkerconfig /debug_ramdisk` 与 OPPO 的 8 个 `/my_*`。
- VN 内 `/data/local/tmp` 换成 tmpfs：会话内可写、退出即弃，写到不了
  N 的真实 `/data`（N5 的机制）。
- 审计落点 `/data/adb/trysu/audit.log`（0700 root，0600 文件），格式：
  `ts=<mono> pid=<pid> uid=<uid> domain=<ctx> via=self manifest=<ok|absent|mismatch> result=<enter|deny>`。

## 3 材料度量

- `manifest.sha256` 行格式：`<sha256> <mode-octal> <bytes> <name>`，
  文件在 `/data/adb/trysu/material/<name>`。
- tsu 用 `std.crypto.hash.sha2.Sha256` 流式（4KB）计算，`fstat` 取
  mode/size；任何一项不符返回 `mismatch`，manifest 缺失/空返回 `absent`，
  两者都 `deny` + exit 2。
- 实测矩阵：

| 状态 | rc | 审计 |
|---|---|---|
| 无 manifest | 2 | `manifest=absent result=deny` |
| 篡改 1 字节 | 2 | `manifest=mismatch result=deny` |
| mode 0600 → 0644 | 2 | `manifest=mismatch result=deny` |
| 恢复原样 | 0 | `manifest=ok result=enter` |
| audit.log 换成目录 | 2（errno=21 EISDIR） | 无（写不进去） |

## 4 与设计的偏差（诚实标注）

1. ~~overlay 私有可写层未实现~~ → **P1.5 已补（tsu `5863c515`）**。
   对 `/system /system_ext /vendor /product /odm` 建 per-mount overlay：
   upper/work 在 `/metadata/trysu/<pid>/<name>/{upper,work}`，构造前
   `statfs(/metadata)` 闸门（可用 < 8MB → exit 2）。实测：5 个分区
   `mountinfo` 均为 ` - overlay `、rw；VN 内写 `/system`、`/vendor` 成功；
   写入只出现在 upper，N 侧 `ls /system/.trysu-n13` ENOENT；全局挂载泄漏 0；
   审计 `overlay=5`。N13 四项全绿。
   冷 boot 由 postlock 清空 `/metadata/trysu/*` 与 `/data/local/tmp/trysu-vn-*`。
2. **材料只度量、未注入**（唯一剩余偏差）。设计 §2.2 ⑤ 要求校验后写入
   upper 对应路径；实际只做校验（拒绝构造），不复制材料。注入落点需要
   单独设计：`/data` 是 f2fs（overlay 不支持），tmpfs 覆盖 `/data/adb`
   会丢失现有模块视图，且「restore-only 资产在 VN 内的目标路径」清单未定。

因此准确说法：**P1 的隔离、生命周期、度量、私有可写层已落地；材料注入待定**。

## 5 恢复链变更（`tools/postlock.sh`）

- 删除：W world 段（holder 启动、sidecar 发布、mountpoint/exec 探测、
  Phase B 材料迁移、Phase C 删 N 副本），以及所有 `WMIG_*`/`WCKO` 消费者
  的 W 分支（hotload、ocsk、adb_keys、persistent_properties）。
- 新增：restore 早期把 restore-only 资产集中到
  `/data/adb/trysu/material/` 并生成 `manifest.sha256`（**WARN-only**，
  失败不影响恢复链）。
- 清理：`rm -f /data/local/tmp/vtz_w.pid`；若 `.w` 是普通空目录则 rmdir。
- host 不再 push `wns`（`tools/wns/` 源码保留，hold/run 已无用）。

## 6 已知残留 / 待办

- `/data/local/tmp/trysu-vn-<pid>` 空目录与 `/metadata/trysu/<pid>/`
  （overlay upper）在会话退出后残留。冷 boot 由 postlock 整体清空；
  同 boot 内不跨会话回收（避免误删活会话）。会话内的 upper 用量上限
  由 8MB 闸门间接约束，但**单会话写满 11MB 时 overlay 会返回 ENOSPC**——
  这是可接受的行为（写失败而不是写穿到 N）。
- 材料注入落点设计（见 §4 偏差二）。
- 冷 boot 验证尚未做。
- `tools/tsu/rows.sh`（V0b/T0–T7）已不适用于 daemonless 形态，保留为
  历史基线；验收一律用 `tools/tsu/n_accept.sh`。
- 冷 boot 验证尚未做（本 boot 是手工退役 holder 后验收的）。

## 7 下一步

1. 一次冷 boot 跑 `tools/tsu/n_accept.sh`（N8_ARM=1 N10_ARM=1）+ 回归三件套。
2. 冷 boot 后确认 `postlock_restore.log` 里有 `trysu: manifest entries=N`
   且没有 `suvtz-w:` 的 holder 日志。
3. P1.5 设计 overlay 形态（先测 `/metadata` 11MB 下的 upper/work 行为）。
