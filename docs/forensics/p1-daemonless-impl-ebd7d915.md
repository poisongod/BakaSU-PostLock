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

1. **overlay 私有可写层未实现**。设计 §2.3 定的是「lower = N 只读视图，
   upper/work 在 `/metadata`（11MB 闸门），VN 根 = merged」。实际 P1 第一版
   用 **tmpfs 骨架 + 分区只读 bind**，`/system` 等在 VN 内仍只读；
   `/data/local/tmp` 用 tmpfs 单独给了可写可弃。隔离性与「写不落 N」
   已由 N5/N11 验收，但「VN 内可写系统分区」这一能力还没有。
2. **材料只度量、未注入**。设计 §2.2 ⑤ 要求校验后写入 upper 对应路径；
   实际只做校验（拒绝构造），不复制材料。注入需要先定义
   「材料 → VN 内目标路径」清单（`restore-only` 资产的目标位置），
   留到 P1.5。

两项都不影响已验收的判据，但**不能宣称「P1 完整落地」**——
准确说法是「P1 的隔离/生命周期/度量部分落地，私有可写层与注入留待 P1.5」。

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

- `/data/local/tmp/trysu-vn-<pid>` 空目录会在会话退出后残留（挂载已随 ns
  销毁）。当前不做跨会话回收（避免误删活会话），可在 postlock 里做
  「非挂载点且为空」的批量 rmdir。
- P1.5：overlay 私有可写层（`/metadata` 容量闸门 + 清理）、材料注入清单。
- `tools/tsu/rows.sh`（V0b/T0–T7）已不适用于 daemonless 形态，保留为
  历史基线；验收一律用 `tools/tsu/n_accept.sh`。
- 冷 boot 验证尚未做（本 boot 是手工退役 holder 后验收的）。

## 7 下一步

1. 一次冷 boot 跑 `tools/tsu/n_accept.sh`（N8_ARM=1 N10_ARM=1）+ 回归三件套。
2. 冷 boot 后确认 `postlock_restore.log` 里有 `trysu: manifest entries=N`
   且没有 `suvtz-w:` 的 holder 日志。
3. P1.5 设计 overlay 形态（先测 `/metadata` 11MB 下的 upper/work 行为）。
