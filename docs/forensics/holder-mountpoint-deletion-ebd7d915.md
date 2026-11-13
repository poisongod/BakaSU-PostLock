# 事故复盘（第二起）：删除 holder 挂载点目录导致 VN 隔离静默退化

> boot `ebd7d915`（2026-11-13 21:5x），由 `tools/tsu/n_rows.sh` 早期版本的清理逻辑触发。
> 严重度：中（无数据损失、无 `adb shell` 中断）；**隐蔽性高**（无任何报错，隔离静默失效）。
> 与第一起 `overlay-probe-leak-11e3bdc8.md` 同源：**对挂载点做破坏性清理**。

## 1 触发

编写 N1–N12 判据脚本时，为让 N5（N 侧不可见 VN 内容）可重复判定，加了清理函数：

```sh
clean_w() {
  ...
  suc -c 'rm -rf /data/local/tmp/.w'      # ← 事故点
  ...
}
```

当时依据是「N 侧 `/data/local/tmp/.w` 是真实目录，holder 的 tmpfs 在 holder ns 里」。
前半句对，后半句不完整：**N 侧那个目录正是 holder tmpfs 的挂载点目录**。

## 2 机制

`wns hold` 的构造是（`tools/wns/wns.c`）：

```
unshare(CLONE_NEWNS) → mount("/", MS_REC|MS_PRIVATE) → mkdir_p(dir) → mount("tmpfs", dir)
```

- 挂载点 `/data/local/tmp/.w` 是**N ns 里可见的真实目录**，tmpfs 覆盖其上（只在 holder ns 里可见）。
- 在 N ns 删掉该目录后，holder ns 里的挂载 dentry 变成 `(deleted)`。
- 此后 holder ns 内对 `/data/local/tmp/.w` 的**路径解析回落到父目录的普通子目录**（tsu 在 N 侧又新建的同名目录），于是：
  - VN 内 `.w` 的内容 == N 侧 `.w` 的内容；
  - holder 进程仍存活、`setns` 仍成功、`--trysu-vn` 仍返回正确的 ns inode；
  - **没有任何一步报错**——隔离已经消失但观测面看起来正常。

## 3 发现过程

N5 判据出现「同一脚本两次运行结果不同」：

| 轮次 | N5 观测 | 真实原因 |
|---|---|---|
| 第 1 轮 | PASS（N 侧 `.w/log` ENOENT） | holder 挂载点完好 |
| 第 2 轮 | FAIL（N 侧出现 `.w/log`） | 第 1 轮的 `rm -rf` 已删挂载点，`--trysu-vn` 的审计落到了 N 侧 |

一度误判为「旧 tsu 在 `setns` 前写审计」。定点实验（手动 `rm -rf` → 跑 `su --trysu-vn -c true` → 查 N 侧）确认：**holder 完好时审计写 VN 侧；挂载点被删后写 N 侧**。即 N5 的 FAIL 是事故假象，不是 tsu 缺陷。

诊断命令（事后看很清楚）：

```sh
P=$(pgrep -f "^/data/local/tmp/ksu_boot/wns hold " | head -n1)
grep -F " /data/local/tmp/.w " /proc/$P/mountinfo     # 事故后：无输出
su --trysu-vn -c 'ls -A /data/local/tmp/.w'           # 与 N 侧内容相同（不再是 tmpfs 私有）
```

## 4 恢复

无需 reboot（挂载未泄漏到 N，只影响 holder 自身视图）：

```sh
kill <旧 holder>                      # 旧 ns 释放
setsid /data/local/tmp/ksu_boot/wns hold /data/local/tmp/.w >> log 2>&1 &
# wns hold 自建 mkdir_p + tmpfs
N=$(readlink /proc/<new_pid>/ns/mnt)
printf '%s %s\n' <new_pid> $(echo $N | tr -cd 0-9) > /data/local/tmp/vtz_w.pid
```

本次执行结果：holder 8831 → 10021，ns `4026534023`（inode 号被复用，属正常）。
恢复后 N 侧 `.w` 为空、VN 侧含 `holder.pid/log/stage/state`，`rows.sh` T0–T7 重新全绿。

> 注：`wns hold` 使用固定挂载点，重启 holder 即可，不需要重跑 exploit。

## 5 硬规则（补充到第一起事故的规则集）

1. **绝不删除 holder 的挂载点目录**（`/data/local/tmp/.w`），即使它在当前 ns 里只是普通目录；
2. 判据脚本的清理**只允许**删 `$VNROOT/log/access.log` 与空的 `log` 目录，且删除前用
   `grep -Fq " /data/local/tmp/.w " /proc/self/mountinfo` 排除当前 ns 就是挂载点的情况；
3. **脚本每轮结束要校验 holder 仍在、挂载点未丢**（`mountinfo` 有 `.w` 行），
   发现退化立即停止后续判据（否则后续结果全是假象）；
4. 任何「结果前后不一致」先怀疑观测面被自己的清理动作破坏，再怀疑被测对象。

## 6 对 P1 的含义

- 这是**旧守护形态独有的脆弱性**（固定挂载点 + 外部可删）。P1 的 per-session 构造把 VN
  根放在会话私有路径（tmpfs 骨架），会话退出即整体消亡，天然没有「常驻挂载点被外部删除」这个面。
- N5 的判据语义因此定为：**holder/构造器挂载完好时，进入 VN 不得在 N 侧留痕**；
  若 N5 红，先查挂载点，再怀疑 tsu（已写入 `tools/tsu/n_rows.sh` 头部注释）。
