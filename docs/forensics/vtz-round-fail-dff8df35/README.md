# VtzSU V0a 正式轮 — 第 1 次尝试失败（boot `dff8df35`）

时间：2026-11-11 14:58:46 触发 → 15:00:18 链退出，root=0（restore 未 fork）。

## 死点

```
win tick +5s skbrxq=1 ... dead=0
win tick +7s skbrxq=1 ... dead=1        <- payload 页在 win 段被回收
phys prepare skipped: payload table dead tbl=0 rv=-1 queue=1; abort before gate
cfgfs read set-fail fd=216 target=... ret=-1 errno=25 (ENOTTY)
pselect route done calls=1 success=1 step=8 errno=25
ks_neutralize fake fops close slots owner=-1 tail=-1 ok=0 verified=0
exit tail: neutralize FAILED (no pipe child); fd-hold containment
pipe-physrw-summary done=0 root=0 kaslr=1
```

判定：**已知「payload 页死抽签」家族**（AGENTS「win 段页死」/ redo25/26/37/40/47
同族），与 VtzSU V0a 改动（`su --vtz` / holder / sidecar）无因果关系——链在
`root` 之前就 abort，restore 从未 fork，故 `vtz_w.pid` 未被重写、§7 判据本轮
不可测。

`neutralize ok=0` → `fd-hold containment`（`reboot before any re-run`），按
fail-amplifier 规则判明即 reboot（15:05:40 已执行）。

## 本轮之前的状态

`postlock.log` 显示 stage 只有 `oplus_check_suppress.ko` 与 `ksud` 发生变化
（`stage-pushed`），其余 `stage-unchanged`；`ksud` 即 V0a 版 `bbc7afcd`。

## 文件

- `chain.log.gz` — 完整链日志（253586 字节压缩后 8430）。
- `postlock.log` — host 侧编排日志（止于 `wait for restore`）。
- `rows-on-failed-boot.log` — 在该失败 boot 上跑的 §7 判据输出，**仅作对照**：
  侧车仍是上一 boot 的值、holder 已随 reboot 消失，因此 R1–R10 全红属预期，
  不作为 V0a 结论。

## 处置

reboot 换 fresh boot 重跑（多轮编排器 `round_multi.sh`，失败自动 reboot 重试）。
