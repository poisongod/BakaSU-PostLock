# v17（ko 185e7dfb）su 回归现场归档

来源：设备 192.168.137.10，冷 boot `261cfe5f` 上 pull 回的上一 boot 日志。

- `postlock_restore.log`：boot `bc35c90a` 的 restore 全文，24 行，**双 OK 原生**
  （`SELINUX-STRICT-OK enforce=1 probe=host-verify` + `POSTLOCK-RESTORE-OK`），
  `driver-already-loaded`（链 self 路径已 finitmod v17 ko）、
  `manager-appid=10277`、ocsk v14 `kill.scan sites=2` + `rep armed=2`、
  `suvtz-p1-1 dac hardened`、`sepolicy enforce1 rules applied`。
  唯一异常 = 第 21 行 `cmd: Can't find service: activity`（`am start` 瞬时失败，非阻塞）。
- `postlock_chain.log`：189549B，链 `pipe-physrw-summary done=1 root=1 kaslr=1`
  三连 + `ks_neutralize ok=1 verified=1` + `CHAIN_EXIT_DONE`，全程无 panic。

**关键结论**：restore 侧一切正常，su 的失败发生在 restore 之后的外部调用；
本轮 restore 版本尚无 `su-triage` 块，故无内核侧证据。分析见
`docs/su-regression-analysis.md`。
