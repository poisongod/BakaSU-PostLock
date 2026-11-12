boot: 11e3bdc8（本 boot 未重启；旧 ko e78ec0c6 + Rust ksud 落点 1a45cddd）
serial: 100.120.155.127:5555

tsu_direct_probe.sh（经 su -c 以 uid0 + u:r:ksu:s0 直调 tsu 0.3.0）
  PASS=22 FAIL=0 INFO=2 -> RESULT: OK
  真进入 VN：mnt:[4026534014] == sidecar inode，access.log via=sidecar / via=ns-explicit
  -M 覆盖 --vtz：mnt:[4026533362] == init ns
  fail-closed 四连：参数冲突 / -l / 无 sidecar(no W registered) / sidecar inode 不符

rows.sh（落点模式，针对当前 Rust ksud 落点）
  PASS=2 FAIL=9 INFO=3 —— 期望：T0 判 FAIL（落点仍是 Rust ksud）、T2/T3/T4/T5 判 FAIL（Rust su 不认 --vtz）
  意义：证明判据在「未换落点」时不会误报 PASS
