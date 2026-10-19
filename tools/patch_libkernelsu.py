#!/usr/bin/env python3
"""Patch ReSukiSU libkernelsu.so JNI stubs so the manager app flips the
"working" card without a real kernel driver.

Usage:
  tools/patch_libkernelsu.py IN.so OUT.so --version 35193
  tools/patch_libkernelsu.py IN.so OUT.so --version 35193 --expect-orig   # abort if already patched

Offsets are *file* offsets (== VA; .text sh_addr == sh_offset in this lib).
Anchor for every entry is the original prologue `str x30, [sp, #-0x10]!`
(0xf81f0ffe).  If an upgrade moves/changes a stub the anchor check fails and
the offsets must be re-derived from `llvm-objdump -d` symbol names.
"""
import argparse
import struct
import sys

# offset -> (symbol, patched-word-or-None-if-version-derived)
# word = movz w0, #imm16 ; ret
TABLE = {
    0x1DA8: ("Java_com_resukisu_resukisu_Natives_getVersion", "version"),
    0x1DC0: ("Java_com_resukisu_resukisu_Natives_getKernelUAPIVersion", 0x52800080),  # w0=4
    0x1EF8: ("Java_com_resukisu_resukisu_Natives_isLkmMode", 0x52800000),              # w0=0
    0x1F14: ("Java_com_resukisu_resukisu_Natives_isManager", 0x52800020),               # w0=1
    0x1F3C: ("Java_com_resukisu_resukisu_Natives_isPrBuild", 0x52800000),               # w0=0
    0x1F58: ("Java_com_resukisu_resukisu_Natives_isLkmBundled", 0x52800000),            # w0=0
    0x1F74: ("Java_com_resukisu_resukisu_Natives_isLateLoadMode", 0x52800020),          # w0=1
}
ANCHOR = 0xF81F0FFE  # str x30, [sp, #-0x10]!
RET = 0xD65F03C0
SIZE_OK = (18520,)


def movz_w0(imm16: int) -> int:
    if not 0 <= imm16 <= 0xFFFF:
        sys.exit(f"imm16 out of range: {hex(imm16)}")
    return 0x52800000 | (imm16 << 5)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("inp")
    ap.add_argument("out")
    ap.add_argument("--version", type=int, required=True,
                    help="versionCode for getVersion stub (e.g. 35193)")
    ap.add_argument("--expect-orig", action="store_true",
                    help="fail if input already patched (strict baseline check)")
    args = ap.parse_args()

    data = bytearray(open(args.inp, "rb").read())
    if len(data) not in SIZE_OK:
        sys.exit(f"unexpected so size {len(data)} (want {SIZE_OK}); "
                 "ReSukiSU libkernelsu.so layout changed, re-derive offsets")

    ver_word = movz_w0(args.version & 0xFFFF)
    for off, (sym, spec) in TABLE.items():
        if off + 8 > len(data):
            sys.exit(f"offset 0x{off:x} ({sym}) past EOF")
        cur = struct.unpack_from("<I", data, off)[0]
        nxt = struct.unpack_from("<I", data, off + 4)[0]
        want = ver_word if spec == "version" else spec

        if args.expect_orig and cur != ANCHOR:
            sys.exit(f"input already modified at 0x{off:x} ({sym}): 0x{cur:08x} "
                     f"(--expect-orig wanted prologue 0x{ANCHOR:08x})")

        if cur == ANCHOR:
            pass  # pristine, patch it below
        elif cur == want and nxt == RET:
            print(f"0x{off:x} {sym}: already patched")
            continue
        elif (cur & 0xFFE0001F) == 0x52800000 and nxt == RET:
            print(f"0x{off:x} {sym}: was patched with imm16=0x{(cur >> 5) & 0xFFFF:x}, "
                  f"repatching to 0x{(want >> 5) & 0xFFFF:x}")
        else:
            sys.exit(f"anchor mismatch at 0x{off:x} ({sym}): found 0x{cur:08x}, "
                     f"want prologue 0x{ANCHOR:08x} or patched 0x{want:08x}.\n"
                     "Offsets likely changed with an app upgrade: re-derive them "
                     "from `llvm-objdump -d` symbol names and update TABLE.")
        struct.pack_into("<I", data, off, want)
        struct.pack_into("<I", data, off + 4, RET)
        print(f"0x{off:x} {sym}: -> 0x{want:08x} (movz w0,#0x{(want >> 5) & 0xFFFF:x}); ret")

    open(args.out, "wb").write(data)
    print(f"wrote {args.out} ({len(data)} B) version={args.version}")


if __name__ == "__main__":
    main()
