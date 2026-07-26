#!/usr/bin/env python3
"""Unified target.h generator for this repository.

This is a repo-local wrapper around the target generation helpers that were
originally kept next to this checkout:

- generate_target.py: full boot/xbl/MTK front-end
- generate_target_2.py: profile-json front-end with more tolerant boot reads
- detect_offset.py: ADB /proc/iomem profile detector

Typical usage:

  # Generate directly into src/targets/<project>/target.h from boot.img + profile
  tools/generate_target.py --project mytarget --boot ../boot.img \
      --profile ../profile.json

  # Detect p0_phys_offset/p0_kernel_phys_load from an already-rooted ADB device
  tools/generate_target.py --detect-adb-profile -o profile.json

  # Use MTK vendor_boot/partition recovery and write target.h
  tools/generate_target.py --project mytarget --boot ../boot.img \
      --mtk-vendor-boot ../vendor_boot.img

The script deliberately delegates the heavy BTF/kallsyms/disassembly logic to
vendored generator modules instead of duplicating them.  Search order:

1. tools/vendor/generate_target.py and tools/vendor/generate_target_2.py
2. repository root copies: ./generate_target.py and ./generate_target_2.py
3. parent checkout copies: ../generate_target.py and ../generate_target_2.py

For a standalone GitHub release, copy the parent generator files into
`tools/vendor/`.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
TOOLS = Path(__file__).resolve().parent


class ToolError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise ToolError(message)


def repo_path(path: str) -> Path:
    return (ROOT / path).resolve()


def module_candidates(name: str) -> list[Path]:
    return [
        TOOLS / "vendor" / f"{name}.py",
        ROOT / f"{name}.py",
        ROOT.parent / f"{name}.py",
    ]


def load_module(name: str) -> Any:
    for path in module_candidates(name):
        if path.is_file():
            spec = importlib.util.spec_from_file_location(f"duchamp_{name}", path)
            if spec is None or spec.loader is None:
                fail(f"无法加载模块 spec: {path}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            module.__duchamp_source__ = str(path)
            return module
    searched = "\n  ".join(str(p) for p in module_candidates(name))
    fail(f"找不到 {name}.py，已搜索:\n  {searched}")


def run(*args: str) -> str:
    proc = subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"rc={proc.returncode}"
        raise ToolError(detail)
    return proc.stdout.replace("\r", "")


IOMEM_LINE = re.compile(r"^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.*?)\s*$")
ARM64_MEMSTART_ALIGN = 1 << 30
ARM64_STEXT_OFFSET = 0x10000
PAGE_SIZE = 0x1000


@dataclass(frozen=True)
class MemoryRange:
    start: int
    end: int
    name: str

    def contains(self, other: "MemoryRange") -> bool:
        return self.start <= other.start and other.end <= self.end


def align_down(value: int, alignment: int) -> int:
    return value & -alignment


def parse_iomem(text: str) -> list[MemoryRange]:
    ranges: list[MemoryRange] = []
    for line in text.splitlines():
        match = IOMEM_LINE.fullmatch(line)
        if match is None:
            continue
        start = int(match.group(1), 16)
        inclusive_end = int(match.group(2), 16)
        if inclusive_end < start:
            fail(f"非法 /proc/iomem range: {line.strip()}")
        ranges.append(MemoryRange(start, inclusive_end + 1, match.group(3)))
    if not ranges:
        fail("无法解析 /proc/iomem")
    return ranges


def detect_profile_from_iomem(iomem: str) -> dict[str, int]:
    ranges = parse_iomem(iomem)
    system_ram = [item for item in ranges if item.name == "System RAM"]
    kernel_code = [item for item in ranges if item.name == "Kernel code"]
    if not system_ram:
        fail("/proc/iomem 缺少 System RAM")
    if len(kernel_code) != 1:
        fail(f"期望 1 个 Kernel code range，实际 {len(kernel_code)} 个")

    first_ram = min(item.start for item in system_ram)
    phys_offset = align_down(first_ram, ARM64_MEMSTART_ALIGN)
    code = kernel_code[0]
    if code.start < ARM64_STEXT_OFFSET:
        fail("Kernel code 地址被隐藏或异常")
    kernel_phys_load = code.start - ARM64_STEXT_OFFSET

    containing_ram = [item for item in system_ram if item.contains(code)]
    if len(containing_ram) != 1:
        fail("Kernel code 不在唯一 System RAM range 中")
    ram = containing_ram[0]
    if first_ram - phys_offset >= ARM64_MEMSTART_ALIGN:
        fail("PHYS_OFFSET rounding invariant failed")
    if phys_offset % ARM64_MEMSTART_ALIGN != 0:
        fail("PHYS_OFFSET 不是 1GiB 对齐")
    if kernel_phys_load % PAGE_SIZE != 0:
        fail("kernel Image load address 不是 4K 对齐")
    if not (ram.start <= kernel_phys_load < ram.end):
        fail("kernel Image load address 不在 System RAM 中")
    return {
        "p0_phys_offset": phys_offset,
        "p0_kernel_phys_load": kernel_phys_load,
    }


def adb_devices() -> list[str]:
    devices: list[str] = []
    for line in run("adb", "devices").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "device":
            devices.append(fields[0])
    return devices


def adb_root_iomem(serial: str | None) -> str:
    if serial is None:
        devices = adb_devices()
        if not devices:
            fail("没有 authorized ADB device")
        serial = devices[0]
        if len(devices) > 1:
            print(f"warning: 多个设备，使用 {serial}", file=sys.stderr)
    prefix = ["adb", "-s", serial] if serial else ["adb"]
    identity = run(*prefix, "shell", "su", "-c", "id")
    if re.search(r"(?:^|\s)uid=0(?:\(|\s|$)", identity) is None:
        fail(f"su 未返回 uid 0: {identity.strip()}")
    return run(*prefix, "shell", "su", "-c", "cat /proc/iomem")


def write_profile(profile: dict[str, int], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "p0_phys_offset": f"0x{profile['p0_phys_offset']:x}",
                "p0_kernel_phys_load": f"0x{profile['p0_kernel_phys_load']:x}",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def target_output(project: str | None, output: Path | None) -> Path:
    if output is not None:
        return output
    if not project:
        fail("未指定 -o 时必须提供 --project")
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", project):
        fail(f"非法 project 名称: {project!r}")
    return repo_path(f"src/targets/{project}/target.h")


def call_generator(argv: list[str], prefer_full: bool) -> int:
    # generate_target.py imports generate_target_2 by bare name on MTK paths.
    # Ensure the sibling module is visible even when loaded dynamically.
    gt2 = load_module("generate_target_2")
    sys.modules.setdefault("generate_target_2", gt2)
    module = load_module("generate_target" if prefer_full else "generate_target_2")
    print(f"using generator: {module.__duchamp_source__}", file=sys.stderr)
    return int(module.main(argv))



def parse_profile_json(path: Path) -> dict[str, int]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {
        "p0_phys_offset": int(str(raw["p0_phys_offset"]), 0),
        "p0_kernel_phys_load": int(str(raw["p0_kernel_phys_load"]), 0),
    }


def parse_header_profile(path: Path) -> dict[str, int]:
    text = path.read_text(encoding="utf-8")
    def macro(name: str) -> int:
        m = re.search(rf"^#define\s+{name}\s+(0x[0-9a-fA-F]+|[0-9]+)", text, re.M)
        if not m:
            fail(f"生成器输出缺少 {name}，无法补全")
        return int(m.group(1), 0)
    return {
        "p0_phys_offset": macro("P0_PHYS_OFFSET"),
        "p0_kernel_phys_load": macro("P0_KERNEL_PHYS_LOAD"),
    }


def parse_target_header_macros(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for m in re.finditer(r"^#define\s+(\w+)\s+(.+?)\s*$", text, re.M):
        out[m.group(1)] = m.group(2)
    return out


def replace_macro_lines(text: str, replacements: dict[str, str]) -> str:
    used: set[str] = set()
    out_lines: list[str] = []
    for line in text.splitlines():
        fields = line.split(None, 2)
        if len(fields) >= 2 and fields[0] == "#define" and fields[1] in replacements:
            name = fields[1]
            used.add(name)
            out_lines.append(f"#define {name} {replacements[name]}")
        else:
            out_lines.append(line)
    text = "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")
    missing = sorted(set(replacements) - used)
    if missing:
        print(f"警告: 模板 target.h 缺少可选宏，追加到 header 前部: {missing}", file=sys.stderr)
        insert = "\n".join(f"#define {name} {replacements[name]}" for name in missing) + "\n"
        text = text.replace("#define TARGET_H\n", "#define TARGET_H\n" + insert, 1)
    return text


def template_target_path(args: argparse.Namespace, output: Path) -> Path:
    name = getattr(args, "template_target", None) or os.environ.get("TARGET_TEMPLATE") or "rodin"
    path = repo_path(f"src/targets/{name}/target.h")
    if not path.is_file():
        fail(f"BTF fallback 模板不存在: {path}; 可用 --template-target 或 TARGET_TEMPLATE 指定")
    if path.resolve() == output.resolve():
        fail("BTF fallback 模板不能与输出 target.h 相同")
    return path


def first_existing_symbol(kallsyms: Any, names: list[str], *, required: bool = True) -> int | None:
    errors = []
    for name in names:
        try:
            return kall_one(kallsyms, name)
        except Exception as exc:
            errors.append(f"{name}: {exc}")
    if required:
        fail("无法定位符号: " + "; ".join(errors))
    return None


def locate_boot_id_data_without_btf(kernel: bytes, kallsyms: Any) -> int | None:
    # 无 BTF 时无法精确解析 struct ctl_table，做一个保守扫描：
    # 找 sysctl_bootid 指针附近同时存在 boot_id 字符串指针的项。
    import struct as _struct
    base = int(kallsyms.relative_base)
    try:
        sysctl_bootid = kall_one(kallsyms, "sysctl_bootid")
    except Exception:
        return None
    boot_id_string_offsets = []
    pos = 0
    while True:
        pos = kernel.find(b"boot_id\x00", pos)
        if pos < 0:
            break
        boot_id_string_offsets.append(pos)
        pos += 1
    if not boot_id_string_offsets:
        return None
    str_ptrs = {base + off for off in boot_id_string_offsets}
    needle = _struct.pack("<Q", base + sysctl_bootid)
    candidates = []
    pos = 0
    while True:
        pos = kernel.find(needle, pos)
        if pos < 0:
            break
        window_start = max(0, pos - 0x80)
        window_end = min(len(kernel), pos + 0x80)
        window = kernel[window_start:window_end]
        if any(_struct.pack("<Q", ptr) in window for ptr in str_ptrs):
            candidates.append(pos)
        pos += 1
    candidates = sorted(set(candidates))
    if len(candidates) == 1:
        return candidates[0]
    print(f"警告: 无 BTF 扫描 boot_id.data 候选不唯一，使用 sysctl_bootid 兜底: {[hex(x) for x in candidates[:8]]}", file=sys.stderr)
    return sysctl_bootid


def fallback_generate_without_btf(args: argparse.Namespace, profile: dict[str, int], output: Path, boot: Any, config: dict[str, str], kallsyms: Any, reason: Exception) -> int:
    template = template_target_path(args, output)
    template_text = template.read_text(encoding="utf-8")
    template_macros = parse_target_header_macros(template)
    base = int(kallsyms.relative_base)
    va_bits = int(config.get("CONFIG_ARM64_VA_BITS", "39"), 0)
    p0_page_offset = profile.get("p0_page_offset", ((1 << 64) - (1 << va_bits)) & ((1 << 64) - 1))
    direct_map_end = p0_page_offset + (1 << 36)
    vmemmap_start = p0_page_offset | 0x7e00000000

    def fmt(v: int) -> str:
        return f"0x{v:x}ULL"

    def sym_macro(macro: str, *names: str, required: bool = True) -> tuple[str, str] | None:
        val = first_existing_symbol(kallsyms, list(names), required=required)
        if val is None:
            print(f"警告: {macro} 无法从 kallsyms 恢复，沿用模板值 {template_macros.get(macro)}", file=sys.stderr)
            return None
        return macro, fmt(val)

    replacements: dict[str, str] = {
        "BUILD_VARIANT_LABEL": f'"{(args.project or output.parent.name)}_no_btf"',
        "KIMAGE_TEXT_BASE": fmt(base),
        "P0_PAGE_OFFSET": fmt(p0_page_offset),
        "P0_PHYS_OFFSET": fmt(profile["p0_phys_offset"]),
        "P0_KERNEL_PHYS_LOAD": fmt(profile["p0_kernel_phys_load"]),
        "KERNELSNITCH_IDENTITY_START": fmt(p0_page_offset),
        "KERNELSNITCH_IDENTITY_END": fmt(direct_map_end),
        "DIRECT_MAP_BASE": fmt(p0_page_offset),
        "DIRECT_MAP_END": fmt(direct_map_end),
        "VMEMMAP_START": fmt(vmemmap_start),
    }

    symbol_items = [
        sym_macro("ASHMEM_FOPS_OFF", "ashmem_fops"),
        sym_macro("ASHMEM_IOCTL_OFF", "ashmem_ioctl"),
        sym_macro("ASHMEM_COMPAT_IOCTL_OFF", "compat_ashmem_ioctl"),
        sym_macro("ASHMEM_MMAP_OFF", "ashmem_mmap"),
        sym_macro("ASHMEM_OPEN_OFF", "ashmem_open"),
        sym_macro("ASHMEM_RELEASE_OFF", "ashmem_release"),
        sym_macro("ASHMEM_SHOW_FDINFO_OFF", "ashmem_show_fdinfo"),
        sym_macro("CONFIGFS_READ_ITER_OFF", "configfs_read_iter", "configfs_read_file", required=False),
        sym_macro("CONFIGFS_BIN_WRITE_ITER_OFF", "configfs_bin_write_iter", "configfs_write_bin_file", required=False),
        sym_macro("COPY_SPLICE_READ_OFF", "copy_splice_read", "generic_file_splice_read", required=False),
        sym_macro("NOOP_LLSEEK_OFF", "noop_llseek"),
        sym_macro("INIT_TASK_OFF", "init_task"),
        sym_macro("INIT_UTS_NS_OFF", "init_uts_ns"),
        sym_macro("EMPTY_ZERO_PAGE_OFF", "empty_zero_page"),
        sym_macro("ROOT_TASK_GROUP_OFF", "root_task_group"),
        sym_macro("SELINUX_BLOB_SIZES_OFF", "selinux_blob_sizes"),
        sym_macro("SECURITY_HOOK_HEADS_OFF", "security_hook_heads", required=False),
        sym_macro("KMALLOC_CACHES_OFF", "kmalloc_caches"),
        sym_macro("ANON_PIPE_BUF_OPS_OFF", "anon_pipe_buf_ops"),
        sym_macro("SLIDE_NFULNL_LOGGER_OFF", "nfulnl_logger"),
        sym_macro("SLIDE_SYSCTL_BOOTID_OFF", "sysctl_bootid"),
    ]
    for item in symbol_items:
        if item is not None:
            replacements[item[0]] = item[1]

    ashmem_misc = first_existing_symbol(kallsyms, ["ashmem_misc"], required=False)
    if ashmem_misc is not None:
        replacements["ASHMEM_MISC_FOPS_OFF"] = fmt(ashmem_misc + 0x10)
        print("警告: 无 BTF，ASHMEM_MISC_FOPS_OFF 使用 miscdevice.fops=0x10 模板假设", file=sys.stderr)
    loggers = first_existing_symbol(kallsyms, ["loggers"], required=False)
    if loggers is not None:
        replacements["SLIDE_LOGGERS_0_1_OFF"] = fmt(loggers + 8)
        print("警告: 无 BTF，SLIDE_LOGGERS_0_1_OFF 使用 loggers+8 模板假设", file=sys.stderr)
    bootid_data = locate_boot_id_data_without_btf(boot.kernel, kallsyms)
    if bootid_data is not None:
        replacements["SLIDE_RANDOM_BOOT_ID_DATA_OFF"] = fmt(bootid_data)

    selinux_state = first_existing_symbol(kallsyms, ["selinux_state"], required=False)
    if selinux_state is not None:
        old = template_macros.get("SELINUX_ENFORCING_OFF", "0")
        # 模板里 SELINUX_ENFORCING_OFF 通常就是 selinux_state + enforcing 字段偏移；
        # 已知 Android common/GKI 这里常为 +0。不能验证时保守用 +0 并警告。
        replacements["SELINUX_ENFORCING_OFF"] = fmt(selinux_state)
        print(f"警告: 无 BTF，SELINUX_ENFORCING_OFF 使用 selinux_state+0，模板原值 {old}", file=sys.stderr)

    header = replace_macro_lines(template_text, replacements)
    header = re.sub(r"^/\*.*?\*/", f"/* Generated for {args.project or output.parent.name} from {Path(args.boot).name} without BTF; template={template.parent.name}. */", header, count=1, flags=re.S)
    warning = (
        "/* WARNING: BTF was not available. Struct/layout macros not recovered from this image; "
        f"values not overwritten above were inherited from template {template.parent.name}/target.h. "
        f"BTF error: {str(reason).replace('*/', '* /')} */\n"
    )
    header = warning + header
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(header, encoding="utf-8")
    print(f"警告: 未找到/无法解析 BTF，已使用模板 {template} 继续生成", file=sys.stderr)
    print(f"生成成功: {output.resolve()}")
    print(f"kernel SHA-256: {boot.kernel_sha256}")
    print(f"target macros: {len(re.findall(r'^#define ', header, re.M))}")
    return 0


def kall_one(kallsyms: Any, name: str) -> int:
    return int(kallsyms.one(name))


def find_symbol(kallsyms: Any, pattern: str, type_re: str | None = None) -> int:
    rx = re.compile(pattern)
    trx = re.compile(type_re) if type_re else None
    hits = []
    for _idx, typ, name, off in kallsyms.symbols:
        if trx and not trx.fullmatch(typ):
            continue
        if rx.search(name):
            hits.append((name, int(off)))
    uniq = sorted(set(hits), key=lambda item: item[1])
    if len(uniq) != 1:
        sample = ", ".join(f"{n}@0x{o:x}" for n, o in uniq[:12])
        fail(f"符号匹配不唯一 pattern={pattern!r} hits={len(uniq)} {sample}")
    return uniq[0][1]


def one_or_regex(kallsyms: Any, exact: str, pattern: str, type_re: str | None = None) -> int:
    try:
        return kall_one(kallsyms, exact)
    except Exception:
        return find_symbol(kallsyms, pattern, type_re)


def maybe_one(kallsyms: Any, exact: str) -> int | None:
    try:
        return kall_one(kallsyms, exact)
    except Exception:
        return None


def build_complete_header(
    *,
    project: str,
    profile: dict[str, int],
    config: dict[str, str],
    image_size: int,
    kallsyms: Any,
    btf: Any,
    pselect: dict[str, int],
    slides: dict[str, int],
    mm_struct_sz_override: int | None,
    ksnitch_collisions: int,
    boot_name: str,
) -> str:
    base = int(kallsyms.relative_base)
    va_bits = int(config["CONFIG_ARM64_VA_BITS"], 0)
    p0_page_offset = ((1 << 64) - (1 << va_bits)) & ((1 << 64) - 1)
    direct_map_base = p0_page_offset
    # KernelSnitch only needs the low direct-map window used by existing
    # targets.  The architectural linear map would wrap at 2^64 for VA_BITS=39,
    # so keep the generator compatible with the checked-in target headers.
    direct_map_end = p0_page_offset + (1 << 36)
    vmemmap_start = p0_page_offset | 0x7e00000000
    mm_struct_sz = mm_struct_sz_override if mm_struct_sz_override is not None else int(btf.size("mm_struct"))

    def off(name: str) -> int:
        return kall_one(kallsyms, name)

    def addr_macro(name: str, off_macro: str) -> str:
        return f"#define {name} (KIMAGE_TEXT_BASE + {off_macro})"

    ashmem_ioctl = one_or_regex(kallsyms, "ashmem_ioctl", r"fops_ioctl.*ashmem_rust6Ashmem", "[tT]")
    ashmem_compat_ioctl = one_or_regex(kallsyms, "compat_ashmem_ioctl", r"fops_compat_ioctl.*ashmem_rust6Ashmem", "[tT]")
    ashmem_mmap = one_or_regex(kallsyms, "ashmem_mmap", r"fops_mmap.*ashmem_rust6Ashmem", "[tT]")
    ashmem_open = one_or_regex(kallsyms, "ashmem_open", r"fops_open.*ashmem_rust6Ashmem", "[tT]")
    ashmem_release = one_or_regex(kallsyms, "ashmem_release", r"fops_release.*ashmem_rust6Ashmem", "[tT]")
    ashmem_show_fdinfo = one_or_regex(kallsyms, "ashmem_show_fdinfo", r"fops_show_fdinfo.*ashmem_rust6Ashmem", "[tT]")
    ashmem_fops = off("ashmem_fops") if maybe_one(kallsyms, "ashmem_fops") is not None else find_ashmem_fops_table(kallsyms, btf, [ashmem_open, ashmem_ioctl, ashmem_mmap, ashmem_release, ashmem_show_fdinfo])
    ashmem_misc = maybe_one(kallsyms, "ashmem_misc")
    if ashmem_misc is not None:
        ashmem_misc_fops = ashmem_misc + int(btf.field("miscdevice", "fops"))
    else:
        ashmem_misc_fops = ashmem_fops

    security_hook_heads = maybe_one(kallsyms, "security_hook_heads")
    if security_hook_heads is None:
        security_capable0 = maybe_one(kallsyms, "security_hook_active_capable_0")
        if security_capable0 is None:
            security_capable0 = find_symbol(kallsyms, r"^security_hook_active_capable_0$", "[bBdD]")
        security_hook_heads = security_capable0 - 0x40

    off_macros: list[tuple[str, int]] = [
        ("ASHMEM_MISC_FOPS_OFF", ashmem_misc_fops),
        ("ASHMEM_FOPS_OFF", ashmem_fops),
        ("ASHMEM_IOCTL_OFF", ashmem_ioctl),
        ("ASHMEM_COMPAT_IOCTL_OFF", ashmem_compat_ioctl),
        ("ASHMEM_MMAP_OFF", ashmem_mmap),
        ("ASHMEM_OPEN_OFF", ashmem_open),
        ("ASHMEM_RELEASE_OFF", ashmem_release),
        ("ASHMEM_SHOW_FDINFO_OFF", ashmem_show_fdinfo),
        ("CONFIGFS_READ_ITER_OFF", off("configfs_read_iter")),
        ("CONFIGFS_BIN_WRITE_ITER_OFF", off("configfs_bin_write_iter")),
        ("COPY_SPLICE_READ_OFF", off("copy_splice_read")),
        ("NOOP_LLSEEK_OFF", off("noop_llseek")),
        ("INIT_TASK_OFF", off("init_task")),
        ("INIT_UTS_NS_OFF", off("init_uts_ns")),
        ("EMPTY_ZERO_PAGE_OFF", off("empty_zero_page")),
        ("ROOT_TASK_GROUP_OFF", off("root_task_group")),
        ("SELINUX_BLOB_SIZES_OFF", off("selinux_blob_sizes")),
        ("SELINUX_ENFORCING_OFF", off("selinux_state") + int(btf.field("selinux_state", "enforcing"))),
        ("SECURITY_HOOK_HEADS_OFF", security_hook_heads),
        ("KMALLOC_CACHES_OFF", off("kmalloc_caches")),
        ("ANON_PIPE_BUF_OPS_OFF", off("anon_pipe_buf_ops")),
    ]

    lines = [
        f"/* Generated for {project} from {boot_name} BTF/kallsyms; compile-complete target.h. */",
        "#ifndef TARGET_H",
        "#define TARGET_H",
        "",
        f"#define BUILD_VARIANT_LABEL \"{project}_unknown\"",
        "#ifndef BUILD_FINGERPRINT",
        "#define BUILD_FINGERPRINT \"unknown\"",
        "#endif",
        "",
        f"#define KIMAGE_TEXT_BASE 0x{base:x}ULL",
        f"#define P0_PAGE_OFFSET 0x{p0_page_offset:x}ULL",
        f"#define P0_PHYS_OFFSET 0x{profile['p0_phys_offset']:x}ULL",
        f"#define P0_KERNEL_PHYS_LOAD 0x{profile['p0_kernel_phys_load']:x}ULL",
        f"#define KERNELSNITCH_IDENTITY_START 0x{direct_map_base:x}ULL",
        f"#define KERNELSNITCH_IDENTITY_END 0x{direct_map_end:x}ULL",
        f"#define DIRECT_MAP_BASE 0x{direct_map_base:x}ULL",
        f"#define DIRECT_MAP_END 0x{direct_map_end:x}ULL",
        f"#define VMEMMAP_START 0x{vmemmap_start:x}ULL",
        "",
        f"#define PSELECT_WAITER_WORD_SHIFT {pselect['PSELECT_WAITER_WORD_SHIFT']}",
    ]
    if mm_struct_sz_override is None:
        lines.append(f"/* sizeof(struct mm_struct), recovered from this boot.img's BTF. */")
    lines.extend([
        f"#define MM_STRUCT_SZ 0x{mm_struct_sz:x}",
        f"#define KSNITCH_COLLISIONS {ksnitch_collisions}",
        "#define PSELECT_CFI_ROUTE_ATTEMPTS 12",
        "#define PSELECT_CFI_REPREPARE_EVERY 4",
        "",
    ])
    for name, val in off_macros:
        lines.append(f"#define {name} 0x{val:x}ULL")
    lines.append("")
    for macro in [name[:-4] for name, _ in off_macros]:
        lines.append(addr_macro(macro, macro + "_OFF"))

    lines.extend([
        "",
        f"#define SLIDE_NFULNL_LOGGER_OFF 0x{slides['SLIDE_NFULNL_LOGGER_OFF']:x}ULL",
        f"#define SLIDE_LOGGERS_0_1_OFF 0x{slides['SLIDE_LOGGERS_0_1_OFF']:x}ULL",
        f"#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x{slides['SLIDE_RANDOM_BOOT_ID_DATA_OFF']:x}ULL",
        "#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF",
        "#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF",
        f"#define SLIDE_SYSCTL_BOOTID_OFF 0x{off('sysctl_bootid'):x}ULL",
        "",
        "#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)",
        "#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)",
        "#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)",
        "#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)",
        "#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)",
        "#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)",
        "",
        "#define LOCK_OFF 0x1350",
        "#define W0_OFF 0x2220",
        "#define FOPS_OFF 0x1000",
        "#define SCRATCH_OFF 0x3000",
        "#define RIGHT_OFF 0x4440",
        "#define LEFT_OFF 0x5550",
        "#define FAKE_TASK_OFF 0x3200",
        "",
        f"#define WAITER_LOCAL_OFF 0x{pselect['WAITER_LOCAL_OFF']:x}",
    ])

    def add_btf_macro(name: str, struct_name: str, field_name: str) -> None:
        lines.append(f"#define {name} 0x{int(btf.field(struct_name, field_name)):x}")

    waiter = {
        "WAITER_TREE_ENTRY_OFF": int(btf.field("rt_mutex_waiter", "tree")),
        "WAITER_PI_TREE_ENTRY_OFF": int(btf.field("rt_mutex_waiter", "pi_tree")),
        "WAITER_TASK_OFF": int(btf.field("rt_mutex_waiter", "task")),
        "WAITER_LOCK_OFF": int(btf.field("rt_mutex_waiter", "lock")),
        "WAITER_WAKE_STATE_OFF": int(btf.field("rt_mutex_waiter", "wake_state")),
        "WAITER_PRIO_OFF": int(btf.field("rt_mutex_waiter", "tree")) + int(btf.field("rt_waiter_node", "prio")),
        "WAITER_DEADLINE_OFF": int(btf.field("rt_mutex_waiter", "tree")) + int(btf.field("rt_waiter_node", "deadline")),
        "WAITER_WW_CTX_OFF": int(btf.field("rt_mutex_waiter", "ww_ctx")),
    }
    for name, val in waiter.items():
        lines.append(f"#define {name} 0x{val:x}")
    fake_waiter = {
        "FAKE_WAITER_TREE_PRIO_OFF": waiter["WAITER_PRIO_OFF"],
        "FAKE_WAITER_TREE_DEADLINE_OFF": waiter["WAITER_DEADLINE_OFF"],
        "FAKE_WAITER_PI_TREE_ENTRY_OFF": waiter["WAITER_PI_TREE_ENTRY_OFF"],
        "FAKE_WAITER_PI_TREE_PRIO_OFF": waiter["WAITER_PI_TREE_ENTRY_OFF"] + int(btf.field("rt_waiter_node", "prio")),
        "FAKE_WAITER_PI_TREE_DEADLINE_OFF": waiter["WAITER_PI_TREE_ENTRY_OFF"] + int(btf.field("rt_waiter_node", "deadline")),
        "FAKE_WAITER_TASK_OFF": waiter["WAITER_TASK_OFF"],
        "FAKE_WAITER_LOCK_OFF": waiter["WAITER_LOCK_OFF"],
        "FAKE_WAITER_WAKE_STATE_OFF": waiter["WAITER_WAKE_STATE_OFF"],
        "FAKE_WAITER_WW_CTX_OFF": waiter["WAITER_WW_CTX_OFF"],
    }
    for name, val in fake_waiter.items():
        lines.append(f"#define {name} 0x{val:x}")
    for macro, field in [
        ("FAKE_TASK_USAGE_OFF", "usage"), ("FAKE_TASK_PRIO_OFF", "prio"),
        ("FAKE_TASK_NORMAL_PRIO_OFF", "normal_prio"), ("FAKE_TASK_TASK_GROUP_OFF", "sched_task_group"),
        ("FAKE_TASK_PI_LOCK_OFF", "pi_lock"), ("FAKE_TASK_PI_WAITERS_OFF", "pi_waiters"),
        ("FAKE_TASK_PI_TOP_TASK_OFF", "pi_top_task"), ("FAKE_TASK_PI_BLOCKED_ON_OFF", "pi_blocked_on"),
        ("FAKE_TASK_UCLAMP_REQ_OFF", "uclamp_req"), ("FAKE_TASK_UCLAMP_OFF", "uclamp"),
    ]:
        add_btf_macro(macro, "task_struct", field)

    lines.append("")
    for macro, struct_name, field in [
        ("CFG_PAGE_OFF", "configfs_buffer", "page"),
        ("CFG_NEEDS_READ_FILL_OFF", "configfs_buffer", "needs_read_fill"),
        ("CFG_BIN_BUFFER_OFF", "configfs_buffer", "bin_buffer"),
        ("CFG_BIN_BUFFER_SIZE_OFF", "configfs_buffer", "bin_buffer_size"),
        ("CFG_CB_MAX_SIZE_OFF", "configfs_buffer", "cb_max_size"),
        ("MM_OWNER_OFF", "mm_struct", "owner"),
        ("TASK_PID_OFF", "task_struct", "pid"),
        ("TASK_TGID_OFF", "task_struct", "tgid"),
        ("TASK_REAL_PARENT_OFF", "task_struct", "real_parent"),
        ("TASK_ATOMIC_FLAGS_OFF", "task_struct", "atomic_flags"),
        ("TASK_REAL_CRED_OFF", "task_struct", "real_cred"),
        ("TASK_CRED_OFF", "task_struct", "cred"),
        ("TASK_COMM_OFF", "task_struct", "comm"),
        ("TASK_TASKS_OFF", "task_struct", "tasks"),
        ("TASK_SECCOMP_OFF", "task_struct", "seccomp"),
        ("CRED_UID_OFF", "cred", "uid"),
        ("CRED_SECUREBITS_OFF", "cred", "securebits"),
        ("CRED_CAPS_OFF", "cred", "cap_inheritable"),
        ("CRED_SECURITY_OFF", "cred", "security"),
        ("SECCOMP_MODE_OFF", "seccomp", "mode"),
        ("SECCOMP_FILTER_COUNT_OFF", "seccomp", "filter_count"),
        ("SECCOMP_FILTER_OFF", "seccomp", "filter"),
    ]:
        add_btf_macro(macro, struct_name, field)
    lines.extend([
        "#define TASK_THREAD_INFO_FLAGS_OFF 0x0",
        "#define SELINUX_CRED_BLOB_OFF 0x0",
        "#define SELINUX_CRED_OSID_OFF 0x0",
        "#define SELINUX_CRED_SID_OFF 0x4",
        "#define TIF_SECCOMP_BIT 11",
        "#define PFA_NO_NEW_PRIVS_BIT 0",
        "",
        f"#define STRUCT_PAGE_SIZE 0x{int(btf.size('page')):x}",
        f"#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x{int(btf.field('page','compound_head')):x}",
        f"#define STRUCT_SLAB_CACHE_OFF 0x{int(btf.field('page','compound_head')):x}",
        "#define STRUCT_PAGE_TYPE_OFF 0x30",
        "",
        f"#define PIPE_BUFFER_SIZE 0x{int(btf.size('pipe_buffer')):x}",
        "#define PIPE_BUFFER_SLOTS 32",
        "#define PIPE_BUF_FLAG_CAN_MERGE 0x10",
        f"#define PIPE_INODE_INFO_STRUCT_SIZE 0x{int(btf.size('pipe_inode_info')):x}",
        f"#define PIPE_INODE_INFO_SIZE 0x{((int(btf.size('pipe_inode_info')) + 0x3f) & ~0x3f):x}",
        f"#define PIPE_INODE_INFO_SLOTS_PER_PAGE {0x1000 // ((int(btf.size('pipe_inode_info')) + 0x3f) & ~0x3f)}",
    ])
    for macro, field in [
        ("PIPE_HEAD_OFF", "head"), ("PIPE_TAIL_OFF", "tail"),
        ("PIPE_MAX_USAGE_OFF", "max_usage"), ("PIPE_RING_SIZE_OFF", "ring_size"),
        ("PIPE_NR_ACCOUNTED_OFF", "nr_accounted"), ("PIPE_READERS_OFF", "readers"),
        ("PIPE_WRITERS_OFF", "writers"), ("PIPE_FILES_OFF", "files"),
        ("PIPE_TMP_PAGE_OFF", "tmp_page"), ("PIPE_BUFS_OFF", "bufs"), ("PIPE_USER_OFF", "user"),
    ]:
        add_btf_macro(macro, "pipe_inode_info", field)
    lines.append("")
    for macro, field in [
        ("FOPS_OWNER_OFF", "owner"), ("FOPS_LLSEEK_OFF", "llseek"),
        ("FOPS_READ_OFF", "read"), ("FOPS_WRITE_OFF", "write"),
        ("FOPS_READ_ITER_OFF", "read_iter"), ("FOPS_WRITE_ITER_OFF", "write_iter"),
        ("FOPS_IOCTL_OFF", "unlocked_ioctl"), ("FOPS_COMPAT_IOCTL_OFF", "compat_ioctl"),
        ("FOPS_MMAP_OFF", "mmap"), ("FOPS_OPEN_OFF", "open"),
        ("FOPS_RELEASE_OFF", "release"), ("FOPS_SPLICE_READ_OFF", "splice_read"),
        ("FOPS_SHOW_FDINFO_OFF", "show_fdinfo"),
    ]:
        add_btf_macro(macro, "file_operations", field)
    lines.extend(["", "#endif", ""])
    return "\n".join(lines)


def find_ashmem_fops_table(kallsyms: Any, btf: Any, funcs: list[int]) -> int:
    # Prefer named symbol if available.  Rust/GKI builds often hide it, so scan
    # data symbols for a file_operations-looking object containing the ashmem
    # function pointers at the BTF-derived slots.
    fields = [
        int(btf.field("file_operations", "open")),
        int(btf.field("file_operations", "unlocked_ioctl")),
        int(btf.field("file_operations", "mmap")),
        int(btf.field("file_operations", "release")),
        int(btf.field("file_operations", "show_fdinfo")),
    ]
    wanted = set(funcs)
    candidates = []
    base = int(kallsyms.relative_base)
    # Need kernel bytes; stash is attached by complete_generate().
    kernel = getattr(kallsyms, "__duchamp_kernel", None)
    if kernel is None:
        fail("内部错误：kallsyms 缺少 kernel bytes")
    import struct as _struct
    max_field = max(fields)
    for off in range(0, len(kernel) - max_field - 8, 8):
        vals = []
        ok = True
        for f in fields:
            val = _struct.unpack_from("<Q", kernel, off + f)[0]
            vals.append(val - base if base <= val < base + len(kernel) else val)
        if set(vals) == wanted:
            candidates.append(off)
    if len(candidates) != 1:
        fail(f"ashmem_fops 扫描候选不唯一: {[hex(x) for x in candidates[:16]]}")
    return candidates[0]


def complete_generate(args: argparse.Namespace, profile: dict[str, int], output: Path) -> int:
    project = args.project or output.parent.name
    gt2 = load_module("generate_target_2")
    boot = gt2.extract_boot_kernel(args.boot)
    _ikcfg_raw, config, _ikcfg_span = gt2.extract_ikconfig(boot.kernel)
    # 不强制校验 CONFIG_DEBUG_INFO_BTF=y。部分 boot image 的 IKCONFIG
    # 可能不完整/被裁剪，但镜像内仍可恢复 BTF；后续 locate_btf()
    # 会以实际镜像内容为准，找不到 BTF 时自然失败。
    profile_full = gt2.complete_profile(profile, config, boot.image_size)
    kallsyms = gt2.recover_kallsyms(boot.kernel, boot.kernel_size, boot.image_size)
    setattr(kallsyms, "__duchamp_kernel", boot.kernel)
    try:
        btf = gt2.locate_btf(boot.kernel, kallsyms)
    except Exception as exc:
        return fallback_generate_without_btf(args, profile_full, output, boot, config, kallsyms, exc)
    try:
        gt2.validate_btf_consumer_layout(btf)
    except Exception as exc:
        print(f"警告: 无法验证 target.h 所需结构字段偏移，继续生成: {exc}", file=sys.stderr)
    try:
        btf.validate_percpu_entry_task(kallsyms.one("__per_cpu_start"), kallsyms.one("__entry_task"))
    except Exception as exc:
        print(f"警告: 无法验证 percpu entry_task 布局，继续生成: {exc}", file=sys.stderr)
    import tempfile as _tempfile
    with _tempfile.TemporaryDirectory(prefix="target-analysis-") as temporary:
        kernel_path = Path(temporary) / "kernel.bin"
        kernel_path.write_bytes(boot.kernel)
        pselect, _ = gt2.derive_pselect_layout(args.llvm_objdump, kernel_path, kallsyms, btf, gt2.PSELECT_ROUTE_NFDS)
        logger_registration, _ = gt2.derive_nf_logger_registration(args.llvm_objdump, kernel_path, boot.kernel, kallsyms, btf)
    slides = gt2.locate_slide_objects(boot.kernel, kallsyms, btf, logger_registration)
    mm_override = args.mm_struct_sz
    if mm_override is None and project == "rodin":
        # Runtime-verified rodin KernelSnitch uses the kmem_cache object size.
        mm_override = 0x500
    header = build_complete_header(
        project=project,
        profile=profile_full,
        config=config,
        image_size=boot.image_size,
        kallsyms=kallsyms,
        btf=btf,
        pselect=pselect,
        slides=slides,
        mm_struct_sz_override=mm_override,
        ksnitch_collisions=args.ksnitch_collisions,
        boot_name=Path(args.boot).name,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(header, encoding="utf-8")
    print(f"生成成功: {output.resolve()}")
    print(f"kernel SHA-256: {boot.kernel_sha256}")
    print(f"target macros: {len(re.findall(r'^#define ', header, re.M))}")
    return 0

def generate_from_profile(args: argparse.Namespace, profile_path: Path, output: Path) -> int:
    if not args.legacy_wrapper:
        return complete_generate(args, parse_profile_json(profile_path), output)
    argv = [
        "--boot",
        str(args.boot),
        "--profile",
        str(profile_path),
        "-o",
        str(output),
        "--llvm-objdump",
        args.llvm_objdump,
    ]
    return call_generator(argv, prefer_full=False)


def generate_from_full_frontend(args: argparse.Namespace, output: Path) -> int:
    if not args.legacy_wrapper and (args.mtk_partitions or args.mtk_vendor_boot):
        full = load_module("generate_target")
        boot = full.extract_boot_kernel(args.boot)
        boot_path = args.boot.resolve()
        if args.mtk_partitions:
            mtk = full.recover_mtk_profile(args.mtk_partitions, boot_path, boot)
        else:
            vendor_boot_path = full.validate_mtk_vendor_boot(args.mtk_vendor_boot, boot_path)
            mtk = full.recover_mtk_profile_from_vendor_boot(vendor_boot_path, boot)
        print(f"arm64 Image text_offset: 0x{boot.text_offset:x}")
        print(f"vendor_boot SHA-256: {mtk.vendor_boot_sha256}")
        print(
            f"MTK profile: phys=0x{mtk.phys_offset:x}, "
            f"kernel=0x{mtk.kernel_phys_load:x}, "
            f"ram={[f'0x{region.base:x}+0x{region.size:x}' for region in mtk.ram_regions]}, "
            f"dtb={[hex(off) for off in mtk.dtb_offsets]}"
        )
        return complete_generate(args, {"p0_phys_offset": mtk.phys_offset, "p0_kernel_phys_load": mtk.kernel_phys_load}, output)

    argv = ["--boot", str(args.boot), "-o", str(output), "--llvm-objdump", args.llvm_objdump]
    if args.xbl_config:
        argv.extend(["--xbl-config", str(args.xbl_config)])
    elif args.mtk_partitions:
        argv.extend(["--mtk-partitions", str(args.mtk_partitions)])
    elif args.mtk_vendor_boot:
        argv.extend(["--mtk-vendor-boot", str(args.mtk_vendor_boot)])
    else:
        fail("内部错误：未选择 full frontend profile source")
    rc = call_generator(argv, prefer_full=True)
    if rc == 0 and not args.legacy_wrapper:
        profile = parse_header_profile(output)
        return complete_generate(args, profile, output)
    return rc


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate src/targets/<project>/target.h for this repo",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--project", help="target project name; default output is src/targets/<project>/target.h")
    parser.add_argument("-o", "--output", type=Path, help="output target.h or profile JSON path")
    parser.add_argument("--llvm-objdump", default="llvm-objdump", help="llvm-objdump executable")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--profile", type=Path, help="profile JSON with p0_phys_offset and p0_kernel_phys_load")
    mode.add_argument("--detect-adb-profile", action="store_true", help="detect profile from rooted ADB /proc/iomem and write JSON")
    mode.add_argument("--detect-adb-and-generate", action="store_true", help="detect profile from rooted ADB and immediately generate target.h")
    mode.add_argument("--xbl-config", type=Path, help="xbl_config image; handled by full parent generator")
    mode.add_argument("--mtk-partitions", type=Path, help="MTK partition directory containing matching vendor_boot")
    mode.add_argument("--mtk-vendor-boot", type=Path, help="matching MTK vendor_boot image")

    parser.add_argument("--boot", type=Path, help="Android boot.img; required except --detect-adb-profile")
    parser.add_argument("--serial", help="ADB serial for profile detection")
    parser.add_argument("--profile-out", type=Path, help="where to save detected profile when using --detect-adb-and-generate")
    parser.add_argument("--mm-struct-sz", type=lambda x: int(x, 0), help="override MM_STRUCT_SZ / mm cache object size")
    parser.add_argument("--ksnitch-collisions", type=int, default=4, help="default KSNITCH_COLLISIONS macro")
    parser.add_argument("--legacy-wrapper", action="store_true", help="call parent generator directly without compile-complete post generation")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    try:
        if args.detect_adb_profile:
            output = args.output or Path("profile.json")
            profile = detect_profile_from_iomem(adb_root_iomem(args.serial))
            write_profile(profile, output)
            print(f"profile written: {output.resolve()}")
            print(f"p0_phys_offset=0x{profile['p0_phys_offset']:x}")
            print(f"p0_kernel_phys_load=0x{profile['p0_kernel_phys_load']:x}")
            return 0

        if not args.boot:
            fail("生成 target.h 需要 --boot")
        output = target_output(args.project, args.output)
        if args.detect_adb_and_generate:
            profile = detect_profile_from_iomem(adb_root_iomem(args.serial))
            if args.profile_out:
                profile_path = args.profile_out
                write_profile(profile, profile_path)
            else:
                profile_path = output.parent / "profile.generated.json"
                write_profile(profile, profile_path)
            print(f"detected profile: {profile_path.resolve()}")
            return generate_from_profile(args, profile_path, output)

        if args.profile:
            return generate_from_profile(args, args.profile, output)

        return generate_from_full_frontend(args, output)
    except (ToolError, OSError) as exc:
        if os.environ.get("TARGET_GENERATOR_TRACEBACK") == "1":
            raise
        print(f"生成失败: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
