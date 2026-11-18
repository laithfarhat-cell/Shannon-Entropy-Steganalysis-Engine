"""Static, on-disk PE/ELF triage. Never load a sample as executable code."""

import io
import struct

import pefile
from elftools.common.exceptions import ELFError
from elftools.construct import ConstructError
from elftools.elf.elffile import ELFFile

from core.evidence import identity
from core.information_theory import (
    entropy_from_counts,
    histogram,
    monte_carlo_pi,
    shannon_entropy,
    sliding_entropy,
    uniformity,
)

PACKED = 7.2
MIN_REGION = 256


def _end(data, offset, size):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError("declared structure extends beyond file")
    return offset + size


def _pe(data):
    sections = []
    with pefile.PE(data=data, fast_load=True) as pe:
        if len(pe.sections) != pe.FILE_HEADER.NumberOfSections:
            raise ValueError("incomplete PE section table")
        table_end = (
            pe.OPTIONAL_HEADER.get_file_offset()
            + pe.FILE_HEADER.SizeOfOptionalHeader
            + 40 * len(pe.sections)
        )
        end = _end(data, 0, max(pe.OPTIONAL_HEADER.SizeOfHeaders, table_end))
        for s in pe.sections:
            name = s.Name.rstrip(b"\0").decode("ascii", "replace")
            size, offset = s.SizeOfRawData, s.PointerToRawData
            if size:
                end = max(end, _end(data, offset, size))
            sections.append((name, offset, size, bool(s.Characteristics & 0x20000020)))
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(dirs) > 4 and dirs[4].Size:  # certificate directory uses a file offset
            end = max(end, _end(data, dirs[4].VirtualAddress, dirs[4].Size))
        imports = None
        if len(dirs) > 1 and dirs[1].VirtualAddress:
            pe.parse_data_directories(directories=[1])
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                names = [
                    imp.name.decode("ascii", "replace")
                    if imp.name
                    else f"#{imp.ordinal}"
                    for dll in pe.DIRECTORY_ENTRY_IMPORT
                    for imp in dll.imports
                ]
                imports = {
                    "count": len(names),
                    "sample": names[:16],
                    "resolver_only": bool(names)
                    and len(names) <= 4
                    and set(names) <= {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"}
                    and "GetProcAddress" in names,
                }
        return sections, end, imports


def _elf(data):
    # Decode table records, not section payloads (which may be compressed).
    stream = io.BytesIO(data)
    elf = ELFFile(stream)
    end = _end(data, 0, elf["e_ehsize"])

    def table(prefix, count, parser):
        nonlocal end
        start, stride = elf[f"e_{prefix}off"], elf[f"e_{prefix}entsize"]
        if count > 8192 or (count and stride < parser.sizeof()):
            raise ValueError("invalid or excessive ELF table dimensions")
        if count:
            end = max(end, _end(data, start, count * stride))
        for i in range(count):
            stream.seek(start + i * stride)
            yield parser.parse_stream(stream)

    for p in table("ph", elf.num_segments(), elf.structs.Elf_Phdr):
        if p.p_filesz:
            end = max(end, _end(data, p.p_offset, p.p_filesz))
    headers = list(table("sh", elf.num_sections(), elf.structs.Elf_Shdr))
    strings = None
    if headers and elf.get_shstrndx():
        strings = headers[elf.get_shstrndx()]
        _end(data, strings.sh_offset, strings.sh_size)
    sections = []
    for s in headers:
        if s.sh_type == "SHT_NULL":
            continue
        size = 0 if s.sh_type == "SHT_NOBITS" else s.sh_size
        if size:
            end = max(end, _end(data, s.sh_offset, size))
        name = ""
        if strings and s.sh_name < strings.sh_size:
            start = strings.sh_offset + s.sh_name
            name = (
                data[start : min(start + 256, strings.sh_offset + strings.sh_size)]
                .split(b"\0")[0]
                .decode("utf8", "replace")
            )
        sections.append((name, s.sh_offset, size, bool(s.sh_flags & 4)))
    return sections, end, None


def analyze_binary(
    data: bytes, name: str = "<memory>", window: int = 1024, step: int = 256
) -> dict:
    report = identity(data, name, "binary")
    counts = histogram(data)
    profile = list(sliding_entropy(data, window, step))
    h = entropy_from_counts(counts)
    fmt = (
        "PE"
        if data.startswith(b"MZ")
        else "ELF"
        if data.startswith(b"\x7fELF")
        else "raw"
    )
    findings, sections = [], []
    records, end, imports = [], len(data), None
    if fmt != "raw":
        try:
            records, end, imports = (_pe if fmt == "PE" else _elf)(data)
            if sum(s[2] for s in records) > 2 * len(data):
                raise ValueError("overlapping section budget exceeded")
        except (
            pefile.PEFormatError,
            ELFError,
            ConstructError,
            struct.error,
            ValueError,
            IndexError,
            KeyError,
            OverflowError,
        ) as exc:
            findings.append(
                f"{fmt} structure unreadable ({type(exc).__name__}); raw statistics only"
            )
            records, end, imports = [], len(data), None
    strong = False
    view = memoryview(data)
    for label, off, size, code in records:
        entropy = shannon_entropy(view[off : off + size]) if size else None
        sections.append(
            {
                "name": label,
                "offset": off,
                "size": size,
                "executable": code,
                "entropy": entropy,
            }
        )
        if label.lower().lstrip(".").startswith(("upx", "aspack", "adata", "themida")):
            findings.append(f"Packer-associated section name: {label}")
            strong = True
        if size >= MIN_REGION and code and entropy > PACKED:
            findings.append(f"High-entropy code: {label}")
            strong = True
        if size >= MIN_REGION and entropy < 1:
            findings.append(f"Low-entropy section: {label} (possible padding)")
    overlay = None
    if end < len(data):
        tail_h = shannon_entropy(view[end:])
        overlay = {"offset": end, "size": len(data) - end, "entropy": tail_h}
        if len(data) - end >= MIN_REGION and tail_h > PACKED:
            findings.append("High-entropy overlay beyond mapped structures")
    if imports and imports["resolver_only"]:
        findings.append("Sparse imports limited to dynamic resolution")
    if len(data) >= MIN_REGION and h > PACKED:
        findings.append("High global byte entropy")
        strong |= fmt == "raw"
    if min(window, len(data)) >= MIN_REGION:
        for key, match in [
            ("High-entropy", lambda x: x > PACKED),
            ("Low-entropy", lambda x: x < 1),
        ]:
            n = sum(match(p["entropy"]) for p in profile)
            if n:
                findings.append(f"{key} profile windows: {n}/{len(profile)}")
    if not data:
        findings.append("Empty input: no evidence to assess")
    return dict(
        report,
        format=fmt,
        entropy=h,
        uniformity=uniformity(counts),
        pi=monte_carlo_pi(data),
        profile=profile,
        window=window,
        step=step,
        sections=sections,
        overlay=overlay,
        imports=imports,
        findings=findings,
        verdict="PACKED / ENCRYPTED"
        if strong
        else "SUSPICIOUS"
        if findings
        else "CLEAN",
    )
