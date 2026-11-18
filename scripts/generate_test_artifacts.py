"""Generate inert lab evidence; uses synthetic parity noise, not a secret message."""

import argparse
import struct
from pathlib import Path

import numpy as np
from PIL import Image


def pe_fixture(random_bytes):
    """Minimal PE32 section-table fixture. No entry point, imports, or code."""
    header = bytearray(512)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 128)
    header[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 132, 0x14C, 2, 0, 0, 0, 224, 0x102)
    opt = 152
    struct.pack_into("<H", header, opt, 0x10B)
    struct.pack_into("<III", header, opt + 28, 0x400000, 4096, 512)
    struct.pack_into("<II", header, opt + 56, 0x5000, 512)
    struct.pack_into("<I", header, opt + 92, 16)
    for i, (name, size, rva, offset, flags) in enumerate(
        [
            (b".data", 4096, 4096, 512, 0x40000040),
            (b"UPX1", 8192, 8192, 4608, 0x60000020),
        ]
    ):
        struct.pack_into(
            "<8sIIIIIIHHI",
            header,
            opt + 224 + 40 * i,
            name,
            size,
            rva,
            size,
            offset,
            0,
            0,
            0,
            0,
            flags,
        )
    return bytes(header) + bytes(4096) + random_bytes


def generate(dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(1701)
    y, x = np.mgrid[:192, :256]
    wave = np.sin(x / 29 + y / 41) * 0.15 + x / 700 + y / 600
    base = (
        np.stack([18 + 105 * wave, 14 + 94 * wave, 27 + 85 * wave], axis=-1)
        .clip(0, 127)
        .astype("uint8")
        * 2
    )
    cover = base | (rng.random(base.shape) < 0.18).astype("uint8")
    equalized = base | rng.integers(0, 2, base.shape, dtype="uint8")
    files = {
        "benign.bin": (b"Inventory record: verified.\n" * 300),
        "packed-simulation.exe": pe_fixture(rng.bytes(8192)) + rng.bytes(2048),
    }
    for name, payload in files.items():
        with (dest / name).open("xb") as f:
            f.write(payload)
    for name, pixels in [("cover.png", cover), ("stego-simulation.png", equalized)]:
        with (dest / name).open("xb") as f:
            Image.fromarray(pixels).save(f, "PNG")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", nargs="?", type=Path, default=Path("samples"))
    generate(p.parse_args().directory)
