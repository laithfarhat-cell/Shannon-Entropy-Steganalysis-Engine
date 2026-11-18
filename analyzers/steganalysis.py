"""Statistical triage of decoded, eight-bit intensity samples. No payload extraction."""

import struct
import zlib
from io import BytesIO

import numpy as np
from PIL import Image
from scipy.stats import chi2

from core.evidence import identity
from core.information_theory import entropy_from_counts

CHANNELS = "RGB"
MAX_PIXELS = 16_000_000
META_LIMIT = 64 * 1024


def _png_end(data):
    pos = 8
    while pos + 12 <= len(data):
        size = int.from_bytes(data[pos : pos + 4], "big")
        kind = data[pos + 4 : pos + 8]
        pos += size + 12
        if pos > len(data):
            break
        stored = int.from_bytes(data[pos - 4 : pos], "big")
        if zlib.crc32(memoryview(data)[pos - size - 8 : pos - 4]) != stored:
            raise ValueError("invalid PNG chunk checksum")
        if kind == b"IEND" and size == 0:
            return pos
    raise ValueError("missing or truncated PNG IEND chunk")


def decode(data):
    with Image.open(BytesIO(data), formats=["PNG", "BMP", "TIFF"]) as im:
        if im.width * im.height > MAX_PIXELS:
            raise ValueError("image exceeds 16 megapixels")
        if im.mode not in {"RGB", "RGBA", "L", "LA", "P", "1"}:
            raise ValueError(f"unsupported sample mode: {im.mode}")
        if im.format == "PNG" and data[24] > 8:
            raise ValueError("16-bit PNG would lose its native LSB during conversion")
        if im.format == "TIFF":
            if im.tag_v2.get(259, 1) not in {1, 2, 3, 4, 5, 8, 32773, 32946}:
                raise ValueError("unsupported or lossy TIFF compression")
            if max(np.atleast_1d(im.tag_v2.get(258, 1))) > 8:
                raise ValueError("high-depth TIFF would lose its native LSB")
        fmt, mode = im.format, im.mode
        rgb = np.asarray(im.convert("RGB"))
        # Pillow may lazily decode trailing PNG text during load.
        fields = dict(im.info)
        if fmt == "TIFF":
            for tag in (270, 37510, 700):  # description, user comment, XMP
                if tag in im.tag_v2:
                    fields[str(tag)] = im.tag_v2[tag]
        metadata = sum(
            len(v.encode("utf8")) if isinstance(v, str) else len(v)
            for v in fields.values()
            if isinstance(v, (bytes, str))
        )
        if fmt == "TIFF" and 34665 in im.tag_v2:
            metadata += len(im.getexif().tobytes())
    return rgb, fmt, mode, metadata


def bit_planes(rgb):
    return rgb & 1


def pair_test(counts):
    """Westfeld–Pfitzmann score plus a two-cell conditional Pearson test."""
    even, odd = counts[::2], counts[1::2]
    totals = even + odd
    keep = totals >= 10  # equal-frequency expectation >= 5 for each cell
    groups = int(keep.sum())
    if groups < 2:
        return {
            "pairs": groups,
            "statistic": None,
            "df": None,
            "p_value": None,
            "conditional_p": None,
        }
    diff = even[keep].astype(float) - odd[keep]
    both = float(np.sum(diff**2 / totals[keep]))
    return {
        "pairs": groups,
        "statistic": both / 2,
        "df": groups - 1,
        "p_value": float(chi2.sf(both / 2, groups - 1)),
        "conditional_p": float(chi2.sf(both, groups)),
    }


def analyze_image(data: bytes, name: str = "<memory>") -> dict:
    rgb, fmt, mode, metadata = decode(data)
    height, width = rgb.shape[:2]
    report = identity(data, name, "image")
    end = _png_end(data) if fmt == "PNG" else None
    if fmt == "BMP":
        end = struct.unpack_from("<I", data, 2)[0]
        if not 14 <= end <= len(data):
            raise ValueError("invalid BMP declared file size")
    trailing = len(data) - end if end is not None else None
    counts = np.zeros((3, 256), dtype=np.int64)
    scans, findings = [], []
    start = streak = longest = 0
    for stop in sorted({(height * i + 9) // 10 for i in range(1, 11)}):
        channels = {}
        votes = 0
        for c, label in enumerate(CHANNELS):
            hist = np.bincount(rgb[start:stop, :, c].ravel(), minlength=256)
            counts[c] += hist
            fit = pair_test(counts[c])
            h = entropy_from_counts(hist.reshape(128, 2).sum(axis=0))
            channels[label] = dict(fit, band_lsb_entropy=h)
            votes += (
                fit["pairs"] >= 16
                and fit["p_value"] >= 0.95
                and fit["conditional_p"] >= 0.05
            )
        streak = streak + 1 if votes >= 2 else 0
        longest = max(longest, streak)
        scans.append(
            {
                "start_row": start,
                "end_row": stop,
                "fraction": stop / height,
                "channels": channels,
            }
        )
        start = stop
    # Grayscale has replicated channels, and palette expansion changes the sample domain.
    detected = mode in {"RGB", "RGBA"} and longest >= 3
    limitations = ["Decoded RGB intensities only; alpha is excluded."]
    if fmt == "TIFF":
        limitations.append("First TIFF frame only; TIFF has no universal EOF marker.")
    if mode not in {"RGB", "RGBA"}:
        limitations.append(
            "Expanded grayscale/palette samples: color-channel verdict disabled."
        )
    if not any(ch["pairs"] >= 16 for scan in scans for ch in scan["channels"].values()):
        limitations.append(
            "Too few populated intensity pairs for the equalization rule."
        )
    if detected:
        findings.append(
            "Sustained pair equalization in at least two decoded color channels"
        )
    if trailing:
        findings.append(f"{trailing} bytes beyond the image boundary")
    if metadata > META_LIMIT:
        findings.append("Text/profile metadata exceeds 64 KiB")
    return dict(
        report,
        format=fmt,
        source_mode=mode,
        width=width,
        height=height,
        scans=scans,
        trailing_bytes=trailing,
        metadata_bytes=metadata,
        findings=findings,
        limitations=limitations,
        verdict="STEGO DETECTED" if detected else "SUSPICIOUS" if findings else "CLEAN",
    )
