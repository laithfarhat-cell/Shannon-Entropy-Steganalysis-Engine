"""Known distributions, inert format fixtures, synthetic controls and CLI contracts."""

import base64
import json
import struct
from io import BytesIO
from pathlib import Path

import numpy as np
import pytest
from PIL import Image, PngImagePlugin

from analyzers.binary_analyzer import analyze_binary
from analyzers.steganalysis import analyze_image, bit_planes, pair_test
from core.information_theory import (
    histogram,
    monte_carlo_pi,
    shannon_entropy,
    sliding_entropy,
    uniformity,
)
from main import main
from reporters.exporter import html, markdown
from scripts.generate_test_artifacts import generate, pe_fixture


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", 0),
        (bytes(4096), 0),
        (bytes(range(256)) * 7, 8),
        (b"12" * 43, 1),
        (b"1234", 2),
    ],
)
def test_entropy(data, expected):
    assert shannon_entropy(data) == expected


def test_stride_and_tail():
    data = bytes(70) + bytes(range(256)) * 2
    profile = list(sliding_entropy(data, 256, 75))
    assert [p["offset"] for p in profile] == [0, 75, 150, 225, 300, 326]
    assert [p["entropy"] for p in profile] == [
        shannon_entropy(data[p["offset"] : p["offset"] + 256]) for p in profile
    ]
    assert list(sliding_entropy(b"")) == []
    assert list(sliding_entropy(b"A")) == [{"offset": 0, "entropy": 0}]
    with pytest.raises(ValueError):
        list(sliding_entropy(b"123", 1, 0))
    with pytest.raises(ValueError, match="budget"):
        list(sliding_entropy(bytes(260000), 16, 1))


def test_uniform_and_pi():
    fit = uniformity(histogram(bytes(range(256)) * 5))
    assert fit == {"statistic": 0, "df": 255, "p_value": 1, "expected_per_bin": 5}
    assert uniformity(histogram(b"x"))["p_value"] is None
    assert monte_carlo_pi(bytes(5))["estimate"] is None
    assert monte_carlo_pi(bytes(6) + b"\xff" * 6 + bytes(5)) == {
        "pairs": 2,
        "estimate": 2,
    }
    assert (
        abs(monte_carlo_pi(np.random.default_rng(1).bytes(600_000))["estimate"] - np.pi)
        < 0.025
    )


def test_pe_sections_overlay_and_certificate():
    payload = bytes(range(256)) * 32
    pe = pe_fixture(payload)
    r = analyze_binary(pe + payload)
    assert r["format"] == "PE" and r["verdict"] == "PACKED / ENCRYPTED"
    assert [(s["name"], s["entropy"]) for s in r["sections"]] == [
        (".data", 0),
        ("UPX1", 8),
    ]
    assert r["overlay"] == {"offset": len(pe), "size": 8192, "entropy": 8}
    assert any("Packer-associated" in f for f in r["findings"])
    assert any("High-entropy code" in f for f in r["findings"])
    assert any("possible padding" in f for f in r["findings"])
    cert = bytearray(pe + bytes(64) + b"xyz")
    struct.pack_into("<II", cert, 152 + 96 + 4 * 8, len(pe), 64)
    assert analyze_binary(bytes(cert))["overlay"]["size"] == 3


def test_pe_sparse_imports():
    data = bytearray(pe_fixture(bytes(8192)))
    struct.pack_into("<II", data, 152 + 96 + 8, 4096, 40)
    struct.pack_into("<5I", data, 512, 4192, 0, 0, 4160, 4224)
    data[576:589] = b"kernel32.dll\0"
    for off in (608, 640):
        struct.pack_into("<III", data, off, 4256, 4288, 0)
    for off, name in [(672, b"LoadLibraryA"), (704, b"GetProcAddress")]:
        data[off + 2 : off + 2 + len(name)] = name
    r = analyze_binary(bytes(data))
    assert r["imports"]["count"] == 2 and r["imports"]["resolver_only"]
    assert any("Sparse imports" in f for f in r["findings"])


def test_elf_tables_nobits_segment_and_overlay():
    # ELF64 little endian: section table BEFORE segment end; .bss is not file-backed.
    data = bytearray(1024)
    ident = b"\x7fELF\x02\x01\x01".ljust(16, b"\0")
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        2,
        62,
        1,
        0,
        64,
        128,
        0,
        64,
        56,
        1,
        64,
        4,
        1,
    )
    struct.pack_into("<II6Q", data, 64, 1, 5, 0, 0, 0, 1024, 4096, 4096)
    names = b"\0.shstrtab\0.text\0.bss\0"
    data[384 : 384 + len(names)] = names
    for i, (idx, typ, flags, off, size) in enumerate(
        [(1, 3, 0, 384, len(names)), (11, 1, 6, 512, 256), (17, 8, 3, 1024, 1 << 30)], 1
    ):
        struct.pack_into(
            "<IIQQQQIIQQ", data, 128 + 64 * i, idx, typ, flags, 0, off, size, 0, 0, 1, 0
        )
    data[512:768] = bytes(range(256))
    r = analyze_binary(bytes(data) + b"tail")
    assert r["overlay"]["offset"] == 1024 and r["overlay"]["size"] == 4
    assert [(s["name"], s["entropy"]) for s in r["sections"][1:]] == [
        (".text", 8),
        (".bss", None),
    ]


@pytest.mark.parametrize("magic", [b"MZ", b"\x7fELF"])
def test_truncated_format(magic):
    r = analyze_binary(magic)
    assert r["verdict"] == "SUSPICIOUS" and "unreadable" in r["findings"][0]


def encoded(pixels, fmt="PNG", **opts):
    b = BytesIO()
    Image.fromarray(pixels).save(b, fmt, **opts)
    return b.getvalue()


def test_pov_hand_calculation_and_sparse_bins():
    hist = np.zeros(256, dtype=int)
    assert pair_test(hist)["p_value"] is None
    hist[:4] = [30, 10, 5, 15]
    r = pair_test(hist)
    assert r["df"] == 1 and r["statistic"] == (400 / 40 + 100 / 20) / 2
    assert bit_planes(np.array([0, 1, 64, 255], dtype="uint8")).tolist() == [0, 1, 0, 1]


@pytest.mark.parametrize("seed", [0, 5, 17])
def test_controls_prefix_and_full_frame(seed):
    rng = np.random.default_rng(seed)
    base = rng.integers(0, 128, (120, 200, 3), dtype="uint8") * 2
    cover = base | (rng.random(base.shape) < 0.15).astype("uint8")
    assert analyze_image(encoded(cover))["verdict"] == "CLEAN"
    stego = base | rng.integers(0, 2, base.shape, dtype="uint8")
    r = analyze_image(encoded(stego))
    assert len(r["scans"]) == 10 and r["verdict"] == "STEGO DETECTED"
    assert r["scans"][-1]["channels"]["G"]["band_lsb_entropy"] > 0.99
    stego[60:] = cover[60:]
    r = analyze_image(encoded(stego))
    assert (
        r["verdict"] == "STEGO DETECTED"
        and r["scans"][-1]["channels"]["R"]["p_value"] < 0.01
    )


@pytest.mark.parametrize("fmt,tail", [("PNG", 7), ("BMP", 7), ("TIFF", None)])
def test_small_images_and_trailers(fmt, tail):
    image = encoded(np.zeros((2, 1, 3), dtype="uint8"), fmt)
    r = analyze_image(image + b"trailer")
    assert r["trailing_bytes"] == tail
    assert len(r["scans"]) == 2 and r["scans"][0]["channels"]["R"]["p_value"] is None
    assert r["verdict"] == ("SUSPICIOUS" if tail else "CLEAN")


def test_metadata_not_confused_with_iend():
    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", "IEND" * 18000, zip=True)
    data = encoded(np.zeros((4, 6, 3), dtype="uint8"), pnginfo=info)
    r = analyze_image(data)
    assert r["metadata_bytes"] >= 72000 and r["trailing_bytes"] == 0
    assert r["verdict"] == "SUSPICIOUS"
    with pytest.raises(ValueError):
        analyze_image(data[:-8])


def test_reject_high_depth():
    with pytest.raises(ValueError):
        analyze_image(encoded(np.zeros((6, 6), dtype="uint16")))


def test_reports_escape_untrusted_names():
    r = analyze_binary(b"ab", "<script>bad</script>")
    assert "<script>" not in html(r, b"png") and "<script>" not in markdown(r)


@pytest.mark.parametrize(
    "cmd,sample,plot",
    [
        ("analyze-bin", "packed-simulation.exe", "entropy_plot.png"),
        ("analyze-img", "stego-simulation.png", "steg_plot.png"),
    ],
)
def test_cli_exports(tmp_path, monkeypatch, cmd, sample, plot):
    monkeypatch.chdir(tmp_path)
    generate(Path("samples"))
    assert (
        main(
            [
                cmd,
                "-f",
                "samples/" + sample,
                "--plot",
                "--html",
                "case.html",
                "--json",
                "case.json",
                "--md",
                "case.md",
            ]
        )
        == 0
    )
    assert (
        base64.b64encode(Path(plot).read_bytes()).decode()
        in Path("case.html").read_text()
    )
    assert (
        json.loads(Path("case.json").read_text())["size"]
        == Path("samples", sample).stat().st_size
    )
    assert "## Findings" in Path("case.md").read_text()
    assert main([cmd, "-f", "samples/" + sample, "--json", "samples/" + sample]) == 1


def test_batch_continues_after_errors(tmp_path):
    root = tmp_path / "samples"
    generate(root)
    (root / "broken.png").write_bytes(b"bad")
    output = tmp_path / "summary.json"
    assert main(["batch", "-d", str(root), "--json", str(output)]) == 1
    rows = json.loads(output.read_text())["files"]
    assert len(rows) == 5 and sum("error" in r for r in rows) == 1
    assert {r.get("verdict") for r in rows} >= {
        "STEGO DETECTED",
        "CLEAN",
        "PACKED / ENCRYPTED",
    }
