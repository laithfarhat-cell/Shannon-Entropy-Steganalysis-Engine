"""Headless PNG diagnostics; return bytes so HTML and file share the same chart."""

from io import BytesIO

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

from analyzers.steganalysis import CHANNELS, bit_planes

ACCENT = "#5eead4"


def _save(fig):
    buf = BytesIO()
    try:
        fig.savefig(buf, format="png", dpi=145, facecolor=fig.get_facecolor())
        return buf.getvalue()
    finally:
        plt.close(fig)


@plt.style.context("dark_background")
def binary_chart(report):
    fig, ax = plt.subplots(figsize=(10, 4), layout="constrained", facecolor="#101923")
    ax.set_facecolor("#16222d")
    for i, section in enumerate(report["sections"]):
        start = section["offset"]
        stop = start + section["size"]
        ax.axvspan(start, stop, color=("#7dd3fc", "#c084fc")[i % 2], alpha=0.16)
        if section["size"] > report["size"] * 0.06:
            ax.text(
                (start + stop) / 2,
                0.25,
                section["name"][:20],
                ha="center",
                fontsize=8,
                parse_math=False,
            )
    ax.plot(
        [p["offset"] for p in report["profile"]],
        [p["entropy"] for p in report["profile"]],
        color=ACCENT,
        lw=1.2,
        marker="." if len(report["profile"]) < 2 else None,
    )
    ax.axhline(7.2, ls="--", lw=1, color="#fb923c", label="7.2 heuristic threshold")
    ax.set(
        title="01   /   Binary entropy profile",
        xlabel="Window start · file offset (bytes)",
        ylabel="Shannon entropy (bits/byte)",
        ylim=(0, 8.2),
        xlim=(0, max(1, report["size"])),
    )
    ax.grid(alpha=0.12)
    ax.legend(loc="lower right")
    return _save(fig)


@plt.style.context("dark_background")
def image_chart(report, rgb):
    fig = plt.figure(figsize=(11, 5), layout="constrained", facecolor="#101923")
    grid = fig.add_gridspec(2, 4, height_ratios=[1, 1.1])
    # Bound preview resolution; statistical tests always use full resolution.
    display = rgb[
        :: max(1, (rgb.shape[0] + 599) // 600), :: max(1, (rgb.shape[1] + 599) // 600)
    ]
    planes = bit_planes(display)
    for i, title in enumerate(
        ["Decoded image", "Red · bit 0", "Green · bit 0", "Blue · bit 0"]
    ):
        ax = fig.add_subplot(grid[0, i])
        ax.axis("off")
        ax.set_title(title, fontsize=11)
        ax.imshow(
            display if i == 0 else planes[:, :, i - 1],
            cmap="gray",
            vmin=0,
            vmax=1,
            interpolation="nearest",
            aspect=report["height"]
            * display.shape[1]
            / (report["width"] * display.shape[0]),
        )
    ax = fig.add_subplot(grid[1, :])
    ax.set_facecolor("#16222d")
    for c, color in zip(CHANNELS, ["#fb7185", ACCENT, "#7dd3fc"]):
        ax.plot(
            [s["fraction"] for s in report["scans"]],
            [s["channels"][c]["p_value"] for s in report["scans"]],
            marker=".",
            label=c,
            color=color,
        )
    ax.axhline(0.95, ls="--", color="#fb923c", lw=1)
    ax.set(
        xlabel="Cumulative rows sampled",
        ylabel="PoV upper-tail score",
        ylim=(-0.04, 1.04),
    )
    ax.xaxis.set_major_formatter(PercentFormatter(1))
    ax.grid(alpha=0.12)
    ax.legend(ncol=3)
    return _save(fig)
