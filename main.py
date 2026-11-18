"""Command line entry points; no sample execution, network or payload recovery."""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from analyzers.binary_analyzer import analyze_binary
from analyzers.steganalysis import analyze_image, decode
from core.evidence import snapshot
from reporters.exporter import NOTICE, as_json, html, markdown, tables, text


def parser():
    p = argparse.ArgumentParser(
        description="Static entropy and RGB steganalysis triage"
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    for cmd in ["analyze-bin", "analyze-img", "batch"]:
        s = sub.add_parser(cmd)
        if cmd == "batch":
            s.add_argument(
                "-d", required=True, type=Path, help="directory to scan recursively"
            )
        else:
            s.add_argument("-f", required=True, type=Path)
            s.add_argument(
                "--plot",
                action="store_true",
                help="save diagnostic PNG in current directory",
            )
            s.add_argument("--html", type=Path)
            s.add_argument("--markdown", "--md", type=Path)
        if cmd != "analyze-img":
            s.add_argument("--window", type=int, default=1024)
            s.add_argument("--step", type=int, default=256)
        s.add_argument("--json", type=Path)
    return p


def save(path, content):
    # Exclusive creation: never replace evidence, even via a symlink.
    with path.open("xb") as f:
        f.write(content if isinstance(content, bytes) else content.encode("utf8"))


def show(report, console):
    for title, cols, rows in tables(report):
        table = Table(*cols, title=title, title_style="bold cyan")
        for row in rows:
            table.add_row(*(Text(text(v)) for v in row))
        console.print(table)
    console.print(NOTICE)


def batch(a, console):
    if not a.d.is_dir():
        raise ValueError("batch input is not a directory")
    rows = []
    for path in sorted(a.d.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        name = str(path.relative_to(a.d))
        try:
            data = snapshot(path)
            if data.startswith(
                (b"\x89PNG\r\n\x1a\n", b"BM", b"II*\0", b"MM\0*")
            ) or path.suffix.lower() in {".png", ".bmp", ".tif", ".tiff"}:
                r = analyze_image(data, name)
            else:
                r = analyze_binary(data, name, a.window, a.step)
            rows.append(
                {
                    k: r[k]
                    for k in (
                        "name",
                        "mode",
                        "size",
                        "format",
                        "sha256",
                        "verdict",
                        "findings",
                    )
                }
            )
        # Per-item error boundary; one malformed sample must not abort the batch.
        except Exception as exc:  # noqa: BLE001
            rows.append({"name": name, "error": text(exc)})
        console.print(
            Text(f"{text(name)}: {rows[-1].get('verdict', rows[-1].get('error'))}")
        )
    if a.json:
        save(a.json, as_json({"schema_version": 1, "files": rows}))
    return int(any("error" in row for row in rows))


def main(argv=None):
    a = parser().parse_args(argv)
    console = Console()
    try:
        if getattr(a, "step", 1) <= 0 or getattr(a, "window", 1) <= 0:
            raise ValueError("window and step must be positive")
        if a.cmd == "batch":
            return batch(a, console)
        data = snapshot(a.f)
        binary = a.cmd == "analyze-bin"
        r = (
            analyze_binary(data, a.f.name, a.window, a.step)
            if binary
            else analyze_image(data, a.f.name)
        )
        show(r, console)
        if a.plot or a.html:
            from visualizers.plotter import binary_chart, image_chart

            chart = binary_chart(r) if binary else image_chart(r, decode(data)[0])
            if a.plot:
                save(Path("entropy_plot.png" if binary else "steg_plot.png"), chart)
            if a.html:
                save(a.html, html(r, chart))
        if a.markdown:
            save(a.markdown, markdown(r))
        if a.json:
            save(a.json, as_json(r))
    except Exception as exc:  # noqa: BLE001 - CLI error boundary
        Console(stderr=True).print(Text(f"Error: {text(exc)}"))
        return 1
    return 0


def entrypoint():
    sys.exit(main())


if __name__ == "__main__":
    entrypoint()
