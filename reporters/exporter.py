"""Shared human-readable tables and lossless machine-readable reports."""

import base64
import json
import re
from html import escape

NOTICE = (
    "Heuristic triage only. CLEAN means no configured rule fired, not proof of safety. "
    "Randomness cannot identify encryption; PoV scores are not embedding probabilities."
)


def text(value):
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.5g}"
    return "".join(c if c.isprintable() else "�" for c in str(value))


def tables(r):
    facts = [(k, r[k]) for k in ("name", "format", "size", "sha256", "verdict")]
    extra = []
    if r["mode"] == "binary":
        facts += [
            ("Entropy (bits/byte)", r["entropy"]),
            ("Window / stride", f"{r['window']} / {r['step']}"),
            ("Uniform χ²", r["uniformity"]["statistic"]),
            ("Uniform p", r["uniformity"]["p_value"]),
            ("Monte Carlo π", r["pi"]["estimate"]),
            ("Coordinate pairs", r["pi"]["pairs"]),
        ]
        if r["overlay"]:
            facts.extend((f"Overlay {k}", v) for k, v in r["overlay"].items())
        if r["imports"]:
            facts += [
                ("Parsed imports", r["imports"]["count"]),
                ("Import sample", ", ".join(r["imports"]["sample"])),
            ]
        if r["sections"]:
            extra.append(
                (
                    "Sections",
                    ["Name", "Offset", "Bytes", "Code", "H"],
                    [
                        [
                            s[k]
                            for k in ("name", "offset", "size", "executable", "entropy")
                        ]
                        for s in r["sections"]
                    ],
                )
            )
    else:
        facts.extend(
            (k, r[k])
            for k in (
                "source_mode",
                "width",
                "height",
                "trailing_bytes",
                "metadata_bytes",
            )
        )
        extra.append(
            (
                "Progressive PoV scores",
                ["Rows through", "R", "G", "B"],
                [
                    [s["end_row"], *(s["channels"][c]["p_value"] for c in "RGB")]
                    for s in r["scans"]
                ],
            )
        )
    if r.get("limitations"):
        extra.append(("Scope", ["Limitation"], [[note] for note in r["limitations"]]))
    return [
        ("Evidence", ["Measurement", "Value"], facts),
        *extra,
        (
            "Findings",
            ["Observation"],
            [[f] for f in r["findings"] or ["No rule fired"]],
        ),
    ]


def as_json(data):
    return json.dumps(data, ensure_ascii=True, allow_nan=False, indent=2) + "\n"


def markdown(report):
    def row(cells):
        return (
            "| "
            + " | ".join(
                re.sub(r"([\\|`*_\[\]])", r"\\\1", escape(text(v))) for v in cells
            )
            + " |"
        )

    lines = ["# Shannon forensic report", "", NOTICE]
    for title, headers, rows in tables(report):
        lines.extend(["", f"## {title}", "", row(headers), row(["---"] * len(headers))])
        lines.extend(map(row, rows))
    return "\n".join(lines) + "\n"


def html(report, chart):
    parts = [
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Shannon forensic report</title>',
        "<style>body{max-width:70rem;margin:2rem auto;padding:1rem;background:#101923;color:#e5edf3;font:16px system-ui}h1,h2{color:#5eead4}table{border-collapse:collapse}td,th{padding:.45rem;border:1px solid #42505e;text-align:left;overflow-wrap:anywhere}img{width:100%}</style>",
        "<h1>Shannon forensic report</h1><p>" + NOTICE + "</p>",
    ]
    for title, headers, rows in tables(report):
        parts += [
            f"<h2>{title}</h2><table><tr>",
            *(f"<th>{v}</th>" for v in headers),
            "</tr>",
        ]
        for cells in rows:
            parts.append(
                "<tr>" + "".join(f"<td>{escape(text(v))}</td>" for v in cells) + "</tr>"
            )
        parts.append("</table>")
    parts.append(
        '<img alt="Forensic diagnostics" src="data:image/png;base64,'
        + base64.b64encode(chart).decode("ascii")
        + '"></html>'
    )
    return "\n".join(parts)
