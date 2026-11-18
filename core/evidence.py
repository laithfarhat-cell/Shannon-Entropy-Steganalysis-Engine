"""Read-only bounded evidence snapshots; shared report identity."""

import hashlib
from pathlib import Path

MAX_BYTES = 64 * 1024**2


def snapshot(path: Path) -> bytes:
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("expected a regular file of at most 64 MiB")
    with path.open("rb") as f:
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("file exceeds 64 MiB")
    return data


def identity(data: bytes, name: str, mode: str) -> dict:
    return {
        "schema_version": 1,
        "name": name,
        "mode": mode,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
