"""Compressed audit exports."""

from __future__ import annotations

import gzip
from pathlib import Path


def gzip_file(source: str | Path, output: str | Path | None = None) -> Path:
    """Create a gzip-compressed copy of a file."""

    source_path = Path(source)
    output_path = Path(output) if output is not None else source_path.with_suffix(source_path.suffix + ".gz")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with source_path.open("rb") as src, output_path.open("wb") as raw_dst:
        with gzip.GzipFile(fileobj=raw_dst, mode="wb", mtime=0) as dst:
            dst.writelines(src)
    return output_path


def gunzip_file(source: str | Path, output: str | Path) -> Path:
    """Decompress a gzip file."""

    source_path = Path(source)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(source_path, "rb") as src, output_path.open("wb") as dst:
        dst.writelines(src)
    return output_path
