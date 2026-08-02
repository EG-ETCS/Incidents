#!/usr/bin/env python3
"""Update the index hero status date between INDEX_DATE markers."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "docs" / "index.md"
TIMEZONE = ZoneInfo("Africa/Cairo")
PATTERN = re.compile(
    r"(<!--INDEX_DATE-->)(.*?)(<!--/INDEX_DATE-->)",
    re.DOTALL,
)


def format_today(now: datetime | None = None) -> str:
    current = now or datetime.now(TIMEZONE)
    # e.g. Sunday, August 2, 2026
    return f"{current.strftime('%A')}, {current.strftime('%B')} {current.day}, {current.year}"


def update_index(path: Path = INDEX) -> bool:
    text = path.read_text(encoding="utf-8")
    if not PATTERN.search(text):
        raise SystemExit(
            f"Could not find <!--INDEX_DATE--> markers in {path.relative_to(ROOT)}"
        )

    today = format_today()
    updated, count = PATTERN.subn(rf"\g<1>{today}\g<3>", text, count=1)
    if count != 1:
        raise SystemExit("Failed to replace INDEX_DATE marker")

    if updated == text:
        print(f"Index date already current: {today}")
        return False

    path.write_text(updated, encoding="utf-8", newline="\n")
    print(f"Updated index date to: {today}")
    return True


if __name__ == "__main__":
    update_index()
