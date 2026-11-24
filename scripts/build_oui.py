"""Build src/mcp_tplink_router/data/oui.tsv.gz from IEEE's public MA-L registry.

    python scripts/build_oui.py [path-or-url-of-oui.txt]

Source: https://standards-oui.ieee.org/oui/oui.txt (the IEEE Registration Authority's public listing).
Re-run before a release to pick up new assignments.
"""

from __future__ import annotations

import gzip
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUT = Path(__file__).resolve().parent.parent / "src" / "mcp_tplink_router" / "data" / "oui.tsv.gz"
LINE = re.compile(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+?)\s*$")


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else URL
    if src.startswith("https://"):
        req = urllib.request.Request(src, headers={"User-Agent": "opus-tplink-mcp build_oui"})
        text = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")  # nosec B310 - fixed https URL
    else:
        text = Path(src).read_text(encoding="utf-8", errors="replace")
    rows = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if m:
            rows[m.group(1)] = " ".join(m.group(2).split())
    if len(rows) < 30000:
        raise SystemExit(f"only {len(rows)} entries parsed - not the IEEE MA-L list?")
    body = "".join(f"{k}\t{v}\n" for k, v in sorted(rows.items()))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(gzip.compress(body.encode("utf-8"), mtime=0))
    print(f"{len(rows)} prefixes -> {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
