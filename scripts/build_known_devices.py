"""Refresh src/mcp_tplink_router/data/known-devices.json (the shared device-names table shipped with a release).

    python scripts/build_known_devices.py [url-or-path]

Default source: https://kd.by-ai-for-ai.com/known-devices.json.  Run before a release.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

URL = "https://kd.by-ai-for-ai.com/known-devices.json"
OUT = Path(__file__).resolve().parent.parent / "src" / "mcp_tplink_router" / "data" / "known-devices.json"


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else URL
    if src.startswith("https://"):
        req = urllib.request.Request(src, headers={"User-Agent": "opus-tplink-mcp build_known_devices"})
        raw = urllib.request.urlopen(req, timeout=60).read(5_000_000)  # nosec B310 - fixed https URL
    else:
        raw = Path(src).read_bytes()
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise SystemExit("not a known-devices table")
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    print(f"{len(data['entries'])} entries -> {OUT}")


if __name__ == "__main__":
    main()
