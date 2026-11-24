"""Who made a device, from its MAC address (IEEE's public MA-L registry, shipped in data/oui.tsv.gz).

A MAC with the 'locally administered' bit set (second hex digit 2, 6, A or E) is a PRIVATE / randomized address:
phones and laptops make these up per network for privacy.  Its first half is not a maker's prefix, so the maker
cannot be read from it - say so rather than guessing (a lookup would return nothing, or a coincidence).
"""

from __future__ import annotations

import gzip
from functools import lru_cache
from importlib import resources

PRIVATE_NOTE = ("private (randomized) address - the maker cannot be read from it. Phones and laptops make these "
                "up for privacy; extenders and mesh units also use them for extra interfaces")
# Well-known locally administered prefixes that are NOT random: virtual machines and containers.
VIRTUAL = {"525400": "QEMU/KVM virtual machine", "0242": "Docker container network interface"}


def is_private(mac: str) -> bool:
    hexed = "".join(c for c in str(mac).upper() if c in "0123456789ABCDEF")
    return len(hexed) >= 2 and int(hexed[1], 16) & 2 == 2


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    try:
        raw = resources.files(__package__).joinpath("data/oui.tsv.gz").read_bytes()
    except (FileNotFoundError, OSError):
        return {}
    out = {}
    for line in gzip.decompress(raw).decode("utf-8").splitlines():
        prefix, _, name = line.partition("\t")
        out[prefix] = name
    return out


def virtual(mac: str) -> str | None:
    hexed = "".join(c for c in str(mac).upper() if c in "0123456789ABCDEF")
    return next((v for k, v in VIRTUAL.items() if hexed.startswith(k)), None)


def maker(mac: str) -> str | None:
    """The registered maker of a (non-private) MAC, or None when unknown or private."""
    hexed = "".join(c for c in str(mac).upper() if c in "0123456789ABCDEF")
    if len(hexed) < 6 or is_private(hexed):
        return None
    return _table().get(hexed[:6])
