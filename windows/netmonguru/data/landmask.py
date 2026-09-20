"""Embedded world land/ocean mask.

A 720x360 (0.5 degree) equirectangular boolean grid, row 0 = +90 deg latitude,
column 0 = -180 deg longitude.  Generated offline from the public-domain
GSHHG-derived land mask shipped with `global-land-mask`; embedded here so the
tool needs no map data at runtime.
"""

from __future__ import annotations

import base64
import zlib
from functools import lru_cache
from typing import List

MASK_W = 720
MASK_H = 360

_BLOB = (
    "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"
)


@lru_cache(maxsize=1)
def land_rows() -> List[bytes]:
    """Return the mask as a list of MASK_H rows, each MASK_W bytes of 0/1."""
    packed = zlib.decompress(base64.b64decode(_BLOB))
    bits = bytearray(MASK_W * MASK_H)
    for i in range(MASK_W * MASK_H):
        bits[i] = (packed[i >> 3] >> (7 - (i & 7))) & 1
    return [bytes(bits[r * MASK_W:(r + 1) * MASK_W]) for r in range(MASK_H)]


def is_land(lat: float, lon: float) -> bool:
    """True when the given coordinate falls on land."""
    row = int((90.0 - lat) / 180.0 * MASK_H)
    col = int((lon + 180.0) / 360.0 * MASK_W)
    row = min(max(row, 0), MASK_H - 1)
    col = min(max(col, 0), MASK_W - 1)
    return bool(land_rows()[row][col])
