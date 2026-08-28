"""Braille canvas helpers - 2x4 sub-cell resolution in a normal terminal."""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple

BRAILLE_BASE = 0x2800

# dot bit for (y_in_cell, x_in_cell)
DOT_BITS: Tuple[Tuple[int, int], ...] = (
    (0x01, 0x08),
    (0x02, 0x10),
    (0x04, 0x20),
    (0x40, 0x80),
)


class BrailleCanvas:
    """A width x height character grid addressed at 2x4 dot resolution."""

    __slots__ = ("width", "height", "dw", "dh", "cells")

    def __init__(self, width: int, height: int) -> None:
        self.width = max(1, width)
        self.height = max(1, height)
        self.dw = self.width * 2
        self.dh = self.height * 4
        self.cells: Dict[Tuple[int, int], int] = {}

    def set(self, x: int, y: int) -> None:
        if x < 0 or y < 0 or x >= self.dw or y >= self.dh:
            return
        cell = (y >> 2, x >> 1)
        self.cells[cell] = self.cells.get(cell, 0) | DOT_BITS[y & 3][x & 1]

    def line(self, x0: int, y0: int, x1: int, y1: int, step: int = 1) -> None:
        """Bresenham; ``step`` > 1 draws a dashed line."""
        dx = abs(x1 - x0)
        dy = -abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        err = dx + dy
        i = 0
        while True:
            if i % step == 0:
                self.set(x0, y0)
            i += 1
            if x0 == x1 and y0 == y1:
                break
            e2 = 2 * err
            if e2 >= dy:
                err += dy
                x0 += sx
            if e2 <= dx:
                err += dx
                y0 += sy

    def rows(self) -> List[List[str]]:
        grid = [[" "] * self.width for _ in range(self.height)]
        for (r, c), bits in self.cells.items():
            if 0 <= r < self.height and 0 <= c < self.width:
                grid[r][c] = chr(BRAILLE_BASE + bits)
        return grid


def braille_bars(values: Sequence[float], width: int, height: int,
                 maxval: float | None = None) -> List[str]:
    """Bottom-anchored braille bar graph, newest sample on the right."""
    width = max(1, width)
    height = max(1, height)
    dw, dh = width * 2, height * 4
    data: List[float] = list(values)[-dw:]
    if len(data) < dw:
        data = [0.0] * (dw - len(data)) + data
    top = maxval if maxval is not None else max(data or [0.0])
    if not top or top <= 0:
        top = 1.0

    canvas = BrailleCanvas(width, height)
    for x, v in enumerate(data):
        filled = int(round(max(0.0, min(1.0, v / top)) * dh))
        if v > 0:
            filled = max(1, filled)
        for k in range(filled):
            canvas.set(x, dh - 1 - k)
    return ["".join(row) for row in canvas.rows()]


def sparkline(values: Iterable[float], width: int = 20) -> str:
    """Single-row block sparkline for table cells."""
    blocks = " ▁▂▃▄▅▆▇█"
    data = list(values)[-width:]
    if not data:
        return ""
    top = max(data)
    if top <= 0:
        return "▁" * len(data)
    return "".join(blocks[min(8, int(v / top * 8) + (1 if v > 0 else 0))]
                   for v in data)
