"""Braille bandwidth graph (btop style: download above, upload below)."""

from __future__ import annotations

from typing import List, Sequence

from rich.text import Text
from textual.widget import Widget

from ...core.bandwidth import human_rate
from .braille import braille_bars

DOWN_STYLE = "#5fd7ff"
UP_STYLE = "#ffaf5f"
AXIS_STYLE = "#4a5a6a"


class BandwidthGraph(Widget):
    """Two stacked braille graphs sharing one auto-scaled y axis."""

    DEFAULT_CSS = """
    BandwidthGraph { height: 1fr; min-height: 8; }
    """

    def __init__(self, title: str = "total", **kwargs) -> None:
        super().__init__(**kwargs)
        self.title = title
        self.down: List[float] = []
        self.up: List[float] = []

    def update_series(self, title: str, down: Sequence[float],
                      up: Sequence[float]) -> None:
        self.title = title
        self.down = list(down)
        self.up = list(up)
        self.refresh()

    def on_resize(self, event) -> None:
        self.refresh()

    def render(self) -> Text:
        width = max(20, self.size.width)
        height = max(6, self.size.height)
        # 1 header line + 1 divider line
        body = max(4, height - 2)
        h_down = body // 2
        h_up = body - h_down

        peak = max([0.0] + list(self.down) + list(self.up))
        scale = peak if peak > 0 else 1.0

        cur_down = self.down[-1] if self.down else 0.0
        cur_up = self.up[-1] if self.up else 0.0

        out = Text(no_wrap=True, overflow="crop")
        head = f" {self.title} "
        out.append(head, style="bold #d0d0d0")
        out.append(f"▼ {human_rate(cur_down):>11}", style=DOWN_STYLE)
        out.append("   ")
        out.append(f"▲ {human_rate(cur_up):>11}", style=UP_STYLE)
        out.append(f"   peak {human_rate(peak)}", style=AXIS_STYLE)
        out.append("\n")

        for line in braille_bars(self.down, width, h_down, scale):
            out.append(line, style=DOWN_STYLE)
            out.append("\n")
        out.append("─" * width, style=AXIS_STYLE)
        out.append("\n")
        up_lines = braille_bars(self.up, width, h_up, scale)
        for i, line in enumerate(reversed(up_lines)):
            out.append(_flip(line), style=UP_STYLE)
            if i != len(up_lines) - 1:
                out.append("\n")
        return out


def _resample(values: Sequence[float], size: int) -> List[float]:
    """Stretch/squeeze a fixed-length series onto ``size`` points."""
    data = list(values)
    if not data or size <= 0:
        return list(data)
    if len(data) == size:
        return data
    step = len(data) / size
    return [data[min(len(data) - 1, int(i * step))] for i in range(size)]


class MiniGraph(Widget):
    """A short single-series braille graph with a caption."""

    DEFAULT_CSS = """
    MiniGraph { height: 5; }
    """

    def __init__(self, caption: str = "", color: str = "#5fd7ff",
                 **kwargs) -> None:
        super().__init__(**kwargs)
        self.caption = caption
        self.color = color
        self.values: List[float] = []

    def update_series(self, caption: str, values: Sequence[float]) -> None:
        self.caption = caption
        self.values = list(values)
        self.refresh()

    def on_resize(self, event) -> None:
        self.refresh()

    def render(self) -> Text:
        width = max(20, self.size.width)
        height = max(2, self.size.height)
        out = Text(no_wrap=True, overflow="crop")
        out.append(f" {self.caption}", style="#9fb0c0")
        out.append("\n")
        lines = braille_bars(_resample(self.values, width * 2), width,
                             height - 1)
        for i, line in enumerate(lines):
            out.append(line, style=self.color)
            if i != len(lines) - 1:
                out.append("\n")
        return out


_FLIP_MAP = {}


def _flip_bits(bits: int) -> int:
    # swap dot rows vertically inside the 2x4 cell
    pairs = [(0x01, 0x40), (0x02, 0x04), (0x08, 0x80), (0x10, 0x20)]
    out = 0
    for a, b in pairs:
        if bits & a:
            out |= b
        if bits & b:
            out |= a
    return out


def _flip(line: str) -> str:
    res = []
    for ch in line:
        code = ord(ch)
        if 0x2800 <= code <= 0x28FF:
            bits = code - 0x2800
            if bits not in _FLIP_MAP:
                _FLIP_MAP[bits] = _flip_bits(bits)
            res.append(chr(0x2800 + _FLIP_MAP[bits]))
        else:
            res.append(ch)
    return "".join(res)
