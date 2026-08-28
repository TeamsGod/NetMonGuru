"""Braille world map with connection arcs and clickable destination markers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from rich.text import Text
from textual import events
from textual.message import Message
from textual.widget import Widget

from ...data.landmask import MASK_H, MASK_W, land_rows

LAND_STYLE = "#2f6f4f"
GRID_STYLE = "#1b2733"
ARC_STYLE = "#4d86b8"
ARC_SELECTED_STYLE = "#ffd75f"
HOME_STYLE = "bold #ffd75f"

MARKER_PALETTE = [
    "#ff5f5f", "#5fd7ff", "#ffaf5f", "#af87ff", "#5fff87",
    "#ff87d7", "#87d7ff", "#d7ff5f", "#ff875f", "#87ffaf",
]

#: markers get bigger as more sockets share one location
SIZE_MARKERS = ((10, "◉"), (4, "●"), (0, "•"))

#: how far (in cells) a click may land from a marker and still select it
CLICK_RADIUS = 2


@dataclass(slots=True)
class MapPoint:
    lat: float
    lon: float
    count: int
    label: str
    detail: str = ""
    color: str = MARKER_PALETTE[0]
    marker: str = "●"
    ips: List[str] = field(default_factory=list)

    def size_marker(self) -> str:
        for threshold, char in SIZE_MARKERS:
            if self.count > threshold:
                return char
        return "•"


class WorldMap(Widget):
    """Equirectangular land mask, arcs from home, one marker per destination.

    Markers are mouse-clickable and keyboard-selectable; selecting one posts
    :class:`WorldMap.PointSelected` so the screen can expand its details.
    """

    DEFAULT_CSS = """
    WorldMap { height: 1fr; }
    """

    can_focus = True

    lat_top = 80.0
    lat_bottom = -58.0

    class PointSelected(Message):
        """Posted when a destination marker is picked."""

        def __init__(self, index: int) -> None:
            super().__init__()
            self.index = index

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.points: List[MapPoint] = []
        self.home: Optional[Tuple[float, float]] = None
        self.show_arcs = True
        self.selected: int = -1
        self._marker_cells: Dict[Tuple[int, int], int] = {}

    # -- data --------------------------------------------------------------
    def update_points(self, points: List[MapPoint],
                      home: Optional[Tuple[float, float]]) -> None:
        self.points = points
        self.home = home
        if self.selected >= len(points):
            self.selected = len(points) - 1
        self.refresh()

    def toggle_arcs(self) -> None:
        self.show_arcs = not self.show_arcs
        self.refresh()

    def select(self, index: int) -> None:
        if not self.points:
            return
        index = max(0, min(index, len(self.points) - 1))
        if index != self.selected:
            self.selected = index
            self.refresh()
            self.post_message(self.PointSelected(index))

    def select_next(self, step: int = 1) -> None:
        if not self.points:
            return
        start = self.selected if self.selected >= 0 else -1
        self.select((start + step) % len(self.points))

    # -- input -------------------------------------------------------------
    def on_click(self, event: events.Click) -> None:
        idx = self._hit_test(event.x, event.y)
        if idx is not None:
            self.focus()
            self.select(idx)
            event.stop()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        idx = self._hit_test(event.x, event.y)
        self.tooltip = self._tooltip_for(idx) if idx is not None else None

    def _tooltip_for(self, idx: int) -> str:
        p = self.points[idx]
        return (f"{p.label} — {p.count} socket(s)\n"
                f"{p.detail or 'unknown org'}\nclick for details")

    def _hit_test(self, x: int, y: int) -> Optional[int]:
        """Nearest marker within CLICK_RADIUS cells of (x, y)."""
        best: Optional[int] = None
        best_d = CLICK_RADIUS * CLICK_RADIUS + 1
        for (row, col), idx in self._marker_cells.items():
            d = (row - y) ** 2 + (col - x) ** 2
            if d < best_d:
                best, best_d = idx, d
        return best

    # -- rendering ---------------------------------------------------------
    def on_resize(self, event) -> None:
        self.refresh()

    def render(self) -> Text:
        width = max(20, self.size.width)
        height = max(6, self.size.height)
        dw, dh = width * 2, height * 4

        land = self._land_cells(width, height, dw, dh)
        arcs: Dict[Tuple[int, int], int] = {}
        hot_arcs: Dict[Tuple[int, int], int] = {}
        markers: Dict[Tuple[int, int], Tuple[str, str]] = {}
        self._marker_cells = {}

        home_xy = None
        if self.home:
            home_xy = self._project(self.home[0], self.home[1], dw, dh)

        from .braille import BrailleCanvas

        if home_xy and (self.show_arcs or self.selected >= 0):
            canvas = BrailleCanvas(width, height)
            hot = BrailleCanvas(width, height)
            for idx, p in enumerate(self.points):
                target = self._project(p.lat, p.lon, dw, dh)
                if not target:
                    continue
                if idx == self.selected:
                    hot.line(home_xy[0], home_xy[1], target[0], target[1],
                             step=1)
                elif self.show_arcs:
                    canvas.line(home_xy[0], home_xy[1], target[0], target[1],
                                step=3)
            arcs = canvas.cells
            hot_arcs = hot.cells

        for idx, p in enumerate(self.points):
            xy = self._project(p.lat, p.lon, dw, dh)
            if not xy:
                continue
            cell = (xy[1] >> 2, xy[0] >> 1)
            style = p.color
            char = p.size_marker()
            if idx == self.selected:
                style = f"bold reverse {p.color}"
                char = "◉"
            markers[cell] = (char, style)
            self._marker_cells[cell] = idx

        if home_xy:
            markers[(home_xy[1] >> 2, home_xy[0] >> 1)] = ("⌂", HOME_STYLE)

        out = Text(no_wrap=True, overflow="crop")
        for r in range(height):
            for c in range(width):
                cell = (r, c)
                if cell in markers:
                    char, style = markers[cell]
                    out.append(char, style=style)
                    continue
                bits = land.get(cell, 0)
                hot = hot_arcs.get(cell, 0)
                arc = arcs.get(cell, 0)
                if hot:
                    out.append(chr(0x2800 + (bits | hot)),
                               style=ARC_SELECTED_STYLE)
                elif arc:
                    out.append(chr(0x2800 + (bits | arc)), style=ARC_STYLE)
                elif bits:
                    out.append(chr(0x2800 + bits), style=LAND_STYLE)
                else:
                    out.append("·" if (r % 3 == 1 and c % 6 == 3) else " ",
                               style=GRID_STYLE)
            if r != height - 1:
                out.append("\n")
        return out

    # -- projection --------------------------------------------------------
    def _project(self, lat: float, lon: float, dw: int, dh: int
                 ) -> Optional[Tuple[int, int]]:
        span = self.lat_top - self.lat_bottom
        lat = min(max(lat, self.lat_bottom), self.lat_top)
        x = int((lon + 180.0) / 360.0 * dw)
        y = int((self.lat_top - lat) / span * dh)
        if x < 0 or y < 0 or x >= dw or y >= dh:
            return None
        return x, y

    # -- land cache --------------------------------------------------------
    _cache_key: Tuple[int, int] = (0, 0)
    _cache_cells: Dict[Tuple[int, int], int] = {}

    def _land_cells(self, width: int, height: int, dw: int, dh: int
                    ) -> Dict[Tuple[int, int], int]:
        key = (width, height)
        if key == self._cache_key and self._cache_cells:
            return self._cache_cells

        from .braille import DOT_BITS

        rows = land_rows()
        span = self.lat_top - self.lat_bottom
        cells: Dict[Tuple[int, int], int] = {}
        for y in range(dh):
            lat = self.lat_top - (y + 0.5) / dh * span
            mrow = int((90.0 - lat) / 180.0 * MASK_H)
            mrow = min(max(mrow, 0), MASK_H - 1)
            row = rows[mrow]
            cy, dy = y >> 2, y & 3
            for x in range(dw):
                mcol = int(x / dw * MASK_W)
                if row[mcol]:
                    cell = (cy, x >> 1)
                    cells[cell] = cells.get(cell, 0) | DOT_BITS[dy][x & 1]
        self._cache_key = key
        self._cache_cells = cells
        return cells
