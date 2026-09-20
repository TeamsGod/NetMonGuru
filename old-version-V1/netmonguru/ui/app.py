"""NetMonGuru - btop-style network monitor for macOS (Textual TUI)."""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (DataTable, Footer, Input, Static, TabbedContent,
                             TabPane)

from ..core.bandwidth import human_bytes, human_rate
from ..core.models import Connection, GeoInfo, Snapshot, classify_address
from ..core.monitor import Monitor
from ..core.procs import aggregate
from .widgets.braille import sparkline
from .widgets.graph import BandwidthGraph, MiniGraph
from .widgets.worldmap import MARKER_PALETTE, MapPoint, WorldMap

STATE_STYLES = {
    "ESTABLISHED": "#5fff87",
    "LISTEN": "#5fd7ff",
    "SYN_SENT": "#ffd75f",
    "SYN_RECV": "#ffd75f",
    "TIME_WAIT": "#7a8a99",
    "CLOSE_WAIT": "#ffaf5f",
    "FIN_WAIT_1": "#ffaf5f",
    "FIN_WAIT_2": "#ffaf5f",
    "CLOSED": "#7a8a99",
}

SOURCE_STYLES = {
    "log": "#5fff87",
    "pcap": "#ffd75f",
    "passive": "#7a8a99",
    "demo": "#af87ff",
}

SORTS = [("process", "Process"), ("proto", "Proto"), ("state", "State"),
         ("remote", "Remote"), ("country", "Country"), ("pid", "PID")]

#: which widget takes focus when a pane is opened - a focused widget left
#: behind in a hidden pane makes TabbedContent snap back to it.
TAB_FOCUS = {
    "tab-conn": "#conn-table",
    "tab-map": "#worldmap",
    "tab-bw": "#nic-table",
    "tab-proc": "#proc-table",
    "tab-dns": "#dns-live",
}


def _state_text(c: Connection) -> Text:
    label = c.state or ("—" if c.proto == "UDP" else "")
    return Text(label, style=STATE_STYLES.get(c.state, "#c0c0c0"))


def _short_location(g: Optional[GeoInfo]) -> str:
    """``Warsaw, PL`` - compact enough for a table column."""
    if g is None:
        return ""
    if g.source == "local":
        return g.country
    if g.city and g.country_code:
        return f"{g.city}, {g.country_code}"
    return g.city or g.country or ""


def _proto_text(c: Connection) -> Text:
    style = "#87d7ff" if c.proto == "TCP" else "#d7afff"
    suffix = "6" if c.family == "IPv6" else ""
    return Text(f"{c.proto}{suffix}", style=style)


def _ago(ts: float) -> str:
    delta = max(0, int(time.time() - ts))
    if delta < 60:
        return f"{delta}s"
    return f"{delta // 60}m{delta % 60:02d}s"


class SummaryBar(Static):
    DEFAULT_CSS = """
    SummaryBar {
        height: 1; background: #10161d; color: #c8d3de; padding: 0 1;
    }
    """


class FilterBar(Static):
    DEFAULT_CSS = """
    FilterBar { height: 1; background: #0c1116; color: #7a8a99; padding: 0 1; }
    """


class DetailBar(Static):
    DEFAULT_CSS = """
    DetailBar {
        height: 3; background: #0c1116; color: #9fb0c0; padding: 0 1;
        border-top: solid #1f2b36;
    }
    """


class NetMonGuruApp(App):
    """The application shell: five panes over one shared snapshot."""

    CSS = """
    Screen { background: #06090c; }
    TabbedContent { height: 1fr; }
    DataTable { height: 1fr; background: #06090c; }
    DataTable > .datatable--cursor { background: #1d3b52; }
    #search { display: none; height: 3; border: tall #2b4a63; }
    #search.visible { display: block; }
    #worldmap { width: 1fr; height: 1fr; }
    #map-side { width: 52; height: 1fr; border-left: solid #1f2b36; }
    #map-detail-head {
        height: 3; background: #0c1116; color: #9fb0c0; padding: 0 1;
        border-top: solid #1f2b36;
    }
    #map-detail { height: 11; }
    #nic-table { height: 12; }
    #dns-status { height: 1; background: #0c1116; padding: 0 1; }
    #dns-rate { height: 5; }
    #dns-cache { height: 14; }
    .pane-title {
        height: 1; background: #10161d; color: #7fb3d5; padding: 0 1;
    }
    .note { color: #ffaf5f; padding: 0 1; height: auto; }
    """

    ENABLE_COMMAND_PALETTE = False
    AUTO_FOCUS = "#conn-table"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("1", "show_tab('tab-conn')", "Conns"),
        Binding("2", "show_tab('tab-map')", "Map"),
        Binding("3", "show_tab('tab-bw')", "Bandwidth"),
        Binding("4", "show_tab('tab-proc')", "Procs"),
        Binding("5", "show_tab('tab-dns')", "DNS"),
        Binding("t", "toggle_tcp", "TCP"),
        Binding("u", "toggle_udp", "UDP"),
        Binding("e", "toggle_established", "Estab"),
        Binding("l", "toggle_listening", "Listen"),
        Binding("p", "toggle_private", "Public only"),
        Binding("slash", "search", "Search"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("space", "toggle_pause", "Pause"),
        Binding("r", "reverse_sort", "Reverse", show=False),
        Binding("a", "toggle_arcs", "Arcs", show=False),
        Binding("n", "cycle_nic", "Interface", show=False),
        Binding("comma", "map_prev", "Prev marker", show=False),
        Binding("full_stop", "map_next", "Next marker", show=False),
        Binding("escape", "clear_search", "Clear", show=False),
    ]

    def __init__(self, monitor: Monitor) -> None:
        super().__init__()
        self.monitor = monitor
        self.snapshot: Snapshot = monitor.snapshot
        self.show_tcp = True
        self.show_udp = True
        self.only_established = False
        self.show_listening = True
        self.show_private = True
        self.search_term = ""
        self.sort_idx = 0
        self.sort_reverse = False
        self.nic_choice = "total"
        self.rows: List[Connection] = []
        self.map_points: List[MapPoint] = []
        self.map_detail_rows: List[Connection] = []
        self.dns_rows: List = []
        self.dns_cache_rows: List = []
        self._syncing_geo = False

    # -- layout ------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield SummaryBar(id="summary")
        yield Input(placeholder="filter: process, ip, port, country, "
                                "hostname…", id="search")
        with TabbedContent(initial="tab-conn", id="tabs"):
            with TabPane("Connections", id="tab-conn"):
                yield FilterBar(id="filters")
                yield DataTable(id="conn-table", zebra_stripes=True,
                                cursor_type="row")
                yield DetailBar(id="detail")
            with TabPane("Map", id="tab-map"):
                with Horizontal():
                    with Vertical():
                        yield WorldMap(id="worldmap")
                        yield Static("", id="map-detail-head")
                        yield DataTable(id="map-detail", zebra_stripes=True,
                                        cursor_type="row")
                    with Vertical(id="map-side"):
                        yield Static(" DESTINATIONS", classes="pane-title")
                        yield DataTable(id="geo-table", zebra_stripes=True,
                                        cursor_type="row")
            with TabPane("Bandwidth", id="tab-bw"):
                yield BandwidthGraph(id="bw-graph")
                yield DataTable(id="nic-table", zebra_stripes=True,
                                cursor_type="row")
            with TabPane("Processes", id="tab-proc"):
                yield Static("", id="proc-note", classes="note")
                yield DataTable(id="proc-table", zebra_stripes=True,
                                cursor_type="row")
            with TabPane("DNS", id="tab-dns"):
                yield Static("", id="dns-status")
                yield MiniGraph(color="#af87ff", id="dns-rate")
                yield Static(" LIVE RESOLUTIONS", classes="pane-title")
                yield DataTable(id="dns-live", zebra_stripes=True,
                                cursor_type="row")
                yield Static(" CACHE", id="dns-cache-title",
                             classes="pane-title")
                yield DataTable(id="dns-cache", zebra_stripes=True,
                                cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "NetMonGuru"
        ct = self.query_one("#conn-table", DataTable)
        ct.add_columns("PROTO", "STATE", "PID", "PROCESS", "LOCAL",
                       "REMOTE", "HOST / ORG", "LOCATION")
        gt = self.query_one("#geo-table", DataTable)
        for label, w in ((" ", 1), ("LOCATION", 22), ("ORG", 14), ("N", 3)):
            gt.add_column(label, width=w)
        md = self.query_one("#map-detail", DataTable)
        md.add_columns("PROTO", "STATE", "PID", "PROCESS", "LOCAL",
                       "REMOTE", "HOSTNAME")
        nt = self.query_one("#nic-table", DataTable)
        nt.add_columns("IFACE", "DOWN", "UP", "RECV", "SENT", "HISTORY")
        pt = self.query_one("#proc-table", DataTable)
        pt.add_columns("PID", "PROCESS", "DOWN", "UP", "IN", "OUT",
                       "SOCKETS", "ESTAB", "PEERS", "LISTENING")
        dl = self.query_one("#dns-live", DataTable)
        dl.add_columns("TIME", "SRC", "CLIENT", "TYPE", "QUERY", "ANSWERS")
        dc = self.query_one("#dns-cache", DataTable)
        dc.add_columns("NAME", "ADDRESSES", "HITS", "AGE", "TTL")

        self.query_one("#conn-table", DataTable).focus()
        self.monitor.start()
        self.set_interval(0.5, self.tick)
        self.tick()

    def _find(self, selector: str, kind):
        """query_one that tolerates a screen being torn down."""
        try:
            return self.query_one(selector, kind)
        except Exception:                              # noqa: BLE001
            return None

    # -- refresh -----------------------------------------------------------
    def tick(self) -> None:
        summary = self._find("#summary", SummaryBar)
        if summary is None:            # screen not mounted / shutting down
            return
        self.snapshot = self.monitor.snapshot
        try:
            self._render_summary()
            self._render_connections()
            self._render_map()
            self._render_bandwidth()
            self._render_processes()
            self._render_dns()
        except Exception as exc:                       # noqa: BLE001
            summary.update(Text(f"render error: {exc}", style="bold red"))

    # -- connections -------------------------------------------------------
    def _geo(self, ip: str) -> Optional[GeoInfo]:
        return self.snapshot.geo.get(ip) if ip else None

    def _hostname(self, ip: str) -> str:
        """Prefer a name we actually watched being resolved over a PTR."""
        if not ip:
            return ""
        observed = self.snapshot.dns_names.get(ip)
        if observed:
            return observed
        g = self._geo(ip)
        return (g.hostname or g.org or "") if g else ""

    def _matches(self, c: Connection) -> bool:
        if c.proto == "TCP" and not self.show_tcp:
            return False
        if c.proto == "UDP" and not self.show_udp:
            return False
        if not self.show_listening and c.is_listening:
            return False
        if self.only_established and c.state != "ESTABLISHED":
            return False
        if not self.show_private and classify_address(c.raddr) != "public":
            return False
        if self.search_term:
            g = self._geo(c.raddr)
            hay = " ".join([
                c.proto, c.state, c.pname, str(c.pid or ""), c.local, c.remote,
                self._hostname(c.raddr), (g.org if g else ""),
                (g.label if g else ""), (g.country_code if g else ""),
            ]).lower()
            if self.search_term.lower() not in hay:
                return False
        return True

    def _sort_key(self, c: Connection):
        mode = SORTS[self.sort_idx][0]
        g = self._geo(c.raddr)
        if mode == "process":
            return (c.pname.lower(), c.pid or 0)
        if mode == "proto":
            return (c.proto, c.family, c.lport)
        if mode == "state":
            return (c.state or "zz", c.pname.lower())
        if mode == "remote":
            return (c.raddr or "zzz", c.rport)
        if mode == "country":
            return ((g.country if g else "zzz"), c.pname.lower())
        return (c.pid or 0, c.pname.lower())

    def _render_connections(self) -> None:
        table = self._find("#conn-table", DataTable)
        if table is None:
            return
        rows = [c for c in self.snapshot.connections if self._matches(c)]
        rows.sort(key=self._sort_key, reverse=self.sort_reverse)
        self.rows = rows

        cursor = table.cursor_row
        table.clear()
        for c in rows:
            table.add_row(
                _proto_text(c),
                _state_text(c),
                Text(str(c.pid or "-"), style="#7a8a99"),
                Text(c.pname[:22], style="#e6edf3"),
                Text(c.local, style="#9fb0c0"),
                Text(c.remote, style="#c8d3de" if c.raddr else "#4a5a6a"),
                Text(self._hostname(c.raddr)[:36], style="#7fb3d5"),
                Text(_short_location(self._geo(c.raddr))[:24],
                     style="#c6a15b"),
            )
        if rows:
            table.move_cursor(row=min(cursor, len(rows) - 1))

        filters = self._find("#filters", FilterBar)
        if filters is not None:
            filters.update(self._filter_line())
        self._render_detail()

    def _filter_line(self) -> Text:
        t = Text()
        for on, label in ((self.show_tcp, "TCP"), (self.show_udp, "UDP"),
                          (self.show_listening, "LISTEN"),
                          (self.only_established, "ESTAB-ONLY"),
                          (self.show_private, "PRIVATE")):
            t.append(f" {label} ", style="bold #06090c on #5fd7ff" if on
                     else "#4a5a6a")
            t.append(" ")
        t.append(f" sort:{SORTS[self.sort_idx][1]}"
                 f"{'↓' if self.sort_reverse else '↑'} ", style="#9fb0c0")
        if self.search_term:
            t.append(f" /{self.search_term} ", style="bold #ffd75f")
        t.append(f"  {len(self.rows)} shown", style="#4a5a6a")
        return t

    def _render_detail(self) -> None:
        bar = self._find("#detail", DetailBar)
        table = self._find("#conn-table", DataTable)
        if bar is None or table is None:
            return
        idx = table.cursor_row
        if not self.rows or idx is None or idx >= len(self.rows):
            bar.update(Text("—", style="#4a5a6a"))
            return
        c = self.rows[idx]
        g = self._geo(c.raddr)
        t = Text()
        t.append(f"{c.pname} ", style="bold #e6edf3")
        t.append(f"(pid {c.pid or '?'})  ", style="#7a8a99")
        t.append(f"{c.local} → {c.remote}  ", style="#c8d3de")
        t.append(f"{c.proto}/{c.family} {c.state}\n", style="#9fb0c0")
        if g:
            t.append(f"host {self._hostname(c.raddr) or '-'}   ",
                     style="#7fb3d5")
            t.append(f"org {g.org or '-'}   ", style="#c6a15b")
            t.append(f"asn {g.asn or '-'}   ", style="#c6a15b")
            t.append(f"loc {g.label}", style="#c6a15b")
        elif c.raddr:
            t.append("resolving…", style="#4a5a6a")
        else:
            t.append("local socket", style="#4a5a6a")
        bar.update(t)

    # -- map ---------------------------------------------------------------
    def _render_map(self) -> None:
        world = self._find("#worldmap", WorldMap)
        table = self._find("#geo-table", DataTable)
        if world is None or table is None:
            return
        buckets: Dict[Tuple[float, float], MapPoint] = {}
        for c in self.snapshot.connections:
            if not c.raddr:
                continue
            g = self._geo(c.raddr)
            if not g or not g.located:
                continue
            key = (round(g.lat, 1), round(g.lon, 1))
            p = buckets.get(key)
            if p is None:
                buckets[key] = MapPoint(lat=g.lat, lon=g.lon, count=1,
                                        label=_short_location(g) or g.country,
                                        detail=g.org or g.asn,
                                        ips=[c.raddr])
            else:
                p.count += 1
                if c.raddr not in p.ips:
                    p.ips.append(c.raddr)
        points = sorted(buckets.values(), key=lambda p: -p.count)
        for i, p in enumerate(points):
            p.color = MARKER_PALETTE[i % len(MARKER_PALETTE)]
        self.map_points = points

        home = None
        h = self.monitor.enricher.home
        if h and h.located:
            home = (h.lat, h.lon)
        world.update_points(points, home)

        cursor = table.cursor_row
        table.clear()
        for p in points:
            table.add_row(Text(p.size_marker(), style=p.color),
                          Text(p.label[:20], style="#e6edf3"),
                          Text((p.detail or "-")[:13], style="#7fb3d5"),
                          Text(str(p.count), style="#5fff87"))
        if points:
            self._syncing_geo = True
            try:
                target = world.selected if world.selected >= 0 else (cursor or 0)
                table.move_cursor(row=min(max(target, 0), len(points) - 1))
            finally:
                self._syncing_geo = False
        else:
            table.add_row("", Text("no located peers yet", style="#4a5a6a"),
                          "", "")
        self._render_map_detail()

    def _render_map_detail(self) -> None:
        head = self._find("#map-detail-head", Static)
        table = self._find("#map-detail", DataTable)
        world = self._find("#worldmap", WorldMap)
        if head is None or table is None or world is None:
            return
        idx = world.selected

        table.clear()
        if idx < 0 or idx >= len(self.map_points):
            self.map_detail_rows = []
            head.update(Text("click a marker on the map (or pick a row on the "
                             "right) to expand its connections",
                             style="#4a5a6a"))
            return

        point = self.map_points[idx]
        ips = set(point.ips)
        rows = [c for c in self.snapshot.connections if c.raddr in ips]
        rows.sort(key=lambda c: (c.pname.lower(), c.raddr, c.rport))
        self.map_detail_rows = rows

        procs = sorted({c.pname for c in rows if c.pname and c.pname != "?"})
        est = sum(1 for c in rows if c.state == "ESTABLISHED")
        geo = self._geo(point.ips[0]) if point.ips else None

        t = Text()
        t.append(f" {point.label} ", style=f"bold {point.color}")
        t.append(f" {len(rows)} socket(s), {est} established  ",
                 style="#c8d3de")
        t.append(f"{len(ips)} address(es)  ", style="#9fb0c0")
        t.append(f"{point.lat:.2f}, {point.lon:.2f}\n", style="#4a5a6a")
        if geo:
            t.append(f" {geo.org or '-'}", style="#c6a15b")
            t.append(f"   {geo.asn or '-'}", style="#c6a15b")
            t.append(f"   {geo.country}", style="#c6a15b")
        if procs:
            t.append(f"   processes: {', '.join(procs[:6])}", style="#7fb3d5")
        head.update(t)

        for c in rows:
            table.add_row(
                _proto_text(c),
                _state_text(c),
                Text(str(c.pid or "-"), style="#7a8a99"),
                Text(c.pname[:22], style="#e6edf3"),
                Text(c.local, style="#9fb0c0"),
                Text(c.remote, style="#c8d3de"),
                Text(self._hostname(c.raddr)[:44], style="#7fb3d5"))

    def on_world_map_point_selected(self, event: WorldMap.PointSelected
                                    ) -> None:
        table = self._find("#geo-table", DataTable)
        if table is None:                       # screen torn down mid-message
            return
        if table.row_count > event.index >= 0:
            self._syncing_geo = True
            try:
                table.move_cursor(row=event.index)
            finally:
                self._syncing_geo = False
        self._render_map_detail()

    # -- bandwidth ---------------------------------------------------------
    def _render_bandwidth(self) -> None:
        snap = self.snapshot
        graph = self._find("#bw-graph", BandwidthGraph)
        table = self._find("#nic-table", DataTable)
        if graph is None or table is None:
            return
        if self.nic_choice == "total" or self.nic_choice not in snap.nics:
            graph.update_series("all interfaces", snap.down_history,
                                snap.up_history)
        else:
            nic = snap.nics[self.nic_choice]
            graph.update_series(nic.name, nic.down_history, nic.up_history)

        cursor = table.cursor_row
        table.clear()
        table.add_row(Text("total", style="bold #e6edf3"),
                      Text(human_rate(snap.total_down), style="#5fd7ff"),
                      Text(human_rate(snap.total_up), style="#ffaf5f"),
                      Text(human_bytes(sum(n.bytes_recv
                                           for n in snap.nics.values())),
                           style="#9fb0c0"),
                      Text(human_bytes(sum(n.bytes_sent
                                           for n in snap.nics.values())),
                           style="#9fb0c0"),
                      Text(sparkline(snap.down_history, 24), style="#5fd7ff"))
        for name in sorted(snap.nics):
            n = snap.nics[name]
            marker = "▸ " if name == self.nic_choice else "  "
            table.add_row(Text(marker + n.name, style="#e6edf3"),
                          Text(human_rate(n.down_rate), style="#5fd7ff"),
                          Text(human_rate(n.up_rate), style="#ffaf5f"),
                          Text(human_bytes(n.bytes_recv), style="#9fb0c0"),
                          Text(human_bytes(n.bytes_sent), style="#9fb0c0"),
                          Text(sparkline(n.down_history, 24), style="#5fd7ff"))
        if cursor:
            table.move_cursor(row=min(cursor, len(snap.nics)))

    # -- processes ---------------------------------------------------------
    def _render_processes(self) -> None:
        snap = self.snapshot
        note = self._find("#proc-note", Static)
        table = self._find("#proc-table", DataTable)
        if note is None or table is None:
            return
        cursor = table.cursor_row
        table.clear()

        if not snap.procs:
            if not self.monitor.procnet.available:
                note.update("nettop not found — throughput columns are empty; "
                            "socket ownership is still shown.")
            elif not self.monitor.procnet.enabled:
                note.update("per-process bandwidth disabled "
                            f"({self.monitor.procnet.error or 'off'})")
            else:
                note.update("waiting for the first nettop sample…")
        else:
            note.update("")

        for r in aggregate(snap.connections, snap.procs)[:250]:
            listening = ",".join(str(p) for p in sorted(r.listen_ports)[:6])
            table.add_row(
                Text(str(r.pid if r.pid is not None else "-"),
                     style="#7a8a99"),
                Text(r.name[:26], style="#e6edf3"),
                Text(f"{human_rate(r.in_rate) if r.in_rate else '-':>10}",
                     style="#5fd7ff"),
                Text(f"{human_rate(r.out_rate) if r.out_rate else '-':>10}",
                     style="#ffaf5f"),
                Text(f"{human_bytes(r.bytes_in) if r.bytes_in else '-':>8}",
                     style="#9fb0c0"),
                Text(f"{human_bytes(r.bytes_out) if r.bytes_out else '-':>8}",
                     style="#9fb0c0"),
                Text(str(r.conns), style="#c8d3de"),
                Text(str(r.established or "-"), style="#5fff87"),
                Text(str(r.remotes or "-"), style="#7fb3d5"),
                Text(listening or "-", style="#c6a15b"))
        if cursor and table.row_count:
            table.move_cursor(row=min(cursor, table.row_count - 1))

    # -- dns ---------------------------------------------------------------
    def _dns_match(self, haystack: str) -> bool:
        return (not self.search_term
                or self.search_term.lower() in haystack.lower())

    def _render_dns(self) -> None:
        status_bar = self._find("#dns-status", Static)
        live = self._find("#dns-live", DataTable)
        cache_table = self._find("#dns-cache", DataTable)
        rate = self._find("#dns-rate", MiniGraph)
        title = self._find("#dns-cache-title", Static)
        if None in (status_bar, live, cache_table, rate, title):
            return
        watcher = self.monitor.dns
        cache = watcher.cache
        stats = cache.stats()
        window_min = cache.window // 60

        status = Text()
        status.append(f" source: {watcher.mode} ",
                      style=f"bold {SOURCE_STYLES.get(watcher.mode, '#c0c0c0')}")
        if watcher.status and watcher.status != watcher.mode:
            status.append(f" {watcher.status}", style="#7a8a99")
        status.append(f"   {stats['records']} answers", style="#c8d3de")
        status.append(f"   {stats['names']} names", style="#c8d3de")
        status.append(f"   {stats['addresses']} addresses", style="#c8d3de")
        status.append(f"   window {window_min} min", style="#4a5a6a")
        if watcher.error:
            status.append(f"   ! {watcher.error[:50]}", style="#ff5f5f")
        status_bar.update(status)

        series = cache.rate_series(60)
        bucket = max(1, cache.window // 60)
        rate.update_series(
            f"resolutions per {bucket}s  (peak {int(max(series or [0]))})",
            series)

        live.clear()
        rows = [r for r in cache.recent(400)
                if self._dns_match(f"{r.name} {r.client} {r.answer_text}")]
        self.dns_rows = rows
        for rec in rows[:250]:
            live.add_row(
                Text(time.strftime("%H:%M:%S", time.localtime(rec.ts)),
                     style="#7a8a99"),
                Text(rec.source[:4],
                     style=SOURCE_STYLES.get(rec.source, "#c0c0c0")),
                Text((rec.client or "-")[:18], style="#e6edf3"),
                Text(rec.rtype, style="#d7afff"),
                Text(rec.name[:46], style="#7fb3d5"),
                Text(rec.answer_text[:40], style="#c6a15b"))

        cursor = cache_table.cursor_row
        cache_table.clear()
        entries = [e for e in cache.entries()
                   if self._dns_match(f"{e.name} {e.address_text}")]
        self.dns_cache_rows = entries
        title.update(f" CACHE — last {window_min} min "
                     f"({len(entries)} names)")
        for e in entries[:400]:
            cache_table.add_row(
                Text(e.name[:34], style="#e6edf3"),
                Text(e.address_text[:30], style="#c6a15b"),
                Text(str(e.hits), style="#5fff87"),
                Text(_ago(e.last_seen), style="#7a8a99"),
                Text(str(e.ttl) if e.ttl else "-", style="#4a5a6a"))
        if cursor and cache_table.row_count:
            cache_table.move_cursor(row=min(cursor, cache_table.row_count - 1))

    # -- summary -----------------------------------------------------------
    def _render_summary(self) -> None:
        bar = self._find("#summary", SummaryBar)
        if bar is None:
            return
        snap = self.snapshot
        tcp, udp, est, lis = snap.counts()
        t = Text()
        t.append(" NetMonGuru ", style="bold #06090c on #5fd7ff")
        t.append(f"  {len(snap.connections)} sockets", style="#e6edf3")
        t.append(f"  TCP {tcp}", style="#87d7ff")
        t.append(f"  UDP {udp}", style="#d7afff")
        t.append(f"  estab {est}", style="#5fff87")
        t.append(f"  listen {lis}", style="#5fd7ff")
        t.append(f"   ▼ {human_rate(snap.total_down)}", style="#5fd7ff")
        t.append(f"  ▲ {human_rate(snap.total_up)}", style="#ffaf5f")
        t.append(f"   dns {self.monitor.dns.cache.stats()['names']}",
                 style="#af87ff")
        pend = self.monitor.enricher.pending
        if pend:
            t.append(f"   geo:{pend}↻", style="#c6a15b")
        status = self.monitor.enricher.status
        if status and status not in ("ok", "idle") \
                and not status.startswith("resolving"):
            t.append(f"   geo: {status[:30]}", style="#ff875f")
        if snap.backend:
            t.append(f"   [{snap.backend}]", style="#4a5a6a")
        if not snap.elevated and snap.backend != "demo":
            t.append("  unprivileged", style="#ffaf5f")
        if self.monitor.paused:
            t.append("  PAUSED", style="bold #ff5f5f")
        if snap.errors:
            t.append(f"  ! {snap.errors[0][:36]}", style="#ff5f5f")
        bar.update(t)

    # -- events ------------------------------------------------------------
    def on_data_table_row_highlighted(self, event) -> None:
        table_id = event.data_table.id
        if table_id == "conn-table":
            if self._find("#detail", DetailBar) is not None:
                self._render_detail()
        elif table_id == "geo-table":
            # Only react to cursor moves the user made: programmatic moves
            # (map click, keyboard cycling) can deliver a stale row later and
            # would otherwise fight the map selection.
            if self._syncing_geo or not event.data_table.has_focus:
                return
            row = event.cursor_row
            world = self._find("#worldmap", WorldMap)
            if world is not None and row is not None \
                    and 0 <= row < len(self.map_points) \
                    and row != world.selected:
                world.select(row)
                self._render_map_detail()
        elif table_id == "nic-table":
            row = event.cursor_row
            names = ["total"] + sorted(self.snapshot.nics)
            if row is not None and 0 <= row < len(names):
                self.nic_choice = names[row]

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "search":
            return
        self.search_term = event.value.strip()
        if self._find("#conn-table", DataTable) is None:
            return
        self._render_connections()
        self._render_dns()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search":
            self.query_one("#conn-table", DataTable).focus()

    def on_unmount(self) -> None:
        self.monitor.stop()

    # -- actions -----------------------------------------------------------
    def action_show_tab(self, tab: str) -> None:
        tabs = self._find("#tabs", TabbedContent)
        if tabs is None:
            return
        tabs.active = tab
        try:
            self.query(TAB_FOCUS[tab]).first().focus()
        except Exception:                              # noqa: BLE001
            pass

    def action_toggle_tcp(self) -> None:
        self.show_tcp = not self.show_tcp
        self._render_connections()

    def action_toggle_udp(self) -> None:
        self.show_udp = not self.show_udp
        self._render_connections()

    def action_toggle_established(self) -> None:
        self.only_established = not self.only_established
        self._render_connections()

    def action_toggle_listening(self) -> None:
        self.show_listening = not self.show_listening
        self._render_connections()

    def action_toggle_private(self) -> None:
        self.show_private = not self.show_private
        self._render_connections()

    def action_cycle_sort(self) -> None:
        self.sort_idx = (self.sort_idx + 1) % len(SORTS)
        self._render_connections()

    def action_reverse_sort(self) -> None:
        self.sort_reverse = not self.sort_reverse
        self._render_connections()

    def action_toggle_pause(self) -> None:
        self.monitor.paused = not self.monitor.paused
        self._render_summary()

    def action_toggle_arcs(self) -> None:
        self.query_one("#worldmap", WorldMap).toggle_arcs()

    def action_map_next(self) -> None:
        self.query_one("#worldmap", WorldMap).select_next(1)

    def action_map_prev(self) -> None:
        self.query_one("#worldmap", WorldMap).select_next(-1)

    def action_cycle_nic(self) -> None:
        names = ["total"] + sorted(self.snapshot.nics)
        try:
            i = names.index(self.nic_choice)
        except ValueError:
            i = 0
        self.nic_choice = names[(i + 1) % len(names)]
        self._render_bandwidth()

    def action_search(self) -> None:
        box = self.query_one("#search", Input)
        box.add_class("visible")
        box.focus()

    def action_clear_search(self) -> None:
        box = self.query_one("#search", Input)
        box.value = ""
        box.remove_class("visible")
        self.search_term = ""
        active = self.query_one("#tabs", TabbedContent).active
        focus_id = "#dns-live" if active == "tab-dns" else "#conn-table"
        self.query_one(focus_id, DataTable).focus()
        self._render_connections()
        self._render_dns()
