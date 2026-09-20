"""NetMonGuru - btop-style network monitor for macOS (Textual TUI)."""

from __future__ import annotations

import socket
import time
from typing import Dict, List, Optional, Tuple

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (DataTable, Footer, Input, Static, TabbedContent,
                             TabPane)

from ..core.bandwidth import human_bytes, human_rate
from ..core.killer import PfCutter, terminate_process
from ..core.models import Connection, GeoInfo, Snapshot, classify_address
from ..core.monitor import Monitor
from ..core.procs import ProcRow, aggregate, process_info, related_processes
from ..core.watch import (DEFAULT_RULES_PATH, SeenIndex, WatchList, WatchRule,
                          WatchTracker, unique_keys)
from .help import HELP, GLOBAL_HELP
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

SORTS = [("newest", "Newest"), ("process", "Process"), ("proto", "Proto"), ("state", "State"),
         ("remote", "Remote"), ("country", "Country"), ("pid", "PID")]

#: which widget takes focus when a pane is opened - a focused widget left
#: behind in a hidden pane makes TabbedContent snap back to it.
TAB_FOCUS = {
    "tab-conn": "#conn-table",
    "tab-map": "#worldmap",
    "tab-bw": "#bw-table",
    "tab-proc": "#proc-table",
    "tab-dns": "#dns-live",
    "tab-mon": "#mon-table",
    "tab-intel": "#intel-list",
    "tab-alerts": "#alert-table",
    "tab-hist": "#hist-table",
}

LEVEL_STYLES = {"malicious": "bold #ffffff on #d70000",
                "suspicious": "bold #06090c on #ffaf5f",
                "info": "#d7afff", "clean": "#5f875f", "unknown": "#7a8a99",
                "": "#4a5a6a"}
LEVEL_TEXT = {"malicious": "bold #ff5f5f", "suspicious": "bold #ffaf5f",
              "info": "#d7afff", "clean": "#5fff87", "unknown": "#9fb0c0",
              "": "#7a8a99"}
SIG_STYLES = {"apple": "#5f875f", "appstore": "#5f875f", "devid": "#5f875f",
              "adhoc": "#c6a15b", "unsigned": "bold #ffaf5f",
              "invalid": "bold #ff5f5f", "unknown": "#4a5a6a"}
STATUS_STYLES = {"ok": "#5fff87", "pending": "#ffd75f", "skipped": "#4a5a6a",
                 "error": "#ff5f5f", "limited": "#ffaf5f", "none": "#7a8a99"}

BW_VIEWS = ("processes", "connections", "interfaces")
BW_COLUMNS = {
    "processes": ("PID", "PROCESS", "DOWN", "UP", "SHARE", "RECV", "SENT",
                  "CONNS", "HISTORY"),
    "connections": ("PROCESS", "PID", "PROTO", "LOCAL", "REMOTE", "HOST",
                    "DOWN", "UP", "RECV", "SENT", "HISTORY"),
    "interfaces": ("IFACE", "DOWN", "UP", "RECV", "SENT", "HISTORY"),
}
ALL_KEY = "__all__"

SCOPE_STYLES = {"endpoint": "#5fd7ff", "host": "#ffd75f",
                "process": "#af87ff", "listen": "#5fff87"}


class Cell(Text):
    """A ``Text`` that can carry a sort index.

    ``rich.text.Text`` uses ``__slots__``; this subclass gets a ``__dict__``
    so the first cell of every row can hold the row's target position, which
    lets ``DataTable.sort`` reorder rows in place instead of us clearing and
    refilling the table (the cause of the jumpy scrolling in 1.1).
    """

    order = 0


class ClickTable(DataTable):
    """DataTable that reports a selection on the *first* click of a row.

    Stock behaviour is "first click moves the cursor, second click selects",
    which makes click-to-expand feel broken.
    """

    async def _on_click(self, event) -> None:
        before = self.cursor_coordinate
        meta = event.style.meta
        await super()._on_click(event)
        row = meta.get("row", -1) if meta else -1
        if row is not None and row >= 0 and self.cursor_type == "row" \
                and (before.row, before.column) != (row, meta.get("column")):
            self._post_selected_message()


def _service(port: int, proto: str) -> str:
    if not port:
        return ""
    try:
        return socket.getservbyport(port, proto.lower())
    except Exception:                                  # noqa: BLE001
        return ""


def _span(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m"


def _coarse_age(ts: float, now: float) -> str:
    """Minute granularity on purpose: a column that changes every second in
    every row would force a repaint of the whole table on each sample."""
    if not ts:
        return "·"
    delta = max(0, int(now - ts))
    if delta < 60:
        return "<1m"
    if delta < 3600:
        return f"{delta // 60}m"
    return f"{delta // 3600}h{delta % 3600 // 60:02d}"


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


class KillScreen(ModalScreen):
    """Confirmation dialog for ending a connection.  Dismisses with
    ``"cut"``, ``"term"``, ``"kill"`` or ``None``."""

    DEFAULT_CSS = """
    KillScreen { align: center middle; background: #000000 60%; }
    #kill-box {
        width: 92; height: auto; padding: 1 2; background: #0c1116;
        border: heavy #ff5f5f;
    }
    """

    BINDINGS = [
        Binding("c", "pick('cut')", "Cut connection"),
        Binding("t", "pick('term')", "Terminate process"),
        Binding("K", "pick('kill')", "Force kill"),
        Binding("b", "pick('block')", "Block host"),
        Binding("escape", "pick('')", "Cancel"),
        Binding("n", "pick('')", "Cancel", show=False),
        Binding("q", "pick('')", "Cancel", show=False),
    ]

    def __init__(self, conn: Connection, host: str, sockets: int,
                 cut_error: str, block_error: str = "",
                 blocked: bool = False) -> None:
        super().__init__()
        self.conn = conn
        self.host = host
        self.sockets = sockets
        self.cut_error = cut_error
        self.block_error = block_error
        self.blocked = blocked

    def compose(self) -> ComposeResult:
        c = self.conn
        t = Text()
        t.append(" END CONNECTION \n\n", style="bold #06090c on #ff5f5f")
        t.append(f" {c.pname or '?'} ", style="bold #e6edf3")
        t.append(f"(pid {c.pid or '?'})   ", style="#7a8a99")
        t.append(f"{c.local} → {c.remote}" if c.proto else "whole process",
                 style="#c8d3de")
        if self.host:
            t.append(f"   {self.host}", style="#7fb3d5")
        t.append(f"   {c.proto} {c.state}\n\n", style="#9fb0c0")

        can_cut = not self.cut_error
        t.append("  c  ", style="bold #ffd75f" if can_cut else "#4a5a6a")
        t.append("cut this connection only", style="bold #e6edf3" if can_cut
                 else "#4a5a6a")
        t.append("  — pf block + reset for this exact socket pair;\n"
                 "     the process keeps running and may reconnect\n",
                 style="#7a8a99")
        if self.cut_error:
            t.append(f"     unavailable: {self.cut_error}\n", style="#ffaf5f")

        can_sig = bool(c.pid)
        style = "bold #e6edf3" if can_sig else "#4a5a6a"
        t.append("\n  t  ", style="bold #ffd75f" if can_sig else "#4a5a6a")
        t.append(f"terminate {c.pname or 'the process'}", style=style)
        t.append(f"  — SIGTERM; closes all {self.sockets} of its socket(s) "
                 "at once\n", style="#7a8a99")
        t.append("  K  ", style="bold #ff5f5f" if can_sig else "#4a5a6a")
        t.append("force kill", style=style)
        t.append("  — SIGKILL, no chance to clean up (shift+k)\n",
                 style="#7a8a99")
        if not can_sig:
            t.append("     unavailable: owning process unknown - run with "
                     "sudo\n", style="#ffaf5f")
        can_block = bool(c.raddr) and not self.blocked
        t.append("\n  b  ", style="bold #ffd75f" if can_block else "#4a5a6a")
        t.append(f"block {c.raddr or 'host'} permanently",
                 style="bold #e6edf3" if can_block else "#4a5a6a")
        t.append("  — every process, every port; kept on the\n     "
                 "blocklist across restarts (Alerts pane → d to unblock)\n",
                 style="#7a8a99")
        if self.blocked:
            t.append("     already on the blocklist\n", style="#ffaf5f")
        elif self.block_error and c.raddr:
            t.append(f"     saved but not enforced now: {self.block_error}\n",
                     style="#ffaf5f")
        t.append("\n  esc  cancel", style="#7a8a99")
        yield Static(t, id="kill-box")

    def action_pick(self, choice: str) -> None:
        if choice == "cut" and self.cut_error:
            return
        if choice in ("term", "kill") and not self.conn.pid:
            return
        if choice == "block" and (not self.conn.raddr or self.blocked):
            return
        self.dismiss(choice or None)


class HelpScreen(ModalScreen):
    DEFAULT_CSS = """
    HelpScreen { align: center middle; background: #000000 60%; }
    #help-box {
        width: 100; height: auto; max-height: 90%; padding: 1 2;
        background: #0c1116; border: heavy #2b6a94;
    }
    """
    BINDINGS = [Binding("escape", "close", "Close"),
                Binding("question_mark", "close", "Close"),
                Binding("q", "close", "Close", show=False)]

    def __init__(self, tab: str) -> None:
        super().__init__()
        self.tab = tab

    def compose(self) -> ComposeResult:
        title, rows = HELP.get(self.tab, ("", []))
        t = Text()
        t.append(f" {title.upper()} ", style="bold #06090c on #5fd7ff")
        t.append("  keys for this pane\n\n", style="#7a8a99")
        for key, text in rows:
            t.append(f"  {key:<15}", style="bold #ffd75f")
            t.append(f"{text}\n", style="#c8d3de")
        t.append("\n EVERYWHERE \n\n", style="bold #06090c on #7fb3d5")
        for key, text in GLOBAL_HELP:
            t.append(f"  {key:<15}", style="bold #ffd75f")
            t.append(f"{text}\n", style="#c8d3de")
        t.append("\n  esc / ? to close", style="#4a5a6a")
        yield Static(t, id="help-box")

    def action_close(self) -> None:
        self.dismiss(None)


SEVERITY_RANK_UI = {"low": 1, "medium": 2, "high": 3}
SEVERITY_STYLES = {"high": "bold #ffffff on #d70000",
                   "medium": "bold #06090c on #ffaf5f",
                   "low": "#d7afff"}
HISTORY_WINDOWS = [("1 h", "1h"), ("24 h", "24h"), ("7 d", "7d"),
                   ("all", "all")]


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
    DetailBar.hidden { display: none; }
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
    #conn-detail {
        display: none; height: 16; background: #0a0f14;
        border-top: heavy #2b6a94;
    }
    #conn-detail.open { display: block; }
    #cd-info { width: 3fr; height: 1fr; padding: 0 1; overflow-y: auto; }
    #cd-side { width: 2fr; height: 1fr; border-left: solid #1f2b36; }
    #cd-procs { height: 1fr; }
    #cd-socks { height: 1fr; }
    #intel-status { height: 1; background: #0c1116; padding: 0 1; }
    #intel-input { height: 3; border: tall #2b4a63; }
    #intel-side { width: 58; height: 1fr; border-right: solid #1f2b36; }
    #intel-list { height: 1fr; }
    #intel-feeds { height: 11; }
    #intel-scroll { width: 1fr; height: 1fr; padding: 0 1; }
    #intel-report { height: auto; }
    #proc-bar { height: 1; background: #0c1116; color: #7a8a99; padding: 0 1; }
    #proc-detail {
        display: none; height: 18; background: #0a0f14;
        border-top: heavy #2b6a94;
    }
    #proc-detail.open { display: block; }
    #pd-info { width: 1fr; height: 1fr; padding: 0 1; overflow-y: auto; }
    #pd-side { width: 1fr; height: 1fr; border-left: solid #1f2b36; }
    #pd-conns { height: 1fr; }
    #alert-status { height: 1; background: #0c1116; padding: 0 1; }
    #alert-table { height: 2fr; }
    #block-table { height: 1fr; }
    #hist-status { height: 1; background: #0c1116; padding: 0 1; }
    #hist-table { height: 1fr; }
    #mon-status { height: 1; background: #0c1116; padding: 0 1; }
    #mon-rules { height: 9; }
    #mon-empty { height: auto; padding: 1 2; color: #7a8a99; }
    #mon-empty.hidden { display: none; }
    #bw-table { height: 1fr; }
    #bw-graph { height: 14; }
    #bw-bar { height: 1; background: #0c1116; padding: 0 1; }
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
        Binding("1", "show_tab('tab-conn')", "Conns", show=False),
        Binding("2", "show_tab('tab-map')", "Map", show=False),
        Binding("3", "show_tab('tab-bw')", "Bw", show=False),
        Binding("4", "show_tab('tab-proc')", "Procs", show=False),
        Binding("5", "show_tab('tab-dns')", "DNS", show=False),
        Binding("6", "show_tab('tab-mon')", "Mon", show=False),
        Binding("m", "mark", "Mark"),
        Binding("f", "monitor_marked('endpoint')", "Monitor"),
        Binding("F", "monitor_marked('host')", "Monitor host", show=False),
        Binding("P", "monitor_marked('process')", "Monitor process",
                show=False),
        Binding("x", "clear_marks", "Unmark all", show=False),
        Binding("g", "goto_process", "Go to process", show=False),
        Binding("d", "delete_rule", "Delete rule", show=False),
        Binding("delete", "delete_rule", "Delete rule", show=False),
        Binding("c", "clear_history", "Clear closed", show=False),
        Binding("k", "kill_connection", "Kill"),
        Binding("7", "show_tab('tab-intel')", "Intel", show=False),
        Binding("8", "show_tab('tab-alerts')", "Alerts", show=False),
        Binding("9", "show_tab('tab-hist')", "History", show=False),
        Binding("question_mark", "help", "Help"),
        Binding("A", "ack_alerts", "Acknowledge", show=False),
        Binding("left_square_bracket", "hist_window(-1)", "Shorter",
                show=False),
        Binding("right_square_bracket", "hist_window(1)", "Longer",
                show=False),
        Binding("exclamation_mark", "hist_flagged", "Flagged only",
                show=False),
        Binding("i", "investigate", "Check TI"),
        Binding("w", "export_report", "Write report", show=False),
        Binding("R", "refresh_feeds", "Refresh feeds", show=False),
        Binding("t", "toggle_tcp", "TCP", show=False),
        Binding("u", "toggle_udp", "UDP", show=False),
        Binding("e", "toggle_established", "Estab", show=False),
        Binding("l", "toggle_listening", "Listen", show=False),
        Binding("p", "toggle_private", "Public", show=False),
        Binding("slash", "search", "Search"),
        Binding("s", "cycle_sort", "Sort", show=False),
        Binding("space", "toggle_pause", "Pause", show=False),
        Binding("r", "reverse_sort", "Reverse", show=False),
        Binding("a", "toggle_arcs", "Arcs", show=False),
        Binding("n", "cycle_nic", "Next row", show=False),
        Binding("b", "bw_view", "Bw view", show=False),
        Binding("comma", "map_prev", "Prev marker", show=False),
        Binding("full_stop", "map_next", "Next marker", show=False),
        Binding("escape", "clear_search", "Clear", show=False),
    ]

    def __init__(self, monitor: Monitor, rules_path=DEFAULT_RULES_PATH,
                 bw_view: str = "processes") -> None:
        super().__init__()
        self.monitor = monitor
        self.seen = SeenIndex()
        self.watchlist = WatchList(rules_path)
        self.tracker = WatchTracker(self.watchlist)
        self.cutter = monitor.cutter
        self.ti = monitor.ti
        self.intel_rows: List = []
        self.alert_rows: List = []
        self.block_rows: List = []
        self.hist_rows: List = []
        self.hist_window = 1
        self.hist_flagged = False
        self._proc_ctx: Dict[int, tuple] = {}
        self.proc_detail_open = False
        self.proc_detail_row: Optional[ProcRow] = None
        self.proc_detail_conns: List[Tuple[str, Connection]] = []
        self._intel_sig = None
        self.keyed: List[Tuple[str, Connection]] = []
        self.row_keys: List[str] = []
        self.marked: set = set()
        self.detail_open = False
        self.detail_conn: Optional[Connection] = None
        self.detail_related: List[Tuple[str, ProcRow]] = []
        self.proc_rows: List[ProcRow] = []
        self.mon_rows: List = []
        self.flash = ""
        self._flash_until = 0.0
        self._last_snapshot: Optional[Snapshot] = None
        self._tables: Dict[str, dict] = {}
        self._cols: Dict[str, list] = {}
        self.snapshot: Snapshot = monitor.snapshot
        self.show_tcp = True
        self.show_udp = True
        self.only_established = False
        self.show_listening = True
        self.show_private = True
        self.search_term = ""
        self.sort_idx = 0
        self.sort_reverse = False
        general = monitor.config.section("general")
        self.show_listening = bool(general["show_listening"])
        self.show_private = bool(general["show_private"])
        wanted = str(general["sort"]).lower()
        self.sort_idx = next((i for i, (k, _) in enumerate(SORTS)
                              if k == wanted), 0)
        self.bw_view = bw_view if bw_view in BW_VIEWS else "processes"
        self.bw_process: Optional[Tuple[Optional[int], str]] = None  # drill-down
        self.bw_keys: List[str] = []
        self._bw_columns_for = ""
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
                yield ClickTable(id="conn-table", zebra_stripes=True,
                                 cursor_type="row")
                yield DetailBar(id="detail")
                with Horizontal(id="conn-detail"):
                    yield Static("", id="cd-info")
                    with Vertical(id="cd-side"):
                        yield Static(" RELATED PROCESSES", id="cd-procs-title",
                                     classes="pane-title")
                        yield ClickTable(id="cd-procs", zebra_stripes=True,
                                         cursor_type="row")
                        yield Static(" SOCKETS OF THIS PROCESS",
                                     id="cd-socks-title", classes="pane-title")
                        yield DataTable(id="cd-socks", zebra_stripes=True,
                                        cursor_type="row")
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
                yield Static("", id="bw-bar")
                yield BandwidthGraph(id="bw-graph")
                yield ClickTable(id="bw-table", zebra_stripes=True,
                                cursor_type="row")
            with TabPane("Processes", id="tab-proc"):
                yield Static("", id="proc-note", classes="note")
                yield Static("", id="proc-bar")
                yield ClickTable(id="proc-table", zebra_stripes=True,
                                 cursor_type="row")
                with Horizontal(id="proc-detail"):
                    yield Static("", id="pd-info")
                    with Vertical(id="pd-side"):
                        yield Static(" CONNECTIONS OF THIS PROCESS",
                                     id="pd-conns-title", classes="pane-title")
                        yield ClickTable(id="pd-conns", zebra_stripes=True,
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
            with TabPane("Monitor", id="tab-mon"):
                yield Static("", id="mon-status")
                yield Static(" MONITOR RULES", id="mon-rules-title",
                             classes="pane-title")
                yield DataTable(id="mon-rules", zebra_stripes=True,
                                cursor_type="row")
                yield Static(" MONITORED TRAFFIC", id="mon-table-title",
                             classes="pane-title")
                yield Static(
                    "Nothing is monitored yet.\n\n"
                    "On the Connections pane press [b]m[/b] to mark one or "
                    "more connections, then [b]f[/b] to monitor them here "
                    "([b]F[/b] = whole remote host, [b]P[/b] = whole "
                    "process). Come back and repeat to add more.",
                    id="mon-empty")
                yield ClickTable(id="mon-table", zebra_stripes=True,
                                 cursor_type="row")
            with TabPane("Intel", id="tab-intel"):
                yield Static("", id="intel-status")
                with Horizontal():
                    with Vertical(id="intel-side"):
                        yield Input(placeholder="investigate an address: type "
                                                "an IP and press enter",
                                    id="intel-input")
                        yield Static(" INVESTIGATIONS", classes="pane-title")
                        yield DataTable(id="intel-list", zebra_stripes=True,
                                        cursor_type="row")
                        yield Static(" LOCAL FEEDS", id="intel-feeds-title",
                                     classes="pane-title")
                        yield DataTable(id="intel-feeds", zebra_stripes=True,
                                        cursor_type="row")
                    with VerticalScroll(id="intel-scroll"):
                        yield Static("", id="intel-report")
            with TabPane("Alerts", id="tab-alerts"):
                yield Static("", id="alert-status")
                yield Static(" ALERTS", id="alert-title", classes="pane-title")
                yield ClickTable(id="alert-table", zebra_stripes=True,
                                 cursor_type="row")
                yield Static(" BLOCKED HOSTS", id="block-title",
                             classes="pane-title")
                yield DataTable(id="block-table", zebra_stripes=True,
                                cursor_type="row")
            with TabPane("History", id="tab-hist"):
                yield Static("", id="hist-status")
                yield DataTable(id="hist-table", zebra_stripes=True,
                                cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "NetMonGuru"
        self._columns("#conn-table", "  ", "AGE", "TI", "PROTO", "STATE",
                      "PID", "PROCESS", "SIG", "▼ DOWN", "▲ UP", "LOCAL",
                      "REMOTE", "HOST / ORG", "LOCATION")
        self._columns("#alert-table", "TIME", "SEV", "KIND", "SUBJECT",
                      "DETAIL")
        self._columns("#block-table", "ADDRESS", "HOST", "REASON", "BY",
                      "ADDED", "STATE")
        self._columns("#hist-table", "STARTED", "DURATION", " ", "PROTO",
                      "PROCESS", "PID", "REMOTE", "HOST", "ORG", "CC", "TI",
                      "SIG", "RECV", "SENT")
        self._columns("#intel-list", "TIME", "TARGET", "VERDICT", "PROCESS")
        self._columns("#intel-feeds", "FEED", "STATUS", "ENTRIES", "AGE")
        self._columns("#cd-procs", "REL", "PID", "PROCESS", "DOWN", "UP",
                      "SOCK", "ESTAB", "PEERS")
        self._columns("#cd-socks", "PROTO", "STATE", "LOCAL", "REMOTE", "HOST")
        self._columns("#mon-rules", "#", "SCOPE", "PROCESS", "PROTO", "TARGET",
                      "PORT", "LIVE", "TOTAL", "LAST SEEN")
        self._columns("#mon-table", "  ", "STATUS", "PROTO", "PID", "PROCESS",
                      "LOCAL", "REMOTE", "HOST", "LOCATION", "FIRST SEEN",
                      "DURATION")
        gt = self.query_one("#geo-table", DataTable)
        self._cols[gt.id] = [gt.add_column(label, width=w) for label, w in
                             ((" ", 1), ("LOCATION", 22), ("ORG", 14),
                              ("N", 3))]
        self._columns("#map-detail", "PROTO", "STATE", "PID", "PROCESS",
                      "LOCAL", "REMOTE", "HOSTNAME")
        self._columns("#proc-table", "PID", "PROCESS", "TI", "SIG", "DOWN",
                      "UP", "IN", "OUT", "SOCKETS", "ESTAB", "PEERS",
                      "LISTENING")
        self._columns("#pd-conns", "TI", "PROTO", "STATE", "REMOTE", "HOST",
                      "LOCATION", "DOWN", "UP")
        self._columns("#dns-live", "TIME", "SRC", "CLIENT", "TYPE", "TI",
                      "QUERY", "ANSWERS")
        self._columns("#dns-cache", "NAME", "TI", "ADDRESSES", "HITS", "AGE",
                      "TTL")

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

    # -- incremental tables ------------------------------------------------
    def _columns(self, selector: str, *labels: str) -> None:
        table = self.query_one(selector, DataTable)
        self._cols[table.id] = list(table.add_columns(*labels))

    def _sync_table(self, table: DataTable,
                    items: List[Tuple[str, List[Text]]]) -> None:
        """Bring ``table`` to ``items`` (ordered ``(row key, cells)``) without
        clearing it.

        Rows that disappeared are removed, new ones appended, only cells whose
        text or style changed are rewritten, and if the resulting order is not
        the wanted one the rows are re-sorted in place.  The cursor follows
        its row (not its index) and the viewport is shifted by the same amount
        so whatever the user is looking at stays put - unless they are at the
        top of the list, where new rows are supposed to scroll into view.
        """
        state = self._tables.setdefault(
            table.id, {"order": [], "sig": {}, "first": {}})
        cols = self._cols[table.id]
        old_order: List[str] = state["order"]
        new_order = [k for k, _ in items]
        wanted = set(new_order)

        cursor_idx = table.cursor_row
        cursor_key = old_order[cursor_idx] \
            if 0 <= cursor_idx < len(old_order) else None

        for key in [k for k in old_order if k not in wanted]:
            table.remove_row(key)
            state["sig"].pop(key, None)
            state["first"].pop(key, None)
        current = [k for k in old_order if k in wanted]

        for key, cells in items:
            sig = [(c.plain, str(c.style)) for c in cells]
            old_sig = state["sig"].get(key)
            if old_sig is None:
                first = Cell(cells[0].plain, style=cells[0].style)
                table.add_row(first, *cells[1:], key=key)
                state["first"][key] = first
                current.append(key)
            elif old_sig != sig:
                for i, (a, b) in enumerate(zip(old_sig, sig)):
                    if a == b:
                        continue
                    value = cells[i]
                    if i == 0:
                        value = Cell(cells[0].plain, style=cells[0].style)
                        state["first"][key] = value
                    table.update_cell(key, cols[i], value, update_width=True)
            state["sig"][key] = sig

        if current != new_order:
            for i, key in enumerate(new_order):
                state["first"][key].order = i
            table.sort(cols[0], key=lambda cell: getattr(cell, "order", 0))
        state["order"] = new_order

        if not new_order:
            return
        if cursor_key in wanted:
            target = new_order.index(cursor_key)
        else:
            target = min(max(cursor_idx, 0), len(new_order) - 1)
        if target != table.cursor_row:
            at_top = table.scroll_y <= 0
            shift = target - cursor_idx
            table.move_cursor(row=target, scroll=False)
            if not at_top and cursor_key in wanted and shift:
                y = table.scroll_y + shift
                table.call_after_refresh(
                    lambda: table.scroll_to(y=y, animate=False, force=True))

    def _table_key(self, table: DataTable) -> Optional[str]:
        order = self._tables.get(table.id, {}).get("order", [])
        idx = table.cursor_row
        return order[idx] if 0 <= idx < len(order) else None

    def _cursor_to_key(self, table: DataTable, key: str) -> bool:
        order = self._tables.get(table.id, {}).get("order", [])
        if key not in order:
            return False
        table.move_cursor(row=order.index(key))
        return True

    # -- refresh -----------------------------------------------------------
    def tick(self) -> None:
        summary = self._find("#summary", SummaryBar)
        if summary is None:            # screen not mounted / shutting down
            return
        snap = self.monitor.snapshot
        fresh = snap is not self._last_snapshot
        self.snapshot = snap
        try:
            if fresh:
                self._last_snapshot = snap
                self._track()
            self._render_summary()
            self._render_active(fresh)
        except Exception as exc:                       # noqa: BLE001
            summary.update(Text(f"render error: {exc}", style="bold red"))

    def _track(self) -> None:
        """Bookkeeping that must see every sample, whichever pane is open."""
        now = time.time()
        self.keyed = unique_keys(self.snapshot.connections)
        self.seen.observe([k for k, _ in self.keyed], now)
        hosts = {c.raddr: self._hostname(c.raddr)
                 for _, c in self.keyed if c.raddr}
        self.tracker.observe(self.keyed, hosts, now, self.seen)
        live = {k for k, _ in self.keyed}
        self.marked &= live

    def _render_active(self, fresh: bool = True) -> None:
        """Only the visible pane is rendered: hidden tables cost CPU on every
        sample and gain nothing.  The socket tables are skipped entirely when
        the sample has not changed, which is what keeps scrolling smooth."""
        tabs = self._find("#tabs", TabbedContent)
        active = tabs.active if tabs is not None else "tab-conn"
        if active == "tab-conn":
            if fresh:
                self._render_connections()
        elif active == "tab-map":
            self._render_map()
        elif active == "tab-bw":
            self._render_bandwidth()
        elif active == "tab-proc":
            if fresh:
                self._render_processes()
        elif active == "tab-dns":
            self._render_dns()
        elif active == "tab-mon":
            self._render_monitor()
        elif active == "tab-intel":
            self._render_intel()
        elif active == "tab-alerts":
            self._render_alerts()
        elif active == "tab-hist":
            if fresh:
                self._render_history()

    def _notify(self, message: str, seconds: float = 4.0) -> None:
        self.flash = message
        self._flash_until = time.time() + seconds
        self._render_summary()

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
                (self.snapshot.ti[c.raddr].label
                 if c.raddr in self.snapshot.ti else ""),
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
        now = time.time()
        if not self.keyed and self.snapshot.connections:
            self._track()
        shown = [(k, c) for k, c in self.keyed if self._matches(c)]

        newest = SORTS[self.sort_idx][0] == "newest"
        threats = [kc for kc in shown
                   if self._ti_level(kc[1].raddr) == "malicious"]
        if threats:
            bad = {k for k, _ in threats}
            shown = [kc for kc in shown if kc[0] not in bad]
        if newest:
            shown.sort(key=lambda kc: -self.seen.seq(kc[0]),
                       reverse=self.sort_reverse)
        else:
            # whatever the sort, sockets that just appeared are pinned on top
            fresh = [kc for kc in shown if self.seen.is_new(kc[0], now)]
            rest = [kc for kc in shown if not self.seen.is_new(kc[0], now)]
            fresh.sort(key=lambda kc: -self.seen.seq(kc[0]))
            rest.sort(key=lambda kc: self._sort_key(kc[1]),
                      reverse=self.sort_reverse)
            shown = fresh + rest

        shown = threats + shown          # confirmed-malicious peers lead
        self.rows = [c for _, c in shown]
        self.row_keys = [k for k, _ in shown]

        flows = {(f.proto, f.lport, f.raddr, f.rport): f
                 for f in self.snapshot.flows.values()}
        items = []
        for key, c in shown:
            flow = flows.get((c.proto, c.lport, c.raddr, c.rport))
            is_new = self.seen.is_new(key, now)
            monitored = bool(len(self.watchlist)) and bool(
                self.watchlist.match(c, self._hostname(c.raddr)))
            flag = Text()
            flag.append("●" if key in self.marked else " ", style="bold #ffd75f")
            flag.append("◉" if monitored else " ", style="#ff87d7")
            age = Text("NEW", style="bold #06090c on #5fff87") if is_new else \
                Text(_coarse_age(self.seen.first_seen(key), now),
                     style="#4a5a6a")
            v = self.snapshot.ti.get(c.raddr) if c.raddr else None
            ti_cell = Text(f" {v.label[:26]} ", style=LEVEL_STYLES.get(
                v.level, "#4a5a6a")) if v is not None and v.label else Text("")
            sig = self.snapshot.procsig.get(c.pid) if c.pid else None
            sig_cell = Text(sig.short + ("!" if sig.path_flags else ""),
                            style="bold #ff5f5f" if sig.verdict == "suspicious"
                            else SIG_STYLES.get(sig.signing, "#4a5a6a")) \
                if sig is not None else Text("")
            items.append((key, [
                flag,
                age,
                ti_cell,
                _proto_text(c),
                _state_text(c),
                Text(str(c.pid or "-"), style="#7a8a99"),
                Text(c.pname[:22],
                     style="bold #5fff87" if is_new else "#e6edf3"),
                sig_cell,
                Text(f"{human_rate(flow.in_rate):>9}" if flow and flow.in_rate
                     else "", style="#5fd7ff"),
                Text(f"{human_rate(flow.out_rate):>9}"
                     if flow and flow.out_rate else "", style="#ffaf5f"),
                Text(c.local, style="#9fb0c0"),
                Text(c.remote, style="#c8d3de" if c.raddr else "#4a5a6a"),
                Text(self._hostname(c.raddr)[:36], style="#7fb3d5"),
                Text(_short_location(self._geo(c.raddr))[:24],
                     style="#c6a15b"),
            ]))
        self._sync_table(table, items)

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
        if self.marked:
            t.append(f"   ● {len(self.marked)} marked — f: monitor  x: unmark",
                     style="bold #ffd75f")
        else:
            t.append("   enter/click: details  m: mark  f: monitor  "
                     "i: investigate  k: kill",
                     style="#4a5a6a")
        return t

    def _ti_level(self, ip: str) -> str:
        v = self.snapshot.ti.get(ip) if ip else None
        return v.level if v is not None else ""

    def _current(self) -> Tuple[Optional[str], Optional[Connection]]:
        table = self._find("#conn-table", DataTable)
        if table is None:
            return None, None
        idx = table.cursor_row
        if not self.rows or idx is None or not 0 <= idx < len(self.rows):
            return None, None
        return self.row_keys[idx], self.rows[idx]

    def _render_detail(self) -> None:
        bar = self._find("#detail", DetailBar)
        if bar is None:
            return
        if self.detail_open:
            self._render_detail_panel()
            return
        _, c = self._current()
        if c is None:
            bar.update(Text("—", style="#4a5a6a"))
            return
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

    # -- expanded connection detail ----------------------------------------
    def _set_detail(self, is_open: bool) -> None:
        self.detail_open = is_open
        panel = self._find("#conn-detail", Horizontal)
        bar = self._find("#detail", DetailBar)
        if panel is None or bar is None:
            return
        panel.set_class(is_open, "open")
        bar.set_class(is_open, "hidden")
        self._render_detail()
        if is_open:
            table = self._find("#conn-table", DataTable)
            if table is not None:          # the list just got shorter
                table.call_after_refresh(table._scroll_cursor_into_view)

    def _render_detail_panel(self) -> None:
        info = self._find("#cd-info", Static)
        procs = self._find("#cd-procs", DataTable)
        socks = self._find("#cd-socks", DataTable)
        if info is None or procs is None or socks is None:
            return
        key, c = self._current()
        self.detail_conn = c
        if c is None or key is None:
            info.update(Text("no connection selected", style="#4a5a6a"))
            self.detail_related = []
            self._sync_table(procs, [])
            self._sync_table(socks, [])
            return

        now = time.time()
        g = self._geo(c.raddr)
        host = self._hostname(c.raddr)
        label = "#7a8a99"

        def line(t: Text, name: str, value: str, style: str = "#e6edf3",
                 extra: str = "", extra_style: str = "#7a8a99") -> None:
            t.append(f" {name:<9}", style=label)
            t.append(value or "-", style=style if value else "#4a5a6a")
            if extra:
                t.append(f"   {extra}", style=extra_style)
            t.append("\n")

        t = Text()
        t.append(f" {c.pname or '?'} ", style="bold #06090c on #5fd7ff")
        t.append(f"  pid {c.pid or '?'}  ", style="#c8d3de")
        t.append(f" {c.state or c.proto} ",
                 style=f"bold {STATE_STYLES.get(c.state, '#c0c0c0')}")
        t.append(f"  {c.proto}/{c.family}", style="#9fb0c0")
        if self.seen.is_new(key, now):
            t.append("   ")
            t.append(" NEW ", style="bold #06090c on #5fff87")
        if key in self.marked:
            t.append("   ● marked", style="bold #ffd75f")
        hits = self.watchlist.match(c, host)
        if hits:
            t.append("   ◉ monitored (rule "
                     + ", ".join(f"#{i + 1}" for i in hits) + ")",
                     style="#ff87d7")
        t.append("\n")

        line(t, "local", c.local, "#9fb0c0",
             classify_address(c.laddr) if c.laddr else "")
        svc = _service(c.rport or c.lport, c.proto)
        line(t, "remote", c.remote if c.raddr else "", "bold #e6edf3",
             " · ".join(b for b in (svc, classify_address(c.raddr)
                                    if c.raddr else "") if b))
        if c.raddr:
            ptr = g.hostname if g and g.hostname and g.hostname != host else ""
            line(t, "host", host, "#7fb3d5", f"ptr {ptr}" if ptr else "")
            if g:
                line(t, "owner", g.org, "#c6a15b", g.asn, "#c6a15b")
                where = g.label
                if g.located:
                    where += f"  ({g.lat:.2f}, {g.lon:.2f})"
                line(t, "location", where, "#c6a15b",
                     f"via {g.source}" if g.source else "")
            elif classify_address(c.raddr) == "public":
                line(t, "owner", "resolving…", "#4a5a6a")
        elif svc:
            line(t, "service", svc, "#7fb3d5", "listening"
                 if c.is_listening else "")
        v = self.snapshot.ti.get(c.raddr) if c.raddr else None
        if v is not None:
            t.append(f" {'intel':<9}", style=label)
            if v.label:
                t.append(f" {v.label} ", style=LEVEL_STYLES.get(v.level, ""))
            else:
                t.append("no local feed hit", style="#5f875f")
            for h in v.hits[:2]:
                t.append(f"  {h.detail[:60]}", style="#9fb0c0")
            if v.abuse_score is not None:
                t.append(f"   AbuseIPDB {v.abuse_score}% "
                         f"({v.abuse_reports} reports)", style="#9fb0c0")
            t.append("   i: full investigation\n", style="#4a5a6a")
        first = self.seen.first_seen(key)
        line(t, "seen", time.strftime("%H:%M:%S", time.localtime(first))
             if first else "open before NetMonGuru started", "#c8d3de",
             f"{_span(now - first)} ago" if first else "")

        p = process_info(c.pid)
        if p:
            who = " · ".join(str(b) for b in (
                p.get("user"),
                f"parent {p.get('parent', '?')} ({p['ppid']})"
                if p.get("ppid") else "",
                f"up {_span(now - float(p['started']))}"
                if p.get("started") else "",
                f"rss {human_bytes(int(p['rss']))}" if p.get("rss") else "",
                f"{p['threads']} thr" if p.get("threads") else "") if b)
            line(t, "process", str(p.get("exe") or p.get("name") or c.pname),
                 "#e6edf3")
            if who:
                line(t, "", who, "#9fb0c0")
            sig = self.snapshot.procsig.get(c.pid)
            if sig is not None and (sig.signing != "unknown" or sig.path_flags):
                line(t, "signed", sig.signing + (f" — {sig.signer}"
                                                 if sig.signer else ""),
                     LEVEL_TEXT.get(sig.verdict, "#9fb0c0"),
                     ", ".join(sig.path_flags), "bold #ffaf5f")
            cmd = str(p.get("cmdline") or "")
            if cmd and cmd != p.get("exe"):
                line(t, "cmdline", cmd[:160], "#7a8a99")
        elif c.pid:
            line(t, "process", "", extra="details need sudo or the process "
                                         "has exited")
        else:
            line(t, "process", "", extra="owner unknown — run with sudo to "
                                         "attribute sockets")
        t.append(" m mark · f monitor · F monitor host · P monitor process · "
                 "g process · i investigate · k end connection · esc close", style="#4a5a6a")
        info.update(t)

        # related processes -------------------------------------------------
        conns = self.snapshot.connections
        rows = aggregate(conns, self.snapshot.procs)
        related = related_processes(c, conns, rows)
        self.detail_related = related
        rel_style = {"owner": "bold #5fd7ff", "same peer": "#ffd75f",
                     "same app": "#af87ff"}
        items = []
        for relation, r in related:
            rk = f"{r.pid if r.pid is not None else 'name:' + r.name}"
            items.append((rk, [
                Text(relation, style=rel_style.get(relation, "#c0c0c0")),
                Text(str(r.pid if r.pid is not None else "-"),
                     style="#7a8a99"),
                Text(r.name[:20], style="#e6edf3"),
                Text(human_rate(r.in_rate) if r.in_rate else "-",
                     style="#5fd7ff"),
                Text(human_rate(r.out_rate) if r.out_rate else "-",
                     style="#ffaf5f"),
                Text(str(r.conns), style="#c8d3de"),
                Text(str(r.established or "-"), style="#5fff87"),
                Text(str(r.remotes or "-"), style="#7fb3d5"),
            ]))
        self._sync_table(procs, items)
        title = self._find("#cd-procs-title", Static)
        if title is not None:
            title.update(f" RELATED PROCESSES ({len(related)}) — enter: open "
                         "in Processes")

        # every socket the owning process holds -----------------------------
        items = []
        if c.pid is not None or (c.pname and c.pname != "?"):
            for k2, o in self.keyed:
                same = o.pid == c.pid if c.pid is not None \
                    else o.pname == c.pname
                if not same:
                    continue
                here = k2 == key
                items.append((k2, [
                    _proto_text(o), _state_text(o),
                    Text(o.local, style="#9fb0c0"),
                    Text(o.remote, style="bold #e6edf3" if here
                         else "#c8d3de"),
                    Text(self._hostname(o.raddr)[:30], style="#7fb3d5"),
                ]))
        self._sync_table(socks, items)
        stitle = self._find("#cd-socks-title", Static)
        if stitle is not None:
            stitle.update(f" SOCKETS OF {c.pname or '?'} ({len(items)})")

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

        items = [(f"{p.lat:.1f},{p.lon:.1f}", [
            Text(p.size_marker(), style=p.color),
            Text(p.label[:20], style="#e6edf3"),
            Text((p.detail or "-")[:13], style="#7fb3d5"),
            Text(str(p.count), style="#5fff87")]) for p in points]
        if not items:
            items = [("none", [Text(""), Text("no located peers yet",
                                              style="#4a5a6a"),
                               Text(""), Text("")])]
        self._syncing_geo = True
        try:
            self._sync_table(table, items)
            if points and 0 <= world.selected < len(points) \
                    and world.selected != table.cursor_row:
                table.move_cursor(row=world.selected, scroll=False)
        finally:
            self._syncing_geo = False
        self._render_map_detail()

    def _render_map_detail(self) -> None:
        head = self._find("#map-detail-head", Static)
        table = self._find("#map-detail", DataTable)
        world = self._find("#worldmap", WorldMap)
        if head is None or table is None or world is None:
            return
        idx = world.selected

        if idx < 0 or idx >= len(self.map_points):
            self._sync_table(table, [])
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

        self._sync_table(table, [(key, [
            _proto_text(c),
            _state_text(c),
            Text(str(c.pid or "-"), style="#7a8a99"),
            Text(c.pname[:22], style="#e6edf3"),
            Text(c.local, style="#9fb0c0"),
            Text(c.remote, style="#c8d3de"),
            Text(self._hostname(c.raddr)[:44], style="#7fb3d5")])
            for key, c in unique_keys(rows)])

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
    def _bw_match(self, *fields: str) -> bool:
        return (not self.search_term or
                self.search_term.lower() in " ".join(fields).lower())

    def _render_bandwidth(self) -> None:
        snap = self.snapshot
        graph = self._find("#bw-graph", BandwidthGraph)
        table = self._find("#bw-table", DataTable)
        bar = self._find("#bw-bar", Static)
        if graph is None or table is None or bar is None:
            return
        view = self.bw_view
        if self._bw_columns_for != view:        # different columns per view
            table.clear(columns=True)
            self._tables.pop(table.id, None)
            self._columns("#bw-table", *BW_COLUMNS[view])
            self._bw_columns_for = view

        net = self.monitor.procnet
        total_rate = max(1.0, snap.total_down + snap.total_up)
        items: List[Tuple[str, List[Text]]] = []
        series: Dict[str, Tuple[str, List[float], List[float]]] = {
            ALL_KEY: ("all traffic", snap.down_history, snap.up_history)}

        def rate(v: float, style: str) -> Text:
            return Text(f"{human_rate(v) if v else '-':>10}", style=style)

        if view == "processes":
            rows = [(k, p) for k, p in snap.procs.items()
                    if self._bw_match(p.name, str(p.pid or ""))]
            rows.sort(key=lambda kp: (-(kp[1].in_rate + kp[1].out_rate),
                                      -(kp[1].bytes_in + kp[1].bytes_out),
                                      kp[1].name.lower()))
            items.append((ALL_KEY, [
                Text("", style="#7a8a99"),
                Text("all processes", style="bold #e6edf3"),
                rate(snap.total_down, "#5fd7ff"), rate(snap.total_up, "#ffaf5f"),
                Text("100%", style="#7a8a99"), Text(""), Text(""),
                Text(str(sum(1 for c in snap.connections if c.raddr)),
                     style="#c8d3de"),
                Text(sparkline(snap.down_history, 24), style="#5fd7ff")]))
            for key, p in rows[:300]:
                down, up = net.proc_history(key)
                series[key] = (f"{p.name} (pid {p.pid or '?'})", down, up)
                share = (p.in_rate + p.out_rate) / total_rate
                items.append((key, [
                    Text(str(p.pid if p.pid is not None else "-"),
                         style="#7a8a99"),
                    Text(p.name[:28], style="#e6edf3"),
                    rate(p.in_rate, "#5fd7ff"), rate(p.out_rate, "#ffaf5f"),
                    Text(f"{min(share, 9.99):>4.0%}" if share >= 0.005 else "",
                         style="#c6a15b"),
                    Text(f"{human_bytes(p.bytes_in):>8}", style="#9fb0c0"),
                    Text(f"{human_bytes(p.bytes_out):>8}", style="#9fb0c0"),
                    Text(str(p.conns or "-"), style="#c8d3de"),
                    Text(sparkline(down, 24), style="#5fd7ff")]))

        elif view == "connections":
            rows = list(snap.flows.values())
            if self.bw_process is not None:
                pid, name = self.bw_process
                rows = [f for f in rows if (f.pid == pid if pid is not None
                                            else f.pname == name)]
            rows = [f for f in rows if self._bw_match(
                f.pname, str(f.pid or ""), f.local, f.remote,
                self._hostname(f.raddr))]
            rows.sort(key=lambda f: (-(f.in_rate + f.out_rate),
                                     -(f.bytes_in + f.bytes_out), f.key))
            label = (f"all connections of {self.bw_process[1]}"
                     if self.bw_process else "all connections")
            if self.bw_process is not None:
                # the drill-down total is the sum of that process' flows
                pk = next((k for k, p in snap.procs.items()
                           if (p.pid, p.name) == self.bw_process
                           or (self.bw_process[0] is not None
                               and p.pid == self.bw_process[0])), None)
                if pk is not None:
                    series[ALL_KEY] = (label,) + net.proc_history(pk)
            items.append((ALL_KEY, [
                Text(label[:28], style="bold #e6edf3"), Text(""), Text(""),
                Text(""), Text(""), Text(""),
                rate(sum(f.in_rate for f in rows), "#5fd7ff"),
                rate(sum(f.out_rate for f in rows), "#ffaf5f"),
                Text(""), Text(""), Text("")]))
            for f in rows[:400]:
                down, up = net.flow_history(f.key)
                series[f.key] = (f"{f.pname or '?'}  {f.local} → {f.remote}",
                                 down, up)
                items.append((f.key, [
                    Text((f.pname or "?")[:22], style="#e6edf3"),
                    Text(str(f.pid if f.pid is not None else "-"),
                         style="#7a8a99"),
                    Text(f.proto + ("6" if f.family == "IPv6" else ""),
                         style="#87d7ff" if f.proto == "TCP" else "#d7afff"),
                    Text(f.local, style="#9fb0c0"),
                    Text(f.remote, style="#c8d3de" if f.raddr else "#4a5a6a"),
                    Text(self._hostname(f.raddr)[:30], style="#7fb3d5"),
                    rate(f.in_rate, "#5fd7ff"), rate(f.out_rate, "#ffaf5f"),
                    Text(f"{human_bytes(f.bytes_in):>8}", style="#9fb0c0"),
                    Text(f"{human_bytes(f.bytes_out):>8}", style="#9fb0c0"),
                    Text(sparkline(down, 20), style="#5fd7ff")]))

        else:                                                   # interfaces
            items.append((ALL_KEY, [
                Text("all interfaces", style="bold #e6edf3"),
                rate(snap.total_down, "#5fd7ff"), rate(snap.total_up, "#ffaf5f"),
                Text(human_bytes(sum(n.bytes_recv for n in snap.nics.values())),
                     style="#9fb0c0"),
                Text(human_bytes(sum(n.bytes_sent for n in snap.nics.values())),
                     style="#9fb0c0"),
                Text(sparkline(snap.down_history, 24), style="#5fd7ff")]))
            for name in sorted(snap.nics):
                n = snap.nics[name]
                if not self._bw_match(name):
                    continue
                series[name] = (n.name, n.down_history, n.up_history)
                items.append((name, [
                    Text(n.name, style="#e6edf3"),
                    rate(n.down_rate, "#5fd7ff"), rate(n.up_rate, "#ffaf5f"),
                    Text(human_bytes(n.bytes_recv), style="#9fb0c0"),
                    Text(human_bytes(n.bytes_sent), style="#9fb0c0"),
                    Text(sparkline(n.down_history, 24), style="#5fd7ff")]))

        self.bw_keys = [k for k, _ in items]
        self._sync_table(table, items)

        # the graph shows whatever row the cursor is on
        chosen = self._table_key(table) or ALL_KEY
        title, down, up = series.get(chosen, series[ALL_KEY])
        graph.update_series(title, down, up)

        t = Text()
        for v in BW_VIEWS:
            t.append(f" {v.upper()} ", style="bold #06090c on #5fd7ff"
                     if v == view else "#4a5a6a")
            t.append(" ")
        t.append(" b: switch view ", style="#4a5a6a")
        if self.bw_process is not None and view == "connections":
            t.append(f" process: {self.bw_process[1]} ",
                     style="bold #06090c on #ffd75f")
            t.append(" esc: all processes ", style="#4a5a6a")
        elif view == "processes":
            t.append(" enter: connections of the process ", style="#4a5a6a")
        if self.search_term:
            t.append(f" /{self.search_term} ", style="bold #ffd75f")
        else:
            t.append(" /: filter ", style="#4a5a6a")
        t.append(f"  graph: {title[:60]}", style="#9fb0c0")
        if view != "interfaces" and len(items) <= 1:
            if not net.available:
                note = "nettop not found — per-process data is macOS only"
            elif not net.enabled:
                note = f"per-process bandwidth is off ({net.error or 'disabled'})"
            elif view == "connections" and snap.procs:
                note = ("nettop gave no per-connection rows on this system — "
                        "the per-process view still works")
            else:
                note = "waiting for the first nettop samples…"
            t.append(f"   {note}", style="#ffaf5f")
        bar.update(t)

    # -- processes ---------------------------------------------------------
    def _render_processes(self) -> None:
        snap = self.snapshot
        note = self._find("#proc-note", Static)
        table = self._find("#proc-table", DataTable)
        if note is None or table is None:
            return
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

        rows = aggregate(snap.connections, snap.procs)
        if self.search_term:
            term = self.search_term.lower()
            rows = [r for r in rows
                    if term in f"{r.name} {r.pid or ''}".lower()
                    or term in self._proc_ti(r)[1].lower()]
        # like the connections pane: a process talking to a confirmed
        # malicious peer leads the list whatever its traffic
        rows.sort(key=lambda r: self._proc_ti(r)[0] != "malicious")
        self.proc_rows = rows[:250]
        items = []
        for r in self.proc_rows:
            listening = ",".join(str(p) for p in sorted(r.listen_ports)[:6])
            level, label = self._proc_ti(r)
            sig = snap.procsig.get(r.pid) if r.pid else None
            items.append((self._proc_key(r), [
                Text(str(r.pid if r.pid is not None else "-"),
                     style="#7a8a99"),
                Text(r.name[:26], style="#e6edf3"),
                Text(f" {label[:38]} " if label else "",
                     style=LEVEL_STYLES.get(level, "#4a5a6a")),
                Text(sig.short + ("!" if sig.path_flags else ""),
                     style="bold #ff5f5f" if sig.verdict == "suspicious"
                     else SIG_STYLES.get(sig.signing, "#4a5a6a"))
                if sig is not None else Text(""),
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
                Text(listening or "-", style="#c6a15b")]))
        self._sync_table(table, items)

        bar = self._find("#proc-bar", Static)
        if bar is not None:
            t = Text(" enter/click: details  i: investigate process (TI + "
                     "OSINT)  P: monitor  k: terminate  /: filter",
                     style="#4a5a6a")
            if self.search_term:
                t.append(f"   /{self.search_term} ", style="bold #ffd75f")
            t.append(f"   {len(self.proc_rows)} processes", style="#4a5a6a")
            bar.update(t)
        if self.proc_detail_open:
            self._render_proc_detail()

    def _proc_conns(self, r: ProcRow) -> List[Tuple[str, Connection]]:
        return [(k, c) for k, c in self.keyed
                if (c.pid == r.pid if r.pid is not None
                    else (c.pid is None and (c.pname or "?") == r.name))]

    def _proc_ti(self, r: ProcRow) -> Tuple[str, str]:
        """Worst verdict among the process' peers -> (level, label)."""
        ti = self.snapshot.ti
        if not ti:
            return "", ""
        seen: Dict[str, object] = {}
        for c in self.snapshot.connections:
            if c.raddr and c.raddr in ti and (
                    c.pid == r.pid if r.pid is not None
                    else (c.pid is None and (c.pname or "?") == r.name)):
                seen[c.raddr] = ti[c.raddr]
        if not seen:
            return "", ""
        rank = {"malicious": 3, "suspicious": 2, "info": 1}
        worst = max(seen.values(), key=lambda v: rank.get(v.level, 0))
        flagged = sum(1 for v in seen.values() if rank.get(v.level, 0) >= 2)
        if rank.get(worst.level, 0) >= 1:
            label = worst.label + (f" (+{flagged - 1} peer)"
                                   if flagged > 1 else "")
            return worst.level, label
        if all(v.level == "clean" for v in seen.values()):
            return "clean", "ok"
        return "", "…" if any(v.abuse_state == "pending"
                              for v in seen.values()) else ""

    def _process_context(self, pid: Optional[int]):
        """Process tree + launchd persistence (cheap part only), cached 15 s."""
        if not pid:
            return None
        cached = self._proc_ctx.get(pid)
        if cached and time.monotonic() - cached[0] < 15:
            return cached[1]
        try:
            ctx = self.monitor.macctx.collect(pid)
        except Exception:                              # noqa: BLE001
            return None
        if len(self._proc_ctx) > 200:
            self._proc_ctx.clear()
        self._proc_ctx[pid] = (time.monotonic(), ctx)
        return ctx

    def _current_proc(self) -> Optional[ProcRow]:
        table = self._find("#proc-table", DataTable)
        if table is None or not self.proc_rows:
            return None
        idx = table.cursor_row
        return self.proc_rows[idx] if 0 <= idx < len(self.proc_rows) else None

    def _set_proc_detail(self, is_open: bool) -> None:
        self.proc_detail_open = is_open
        panel = self._find("#proc-detail", Horizontal)
        if panel is None:
            return
        panel.set_class(is_open, "open")
        if is_open:
            self._render_proc_detail()
            table = self._find("#proc-table", DataTable)
            if table is not None:
                table.call_after_refresh(table._scroll_cursor_into_view)

    def _render_proc_detail(self) -> None:
        info = self._find("#pd-info", Static)
        conns_table = self._find("#pd-conns", DataTable)
        if info is None or conns_table is None:
            return
        r = self._current_proc()
        self.proc_detail_row = r
        if r is None:
            info.update(Text("no process selected", style="#4a5a6a"))
            self.proc_detail_conns = []
            self._sync_table(conns_table, [])
            return
        now = time.time()
        label = "#7a8a99"

        def line(t: Text, name: str, value: str, style: str = "#e6edf3",
                 extra: str = "", extra_style: str = "#7a8a99") -> None:
            t.append(f" {name:<11}", style=label)
            t.append(value or "-", style=style if value else "#4a5a6a")
            if extra:
                t.append(f"   {extra}", style=extra_style)
            t.append("\n")

        level, ti_label = self._proc_ti(r)
        t = Text()
        t.append(f" {r.name} ", style="bold #06090c on #5fd7ff")
        t.append(f"  pid {r.pid if r.pid is not None else '?'}  ",
                 style="#c8d3de")
        if ti_label:
            t.append(f" {ti_label} ", style=LEVEL_STYLES.get(level, ""))
        t.append("\n")

        p = process_info(r.pid)
        if p:
            line(t, "executable", str(p.get("exe") or p.get("name") or ""))
            line(t, "user", str(p.get("user") or ""), "#c8d3de",
                 f"parent {p.get('parent', '?')} ({p['ppid']})"
                 if p.get("ppid") else "")
            bits = " · ".join(str(b) for b in (
                f"up {_span(now - float(p['started']))}"
                if p.get("started") else "",
                f"rss {human_bytes(int(p['rss']))}" if p.get("rss") else "",
                f"{p['threads']} threads" if p.get("threads") else "",
                str(p.get("status") or "")) if b)
            line(t, "runtime", bits, "#9fb0c0")
            cmd = str(p.get("cmdline") or "")
            if cmd and cmd != p.get("exe"):
                line(t, "cmdline", cmd[:200], "#7a8a99")
        elif r.pid:
            line(t, "executable", "", extra="details need sudo or the process "
                                            "has exited")
        else:
            line(t, "executable", "", extra="owner unknown — run with sudo to "
                                            "attribute sockets")
        sig = self.snapshot.procsig.get(r.pid) if r.pid else None
        if sig is not None:
            line(t, "signature", sig.signing + (f" — {sig.signer}"
                                                if sig.signer else ""),
                 LEVEL_TEXT.get(sig.verdict, "#9fb0c0"))
            if sig.path_flags:
                line(t, "path flags", ", ".join(sig.path_flags),
                     "bold #ffaf5f")
            if sig.error:
                line(t, "", sig.error, "#7a8a99")
        ctx = self._process_context(r.pid)
        if ctx is not None:
            if ctx.tree:
                line(t, "tree", ctx.tree_text[-150:], "#9fb0c0")
            if ctx.persistence:
                for item in ctx.persistence[:2]:
                    line(t, "persists", item.describe()[:150], "#ffd75f")
            elif r.pid:
                line(t, "persists", "no launchd job starts this binary",
                     "#7a8a99")
            for note in ctx.notes[:1]:
                line(t, "", note[:150], "#ffaf5f")
        line(t, "traffic", f"▼ {human_rate(r.in_rate)}  ▲ "
                           f"{human_rate(r.out_rate)}", "#c8d3de",
             f"total in {human_bytes(r.bytes_in)} / out "
             f"{human_bytes(r.bytes_out)}")
        line(t, "sockets", f"{r.conns} ({r.established} established, "
                           f"{r.remotes} peer(s))", "#c8d3de",
             "listening on " + ", ".join(map(str, sorted(r.listen_ports)[:10]))
             if r.listen_ports else "")

        mine = self._proc_conns(r)
        peers = {c.raddr for _, c in mine if c.raddr}
        flagged = [(ip, self.snapshot.ti[ip]) for ip in sorted(peers)
                   if ip in self.snapshot.ti
                   and self.snapshot.ti[ip].level in ("malicious",
                                                      "suspicious")]
        t.append(f" {'intel':<11}", style=label)
        if flagged:
            t.append(f"{len(flagged)} of {len(peers)} peer(s) flagged\n",
                     style=LEVEL_TEXT.get(level, ""))
            for ip, v in flagged[:4]:
                t.append(f"            {ip}  ", style="#c8d3de")
                t.append(f" {v.label[:30]} ",
                         style=LEVEL_STYLES.get(v.level, ""))
                t.append("\n")
        elif peers:
            t.append(f"no flagged peer among {len(peers)}\n", style="#5f875f")
        else:
            t.append("no remote peers\n", style="#4a5a6a")
        hits = [i for i, rule in enumerate(self.watchlist)
                if any(rule.matches(c, self._hostname(c.raddr))
                       for _, c in mine)]
        if hits:
            line(t, "monitored", ", ".join(f"rule #{i + 1}" for i in hits),
                 "#ff87d7")
        t.append(" i investigate · P monitor process · k terminate · tab: "
                 "connections (enter opens, i investigates) · esc close",
                 style="#4a5a6a")
        info.update(t)

        rank = {"malicious": 0, "suspicious": 1}
        mine.sort(key=lambda kc: (
            rank.get(self._ti_level(kc[1].raddr), 2), not kc[1].raddr,
            kc[1].raddr, kc[1].rport))
        self.proc_detail_conns = mine
        flows = self.snapshot.flows
        items = []
        for key, c in mine:
            v = self.snapshot.ti.get(c.raddr) if c.raddr else None
            f = next((x for x in flows.values()
                      if (x.proto, x.lport, x.raddr, x.rport) ==
                      (c.proto, c.lport, c.raddr, c.rport)), None)
            items.append((key, [
                Text(f" {v.label[:22]} ", style=LEVEL_STYLES.get(v.level, ""))
                if v is not None and v.label else Text(""),
                _proto_text(c), _state_text(c),
                Text(c.remote if c.raddr else f"(local :{c.lport})",
                     style="#c8d3de" if c.raddr else "#4a5a6a"),
                Text(self._hostname(c.raddr)[:30], style="#7fb3d5"),
                Text(_short_location(self._geo(c.raddr))[:20],
                     style="#c6a15b"),
                Text(human_rate(f.in_rate) if f and f.in_rate else "-",
                     style="#5fd7ff"),
                Text(human_rate(f.out_rate) if f and f.out_rate else "-",
                     style="#ffaf5f")]))
        self._sync_table(conns_table, items)
        title = self._find("#pd-conns-title", Static)
        if title is not None:
            title.update(f" CONNECTIONS OF {r.name} ({len(mine)}) — enter: "
                         "open in Connections, i: investigate address")

    @staticmethod
    def _proc_key(r: ProcRow) -> str:
        return str(r.pid) if r.pid is not None else f"name:{r.name}"

    # -- monitor -----------------------------------------------------------
    def _render_monitor(self) -> None:
        status = self._find("#mon-status", Static)
        rules = self._find("#mon-rules", DataTable)
        table = self._find("#mon-table", DataTable)
        empty = self._find("#mon-empty", Static)
        if None in (status, rules, table, empty):
            return
        now = time.time()
        entries = self.tracker.rows()
        self.mon_rows = entries
        live = sum(1 for e in entries if not e.closed)

        t = Text()
        t.append(f" {len(self.watchlist)} rule(s) ", style="bold #ff87d7")
        t.append(f"  {live} live", style="#5fff87")
        t.append(f"  {len(entries) - live} closed", style="#7a8a99")
        t.append("    d: delete rule   c: clear closed   enter: show in "
                 "Connections   tab: switch table", style="#4a5a6a")
        if self.watchlist.error:
            t.append(f"   ! {self.watchlist.error[:60]}", style="#ff5f5f")
        elif self.watchlist.path:
            t.append(f"   saved in {self.watchlist.path}", style="#4a5a6a")
        status.update(t)
        empty.set_class(bool(len(self.watchlist)), "hidden")

        items = []
        for i, r in enumerate(self.watchlist):
            n_live = self.tracker.live_count(r)
            last = self.tracker.last_seen(r)
            items.append((r.ident, [
                Text(str(i + 1), style="#7a8a99"),
                Text(r.scope, style=SCOPE_STYLES.get(r.scope, "#c0c0c0")),
                Text(r.pname or "any", style="#e6edf3" if r.pname
                     else "#4a5a6a"),
                Text(r.proto or "any", style="#87d7ff" if r.proto
                     else "#4a5a6a"),
                Text((r.host or r.raddr or
                      (f"local :{r.lport}" if r.lport else "any"))[:40],
                     style="#7fb3d5"),
                Text(str(r.rport or "any"), style="#c8d3de" if r.rport
                     else "#4a5a6a"),
                Text(str(n_live), style="bold #5fff87" if n_live
                     else "#4a5a6a"),
                Text(str(self.tracker.totals.get(r.ident, 0)),
                     style="#c8d3de"),
                Text("now" if n_live else
                     (f"{_span(now - last)} ago" if last else "never"),
                     style="#5fff87" if n_live else "#7a8a99"),
            ]))
        self._sync_table(rules, items)

        items = []
        for e in entries:
            c = e.conn
            dim = e.closed
            new = (not e.closed and not e.preexisting
                   and now - e.first_seen < 20)
            if e.closed:
                flag = Text("✕ ", style="#7a8a99")
                state = Text("CLOSED", style="#7a8a99")
            else:
                flag = Text("◉ ", style="bold #5fff87" if new else "#ff87d7")
                state = _state_text(c) if c.state else \
                    Text("OPEN", style="#5fff87")
            since = ("before rule" if e.preexisting else
                     time.strftime("%H:%M:%S", time.localtime(e.first_seen)))
            duration = _span(e.duration) if e.closed else \
                _coarse_age(e.first_seen, now)
            if e.closed:
                duration += f"  (closed {_coarse_age(e.last_seen, now)} ago)"
            base = "#5a6a7a" if dim else None
            items.append((f"{e.key}@{e.seq}", [
                flag, state,
                Text(_proto_text(c).plain, style=base or "#87d7ff"),
                Text(str(c.pid or "-"), style=base or "#7a8a99"),
                Text(c.pname[:22], style=base or
                     ("bold #5fff87" if new else "#e6edf3")),
                Text(c.local, style=base or "#9fb0c0"),
                Text(c.remote, style=base or "#c8d3de"),
                Text((e.hostname or self._hostname(c.raddr))[:32],
                     style=base or "#7fb3d5"),
                Text(_short_location(self._geo(c.raddr))[:22],
                     style=base or "#c6a15b"),
                Text(since, style=base or "#9fb0c0"),
                Text(duration, style=base or "#9fb0c0"),
            ]))
        self._sync_table(table, items)
        title = self._find("#mon-table-title", Static)
        if title is not None:
            title.update(f" MONITORED TRAFFIC — {live} live, "
                         f"{len(entries) - live} closed (new on top)")

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

        labels = self.monitor.dns_labels
        rows = [r for r in cache.recent(400)
                if self._dns_match(f"{r.name} {r.client} {r.answer_text} "
                                   f"{labels.get(r.name, '')}")]
        self.dns_rows = rows

        def ti_cell(name: str) -> Text:
            label = labels.get(name, "")
            if not label:
                return Text("")
            style = LEVEL_STYLES["info"] if label == "DGA?" \
                else LEVEL_STYLES["malicious"]
            return Text(f" {label[:20]} ", style=style)

        items, seen = [], {}
        for rec in rows[:250]:
            key = f"{rec.ts:.4f}|{rec.name}|{rec.rtype}|{rec.answer_text}"
            n = seen.get(key, 0)
            seen[key] = n + 1
            items.append((key if not n else f"{key}#{n}", [
                Text(time.strftime("%H:%M:%S", time.localtime(rec.ts)),
                     style="#7a8a99"),
                Text(rec.source[:4],
                     style=SOURCE_STYLES.get(rec.source, "#c0c0c0")),
                Text((rec.client or "-")[:18], style="#e6edf3"),
                Text(rec.rtype, style="#d7afff"),
                ti_cell(rec.name),
                Text(rec.name[:46], style="#7fb3d5"),
                Text(rec.answer_text[:40], style="#c6a15b")]))
        self._sync_table(live, items)

        entries = [e for e in cache.entries()
                   if self._dns_match(f"{e.name} {e.address_text} "
                                      f"{labels.get(e.name, '')}")]
        self.dns_cache_rows = entries
        title.update(f" CACHE — last {window_min} min "
                     f"({len(entries)} names)")
        now = time.time()
        self._sync_table(cache_table, [(e.name, [
            Text(e.name[:34], style="#e6edf3"),
            ti_cell(e.name),
            Text(e.address_text[:30], style="#c6a15b"),
            Text(str(e.hits), style="#5fff87"),
            # minute granularity once it is old: a column that changes every
            # second in every row would repaint the whole table each tick
            Text(_ago(e.last_seen) if now - e.last_seen < 60
                 else _coarse_age(e.last_seen, now), style="#7a8a99"),
            Text(str(e.ttl) if e.ttl else "-", style="#4a5a6a")])
            for e in entries[:400]])

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
        bad = {c.raddr for c in snap.connections
               if c.raddr and self._ti_level(c.raddr) == "malicious"}
        sus = {c.raddr for c in snap.connections
               if c.raddr and self._ti_level(c.raddr) == "suspicious"}
        if bad:
            t.append(f"   ⚠ {len(bad)} MALICIOUS PEER(S) ",
                     style="bold #ffffff on #d70000")
        if sus:
            t.append(f"   ⚠ {len(sus)} suspicious", style="bold #ffaf5f")
        if len(self.watchlist):
            live = sum(1 for e in self.tracker.entries.values()
                       if not e.closed)
            t.append(f"   ◉ {live}", style="#ff87d7")
        unack = self.monitor.alerts.unacknowledged
        if unack:
            worst = max((SEVERITY_RANK_UI.get(a.severity, 0)
                         for a in self.monitor.alerts.snapshot()
                         if not a.acknowledged), default=0)
            t.append(f"   ▲ {unack} alert(s) — 8 ",
                     style="bold #ffffff on #d70000" if worst >= 3
                     else "bold #06090c on #ffaf5f")
        if len(self.monitor.blocklist):
            t.append(f"   ⛔ {len(self.monitor.blocklist)}", style="#ff5f5f")
        if self.flash and time.time() < self._flash_until:
            t.append(f"   {self.flash} ", style="bold #06090c on #ffd75f")
        bar.update(t)

    # -- events ------------------------------------------------------------
    def on_data_table_row_highlighted(self, event) -> None:
        table_id = event.data_table.id
        if table_id == "intel-list":
            self._render_intel_report(force=True)
            return
        if table_id == "proc-table":
            if self.proc_detail_open and event.data_table.has_focus:
                self._render_proc_detail()
            return
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
        elif table_id == "bw-table":
            if event.data_table.has_focus:
                self._render_bandwidth()          # graph follows the cursor

    def on_data_table_row_selected(self, event) -> None:
        table_id = event.data_table.id
        if table_id == "conn-table":
            self._set_detail(True)
        elif table_id == "bw-table":
            self._bw_drill(event.cursor_row)
        elif table_id == "alert-table":
            self._goto_alert(event.cursor_row)
        elif table_id == "proc-table":
            self._set_proc_detail(True)
        elif table_id == "pd-conns":
            idx = event.cursor_row
            if 0 <= idx < len(self.proc_detail_conns):
                key = self.proc_detail_conns[idx][0]
                self.action_show_tab("tab-conn")
                table = self._find("#conn-table", DataTable)
                if table is not None and self._cursor_to_key(table, key):
                    self._set_detail(True)
                else:
                    self._notify("hidden by the current filters")
        elif table_id == "cd-procs":
            idx = event.cursor_row
            if 0 <= idx < len(self.detail_related):
                self._goto_process(self.detail_related[idx][1])
        elif table_id == "mon-table":
            idx = event.cursor_row
            if 0 <= idx < len(self.mon_rows):
                self._goto_connection(self.mon_rows[idx])

    def on_tabbed_content_tab_activated(self, event) -> None:
        # covers mouse clicks on the tab strip; panes are rendered lazily
        try:
            self._render_active(True)
        except Exception:                              # noqa: BLE001
            pass

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "search":
            return
        self.search_term = event.value.strip()
        if self._find("#conn-table", DataTable) is None:
            return
        self._render_connections()
        self._render_dns()
        self._render_bandwidth()
        self._render_processes()
        tabs = self._find("#tabs", TabbedContent)
        if tabs is not None and tabs.active == "tab-alerts":
            self._render_alerts()
        elif tabs is not None and tabs.active == "tab-hist":
            self._render_history()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "intel-input":
            self._investigate_text(event.value)
            event.input.value = ""
            return
        if event.input.id == "search":
            self.query_one("#conn-table", DataTable).focus()

    def on_unmount(self) -> None:
        self.monitor.stop()
        self.cutter.release()

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
        self._render_active(True)

    # -- marking / monitor ---------------------------------------------------
    def _on_conn_pane(self) -> bool:
        tabs = self._find("#tabs", TabbedContent)
        return tabs is not None and tabs.active == "tab-conn"

    def action_mark(self) -> None:
        if not self._on_conn_pane():
            return
        key, _ = self._current()
        if key is None:
            return
        self.marked.symmetric_difference_update({key})
        table = self._find("#conn-table", DataTable)
        self._render_connections()
        if table is not None and key in self.marked \
                and table.cursor_row < len(self.rows) - 1:
            table.move_cursor(row=table.cursor_row + 1)   # mark-and-advance

    def action_clear_marks(self) -> None:
        if self.marked:
            self.marked.clear()
            self._render_connections()

    def action_monitor_marked(self, scope: str = "endpoint") -> None:
        """Turn the marked connections (or the highlighted one when nothing
        is marked) into monitor rules and open the Monitor pane.  Calling it
        again later simply adds to the existing rules."""
        tabs = self._find("#tabs", TabbedContent)
        if tabs is not None and tabs.active == "tab-proc":
            r = self._current_proc()
            if r is None or r.name in ("", "?"):
                self._notify("no named process selected")
                return
            added = self.watchlist.add(WatchRule(pname=r.name,
                                                 scope="process"))
            self.tracker.observe(self.keyed, {
                c.raddr: self._hostname(c.raddr) for _, c in self.keyed
                if c.raddr}, time.time(), self.seen)
            self._notify(f"monitor: process {r.name} added" if added
                         else "monitor: already monitored")
            self.action_show_tab("tab-mon")
            return
        if not self._on_conn_pane():
            return
        by_key = dict(self.keyed)
        picked = [by_key[k] for k in self.row_keys if k in self.marked]
        if not picked:
            _, c = self._current()
            picked = [c] if c is not None else []
        if not picked:
            self._notify("nothing selected")
            return
        added = 0
        for c in picked:
            rule = WatchRule.from_connection(c, scope,
                                             self._hostname(c.raddr))
            added += bool(self.watchlist.add(rule))
        self.marked.clear()
        self.tracker.observe(self.keyed, {
            c.raddr: self._hostname(c.raddr) for _, c in self.keyed
            if c.raddr}, time.time(), self.seen)
        self._render_connections()
        self._notify(f"monitor: +{added} rule(s), {len(self.watchlist)} total"
                     if added else "monitor: already monitored")
        self.action_show_tab("tab-mon")

    # -- alerts ----------------------------------------------------------------
    def _render_alerts(self) -> None:
        status = self._find("#alert-status", Static)
        table = self._find("#alert-table", DataTable)
        blocks = self._find("#block-table", DataTable)
        if None in (status, table, blocks):
            return
        mon = self.monitor
        engine = mon.alerts
        now = time.time()
        rows = [a for a in engine.snapshot()
                if not self.search_term or self.search_term.lower() in
                f"{a.kind} {a.subject} {a.detail} {a.pname}".lower()]
        self.alert_rows = rows

        t = Text()
        if not engine.enabled:
            t.append(" alerting is off ", style="bold #ffaf5f")
        else:
            t.append(f" {engine.unacknowledged} new ", style="bold #ff5f5f"
                     if engine.unacknowledged else "#5f875f")
            t.append(f" {len(rows)} shown", style="#c8d3de")
        t.append(f"   baseline: {engine.baseline.status()}", style="#9fb0c0")
        j = mon.journal
        t.append("   journal: " + ("on" if j is not None and j.enabled
                                   else "off"), style="#9fb0c0")
        t.append("   enter: go to   i: investigate   A: acknowledge all   "
                 "tab → d: unblock", style="#4a5a6a")
        err = mon.alerts_error or (j.error if j is not None else "")
        if err:
            t.append(f"   ! {err[:60]}", style="#ff5f5f")
        status.update(t)

        items = []
        for a in rows[:400]:
            dim = a.acknowledged
            items.append((f"{a.ts:.4f}|{a.dedup}", [
                Text(time.strftime("%H:%M:%S", time.localtime(a.ts)),
                     style="#7a8a99"),
                Text(f" {a.severity.upper()} ", style="#4a5a6a" if dim
                     else SEVERITY_STYLES.get(a.severity, "")),
                Text(a.kind, style="#7a8a99" if dim else "#7fb3d5"),
                Text(a.subject[:60], style="#7a8a99" if dim
                     else "bold #e6edf3"),
                Text(a.detail[:110], style="#5a6a7a" if dim else "#9fb0c0")]))
        self._sync_table(table, items)
        title = self._find("#alert-title", Static)
        if title is not None:
            title.update(f" ALERTS ({len(rows)})" + (
                f" — filter /{self.search_term}" if self.search_term else ""))

        self.block_rows = list(mon.blocklist.entries)
        enforced = set(mon.cutter.blocked)
        self._sync_table(blocks, [(e.ip, [
            Text(e.ip, style="bold #ff5f5f"),
            Text((e.host or "-")[:34], style="#7fb3d5"),
            Text((e.reason or "-")[:40], style="#c6a15b"),
            Text(e.by, style="#9fb0c0"),
            Text(_coarse_age(e.added, now) + " ago", style="#7a8a99"),
            Text("enforced" if e.ip in enforced else "NOT enforced",
                 style="#5fff87" if e.ip in enforced else "bold #ffaf5f")])
            for e in self.block_rows])
        btitle = self._find("#block-title", Static)
        if btitle is not None:
            btitle.update(f" BLOCKED HOSTS ({len(self.block_rows)})" + (
                f" — {mon.block_status}" if mon.block_status else "")
                + ("" if mon.cutter.available or not self.block_rows
                   else "  (run with sudo to enforce)"))

    def action_ack_alerts(self) -> None:
        self.monitor.alerts.acknowledge_all()
        self._render_summary()
        self._render_alerts()

    def _goto_alert(self, row: int) -> None:
        if not 0 <= row < len(self.alert_rows):
            return
        a = self.alert_rows[row]
        a.acknowledged = True
        if a.raddr:
            for key, c in self.keyed:
                if c.raddr == a.raddr and (not a.rport or c.rport == a.rport):
                    self.action_show_tab("tab-conn")
                    table = self._find("#conn-table", DataTable)
                    if table is not None and self._cursor_to_key(table, key):
                        self._set_detail(True)
                        return
        if a.pid or a.pname:
            self._goto_process(ProcRow(pid=a.pid, name=a.pname or "?"))
            return
        self._notify("nothing live to show for this alert - see History (9)")

    def _block(self, ip: str, host: str, reason: str) -> None:
        mon = self.monitor
        try:
            added = mon.blocklist.add(ip, host, reason)
        except ValueError:
            self._notify(f"✗ not an address: {ip}")
            return
        message = mon.apply_blocklist()
        self._notify(("✓ blocked " if added else "already blocked: ") + ip
                     + (f" — {message}" if message else ""), 8.0)

    def _unblock_selected(self) -> None:
        table = self._find("#block-table", DataTable)
        if table is None or not 0 <= table.cursor_row < len(self.block_rows):
            self._notify("select a blocked host first (tab)")
            return
        ip = self.block_rows[table.cursor_row].ip
        self.monitor.blocklist.remove(ip)
        message = self.monitor.apply_blocklist()
        self._notify(f"✓ unblocked {ip}" + (f" — {message}" if message
                                            else ""), 6.0)
        self._render_alerts()

    # -- history -----------------------------------------------------------------
    def _render_history(self) -> None:
        status = self._find("#hist-status", Static)
        table = self._find("#hist-table", DataTable)
        if status is None or table is None:
            return
        j = self.monitor.journal
        t = Text()
        if j is None or not j.enabled:
            t.append(" the journal is off ", style="bold #ffaf5f")
            t.append(" (--no-journal, journal.enabled = false, or --demo)"
                     + (f" — {j.error}" if j is not None and j.error else ""),
                     style="#7a8a99")
            status.update(t)
            self.hist_rows = []
            self._sync_table(table, [])
            return
        from ..core.journal import parse_since

        label, span = HISTORY_WINDOWS[self.hist_window]
        rows = j.connections(parse_since(span), self.search_term,
                             self.hist_flagged, 600)
        self.hist_rows = rows
        for i, (name, _) in enumerate(HISTORY_WINDOWS):
            t.append(f" {name} ", style="bold #06090c on #5fd7ff"
                     if i == self.hist_window else "#4a5a6a")
            t.append(" ")
        t.append(" [ ]: window ", style="#4a5a6a")
        t.append(" FLAGGED ONLY " if self.hist_flagged else " !: flagged only ",
                 style="bold #06090c on #ffaf5f" if self.hist_flagged
                 else "#4a5a6a")
        if self.search_term:
            t.append(f" /{self.search_term} ", style="bold #ffd75f")
        stats = j.stats()
        t.append(f"  {len(rows)} shown", style="#c8d3de")
        t.append(f"   journal: {stats['connections']} connections, "
                 f"{stats['alerts']} alerts, {stats['dns']} DNS answers, "
                 f"{human_bytes(stats['bytes'])}   w: export CSV   "
                 "i: investigate", style="#4a5a6a")
        status.update(t)

        now = time.time()
        items = []
        for r in rows:
            closed = bool(r["closed"])
            base = "#7a8a99" if closed else None
            level = r["ti_level"] or ""
            day = time.strftime("%m-%d ", time.localtime(r["first_seen"])) \
                if now - r["first_seen"] > 86400 else ""
            remote = (f"{r['raddr']}:{r['rport']}" if r["raddr"]
                      else f"(listen :{r['lport']})")
            items.append((str(r["id"]), [
                Text(day + time.strftime("%H:%M:%S",
                                         time.localtime(r["first_seen"])),
                     style="#9fb0c0"),
                Text(_span(r["last_seen"] - r["first_seen"]),
                     style=base or "#c8d3de"),
                Text("✕" if closed else "●",
                     style="#5a6a7a" if closed else "#5fff87"),
                Text(r["proto"] or "", style=base or "#87d7ff"),
                Text((r["pname"] or "?")[:20], style=base or "#e6edf3"),
                Text(str(r["pid"] or "-"), style="#7a8a99"),
                Text(remote, style=base or "#c8d3de"),
                Text((r["host"] or "")[:30], style=base or "#7fb3d5"),
                Text((r["org"] or "")[:20], style=base or "#c6a15b"),
                Text(r["country"] or "", style=base or "#c6a15b"),
                Text(f" {(r['ti_label'] or '')[:20]} " if r["ti_label"]
                     else "", style=LEVEL_STYLES.get(level, "#4a5a6a")),
                Text(r["sig"] or "", style=SIG_STYLES.get(r["sig"] or "",
                                                          "#4a5a6a")),
                Text(human_bytes(r["bytes_in"]) if r["bytes_in"] else "",
                     style="#5fd7ff"),
                Text(human_bytes(r["bytes_out"]) if r["bytes_out"] else "",
                     style="#ffaf5f")]))
        self._sync_table(table, items)

    def action_hist_window(self, step: int) -> None:
        tabs = self._find("#tabs", TabbedContent)
        if tabs is None or tabs.active != "tab-hist":
            return
        self.hist_window = min(len(HISTORY_WINDOWS) - 1,
                               max(0, self.hist_window + int(step)))
        self._render_history()

    def action_hist_flagged(self) -> None:
        tabs = self._find("#tabs", TabbedContent)
        if tabs is None or tabs.active != "tab-hist":
            return
        self.hist_flagged = not self.hist_flagged
        self._render_history()

    def _export_history(self) -> None:
        j = self.monitor.journal
        if j is None or not j.enabled or not self.hist_rows:
            self._notify("nothing to export")
            return
        import csv
        from pathlib import Path
        from ..core.util import give_back

        folder = Path.home() / "netmonguru-reports"
        target = folder / time.strftime("history-%Y%m%d-%H%M%S.csv")
        try:
            folder.mkdir(parents=True, exist_ok=True)
            with target.open("w", newline="", encoding="utf-8") as fh:
                cols = [k for k in self.hist_rows[0].keys() if k != "id"]
                w = csv.writer(fh)
                w.writerow(cols + ["first_seen_iso", "duration_s"])
                for r in self.hist_rows:
                    w.writerow([r[c] for c in cols] + [
                        time.strftime("%Y-%m-%dT%H:%M:%S%z",
                                      time.localtime(r["first_seen"])),
                        round(r["last_seen"] - r["first_seen"], 1)])
            give_back(target)
            self._notify(f"✓ {len(self.hist_rows)} rows → {target}", 8.0)
        except Exception as exc:                       # noqa: BLE001
            self._notify(f"✗ export failed: {exc}"[:80], 8.0)

    def action_help(self) -> None:
        tabs = self._find("#tabs", TabbedContent)
        self.push_screen(HelpScreen(tabs.active if tabs is not None
                                    else "tab-conn"))

    # -- threat intelligence -------------------------------------------------
    def _render_intel(self) -> None:
        status = self._find("#intel-status", Static)
        listing = self._find("#intel-list", DataTable)
        feeds = self._find("#intel-feeds", DataTable)
        if None in (status, listing, feeds):
            return
        ti = self.ti
        now = time.time()
        t = Text()
        if not ti.enabled:
            t.append(" threat intelligence is off ", style="bold #ffaf5f")
            t.append(" (--no-ti or --demo)", style="#7a8a99")
        else:
            t.append(" keys: ", style="#7a8a99")
            for title, present in ti.key_status():
                t.append(("✓" if present else "✗") + title.split(" ")[0] + " ",
                         style="#5fff87" if present else "#4a5a6a")
            if ti.auto_active:
                t.append(f"  auto AbuseIPDB: on ({ti.auto_left} left today)",
                         style="#c8d3de")
            else:
                t.append("  auto AbuseIPDB: off" + (
                    "" if ti.keys.get("abuseipdb") or not ti.auto
                    else " (no key)"), style="#7a8a99")
            t.append("   i: investigate  w: write report  R: refresh feeds",
                     style="#4a5a6a")
            if ti.key_warning:
                t.append(f"   ! {ti.key_warning[:60]}", style="#ff5f5f")
        status.update(t)

        self.intel_rows = list(ti.reports)
        items = []
        for r in self.intel_rows:
            level, _ = r.overall()
            if not r.done:
                verdict = Text(f"… {r.pending} pending", style="#ffd75f")
            else:
                verdict = Text(f" {level.upper()} ",
                               style=LEVEL_STYLES.get(level, ""))
            items.append((f"{r.title}@{r.started}", [
                Text(time.strftime("%H:%M:%S", time.localtime(r.started)),
                     style="#7a8a99"),
                Text(("⚙ " if r.kind == "process" else "") + r.title[:30],
                     style="#e6edf3"),
                verdict,
                Text((r.pname or "-")[:14], style="#9fb0c0")]))
        self._sync_table(listing, items)

        items = []
        if ti.feeds is not None:
            for title, state, size, fetched, error in ti.feeds.summary():
                style = {"ok": "#5fff87", "cached": "#c6a15b",
                         "stale": "#ffaf5f", "error": "#ff5f5f"}.get(
                             state, "#7a8a99")
                items.append((title, [
                    Text(title[:28], style="#e6edf3"),
                    Text((error or state)[:16] if state in ("error", "stale")
                         else state[:16], style=style),
                    Text(str(size), style="#c8d3de"),
                    Text(_coarse_age(fetched, now) if fetched else "-",
                         style="#7a8a99")]))
        self._sync_table(feeds, items)
        self._render_intel_report()

    def _selected_report(self):
        listing = self._find("#intel-list", DataTable)
        if listing is None or not self.intel_rows:
            return None
        idx = listing.cursor_row
        return self.intel_rows[idx] if 0 <= idx < len(self.intel_rows) \
            else self.intel_rows[0]

    def _render_intel_report(self, force: bool = False) -> None:
        widget = self._find("#intel-report", Static)
        if widget is None:
            return
        r = self._selected_report()
        sig = None if r is None else (
            r.started, r.pending, r.done,
            tuple(s.status for s in r.sources.values()),
            tuple(sub.done for sub in r.subs))
        if not force and sig == self._intel_sig:
            return
        self._intel_sig = sig
        if r is None:
            widget.update(Text(
                "\n No investigation yet.\n\n"
                " Select a connection (Connections, Monitor or Map) and press "
                "i,\n or type an address in the box on the left.\n\n"
                " An investigation asks every configured reputation source, "
                "runs RDAP/whois,\n collects OSINT (Shodan InternetDB, DNS, "
                "certificate transparency) and checks\n the owning process "
                "(code signature, Gatekeeper, SHA-256 → VirusTotal).\n\n"
                " API keys: ~/.config/netmonguru/keys.toml",
                style="#7a8a99"))
            return
        widget.update(self._report_text(r))

    def _report_text(self, r) -> Text:
        level, reasons = r.overall()
        t = Text()
        t.append(f" {'PROCESS  ' if r.kind == 'process' else ''}{r.title} ",
                 style="bold #06090c on #5fd7ff")
        if r.hostname:
            t.append(f"  {r.hostname}", style="#7fb3d5")
        t.append("   ")
        if r.done:
            t.append(f" {level.upper()} ", style=LEVEL_STYLES.get(level, ""))
            t.append(f"   {r.finished - r.started:.1f}s", style="#4a5a6a")
        else:
            t.append(f" collecting… {r.pending} source(s) pending ",
                     style="bold #06090c on #ffd75f")
        t.append("\n")
        if r.note:
            t.append(f" {r.note}\n", style="#ffaf5f")
        for reason in reasons:
            t.append(f"  • {reason[:150]}\n", style=LEVEL_TEXT.get(level, ""))

        def head(title: str) -> None:
            t.append(f"\n ── {title} ", style="bold #7fb3d5")
            t.append("─" * max(4, 70 - len(title)) + "\n", style="#1f2b36")

        def fact(name: str, value: str, style: str = "#c8d3de") -> None:
            t.append(f"   {name[:18]:<19}", style="#7a8a99")
            t.append(f"{value}\n", style=style)

        if r.context:
            head("LOCAL CONTEXT")
            for k, v in r.context:
                fact(k, v)

        if r.kind == "ip":
            head("LOCAL FEEDS")
            if r.feed_hits:
                for h in r.feed_hits:
                    t.append(f"   {h.label} ",
                             style=LEVEL_STYLES.get(h.severity))
                    t.append(f"  {h.detail}\n", style="#c8d3de")
            else:
                t.append("   no hit in any local feed\n", style="#5f875f")

        if r.process is not None:
            p = r.process
            head(f"PROCESS  {r.pname or '?'} (pid {r.pid})")
            fact("executable", p.exe or "?")
            fact("signature", p.signing + (f" — {p.signer}" if p.signer
                                           else ""),
                 LEVEL_TEXT.get(p.verdict, "#c8d3de"))
            if p.identifier:
                fact("identifier", p.identifier)
            if p.gatekeeper:
                fact("gatekeeper", p.gatekeeper)
            if p.path_flags:
                fact("path flags", ", ".join(p.path_flags), "bold #ffaf5f")
            if p.sha256:
                fact("sha-256", p.sha256)
            if p.error:
                fact("note", p.error, "#7a8a99")
        if r.proc_ctx is not None:
            x = r.proc_ctx
            head("PROCESS CONTEXT")
            fact("process tree", x.tree_text or "-")
            if x.children:
                fact("children", ", ".join(f"{n} ({p})"
                                           for p, n in x.children))
            if x.persistence:
                for item in x.persistence:
                    fact("persistence", item.describe(), "#ffd75f")
            else:
                fact("persistence", "no launchd job starts this binary",
                     "#7a8a99")
            if x.hardened is not None:
                fact("hardened runtime", "yes" if x.hardened else "NO",
                     "#5fff87" if x.hardened else "bold #ffaf5f")
            if x.sandboxed is not None:
                fact("app sandbox", "yes" if x.sandboxed else "no")
            for e in x.entitlements:
                fact("entitlement", e, "#ffd75f")
            for n in x.notes:
                fact("note", n, "#ffaf5f")
            for i, f in enumerate(x.open_files[:25]):
                fact("open files" if i == 0 else "", f, "#9fb0c0")

        for kind, title in (("ti", "THREAT INTELLIGENCE"),
                            ("process", "PROCESS REPUTATION"),
                            ("whois", "WHOIS"), ("osint", "OSINT")):
            rows = [x for x in r.sources.values() if x.kind == kind]
            if not rows:
                continue
            head(title)
            for x in rows:
                t.append(f"  {x.title:<34}", style="bold #e6edf3")
                if x.verdict:
                    t.append(f" {x.verdict.upper()} ",
                             style=LEVEL_STYLES.get(x.verdict, ""))
                else:
                    t.append(x.status, style=STATUS_STYLES.get(x.status, ""))
                if x.elapsed:
                    t.append(f"  {x.elapsed:.1f}s", style="#4a5a6a")
                t.append("\n")
                if x.headline:
                    t.append(f"   {x.headline[:160]}\n",
                             style=LEVEL_TEXT.get(x.verdict, "#c8d3de")
                             if x.status == "ok" else "#7a8a99")
                for k, v in x.facts:
                    fact(k, str(v)[:200])
                if x.link and x.status in ("ok", "none"):
                    t.append(f"   {x.link}\n", style="#4a6a8a")

        if r.kind == "process":
            head(f"REMOTE PEERS ({len(r.peers)})")
            deep = {sub.ip for sub in r.subs}
            for ip, port, host, lvl, label in r.peers[:40]:
                t.append(f"   {ip + ':' + str(port):<28}", style="#c8d3de")
                t.append(f"{(host or '-')[:34]:<36}", style="#7fb3d5")
                if label:
                    t.append(f" {label} ", style=LEVEL_STYLES.get(lvl, ""))
                else:
                    t.append("no local data", style="#4a5a6a")
                if ip in deep:
                    t.append("  ← investigated below", style="#4a5a6a")
                t.append("\n")
            if not r.peers:
                t.append("   no public peers\n", style="#4a5a6a")
            for sub in r.subs:
                sub_level, _ = sub.overall()
                head(f"PEER {sub.title}" + (f"  {sub.hostname}"
                                            if sub.hostname else ""))
                if sub.done:
                    t.append(f"   verdict  ", style="#7a8a99")
                    t.append(f" {sub_level.upper()} ",
                             style=LEVEL_STYLES.get(sub_level, ""))
                else:
                    t.append(f"   collecting… {sub.pending} pending",
                             style="#ffd75f")
                t.append("   (full report: see the list on the left)\n",
                         style="#4a5a6a")
                for h in sub.feed_hits:
                    t.append(f"   {h.label} ",
                             style=LEVEL_STYLES.get(h.severity))
                    t.append(f"  {h.detail}\n", style="#c8d3de")
                for x in sub.sources.values():
                    if x.status == "skipped":
                        continue
                    t.append(f"   {x.title[:30]:<31}", style="#e6edf3")
                    if x.verdict:
                        t.append(f" {x.verdict.upper()} ",
                                 style=LEVEL_STYLES.get(x.verdict, ""))
                        t.append(" ")
                    elif x.status != "ok":
                        t.append(f"{x.status} ",
                                 style=STATUS_STYLES.get(x.status, ""))
                    t.append(f"{x.headline[:110]}\n", style="#9fb0c0")
        return t

    def _conn_context(self, c: Connection) -> List[Tuple[str, str]]:
        ip = c.raddr
        peers = [o for o in self.snapshot.connections if o.raddr == ip]
        procs = sorted({f"{o.pname or '?'} ({o.pid or '?'})" for o in peers})
        ports = sorted({o.rport for o in peers})
        ctx = [("connection", f"{c.local} → {c.remote}  {c.proto} {c.state}"),
               ("talking to it", f"{len(peers)} socket(s) from "
                                 f"{', '.join(procs[:6])}"),
               ("remote ports", ", ".join(map(str, ports[:12])))]
        g = self._geo(ip)
        if g:
            ctx.append(("geo / owner", f"{g.label} — {g.org or '-'} "
                                       f"{g.asn or ''}".strip()))
        names = sorted({e.name for e in self.monitor.dns.cache.entries()
                        if ip in getattr(e, "addresses", [])})
        if names:
            ctx.append(("names resolved", ", ".join(names[:8])))
        hits = self.watchlist.match(c, self._hostname(ip))
        if hits:
            ctx.append(("monitored by", ", ".join(
                f"rule #{i + 1}" for i in hits)))
        return ctx

    def action_investigate(self) -> None:
        tabs = self._find("#tabs", TabbedContent)
        if tabs is not None and tabs.active == "tab-intel":
            box = self._find("#intel-input", Input)
            if box is not None:
                box.focus()
            return
        c = self._target_conn()
        if c is None and tabs is not None and tabs.active == "tab-proc":
            self._investigate_process()
            return
        if c is None or not c.raddr:
            self._notify("select a connection with a remote address")
            return
        self.ti.investigate(c.raddr, c.rport, c.proto,
                            self._hostname(c.raddr), c.pid, c.pname,
                            self._conn_context(c))
        self._open_intel()

    def _investigate_process(self) -> None:
        r = self._current_proc()
        if r is None:
            self._notify("no process selected")
            return
        mine = [c for _, c in self._proc_conns(r)]
        peers = [(c.raddr, c.rport, c.proto, self._hostname(c.raddr))
                 for c in mine if c.raddr]
        p = process_info(r.pid)
        ctx = [("sockets", f"{r.conns} ({r.established} established), "
                           f"{r.remotes} peer(s)"),
               ("traffic", f"down {human_rate(r.in_rate)}, up "
                           f"{human_rate(r.out_rate)}, total in "
                           f"{human_bytes(r.bytes_in)} / out "
                           f"{human_bytes(r.bytes_out)}")]
        if r.listen_ports:
            ctx.append(("listening on", ", ".join(
                map(str, sorted(r.listen_ports)[:12]))))
        for name, key in (("user", "user"), ("command line", "cmdline")):
            if p.get(key):
                ctx.append((name, str(p[key])[:200]))
        if p.get("ppid"):
            ctx.append(("parent", f"{p.get('parent', '?')} ({p['ppid']})"))
        names = sorted({e.name for e in self.monitor.dns.cache.entries()
                        if any(ip in getattr(e, "addresses", [])
                               for ip, *_ in peers)})
        if names:
            ctx.append(("names resolved", ", ".join(names[:10])))
        self.ti.investigate_process(r.pid, r.name, peers, ctx)
        self._open_intel()

    def _investigate_text(self, value: str) -> None:
        import ipaddress

        value = value.strip().strip("[]")
        try:
            ip = str(ipaddress.ip_address(value))
        except ValueError:
            self._notify(f"not an IP address: {value[:40]}")
            return
        match = next((c for c in self.snapshot.connections if c.raddr == ip),
                     None)
        if match is not None:
            self.ti.investigate(ip, match.rport, match.proto,
                                self._hostname(ip), match.pid, match.pname,
                                self._conn_context(match))
        else:
            self.ti.investigate(ip, hostname=self._hostname(ip), context=[
                ("connection", "none right now - address entered by hand")])
        self._open_intel()

    def _open_intel(self) -> None:
        self.action_show_tab("tab-intel")
        listing = self._find("#intel-list", DataTable)
        if listing is not None and listing.row_count:
            listing.move_cursor(row=0)
        self._render_intel_report(force=True)

    def action_export_report(self) -> None:
        tabs = self._find("#tabs", TabbedContent)
        if tabs is not None and tabs.active == "tab-hist":
            self._export_history()
            return
        if tabs is None or tabs.active != "tab-intel":
            return
        r = self._selected_report()
        if r is None:
            self._notify("no report selected")
            return
        try:
            md, _ = self.ti.export(r)
            self._notify(f"✓ saved {md} (+ .json)", 8.0)
        except Exception as exc:                       # noqa: BLE001
            self._notify(f"✗ export failed: {exc}"[:80], 8.0)

    def action_refresh_feeds(self) -> None:
        self.ti.refresh_feeds()
        self._notify("refreshing threat feeds…")

    # -- ending a connection ------------------------------------------------
    def _target_conn(self) -> Optional[Connection]:
        """The connection under the cursor of the pane being looked at."""
        tabs = self._find("#tabs", TabbedContent)
        active = tabs.active if tabs is not None else ""
        if active == "tab-conn":
            return self._current()[1]
        if active == "tab-mon":
            table = self._find("#mon-table", DataTable)
            if table is not None and 0 <= table.cursor_row < len(self.mon_rows):
                entry = self.mon_rows[table.cursor_row]
                return None if entry.closed else entry.conn
        if active == "tab-alerts":
            table = self._find("#alert-table", DataTable)
            if table is not None and \
                    0 <= table.cursor_row < len(self.alert_rows):
                a = self.alert_rows[table.cursor_row]
                if a.raddr:
                    live = next((c for _, c in self.keyed
                                 if c.raddr == a.raddr), None)
                    return live or Connection(
                        proto="TCP", family="IPv6" if ":" in a.raddr
                        else "IPv4", raddr=a.raddr, rport=a.rport,
                        pid=a.pid, pname=a.pname)
            return None
        if active == "tab-hist":
            table = self._find("#hist-table", DataTable)
            if table is not None and \
                    0 <= table.cursor_row < len(self.hist_rows):
                r = self.hist_rows[table.cursor_row]
                if r["raddr"]:
                    return Connection(
                        proto=r["proto"] or "TCP", family=r["family"] or "",
                        laddr=r["laddr"] or "", lport=r["lport"] or 0,
                        raddr=r["raddr"], rport=r["rport"] or 0,
                        state="" if r["closed"] else (r["state"] or ""),
                        pid=None if r["closed"] else r["pid"],
                        pname=r["pname"] or "")
            return None
        if active == "tab-proc":
            table = self._find("#pd-conns", DataTable)
            if table is not None and table.has_focus and \
                    0 <= table.cursor_row < len(self.proc_detail_conns):
                return self.proc_detail_conns[table.cursor_row][1]
            return None
        if active == "tab-map":
            table = self._find("#map-detail", DataTable)
            if table is not None and \
                    0 <= table.cursor_row < len(self.map_detail_rows):
                return self.map_detail_rows[table.cursor_row]
        return None

    def action_kill_connection(self) -> None:
        c = self._target_conn()
        tabs = self._find("#tabs", TabbedContent)
        if c is None and tabs is not None and tabs.active == "tab-proc":
            r = self._current_proc()
            if r is None or not r.pid:
                self._notify("no process with a known pid selected")
                return
            ghost = Connection(proto="", family="", pid=r.pid, pname=r.name,
                               state=f"{r.conns} socket(s)")
            self.push_screen(
                KillScreen(ghost, "", r.conns, "pick a single connection to "
                           "cut (tab → list on the right, or Connections)"),
                lambda choice: self._do_kill(ghost, choice))
            return
        if c is None:
            self._notify("no live connection selected")
            return
        cut_error = self.cutter.why_not
        if not cut_error and not c.raddr:
            cut_error = "listening socket - only its process can be stopped"
        sockets = sum(1 for o in self.snapshot.connections
                      if c.pid is not None and o.pid == c.pid)
        self.push_screen(
            KillScreen(c, self._hostname(c.raddr), sockets, cut_error,
                       self.cutter.why_not, c.raddr in self.monitor.blocklist),
            lambda choice: self._do_kill(c, choice))

    def _do_kill(self, c: Connection, choice: Optional[str]) -> None:
        if not choice:
            return
        if choice == "block":
            v = self.snapshot.ti.get(c.raddr)
            self._block(c.raddr, self._hostname(c.raddr),
                        (v.label if v is not None and v.label else "")
                        or f"blocked from {c.pname or 'a connection'}")
            return
        if choice == "cut":
            ok, message = self.cutter.cut(c)
        else:
            ok, message = terminate_process(c.pid, force=choice == "kill")
        self._notify(("✓ " if ok else "✗ ") + message, 8.0)

    def action_delete_rule(self) -> None:
        tabs = self._find("#tabs", TabbedContent)
        if tabs is not None and tabs.active == "tab-alerts":
            self._unblock_selected()
            return
        rules = self._find("#mon-rules", DataTable)
        if tabs is None or rules is None or tabs.active != "tab-mon":
            return
        removed = self.watchlist.remove(rules.cursor_row)
        if removed is not None:
            self.tracker.prune()
            self._notify(f"rule removed: {removed.describe()}")
            self._render_monitor()

    def action_clear_history(self) -> None:
        tabs = self._find("#tabs", TabbedContent)
        if tabs is None or tabs.active != "tab-mon":
            return
        self.tracker.clear_history()
        self._render_monitor()

    def action_goto_process(self) -> None:
        if not self._on_conn_pane():
            return
        _, c = self._current()
        if c is None:
            return
        self._goto_process(ProcRow(pid=c.pid, name=c.pname or "?"))

    def _goto_process(self, row: ProcRow) -> None:
        self.action_show_tab("tab-proc")
        table = self._find("#proc-table", DataTable)
        if table is not None and not self._cursor_to_key(
                table, self._proc_key(row)):
            self._notify(f"{row.name}: not in the process list")

    def _goto_connection(self, entry) -> None:
        if entry.closed:
            self._notify("that connection has closed")
            return
        self.action_show_tab("tab-conn")
        table = self._find("#conn-table", DataTable)
        if table is None:
            return
        if self._cursor_to_key(table, entry.key):
            self._set_detail(True)
        else:
            self._notify("hidden by the current filters")

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
        table = self._find("#bw-table", DataTable)
        if table is not None and table.row_count:
            table.move_cursor(row=(table.cursor_row + 1) % table.row_count)
            self._render_bandwidth()

    def action_bw_view(self, view: str = "") -> None:
        tabs = self._find("#tabs", TabbedContent)
        if tabs is None or tabs.active != "tab-bw":
            return
        if view not in BW_VIEWS:
            view = BW_VIEWS[(BW_VIEWS.index(self.bw_view) + 1) % len(BW_VIEWS)]
        self.bw_view = view
        self.bw_process = None
        self._render_bandwidth()
        table = self._find("#bw-table", DataTable)
        if table is not None and table.row_count:
            table.move_cursor(row=0)
            self._render_bandwidth()

    def _bw_drill(self, row: int) -> None:
        """Enter on a process -> its connections; on a connection -> open it
        in the Connections pane."""
        if not 0 <= row < len(self.bw_keys):
            return
        key = self.bw_keys[row]
        if self.bw_view == "processes" and key != ALL_KEY:
            p = self.snapshot.procs.get(key)
            if p is not None:
                self.bw_view = "connections"
                self.bw_process = (p.pid, p.name)
                self._render_bandwidth()
                table = self._find("#bw-table", DataTable)
                if table is not None:
                    table.move_cursor(row=0)
                self._render_bandwidth()
        elif self.bw_view == "connections" and key != ALL_KEY:
            f = self.snapshot.flows.get(key)
            if f is None:
                return
            for k, c in self.keyed:
                if (c.proto, c.lport, c.raddr, c.rport) == \
                        (f.proto, f.lport, f.raddr, f.rport):
                    self.action_show_tab("tab-conn")
                    table = self._find("#conn-table", DataTable)
                    if table is not None and self._cursor_to_key(table, k):
                        self._set_detail(True)
                    else:
                        self._notify("hidden by the current filters")
                    return
            self._notify("that connection is not in the socket table")

    def action_search(self) -> None:
        box = self.query_one("#search", Input)
        box.add_class("visible")
        box.focus()

    def action_clear_search(self) -> None:
        box = self.query_one("#search", Input)
        searching = box.has_class("visible") or bool(self.search_term)
        if not searching and self.detail_open:
            self._set_detail(False)
            return
        tabs = self._find("#tabs", TabbedContent)
        if not searching and tabs is not None and tabs.active == "tab-proc" \
                and self.proc_detail_open:
            self._set_proc_detail(False)
            proc_table = self._find("#proc-table", DataTable)
            if proc_table is not None:
                proc_table.focus()
            return
        if not searching and tabs is not None and tabs.active == "tab-bw" \
                and self.bw_process is not None:
            self.bw_process = None
            self.bw_view = "processes"
            self._render_bandwidth()
            return
        box.value = ""
        box.remove_class("visible")
        self.search_term = ""
        active = self.query_one("#tabs", TabbedContent).active
        focus_id = {"tab-dns": "#dns-live", "tab-intel": "#intel-list",
                    "tab-bw": "#bw-table", "tab-proc": "#proc-table",
                    "tab-alerts": "#alert-table", "tab-hist": "#hist-table",
                    "tab-mon": "#mon-table"}.get(active, "#conn-table")
        self.query_one(focus_id, DataTable).focus()
        self._render_connections()
        self._render_dns()
        self._render_bandwidth()
        self._render_processes()
        tabs = self._find("#tabs", TabbedContent)
        if tabs is not None and tabs.active == "tab-alerts":
            self._render_alerts()
        elif tabs is not None and tabs.active == "tab-hist":
            self._render_history()
