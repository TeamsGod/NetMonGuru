"""Headless UI test for the Bandwidth pane: per-process default view, graph
following the selected row, drill-down to a process' connections, text filter,
view switching."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from textual.widgets import DataTable                            # noqa: E402

from netmonguru.core.monitor import Monitor                      # noqa: E402
from netmonguru.ui.app import ALL_KEY, NetMonGuruApp             # noqa: E402
from netmonguru.ui.widgets.graph import BandwidthGraph           # noqa: E402


async def main() -> int:
    out = Path("screenshots")
    out.mkdir(exist_ok=True)
    monitor = Monitor(interval=0.5, geo=False, dns=False, demo=True)
    app = NetMonGuruApp(monitor,
                        rules_path=Path(tempfile.mkdtemp()) / "r.json")
    checks = []

    async with app.run_test(size=(160, 46)) as pilot:
        await pilot.pause(2.5)                       # a few demo samples
        await pilot.press("3")
        await pilot.pause(0.8)
        table = app.query_one("#bw-table", DataTable)
        graph = app.query_one("#bw-graph", BandwidthGraph)

        # --- per-process is the default view --------------------------------
        assert app.bw_view == "processes"
        assert app.bw_keys[0] == ALL_KEY
        names = {app.snapshot.procs[k].name for k in app.bw_keys[1:]}
        assert {"firefox", "ssh", "git"} <= names, names
        rates = [app.snapshot.procs[k].in_rate + app.snapshot.procs[k].out_rate
                 for k in app.bw_keys[1:]]
        assert rates == sorted(rates, reverse=True), "not sorted by traffic"
        assert any(r > 0 for r in rates), "demo traffic is flat"
        checks.append(f"Bandwidth opens per process ({len(names)} processes, "
                      "busiest first)")

        # --- the graph follows the selected row --------------------------------
        monitor.paused = True
        await pilot.pause(0.6)
        assert graph.title == "all traffic", graph.title
        table.move_cursor(row=1)
        await pilot.pause(0.4)
        first = app.snapshot.procs[app.bw_keys[1]]
        assert graph.title.startswith(first.name), graph.title
        assert any(v > 0 for v in graph.down), "process history is empty"
        checks.append(f"graph follows the cursor ({graph.title})")
        app.save_screenshot(str(out / "3-bandwidth.svg"))

        # --- enter: drill down into the process' connections ---------------------
        target = next(i for i, k in enumerate(app.bw_keys)
                      if k != ALL_KEY
                      and app.snapshot.procs[k].name == "firefox")
        table.move_cursor(row=target)
        await pilot.pause(0.3)
        await pilot.press("enter")
        await pilot.pause(0.5)
        assert app.bw_view == "connections"
        assert app.bw_process == (501, "firefox"), app.bw_process
        flows = [app.snapshot.flows[k] for k in app.bw_keys[1:]]
        assert flows and all(f.pname == "firefox" for f in flows), flows
        assert graph.title == "all connections of firefox", graph.title
        table.move_cursor(row=1)
        await pilot.pause(0.4)
        assert "→" in graph.title and "firefox" in graph.title, graph.title
        checks.append(f"enter filters to the process: {len(flows)} firefox "
                      "connection(s), graph per connection")
        app.save_screenshot(str(out / "3b-bandwidth-connections.svg"))

        # enter on a connection opens it in the Connections pane
        wanted = app.snapshot.flows[app.bw_keys[1]]
        await pilot.press("enter")
        await pilot.pause(0.5)
        assert app.query_one("#tabs").active == "tab-conn"
        assert app.detail_open and app.detail_conn.rport == wanted.rport \
            and app.detail_conn.raddr == wanted.raddr
        checks.append("enter on a connection opens its details")
        await pilot.press("escape")                  # close the detail panel
        await pilot.press("3")
        await pilot.pause(0.4)

        # esc leaves the drill-down
        await pilot.press("escape")
        await pilot.pause(0.4)
        assert app.bw_process is None and app.bw_view == "processes"
        checks.append("esc returns to all processes")

        # --- b cycles views; / filters rows ------------------------------------------
        await pilot.press("b")
        await pilot.pause(0.4)
        assert app.bw_view == "connections" and app.bw_process is None
        all_flows = len(app.bw_keys) - 1
        await pilot.press("slash")
        for ch in "github":
            await pilot.press(ch)
        await pilot.pause(0.4)
        shown = [app.snapshot.flows[k] for k in app.bw_keys[1:]]
        assert shown and len(shown) < all_flows
        assert all(f.pname == "git" for f in shown), shown   # host github.com
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert len(app.bw_keys) - 1 == all_flows
        checks.append("/ filters by process, address or hostname")

        await pilot.press("b")
        await pilot.pause(0.4)
        assert app.bw_view == "interfaces"
        assert table.row_count >= 1
        await pilot.press("b")
        await pilot.pause(0.4)
        assert app.bw_view == "processes"
        checks.append("b cycles processes → connections → interfaces")
        assert "render error" not in str(app.query_one("#summary").render())

    # --bw-view picks the starting view
    app2 = NetMonGuruApp(Monitor(interval=0.5, geo=False, dns=False,
                                 demo=True), bw_view="interfaces",
                         rules_path=Path(tempfile.mkdtemp()) / "r.json")
    assert app2.bw_view == "interfaces"
    monitor.stop()
    for line in checks:
        print("  ok -", line)
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
