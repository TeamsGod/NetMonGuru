"""Headless UI test for 1.2: stable scrolling, new-on-top ordering, the
connection detail panel, marking, and the Monitor pane."""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from textual.widgets import DataTable                            # noqa: E402

from netmonguru.core.models import Connection, Snapshot          # noqa: E402
from netmonguru.core.monitor import Monitor                      # noqa: E402
from netmonguru.ui.app import NetMonGuruApp                      # noqa: E402


def conn(i: int, pname: str = "", raddr: str = "", rport: int = 443
         ) -> Connection:
    return Connection(proto="TCP", family="IPv4", laddr="192.168.1.24",
                      lport=40000 + i, raddr=raddr or f"198.51.100.{i % 250}",
                      rport=rport, state="ESTABLISHED", pid=1000 + i % 7,
                      pname=pname or f"app{i % 7}")


def publish(monitor: Monitor, conns) -> None:
    monitor.snapshot = Snapshot(connections=list(conns), backend="demo",
                                ts=time.time())


async def main() -> int:
    out = Path("screenshots")
    out.mkdir(exist_ok=True)
    rules_path = Path(tempfile.mkdtemp()) / "monitor.json"
    monitor = Monitor(interval=0.5, geo=False, dns=False, demo=True,
                      per_process_bw=False)
    monitor.paused = True                      # we publish snapshots by hand
    app = NetMonGuruApp(monitor, rules_path=rules_path)
    checks = []

    base = [conn(i) for i in range(120)]

    async with app.run_test(size=(160, 48)) as pilot:
        publish(monitor, base)
        app.tick()
        await pilot.pause(0.3)
        table = app.query_one("#conn-table", DataTable)
        assert table.row_count == 120

        # from here on the table must never be cleared again
        def boom(*a, **k):
            raise AssertionError("conn-table was cleared - scrolling resets")
        table.clear = boom

        # --- scroll position and cursor survive refreshes -----------------
        table.move_cursor(row=60)
        await pilot.pause(0.2)
        table.scroll_to(y=50, animate=False, force=True)
        await pilot.pause(0.2)
        assert table.scroll_y == 50, table.scroll_y
        cursor_key = app.row_keys[60]

        publish(monitor, base)                 # same sockets, new sample
        app.tick()
        await pilot.pause(0.3)
        assert table.scroll_y == 50, f"scroll jumped to {table.scroll_y}"
        assert table.cursor_row == 60
        checks.append("refresh keeps scroll position and cursor")

        # the user scrolls away from the cursor with the wheel: stay there
        table.scroll_to(y=5, animate=False, force=True)
        await pilot.pause(0.2)
        publish(monitor, base)
        app.tick()
        await pilot.pause(0.3)
        assert table.scroll_y == 5, \
            f"view yanked back to the cursor ({table.scroll_y})"
        checks.append("view is not pulled back to the cursor on refresh")
        table.scroll_to(y=50, animate=False, force=True)
        await pilot.pause(0.2)

        # --- new sockets land on top, the viewport does not move ----------
        newcomers = [conn(500 + i, pname="curl", raddr="203.0.113.77")
                     for i in range(3)]
        publish(monitor, base[:40] + newcomers + base[40:])
        app.tick()
        await pilot.pause(0.4)
        assert [c.pname for c in app.rows[:3]] == ["curl"] * 3, \
            [c.pname for c in app.rows[:5]]
        assert app.rows[0].lport == 40502, "newest socket is not first"
        assert app.row_keys[table.cursor_row] == cursor_key, \
            "cursor did not follow its connection"
        assert table.cursor_row == 63
        assert table.scroll_y == 53, \
            f"content under the eyes moved (scroll_y={table.scroll_y})"
        first_cell = table.get_row_at(0)[6]
        assert first_cell.plain == "curl", first_cell.plain
        checks.append("new connections are inserted at the top; cursor and "
                      "viewport follow the content")

        # pinned on top under every sort mode
        for _ in range(3):
            await pilot.press("s")
            await pilot.pause(0.1)
            assert all(c.pname == "curl" for c in app.rows[:3]), \
                f"sort {app.sort_idx} lost the new rows"
        while app.sort_idx:
            await pilot.press("s")
        checks.append("new connections stay pinned on top in every sort mode")

        # at the top of the list the new rows must scroll into view
        table.move_cursor(row=0)
        await pilot.pause(0.2)
        late = [conn(600, pname="nc", raddr="203.0.113.99", rport=4444)]
        publish(monitor, base + newcomers + late)
        app.tick()
        await pilot.pause(0.4)
        assert app.rows[0].pname == "nc"
        assert table.scroll_y == 0, table.scroll_y
        checks.append("at the top of the list new rows are visible at once")
        app.save_screenshot(str(out / "1-connections.svg"))

        # --- click opens the detail panel ---------------------------------
        assert not app.detail_open
        await pilot.click("#conn-table", offset=(20, 3))   # header + 2 rows
        await pilot.pause(0.4)
        assert app.detail_open, "single click did not open the detail panel"
        assert app.detail_conn is app.rows[table.cursor_row]
        assert table.cursor_row == 2
        rel = [r for r, _ in app.detail_related]
        assert rel and rel[0] == "owner", rel
        assert app.detail_conn.pname == "curl"
        socks = app.query_one("#cd-socks", DataTable)
        assert socks.row_count == sum(
            1 for c in app.rows if c.pid == app.detail_conn.pid)
        checks.append(f"click expands details with {len(rel)} related "
                      f"process(es) and {socks.row_count} sockets")
        app.save_screenshot(str(out / "1b-connection-detail.svg"))

        # the panel follows the cursor
        await pilot.press("down")
        await pilot.pause(0.3)
        assert app.detail_conn is app.rows[table.cursor_row]

        # g jumps to the owning process
        owner_pid = app.detail_conn.pid
        await pilot.press("g")
        await pilot.pause(0.4)
        assert app.query_one("#tabs").active == "tab-proc"
        ptable = app.query_one("#proc-table", DataTable)
        assert app.proc_rows[ptable.cursor_row].pid == owner_pid
        checks.append("g opens the Processes pane on the owning process")
        await pilot.press("1")
        await pilot.pause(0.3)
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert not app.detail_open, "escape did not close the panel"

        # --- mark + monitor -----------------------------------------------
        table.move_cursor(row=0)
        await pilot.pause(0.2)
        await pilot.press("m", "m")            # nc + first curl (auto-advance)
        await pilot.pause(0.2)
        assert len(app.marked) == 2
        await pilot.press("f")
        await pilot.pause(0.4)
        assert app.query_one("#tabs").active == "tab-mon"
        assert len(app.watchlist) == 2, len(app.watchlist)
        # rule = process + remote endpoint, so all three curl sockets match
        live = [e for e in app.mon_rows if not e.closed]
        assert sorted(e.conn.pname for e in live) == \
            ["curl", "curl", "curl", "nc"], [e.conn.pname for e in live]
        assert not app.marked
        checks.append("f turns marked connections into rules and opens the "
                      "Monitor pane")

        # add more later
        await pilot.press("1")
        await pilot.pause(0.3)
        table.move_cursor(row=30)
        await pilot.pause(0.2)
        extra = app.rows[30]
        await pilot.press("f")                 # nothing marked -> cursor row
        await pilot.pause(0.4)
        assert len(app.watchlist) == 3
        assert any(e.conn is extra or e.conn.key == extra.key
                   for e in app.mon_rows)
        checks.append("more connections can be added to the monitor later")

        # a monitored socket that closes stays as history; a reconnect on a
        # new local port is picked up by the same rule and shown on top
        reconnect = conn(700, pname="nc", raddr="203.0.113.99", rport=4444)
        publish(monitor, base + newcomers + [reconnect])
        app.tick()
        await pilot.pause(0.4)
        closed = [e for e in app.mon_rows if e.closed]
        assert [e.conn.lport for e in closed] == [40600]
        assert app.mon_rows[0].conn.lport == 40700, "reconnect not on top"
        checks.append("closed sockets are kept as history; reconnects match "
                      "the same rule and appear first")
        app.save_screenshot(str(out / "6-monitor.svg"))

        # rules persist
        from netmonguru.core.watch import WatchList
        assert len(WatchList(rules_path)) == 3
        checks.append("rules are persisted to disk")

        # delete a rule
        app.query_one("#mon-rules", DataTable).focus()
        await pilot.pause(0.1)
        await pilot.press("d")
        await pilot.pause(0.3)
        assert len(app.watchlist) == 2
        assert not any(e.conn.pname == "nc" for e in app.mon_rows)
        checks.append("d removes a rule and its traffic")

        # enter on monitored traffic jumps back to the connection
        mt = app.query_one("#mon-table", DataTable)
        mt.focus()
        mt.move_cursor(row=0)
        await pilot.pause(0.2)
        wanted = app.mon_rows[0].key
        await pilot.press("enter")
        await pilot.pause(0.4)
        assert app.query_one("#tabs").active == "tab-conn"
        assert app.row_keys[table.cursor_row] == wanted
        assert app.detail_open
        checks.append("enter in the Monitor pane opens the connection")

        # --- k: end a connection -------------------------------------------
        import subprocess
        victim = subprocess.Popen([sys.executable, "-c",
                                   "import time; time.sleep(60)"])
        try:
            doomed = Connection(proto="TCP", family="IPv4",
                                laddr="192.168.1.24", lport=45555,
                                raddr="203.0.113.200", rport=443,
                                state="ESTABLISHED", pid=victim.pid,
                                pname="victim")
            app.sort_idx = 0
            publish(monitor, base + [doomed])
            app.tick()
            await pilot.pause(0.4)
            assert app.rows[0].pname == "victim"
            table.focus()
            table.move_cursor(row=0)
            await pilot.pause(0.2)

            await pilot.press("k")
            await pilot.pause(0.3)
            assert type(app.screen).__name__ == "KillScreen"
            app.save_screenshot(str(out / "1c-kill-dialog.svg"))
            await pilot.press("escape")
            await pilot.pause(0.2)
            assert type(app.screen).__name__ != "KillScreen"
            assert victim.poll() is None, "cancel must not signal anything"

            # not root here -> the pf option is refused, nothing happens
            if not app.cutter.available:
                await pilot.press("k")
                await pilot.pause(0.2)
                await pilot.press("c")
                await pilot.pause(0.2)
                assert type(app.screen).__name__ == "KillScreen"
                await pilot.press("escape")
                await pilot.pause(0.2)

            await pilot.press("k")
            await pilot.pause(0.2)
            await pilot.press("t")
            await pilot.pause(0.2)
            assert victim.wait(timeout=5) is not None
            assert "SIGTERM" in app.flash or "terminated" in app.flash, \
                app.flash
            checks.append("k opens a confirmation; esc cancels; t terminates "
                          "the owning process")
        finally:
            if victim.poll() is None:
                victim.kill()

    monitor.stop()
    for line in checks:
        print("  ok -", line)
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
