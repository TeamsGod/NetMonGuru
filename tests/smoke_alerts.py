"""Headless UI test for 1.6: alerts, journal/History, blocklist, help screen,
throughput columns, DNS threat labels - driven through the real sampler hook
(`Monitor._after_sample`) with canned threat intelligence."""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from textual.widgets import DataTable                            # noqa: E402

from netmonguru.core.alerts import AlertEngine, Baseline         # noqa: E402
from netmonguru.core.bandwidth import flow_key                   # noqa: E402
from netmonguru.core.config import Config                        # noqa: E402
from netmonguru.core.dnswatch import DNSRecord                   # noqa: E402
from netmonguru.core.journal import Journal                      # noqa: E402
from netmonguru.core.killer import BlockList, PfCutter           # noqa: E402
from netmonguru.core.models import (Connection, FlowNet, GeoInfo,  # noqa: E402
                                    Snapshot)
from netmonguru.core.monitor import Monitor                      # noqa: E402
from netmonguru.core.ti import ThreatIntel                       # noqa: E402
from netmonguru.core.ti_feeds import FeedStore                   # noqa: E402
from netmonguru.ui.app import NetMonGuruApp                      # noqa: E402
from tests import ti_fakes as F                                  # noqa: E402


def conn(i, raddr, pname, pid=None, rport=443):
    return Connection(proto="TCP", family="IPv4", laddr="192.168.1.24",
                      lport=43000 + i, raddr=raddr, rport=rport,
                      state="ESTABLISHED", pid=pid, pname=pname)


async def main() -> int:
    out = Path("screenshots")
    out.mkdir(exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    feeds = FeedStore(keys=F.KEYS, directory=tmp / "feeds", fetch=F.fetch)
    feeds.update_due(force=True)
    engine = ThreatIntel(keys={}, http=F.http, feed_store=feeds,
                         state_dir=tmp, auto=False)
    pf_calls = []

    def fake_pf(cmd, stdin=""):
        pf_calls.append((cmd[1:], stdin))
        return 0, "Token : 99" if cmd[1] == "-E" else ""

    notes = []
    alerts = AlertEngine({"notify": True}, Baseline(persist=False,
                                                    learn_days=0),
                         notifier=lambda t, m: notes.append(m) or True)
    monitor = Monitor(interval=0.5, geo=False, dns=False, demo=True,
                      ti_engine=engine, config=Config(),
                      journal=Journal(tmp / "journal.db", flush_every=0),
                      alerts=alerts,
                      cutter=PfCutter(runner=fake_pf, is_root=True,
                                      pfctl="/sbin/pfctl"),
                      blocklist=BlockList(tmp / "blocklist.json"))
    monitor.paused = True
    app = NetMonGuruApp(monitor, rules_path=tmp / "rules.json")
    checks = []

    geo = {F.BAD: GeoInfo(F.BAD, city="Berlin", country="Germany",
                          country_code="DE", org="Example Hosting"),
           F.GOOD: GeoInfo(F.GOOD, city="Mountain View",
                           country="United States", country_code="US",
                           org="Google LLC")}

    def sample(conns, rates=None):
        """What the sampler thread does, minus the collectors."""
        names = monitor.dns.cache.names()
        engine.submit(conns, names)
        verdicts, procsig = engine.snapshot()
        flows = {}
        for c in conns:
            if c.raddr:
                key = flow_key(c.proto, c.laddr, c.lport, c.raddr, c.rport)
                r_in, r_out = (rates or {}).get(c.lport, (0.0, 0.0))
                flows[key] = FlowNet(key, c.proto, c.family, c.laddr, c.lport,
                                     c.raddr, c.rport, c.pid, c.pname,
                                     bytes_in=int(r_in * 10),
                                     bytes_out=int(r_out * 10),
                                     in_rate=r_in, out_rate=r_out)
        monitor.procnet.flows = flows
        monitor._after_sample(conns, verdicts, procsig, geo, {}, names)
        monitor.snapshot = Snapshot(connections=list(conns), ti=verdicts,
                                    procsig=procsig, geo=geo, flows=flows,
                                    backend="demo", ts=time.time())
        app.tick()

    base = [conn(1, F.GOOD, "firefox", 501), conn(2, "8.8.8.8", "firefox", 501)]

    async with app.run_test(size=(180, 50)) as pilot:
        sample(base)
        await pilot.pause(0.3)
        assert alerts.snapshot() == [], "the first sample must be silent"

        # --- a bad peer, a new program and a bad DNS name appear ------------
        monitor.dns.cache.add(DNSRecord(ts=time.time(), name="cdn.bad.test",
                                        answers=["93.184.216.34"],
                                        source="log", client="updater"))
        now_conns = base + [conn(3, F.BAD, "updater", 777),
                            conn(4, "93.184.216.34", "updater", 777)]
        sample(now_conns, rates={43003: (2.5e6, 4e5)})
        await pilot.pause(0.3)
        kinds = sorted(a.kind for a in alerts.snapshot())
        assert kinds == ["bad-domain", "new-country", "new-process", "threat",
                         "threat"], kinds
        assert any("C2 Emotet" in n for n in notes), notes
        summary = str(app.query_one("#summary").render())
        assert "5 alert(s)" in summary, summary
        checks.append(f"sampler raises {kinds} and notifies")

        # the address behind the bad name is flagged although its IP is clean
        table = app.query_one("#conn-table", DataTable)
        row = next(i for i, c in enumerate(app.rows)
                   if c.raddr == "93.184.216.34")
        assert "MALWARE-HOST" in table.get_row_at(row)[2].plain
        # live throughput of a single connection in the Connections pane
        bad_row = next(i for i, c in enumerate(app.rows) if c.raddr == F.BAD)
        assert "MB/s" in table.get_row_at(bad_row)[8].plain, \
            table.get_row_at(bad_row)[8].plain
        checks.append("domain IOC flags a clean IP; ▼/▲ columns show "
                      "per-connection throughput")
        app.save_screenshot(str(out / "1-connections.svg"))

        # --- DNS pane shows the label ------------------------------------------
        await pilot.press("5")
        await pilot.pause(0.4)
        live = app.query_one("#dns-live", DataTable)
        assert "MALWARE-HOST" in live.get_row_at(0)[4].plain
        checks.append("DNS pane labels the malicious name")

        # --- Alerts pane -----------------------------------------------------------
        await pilot.press("8")
        await pilot.pause(0.4)
        assert app.query_one("#tabs").active == "tab-alerts"
        atable = app.query_one("#alert-table", DataTable)
        assert atable.row_count == 5
        status = str(app.query_one("#alert-status").render())
        assert "baseline: active" in status and "journal: on" in status, status
        app.save_screenshot(str(out / "8-alerts.svg"))

        # enter on the threat alert jumps to the live connection
        idx = next(i for i, a in enumerate(app.alert_rows)
                   if a.kind == "threat" and a.raddr == F.BAD)
        atable.move_cursor(row=idx)
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.4)
        assert app.query_one("#tabs").active == "tab-conn"
        assert app.detail_open and app.detail_conn.raddr == F.BAD
        checks.append("enter on an alert opens the connection")

        # --- k → b: block the host permanently --------------------------------------
        await pilot.press("k")
        await pilot.pause(0.3)
        assert type(app.screen).__name__ == "KillScreen"
        await pilot.press("b")
        await pilot.pause(0.4)
        assert monitor.blocklist.ips() == [F.BAD]
        load = [c for c in pf_calls if "-f" in c[0]][-1][1]
        assert f"table <nmg_block> persist {{ {F.BAD} }}" in load, load
        assert BlockList(tmp / "blocklist.json").ips() == [F.BAD]
        checks.append("k → b puts the host on the persisted blocklist and "
                      "loads the pf table")
        await pilot.press("escape")

        await pilot.press("8")
        await pilot.pause(0.4)
        btable = app.query_one("#block-table", DataTable)
        assert btable.row_count == 1
        assert "enforced" in btable.get_row_at(0)[5].plain
        assert "C2 Emotet" in btable.get_row_at(0)[2].plain
        btable.focus()
        await pilot.pause(0.1)
        await pilot.press("d")
        await pilot.pause(0.4)
        assert monitor.blocklist.ips() == []
        assert "nmg_block" not in [c for c in pf_calls if "-f" in c[0]][-1][1]
        checks.append("d in the blocked-hosts table removes the block")

        await pilot.press("A")
        await pilot.pause(0.2)
        assert alerts.unacknowledged == 0
        assert "alert(s)" not in str(app.query_one("#summary").render())

        # --- History: the closed connection is still there ---------------------------
        sample(base)                                   # updater's sockets close
        await pilot.press("9")
        await pilot.pause(0.5)
        assert app.query_one("#tabs").active == "tab-hist"
        assert len(app.hist_rows) == 4, len(app.hist_rows)
        gone = next(r for r in app.hist_rows if r["raddr"] == F.BAD)
        assert gone["closed"] == 1 and gone["ti_label"].startswith("C2 Emotet")
        assert gone["country"] == "DE" and gone["bytes_in"] > 0
        app.save_screenshot(str(out / "9-history.svg"))

        await pilot.press("exclamation_mark")          # flagged only
        await pilot.pause(0.4)
        assert {r["raddr"] for r in app.hist_rows} == {F.BAD, "93.184.216.34"}
        await pilot.press("exclamation_mark")
        await pilot.press("slash")
        for ch in "updater":
            await pilot.press(ch)
        await pilot.pause(0.4)
        assert len(app.hist_rows) == 2
        await pilot.press("escape")
        await pilot.pause(0.3)
        await pilot.press("left_square_bracket")
        await pilot.pause(0.3)
        assert app.hist_window == 0 and len(app.hist_rows) == 4
        checks.append("History keeps closed connections with TI, country and "
                      "bytes; ! [ ] and / filter it")

        # i on a history row investigates that address
        htable = app.query_one("#hist-table", DataTable)
        htable.focus()
        htable.move_cursor(row=next(i for i, r in enumerate(app.hist_rows)
                                    if r["raddr"] == F.BAD))
        await pilot.pause(0.2)
        await pilot.press("i")
        await pilot.pause(0.4)
        assert engine.reports and engine.reports[0].ip == F.BAD
        assert app.query_one("#tabs").active == "tab-intel"
        checks.append("i investigates an address straight from History")

        # journal export
        target = tmp / "export.csv"
        n = monitor.journal.export(target, "connections")
        assert n == 4 and F.BAD in target.read_text()
        assert monitor.journal.export(tmp / "a.json", "alerts") == 5
        checks.append("journal exports connections and alerts")

        # --- help --------------------------------------------------------------------
        await pilot.press("9")
        await pilot.press("question_mark")
        await pilot.pause(0.3)
        assert type(app.screen).__name__ == "HelpScreen"
        text = str(app.screen.query_one("#help-box").render())
        assert "HISTORY" in text and "flagged" in text and "EVERYWHERE" in text
        app.save_screenshot(str(out / "0-help.svg"))
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert type(app.screen).__name__ != "HelpScreen"
        checks.append("? shows the keys of the current pane")

        for key, tab in (("1", "tab-conn"), ("2", "tab-map"), ("5", "tab-dns"),
                         ("8", "tab-alerts"), ("9", "tab-hist")):
            await pilot.press(key)
            await pilot.pause(0.25)
            assert app.query_one("#tabs").active == tab, tab
        assert "render error" not in str(app.query_one("#summary").render())

    monitor.stop()
    assert pf_calls[-1][0] == ["-X", "99"], "pf token must be released"
    for line in checks:
        print("  ok -", line)
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
