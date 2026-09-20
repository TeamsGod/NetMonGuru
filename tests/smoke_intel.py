"""Headless UI test for threat intelligence: TI column, pinning of malicious
peers, manual investigation, the Intel pane and report export.  All upstream
services are replaced by canned answers (tests/ti_fakes.py)."""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from textual.widgets import DataTable, Input                     # noqa: E402

from netmonguru.core.models import Connection, Snapshot          # noqa: E402
from netmonguru.core.monitor import Monitor                      # noqa: E402
from netmonguru.core.ti import ThreatIntel                       # noqa: E402
from netmonguru.core.ti_feeds import FeedStore                   # noqa: E402
from netmonguru.ui.app import NetMonGuruApp                      # noqa: E402
from tests import ti_fakes as F                                  # noqa: E402


def conn(i, raddr, pname="app", rport=443, pid=None):
    return Connection(proto="TCP", family="IPv4", laddr="192.168.1.24",
                      lport=41000 + i, raddr=raddr, rport=rport,
                      state="ESTABLISHED", pid=pid, pname=pname)


async def wait_for(pilot, predicate, seconds=20.0):
    end = time.time() + seconds
    while time.time() < end:
        if predicate():
            return True
        await pilot.pause(0.1)
    return False


async def main() -> int:
    out = Path("screenshots")
    out.mkdir(exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    feeds = FeedStore(keys=F.KEYS, directory=tmp / "feeds", fetch=F.fetch)
    feeds.update_due(force=True)
    engine = ThreatIntel(keys=F.KEYS, http=F.http, feed_store=feeds,
                         state_dir=tmp, auto_pause=0.0)
    monitor = Monitor(interval=0.5, geo=False, dns=False, demo=True,
                      per_process_bw=False, ti_engine=engine)
    monitor.paused = True
    app = NetMonGuruApp(monitor, rules_path=tmp / "rules.json")
    checks = []

    conns = [conn(i, f"198.51.100.{i}") for i in range(30)] + [
        conn(90, F.GOOD, "firefox"),
        conn(91, F.BAD, "updater", pid=os.getpid()),
        conn(92, "45.9.148.77", "curl"),
    ]

    def publish():
        engine.submit(conns)
        verdicts, procsig = engine.snapshot()
        monitor.snapshot = Snapshot(connections=list(conns), ti=verdicts,
                                    procsig=procsig, backend="demo",
                                    ts=time.time())
        app.tick()

    async with app.run_test(size=(170, 50)) as pilot:
        engine.start()
        publish()
        await pilot.pause(0.3)

        # --- feeds give an immediate verdict; malicious peer leads ----------
        assert app.rows[0].raddr == F.BAD, app.rows[0].raddr
        table = app.query_one("#conn-table", DataTable)
        assert "C2 Emotet" in table.get_row_at(0)[2].plain
        drop_row = next(i for i, c in enumerate(app.rows)
                        if c.raddr == "45.9.148.77")
        assert "DROP" in table.get_row_at(drop_row)[2].plain
        checks.append("local feeds label connections; malicious peer is "
                      "pinned first")

        # --- automatic AbuseIPDB fills in the rest ---------------------------
        ok = await wait_for(pilot, lambda: all(
            engine.verdicts[ip].abuse_state == "ok"
            for ip in (F.GOOD, F.BAD)), 60)
        assert ok, "auto check never completed"
        publish()
        await pilot.pause(0.3)
        good_row = next(i for i, c in enumerate(app.rows)
                        if c.raddr == F.GOOD)
        assert table.get_row_at(good_row)[2].plain.strip() == "ok"
        assert "abuse 100%" in table.get_row_at(0)[2].plain
        summary = str(app.query_one("#summary").render())
        assert "MALICIOUS PEER" in summary, summary
        checks.append("automatic AbuseIPDB check updates the TI column and "
                      "the summary bar warns")
        app.save_screenshot(str(out / "1-connections.svg"))

        # --- i: investigate ---------------------------------------------------
        table.move_cursor(row=0)
        await pilot.pause(0.2)
        await pilot.press("i")
        await pilot.pause(0.3)
        assert app.query_one("#tabs").active == "tab-intel"
        assert engine.reports and engine.reports[0].ip == F.BAD
        report = engine.reports[0]
        assert await wait_for(pilot, lambda: report.done, 40), \
            f"still pending: {[s.source for s in report.sources.values() if s.status == 'pending']}"
        app.tick()
        await pilot.pause(0.3)
        level, reasons = report.overall()
        assert level == "malicious", (level, reasons)
        assert report.process is not None and report.process.sha256, \
            "process was not hashed"
        assert report.sources["vt-file"].status == "none"
        text = app._report_text(report).plain
        for needle in ("MALICIOUS", "C2 Emotet", "AbuseIPDB", "VirusTotal",
                       "ThreatFox", "OTX", "GreyNoise", "RDAP",
                       "abuse@example.net", "Shodan InternetDB", "sha-256",
                       "LOCAL CONTEXT", "updater"):
            assert needle in text, f"report lacks {needle!r}"
        checks.append(f"i runs {len(report.sources)} sources + process "
                      "checks and renders the report")
        app.save_screenshot(str(out / "7-intel.svg"))

        # --- manual address entry ----------------------------------------------
        await pilot.press("i")                 # in the Intel pane: focus input
        await pilot.pause(0.2)
        assert isinstance(app.focused, Input)
        for ch in F.GOOD:
            await pilot.press("full_stop" if ch == "." else ch)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert engine.reports[0].ip == F.GOOD, engine.reports[0].ip
        second = engine.reports[0]
        assert await wait_for(pilot, lambda: second.done, 40)
        assert second.overall()[0] == "clean", second.overall()
        assert app.query_one("#tabs").active == "tab-intel"
        checks.append("typed address is investigated; benign address comes "
                      "back CLEAN")

        # junk is refused without creating a report
        n = len(engine.reports)
        app._investigate_text("not-an-ip; rm -rf")
        assert len(engine.reports) == n

        # --- export ----------------------------------------------------------------
        os.environ["HOME"] = str(tmp)
        app.query_one("#intel-list", DataTable).focus()
        await pilot.pause(0.1)
        await pilot.press("w")
        await pilot.pause(0.3)
        files = sorted((tmp / "netmonguru-reports").glob("*"))
        assert [f.suffix for f in files] == [".json", ".md"], files
        checks.append("w writes the report as Markdown + JSON")

        # --- every other pane still opens ---------------------------------------------
        for key, tab in (("1", "tab-conn"), ("6", "tab-mon"),
                         ("7", "tab-intel"), ("1", "tab-conn")):
            await pilot.press(key)
            await pilot.pause(0.2)
            assert app.query_one("#tabs").active == tab, tab
        assert "render error" not in str(app.query_one("#summary").render())

    monitor.stop()
    for line in checks:
        print("  ok -", line)
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
