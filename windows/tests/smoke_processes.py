"""Headless UI test for the Processes pane: TI / SIG columns, detail panel,
process investigation (binary + peers + OSINT), monitor and terminate."""

from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from textual.widgets import DataTable                            # noqa: E402

from netmonguru.core.models import Connection, Snapshot          # noqa: E402
from netmonguru.core.monitor import Monitor                      # noqa: E402
from netmonguru.core.ti import ThreatIntel                       # noqa: E402
from netmonguru.core.ti_feeds import FeedStore                   # noqa: E402
from netmonguru.ui.app import NetMonGuruApp                      # noqa: E402
from tests import ti_fakes as F                                  # noqa: E402


def conn(i, raddr, pname, pid, rport=443, state="ESTABLISHED"):
    return Connection(proto="TCP", family="IPv4", laddr="192.168.1.24",
                      lport=42000 + i, raddr=raddr, rport=rport, state=state,
                      pid=pid, pname=pname)


async def wait_for(pilot, predicate, seconds=40.0):
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
                      ti_engine=engine)
    monitor.paused = True
    app = NetMonGuruApp(monitor, rules_path=tmp / "rules.json")
    checks = []

    victim = subprocess.Popen([sys.executable, "-c",
                               "import time; time.sleep(120)"])
    conns = [conn(1, F.GOOD, "firefox", 501), conn(2, "8.8.8.8", "firefox", 501),
             conn(3, "140.82.121.4", "git", 502),
             conn(10, F.BAD, "updater", victim.pid),
             conn(11, "45.9.148.77", "updater", victim.pid),
             conn(12, F.GOOD, "updater", victim.pid),
             conn(13, "93.184.216.34", "updater", victim.pid),
             conn(14, "151.101.1.140", "updater", victim.pid),
             Connection("TCP", "IPv4", "", 8080, "", 0, "LISTEN", victim.pid,
                        "updater")]

    def publish():
        engine.submit(conns)
        verdicts, procsig = engine.snapshot()
        monitor.snapshot = Snapshot(connections=list(conns), ti=verdicts,
                                    procsig=procsig, backend="demo",
                                    ts=time.time())
        app.tick()

    try:
        async with app.run_test(size=(170, 50)) as pilot:
            engine.start()
            publish()
            await pilot.press("4")
            await pilot.pause(0.4)
            table = app.query_one("#proc-table", DataTable)

            # --- TI column; process with a malicious peer leads -----------------
            assert app.proc_rows[0].name == "updater", \
                [r.name for r in app.proc_rows]
            level, label = app._proc_ti(app.proc_rows[0])
            assert level == "malicious" and "C2 Emotet" in label, (level, label)
            assert "(+1 peer)" in label, label          # DROP peer counted too
            assert "C2 Emotet" in table.get_row_at(0)[2].plain
            checks.append(f"TI column: {label!r}; flagged process pinned first")

            await wait_for(pilot, lambda: all(
                engine.verdicts[ip].abuse_state == "ok"
                for ip in (F.GOOD, "8.8.8.8")))
            publish()
            await pilot.pause(0.3)
            ff = next(i for i, r in enumerate(app.proc_rows)
                      if r.name == "firefox")
            assert table.get_row_at(ff)[2].plain.strip() == "ok"
            checks.append("process whose peers all check out shows ok")

            # --- click opens the process detail panel -----------------------------
            assert not app.proc_detail_open
            await pilot.click("#proc-table", offset=(12, 1))
            await pilot.pause(0.4)
            assert app.proc_detail_open, "click did not open process details"
            assert app.proc_detail_row.name == "updater"
            info = str(app.query_one("#pd-info").render())
            for needle in ("executable", "python", "2 of 5 peer(s) flagged",
                           "listening on 8080", "C2 Emotet"):
                assert needle in info, f"detail lacks {needle!r}"
            assert len(app.proc_detail_conns) == 6
            assert app.proc_detail_conns[0][1].raddr == F.BAD, \
                "flagged connection is not listed first"
            checks.append("click expands process details with its connections "
                          "(flagged first)")
            app.save_screenshot(str(out / "4b-process-detail.svg"))

            # --- i: process investigation ----------------------------------------------
            await pilot.press("i")
            await pilot.pause(0.3)
            assert app.query_one("#tabs").active == "tab-intel"
            report = engine.reports[0]
            assert report.kind == "process" and report.pname == "updater"
            assert [s.ip for s in report.subs][:2] == [F.BAD, "45.9.148.77"], \
                "worst peers must be investigated first"
            assert len(report.subs) == 3 and len(report.peers) == 5
            assert await wait_for(pilot, lambda: report.done, 90), \
                "process report never finished"
            app.tick()
            await pilot.pause(0.3)
            level, reasons = report.overall()
            assert level == "malicious", (level, reasons)
            assert any(F.BAD in r for r in reasons), reasons
            assert report.process is not None and report.process.sha256
            text = app._report_text(report).plain
            for needle in ("PROCESS  updater", "sha-256", "REMOTE PEERS (5)",
                           f"PEER {F.BAD}:443", "AbuseIPDB", "Shodan InternetDB",
                           "RDAP", "command line", "3 of 5 peers"):
                assert needle in text, f"report lacks {needle!r}"
            checks.append("i builds a process report: binary hash, 5 peers, "
                          f"{len(report.subs)} full OSINT sub-reports")
            app.save_screenshot(str(out / "7b-intel-process.svg"))
            md, _ = engine.export(report, tmp / "reports")
            body = md.read_text()
            assert "## Remote peers" in body and f"## Peer {F.BAD}" in body
            assert md.name.startswith("process-updater-")
            checks.append("process report exports with peer reports embedded")

            # --- i on a connection inside the detail panel -------------------------------
            await pilot.press("4")
            await pilot.pause(0.3)
            side = app.query_one("#pd-conns", DataTable)
            side.focus()
            side.move_cursor(row=2)
            await pilot.pause(0.2)
            wanted = app.proc_detail_conns[2][1].raddr
            n = len(engine.reports)
            await pilot.press("i")
            await pilot.pause(0.3)
            assert len(engine.reports) == n + 1
            assert engine.reports[0].kind == "ip" \
                and engine.reports[0].ip == wanted
            checks.append("i on a connection of the process investigates that "
                          "address")

            # enter on a connection opens it in Connections
            await pilot.press("4")
            await pilot.pause(0.3)
            side.focus()
            side.move_cursor(row=0)
            await pilot.pause(0.2)
            await pilot.press("enter")
            await pilot.pause(0.4)
            assert app.query_one("#tabs").active == "tab-conn"
            assert app.detail_open and app.detail_conn.raddr == F.BAD
            await pilot.press("escape")

            # --- P: monitor the process ----------------------------------------------------
            await pilot.press("4")
            await pilot.pause(0.3)
            table.focus()
            table.move_cursor(row=0)
            await pilot.pause(0.2)
            await pilot.press("P")
            await pilot.pause(0.4)
            assert app.query_one("#tabs").active == "tab-mon"
            assert [r.scope for r in app.watchlist] == ["process"]
            assert sum(1 for e in app.mon_rows if not e.closed) == 6
            checks.append("P monitors the whole process")

            # --- filter, esc, terminate -------------------------------------------------------
            await pilot.press("4")
            await pilot.pause(0.3)
            await pilot.press("slash")
            for ch in "emotet":
                await pilot.press(ch)
            await pilot.pause(0.3)
            assert [r.name for r in app.proc_rows] == ["updater"]
            await pilot.press("escape")
            await pilot.pause(0.3)
            assert len(app.proc_rows) == 3
            await pilot.press("escape")
            await pilot.pause(0.2)
            assert not app.proc_detail_open
            checks.append("/ filters processes (also by TI label); esc closes")

            table.focus()
            table.move_cursor(row=0)
            await pilot.pause(0.2)
            await pilot.press("k")
            await pilot.pause(0.3)
            assert type(app.screen).__name__ == "KillScreen"
            await pilot.press("c")               # cutting needs one connection
            await pilot.pause(0.2)
            assert type(app.screen).__name__ == "KillScreen"
            await pilot.press("t")
            await pilot.pause(0.3)
            assert victim.wait(timeout=5) is not None
            checks.append("k terminates the selected process")
            assert "render error" not in str(
                app.query_one("#summary").render())
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
