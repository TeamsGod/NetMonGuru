"""Command line entry point."""

from __future__ import annotations

import argparse
import platform
import sys

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netmonguru",
        description="btop-style network monitor for macOS: live socket table, "
                    "geographic map of remote peers, and bandwidth graphs.")
    p.add_argument("-i", "--interval", type=float, default=None,
                   metavar="SEC", help="sampling interval (default: 2.0, or "
                                       "general.interval in config.toml)")
    p.add_argument("--no-geo", action="store_true",
                   help="never send addresses to a geolocation service")
    p.add_argument("--no-dns", action="store_true",
                   help="skip reverse DNS lookups")
    p.add_argument("--no-netstat", action="store_true",
                   help="do not merge the system-wide netstat socket table")
    p.add_argument("--no-proc-bw", action="store_true",
                   help="disable per-process bandwidth (nettop)")
    p.add_argument("--mmdb", default="", metavar="PATH",
                   help="use an offline MaxMind GeoLite2-City .mmdb instead "
                        "of the online lookup service")
    p.add_argument("--mmdb-asn", default="", metavar="PATH",
                   help="optional GeoLite2-ASN .mmdb to accompany --mmdb")
    p.add_argument("--dns-capture", default="auto",
                   choices=["auto", "etw", "cache", "passive", "off"],
                   help="real-time DNS source: auto (default: the DNS "
                        "Client event log when it is enabled, else cache "
                        "polling), etw (event log - names the requesting "
                        "process; enabled for you when elevated), cache "
                        "(Get-DnsClientCache, no admin), passive (reverse "
                        "lookups only), off")
    p.add_argument("--dns-window", type=int, default=900, metavar="SEC",
                   help="how long observed DNS answers are kept "
                        "(default: 900 = 15 minutes)")
    p.add_argument("--dns-iface", default="", metavar="IF",
                   help="unused on Windows (kept for command-line "
                        "compatibility)")
    p.add_argument("--bw-view", default=None,
                   choices=["processes", "connections", "interfaces"],
                   help="what the Bandwidth pane opens with "
                        "(default: processes)")
    p.add_argument("--no-ti", action="store_true",
                   help="disable threat intelligence completely (no feed "
                        "downloads, no lookups)")
    p.add_argument("--no-ti-auto", action="store_true",
                   help="keep the local feeds and manual investigations but "
                        "never send addresses to AbuseIPDB automatically")
    p.add_argument("--doctor", action="store_true",
                   help="check every Windows backend (admin rights, sockets, "
                        "TCP statistics, PowerShell, Authenticode, DNS "
                        "sources, config folders) and exit")
    p.add_argument("--record", action="store_true",
                   help="headless: no UI, just sample, journal and alert "
                        "(alerts are printed; stop with Ctrl-C). Suitable "
                        "for a scheduled task - see --print-task")
    p.add_argument("--no-journal", action="store_true",
                   help="do not write the on-disk journal")
    p.add_argument("--no-alerts", action="store_true",
                   help="disable alerting")
    p.add_argument("--export", metavar="FILE",
                   help="export the journal to FILE (.csv or .json) and exit")
    p.add_argument("--what", default="connections",
                   choices=["connections", "alerts", "dns"],
                   help="what --export writes (default: connections)")
    p.add_argument("--since", default="24h", metavar="SPAN",
                   help="time span for --export: 90m, 24h (default), 7d, all")
    p.add_argument("--print-task", action="store_true",
                   help="print the command that registers --record as a "
                        "scheduled task running at boot, and exit")
    p.add_argument("--reset-baseline", action="store_true",
                   help="forget the learned baseline and start learning again")
    p.add_argument("--demo", action="store_true",
                   help="synthetic connection data (useful off macOS)")
    p.add_argument("--dump", action="store_true",
                   help="print one plain-text sample and exit (no TUI)")
    p.add_argument("-V", "--version", action="version",
                   version=f"netmonguru {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.doctor:
        from .doctor import run as run_doctor
        return run_doctor()

    if args.doctor:
        from .doctor import run as run_doctor
        return run_doctor()
    if args.print_task:
        print(task_instructions())
        return 0

    from .core.config import Config
    from .core.journal import Journal, parse_since

    config = Config.load(create=not args.demo)
    for warning in config.warnings:
        print(f"config: {warning}", file=sys.stderr)

    if args.export:
        try:
            since = parse_since(args.since)
            n = Journal(retention_days=0).export(args.export, args.what,
                                                 since)
        except Exception as exc:                        # noqa: BLE001
            print(f"export failed: {exc}", file=sys.stderr)
            return 1
        print(f"{n} {args.what} row(s) since {args.since} → {args.export}")
        return 0

    if args.reset_baseline:
        from .core.alerts import Baseline
        Baseline().reset()
        print("baseline cleared - learning starts now")

    if args.interval is None:
        args.interval = float(config.get("general", "interval"))
    if args.bw_view is None:
        args.bw_view = str(config.get("general", "bw_view"))
    if args.no_journal:
        config.section("journal")["enabled"] = False
    if args.no_alerts:
        config.section("alerts")["enabled"] = False

    from .core.monitor import Monitor

    monitor = Monitor(config=config,
                      interval=args.interval, geo=not args.no_geo,
                      dns=not args.no_dns, mmdb=args.mmdb,
                      mmdb_asn=args.mmdb_asn,
                      per_process_bw=not args.no_proc_bw,
                      use_netstat=not args.no_netstat,
                      dns_capture=args.dns_capture,
                      dns_window=max(60, args.dns_window),
                      dns_iface=args.dns_iface,
                      demo=args.demo,
                      ti=not args.no_ti, ti_auto=not args.no_ti_auto)

    if args.dump:
        return _dump(monitor)

    if platform.system() != "Windows" and not args.demo:
        print("this is the Windows build of NetMonGuru; on other systems "
              "only parts of the data will be available (try --demo).",
              file=sys.stderr)

    if args.record:
        return _record(monitor)

    from .ui.app import NetMonGuruApp

    app = NetMonGuruApp(monitor, bw_view=args.bw_view)
    try:
        app.run()
    finally:
        monitor.stop()
        app.cutter.release()       # never leave pf rules behind
    return 0


def _dump(monitor) -> int:
    import time

    from .core.bandwidth import human_rate

    monitor.start()
    time.sleep(min(3.0, monitor.interval + 1.0))
    snap = monitor.snapshot
    tcp, udp, est, lis = snap.counts()
    print(f"backend={snap.backend} elevated={snap.elevated} "
          f"sockets={len(snap.connections)} tcp={tcp} udp={udp} "
          f"established={est} listening={lis}")
    print(f"throughput  down={human_rate(snap.total_down)} "
          f"up={human_rate(snap.total_up)}")
    for err in snap.errors:
        print(f"warning: {err}")
    print()
    print(f"{'PROTO':<6}{'STATE':<13}{'PID':<8}{'PROCESS':<20}"
          f"{'LOCAL':<26}{'REMOTE':<26}LOCATION")
    for c in sorted(snap.connections, key=lambda c: (c.pname.lower(),
                                                     c.proto, c.lport)):
        g = snap.geo.get(c.raddr)
        loc = g.label if g else ""
        print(f"{c.proto:<6}{(c.state or '-'):<13}{str(c.pid or '-'):<8}"
              f"{c.pname[:19]:<20}{c.local[:25]:<26}{c.remote[:25]:<26}{loc}")
    monitor.stop()
    return 0


def _record(monitor) -> int:
    """Headless mode: the sampler thread does all the work (journal, alerts,
    blocking); this just prints alerts as they happen."""
    import signal
    import threading
    import time

    stop = threading.Event()

    def _alert(a) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.ts))
        print(f"{stamp} [{a.severity.upper():<6}] {a.kind:<13} {a.subject}"
              f" — {a.detail}", flush=True)

    monitor.alerts.on_alert.append(_alert)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    monitor.start()
    j = monitor.journal
    print(f"netmonguru recording — journal: "
          f"{j.path if j is not None and j.enabled else 'off'}; baseline: "
          f"{monitor.alerts.baseline.status()}; Ctrl-C to stop", flush=True)
    if monitor.block_status:
        print(monitor.block_status, flush=True)
    while not stop.is_set():
        stop.wait(1.0)
    monitor.stop()
    return 0


def task_instructions() -> str:
    import sys as _sys
    from pathlib import Path

    python = Path(_sys.executable)
    pythonw = python.with_name("pythonw.exe")
    runner = pythonw if pythonw.exists() else python
    return f"""NetMonGuru as a background recorder (journal + alerts + blocklist)

Run these from an ELEVATED prompt (the task needs "highest privileges" for
per-process bandwidth and firewall blocking):

  schtasks /Create /TN "NetMonGuru recorder" /SC ONLOGON /RL HIGHEST /F ^
    /TR "\\"{runner}\\" -m netmonguru --record"

  schtasks /Run /TN "NetMonGuru recorder"          (start it now)

Remove:

  schtasks /End /TN "NetMonGuru recorder"
  schtasks /Delete /TN "NetMonGuru recorder" /F

It runs as you, at logon, without a window (pythonw), so the journal, the
baseline and the blocklist stay in your own profile and toasts reach your
desktop. Look at what it recorded with:  netmonguru  ->  9 (History), or
  netmonguru --export night.csv --since 12h
"""
