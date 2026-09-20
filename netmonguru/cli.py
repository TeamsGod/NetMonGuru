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
                   choices=["auto", "log", "pcap", "passive", "off"],
                   help="real-time DNS source: auto (default), log "
                        "(mDNSResponder via `log stream`), pcap (tcpdump on "
                        "port 53, needs root), passive (reverse lookups "
                        "only), off")
    p.add_argument("--dns-window", type=int, default=900, metavar="SEC",
                   help="how long observed DNS answers are kept "
                        "(default: 900 = 15 minutes)")
    p.add_argument("--dns-iface", default="", metavar="IF",
                   help="interface for --dns-capture pcap "
                        "(default: the system's primary interface)")
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
                   help="check every macOS backend (nettop, codesign, pf, "
                        "DNS source, folders, keys, network) and exit")
    p.add_argument("--record", action="store_true",
                   help="headless: no UI, just sample, journal and alert "
                        "(alerts are printed; stop with Ctrl-C). Suitable "
                        "for a launchd service - see --print-launchd")
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
    p.add_argument("--print-launchd", action="store_true",
                   help="print a LaunchDaemon plist that runs --record at "
                        "boot, with install instructions, and exit")
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
    if args.print_launchd:
        print(launchd_plist())
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

    if platform.system() != "Darwin" and not args.demo:
        print("netmonguru targets macOS; on other systems only parts of the "
              "data will be available (try --demo).", file=sys.stderr)

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


def launchd_plist() -> str:
    import os
    import sys as _sys

    python = _sys.executable
    home = os.path.expanduser("~")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  NetMonGuru as a background recorder (journal + alerts + blocklist).

  Install:
    netmonguru --print-launchd | sudo tee /Library/LaunchDaemons/com.netmonguru.record.plist
    sudo launchctl bootstrap system /Library/LaunchDaemons/com.netmonguru.record.plist
  Remove:
    sudo launchctl bootout system/com.netmonguru.record
    sudo rm /Library/LaunchDaemons/com.netmonguru.record.plist

  It runs as root (full socket attribution, pf blocking) but keeps its data in
  your home: HOME and SUDO_UID below make the files land there and stay yours.
-->
<plist version="1.0">
<dict>
  <key>Label</key><string>com.netmonguru.record</string>
  <key>ProgramArguments</key>
  <array>
    <string>{python}</string>
    <string>-m</string><string>netmonguru</string>
    <string>--record</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key><string>{home}</string>
    <key>SUDO_UID</key><string>{os.environ.get("SUDO_UID") or os.getuid()}</string>
    <key>SUDO_GID</key><string>{os.environ.get("SUDO_GID") or os.getgid()}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/netmonguru.log</string>
  <key>StandardErrorPath</key><string>/var/log/netmonguru.log</string>
</dict>
</plist>"""
