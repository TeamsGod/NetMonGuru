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
    p.add_argument("-i", "--interval", type=float, default=2.0,
                   metavar="SEC", help="sampling interval (default: 2.0)")
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
    p.add_argument("--demo", action="store_true",
                   help="synthetic connection data (useful off macOS)")
    p.add_argument("--dump", action="store_true",
                   help="print one plain-text sample and exit (no TUI)")
    p.add_argument("-V", "--version", action="version",
                   version=f"netmonguru {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    from .core.monitor import Monitor

    monitor = Monitor(interval=args.interval, geo=not args.no_geo,
                      dns=not args.no_dns, mmdb=args.mmdb,
                      mmdb_asn=args.mmdb_asn,
                      per_process_bw=not args.no_proc_bw,
                      use_netstat=not args.no_netstat,
                      dns_capture=args.dns_capture,
                      dns_window=max(60, args.dns_window),
                      dns_iface=args.dns_iface,
                      demo=args.demo)

    if args.dump:
        return _dump(monitor)

    if platform.system() != "Darwin" and not args.demo:
        print("netmonguru targets macOS; on other systems only parts of the "
              "data will be available (try --demo).", file=sys.stderr)

    from .ui.app import NetMonGuruApp

    app = NetMonGuruApp(monitor)
    try:
        app.run()
    finally:
        monitor.stop()
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
