"""Background sampler that produces immutable snapshots for the UI."""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional

from .bandwidth import BandwidthCollector, ProcessNetCollector
from .connections import ConnectionCollector
from .dnswatch import DEFAULT_WINDOW, DNSWatcher
from .enrich import Enricher
from .models import Connection, ProcNet, Snapshot, is_routable


class Monitor:
    def __init__(self, interval: float = 2.0, geo: bool = True,
                 dns: bool = True, mmdb: str = "", mmdb_asn: str = "",
                 per_process_bw: bool = True, use_netstat: bool = True,
                 dns_capture: str = "auto", dns_window: int = DEFAULT_WINDOW,
                 dns_iface: str = "", demo: bool = False) -> None:
        self.interval = max(0.5, interval)
        self.demo = demo
        self.conns = ConnectionCollector(use_netstat=use_netstat)
        self.bw = BandwidthCollector()
        self.procnet = ProcessNetCollector(enabled=per_process_bw)
        self.dns = DNSWatcher(mode=dns_capture, window=dns_window,
                              interface=dns_iface)
        self.enricher = Enricher(enabled=geo, resolve_dns=dns,
                                 mmdb=mmdb, mmdb_asn=mmdb_asn)
        self.snapshot = Snapshot(ts=time.time())
        self.paused = False
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._listeners: List = []

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        if self._thread:
            return
        self.dns.start()
        if self.demo:
            _seed_demo_dns(self.dns)
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="netmonguru-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.enricher.stop()
        self.dns.stop()

    def _loop(self) -> None:
        while not self._stop.is_set():
            start = time.monotonic()
            if not self.paused:
                try:
                    self.snapshot = self._sample()
                except Exception as exc:                # noqa: BLE001
                    snap = self.snapshot
                    snap.errors = [f"sampler: {exc}"]
            elapsed = time.monotonic() - start
            self._stop.wait(max(0.1, self.interval - elapsed))

    # -- sampling ----------------------------------------------------------
    def _sample(self) -> Snapshot:
        if self.demo:
            connections: List[Connection] = _demo_connections()
            errors: List[str] = []
            backend = "demo"
        else:
            connections = self.conns.collect()
            errors = list(self.conns.errors)
            backend = self.conns.backend

        nics = self.bw.collect()
        procs: Dict[str, ProcNet] = self.procnet.collect()
        if self.procnet.error:
            errors.append(f"nettop: {self.procnet.error}")

        # attach connection counts to processes
        per_pid: Dict[int, int] = {}
        for c in connections:
            if c.pid:
                per_pid[c.pid] = per_pid.get(c.pid, 0) + 1
        for p in procs.values():
            if p.pid and p.pid in per_pid:
                p.conns = per_pid[p.pid]

        remote_ips = {c.raddr for c in connections
                      if c.raddr and is_routable(c.raddr)}
        self.enricher.submit(sorted(remote_ips))

        geo = self.enricher.snapshot()
        for ip, info in geo.items():
            if info.hostname:
                self.dns.note_reverse(ip, info.hostname)
        self.dns.cache.evict()

        up, down = self.bw.totals
        return Snapshot(
            connections=connections,
            nics=nics,
            procs=procs,
            geo=geo,
            dns_names=self.dns.cache.names(),
            total_up=up, total_down=down,
            up_history=list(self.bw.total_up_hist),
            down_history=list(self.bw.total_down_hist),
            errors=errors,
            elevated=self.conns.elevated,
            backend=backend,
            ts=time.time())


# ---------------------------------------------------------------------------
# demo data (used by --demo and by the test-suite on non-macOS hosts)
# ---------------------------------------------------------------------------

_DEMO = [
    ("TCP", "192.168.1.24", 51344, "142.250.203.110", 443, "ESTABLISHED", 501, "firefox"),
    ("TCP", "192.168.1.24", 51345, "140.82.121.4", 443, "ESTABLISHED", 502, "git"),
    ("TCP", "192.168.1.24", 51346, "13.107.42.14", 443, "ESTABLISHED", 503, "Microsoft Teams"),
    ("TCP", "192.168.1.24", 51347, "104.18.32.7", 443, "ESTABLISHED", 501, "firefox"),
    ("TCP", "192.168.1.24", 51348, "151.101.1.140", 443, "TIME_WAIT", 501, "firefox"),
    ("TCP", "192.168.1.24", 51349, "203.0.113.9", 22, "ESTABLISHED", 504, "ssh"),
    ("TCP", "", 22, "", 0, "LISTEN", 1, "launchd"),
    ("TCP", "127.0.0.1", 6379, "", 0, "LISTEN", 505, "redis-server"),
    ("UDP", "", 5353, "", 0, "", 506, "mDNSResponder"),
    ("UDP", "192.168.1.24", 68, "", 0, "", 507, "configd"),
    ("TCP", "192.168.1.24", 51350, "52.109.8.20", 443, "ESTABLISHED", 503, "Microsoft Teams"),
    ("TCP", "192.168.1.24", 51351, "1.1.1.1", 853, "ESTABLISHED", 508, "mDNSResponder"),
]


_DEMO_DNS = [
    ("www.google.com", "A", ["142.250.203.110"], "firefox", 501, 300),
    ("github.com", "A", ["140.82.121.4"], "git", 502, 60),
    ("teams.microsoft.com", "A", ["13.107.42.14"], "Microsoft Teams", 503, 30),
    ("cdnjs.cloudflare.com", "A", ["104.18.32.7"], "firefox", 501, 240),
    ("news.ycombinator.com", "A", ["151.101.1.140"], "firefox", 501, 60),
    ("outlook.office365.com", "A", ["52.109.8.20"], "Microsoft Teams", 503, 45),
    ("one.one.one.one", "A", ["1.1.1.1"], "mDNSResponder", 508, 3600),
    ("jump.example.net", "A", ["203.0.113.9"], "ssh", 504, 900),
    ("safebrowsing.googleapis.com", "A", ["142.250.203.110"], "firefox", 501,
     300),
    ("telemetry.example.com", "AAAA", ["2606:4700::6810:85e5"], "firefox",
     501, 120),
]


def _seed_demo_dns(watcher) -> None:
    """Populate the DNS pane with plausible traffic in --demo mode."""
    from .dnswatch import DNSRecord

    now = time.time()
    for i, (name, rtype, answers, client, pid, ttl) in enumerate(_DEMO_DNS):
        for k in range(1 + (i % 3)):
            watcher.cache.add(DNSRecord(
                ts=now - (i * 37 + k * 11), name=name, rtype=rtype,
                answers=answers, ttl=ttl, source="log", client=client,
                pid=pid))
    watcher.status = "demo"
    watcher.mode = "demo"


def _demo_connections() -> List[Connection]:
    import random

    out = []
    for proto, la, lp, ra, rp, st, pid, name in _DEMO:
        out.append(Connection(proto=proto, family="IPv4", laddr=la, lport=lp,
                              raddr=ra, rport=rp, state=st, pid=pid,
                              pname=name))
    if random.random() < 0.5:
        out.append(Connection(proto="TCP", family="IPv6",
                              laddr="2a00:1450:401b:800::200e", lport=51360,
                              raddr="2606:4700::6810:85e5", rport=443,
                              state="ESTABLISHED", pid=501, pname="firefox"))
    return out
