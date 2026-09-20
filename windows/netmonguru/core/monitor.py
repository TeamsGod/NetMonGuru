"""Background sampler that produces immutable snapshots for the UI."""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional

from .bandwidth import (BandwidthCollector, DemoNetCollector,
                        ProcessNetCollector, WindowsNetCollector)
from .win import IS_WINDOWS
from .connections import ConnectionCollector
from .dnswatch import DEFAULT_WINDOW, DNSWatcher
from .enrich import Enricher
from .models import Connection, ProcNet, Snapshot, is_routable
from .ti import ThreatIntel
from .alerts import AlertEngine, Baseline
from .config import Config, config_dir
from .journal import Journal
from .killer import BlockList, PfCutter
from .macos_ctx import MacContext
from .watch import unique_keys


class Monitor:
    def __init__(self, interval: float = 2.0, geo: bool = True,
                 dns: bool = True, mmdb: str = "", mmdb_asn: str = "",
                 per_process_bw: bool = True, use_netstat: bool = True,
                 dns_capture: str = "auto", dns_window: int = DEFAULT_WINDOW,
                 dns_iface: str = "", demo: bool = False,
                 ti: bool = True, ti_auto: bool = True,
                 ti_engine: Optional[ThreatIntel] = None,
                 config: Optional[Config] = None,
                 journal: Optional[Journal] = None,
                 alerts: Optional[AlertEngine] = None,
                 cutter: Optional[PfCutter] = None,
                 blocklist: Optional[BlockList] = None) -> None:
        self.interval = max(0.5, interval)
        self.demo = demo
        self.conns = ConnectionCollector(use_netstat=use_netstat)
        self.bw = BandwidthCollector()
        if demo:
            self.procnet = DemoNetCollector()
        elif IS_WINDOWS:
            self.procnet = WindowsNetCollector(enabled=per_process_bw)
        else:
            self.procnet = ProcessNetCollector(enabled=per_process_bw)
        self.dns = DNSWatcher(mode=dns_capture, window=dns_window,
                              interface=dns_iface)
        self.enricher = Enricher(enabled=geo, resolve_dns=dns,
                                 mmdb=mmdb, mmdb_asn=mmdb_asn)
        # demo / tests never talk to the network unless handed an engine
        self.config = config or Config()
        tcfg = self.config.section("ti")
        self.ti = ti_engine if ti_engine is not None else ThreatIntel(
            enabled=ti and not demo and bool(tcfg["enabled"]),
            auto=ti_auto and bool(tcfg["auto_abuseipdb"]),
            budget=int(tcfg["abuseipdb_daily_budget"]))
        if ti_engine is None:
            from .ti_sources import set_vt_rate
            set_vt_rate(int(self.config.get("ti", "virustotal_per_minute")))
        # demo / tests never write to the user's real journal or baseline
        # unless they are handed one
        jcfg = self.config.section("journal")
        if journal is not None:
            self.journal: Optional[Journal] = journal
        elif demo or not jcfg["enabled"]:
            self.journal = None
        else:
            self.journal = Journal(retention_days=int(jcfg["retention_days"]))
        if alerts is not None:
            self.alerts = alerts
        else:
            settings = dict(self.config.section("alerts"))
            if demo:
                settings["notify"] = False
            self.alerts = AlertEngine(settings, Baseline(
                learn_days=float(self.config.get("baseline", "learn_days")),
                persist=not demo))
        if self.journal is not None:
            self.alerts.on_alert.append(self.journal.add_alert)
        bcfg = self.config.section("block")
        from .killer import make_cutter
        self.cutter = cutter or make_cutter(bool(bcfg["keep_on_exit"]))
        self.blocklist = blocklist if blocklist is not None else BlockList(
            None if demo else config_dir() / "blocklist.json")
        self.auto_block = bool(bcfg["auto_malicious"])
        self.block_status = ""
        from .win_ctx import make_context
        self.macctx = make_context()
        self.dns_labels: Dict[str, str] = {}
        self._dns_mark = time.time()
        self._first_seen: Dict[str, float] = {}
        self._first_primed = False
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
        self.ti.start()
        self.apply_blocklist()
        if self.demo:
            _seed_demo_dns(self.dns)
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="netmonguru-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.enricher.stop()
        self.dns.stop()
        self.ti.stop()
        self.alerts.close()
        if self.journal is not None:
            self.journal.close()
        self.cutter.release()

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
        if self.demo or IS_WINDOWS:
            procs: Dict[str, ProcNet] = self.procnet.collect_for(
                connections, self.interval)
        else:
            procs = self.procnet.collect()
        if self.procnet.error:
            errors.append(f"bandwidth: {self.procnet.error}")

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

        names = self.dns.cache.names()
        self.ti.submit(connections, names)
        verdicts, procsig = self.ti.snapshot()
        self._after_sample(connections, verdicts, procsig, geo, procs, names)

        up, down = self.bw.totals
        return Snapshot(
            connections=connections,
            nics=nics,
            procs=procs,
            flows=dict(self.procnet.flows),
            geo=geo,
            dns_names=self.dns.cache.names(),
            ti=verdicts, procsig=procsig,
            total_up=up, total_down=down,
            up_history=list(self.bw.total_up_hist),
            down_history=list(self.bw.total_down_hist),
            errors=errors,
            elevated=self.conns.elevated,
            backend=backend,
            ts=time.time())


    # -- alerts, journal, blocking -----------------------------------------
    def _after_sample(self, connections, verdicts, procsig, geo, procs,
                      names) -> None:
        now = time.time()
        keyed = unique_keys(connections)
        hostnames = {}
        for _, c in keyed:
            if c.raddr and c.raddr not in hostnames:
                g = geo.get(c.raddr)
                hostnames[c.raddr] = names.get(c.raddr) or (
                    (g.hostname or "") if g else "")
        try:
            self.alerts.evaluate(keyed, verdicts, procsig, geo, procs,
                                 hostnames, now)
            fresh = [r for r in self.dns.cache.recent(300)
                     if r.ts > self._dns_mark and r.source != "passive"]
            if fresh:
                self._dns_mark = max(r.ts for r in fresh)
                labels = self.alerts.evaluate_dns(fresh, self.ti.lookup_domain,
                                                  now)
                self.dns_labels.update(labels)
                if len(self.dns_labels) > 5000:
                    self.dns_labels = dict(list(self.dns_labels.items())[-2500:])
                if self.journal is not None and \
                        self.config.get("journal", "record_dns"):
                    self.journal.add_dns(fresh, labels)
        except Exception as exc:                        # noqa: BLE001
            self.alerts_error = f"alerts: {exc}"[:120]

        live = set()
        for key, _ in keyed:
            live.add(key)
            if key not in self._first_seen:
                # sockets of the first sample were open before we started
                self._first_seen[key] = now if self._first_primed else 0.0
        for key in [k for k in self._first_seen if k not in live]:
            del self._first_seen[key]
        self._first_primed = self._first_primed or bool(keyed)

        if self.journal is not None:
            flows = {(f.proto, f.lport, f.raddr, f.rport): f
                     for f in self.procnet.flows.values()}
            meta = {}
            for key, c in keyed:
                g = geo.get(c.raddr) if c.raddr else None
                v = verdicts.get(c.raddr) if c.raddr else None
                sig = procsig.get(c.pid) if c.pid else None
                f = flows.get((c.proto, c.lport, c.raddr, c.rport))
                meta[key] = {
                    "host": hostnames.get(c.raddr, ""),
                    "country": (g.country_code or "") if g else "",
                    "org": (g.org or "") if g else "",
                    "ti_level": getattr(v, "level", "") or "",
                    "ti_label": getattr(v, "label", "") or "",
                    "sig": getattr(sig, "signing", "") or "",
                    "bytes_in": f.bytes_in if f else 0,
                    "bytes_out": f.bytes_out if f else 0,
                    "first_seen": self._first_seen.get(key) or now,
                }
            self.journal.observe(keyed, meta, now)

        if self.auto_block and self.cutter.available:
            added = False
            for ip, v in verdicts.items():
                if getattr(v, "level", "") == "malicious" \
                        and getattr(v, "hits", None) and ip not in self.blocklist:
                    try:
                        added |= self.blocklist.add(
                            ip, names.get(ip, ""), v.label, by="auto")
                    except ValueError:
                        continue
            if added:
                self.apply_blocklist()

    def apply_blocklist(self) -> str:
        """Push the persisted blocklist into pf.  Needs root; without it the
        list is kept and applied the next time NetMonGuru runs elevated."""
        if not len(self.blocklist) and not self.cutter.blocked:
            self.block_status = ""
            return ""
        if not self.cutter.available:
            self.block_status = (f"{len(self.blocklist)} host(s) on the "
                                 f"blocklist NOT enforced: "
                                 f"{self.cutter.why_not}")
            return self.block_status
        ok, message = self.cutter.set_blocked(self.blocklist.ips())
        self.block_status = message if ok else f"blocklist: {message}"
        return self.block_status

    alerts_error = ""


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
