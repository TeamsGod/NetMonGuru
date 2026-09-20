"""Real-time DNS observation with a rolling in-memory cache.

Three sources, tried in this order and degrading gracefully:

``log``
    ``log stream`` filtered to ``mDNSResponder`` - macOS' own resolver logs
    every answer it hands back, including the requesting process.  Works for
    plaintext DNS *and* for anything resolved through the system resolver.
``pcap``
    ``tcpdump`` on port 53.  Needs root and only sees plaintext DNS, but it
    also catches processes that bypass the system resolver.
``passive``
    Reverse (PTR) lookups of every new remote address seen in the socket
    table.  Always available, no privileges, and it keeps the pane useful
    when the other two are unavailable.

Everything observed lands in :class:`DNSCache`, a time-windowed store
(15 minutes by default) that also maintains an address -> hostname index the
connections pane uses to label remote endpoints.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Tuple

DEFAULT_WINDOW = 15 * 60          # seconds of history kept
MAX_RECORDS = 5000                # hard cap, protects memory on busy hosts

MODES = ("auto", "log", "pcap", "passive", "off")


@dataclass(slots=True)
class DNSRecord:
    """One observed name -> address answer."""

    ts: float
    name: str
    rtype: str = "A"
    answers: List[str] = field(default_factory=list)
    ttl: Optional[int] = None
    source: str = "log"           # log / pcap / passive
    client: str = ""              # requesting process, when known
    pid: Optional[int] = None

    @property
    def answer_text(self) -> str:
        return ", ".join(self.answers) if self.answers else "-"


@dataclass(slots=True)
class CacheEntry:
    """Aggregated view of one name over the retention window."""

    name: str
    addresses: "OrderedDict[str, float]" = field(default_factory=OrderedDict)
    first_seen: float = 0.0
    last_seen: float = 0.0
    hits: int = 0
    clients: "OrderedDict[str, int]" = field(default_factory=OrderedDict)
    sources: "OrderedDict[str, int]" = field(default_factory=OrderedDict)
    ttl: Optional[int] = None

    @property
    def address_text(self) -> str:
        return ", ".join(self.addresses) if self.addresses else "-"

    @property
    def client_text(self) -> str:
        return ", ".join(self.clients) if self.clients else "-"

    @property
    def age(self) -> float:
        return time.time() - self.last_seen


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------

class DNSCache:
    """Thread-safe, time-windowed store of DNS answers."""

    def __init__(self, window: int = DEFAULT_WINDOW) -> None:
        self.window = window
        self._lock = threading.Lock()
        self._records: Deque[DNSRecord] = deque(maxlen=MAX_RECORDS)
        self._by_name: Dict[str, CacheEntry] = {}
        self._by_ip: Dict[str, Tuple[str, float, str]] = {}
        self.total_seen = 0

    # -- writing -----------------------------------------------------------
    def add(self, rec: DNSRecord) -> None:
        if not rec.name:
            return
        rec.name = rec.name.rstrip(".").lower()
        with self._lock:
            self._records.append(rec)
            self.total_seen += 1
            entry = self._by_name.get(rec.name)
            if entry is None:
                entry = self._by_name[rec.name] = CacheEntry(
                    name=rec.name, first_seen=rec.ts)
            entry.last_seen = rec.ts
            entry.hits += 1
            if rec.ttl is not None:
                entry.ttl = rec.ttl
            for addr in rec.answers:
                entry.addresses[addr] = rec.ts
                # A forward answer we actually watched being resolved beats a
                # PTR guess; PTR only fills addresses nothing else named.
                prev = self._by_ip.get(addr)
                if (rec.source != "passive" or prev is None
                        or prev[2] == "passive"):
                    self._by_ip[addr] = (rec.name, rec.ts, rec.source)
            if rec.client:
                entry.clients[rec.client] = entry.clients.get(rec.client, 0) + 1
            entry.sources[rec.source] = entry.sources.get(rec.source, 0) + 1
            self._evict_locked(rec.ts)

    def add_many(self, records: Iterable[DNSRecord]) -> None:
        for rec in records:
            self.add(rec)

    # -- maintenance -------------------------------------------------------
    def _evict_locked(self, now: float) -> None:
        cutoff = now - self.window
        while self._records and self._records[0].ts < cutoff:
            self._records.popleft()
        stale = [n for n, e in self._by_name.items() if e.last_seen < cutoff]
        for name in stale:
            del self._by_name[name]
        if stale:
            self._by_ip = {ip: v for ip, v in self._by_ip.items()
                           if v[1] >= cutoff}

    def evict(self, now: Optional[float] = None) -> None:
        with self._lock:
            self._evict_locked(now if now is not None else time.time())

    # -- reading -----------------------------------------------------------
    def recent(self, limit: int = 500) -> List[DNSRecord]:
        with self._lock:
            return list(self._records)[-limit:][::-1]

    def entries(self) -> List[CacheEntry]:
        with self._lock:
            return sorted(self._by_name.values(),
                          key=lambda e: -e.last_seen)

    def names(self) -> Dict[str, str]:
        """``{address: hostname}`` for the connections pane."""
        with self._lock:
            return {ip: v[0] for ip, v in self._by_ip.items()}

    def name_for(self, ip: str) -> str:
        with self._lock:
            hit = self._by_ip.get(ip)
            return hit[0] if hit else ""

    def rate_series(self, buckets: int = 60) -> List[float]:
        """Queries per bucket across the retention window, oldest first."""
        now = time.time()
        span = self.window / buckets
        series = [0.0] * buckets
        with self._lock:
            for rec in self._records:
                idx = int((now - rec.ts) / span)
                if 0 <= idx < buckets:
                    series[buckets - 1 - idx] += 1
        return series

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"records": len(self._records),
                    "names": len(self._by_name),
                    "addresses": len(self._by_ip),
                    "total": self.total_seen}


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------

_HOSTNAME = r"(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9_])?\.)+" \
            r"[A-Za-z][A-Za-z0-9-]{0,62}"

_LOG_ANSWER = re.compile(
    rf"(?P<name>{_HOSTNAME})\.?\s+(?P<rtype>Addr|AAAA|A|CNAME)\s+"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9:._-]*)")
_LOG_CLIENT = re.compile(r"PID\[?(?P<pid>\d+)\]?\s*\((?P<proc>[^)]{1,40})\)")
_LOG_CLIENT_ALT = re.compile(r"\((?P<proc>[A-Za-z0-9._ -]{1,40})\)\s*"
                             r"(?:PID|pid)[: ]\s*(?P<pid>\d+)")


def _rtype_for(value: str, declared: str) -> str:
    if declared == "Addr":
        return "AAAA" if ":" in value else "A"
    return declared


def parse_log_line(line: str, now: Optional[float] = None
                   ) -> List[DNSRecord]:
    """Parse one ``log stream`` line from mDNSResponder."""
    if not line or "Addr" not in line and "CNAME" not in line:
        return []
    ts = now if now is not None else time.time()
    client, pid = "", None
    m = _LOG_CLIENT.search(line) or _LOG_CLIENT_ALT.search(line)
    if m:
        client = m.group("proc").strip()
        try:
            pid = int(m.group("pid"))
        except (TypeError, ValueError):
            pid = None

    out: List[DNSRecord] = []
    for hit in _LOG_ANSWER.finditer(line):
        name = hit.group("name")
        value = hit.group("value").rstrip(".")
        rtype = _rtype_for(value, hit.group("rtype"))
        if rtype in ("A", "AAAA") and not _looks_like_ip(value):
            continue
        out.append(DNSRecord(ts=ts, name=name, rtype=rtype, answers=[value],
                             source="log", client=client, pid=pid))
    return _merge_same_name(out)


def _looks_like_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _merge_same_name(records: List[DNSRecord]) -> List[DNSRecord]:
    merged: "OrderedDict[Tuple[str, str], DNSRecord]" = OrderedDict()
    for rec in records:
        key = (rec.name.lower(), rec.rtype)
        if key in merged:
            for a in rec.answers:
                if a not in merged[key].answers:
                    merged[key].answers.append(a)
        else:
            merged[key] = rec
    return list(merged.values())


_TCPDUMP_QUERY = re.compile(
    r"^\S+\s+IP6?\s+(?P<src>\S+?)\.(?P<sport>\d+)\s+>\s+\S+?\.53:\s+"
    r"(?P<id>\d+)\+?[^\s]*\s+(?P<qtype>[A-Z]+[0-9]*)\??\s+"
    r"(?P<name>[^\s,]+)")
_TCPDUMP_RESPONSE = re.compile(
    r"^\S+\s+IP6?\s+\S+?\.53\s+>\s+(?P<dst>\S+?)\.(?P<dport>\d+):\s+"
    r"(?P<id>\d+)[^\s]*\s+(?P<counts>\d+)/\d+/\d+\s+(?P<answers>.+?)\s*"
    r"\(\d+\)\s*$")
_TCPDUMP_ANSWER = re.compile(
    r"\b(?P<rtype>A|AAAA|CNAME)\s+(?P<value>[0-9A-Fa-f:.][^\s,]*)")


class TcpdumpParser:
    """Correlates tcpdump query lines with their responses by transaction id."""

    def __init__(self, max_pending: int = 512) -> None:
        self._pending: "OrderedDict[Tuple[str, str], Tuple[str, str]]" = \
            OrderedDict()
        self.max_pending = max_pending

    def feed(self, line: str, now: Optional[float] = None) -> List[DNSRecord]:
        ts = now if now is not None else time.time()
        line = line.strip()
        if not line:
            return []

        m = _TCPDUMP_QUERY.match(line)
        if m:
            key = (m.group("id"), m.group("sport"))
            self._pending[key] = (m.group("name").rstrip("."),
                                  m.group("qtype"))
            while len(self._pending) > self.max_pending:
                self._pending.popitem(last=False)
            return []

        m = _TCPDUMP_RESPONSE.match(line)
        if not m:
            return []
        key = (m.group("id"), m.group("dport"))
        name, qtype = self._pending.pop(key, ("", ""))
        answers: List[str] = []
        rtype = qtype or "A"
        for hit in _TCPDUMP_ANSWER.finditer(m.group("answers")):
            value = hit.group("value").rstrip(".,")
            if hit.group("rtype") in ("A", "AAAA") and not _looks_like_ip(value):
                continue
            answers.append(value)
            rtype = hit.group("rtype")
        if not name or not answers:
            return []
        return [DNSRecord(ts=ts, name=name, rtype=rtype, answers=answers,
                          source="pcap")]


# ---------------------------------------------------------------------------
# watcher
# ---------------------------------------------------------------------------

LOG_PREDICATE = ('process == "mDNSResponder" AND '
                 '(eventMessage CONTAINS "Addr" OR '
                 'eventMessage CONTAINS "CNAME")')


def default_interface() -> str:
    """Primary interface name, for tcpdump (macOS has no ``-i any``)."""
    try:
        out = subprocess.run(["route", "-n", "get", "default"],
                             capture_output=True, text=True, timeout=4).stdout
    except Exception:                                  # noqa: BLE001
        return ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return ""


class DNSWatcher:
    """Runs a capture subprocess and feeds :class:`DNSCache`."""

    def __init__(self, mode: str = "auto", window: int = DEFAULT_WINDOW,
                 interface: str = "") -> None:
        self.cache = DNSCache(window=window)
        self.requested_mode = mode if mode in MODES else "auto"
        self.mode = "passive"
        self.status = "starting"
        self.error = ""
        self.interface = interface
        self._proc: Optional[subprocess.Popen] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._tcpdump = TcpdumpParser()
        self._seen_passive: Dict[str, float] = {}

    # -- lifecycle ---------------------------------------------------------
    @property
    def elevated(self) -> bool:
        try:
            return os.geteuid() == 0
        except AttributeError:                         # pragma: no cover
            return False

    def _pick_mode(self) -> str:
        if self.requested_mode != "auto":
            return self.requested_mode
        if shutil.which("log"):
            return "log"
        if shutil.which("tcpdump") and self.elevated:
            return "pcap"
        return "passive"

    def start(self) -> None:
        if self._thread or self.requested_mode == "off":
            if self.requested_mode == "off":
                self.mode, self.status = "off", "disabled"
            return
        self.mode = self._pick_mode()
        if self.mode == "passive":
            self.status = "passive (reverse lookups only)"
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="netmonguru-dns")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:                          # noqa: BLE001
                pass

    # -- passive source ----------------------------------------------------
    def note_reverse(self, ip: str, hostname: str) -> None:
        """Record a PTR result discovered by the geo/DNS enricher."""
        if not ip or not hostname:
            return
        now = time.time()
        last = self._seen_passive.get(ip)
        if last and now - last < self.cache.window:
            return
        self._seen_passive[ip] = now
        self.cache.add(DNSRecord(ts=now, name=hostname, rtype="PTR",
                                 answers=[ip], source="passive"))

    # -- capture loop ------------------------------------------------------
    def _command(self) -> List[str]:
        if self.mode == "log":
            return ["log", "stream", "--style", "compact", "--info",
                    "--predicate", LOG_PREDICATE]
        iface = self.interface or default_interface() or "en0"
        self.interface = iface
        return ["tcpdump", "-l", "-n", "-i", iface, "udp port 53"]

    def _run(self) -> None:
        cmd = self._command()
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1)
        except Exception as exc:                       # noqa: BLE001
            self.error = f"{cmd[0]}: {exc}"[:160]
            self.mode, self.status = "passive", f"fell back: {self.error}"
            return

        self.status = f"{self.mode} live"
        assert self._proc.stdout is not None
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                try:
                    if self.mode == "log":
                        records = parse_log_line(line)
                    else:
                        records = self._tcpdump.feed(line)
                except Exception:                      # noqa: BLE001
                    continue
                self.cache.add_many(records)
        except Exception as exc:                       # noqa: BLE001
            self.error = str(exc)[:160]
        finally:
            rc = self._proc.poll()
            if not self._stop.is_set():
                stderr = ""
                try:
                    if self._proc.stderr is not None:
                        stderr = self._proc.stderr.read()[:200]
                except Exception:                      # noqa: BLE001
                    pass
                self.error = (stderr or self.error or
                              f"{cmd[0]} exited ({rc})").strip()
                self.mode = "passive"
                self.status = f"fell back to passive: {self.error[:60]}"
