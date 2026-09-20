"""Alerting: rules over the live picture, a learned baseline, and beaconing.

Everything here is evaluated by the sampler thread on every snapshot, so it
works the same under the TUI and in ``--record`` (headless) mode.

Rules
-----
``threat``        connection to a peer the feeds / AbuseIPDB call malicious or
                  suspicious
``bad-domain``    a name matching a domain IOC was resolved
``dga-domain``    a name that looks machine-generated was resolved (low)
``new-listener``  a process started listening on a port
``unsigned``      unsigned / invalidly signed / oddly placed binary talks to a
                  public address
``new-process``   a program that never used the network before goes outbound
                  (needs a finished baseline)
``new-country``   first connection to a country outside the allow-list or the
                  baseline
``upload-spike``  sustained upload far above the process' own normal
``beacon``        connections to one endpoint at suspiciously regular intervals
"""

from __future__ import annotations

import json
import math
import os
import statistics
import subprocess
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple

from .config import config_dir
from .models import Connection, is_routable
from .util import give_back

SEVERITY = {"low": 1, "medium": 2, "high": 3}


@dataclass
class Alert:
    ts: float
    severity: str               # low | medium | high
    kind: str
    subject: str                # short: what it is about
    detail: str = ""
    pname: str = ""
    pid: Optional[int] = None
    raddr: str = ""
    rport: int = 0
    acknowledged: bool = False

    @property
    def dedup(self) -> str:
        return f"{self.kind}|{self.pname.lower()}|{self.raddr}|{self.subject}"


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------

class Baseline:
    """What is normal on this machine.  Learned for ``learn_days`` of wall
    clock time, then used; things that raised an alert are added afterwards so
    each novelty is reported once."""

    def __init__(self, path: Optional[Path] = None, learn_days: float = 3.0,
                 persist: bool = True) -> None:
        self.path = Path(path) if path else config_dir() / "baseline.json"
        self.persist = persist
        self.learn_days = learn_days
        self.started = time.time()
        self.processes: set = set()          # programs seen going outbound
        self.countries: set = set()
        self.listeners: set = set()          # "pname:port"
        self.upload: Dict[str, float] = {}   # pname -> EWMA of out_rate (B/s)
        self.dirty = False
        if persist:
            self._load()
        #: a baseline that came from disk knows what is normal, so even the
        #: first sample may alert; an empty one has to see the machine first
        self.had_content = bool(self.processes or self.listeners)

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text("utf-8"))
            self.started = float(raw.get("started") or self.started)
            self.processes = set(raw.get("processes") or [])
            self.countries = set(raw.get("countries") or [])
            self.listeners = set(raw.get("listeners") or [])
            self.upload = {k: float(v) for k, v in
                           (raw.get("upload") or {}).items()}
        except Exception:                               # noqa: BLE001
            self.dirty = True

    def save(self) -> None:
        if not self.dirty or not self.persist:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({
                "version": 1, "started": self.started,
                "processes": sorted(self.processes),
                "countries": sorted(self.countries),
                "listeners": sorted(self.listeners),
                "upload": {k: round(v, 1) for k, v in self.upload.items()},
            }, indent=1), "utf-8")
            tmp.replace(self.path)
            give_back(self.path)
            self.dirty = False
        except Exception:                               # noqa: BLE001
            pass

    def reset(self) -> None:
        self.started = time.time()
        self.processes, self.countries, self.listeners = set(), set(), set()
        self.upload = {}
        self.dirty = True
        self.save()

    def remaining(self, now: Optional[float] = None) -> float:
        now = time.time() if now is None else now
        return max(0.0, self.started + self.learn_days * 86400 - now)

    @property
    def learning(self) -> bool:
        return self.remaining() > 0

    def status(self) -> str:
        left = self.remaining()
        if left <= 0:
            return (f"active ({len(self.processes)} programs, "
                    f"{len(self.countries)} countries, "
                    f"{len(self.listeners)} listeners)")
        hours = left / 3600
        return ("learning — " + (f"{hours / 24:.1f} d" if hours >= 24
                                 else f"{hours:.1f} h") + " left")

    def learn(self, collection: set, value: str) -> bool:
        """-> True when ``value`` is new."""
        if not value or value in collection:
            return False
        collection.add(value)
        self.dirty = True
        return True


# ---------------------------------------------------------------------------
# beaconing
# ---------------------------------------------------------------------------

def beacon_score(starts: List[float], min_events: int = 6,
                 min_interval: float = 5.0, max_interval: float = 3600.0,
                 max_jitter: float = 0.2) -> Optional[Tuple[float, float]]:
    """Connection start times -> ``(interval seconds, jitter)`` when they are
    regular enough to look like a timer, else ``None``.

    Jitter is the median absolute deviation of the gaps relative to their
    median - robust against the odd missed or doubled check-in that a plain
    standard deviation would punish.
    """
    if len(starts) < min_events:
        return None
    ordered = sorted(starts)
    gaps = [b - a for a, b in zip(ordered, ordered[1:]) if b - a > 0.5]
    if len(gaps) < min_events - 1:
        return None
    median = statistics.median(gaps)
    if not min_interval <= median <= max_interval:
        return None
    mad = statistics.median(abs(g - median) for g in gaps)
    jitter = mad / median
    if jitter > max_jitter:
        return None
    # most gaps must sit near the median - not just the middle ones
    near = sum(1 for g in gaps if abs(g - median) <= median * 0.35)
    if near / len(gaps) < 0.75:
        return None
    return median, jitter


class BeaconTracker:
    def __init__(self, window: float = 6 * 3600, keep: int = 40) -> None:
        self.window = window
        self.starts: Dict[Tuple[str, str, int], Deque[float]] = {}
        self.keep = keep

    def note(self, pname: str, raddr: str, rport: int, ts: float) -> None:
        key = (pname.lower(), raddr, rport)
        dq = self.starts.get(key)
        if dq is None:
            if len(self.starts) > 5000:
                self.prune(ts)
            dq = self.starts[key] = deque(maxlen=self.keep)
        dq.append(ts)

    def prune(self, now: float) -> None:
        for key in [k for k, dq in self.starts.items()
                    if not dq or now - dq[-1] > self.window]:
            del self.starts[key]

    def check(self, pname: str, raddr: str, rport: int
              ) -> Optional[Tuple[float, float, int]]:
        dq = self.starts.get((pname.lower(), raddr, rport))
        if not dq:
            return None
        score = beacon_score(list(dq))
        return None if score is None else (score[0], score[1], len(dq))


# ---------------------------------------------------------------------------
# notifications
# ---------------------------------------------------------------------------

def _osa_quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def notify_macos(title: str, message: str, run=subprocess.run) -> bool:
    """Notification Centre via ``osascript``.  Under ``sudo`` the notification
    is posted as the invoking user - root has no GUI session to show it in."""
    script = (f"display notification {_osa_quote(message[:240])} "
              f"with title {_osa_quote(title[:80])}")
    cmd = ["osascript", "-e", script]
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0 \
                and os.environ.get("SUDO_UID"):
            cmd = ["launchctl", "asuser", os.environ["SUDO_UID"]] + cmd
        run(cmd, capture_output=True, timeout=5)
        return True
    except Exception:                                   # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------

class AlertEngine:
    def __init__(self, settings: Optional[dict] = None,
                 baseline: Optional[Baseline] = None,
                 notifier: Optional[Callable[[str, str], bool]] = None,
                 history: int = 500) -> None:
        s = settings or {}
        self.enabled = bool(s.get("enabled", True))
        self.notify_enabled = bool(s.get("notify", True))
        self.min_notify = SEVERITY.get(
            str(s.get("min_notify_severity", "medium")), 2)
        self.cooldown = float(s.get("cooldown_minutes", 60)) * 60
        self.allowed_countries = {str(c).upper()
                                  for c in s.get("allowed_countries") or []}
        self.spike_floor = float(s.get("upload_spike_mbps", 8.0)) * 125000.0
        self.ignore = {str(p).lower()
                       for p in s.get("ignore_processes") or []}
        self.baseline = baseline if baseline is not None else Baseline()
        self.notifier = notifier or notify_macos
        self.beacons = BeaconTracker()
        self.alerts: Deque[Alert] = deque(maxlen=history)
        self.on_alert: List[Callable[[Alert], None]] = []
        self._last: Dict[str, float] = {}
        self._known: set = set()            # connection keys already seen
        self._listeners: set = set()
        self._spike: Dict[str, int] = {}
        self._dns_seen: Dict[str, float] = {}
        self._primed = False
        self._last_save = time.time()
        self._lock = threading.Lock()

    # -- helpers -------------------------------------------------------------
    @property
    def unacknowledged(self) -> int:
        return sum(1 for a in self.alerts if not a.acknowledged)

    def acknowledge_all(self) -> None:
        for a in self.alerts:
            a.acknowledged = True

    def raise_alert(self, alert: Alert) -> bool:
        if not self.enabled or alert.pname.lower() in self.ignore:
            return False
        last = self._last.get(alert.dedup)
        if last is not None and alert.ts - last < self.cooldown:
            return False
        self._last[alert.dedup] = alert.ts
        if len(self._last) > 5000:
            cutoff = alert.ts - self.cooldown
            self._last = {k: v for k, v in self._last.items() if v >= cutoff}
        with self._lock:
            self.alerts.appendleft(alert)
        for callback in self.on_alert:
            try:
                callback(alert)
            except Exception:                           # noqa: BLE001
                pass
        if self.notify_enabled and SEVERITY[alert.severity] >= self.min_notify:
            self.notifier(f"NetMonGuru — {alert.kind}",
                          f"{alert.subject}. {alert.detail}")
        return True

    def snapshot(self) -> List[Alert]:
        with self._lock:
            return list(self.alerts)

    # -- evaluation ----------------------------------------------------------
    def evaluate(self, keyed: Iterable[Tuple[str, Connection]],
                 verdicts: Dict[str, object], procsig: Dict[int, object],
                 geo: Dict[str, object], procs: Dict[str, object],
                 hostnames: Optional[Dict[str, str]] = None,
                 now: Optional[float] = None) -> None:
        if not self.enabled:
            return
        now = time.time() if now is None else now
        hostnames = hostnames or {}
        keyed = list(keyed)
        base = self.baseline
        # with an empty baseline the first sample *is* the baseline
        learning = base.learning or (not self._primed
                                     and not base.had_content)
        live = set()

        for key, c in keyed:
            live.add(key)
            fresh = key not in self._known
            pname = c.pname if c.pname not in ("", "?") else ""
            where = (hostnames.get(c.raddr) or c.raddr) + (
                f":{c.rport}" if c.rport else "")

            # listeners ------------------------------------------------------
            if c.is_listening and c.lport and pname:
                tag = f"{pname}:{c.lport}"
                if tag not in self._listeners:
                    self._listeners.add(tag)
                    new = base.learn(base.listeners, tag)
                    if new and not learning:
                        self.raise_alert(Alert(
                            now, "medium", "new-listener",
                            f"{pname} listens on {c.proto} port {c.lport}",
                            f"bound to {c.laddr or '*'} — not seen before",
                            pname, c.pid))

            if not c.raddr or not is_routable(c.raddr):
                continue

            # threat intelligence (re-checked: verdicts arrive late) ----------
            v = verdicts.get(c.raddr)
            level = getattr(v, "level", "")
            if level in ("malicious", "suspicious"):
                self.raise_alert(Alert(
                    now, "high" if level == "malicious" else "medium",
                    "threat", f"{pname or 'unknown process'} → {where}",
                    f"{level.upper()}: {getattr(v, 'label', '')}",
                    pname, c.pid, c.raddr, c.rport))

            if not fresh:
                continue
            self._known.add(key)
            if self._primed:
                self.beacons.note(pname or "?", c.raddr, c.rport, now)
                hit = self.beacons.check(pname or "?", c.raddr, c.rport)
                if hit is not None:
                    interval, jitter, count = hit
                    self.raise_alert(Alert(
                        now, "medium", "beacon",
                        f"{pname or 'unknown process'} → {where}",
                        f"{count} connections every ~{_span(interval)} "
                        f"(jitter {jitter:.0%}) — looks like a timer",
                        pname, c.pid, c.raddr, c.rport))

            # unsigned binary going outbound ---------------------------------
            sig = procsig.get(c.pid) if c.pid else None
            if sig is not None and getattr(sig, "verdict", "") == "suspicious":
                self.raise_alert(Alert(
                    now, "high", "unsigned",
                    f"{pname or 'unknown process'} → {where}",
                    f"{getattr(sig, 'signing', '?')} binary"
                    + (", " + ", ".join(sig.path_flags)
                       if getattr(sig, "path_flags", None) else "")
                    + f" — {getattr(sig, 'exe', '')}",
                    pname, c.pid, c.raddr, c.rport))

            # new program on the network -------------------------------------
            if pname and base.learn(base.processes, pname.lower()) \
                    and not learning:
                self.raise_alert(Alert(
                    now, "medium", "new-process",
                    f"{pname} used the network for the first time",
                    f"first peer: {where}", pname, c.pid, c.raddr, c.rport))

            # country ---------------------------------------------------------
            g = geo.get(c.raddr)
            code = (getattr(g, "country_code", "") or "").upper()
            if code:
                if self.allowed_countries:
                    if code not in self.allowed_countries:
                        self.raise_alert(Alert(
                            now, "medium", "new-country",
                            f"{pname or 'unknown process'} → {code}",
                            f"{getattr(g, 'label', code)} is not on the "
                            f"allow-list — {where}",
                            pname, c.pid, c.raddr, c.rport))
                elif base.learn(base.countries, code) and not learning:
                    self.raise_alert(Alert(
                        now, "low", "new-country",
                        f"first connection to {code}",
                        f"{pname or 'unknown process'} → {where} "
                        f"({getattr(g, 'label', code)})",
                        pname, c.pid, c.raddr, c.rport))

        # geo answers arrive after the socket was first seen: countries of
        # known sockets are learned quietly so they do not alert later
        if learning and not self.allowed_countries:
            for key, c in keyed:
                g = geo.get(c.raddr) if c.raddr else None
                code = (getattr(g, "country_code", "") or "").upper()
                if code:
                    base.learn(base.countries, code)

        # upload spikes ------------------------------------------------------
        for p in procs.values():
            name = (getattr(p, "name", "") or "").lower()
            rate = float(getattr(p, "out_rate", 0.0) or 0.0)
            if not name:
                continue
            avg = base.upload.get(name)
            threshold = max(self.spike_floor, (avg or 0.0) * 10)
            if not learning and rate > threshold:
                self._spike[name] = self._spike.get(name, 0) + 1
                if self._spike[name] == 3:            # sustained, not a burst
                    self.raise_alert(Alert(
                        now, "medium", "upload-spike",
                        f"{p.name} is uploading {_rate(rate)}",
                        f"its normal is {_rate(avg or 0)} — three samples in "
                        "a row above 10× / the configured floor",
                        p.name, getattr(p, "pid", None)))
            else:
                self._spike.pop(name, None)
            if rate > 0:
                # slow EWMA: a single spike must not become the new normal
                alpha = 0.05 if learning else 0.01
                base.upload[name] = rate if avg is None else \
                    avg + alpha * (rate - avg)
                base.dirty = True

        self._known &= live
        self._primed = self._primed or bool(keyed)
        if now - self._last_save > 120:
            base.save()
            self.beacons.prune(now)
            self._last_save = now

    def evaluate_dns(self, records, domain_lookup: Callable[[str], object],
                     now: Optional[float] = None) -> Dict[str, str]:
        """-> ``{name: label}`` for names that matched, for the DNS pane and
        the journal."""
        labels: Dict[str, str] = {}
        if not records:
            return labels
        now = time.time() if now is None else now
        for r in records:
            name = (r.name or "").lower().rstrip(".")
            if not name:
                continue
            hit = domain_lookup(name)
            if hit is None:
                continue
            labels[name] = hit.label
            if not self.enabled:
                continue
            kind = "dga-domain" if hit.feed == "dga" else "bad-domain"
            severity = {"malicious": "high", "suspicious": "medium"}.get(
                hit.severity, "low")
            self.raise_alert(Alert(
                now, severity, kind,
                f"{r.client or 'a process'} resolved {name}",
                f"{hit.label}: {hit.detail}"
                + (f" → {', '.join(r.answers[:3])}" if r.answers else ""),
                r.client or "", getattr(r, "pid", None),
                r.answers[0] if r.answers else ""))
        return labels

    def close(self) -> None:
        self.baseline.save()


def _span(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60}m"
    return f"{seconds / 3600:.1f}h"


def _rate(n: float) -> str:
    for factor, unit in ((1024 ** 3, "GB"), (1024 ** 2, "MB"), (1024, "KB")):
        if n >= factor:
            return f"{n / factor:.1f}{unit}/s"
    return f"{n:.0f}B/s"
