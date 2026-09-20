"""Connection history and the traffic monitor ("watch list").

Two small, UI-independent pieces live here:

``SeenIndex``
    remembers when every socket was first observed, so the connections pane
    can put new sockets at the top of the list and show their age.

``WatchList`` / ``WatchRule`` / ``WatchTracker``
    a socket is ephemeral (its local port changes on every reconnect), so
    "monitor this connection" is stored as a *rule* that describes the
    conversation - process, protocol and remote endpoint - rather than the
    socket itself.  The tracker keeps every socket that ever matched a rule,
    including the ones that have closed since, which turns the monitor pane
    into a small audit trail.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .models import Connection
from .util import give_back

DEFAULT_RULES_PATH = Path(
    os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
) / "netmonguru" / "monitor.json"

#: a socket first seen less than this many seconds ago counts as "new"
NEW_WINDOW = 20.0


# ---------------------------------------------------------------------------
# first-seen bookkeeping
# ---------------------------------------------------------------------------

def unique_keys(connections: Iterable[Connection]) -> List[Tuple[str, Connection]]:
    """``Connection.key`` is not guaranteed unique (unattributed netstat rows
    can repeat), so duplicates get a ``#n`` suffix.  Order is preserved."""
    seen: Dict[str, int] = {}
    out: List[Tuple[str, Connection]] = []
    for c in connections:
        k = c.key
        n = seen.get(k, 0)
        seen[k] = n + 1
        out.append((k if n == 0 else f"{k}#{n}", c))
    return out


class SeenIndex:
    """key -> (first_seen timestamp, monotonically increasing sequence)."""

    def __init__(self) -> None:
        self._seen: Dict[str, Tuple[float, int]] = {}
        self._seq = 0
        self._primed = False

    def observe(self, keys: Iterable[str], now: Optional[float] = None) -> List[str]:
        """Record a sample; returns the keys that appeared in it.

        Sockets present in the very first sample were open before we started
        looking, so they are recorded as old (timestamp 0) and never flagged
        as new.
        """
        now = time.time() if now is None else now
        keys = list(keys)
        live = set(keys)
        fresh: List[str] = []
        for k in keys:
            if k not in self._seen:
                self._seq += 1
                self._seen[k] = (now if self._primed else 0.0, self._seq)
                if self._primed:
                    fresh.append(k)
        for k in [k for k in self._seen if k not in live]:
            del self._seen[k]
        if keys:
            self._primed = True
        return fresh

    def first_seen(self, key: str) -> float:
        return self._seen.get(key, (0.0, 0))[0]

    def seq(self, key: str) -> int:
        return self._seen.get(key, (0.0, 0))[1]

    def is_new(self, key: str, now: Optional[float] = None,
               window: float = NEW_WINDOW) -> bool:
        ts = self.first_seen(key)
        if not ts:
            return False
        now = time.time() if now is None else now
        return now - ts < window


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

@dataclass
class WatchRule:
    """Describes a conversation to monitor.  Empty fields are wildcards."""

    pname: str = ""
    proto: str = ""
    raddr: str = ""
    rport: int = 0
    lport: int = 0                 # only used for listening / local sockets
    host: str = ""                 # observed hostname; survives IP rotation
    scope: str = "endpoint"        # endpoint | host | process | listen
    created: float = field(default_factory=time.time)

    @property
    def ident(self) -> str:
        return (f"{self.scope}|{self.pname.lower()}|{self.proto}|{self.raddr}|"
                f"{self.rport}|{self.lport}|{self.host.lower()}")

    def matches(self, c: Connection, hostname: str = "") -> bool:
        if self.proto and c.proto != self.proto:
            return False
        if self.pname and c.pname.lower() != self.pname.lower():
            return False
        if self.lport and c.lport != self.lport:
            return False
        if self.rport and c.rport != self.rport:
            return False
        if self.raddr or self.host:
            same_ip = bool(self.raddr) and c.raddr == self.raddr
            same_host = bool(self.host and hostname) and \
                hostname.lower() == self.host.lower()
            if not (same_ip or same_host):
                return False
        if self.scope == "listen" and c.raddr:
            return False
        return True

    def describe(self) -> str:
        bits = []
        if self.pname:
            bits.append(self.pname)
        if self.proto:
            bits.append(self.proto)
        target = self.host or self.raddr
        if target:
            bits.append(f"→ {target}" + (f":{self.rport}" if self.rport else ""))
        elif self.rport:
            bits.append(f"→ *:{self.rport}")
        if self.lport:
            bits.append(f"local :{self.lport}")
        return " ".join(bits) or "any"

    @classmethod
    def from_connection(cls, c: Connection, scope: str = "endpoint",
                        hostname: str = "") -> "WatchRule":
        if scope == "process":
            return cls(pname=c.pname, scope="process")
        if not c.raddr:                       # listening / unconnected socket
            return cls(pname=c.pname, proto=c.proto, lport=c.lport,
                       scope="listen")
        if scope == "host":
            return cls(raddr=c.raddr, host=hostname, scope="host")
        return cls(pname="" if c.pname in ("", "?") else c.pname,
                   proto=c.proto, raddr=c.raddr, rport=c.rport,
                   host=hostname, scope="endpoint")


class WatchList:
    """Ordered, de-duplicated, optionally persisted set of rules."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else None
        self.rules: List[WatchRule] = []
        self.error = ""
        self.load()

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    def add(self, rule: WatchRule) -> bool:
        if any(r.ident == rule.ident for r in self.rules):
            return False
        self.rules.append(rule)
        self.save()
        return True

    def remove(self, index: int) -> Optional[WatchRule]:
        if 0 <= index < len(self.rules):
            rule = self.rules.pop(index)
            self.save()
            return rule
        return None

    def clear(self) -> None:
        self.rules = []
        self.save()

    def match(self, c: Connection, hostname: str = "") -> List[int]:
        return [i for i, r in enumerate(self.rules) if r.matches(c, hostname)]

    # -- persistence ---------------------------------------------------------
    def load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text("utf-8"))
            known = set(WatchRule.__dataclass_fields__)
            self.rules = [WatchRule(**{k: v for k, v in item.items()
                                       if k in known})
                          for item in raw.get("rules", [])]
        except Exception as exc:                        # noqa: BLE001
            self.error = f"monitor rules not loaded: {exc}"

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(
                {"version": 1, "rules": [asdict(r) for r in self.rules]},
                indent=2), "utf-8")
            tmp.replace(self.path)
            give_back(self.path)
            self.error = ""
        except Exception as exc:                        # noqa: BLE001
            self.error = f"monitor rules not saved: {exc}"


# ---------------------------------------------------------------------------
# tracking
# ---------------------------------------------------------------------------

@dataclass
class TrackedConn:
    key: str
    conn: Connection
    first_seen: float
    last_seen: float
    seq: int
    hostname: str = ""
    closed: bool = False
    preexisting: bool = False      # was already open when the rule was added

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)


class WatchTracker:
    """Every socket that matched a rule - live ones and closed history."""

    def __init__(self, watchlist: WatchList, history: int = 500) -> None:
        self.watchlist = watchlist
        self.history = history
        self.entries: Dict[str, TrackedConn] = {}
        self.totals: Dict[str, int] = {}          # rule ident -> sockets seen
        self._seq = 0

    def observe(self, keyed: Iterable[Tuple[str, Connection]],
                hostnames: Optional[Dict[str, str]] = None,
                now: Optional[float] = None,
                seen: Optional[SeenIndex] = None) -> None:
        now = time.time() if now is None else now
        hostnames = hostnames or {}
        live = set()
        if len(self.watchlist):
            for key, c in keyed:
                host = hostnames.get(c.raddr, "")
                hits = self.watchlist.match(c, host)
                if not hits:
                    continue
                live.add(key)
                e = self.entries.get(key)
                if e is None or e.closed:
                    self._seq += 1
                    started = seen.first_seen(key) if seen else now
                    self.entries[key] = TrackedConn(
                        key=key, conn=c, first_seen=started or now,
                        last_seen=now, seq=self._seq, hostname=host,
                        preexisting=not started)
                    for i in hits:
                        ident = self.watchlist.rules[i].ident
                        self.totals[ident] = self.totals.get(ident, 0) + 1
                else:
                    e.conn = c
                    e.last_seen = now
                    e.hostname = host or e.hostname
        for key, e in self.entries.items():
            if key not in live:
                e.closed = True
        self._trim()

    def _trim(self) -> None:
        closed = [e for e in self.entries.values() if e.closed]
        if len(closed) > self.history:
            closed.sort(key=lambda e: e.last_seen)
            for e in closed[:len(closed) - self.history]:
                del self.entries[e.key]

    def prune(self) -> None:
        """Drop entries that no remaining rule explains (after a removal)."""
        for key in [k for k, e in self.entries.items()
                    if not self.watchlist.match(e.conn, e.hostname)]:
            del self.entries[key]
        idents = {r.ident for r in self.watchlist}
        self.totals = {k: v for k, v in self.totals.items() if k in idents}

    def clear_history(self) -> None:
        for key in [k for k, e in self.entries.items() if e.closed]:
            del self.entries[key]

    def rows(self) -> List[TrackedConn]:
        """Live sockets first, newest first; then closed, most recent first."""
        out = list(self.entries.values())
        out.sort(key=lambda e: (e.closed,
                                -e.last_seen if e.closed else -e.seq))
        return out

    def live_count(self, rule: WatchRule) -> int:
        return sum(1 for e in self.entries.values()
                   if not e.closed and rule.matches(e.conn, e.hostname))

    def last_seen(self, rule: WatchRule) -> float:
        return max((e.last_seen for e in self.entries.values()
                    if rule.matches(e.conn, e.hostname)), default=0.0)
