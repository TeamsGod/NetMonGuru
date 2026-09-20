"""On-disk journal (SQLite): every connection, alert and DNS answer.

The live views forget a socket the moment it closes.  The journal keeps it -
who talked to whom, when, for how long, how much, and what threat intelligence
said at the time - so "what did this Mac do last night" has an answer and the
answer can be exported as evidence.

One writer (the sampler thread) and any number of short-lived readers (the
History pane, ``--export``); WAL mode keeps them out of each other's way.
"""

from __future__ import annotations

import csv
import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .config import data_dir
from .models import Connection
from .util import give_back

SCHEMA = """
CREATE TABLE IF NOT EXISTS connections (
    id          INTEGER PRIMARY KEY,
    key         TEXT NOT NULL,
    proto       TEXT, family TEXT,
    laddr       TEXT, lport INTEGER,
    raddr       TEXT, rport INTEGER,
    pid         INTEGER, pname TEXT,
    host        TEXT, country TEXT, org TEXT,
    ti_level    TEXT, ti_label TEXT, sig TEXT,
    state       TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    closed      INTEGER NOT NULL DEFAULT 0,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    bytes_out   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS conn_first ON connections(first_seen);
CREATE INDEX IF NOT EXISTS conn_open ON connections(closed, key);
CREATE INDEX IF NOT EXISTS conn_raddr ON connections(raddr);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, severity TEXT, kind TEXT,
    subject TEXT, detail TEXT, pname TEXT, pid INTEGER, raddr TEXT
);
CREATE INDEX IF NOT EXISTS alert_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS dns (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, name TEXT, rtype TEXT,
    answers TEXT, client TEXT, ti_label TEXT
);
CREATE INDEX IF NOT EXISTS dns_ts ON dns(ts);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""

CONNECTION_COLUMNS = ["first_seen", "last_seen", "closed", "proto", "pname",
                      "pid", "laddr", "lport", "raddr", "rport", "host",
                      "country", "org", "ti_level", "ti_label", "sig",
                      "state", "bytes_in", "bytes_out"]

_SINCE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*$", re.I)


def parse_since(text: str, now: Optional[float] = None) -> float:
    """``90m`` / ``24h`` / ``7d`` / ``2w`` / ``all`` -> epoch seconds."""
    now = time.time() if now is None else now
    if not text or text.lower() in ("all", "0"):
        return 0.0
    m = _SINCE.match(text)
    if not m:
        raise ValueError(f"cannot read a time span from {text!r} "
                         "(use e.g. 90m, 24h, 7d, all)")
    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800,
              "": 3600}[m.group(2).lower()]
    return now - float(m.group(1)) * factor


def default_path() -> Path:
    return data_dir() / "journal.db"


class Journal:
    def __init__(self, path: Optional[Path] = None, retention_days: int = 30,
                 flush_every: float = 30.0) -> None:
        self.path = Path(path) if path else default_path()
        self.retention_days = retention_days
        self.flush_every = flush_every
        self.error = ""
        self._open: Dict[str, int] = {}          # live key -> row id
        self._last: Dict[str, Tuple[Connection, Dict[str, Any]]] = {}
        self._last_flush = 0.0
        self._primed = False
        self._lock = threading.Lock()
        self._db: Optional[sqlite3.Connection] = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(self.path), check_same_thread=False,
                                       timeout=5.0)
            self._db.executescript(SCHEMA)
            try:
                self._db.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass
            # sockets left "open" by a crash or kill -9 are closed now
            self._db.execute("UPDATE connections SET closed=1 WHERE closed=0")
            if retention_days > 0:
                cutoff = time.time() - retention_days * 86400
                for table, col in (("connections", "last_seen"),
                                   ("alerts", "ts"), ("dns", "ts")):
                    self._db.execute(
                        f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
            self._db.commit()
            give_back(self.path)
        except Exception as exc:                        # noqa: BLE001
            self.error = f"journal: {exc}"[:160]
            self._db = None

    @property
    def enabled(self) -> bool:
        return self._db is not None

    # -- writing -------------------------------------------------------------
    def observe(self, keyed: Iterable[Tuple[str, Connection]],
                meta: Dict[str, Dict[str, Any]],
                now: Optional[float] = None) -> None:
        """``meta[key]`` may carry host, country, org, ti_level, ti_label,
        sig, bytes_in, bytes_out."""
        if self._db is None:
            return
        now = time.time() if now is None else now
        keyed = list(keyed)
        live = {k for k, _ in keyed}
        flush = now - self._last_flush >= self.flush_every
        try:
            with self._lock:
                for key, c in keyed:
                    m = meta.get(key, {})
                    row = self._open.get(key)
                    if row is None:
                        cur = self._db.execute(
                            "INSERT INTO connections (key, proto, family, "
                            "laddr, lport, raddr, rport, pid, pname, host, "
                            "country, org, ti_level, ti_label, sig, state, "
                            "first_seen, last_seen, bytes_in, bytes_out) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (key, c.proto, c.family, c.laddr, c.lport,
                             c.raddr, c.rport, c.pid, c.pname,
                             m.get("host", ""), m.get("country", ""),
                             m.get("org", ""), m.get("ti_level", ""),
                             m.get("ti_label", ""), m.get("sig", ""), c.state,
                             m.get("first_seen") or now, now,
                             int(m.get("bytes_in") or 0),
                             int(m.get("bytes_out") or 0)))
                        self._open[key] = int(cur.lastrowid)
                    elif flush:
                        self._update(row, c, m, now, closed=0)
                    # remember the newest enrichment: a short-lived socket
                    # may close before the next periodic flush
                    old = self._last.get(key)
                    merged = dict(old[1]) if old else {}
                    merged.update({k: v for k, v in m.items() if v})
                    self._last[key] = (c, merged)
                gone = [k for k in self._open if k not in live]
                for key in gone:
                    # it closed somewhere since the previous sample
                    c_last, m_last = self._last.pop(key, (None, {}))
                    row = self._open.pop(key)
                    if c_last is not None:
                        self._update(row, c_last, m_last, now, closed=1)
                    else:
                        self._db.execute(
                            "UPDATE connections SET closed=1, last_seen=? "
                            "WHERE id=?", (now, row))
                if flush or gone or not self._primed:
                    self._db.commit()
                    self._last_flush = now
                self._primed = True
        except Exception as exc:                        # noqa: BLE001
            self.error = f"journal: {exc}"[:160]

    def _update(self, row: int, c: Connection, m: Dict[str, Any], now: float,
                closed: int) -> None:
        # enrichment arrives late (geo, TI): keep the best value seen
        self._db.execute(
            "UPDATE connections SET last_seen=?, state=?, closed=?, "
            "host=CASE WHEN ?<>'' THEN ? ELSE host END, "
            "country=CASE WHEN ?<>'' THEN ? ELSE country END, "
            "org=CASE WHEN ?<>'' THEN ? ELSE org END, "
            "ti_level=CASE WHEN ?<>'' THEN ? ELSE ti_level END, "
            "ti_label=CASE WHEN ?<>'' THEN ? ELSE ti_label END, "
            "sig=CASE WHEN ?<>'' THEN ? ELSE sig END, "
            "bytes_in=MAX(bytes_in, ?), bytes_out=MAX(bytes_out, ?) "
            "WHERE id=?",
            (now, c.state, closed,
             m.get("host", ""), m.get("host", ""),
             m.get("country", ""), m.get("country", ""),
             m.get("org", ""), m.get("org", ""),
             m.get("ti_level", ""), m.get("ti_level", ""),
             m.get("ti_label", ""), m.get("ti_label", ""),
             m.get("sig", ""), m.get("sig", ""),
             int(m.get("bytes_in") or 0), int(m.get("bytes_out") or 0), row))

    def touch(self, keyed: Iterable[Tuple[str, Connection]],
              meta: Dict[str, Dict[str, Any]],
              now: Optional[float] = None) -> None:
        """Force the late-arriving fields of live rows to disk."""
        if self._db is None:
            return
        now = time.time() if now is None else now
        with self._lock:
            for key, c in keyed:
                row = self._open.get(key)
                if row is not None:
                    self._update(row, c, meta.get(key, {}), now, closed=0)
            self._db.commit()

    def add_alert(self, alert) -> None:
        if self._db is None:
            return
        try:
            with self._lock:
                self._db.execute(
                    "INSERT INTO alerts (ts, severity, kind, subject, detail, "
                    "pname, pid, raddr) VALUES (?,?,?,?,?,?,?,?)",
                    (alert.ts, alert.severity, alert.kind, alert.subject,
                     alert.detail, alert.pname, alert.pid, alert.raddr))
                self._db.commit()
        except Exception as exc:                        # noqa: BLE001
            self.error = f"journal: {exc}"[:160]

    def add_dns(self, records, labels: Optional[Dict[str, str]] = None
                ) -> None:
        if self._db is None or not records:
            return
        labels = labels or {}
        try:
            with self._lock:
                self._db.executemany(
                    "INSERT INTO dns (ts, name, rtype, answers, client, "
                    "ti_label) VALUES (?,?,?,?,?,?)",
                    [(r.ts, r.name, r.rtype, ", ".join(r.answers),
                      r.client or "", labels.get(r.name, ""))
                     for r in records])
                self._db.commit()
        except Exception as exc:                        # noqa: BLE001
            self.error = f"journal: {exc}"[:160]

    def close(self) -> None:
        if self._db is None:
            return
        try:
            with self._lock:
                self._db.execute("UPDATE connections SET closed=1, "
                                 "last_seen=? WHERE closed=0", (time.time(),))
                self._db.commit()
                self._db.close()
        except Exception:                               # noqa: BLE001
            pass
        self._db = None

    # -- reading -------------------------------------------------------------
    def _reader(self) -> sqlite3.Connection:
        db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True,
                             timeout=3.0)
        db.row_factory = sqlite3.Row
        return db

    def connections(self, since: float = 0.0, text: str = "",
                    only_flagged: bool = False, limit: int = 500
                    ) -> List[sqlite3.Row]:
        where, args = ["first_seen >= ? OR last_seen >= ?"], [since, since]
        sql_where = "(" + where[0] + ")"
        if text:
            like = f"%{text.lower()}%"
            sql_where += (" AND (lower(pname) LIKE ? OR raddr LIKE ? OR "
                          "lower(host) LIKE ? OR lower(org) LIKE ? OR "
                          "lower(country) LIKE ? OR lower(ti_label) LIKE ? "
                          "OR CAST(rport AS TEXT) = ? "
                          "OR CAST(pid AS TEXT) = ?)")
            args += [like, like, like, like, like, like, text, text]
        if only_flagged:
            sql_where += " AND ti_level IN ('malicious', 'suspicious')"
        try:
            db = self._reader()
            try:
                return db.execute(
                    f"SELECT * FROM connections WHERE {sql_where} "
                    "ORDER BY first_seen DESC, id DESC LIMIT ?",
                    args + [limit]).fetchall()
            finally:
                db.close()
        except Exception as exc:                        # noqa: BLE001
            self.error = f"journal: {exc}"[:160]
            return []

    def alerts(self, since: float = 0.0, limit: int = 500
               ) -> List[sqlite3.Row]:
        try:
            db = self._reader()
            try:
                return db.execute(
                    "SELECT * FROM alerts WHERE ts >= ? ORDER BY ts DESC "
                    "LIMIT ?", (since, limit)).fetchall()
            finally:
                db.close()
        except Exception:                               # noqa: BLE001
            return []

    def stats(self) -> Dict[str, Any]:
        try:
            db = self._reader()
            try:
                n, first = db.execute("SELECT COUNT(*), MIN(first_seen) FROM "
                                      "connections").fetchone()
                a = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                d = db.execute("SELECT COUNT(*) FROM dns").fetchone()[0]
            finally:
                db.close()
            size = self.path.stat().st_size if self.path.exists() else 0
            return {"connections": n, "alerts": a, "dns": d,
                    "since": first or 0.0, "bytes": size}
        except Exception:                               # noqa: BLE001
            return {"connections": 0, "alerts": 0, "dns": 0, "since": 0.0,
                    "bytes": 0}

    # -- export --------------------------------------------------------------
    def export(self, target: Path, what: str = "connections",
               since: float = 0.0) -> int:
        """CSV or JSON by file extension.  Returns the number of rows."""
        if what not in ("connections", "alerts", "dns"):
            raise ValueError("export: choose connections, alerts or dns")
        column = "first_seen" if what == "connections" else "ts"
        db = self._reader()
        try:
            rows = db.execute(f"SELECT * FROM {what} WHERE {column} >= ? "
                              f"ORDER BY {column}", (since,)).fetchall()
        finally:
            db.close()
        target = Path(target)
        records = []
        for r in rows:
            d = dict(r)
            d.pop("id", None)
            for col in ("first_seen", "last_seen", "ts"):
                if d.get(col):
                    d[col + "_iso"] = time.strftime(
                        "%Y-%m-%dT%H:%M:%S%z", time.localtime(d[col]))
            if what == "connections":
                d["duration_s"] = round(d["last_seen"] - d["first_seen"], 1)
            records.append(d)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.suffix.lower() == ".json":
            target.write_text(json.dumps(records, indent=2), "utf-8")
        else:
            with target.open("w", newline="", encoding="utf-8") as fh:
                if records:
                    writer = csv.DictWriter(fh, fieldnames=list(records[0]))
                    writer.writeheader()
                    writer.writerows(records)
        give_back(target)
        return len(records)
