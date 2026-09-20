"""Threat-intelligence manager.

Three jobs, in increasing order of what leaves the machine:

1. **feeds** - match every public peer against locally cached blocklists
   (nothing leaves);
2. **auto-check** - look each new public peer up in AbuseIPDB (opt-out with
   ``--no-ti-auto``; one request per address per 24 h, daily budget);
3. **investigate** - on demand: every configured TI source + WHOIS + OSINT +
   the owning process, collected into a ``Report``.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .models import Connection, is_routable
from .macos_ctx import MacContext, ProcContext
from .procsig import ProcSig, ProcSigner
from .ti_feeds import SEVERITY_RANK, FeedHit, FeedStore
from .util import give_back
from .win import IS_WINDOWS
from .ti_sources import (IP_SOURCES, KEY_NAMES, Ctx, SourceResult,
                         abuse_verdict, abuseipdb, default_http,
                         virustotal_file)

AUTO_TTL = 24 * 3600
AUTO_BUDGET = 900               # AbuseIPDB free tier allows 1000 checks/day
ENV_KEYS = {"abuseipdb": "ABUSEIPDB_KEY", "virustotal": "VT_API_KEY",
            "abusech": "ABUSECH_AUTH_KEY", "otx": "OTX_API_KEY",
            "greynoise": "GREYNOISE_KEY"}


def config_dir() -> Path:
    from .win import config_dir as _config_dir
    return _config_dir()


def cache_dir() -> Path:
    from .win import cache_dir as _cache_dir
    return _cache_dir()


KEYS_TEMPLATE = """# NetMonGuru threat-intelligence API keys.  All optional: a source
# without a key is skipped.  Keep this file private.
#
# abuseipdb  = ""   # https://www.abuseipdb.com/account/api   (1000 checks/day)
# virustotal = ""   # https://www.virustotal.com/gui/my-apikey (500/day, 4/min,
#                   #   public key is for non-commercial use only)
# abusech    = ""   # https://auth.abuse.ch/                   (ThreatFox)
# otx        = ""   # https://otx.alienvault.com/api
# greynoise  = ""   # optional; works without a key at 10 lookups/day
"""


def load_keys(path: Optional[Path] = None) -> Tuple[Dict[str, str], str]:
    """keys.toml (simple ``name = "value"`` lines) overridden by env vars."""
    path = Path(path) if path else config_dir() / "keys.toml"
    keys: Dict[str, str] = {}
    warning = ""
    try:
        if path.exists():
            # POSIX mode bits mean nothing on NTFS: the profile ACL protects it
            if not IS_WINDOWS and path.stat().st_mode & 0o077:
                warning = f"{path} is readable by others - chmod 600 it"
            for line in path.read_text("utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                if "=" not in line:
                    continue
                name, _, value = line.partition("=")
                value = value.strip().strip("\"'")
                if value:
                    keys[name.strip().lower()] = value
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(KEYS_TEMPLATE, "utf-8")
            path.chmod(0o600)
            give_back(path)
    except Exception as exc:                            # noqa: BLE001
        warning = f"keys: {exc}"
    for name, env in ENV_KEYS.items():
        if os.environ.get(env):
            keys[name] = os.environ[env].strip()
    return keys, warning


# ---------------------------------------------------------------------------
# per-address verdict shown in the connections table
# ---------------------------------------------------------------------------

@dataclass
class Verdict:
    ip: str
    level: str = ""                 # malicious|suspicious|info|clean|""
    label: str = ""                 # short text for the TI column
    hits: List[FeedHit] = field(default_factory=list)
    abuse_score: Optional[int] = None
    abuse_reports: int = 0
    abuse_state: str = ""           # ""|pending|ok|error|limited|off
    investigated: str = ""          # overall verdict of a manual report

    def recompute(self) -> "Verdict":
        level, label = "", ""
        if self.hits:
            top = self.hits[0]
            level, label = top.severity, top.label
            if len(self.hits) > 1:
                label += f" +{len(self.hits) - 1}"
        if self.abuse_score is not None:
            a_level = abuse_verdict(self.abuse_score)
            if SEVERITY_RANK[a_level] > SEVERITY_RANK[level]:
                level = a_level
            if a_level != "clean":
                label = (label + " " if label else "") + \
                    f"abuse {self.abuse_score}%"
            elif not label:
                label = "ok"
                level = level or "clean"
        if self.investigated and \
                SEVERITY_RANK.get(self.investigated, 0) > SEVERITY_RANK[level]:
            level = self.investigated
            label = label if label not in ("", "ok") else self.investigated
        if not label and self.abuse_state == "pending":
            label = "…"
        self.level, self.label = level, label
        return self


# ---------------------------------------------------------------------------
# investigation report
# ---------------------------------------------------------------------------

@dataclass
class Report:
    ip: str
    port: int = 0
    proto: str = ""
    hostname: str = ""
    pname: str = ""
    pid: Optional[int] = None
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    feed_hits: List[FeedHit] = field(default_factory=list)
    sources: Dict[str, SourceResult] = field(default_factory=dict)
    process: Optional[ProcSig] = None
    proc_ctx: Optional[ProcContext] = None
    context: List[Tuple[str, str]] = field(default_factory=list)
    note: str = ""
    kind: str = "ip"                # ip | process
    #: process reports: every public peer with its local verdict ...
    peers: List[Tuple[str, int, str, str, str]] = field(default_factory=list)
    #  (ip, port, hostname, level, label)
    #: ... and the full address investigations run for the worst of them
    subs: List["Report"] = field(default_factory=list)

    @property
    def title(self) -> str:
        if self.kind == "process":
            return f"{self.pname or '?'} (pid {self.pid or '?'})"
        return self.ip + (f":{self.port}" if self.port else "")

    @property
    def done(self) -> bool:
        return bool(self.finished)

    @property
    def pending(self) -> int:
        return sum(1 for s in self.sources.values() if s.status == "pending") \
            + sum(sub.pending for sub in self.subs)

    def overall(self) -> Tuple[str, List[str]]:
        """Worst verdict wins; the reasons say who claimed what."""
        level = ""
        reasons: List[str] = []
        for h in self.feed_hits:
            if SEVERITY_RANK[h.severity] >= 2:
                reasons.append(f"{h.label} (local feed)")
            if SEVERITY_RANK[h.severity] > SEVERITY_RANK[level]:
                level = h.severity
        answered = 0
        for s in self.sources.values():
            if s.kind == "ti" and s.status == "ok":
                answered += 1
            if s.verdict in ("malicious", "suspicious"):
                reasons.append(f"{s.title}: {s.headline}")
            if SEVERITY_RANK.get(s.verdict, 0) > SEVERITY_RANK[level]:
                level = s.verdict
        if self.process is not None and self.process.verdict == "suspicious":
            reasons.append("process: " + ", ".join(
                [self.process.short or self.process.signing]
                + self.process.path_flags))
            if SEVERITY_RANK[level] < 2:
                level = "suspicious"
        if self.kind == "process":
            investigated = {sub.ip for sub in self.subs}
            for sub in self.subs:
                sub_level, sub_reasons = sub.overall()
                if sub_level in ("malicious", "suspicious"):
                    reasons.append(f"talks to {sub.title} — {sub_level}: "
                                   + "; ".join(sub_reasons[:2]))
                    if SEVERITY_RANK[sub_level] > SEVERITY_RANK[level]:
                        level = sub_level
                if sub_level == "clean":
                    answered += 1
            for ip, port, _host, p_level, p_label in self.peers:
                if ip in investigated:
                    continue
                if p_level in ("malicious", "suspicious"):
                    reasons.append(f"talks to {ip}:{port} — {p_label}")
                    if SEVERITY_RANK[p_level] > SEVERITY_RANK[level]:
                        level = p_level
            vt = self.sources.get("vt-file")
            if vt is not None and vt.status in ("ok", "none"):
                answered += 1
            if self.process is not None and self.process.verdict == "clean":
                answered += 1
        if level in ("", "info", "clean"):
            level = "clean" if answered else "unknown"
            if not answered:
                reasons.append("no reputation source answered - configure "
                               "API keys for a real verdict")
        return level, reasons

    # -- export ---------------------------------------------------------------
    def to_dict(self) -> dict:
        level, reasons = self.overall()
        return {
            "kind": self.kind,
            "target": {"ip": self.ip, "port": self.port, "proto": self.proto,
                       "hostname": self.hostname},
            "peers": [{"ip": ip, "port": port, "hostname": host,
                       "level": lvl, "label": label}
                      for ip, port, host, lvl, label in self.peers],
            "peer_reports": [sub.to_dict() for sub in self.subs],
            "process": {"name": self.pname, "pid": self.pid,
                        **({k: v for k, v in asdict(self.process).items()
                            if k != "pid"} if self.process else {}),
                        **({"context": asdict(self.proc_ctx)}
                           if self.proc_ctx else {})},
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z",
                                       time.localtime(self.started)),
            "verdict": level, "reasons": reasons,
            "local_context": [list(x) for x in self.context],
            "feed_hits": [asdict(h) for h in self.feed_hits],
            "sources": [{**asdict(s), "facts": [list(f) for f in s.facts]}
                        for s in self.sources.values()],
        }

    def to_markdown(self) -> str:
        level, reasons = self.overall()
        out = [f"# Threat-intel report: {self.title}", ""]
        out += [f"- **Verdict:** {level.upper()}",
                f"- **Generated:** "
                f"{time.strftime('%Y-%m-%d %H:%M:%S %z', time.localtime(self.started))}",
                f"- **Hostname:** {self.hostname or '-'}",
                f"- **Process:** {self.pname or '?'} (pid {self.pid or '?'})",
                ""]
        if reasons:
            out += ["## Why", ""] + [f"- {r}" for r in reasons] + [""]
        if self.context:
            out += ["## Local context", ""] + \
                [f"- **{k}:** {v}" for k, v in self.context] + [""]
        out += ["## Local feeds", ""]
        out += [f"- **{h.label}** ({h.severity}) — {h.detail}"
                for h in self.feed_hits] or ["- no hit in any local feed"]
        out.append("")
        if self.process is not None:
            p = self.process
            out += ["## Process", "",
                    f"- **Executable:** `{p.exe or '?'}`",
                    f"- **Signature:** {p.signing}"
                    + (f" — {p.signer}" if p.signer else ""),
                    f"- **Gatekeeper:** {p.gatekeeper or '-'}",
                    f"- **SHA-256:** `{p.sha256 or '-'}`",
                    f"- **Path flags:** {', '.join(p.path_flags) or 'none'}",
                    ""]
        if self.proc_ctx is not None:
            x = self.proc_ctx
            out += ["## Process context", "",
                    f"- **Process tree:** {x.tree_text or '-'}"]
            if x.children:
                out.append("- **Children:** " + ", ".join(
                    f"{n} ({p})" for p, n in x.children))
            out += [f"- **Persistence:** {i.describe()}"
                    for i in x.persistence] or \
                ["- **Persistence:** no autostart entry starts this binary"]
            if x.hardened is not None:
                out.append(f"- **Hardened runtime:** "
                           f"{'yes' if x.hardened else 'NO'}")
            if x.sandboxed is not None:
                out.append(f"- **App sandbox:** "
                           f"{'yes' if x.sandboxed else 'no'}")
            out += [f"- **Entitlement:** {e}" for e in x.entitlements]
            out += [f"- **Note:** {n}" for n in x.notes]
            if x.open_files:
                out += ["", "Open files:", ""] + \
                    [f"- `{f}`" for f in x.open_files]
            out.append("")
        for kind, title in (("ti", "Threat intelligence"),
                            ("process", "Process reputation"),
                            ("whois", "WHOIS"), ("osint", "OSINT")):
            rows = [s for s in self.sources.values() if s.kind == kind]
            if not rows:
                continue
            out += [f"## {title}", ""]
            for s in rows:
                tag = s.verdict.upper() if s.verdict else s.status
                out.append(f"### {s.title} — {tag}")
                out.append("")
                out.append(s.headline or s.status)
                out += [f"- **{k}:** {v}" for k, v in s.facts]
                if s.link:
                    out.append(f"- <{s.link}>")
                out.append("")
        if self.kind == "process":
            out += ["## Remote peers", "",
                    "| Address | Host | Local verdict |", "|---|---|---|"]
            out += [f"| {ip}:{port} | {host or '-'} | "
                    f"{(lvl or 'no data').upper()} {label} |"
                    for ip, port, host, lvl, label in self.peers] or \
                ["| - | - | no public peers |"]
            out.append("")
            for sub in self.subs:
                out += ["---", "",
                        sub.to_markdown().replace("\n## ", "\n### ")
                        .replace("# Threat-intel report:", "## Peer", 1)]
        return "\n".join(out)


# ---------------------------------------------------------------------------
# manager
# ---------------------------------------------------------------------------

class ThreatIntel:
    def __init__(self, enabled: bool = True, auto: bool = True,
                 keys: Optional[Dict[str, str]] = None,
                 http=default_http, feed_store: Optional[FeedStore] = None,
                 state_dir: Optional[Path] = None,
                 budget: int = AUTO_BUDGET, signer: Optional[ProcSigner] = None,
                 auto_pause: float = 0.4) -> None:
        self.enabled = enabled
        self.key_warning = ""
        if keys is None:
            keys, self.key_warning = load_keys() if enabled else ({}, "")
        self.keys = keys
        self.http = http
        self.auto = enabled and auto
        self.budget = budget
        self.auto_pause = auto_pause
        self.state_dir = Path(state_dir) if state_dir else cache_dir()
        self.feeds = feed_store if feed_store is not None else (
            FeedStore(keys=keys) if enabled else None)
        self.signer = signer or ProcSigner()
        from .win_ctx import make_context
        self.macctx = make_context()

        self.verdicts: Dict[str, Verdict] = {}
        self.procsigs: Dict[int, ProcSig] = {}
        self.reports: List[Report] = []
        self.status = "off" if not enabled else "starting"
        self._feed_gen = -1
        self._auto_cache: Dict[str, dict] = {}
        self._usage = {"day": "", "count": 0}
        # (priority, n, ip): addresses with a feed hit are checked first
        self._queue: "queue.PriorityQueue" = queue.PriorityQueue()
        self._qn = 0
        self._queued: set = set()
        self._pids: Dict[int, str] = {}
        self._names: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._force_feeds = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # separate pools: a report waits on its sources, so sharing one pool
        # could deadlock when several investigations run at once
        self._pool = ThreadPoolExecutor(max_workers=8,
                                        thread_name_prefix="netmonguru-ti")
        self._report_pool = ThreadPoolExecutor(
            max_workers=3, thread_name_prefix="netmonguru-report")
        if enabled:
            self._load_state()

    # -- lifecycle -------------------------------------------------------------
    def start(self) -> None:
        if not self.enabled or self._thread:
            return
        self._thread = threading.Thread(target=self._worker, daemon=True,
                                        name="netmonguru-ti")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._save_state()
        self._pool.shutdown(wait=False, cancel_futures=True)
        self._report_pool.shutdown(wait=False, cancel_futures=True)

    @property
    def auto_active(self) -> bool:
        return self.auto and bool(self.keys.get("abuseipdb"))

    @property
    def auto_left(self) -> int:
        self._roll_day()
        return max(0, self.budget - self._usage["count"])

    def refresh_feeds(self) -> None:
        self._force_feeds.set()

    # -- state -----------------------------------------------------------------
    def _state_path(self) -> Path:
        return self.state_dir / "ti_state.json"

    def _load_state(self) -> None:
        try:
            raw = json.loads(self._state_path().read_text("utf-8"))
            now = time.time()
            self._auto_cache = {ip: e for ip, e in raw.get("abuse", {}).items()
                                if now - e.get("ts", 0) < AUTO_TTL}
            self._usage = raw.get("usage") or self._usage
        except Exception:                               # noqa: BLE001
            pass

    def _save_state(self) -> None:
        if not self.enabled:
            return
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path().with_suffix(".tmp")
            tmp.write_text(json.dumps({"abuse": self._auto_cache,
                                       "usage": self._usage}), "utf-8")
            tmp.replace(self._state_path())
            give_back(self._state_path())
        except Exception:                               # noqa: BLE001
            pass

    def _roll_day(self) -> None:
        today = time.strftime("%Y-%m-%d", time.gmtime())
        if self._usage.get("day") != today:
            self._usage = {"day": today, "count": 0}

    # -- called by the sampler on every snapshot --------------------------------
    def lookup_domain(self, name: str):
        if not self.enabled or self.feeds is None:
            return None
        return self.feeds.lookup_domain(name)

    def submit(self, connections: Iterable[Connection],
               names: Optional[Dict[str, str]] = None) -> None:
        if not self.enabled:
            return
        names = names or {}
        conns = list(connections)
        regen = self.feeds is not None and self.feeds.generation != self._feed_gen
        if regen:
            self._feed_gen = self.feeds.generation
        ports: Dict[str, int] = {}
        for c in conns:
            if c.raddr and is_routable(c.raddr):
                ports.setdefault(c.raddr, c.rport)
            if c.pid and c.pid not in self._pids:
                self._pids[c.pid] = c.pname
        with self._lock:
            for ip, port in ports.items():
                v = self.verdicts.get(ip)
                if v is None:
                    v = self.verdicts[ip] = Verdict(ip)
                    cached = self._auto_cache.get(ip)
                    if cached:
                        v.abuse_score = cached.get("score")
                        v.abuse_reports = cached.get("reports", 0)
                        v.abuse_state = "ok"
                    fresh = True
                else:
                    fresh = False
                name = names.get(ip, "")
                renamed = name != self._names.get(ip, "")
                if (fresh or regen or renamed) and self.feeds is not None:
                    v.hits = self.feeds.lookup(ip, port)
                    self._names[ip] = name
                    # the address may be clean while the *name* is an IOC
                    # (C2 behind a CDN or a fresh VPS)
                    dom = self.feeds.lookup_domain(name) if name else None
                    if dom is not None and dom.feed != "dga":
                        dom.detail = f"{name} — {dom.detail}"
                        v.hits = sorted(
                            v.hits + [dom],
                            key=lambda h: -SEVERITY_RANK[h.severity])
                    if renamed:
                        v.recompute()
                if fresh and v.abuse_score is None and self.auto_active \
                        and ip not in self._queued:
                    v.abuse_state = "pending"
                    self._queued.add(ip)
                    self._qn += 1
                    self._queue.put((0 if v.hits else 1, self._qn, ip))
                if fresh or regen:
                    v.recompute()
            live_pids = {c.pid for c in conns if c.pid}
            for pid in [p for p in self.procsigs if p not in live_pids]:
                self.procsigs.pop(pid, None)
                self._pids.pop(pid, None)

    def snapshot(self) -> Tuple[Dict[str, Verdict], Dict[int, ProcSig]]:
        with self._lock:
            return dict(self.verdicts), dict(self.procsigs)

    # -- background worker -------------------------------------------------------
    def _worker(self) -> None:
        last_save = time.time()
        while not self._stop.is_set():
            try:
                if self.feeds is not None:
                    force = self._force_feeds.is_set()
                    if force or self.feeds.due():
                        self.status = "updating feeds"
                        self._force_feeds.clear()
                        self.feeds.update_due(force=force)
                self._sign_pending()
                self.status = "ok"
                try:
                    ip = self._queue.get(timeout=1.0)[2]
                except queue.Empty:
                    ip = ""
                if ip:
                    self._auto_check(ip)
                    self._stop.wait(self.auto_pause)   # be a polite client
                if time.time() - last_save > 120:
                    self._save_state()
                    last_save = time.time()
            except Exception as exc:                    # noqa: BLE001
                self.status = f"error: {exc}"[:60]
                self._stop.wait(5)

    def _sign_pending(self) -> None:
        todo = [pid for pid in list(self._pids) if pid not in self.procsigs][:8]
        if not todo:
            return
        import psutil

        exes = {}
        for pid in todo:
            try:
                exes[pid] = psutil.Process(pid).exe()
            except Exception:                           # noqa: BLE001
                exes[pid] = ""
        if IS_WINDOWS:
            self.signer.warm([e for e in exes.values() if e])
        for pid in todo:
            exe = exes[pid]
            sig = self.signer.inspect(pid, exe)
            with self._lock:
                self.procsigs[pid] = sig

    def _auto_check(self, ip: str) -> None:
        self._roll_day()
        v = self.verdicts.get(ip)
        if v is None:
            return
        if self._usage["count"] >= self.budget:
            v.abuse_state = "limited"
            v.recompute()
            return
        self._usage["count"] += 1
        r = abuseipdb(ip, Ctx(keys=self.keys, http=self.http))
        with self._lock:
            self._queued.discard(ip)
            self._apply_abuse(v, r)

    def _apply_abuse(self, v: Verdict, r: SourceResult) -> None:
        if r.status == "ok":
            score = int(r.data.get("score") or 0)
            reports = int(r.data.get("reports") or 0)
            v.abuse_score, v.abuse_reports, v.abuse_state = score, reports, "ok"
            self._auto_cache[v.ip] = {"score": score, "reports": reports,
                                      "ts": time.time()}
        else:
            v.abuse_state = r.status
            if r.status == "limited":
                self._usage["count"] = self.budget      # stop asking today
        v.recompute()

    # -- manual investigation ------------------------------------------------------
    def investigate(self, ip: str, port: int = 0, proto: str = "",
                    hostname: str = "", pid: Optional[int] = None,
                    pname: str = "", context: Optional[List[Tuple[str, str]]]
                    = None) -> Report:
        report = Report(ip=ip, port=port, proto=proto, hostname=hostname,
                        pid=pid, pname=pname, context=list(context or []))
        self.reports.insert(0, report)
        del self.reports[50:]
        if not self.enabled:
            report.note = "threat intelligence is disabled (--no-ti)"
            report.finished = time.time()
            return report
        if not is_routable(ip):
            report.note = ("private / local address - nothing to ask public "
                           "sources about")
        if self.feeds is not None:
            report.feed_hits = self.feeds.lookup(ip, port)
        sources = IP_SOURCES if is_routable(ip) else []
        for fn in sources:
            report.sources[fn.source] = SourceResult(fn.source, fn.title,
                                                     fn.kind)
        if pid:
            report.sources["vt-file"] = SourceResult(
                "vt-file", virustotal_file.title, "process")
        self._report_pool.submit(self._run_report, report, sources)
        return report

    def _run_report(self, report: Report, sources) -> None:
        ctx = Ctx(keys=self.keys, http=self.http, hostname=report.hostname,
                  port=report.port)
        futures = {self._pool.submit(fn, report.ip, ctx): fn for fn in sources}

        if report.pid:
            try:
                import psutil
                exe = psutil.Process(report.pid).exe()
            except Exception:                           # noqa: BLE001
                exe = ""
            report.process = self.signer.inspect(report.pid, exe, deep=True)
            try:
                report.proc_ctx = self.macctx.collect(report.pid, exe,
                                                      deep=True)
            except Exception:                           # noqa: BLE001
                pass
            if report.process.sha256:
                report.sources["vt-file"] = virustotal_file(
                    report.process.sha256, ctx)
            else:
                skipped = report.sources["vt-file"]
                skipped.status = "skipped"
                skipped.headline = "binary could not be hashed"

        for fut, fn in futures.items():
            try:
                report.sources[fn.source] = fut.result(timeout=60)
            except Exception as exc:                    # noqa: BLE001
                r = report.sources[fn.source]
                r.status, r.headline = "error", str(exc)[:100]
        report.finished = time.time()

        level, _ = report.overall()
        with self._lock:
            v = self.verdicts.setdefault(report.ip, Verdict(report.ip))
            abuse = report.sources.get("abuseipdb")
            if abuse is not None and abuse.status == "ok":
                self._apply_abuse(v, abuse)
            v.investigated = level if level != "unknown" else ""
            v.recompute()

    # -- process investigation --------------------------------------------------
    def investigate_process(self, pid: Optional[int], pname: str,
                            peers: List[Tuple[str, int, str, str]],
                            context: Optional[List[Tuple[str, str]]] = None,
                            deep_peers: int = 3) -> Report:
        """Everything about one process: binary trust (signature, Gatekeeper,
        hash -> VirusTotal) plus its remote peers.  Every public peer gets its
        local verdict; the ``deep_peers`` most suspect ones get a full address
        investigation (kept small on purpose - free API quotas are tight)."""
        report = Report(ip="", pid=pid, pname=pname, kind="process",
                        context=list(context or []))
        if not self.enabled:
            report.note = "threat intelligence is disabled (--no-ti)"
        seen = set()
        ranked = []
        for ip, port, proto, host in peers:
            if ip in seen or not is_routable(ip):
                continue
            seen.add(ip)
            v = self.verdicts.get(ip)
            level, label = (v.level, v.label) if v is not None else ("", "")
            if v is None and self.feeds is not None:
                hits = self.feeds.lookup(ip, port)
                if hits:
                    level, label = hits[0].severity, hits[0].label
            report.peers.append((ip, port, host, level, label))
            ranked.append((-SEVERITY_RANK.get(level, 0), len(ranked),
                           ip, port, proto, host))
        report.peers.sort(key=lambda p: -SEVERITY_RANK.get(p[3], 0))
        if self.enabled:
            for _, _, ip, port, proto, host in sorted(ranked)[:deep_peers]:
                report.subs.append(self.investigate(
                    ip, port, proto, host, None, pname,
                    [("investigated as", f"peer of {report.title}")]))
            skipped = len(ranked) - len(report.subs)
            if skipped > 0:
                report.note = (f"{len(report.subs)} of {len(ranked)} peers "
                               "fully investigated (worst first) - press i "
                               "on a connection for any other")
            if pid:
                report.sources["vt-file"] = SourceResult(
                    "vt-file", virustotal_file.title, "process")
        self.reports.insert(0, report)
        del self.reports[50:]
        self._report_pool.submit(self._run_process_report, report)
        return report

    def _run_process_report(self, report: Report) -> None:
        if report.pid:
            try:
                import psutil
                exe = psutil.Process(report.pid).exe()
            except Exception:                           # noqa: BLE001
                exe = ""
            report.process = self.signer.inspect(report.pid, exe, deep=True)
            try:
                report.proc_ctx = self.macctx.collect(report.pid, exe,
                                                      deep=True)
            except Exception:                           # noqa: BLE001
                pass
            if "vt-file" in report.sources:
                if report.process.sha256:
                    report.sources["vt-file"] = virustotal_file(
                        report.process.sha256,
                        Ctx(keys=self.keys, http=self.http))
                else:
                    r = report.sources["vt-file"]
                    r.status, r.headline = "skipped", \
                        "binary could not be hashed"
        deadline = time.time() + 120
        while time.time() < deadline and not self._stop.is_set() \
                and any(not sub.done for sub in report.subs):
            time.sleep(0.2)
        report.finished = time.time()

    # -- export to disk ---
    def export(self, report: Report, directory: Optional[Path] = None
               ) -> Tuple[Path, Path]:
        directory = Path(directory) if directory else \
            Path.home() / "netmonguru-reports"
        directory.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(report.started))
        import re as _re
        name = report.ip if report.kind == "ip" else \
            f"process-{report.pname}-{report.pid}"
        stem = f"{_re.sub(r'[^A-Za-z0-9._-]+', '_', name)}-{stamp}"
        md, js = directory / f"{stem}.md", directory / f"{stem}.json"
        md.write_text(report.to_markdown(), "utf-8")
        js.write_text(json.dumps(report.to_dict(), indent=2, default=str),
                      "utf-8")
        give_back(md, js)
        return md, js

    def key_status(self) -> List[Tuple[str, bool]]:
        return [(title, bool(self.keys.get(name)))
                for name, title in KEY_NAMES.items()]
