"""On-demand threat-intelligence, WHOIS and OSINT sources.

Unlike the feeds in ``ti_feeds`` every call here discloses the queried address
(or file hash) to a third party, so they only run when asked for - with the
one exception of the AbuseIPDB auto-check, which the user opted into.

Each source is a function ``(target, ctx) -> SourceResult`` and never raises.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .ti_feeds import USER_AGENT

Http = Callable[[str, Dict[str, str], Optional[bytes], float],
                Tuple[int, bytes]]


def default_http(url: str, headers: Dict[str, str],
                 body: Optional[bytes] = None, timeout: float = 12.0
                 ) -> Tuple[int, bytes]:
    req = urllib.request.Request(
        url, data=body, headers={"User-Agent": USER_AGENT,
                                 "Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(8 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(64 * 1024) if exc.fp else b""


@dataclass
class SourceResult:
    source: str                       # id
    title: str
    kind: str = "ti"                  # ti | whois | osint | process
    status: str = "pending"           # pending|ok|skipped|error|limited|none
    verdict: str = ""                 # malicious|suspicious|clean|info|""
    headline: str = ""                # one line
    facts: List[Tuple[str, str]] = field(default_factory=list)
    link: str = ""
    elapsed: float = 0.0
    data: Dict[str, object] = field(default_factory=dict)


@dataclass
class Ctx:
    keys: Dict[str, str]
    http: Http = default_http
    hostname: str = ""
    port: int = 0


def _fail(r: SourceResult, code: int, body: bytes = b"") -> SourceResult:
    if code in (401, 403):
        r.status, r.headline = "error", "API key rejected"
    elif code == 429:
        r.status, r.headline = "limited", "rate limit / daily quota reached"
    else:
        r.status = "error"
        r.headline = f"HTTP {code} {body[:80].decode('utf-8', 'replace')}"
    return r


def _guard(fn):
    def wrapper(target: str, ctx: Ctx) -> SourceResult:
        start = time.monotonic()
        try:
            r = fn(target, ctx)
        except Exception as exc:                        # noqa: BLE001
            r = SourceResult(fn.source, fn.title, fn.kind, status="error",
                             headline=f"{type(exc).__name__}: {exc}"[:120])
        r.elapsed = time.monotonic() - start
        return r
    return wrapper


def source(ident: str, title: str, kind: str = "ti", key: str = ""):
    def deco(fn):
        fn.source, fn.title, fn.kind, fn.key = ident, title, kind, key
        wrapped = _guard(fn)
        wrapped.source, wrapped.title = ident, title
        wrapped.kind, wrapped.key = kind, key
        return wrapped
    return deco


def _new(fn_or_id, title: str = "", kind: str = "ti") -> SourceResult:
    return SourceResult(fn_or_id, title, kind)


def _need(ctx: Ctx, key: str, r: SourceResult) -> bool:
    if ctx.keys.get(key):
        return True
    r.status = "skipped"
    r.headline = f"no '{key}' API key configured"
    return False


# ---------------------------------------------------------------------------
# threat intelligence
# ---------------------------------------------------------------------------

def abuse_verdict(score: int, whitelisted: bool = False) -> str:
    if whitelisted:
        return "clean"
    if score >= 75:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"


@source("abuseipdb", "AbuseIPDB", key="abuseipdb")
def abuseipdb(ip: str, ctx: Ctx) -> SourceResult:
    r = _new("abuseipdb", "AbuseIPDB")
    r.link = f"https://www.abuseipdb.com/check/{ip}"
    if not _need(ctx, "abuseipdb", r):
        return r
    q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    code, body = ctx.http(f"https://api.abuseipdb.com/api/v2/check?{q}",
                          {"Key": ctx.keys["abuseipdb"]}, None, 12.0)
    if code != 200:
        return _fail(r, code, body)
    d = json.loads(body).get("data") or {}
    score = int(d.get("abuseConfidenceScore") or 0)
    r.status = "ok"
    r.data = {"score": 0 if d.get("isWhitelisted") else score,
              "reports": int(d.get("totalReports") or 0)}
    r.verdict = abuse_verdict(score, bool(d.get("isWhitelisted")))
    r.headline = (f"abuse confidence {score}% — {d.get('totalReports', 0)} "
                  f"report(s) from {d.get('numDistinctUsers', 0)} source(s) "
                  "in 90 days")
    for name, keyname in (("usage", "usageType"), ("isp", "isp"),
                          ("domain", "domain"), ("country", "countryCode"),
                          ("last report", "lastReportedAt")):
        if d.get(keyname):
            r.facts.append((name, str(d[keyname])))
    if d.get("isTor"):
        r.facts.append(("tor", "yes"))
    if d.get("isWhitelisted"):
        r.facts.append(("whitelisted", "yes"))
    return r


@source("virustotal", "VirusTotal", key="virustotal")
def virustotal_ip(ip: str, ctx: Ctx) -> SourceResult:
    r = _new("virustotal", "VirusTotal")
    r.link = f"https://www.virustotal.com/gui/ip-address/{ip}"
    if not _need(ctx, "virustotal", r):
        return r
    code, body = ctx.http(f"https://www.virustotal.com/api/v3/ip_addresses/"
                          f"{urllib.parse.quote(ip)}",
                          {"x-apikey": ctx.keys["virustotal"]}, None, 15.0)
    if code == 404:
        r.status, r.headline = "none", "unknown to VirusTotal"
        return r
    if code != 200:
        return _fail(r, code, body)
    a = (json.loads(body).get("data") or {}).get("attributes") or {}
    return _vt_fill(r, a)


def _vt_fill(r: SourceResult, a: dict) -> SourceResult:
    stats = a.get("last_analysis_stats") or {}
    mal, sus = int(stats.get("malicious") or 0), int(stats.get("suspicious") or 0)
    total = sum(int(v or 0) for v in stats.values())
    r.status = "ok"
    r.verdict = "malicious" if mal >= 5 else \
        "suspicious" if (mal or sus) else "clean"
    r.headline = f"{mal} malicious / {sus} suspicious of {total} engines"
    if a.get("reputation") is not None:
        r.facts.append(("community score", str(a["reputation"])))
    label = (a.get("popular_threat_classification") or {}).get(
        "suggested_threat_label")
    if label:
        r.facts.append(("threat label", label))
    if a.get("meaningful_name"):
        r.facts.append(("known as", str(a["meaningful_name"])))
    if a.get("as_owner"):
        r.facts.append(("as owner", f"{a['as_owner']} (AS{a.get('asn', '?')})"))
    if a.get("tags"):
        r.facts.append(("tags", ", ".join(a["tags"][:8])))
    flagged = [f"{name}: {res.get('result')}"
               for name, res in (a.get("last_analysis_results") or {}).items()
               if res.get("category") in ("malicious", "suspicious")]
    if flagged:
        r.facts.append(("flagged by", "; ".join(flagged[:6])
                        + (f" (+{len(flagged) - 6})" if len(flagged) > 6
                           else "")))
    return r


@source("vt-file", "VirusTotal (process binary hash)", kind="process",
        key="virustotal")
def virustotal_file(sha256: str, ctx: Ctx) -> SourceResult:
    """Only the hash is sent - never the file."""
    r = _new("vt-file", "VirusTotal (process binary hash)", "process")
    r.link = f"https://www.virustotal.com/gui/file/{sha256}"
    if not _need(ctx, "virustotal", r):
        return r
    code, body = ctx.http(f"https://www.virustotal.com/api/v3/files/{sha256}",
                          {"x-apikey": ctx.keys["virustotal"]}, None, 15.0)
    if code == 404:
        r.status = "none"
        r.verdict = "info"
        r.headline = ("hash never seen by VirusTotal — normal for locally "
                      "built tools, notable for anything else")
        return r
    if code != 200:
        return _fail(r, code, body)
    a = (json.loads(body).get("data") or {}).get("attributes") or {}
    return _vt_fill(r, a)


@source("threatfox", "abuse.ch ThreatFox", key="abusech")
def threatfox(ip: str, ctx: Ctx) -> SourceResult:
    r = _new("threatfox", "abuse.ch ThreatFox")
    r.link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ip}"
    if not _need(ctx, "abusech", r):
        return r
    code, body = ctx.http(
        "https://threatfox-api.abuse.ch/api/v1/",
        {"Auth-Key": ctx.keys["abusech"], "Content-Type": "application/json"},
        json.dumps({"query": "search_ioc", "search_term": ip,
                    "exact_match": False}).encode(), 15.0)
    if code != 200:
        return _fail(r, code, body)
    data = json.loads(body)
    status = data.get("query_status")
    if status == "no_result":
        r.status, r.verdict = "ok", "clean"
        r.headline = "no IOC in the last 6 months"
        return r
    if status != "ok":
        r.status, r.headline = "error", str(status)
        return r
    rows = [x for x in data.get("data") or []
            if str(x.get("ioc", "")).split(":")[0].strip("[]") == ip
            or str(x.get("ioc", "")).rpartition(":")[0].strip("[]") == ip]
    if not rows:
        r.status, r.verdict = "ok", "clean"
        r.headline = "no IOC for this exact address"
        return r
    best = max(int(x.get("confidence_level") or 0) for x in rows)
    r.status = "ok"
    r.verdict = "malicious" if best >= 50 else "suspicious"
    families = sorted({str(x.get("malware_printable")) for x in rows
                       if x.get("malware_printable")})
    r.headline = (f"{len(rows)} IOC(s): {', '.join(families[:4]) or 'unknown'}"
                  f" — confidence up to {best}%")
    for x in rows[:5]:
        r.facts.append((str(x.get("ioc")),
                        f"{x.get('threat_type_desc') or x.get('threat_type')}"
                        f" · first seen {x.get('first_seen')}"
                        f" · tags {', '.join(x.get('tags') or []) or '-'}"))
    return r


@source("otx", "AlienVault OTX", key="otx")
def otx(ip: str, ctx: Ctx) -> SourceResult:
    r = _new("otx", "AlienVault OTX")
    section = "IPv6" if ":" in ip else "IPv4"
    r.link = f"https://otx.alienvault.com/indicator/ip/{ip}"
    if not _need(ctx, "otx", r):
        return r
    code, body = ctx.http(f"https://otx.alienvault.com/api/v1/indicators/"
                          f"{section}/{urllib.parse.quote(ip)}/general",
                          {"X-OTX-API-KEY": ctx.keys["otx"]}, None, 15.0)
    if code != 200:
        return _fail(r, code, body)
    d = json.loads(body)
    info = d.get("pulse_info") or {}
    count = int(info.get("count") or 0)
    pulses = info.get("pulses") or []
    r.status = "ok"
    # pulses are community-written and noisy for shared/CDN addresses
    r.verdict = "suspicious" if count >= 3 else "info" if count else "clean"
    r.headline = f"referenced in {count} pulse(s)"
    families = sorted({f.get("display_name") or f.get("id") or ""
                       for p in pulses
                       for f in (p.get("malware_families") or [])} - {""})
    if families:
        r.facts.append(("malware families", ", ".join(families[:8])))
    tags = sorted({t for p in pulses for t in (p.get("tags") or [])})
    if tags:
        r.facts.append(("tags", ", ".join(tags[:12])))
    for p in pulses[:4]:
        r.facts.append(("pulse", f"{p.get('name')} ({str(p.get('modified'))[:10]})"))
    return r


@source("greynoise", "GreyNoise Community")
def greynoise(ip: str, ctx: Ctx) -> SourceResult:
    r = _new("greynoise", "GreyNoise Community")
    r.link = f"https://viz.greynoise.io/ip/{ip}"
    if ":" in ip:
        r.status, r.headline = "skipped", "IPv4 only"
        return r
    headers = {"key": ctx.keys["greynoise"]} if ctx.keys.get("greynoise") \
        else {}
    code, body = ctx.http(f"https://api.greynoise.io/v3/community/{ip}",
                          headers, None, 12.0)
    if code == 404:
        r.status, r.verdict = "ok", ""
        r.headline = "not seen scanning the internet, not a known service"
        return r
    if code != 200:
        return _fail(r, code, body)
    d = json.loads(body)
    cls = str(d.get("classification") or "unknown")
    r.status = "ok"
    if d.get("riot"):
        r.verdict = "clean"
        r.headline = f"known benign service: {d.get('name')}"
    elif cls == "malicious":
        r.verdict = "malicious"
        r.headline = f"internet scanner classified malicious ({d.get('name')})"
    elif d.get("noise"):
        r.verdict = "suspicious" if cls == "unknown" else "info"
        r.headline = f"mass scanner, classification {cls} ({d.get('name')})"
    else:
        r.headline = f"classification {cls}"
    if d.get("last_seen"):
        r.facts.append(("last seen", str(d["last_seen"])))
    return r


# ---------------------------------------------------------------------------
# whois
# ---------------------------------------------------------------------------

def _vcard(entity: dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    card = entity.get("vcardArray") or []
    for item in (card[1] if len(card) > 1 else []):
        if len(item) >= 4 and item[0] in ("fn", "email", "org"):
            out.setdefault(item[0], str(item[3]))
        if len(item) >= 4 and item[0] == "adr":
            label = (item[1] or {}).get("label")
            if label:
                out.setdefault("adr", str(label).replace("\n", ", "))
    return out


def _walk_entities(entities, depth=0):
    for e in entities or []:
        yield e
        if depth < 2:
            yield from _walk_entities(e.get("entities"), depth + 1)


@source("rdap", "RDAP (registry WHOIS)", kind="whois")
def rdap(ip: str, ctx: Ctx) -> SourceResult:
    r = _new("rdap", "RDAP (registry WHOIS)", "whois")
    url = f"https://rdap.org/ip/{urllib.parse.quote(ip)}"
    r.link = url
    code, body = ctx.http(url, {"Accept": "application/rdap+json"}, None, 15.0)
    if code != 200:
        return _fail(r, code, body)
    d = json.loads(body)
    r.status = "ok"
    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
             for c in d.get("cidr0_cidrs") or []]
    rng = ", ".join(cidrs) or f"{d.get('startAddress')} – {d.get('endAddress')}"
    r.headline = f"{d.get('name') or d.get('handle') or '?'} — {rng}"
    for name, key in (("handle", "handle"), ("type", "type"),
                      ("country", "country"), ("parent", "parentHandle")):
        if d.get(key):
            r.facts.append((name, str(d[key])))
    for ev in d.get("events") or []:
        if ev.get("eventAction") in ("registration", "last changed"):
            r.facts.append((ev["eventAction"], str(ev.get("eventDate"))[:10]))
    seen = set()
    for e in _walk_entities(d.get("entities")):
        roles = ", ".join(e.get("roles") or [])
        card = _vcard(e)
        who = card.get("fn") or card.get("org") or e.get("handle") or ""
        line = " · ".join(b for b in (who, card.get("email", ""),
                                      card.get("adr", "")) if b)
        if line and (roles, line) not in seen:
            seen.add((roles, line))
            r.facts.append((roles or "entity", line))
    for rem in (d.get("remarks") or [])[:2]:
        text = " ".join(rem.get("description") or [])[:200]
        if text:
            r.facts.append(("remark", text))
    if d.get("port43"):
        r.facts.append(("whois server", str(d["port43"])))
    return r


_WHOIS_KEYS = ("netname", "orgname", "org-name", "organization", "descr",
               "country", "inetnum", "netrange", "cidr", "route", "origin",
               "originas", "abuse-mailbox", "orgabuseemail", "abuse-c",
               "created", "regdate", "last-modified", "updated", "mnt-by")


def parse_whois(text: str) -> List[Tuple[str, str]]:
    facts: List[Tuple[str, str]] = []
    seen = set()
    for line in text.splitlines():
        if not line or line[0] in "%#" or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key in _WHOIS_KEYS and value and (key, value) not in seen:
            seen.add((key, value))
            facts.append((key, value[:120]))
    return facts[:24]


@source("whois", "whois (command line)", kind="whois")
def whois_cli(ip: str, ctx: Ctx) -> SourceResult:
    r = _new("whois", "whois (command line)", "whois")
    binary = shutil.which("whois")
    if binary and not binary.lower().endswith(".exe"):
        p = subprocess.run([binary, ip], capture_output=True, text=True,
                           timeout=20, errors="replace")
        text = p.stdout
    else:
        # Windows has no whois command: speak the protocol ourselves
        from .win import whois_query
        text = _timed(lambda: whois_query(ip), 25.0, "") or ""
        r.title = "whois (port 43)"
    facts = parse_whois(text)
    if not facts:
        r.status, r.headline = "none", "no usable whois answer"
        return r
    r.status = "ok"
    r.facts = facts
    names = [v for k, v in facts if k in ("netname", "orgname", "org-name",
                                           "organization")]
    r.headline = " / ".join(dict.fromkeys(names)) or facts[0][1]
    return r


# ---------------------------------------------------------------------------
# osint
# ---------------------------------------------------------------------------

@source("internetdb", "Shodan InternetDB", kind="osint")
def internetdb(ip: str, ctx: Ctx) -> SourceResult:
    r = _new("internetdb", "Shodan InternetDB", "osint")
    r.link = f"https://www.shodan.io/host/{ip}"
    code, body = ctx.http(f"https://internetdb.shodan.io/{ip}", {}, None, 12.0)
    if code == 404:
        r.status, r.headline = "none", "host not in Shodan's index"
        return r
    if code != 200:
        return _fail(r, code, body)
    d = json.loads(body)
    ports, vulns = d.get("ports") or [], d.get("vulns") or []
    tags = d.get("tags") or []
    r.status = "ok"
    bad = {"malware", "c2", "compromised", "honeypot"} & set(tags)
    r.verdict = "suspicious" if bad else "info"
    r.headline = (f"{len(ports)} open port(s), {len(vulns)} known CVE(s)"
                  + (f", tags: {', '.join(tags)}" if tags else ""))
    if ports:
        r.facts.append(("open ports", ", ".join(map(str, sorted(ports)[:40]))))
    if d.get("hostnames"):
        r.facts.append(("hostnames", ", ".join(d["hostnames"][:8])))
    if d.get("cpes"):
        r.facts.append(("software", ", ".join(d["cpes"][:8])))
    if vulns:
        r.facts.append(("cves", ", ".join(sorted(vulns)[:12])
                        + (f" (+{len(vulns) - 12})" if len(vulns) > 12 else "")))
    return r


def _timed(fn, seconds: float, default=None):
    """The resolver calls have no timeout of their own and can block for
    minutes on a filtered network; run them on a daemon thread we can
    abandon."""
    import threading

    box = [default]

    def work() -> None:
        try:
            box[0] = fn()
        except Exception:                               # noqa: BLE001
            pass
    th = threading.Thread(target=work, daemon=True)
    th.start()
    th.join(seconds)
    return box[0]


@source("dns", "DNS", kind="osint")
def dns_osint(ip: str, ctx: Ctx) -> SourceResult:
    r = _new("dns", "DNS", "osint")

    def forward(name: str):
        return sorted({a[4][0] for a in socket.getaddrinfo(name, None)})

    ptr = _timed(lambda: socket.gethostbyaddr(ip)[0], 6.0, "") or ""
    r.status = "ok"
    r.facts.append(("ptr", ptr or "none"))
    confirmed = None
    if ptr:
        addrs = _timed(lambda: forward(ptr), 6.0)
        if addrs is None:
            r.facts.append(("forward-confirmed", "PTR does not resolve"))
        else:
            confirmed = ip in addrs
            r.facts.append(("forward-confirmed", "yes" if confirmed else
                            f"NO — {ptr} resolves to {', '.join(addrs[:4])}"))
    if ctx.hostname and ctx.hostname != ptr:
        r.facts.append(("observed name", ctx.hostname))
        addrs = _timed(lambda: forward(ctx.hostname), 6.0)
        if addrs:
            r.facts.append(("resolves to", ", ".join(addrs[:8])))
    r.headline = ptr or "no reverse DNS"
    if ptr and confirmed is False:
        r.verdict = "info"
    return r


def _registrable(host: str) -> str:
    parts = host.rstrip(".").split(".")
    if len(parts) <= 2:
        return host
    # good enough for a search term; crt.sh matches by substring anyway
    two_level = {"co", "com", "org", "net", "gov", "edu", "ac"}
    return ".".join(parts[-3:] if parts[-2] in two_level else parts[-2:])


@source("crtsh", "crt.sh certificate transparency", kind="osint")
def crtsh(ip: str, ctx: Ctx) -> SourceResult:
    r = _new("crtsh", "crt.sh certificate transparency", "osint")
    host = ctx.hostname
    if not host or host.replace(".", "").isdigit():
        r.status, r.headline = "skipped", "no hostname known for this address"
        return r
    domain = _registrable(host)
    r.link = f"https://crt.sh/?q={urllib.parse.quote(domain)}"
    code, body = ctx.http(f"https://crt.sh/?q={urllib.parse.quote(domain)}"
                          "&output=json&exclude=expired", {}, None, 20.0)
    if code != 200:
        return _fail(r, code, body)
    rows = json.loads(body) or []
    r.status = "ok"
    names = sorted({n.strip().lower() for row in rows
                    for n in str(row.get("name_value", "")).split("\n")
                    if n.strip()})
    issuers = sorted({str(row.get("issuer_name", "")).split("O=")[-1]
                      .split(",")[0].strip('" ') for row in rows} - {""})
    first = min((str(row.get("not_before", "")) for row in rows), default="")
    r.headline = (f"{len(rows)} valid certificate(s) for {domain}, "
                  f"{len(names)} name(s)")
    if first:
        r.facts.append(("oldest valid cert", first[:10]))
        # a domain whose first certificate is days old is a classic C2 tell
    if issuers:
        r.facts.append(("issuers", ", ".join(issuers[:5])))
    if names:
        r.facts.append(("names", ", ".join(names[:20])
                        + (f" (+{len(names) - 20})" if len(names) > 20 else "")))
    return r


IP_SOURCES = [abuseipdb, virustotal_ip, threatfox, otx, greynoise,
              rdap, whois_cli, internetdb, dns_osint, crtsh]

KEY_NAMES = {
    "abuseipdb": "AbuseIPDB",
    "virustotal": "VirusTotal",
    "abusech": "abuse.ch (ThreatFox)",
    "otx": "AlienVault OTX",
    "greynoise": "GreyNoise (optional)",
}
