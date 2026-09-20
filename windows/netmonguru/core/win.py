"""Windows backends.

Everything that is macOS-specific in the original (``nettop``, ``log stream``,
``codesign``/``spctl``, ``pfctl``) has a Windows counterpart here:

===========================  ==============================================
feature                      Windows mechanism
===========================  ==============================================
per-connection / per-process TCP extended statistics
throughput                   (``GetPerTcpConnectionEStats``, iphlpapi) -
                             needs an elevated prompt
live DNS                     DNS Client operational event log (names the
                             requesting process; needs admin to enable) or
                             polling ``Get-DnsClientCache`` (no admin)
code signature               Authenticode (``Get-AuthenticodeSignature``),
                             incl. catalog-signed OS binaries
"Gatekeeper"                 Mark-of-the-Web (``Zone.Identifier`` stream)
cut one connection           ``SetTcpEntry`` with ``MIB_TCP_STATE_DELETE_TCB``
                             (IPv4 TCP, needs admin) - closes it at once
===========================  ==============================================

The module imports on any OS: ctypes is only touched on Windows, and every
parser takes plain text so it can be unit-tested anywhere.
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

IS_WINDOWS = sys.platform.startswith("win")

#: no console window flashes up for helper processes
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


# ---------------------------------------------------------------------------
# basics
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:                               # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def config_dir() -> Path:
    if IS_WINDOWS:
        base = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
        return Path(base) / "netmonguru"
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "netmonguru"


def cache_dir() -> Path:
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or \
            (Path.home() / "AppData" / "Local")
        return Path(base) / "netmonguru" / "cache"
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "netmonguru"


PsRunner = Callable[[str, float], Tuple[int, str]]

#: powershell.exe writes piped output in the OEM code page by default, which
#: mangles non-ASCII paths (C:\\Users\\Paweł\\...) - force UTF-8
UTF8 = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "


def powershell(script: str, timeout: float = 25.0) -> Tuple[int, str]:
    """Run a PowerShell snippet, return ``(exit code, stdout or error)``."""
    exe = "powershell" if IS_WINDOWS else "pwsh"
    try:
        p = subprocess.run(
            [exe, "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", UTF8 + script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW, encoding="utf-8", errors="replace")
        return p.returncode, (p.stdout if p.returncode == 0
                              else (p.stderr or p.stdout))
    except Exception as exc:                            # noqa: BLE001
        return 1, str(exc)


def ps_quote(text: str) -> str:
    """Single-quoted PowerShell literal (the only escape is '' for ')."""
    return "'" + str(text).replace("'", "''") + "'"


# ---------------------------------------------------------------------------
# Authenticode
# ---------------------------------------------------------------------------

AUTHENTICODE_SCRIPT = """
$ErrorActionPreference = 'SilentlyContinue'
$paths = @({paths})
$out = foreach ($p in $paths) {{
  $s = Get-AuthenticodeSignature -LiteralPath $p
  [pscustomobject]@{{
    Path = $p
    Status = [string]$s.Status
    Message = [string]$s.StatusMessage
    Subject = [string]$s.SignerCertificate.Subject
    Issuer = [string]$s.SignerCertificate.Issuer
    OSBinary = [bool]$s.IsOSBinary
    Type = [string]$s.SignatureType
  }}
}}
ConvertTo-Json -InputObject @($out) -Compress
"""


def _cn(subject: str) -> str:
    """``CN=Mozilla Corporation, O=...`` -> ``Mozilla Corporation``."""
    for part in subject.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip('" ')
    return subject.strip()


def parse_authenticode(text: str) -> Dict[str, Tuple[str, str, str, str]]:
    """JSON from ``AUTHENTICODE_SCRIPT`` ->
    ``{path: (signing, publisher, issuer, note)}`` where ``signing`` is one of
    ``microsoft | signed | unsigned | invalid | unknown``."""
    out: Dict[str, Tuple[str, str, str, str]] = {}
    try:
        rows = json.loads(text or "[]")
    except ValueError:
        return out
    if isinstance(rows, dict):
        rows = [rows]
    for row in rows or []:
        status = str(row.get("Status") or "")
        subject = str(row.get("Subject") or "")
        publisher = _cn(subject)
        note = ""
        if status == "Valid":
            is_ms = bool(row.get("OSBinary")) or \
                "O=Microsoft Corporation" in subject
            signing = "microsoft" if is_ms else "signed"
            if str(row.get("Type") or "") == "Catalog":
                note = "catalog-signed"
        elif status == "NotSigned":
            signing = "unsigned"
        elif status in ("HashMismatch", "NotTrusted", "UnknownError",
                        "NotSupportedFileFormat", "Incompatible"):
            signing = "invalid" if status in ("HashMismatch", "NotTrusted") \
                else "unknown"
            note = f"{status}: {str(row.get('Message') or '')[:100]}"
        else:
            signing, note = "unknown", status
        out[str(row.get("Path") or "")] = (signing, publisher,
                                           _cn(str(row.get("Issuer") or "")),
                                           note)
    return out


def authenticode(paths: Iterable[str], run: PsRunner = powershell
                 ) -> Dict[str, Tuple[str, str, str, str]]:
    paths = [p for p in dict.fromkeys(paths) if p]
    if not paths:
        return {}
    script = AUTHENTICODE_SCRIPT.format(
        paths=",".join(ps_quote(p) for p in paths))
    code, text = run(script, 40.0)
    return parse_authenticode(text) if code == 0 else {}


def mark_of_the_web(path: str) -> str:
    """Windows tags downloaded files with a ``Zone.Identifier`` stream - the
    closest thing to a Gatekeeper/quarantine verdict."""
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8",
                  errors="replace") as fh:
            text = fh.read(2048)
    except OSError:
        return "no Mark-of-the-Web (not downloaded, or tag removed)"
    return parse_zone_identifier(text)


def parse_zone_identifier(text: str) -> str:
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip().lower()] = value.strip()
    zone = {"0": "local machine", "1": "intranet", "2": "trusted sites",
            "3": "INTERNET", "4": "restricted sites"}.get(
                fields.get("zoneid", ""), fields.get("zoneid", "?"))
    out = f"downloaded — zone {zone}"
    if fields.get("hosturl"):
        out += f", from {fields['hosturl'][:120]}"
    return out


def windows_path_flags(exe: str, env: Optional[Dict[str, str]] = None
                       ) -> List[str]:
    if not exe:
        return []
    env = dict(os.environ) if env is None else env
    low = exe.replace("/", "\\").lower()
    home = (env.get("USERPROFILE") or "").lower()
    flags: List[str] = []
    checks = [
        ((env.get("TEMP") or "").lower(), "runs from %TEMP%"),
        ("\\appdata\\local\\temp\\", "runs from %TEMP%"),
        ("\\windows\\temp\\", "runs from Windows\\Temp"),
        (home + "\\downloads\\" if home else "", "runs from Downloads"),
        (home + "\\desktop\\" if home else "", "runs from Desktop"),
        ("\\users\\public\\", "runs from Users\\Public"),
        ("\\$recycle.bin\\", "runs from the Recycle Bin"),
        ("\\programdata\\", "runs from ProgramData"),
    ]
    for needle, label in checks:
        if needle and needle in low and label not in flags:
            flags.append(label)
            break
    if low.startswith("\\\\"):
        flags.append("runs from a network share")
    name = low.rsplit("\\", 1)[-1]
    system = {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
              "winlogon.exe", "explorer.exe", "smss.exe", "wininit.exe"}
    if name in system and "\\windows\\" not in low:
        flags.append(f"{name} outside the Windows directory (masquerading?)")
    return flags


# ---------------------------------------------------------------------------
# DNS: long-lived PowerShell that prints one JSON document per line
# ---------------------------------------------------------------------------

DNS_LOG = "Microsoft-Windows-DNS-Client/Operational"

DNS_CACHE_SCRIPT = UTF8 + """
$ErrorActionPreference = 'SilentlyContinue'
while ($true) {
  $rows = Get-DnsClientCache | Select-Object Entry, Name, Type, TimeToLive, Data
  if ($rows) { ConvertTo-Json -InputObject @($rows) -Compress }
  [Console]::Out.Flush()
  Start-Sleep -Seconds 4
}
"""

DNS_ETW_SCRIPT = UTF8 + """
$ErrorActionPreference = 'SilentlyContinue'
$last = (Get-Date).AddSeconds(-5)
while ($true) {
  $now = Get-Date
  $ev = Get-WinEvent -FilterHashtable @{LogName='%s'; Id=3008; StartTime=$last}
  $last = $now
  foreach ($e in $ev) {
    $x = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    $o = [pscustomobject]@{ pid = $e.ProcessId; name = $d['QueryName'];
      qtype = $d['QueryType']; status = $d['QueryStatus'];
      results = $d['QueryResults'] }
    ConvertTo-Json -InputObject $o -Compress
  }
  [Console]::Out.Flush()
  Start-Sleep -Seconds 2
}
""" % DNS_LOG

_DNS_TYPES = {1: "A", 5: "CNAME", 12: "PTR", 28: "AAAA", 15: "MX", 16: "TXT",
              33: "SRV", 2: "NS", 6: "SOA", 65: "HTTPS"}


def dns_log_enabled(run: PsRunner = powershell) -> bool:
    code, text = run(f"(Get-WinEvent -ListLog {ps_quote(DNS_LOG)}).IsEnabled",
                     15.0)
    return code == 0 and text.strip().lower() == "true"


def enable_dns_log() -> Tuple[bool, str]:
    """Needs an elevated prompt; the log stays enabled afterwards."""
    try:
        p = subprocess.run(["wevtutil", "sl", DNS_LOG, "/e:true"],
                           capture_output=True, text=True, timeout=15,
                           creationflags=NO_WINDOW)
        return p.returncode == 0, (p.stderr or p.stdout).strip()[:160]
    except Exception as exc:                            # noqa: BLE001
        return False, str(exc)[:160]


def parse_dns_cache_line(line: str) -> List[Tuple[str, str, List[str], int]]:
    """One JSON line from ``DNS_CACHE_SCRIPT`` ->
    ``[(name, rtype, [data], ttl)]`` for address / alias records."""
    try:
        rows = json.loads(line)
    except ValueError:
        return []
    if isinstance(rows, dict):
        rows = [rows]
    out = []
    for row in rows or []:
        rtype = row.get("Type")
        if isinstance(rtype, int):
            rtype = _DNS_TYPES.get(rtype, str(rtype))
        rtype = str(rtype or "").upper()
        name = str(row.get("Entry") or row.get("Name") or "").rstrip(".")
        data = str(row.get("Data") or "").strip()
        if not name or not data or rtype not in ("A", "AAAA", "CNAME"):
            continue
        try:
            ttl = int(row.get("TimeToLive") or 0)
        except (TypeError, ValueError):
            ttl = 0
        out.append((name.lower(), rtype, [data.rstrip(".")], ttl))
    return out


def parse_dns_event_line(line: str
                         ) -> Optional[Tuple[str, str, List[str], int]]:
    """One JSON line from ``DNS_ETW_SCRIPT`` ->
    ``(name, rtype, [addresses], pid)``; ``None`` for failures / no data.

    ``QueryResults`` looks like ``type:  5 edge.example.net;::ffff:1.2.3.4;
    2a00:1450::200e;``."""
    try:
        row = json.loads(line)
    except ValueError:
        return None
    if not isinstance(row, dict):
        return None
    name = str(row.get("name") or "").rstrip(".").lower()
    if not name or str(row.get("status") or "0") not in ("0", ""):
        return None
    answers: List[str] = []
    for token in str(row.get("results") or "").split(";"):
        token = token.strip()
        if not token or token.lower().startswith("type:"):
            continue
        if token.lower().startswith("::ffff:"):
            token = token[7:]
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in token
                             else socket.AF_INET, token)
        except (OSError, ValueError):
            continue
        answers.append(token)
    if not answers:
        return None
    try:
        qtype = _DNS_TYPES.get(int(row.get("qtype") or 1), "A")
    except (TypeError, ValueError):
        qtype = "A"
    if qtype == "A" and all(":" in a for a in answers):
        qtype = "AAAA"
    try:
        pid = int(row.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    return name, qtype, answers, pid


# ---------------------------------------------------------------------------
# TCP extended statistics + SetTcpEntry (ctypes, iphlpapi)
# ---------------------------------------------------------------------------

MIB_TCP_STATE_ESTAB = 5
MIB_TCP_STATE_DELETE_TCB = 12
TCP_ESTATS_DATA = 1                    # TcpConnectionEstatsData
ERROR_ACCESS_DENIED = 5
ERROR_NOT_FOUND = 1168


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [("dwState", ctypes.c_uint32),
                ("dwLocalAddr", ctypes.c_uint32),
                ("dwLocalPort", ctypes.c_uint32),
                ("dwRemoteAddr", ctypes.c_uint32),
                ("dwRemotePort", ctypes.c_uint32)]


class MIB_TCP6ROW(ctypes.Structure):
    # tcpmib.h: State comes FIRST here (unlike MIB_TCP6ROW_OWNER_PID)
    _fields_ = [("State", ctypes.c_uint32),
                ("LocalAddr", ctypes.c_ubyte * 16),
                ("dwLocalScopeId", ctypes.c_uint32),
                ("dwLocalPort", ctypes.c_uint32),
                ("RemoteAddr", ctypes.c_ubyte * 16),
                ("dwRemoteScopeId", ctypes.c_uint32),
                ("dwRemotePort", ctypes.c_uint32)]


class TCP_ESTATS_DATA_RW_v0(ctypes.Structure):
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


class TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
    _fields_ = [("DataBytesOut", ctypes.c_uint64),
                ("DataSegsOut", ctypes.c_uint64),
                ("DataBytesIn", ctypes.c_uint64),
                ("DataSegsIn", ctypes.c_uint64),
                ("SegsOut", ctypes.c_uint64),
                ("SegsIn", ctypes.c_uint64),
                ("SoftErrors", ctypes.c_uint32),
                ("SoftErrorReason", ctypes.c_uint32),
                ("SndUna", ctypes.c_uint32),
                ("SndNxt", ctypes.c_uint32),
                ("SndMax", ctypes.c_uint32),
                ("ThruBytesAcked", ctypes.c_uint64),
                ("RcvNxt", ctypes.c_uint32),
                ("ThruBytesReceived", ctypes.c_uint64)]


def _port(port: int) -> int:
    """The API wants the port in network byte order inside a DWORD."""
    return socket.htons(port & 0xFFFF)


def tcp_row(laddr: str, lport: int, raddr: str, rport: int,
            state: int = MIB_TCP_STATE_ESTAB) -> MIB_TCPROW:
    row = MIB_TCPROW()
    row.dwState = state
    row.dwLocalAddr = struct.unpack("<I", socket.inet_aton(laddr))[0]
    row.dwLocalPort = _port(lport)
    row.dwRemoteAddr = struct.unpack("<I", socket.inet_aton(raddr))[0]
    row.dwRemotePort = _port(rport)
    return row


def tcp6_row(laddr: str, lport: int, raddr: str, rport: int,
             state: int = MIB_TCP_STATE_ESTAB) -> MIB_TCP6ROW:
    row = MIB_TCP6ROW()
    l_host, _, l_scope = laddr.partition("%")
    r_host, _, r_scope = raddr.partition("%")
    row.LocalAddr = (ctypes.c_ubyte * 16)(
        *socket.inet_pton(socket.AF_INET6, l_host))
    row.RemoteAddr = (ctypes.c_ubyte * 16)(
        *socket.inet_pton(socket.AF_INET6, r_host))
    row.dwLocalScopeId = int(l_scope) if l_scope.isdigit() else 0
    row.dwRemoteScopeId = int(r_scope) if r_scope.isdigit() else 0
    row.dwLocalPort = _port(lport)
    row.dwRemotePort = _port(rport)
    row.State = state
    return row


class TcpEStats:
    """Per-connection byte counters.  Collection has to be switched on for
    each connection first; counters then run from that moment on."""

    def __init__(self) -> None:
        self.error = ""
        self.denied = False
        self._enabled: Dict[Tuple, float] = {}
        self._api = None
        if IS_WINDOWS:
            try:
                self._api = ctypes.WinDLL("iphlpapi")
            except Exception as exc:                    # noqa: BLE001
                self.error = f"iphlpapi: {exc}"

    @property
    def available(self) -> bool:
        return self._api is not None

    def _call(self, v6: bool, which: str, *args) -> int:
        name = f"{which}PerTcp{'6' if v6 else ''}ConnectionEStats"
        return int(getattr(self._api, name)(*args))

    def read(self, laddr: str, lport: int, raddr: str, rport: int
             ) -> Optional[Tuple[int, int]]:
        """``(bytes_in, bytes_out)`` or ``None``."""
        if self._api is None or not raddr:
            return None
        v6 = ":" in raddr
        try:
            row = (tcp6_row if v6 else tcp_row)(laddr, lport, raddr, rport)
        except (OSError, ValueError):
            return None
        key = (laddr, lport, raddr, rport)
        if key not in self._enabled:
            rw = TCP_ESTATS_DATA_RW_v0(1)
            rc = self._call(v6, "Set", ctypes.byref(row), TCP_ESTATS_DATA,
                            ctypes.byref(rw), 0, ctypes.sizeof(rw), 0)
            if rc == ERROR_ACCESS_DENIED:
                self.denied = True
                self.error = "run as Administrator for per-process bandwidth"
                return None
            if rc != 0:
                return None
            self._enabled[key] = time.monotonic()
        rod = TCP_ESTATS_DATA_ROD_v0()
        rc = self._call(v6, "Get", ctypes.byref(row), TCP_ESTATS_DATA,
                        None, 0, 0, None, 0, 0,
                        ctypes.byref(rod), 0, ctypes.sizeof(rod))
        if rc != 0:
            self._enabled.pop(key, None)
            return None
        return int(rod.DataBytesIn), int(rod.DataBytesOut)

    def forget(self, live: Iterable[Tuple]) -> None:
        live = set(live)
        for key in [k for k in self._enabled if k not in live]:
            del self._enabled[key]


def close_tcp_connection(laddr: str, lport: int, raddr: str, rport: int
                         ) -> Tuple[bool, str]:
    """Abort one TCP connection in the kernel (the owner sees a reset)."""
    if not IS_WINDOWS:
        return False, "Windows only"
    if ":" in raddr or ":" in laddr:
        return False, ("Windows can only close IPv4 connections this way - "
                       "terminate the process instead")
    try:
        api = ctypes.WinDLL("iphlpapi")
        row = tcp_row(laddr, lport, raddr, rport, MIB_TCP_STATE_DELETE_TCB)
        rc = int(api.SetTcpEntry(ctypes.byref(row)))
    except Exception as exc:                            # noqa: BLE001
        return False, f"SetTcpEntry: {exc}"
    if rc == 0:
        return True, "connection closed (SetTcpEntry)"
    if rc == ERROR_ACCESS_DENIED:
        return False, "access denied - start NetMonGuru as Administrator"
    if rc in (ERROR_NOT_FOUND, 87):
        return False, "connection no longer exists"
    return False, f"SetTcpEntry failed with error {rc}"


# ---------------------------------------------------------------------------
# whois without a whois binary
# ---------------------------------------------------------------------------

def whois_query(target: str, server: str = "whois.iana.org",
                timeout: float = 8.0, hops: int = 3) -> str:
    """Minimal RFC 3912 client that follows ``refer:`` / ``whois:`` lines."""
    text = ""
    seen = set()
    for _ in range(hops):
        if server in seen:
            break
        seen.add(server)
        query = f"n + {target}" if server == "whois.arin.net" else target
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall((query + "\r\n").encode())
            chunks = []
            while True:
                data = s.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if sum(map(len, chunks)) > 512 * 1024:
                    break
        text = b"".join(chunks).decode("utf-8", "replace")
        nxt = ""
        for line in text.splitlines():
            key, _, value = line.partition(":")
            if key.strip().lower() in ("refer", "whois", "referralserver"):
                nxt = value.strip().replace("whois://", "").split(":")[0] \
                    .strip("/")
                break
        if not nxt:
            break
        server = nxt
    return text
