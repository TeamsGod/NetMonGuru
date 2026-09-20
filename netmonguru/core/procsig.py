"""Local trust signals about the process behind a connection.

Nothing here leaves the machine: code signature (``codesign``), Gatekeeper
assessment (``spctl``, on demand only - it is slow), where the binary runs
from, and its SHA-256 (hashed locally; only the *hash* is ever looked up, and
only when the user asks for an investigation).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HASH_LIMIT = 300 * 1024 * 1024


@dataclass
class ProcSig:
    pid: Optional[int] = None
    exe: str = ""
    signing: str = "unknown"    # apple|appstore|devid|adhoc|unsigned|invalid|unknown
    authority: str = ""         # leaf authority
    team: str = ""
    identifier: str = ""
    path_flags: List[str] = field(default_factory=list)
    sha256: str = ""
    gatekeeper: str = ""        # filled on demand
    error: str = ""

    @property
    def short(self) -> str:
        return {"apple": "apple", "appstore": "store", "devid": "dev-id",
                "adhoc": "ad-hoc", "unsigned": "UNSIGNED",
                "invalid": "INVALID", "unknown": ""}[self.signing]

    @property
    def verdict(self) -> str:
        """``suspicious`` is reserved for combinations that deserve a look -
        plenty of legitimate developer tools are ad-hoc signed."""
        if self.signing == "invalid":
            return "suspicious"
        if self.signing in ("unsigned", "adhoc") and self.path_flags:
            return "suspicious"
        if self.signing == "unsigned":
            return "info"
        return "clean" if self.signing in ("apple", "appstore", "devid") \
            else ""

    @property
    def signer(self) -> str:
        if self.signing == "apple":
            return "Apple system software"
        bits = [self.authority, f"team {self.team}" if self.team else ""]
        return " · ".join(b for b in bits if b)


# ---------------------------------------------------------------------------

def path_flags(exe: str, home: Optional[str] = None) -> List[str]:
    if not exe:
        return []
    home = home or str(Path.home())
    flags = []
    p = exe
    if p.endswith(" (deleted)") or not os.path.exists(p):
        flags.append("binary deleted from disk")
    for prefix, label in (("/tmp/", "runs from /tmp"),
                          ("/private/tmp/", "runs from /tmp"),
                          ("/var/tmp/", "runs from /var/tmp"),
                          ("/private/var/tmp/", "runs from /var/tmp"),
                          ("/private/var/folders/", "runs from a temp folder"),
                          ("/var/folders/", "runs from a temp folder"),
                          ("/Users/Shared/", "runs from /Users/Shared"),
                          ("/Volumes/", "runs from a mounted volume"),
                          (home + "/Downloads/", "runs from Downloads"),
                          (home + "/Desktop/", "runs from Desktop")):
        if p.startswith(prefix):
            flags.append(label)
            break
    if "/AppTranslocation/" in p:
        flags.append("app translocated (quarantined, never moved)")
    rel = p[len(home):] if p.startswith(home + "/") else p
    if any(part.startswith(".") and part not in (".", "..")
           for part in rel.split("/")[:-1]):
        flags.append("inside a hidden directory")
    return flags


def parse_codesign(returncode: int, output: str) -> Tuple[str, str, str, str]:
    """``codesign -dv --verbose=2`` -> (signing, leaf authority, team, id)."""
    text = output or ""
    if "not signed at all" in text:
        return "unsigned", "", "", ""
    if returncode != 0 and "Authority=" not in text and "Signature=" not in text:
        return "unknown", "", "", ""
    authorities = re.findall(r"^Authority=(.+)$", text, re.M)
    team = (re.search(r"^TeamIdentifier=(.+)$", text, re.M) or [None, ""])[1]
    ident = (re.search(r"^Identifier=(.+)$", text, re.M) or [None, ""])[1]
    if team == "not set":
        team = ""
    leaf = authorities[0] if authorities else ""
    if "Signature=adhoc" in text:
        return "adhoc", "", team, ident
    if leaf == "Software Signing":
        return "apple", leaf, team, ident
    if leaf.startswith("Apple Mac OS Application Signing") or \
            leaf.startswith("TestFlight"):
        return "appstore", leaf, team, ident
    if leaf.startswith("Developer ID Application"):
        return "devid", leaf, team, ident
    if leaf:
        return "devid" if "Apple" in " ".join(authorities[1:]) else "unknown", \
            leaf, team, ident
    return "unknown", "", team, ident


def _bundle_or_exe(exe: str) -> str:
    """Sign checks on the .app bundle see the whole seal, not just Mach-O."""
    m = re.match(r"^(.*?\.app)/Contents/MacOS/[^/]+$", exe)
    return m.group(1) if m else exe


def sha256_of(path: str) -> str:
    try:
        if os.path.getsize(path) > HASH_LIMIT:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:                                   # noqa: BLE001
        return ""


class ProcSigner:
    """Caches by (exe, mtime): codesign costs ~50 ms per binary."""

    def __init__(self, run=subprocess.run) -> None:
        self._run = run
        self.codesign = shutil.which("codesign") or ""
        self.spctl = shutil.which("spctl") or ""
        self._cache: Dict[Tuple[str, float], ProcSig] = {}

    def inspect(self, pid: Optional[int], exe: str, deep: bool = False
                ) -> ProcSig:
        if not exe:
            return ProcSig(pid=pid, error="executable path not readable "
                                          "(needs sudo)")
        try:
            mtime = os.path.getmtime(exe)
        except OSError:
            mtime = -1.0
        cached = self._cache.get((exe, mtime))
        if cached is None:
            cached = ProcSig(exe=exe, path_flags=path_flags(exe))
            if self.codesign and mtime >= 0:
                try:
                    target = _bundle_or_exe(exe)
                    p = self._run([self.codesign, "-dv", "--verbose=2", target],
                                  capture_output=True, text=True, timeout=10)
                    (cached.signing, cached.authority, cached.team,
                     cached.identifier) = parse_codesign(
                        p.returncode, (p.stdout or "") + (p.stderr or ""))
                except Exception as exc:                # noqa: BLE001
                    cached.error = str(exc)[:120]
            elif not self.codesign:
                cached.error = "codesign not available (macOS only)"
            if len(self._cache) > 512:
                self._cache.clear()
            self._cache[(exe, mtime)] = cached
        if deep and not getattr(cached, "_verified", False) and self.codesign \
                and cached.signing not in ("unsigned", "unknown"):
            # sealing check of a whole bundle can take seconds: on demand only
            try:
                v = self._run([self.codesign, "--verify", _bundle_or_exe(exe)],
                              capture_output=True, text=True, timeout=45)
                if v.returncode != 0:
                    cached.signing = "invalid"
                    cached.error = ((v.stderr or "").strip().splitlines()
                                    or [""])[-1][:120]
                cached._verified = True
            except Exception:                           # noqa: BLE001
                pass
        if deep:
            if not cached.sha256 and mtime >= 0:
                cached.sha256 = sha256_of(exe)
            if not cached.gatekeeper and self.spctl and mtime >= 0:
                try:
                    p = self._run([self.spctl, "-a", "-vv", "-t", "exec",
                                   _bundle_or_exe(exe)], capture_output=True,
                                  text=True, timeout=20)
                    out = ((p.stdout or "") + (p.stderr or "")).strip()
                    first = (out.splitlines() or [""])[0].rpartition(": ")[2]
                    src = re.search(r"^source=(.+)$", out, re.M)
                    cached.gatekeeper = (first or (
                        "accepted" if p.returncode == 0 else "rejected")) + (
                        f" — {src[1]}" if src else "")
                except Exception:                       # noqa: BLE001
                    pass
        fields = {k: v for k, v in cached.__dict__.items()
                  if not k.startswith("_")}
        out = ProcSig(**{**fields, "pid": pid,
                         "path_flags": list(cached.path_flags)})
        return out
