"""``netmonguru --doctor``: check every macOS backend once and say what works.

Several pieces of NetMonGuru lean on tools whose output differs between macOS
releases (``nettop``, ``log stream``, ``codesign``, ``pfctl``).  This runs each
of them the way the app does and reports OK / WARN / FAIL with the reason, so
a problem can be fixed - or reported - without reading a traceback.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time


def run() -> int:
    from . import __version__

    results = []

    def check(name: str, fn) -> None:
        try:
            status, detail = fn()
        except Exception as exc:                        # noqa: BLE001
            status, detail = "FAIL", f"{type(exc).__name__}: {exc}"
        results.append(status)
        print(f"  [{status:<4}] {name:<24} {detail}")

    root = hasattr(os, "geteuid") and os.geteuid() == 0
    print(f"NetMonGuru {__version__} doctor — Python "
          f"{platform.python_version()} on {platform.platform()}\n")

    def _platform():
        if sys.platform == "darwin":
            return "OK", f"macOS {platform.mac_ver()[0]}"
        return "WARN", f"{sys.platform}: NetMonGuru targets macOS"

    def _root():
        return ("OK", "running as root") if root else (
            "WARN", "not root - sockets of other users show '?', no "
                    "connection cut / blocking, fewer process details "
                    "(use sudo)")

    def _deps():
        import psutil
        import textual
        return "OK", (f"textual {textual.__version__}, psutil "
                      f"{psutil.__version__}")

    def _sockets():
        from .core.connections import ConnectionCollector
        c = ConnectionCollector()
        conns = c.collect()
        if not conns:
            return "FAIL", f"no sockets ({'; '.join(c.errors) or 'empty'})"
        owned = sum(1 for x in conns if x.pid)
        return "OK", (f"{len(conns)} sockets via {c.backend}, {owned} with "
                      "an owning process")

    def _nettop():
        from .core.bandwidth import parse_nettop_full
        if not shutil.which("nettop"):
            return "FAIL", "nettop not found - no per-process bandwidth"
        p = subprocess.run(["nettop", "-L", "1", "-x", "-n", "-J",
                            "bytes_in,bytes_out"], capture_output=True,
                           text=True, timeout=15)
        procs, flows = parse_nettop_full(p.stdout)
        if not procs:
            head = " | ".join(p.stdout.splitlines()[:3])[:120]
            return "FAIL", f"could not parse nettop output: {head}"
        bogus = [n for _, n, _, _ in procs.values() if n[:2].isdigit()
                 and ":" in n]
        if bogus:
            return "FAIL", f"timestamps parsed as process names: {bogus[:2]}"
        if not flows:
            return "WARN", (f"{len(procs)} processes but no per-connection "
                            "rows - Bandwidth → connections will be empty")
        return "OK", f"{len(procs)} processes, {len(flows)} connections"

    def _dns():
        if shutil.which("log"):
            return "OK", "log stream available (names the requesting process)"
        if shutil.which("tcpdump"):
            return "WARN", "no `log`; tcpdump works only as root"
        return "WARN", "passive only (reverse lookups)"

    def _codesign():
        from .core.procsig import parse_codesign
        if not shutil.which("codesign"):
            return "FAIL", "codesign not found - SIG column stays empty"
        p = subprocess.run(["codesign", "-dv", "--verbose=2", "/bin/ls"],
                           capture_output=True, text=True, timeout=15)
        signing, authority, _, _ = parse_codesign(
            p.returncode, (p.stdout or "") + (p.stderr or ""))
        if signing != "apple":
            return "FAIL", (f"/bin/ls parsed as {signing!r} "
                            f"({authority or 'no authority'}) - expected apple")
        return "OK", f"/bin/ls → {signing} ({authority})"

    def _spctl():
        if not shutil.which("spctl"):
            return "WARN", "spctl not found - no Gatekeeper line in reports"
        p = subprocess.run(["spctl", "--status"], capture_output=True,
                           text=True, timeout=10)
        return "OK", ((p.stdout or p.stderr).strip() or "present")[:60]

    def _entitlements():
        from .core.macos_ctx import LaunchdIndex, MacContext
        items = LaunchdIndex().items()
        ctx = MacContext().collect(os.getpid(), sys.executable, deep=True)
        return "OK", (f"{len(items)} launchd jobs indexed; this process: "
                      f"{ctx.tree_text[-70:]}")

    def _pf():
        from .core.killer import block_rules, pf_rules
        from .core.models import Connection
        if not shutil.which("pfctl"):
            return "FAIL", "pfctl not found - no connection cut / blocking"
        if not root:
            return "WARN", "pfctl present; rule syntax is checked only as root"
        rules = block_rules(["203.0.113.9"]) + pf_rules(Connection(
            "TCP", "IPv4", "192.0.2.1", 50000, "203.0.113.9", 443))
        # -n = parse only, nothing is loaded
        p = subprocess.run(["pfctl", "-n", "-a", "com.apple/250.NetMonGuru",
                            "-f", "-"], input="\n".join(rules) + "\n",
                           capture_output=True, text=True, timeout=10)
        if p.returncode != 0:
            return "FAIL", f"pf rejects our rules: {p.stderr.strip()[:120]}"
        info = subprocess.run(["pfctl", "-s", "info"], capture_output=True,
                              text=True, timeout=10).stdout
        state = "enabled" if "Status: Enabled" in info else \
            "disabled (enabled on demand)"
        return "OK", f"rule syntax accepted; pf is {state}"

    def _whois():
        return ("OK", "whois available") if shutil.which("whois") else \
            ("WARN", "no whois binary - reports use RDAP only")

    def _notify():
        if not shutil.which("osascript"):
            return "WARN", "osascript not found - no desktop notifications"
        return "OK", "osascript available"

    def _dirs():
        from .core.config import config_dir, data_dir
        for d in (config_dir(), data_dir()):
            d.mkdir(parents=True, exist_ok=True)
            probe = d / ".write-test"
            probe.write_text("ok", "utf-8")
            probe.unlink()
        owner = ""
        if root and os.environ.get("SUDO_UID"):
            st = config_dir().stat()
            if st.st_uid == 0:
                owner = "  (owned by root - run once without sudo is fine, "\
                        "files are handed back to you)"
        return "OK", f"{config_dir()} | {data_dir()}{owner}"

    def _config():
        from .core.config import Config
        cfg = Config.load()
        if cfg.warnings:
            return "WARN", "; ".join(cfg.warnings[:3])
        return "OK", str(cfg.path)

    def _keys():
        from .core.ti import load_keys
        keys, warning = load_keys()
        if warning:
            return "WARN", warning
        return "OK", (", ".join(sorted(keys)) or
                      "none configured - local feeds only")

    def _journal():
        import tempfile
        from pathlib import Path
        from .core.journal import Journal
        j = Journal(Path(tempfile.mkdtemp()) / "probe.db")
        if not j.enabled:
            return "FAIL", j.error
        j.close()
        return "OK", "SQLite journal writable"

    def _network():
        from .core.ti_feeds import default_fetch
        start = time.monotonic()
        raw = default_fetch("https://check.torproject.org/torbulkexitlist",
                            {}, None)
        return "OK", (f"feed download works ({len(raw) // 1024} KB in "
                      f"{time.monotonic() - start:.1f}s)")

    for name, fn in (("platform", _platform), ("privileges", _root),
                     ("python packages", _deps), ("socket table", _sockets),
                     ("nettop (bandwidth)", _nettop), ("live DNS", _dns),
                     ("codesign (SIG)", _codesign), ("Gatekeeper", _spctl),
                     ("process context", _entitlements),
                     ("pf (cut / block)", _pf), ("whois", _whois),
                     ("notifications", _notify), ("folders", _dirs),
                     ("config.toml", _config), ("API keys", _keys),
                     ("journal", _journal), ("outbound HTTPS", _network)):
        check(name, fn)

    failed = results.count("FAIL")
    print(f"\n{len(results) - failed} of {len(results)} checks passed"
          + (" — copy this output into a GitHub issue if something is off."
             if failed else "."))
    return 1 if failed else 0
