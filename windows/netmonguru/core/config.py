"""User configuration: ``~/.config/netmonguru/config.toml``.

Command-line flags always win; the file only changes the defaults.  The file
is a small TOML subset (sections, strings, numbers, booleans, flat lists), so
it parses the same on Python 3.9 (no ``tomllib``) and on newer versions.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .util import give_back

DEFAULTS: Dict[str, Dict[str, Any]] = {
    "general": {
        "interval": 2.0,
        "bw_view": "processes",          # processes | connections | interfaces
        "sort": "newest",                # newest|process|proto|state|remote|country|pid
        "show_listening": True,
        "show_private": True,
    },
    "ti": {
        "enabled": True,
        "auto_abuseipdb": True,
        "abuseipdb_daily_budget": 900,
        "virustotal_per_minute": 4,
        "deep_peers": 3,
    },
    "alerts": {
        "enabled": True,
        "notify": True,                  # desktop notification
        "min_notify_severity": "medium", # low | medium | high
        "cooldown_minutes": 60,
        "allowed_countries": [],         # ISO codes; empty = learn from baseline
        "upload_spike_mbps": 8.0,        # floor for the upload-spike alert
        "ignore_processes": [],
    },
    "baseline": {
        "learn_days": 3,
    },
    "journal": {
        "enabled": True,
        "retention_days": 30,
        "record_dns": True,
    },
    "block": {
        "auto_malicious": False,         # block a peer the feeds call malicious
        "keep_on_exit": False,           # leave pf rules loaded after quitting
    },
}

TEMPLATE = """# NetMonGuru configuration.  Every line is optional - delete what you do
# not want to change.  Command-line flags override this file.

[general]
# interval = 2.0              # seconds between samples
# bw_view = "processes"       # processes | connections | interfaces
# sort = "newest"             # newest | process | proto | state | remote | country | pid
# show_listening = true
# show_private = true

[ti]
# enabled = true
# auto_abuseipdb = true       # look every new public peer up (needs a key)
# abuseipdb_daily_budget = 900
# virustotal_per_minute = 4   # the public API allows 4
# deep_peers = 3              # peers fully investigated in a process report

[alerts]
# enabled = true
# notify = true               # desktop notifications (Windows toasts)
# min_notify_severity = "medium"
# cooldown_minutes = 60       # the same alert is not repeated sooner
# allowed_countries = ["PL", "DE", "US"]   # empty = learned from the baseline
# upload_spike_mbps = 8.0
# ignore_processes = ["Backblaze", "rsync"]

[baseline]
# learn_days = 3              # how long "normal" is learned before alerting

[journal]
# enabled = true
# retention_days = 30
# record_dns = true

[block]
# auto_malicious = false      # block peers the local feeds call malicious
# keep_on_exit = false        # keep the firewall block rules after quitting
"""


def config_dir() -> Path:
    from .win import config_dir as _config_dir
    return _config_dir()                 # %APPDATA%\\netmonguru on Windows


def data_dir() -> Path:
    from .win import IS_WINDOWS
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or \
            (Path.home() / "AppData" / "Local")
        return Path(base) / "netmonguru" / "data"
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "netmonguru"


def _value(text: str) -> Any:
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [_value(p) for p in _split_list(inner)] if inner else []
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    low = text.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def _split_list(inner: str) -> List[str]:
    parts, buf, quote = [], "", ""
    for ch in inner:
        if quote:
            buf += ch
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            buf += ch
        elif ch == ",":
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf)
    return parts


def _strip_comment(line: str) -> str:
    out, quote = "", ""
    for ch in line:
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            break
        out += ch
    return out.strip()


def parse(text: str) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """-> (values by section, warnings).  Unknown keys are reported, never
    fatal: a typo must not stop a monitoring tool from starting."""
    found: Dict[str, Dict[str, Any]] = {}
    warnings: List[str] = []
    section = "general"
    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw)
        if not line:
            continue
        if line.startswith("[") and line.endswith("]") and "=" not in line:
            section = line[1:-1].strip().lower()
            if section not in DEFAULTS:
                warnings.append(f"line {n}: unknown section [{section}]")
            continue
        key, sep, value = line.partition("=")
        key = key.strip().lower()
        if not sep:
            warnings.append(f"line {n}: expected key = value")
            continue
        if section not in DEFAULTS or key not in DEFAULTS[section]:
            warnings.append(f"line {n}: unknown setting {section}.{key}")
            continue
        parsed = _value(value)
        default = DEFAULTS[section][key]
        if isinstance(default, bool) != isinstance(parsed, bool) or (
                isinstance(default, list) != isinstance(parsed, list)) or (
                isinstance(default, (int, float))
                and not isinstance(default, bool)
                and not isinstance(parsed, (int, float))):
            warnings.append(f"line {n}: {section}.{key} should be "
                            f"{type(default).__name__}, keeping the default")
            continue
        found.setdefault(section, {})[key] = parsed
    return found, warnings


class Config:
    def __init__(self, values: Dict[str, Dict[str, Any]] = None,
                 warnings: List[str] = None, path: Path = None) -> None:
        self.values = {s: dict(d) for s, d in DEFAULTS.items()}
        for section, items in (values or {}).items():
            self.values.setdefault(section, {}).update(items)
        self.warnings = list(warnings or [])
        self.path = path

    def get(self, section: str, key: str) -> Any:
        return self.values[section][key]

    def section(self, name: str) -> Dict[str, Any]:
        return self.values[name]

    @classmethod
    def load(cls, path: Path = None, create: bool = True) -> "Config":
        path = Path(path) if path else config_dir() / "config.toml"
        try:
            if path.exists():
                values, warnings = parse(path.read_text("utf-8"))
                return cls(values, warnings, path)
            if create:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(TEMPLATE, "utf-8")
                give_back(path)
        except Exception as exc:                        # noqa: BLE001
            return cls(warnings=[f"config: {exc}"], path=path)
        return cls(path=path)
