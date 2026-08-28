"""Headless UI smoke test: drives the TUI and saves SVG screenshots."""

from __future__ import annotations

import asyncio
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netmonguru.core.models import GeoInfo                       # noqa: E402
from netmonguru.core.monitor import Monitor                      # noqa: E402
from netmonguru.ui.app import NetMonGuruApp                      # noqa: E402
from netmonguru.ui.widgets.worldmap import WorldMap              # noqa: E402

FAKE_GEO = {
    "142.250.203.110": ("Mountain View", "United States", "US", 37.42, -122.08,
                        "Google LLC", "AS15169 Google LLC",
                        "waw02s16-in-f14.1e100.net"),
    "140.82.121.4": ("San Francisco", "United States", "US", 37.77, -122.41,
                     "GitHub Inc.", "AS36459 GitHub", "lb-140-82-121-4.git"),
    "13.107.42.14": ("Redmond", "United States", "US", 47.67, -122.12,
                     "Microsoft", "AS8075 Microsoft", ""),
    "104.18.32.7": ("Frankfurt", "Germany", "DE", 50.11, 8.68,
                    "Cloudflare", "AS13335 Cloudflare", ""),
    "151.101.1.140": ("London", "United Kingdom", "GB", 51.51, -0.13,
                      "Fastly", "AS54113 Fastly", ""),
    "203.0.113.9": ("Singapore", "Singapore", "SG", 1.35, 103.82,
                    "Example ISP", "AS64496 Example", "jump.example.net"),
    "52.109.8.20": ("Dublin", "Ireland", "IE", 53.34, -6.26,
                    "Microsoft 365", "AS8075 Microsoft", ""),
    "1.1.1.1": ("Sydney", "Australia", "AU", -33.87, 151.21,
                "Cloudflare DNS", "AS13335 Cloudflare", "one.one.one.one"),
    "2606:4700::6810:85e5": ("Warsaw", "Poland", "PL", 52.23, 21.01,
                             "Cloudflare", "AS13335 Cloudflare", ""),
}


def seed(monitor: Monitor) -> None:
    enr = monitor.enricher
    for ip, (city, country, cc, lat, lon, org, asn, host) in FAKE_GEO.items():
        enr.results[ip] = GeoInfo(ip=ip, lat=lat, lon=lon, city=city,
                                  country=country, country_code=cc, org=org,
                                  asn=asn, hostname=host, source="cache")
    enr.home = GeoInfo(ip="203.0.113.1", lat=52.23, lon=21.01, city="Warsaw",
                       country="Poland", country_code="PL", source="cache")


def fake_bandwidth(snap) -> None:
    n = 240
    snap.down_history = [abs(math.sin(i / 9)) * 8e6 + (i % 7) * 2e5
                         for i in range(n)]
    snap.up_history = [abs(math.cos(i / 13)) * 1.6e6 for i in range(n)]
    snap.total_down = snap.down_history[-1]
    snap.total_up = snap.up_history[-1]
    for nic in snap.nics.values():
        nic.down_history = snap.down_history
        nic.up_history = snap.up_history
        nic.down_rate = snap.total_down
        nic.up_rate = snap.total_up


async def main() -> int:
    out = Path("screenshots")
    out.mkdir(exist_ok=True)
    monitor = Monitor(interval=0.5, geo=False, dns=False, demo=True,
                      per_process_bw=True)
    seed(monitor)
    app = NetMonGuruApp(monitor)
    checks = []

    async with app.run_test(size=(150, 44)) as pilot:
        await pilot.pause(0.5)
        monitor.paused = True
        fake_bandwidth(monitor.snapshot)
        app.tick()
        await pilot.pause(0.2)
        app.save_screenshot(str(out / "1-connections.svg"))

        # --- DNS names must reach the connections table -------------------
        assert monitor.snapshot.dns_names, "demo DNS seed did not populate"
        assert any(app._hostname(c.raddr) == "github.com"
                   for c in app.rows), "DNS name not used for remote host"
        checks.append("connections use observed DNS names")

        # --- map ----------------------------------------------------------
        await pilot.press("2")
        await pilot.pause(0.3)
        assert app.query_one("#tabs").active == "tab-map"
        world = app.query_one("#worldmap", WorldMap)
        assert app.map_points, "no map points"
        app.save_screenshot(str(out / "2-map.svg"))   # forces a full paint
        await pilot.pause(0.2)
        assert world._marker_cells, "no clickable marker cells rendered"

        # click the marker furthest from the others (Sydney) by locating its
        # rendered cell and clicking exactly there
        target_idx = max(range(len(app.map_points)),
                         key=lambda i: app.map_points[i].lat * -1)
        cell = next(c for c, i in world._marker_cells.items()
                    if i == target_idx)
        row, col = cell
        await pilot.click(WorldMap, offset=(col, row))
        await pilot.pause(0.3)
        assert world.selected == target_idx, \
            f"click selected {world.selected}, expected {target_idx}"
        assert app.map_detail_rows, "detail table empty after click"
        selected_ips = set(app.map_points[target_idx].ips)
        assert all(c.raddr in selected_ips for c in app.map_detail_rows), \
            "detail rows do not belong to the clicked location"
        checks.append(f"click selects marker {target_idx} "
                      f"({app.map_points[target_idx].label}) and expands "
                      f"{len(app.map_detail_rows)} connection(s)")
        app.save_screenshot(str(out / "2b-map-selected.svg"))

        # clicking empty ocean must not change the selection
        await pilot.click(WorldMap, offset=(2, 2))
        await pilot.pause(0.2)
        assert world.selected == target_idx, "empty click changed selection"
        checks.append("click on empty map area is ignored")

        # the side table stays in sync with the map selection
        geo_table = app.query_one("#geo-table")
        assert geo_table.cursor_row == target_idx, \
            f"geo table cursor {geo_table.cursor_row} != {target_idx}"
        checks.append("destination list follows the map selection")

        # keyboard selection
        await pilot.press("full_stop")
        await pilot.pause(0.2)
        assert world.selected == (target_idx + 1) % len(app.map_points)
        checks.append("keyboard marker cycling works")

        tabs = app.query_one("#tabs")

        await pilot.press("3")
        await pilot.pause(0.3)
        assert tabs.active == "tab-bw", f"tab stuck on {tabs.active}"
        app.save_screenshot(str(out / "3-bandwidth.svg"))

        await pilot.press("4")
        await pilot.pause(0.3)
        assert tabs.active == "tab-proc", f"tab stuck on {tabs.active}"
        app.save_screenshot(str(out / "4-processes.svg"))

        # --- dns pane -----------------------------------------------------
        await pilot.press("5")
        await pilot.pause(0.3)
        assert tabs.active == "tab-dns", f"tab stuck on {tabs.active}"
        checks.append("every pane opens by number key, also after a map click")
        assert app.dns_rows, "no live DNS rows"
        assert app.dns_cache_rows, "no DNS cache rows"
        checks.append(f"DNS pane shows {len(app.dns_rows)} live answers / "
                      f"{len(app.dns_cache_rows)} cached names")
        app.save_screenshot(str(out / "5-dns.svg"))

        # search filters the DNS pane too
        await pilot.press("slash")
        await pilot.pause(0.1)
        for ch in "github":
            await pilot.press(ch)
        await pilot.pause(0.3)
        assert app.dns_cache_rows and all(
            "github" in e.name for e in app.dns_cache_rows), \
            f"dns search failed: {[e.name for e in app.dns_cache_rows]}"
        checks.append("search filters the DNS pane")
        app.save_screenshot(str(out / "5b-dns-search.svg"))
        await pilot.press("escape")
        await pilot.pause(0.2)

        # --- connections filters ------------------------------------------
        await pilot.press("1")
        await pilot.press("u", "e", "s")
        await pilot.pause(0.2)
        assert all(c.proto == "TCP" and c.state == "ESTABLISHED"
                   for c in app.rows), "filters not applied"
        checks.append("protocol/state filters apply")
        await pilot.press("u", "e")
        await pilot.press("slash")
        await pilot.pause(0.1)
        for ch in "firefox":
            await pilot.press(ch)
        await pilot.pause(0.3)
        assert app.rows and all("firefox" in c.pname for c in app.rows)
        checks.append("connection search works")
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert len(app.rows) > 1

        monitor.paused = False
        await pilot.press("space")
        await pilot.pause(0.1)
        assert monitor.paused
        await pilot.press("space")

    monitor.stop()
    for line in checks:
        print("  ok -", line)
    print(f"OK - {len(app.rows)} rows, {len(app.map_points)} map points")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
