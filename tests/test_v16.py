"""1.6: config, journal, alerts / baseline / beaconing, domain IOCs, the
VirusTotal limiter, macOS process context and the persistent blocklist."""

import json
import plistlib
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

from netmonguru.core import config as cfg
from netmonguru.core.alerts import (Alert, AlertEngine, Baseline,
                                    beacon_score, notify_macos)
from netmonguru.core.dnswatch import DNSRecord
from netmonguru.core.journal import Journal, parse_since
from netmonguru.core.killer import BlockList, PfCutter, block_rules
from netmonguru.core.macos_ctx import (LaunchdIndex, parse_entitlements,
                                       parse_hardened, parse_launchd_plist,
                                       parse_lsof_files)
from netmonguru.core.models import Connection, GeoInfo
from netmonguru.core.ti_feeds import FeedStore, looks_generated
from netmonguru.core.ti_sources import RateLimiter
from netmonguru.core.watch import unique_keys
from tests import ti_fakes as F


def conn(lport=50000, raddr="93.184.216.34", rport=443, pname="curl", pid=10,
         state="ESTABLISHED", laddr="10.0.0.2"):
    return Connection("TCP", "IPv4", laddr, lport, raddr, rport, state, pid,
                      pname)


def tmp() -> Path:
    return Path(tempfile.mkdtemp())


class TestConfig(unittest.TestCase):
    def test_parse_types_lists_comments(self):
        values, warnings = cfg.parse('''
            interval = 5            # seconds
            [alerts]
            allowed_countries = ["PL", "DE"]   # trailing
            notify = false
            ignore_processes = ["Back#blaze"]
            [block]
            auto_malicious = true
        ''')
        self.assertEqual(warnings, [])
        c = cfg.Config(values)
        self.assertEqual(c.get("general", "interval"), 5)
        self.assertEqual(c.get("alerts", "allowed_countries"), ["PL", "DE"])
        self.assertEqual(c.get("alerts", "ignore_processes"), ["Back#blaze"])
        self.assertFalse(c.get("alerts", "notify"))
        self.assertTrue(c.get("block", "auto_malicious"))
        self.assertEqual(c.get("journal", "retention_days"), 30)   # default

    def test_typos_warn_but_never_stop_the_app(self):
        values, warnings = cfg.parse("intervall = 3\n[alerts]\nnotify = 7\n"
                                     "[nope]\nx = 1\nbroken line\n")
        self.assertEqual(values, {})
        self.assertEqual(len(warnings), 5)

    def test_template_is_created_and_parses_clean(self):
        path = tmp() / "config.toml"
        c = cfg.Config.load(path)
        self.assertTrue(path.exists())
        self.assertEqual(cfg.parse(path.read_text())[1], [])
        self.assertEqual(c.get("general", "bw_view"), "processes")


class TestJournal(unittest.TestCase):
    def test_lifecycle_enrichment_and_export(self):
        j = Journal(tmp() / "j.db", flush_every=0)
        a, b = conn(1), conn(2, raddr="185.220.101.7", pname="updater")
        keyed = unique_keys([a, b])
        j.observe(keyed, {}, now=1000.0)
        # geo / TI arrive on a later sample and must not be lost
        meta = {keyed[1][0]: {"host": "evil.test", "country": "DE",
                              "ti_level": "malicious", "ti_label": "C2 Emotet",
                              "bytes_in": 5000, "bytes_out": 700}}
        j.observe(keyed, meta, now=1010.0)
        j.observe(keyed[:1], {}, now=1020.0)          # b closed
        rows = j.connections(0)
        self.assertEqual(len(rows), 2)
        bad = next(r for r in rows if r["pname"] == "updater")
        self.assertEqual((bad["closed"], bad["ti_label"], bad["country"],
                          bad["bytes_in"]), (1, "C2 Emotet", "DE", 5000))
        self.assertEqual(bad["last_seen"] - bad["first_seen"], 20.0)
        self.assertEqual(len(j.connections(0, only_flagged=True)), 1)
        self.assertEqual(len(j.connections(0, text="evil")), 1)
        self.assertEqual(len(j.connections(0, text="443")), 2)
        self.assertEqual(j.connections(2000.0), [])

        j.add_alert(Alert(1015.0, "high", "threat", "updater → evil", "C2"))
        j.add_dns([DNSRecord(ts=1001.0, name="evil.test", answers=["1.2.3.4"],
                             client="updater")], {"evil.test": "IOC"})
        out = tmp()
        self.assertEqual(j.export(out / "c.csv", "connections"), 2)
        self.assertIn("C2 Emotet", (out / "c.csv").read_text())
        self.assertEqual(j.export(out / "a.json", "alerts"), 1)
        self.assertEqual(json.loads((out / "a.json").read_text())[0]["kind"],
                         "threat")
        self.assertEqual(j.export(out / "d.csv", "dns"), 1)
        self.assertEqual(j.stats()["connections"], 2)
        j.close()

    def test_crash_leftovers_are_closed_and_old_rows_pruned(self):
        path = tmp() / "j.db"
        j = Journal(path, retention_days=0)
        j.observe(unique_keys([conn(1)]), {}, now=time.time() - 40 * 86400)
        j._db.commit()
        j._db.close()                                  # simulated kill -9
        j2 = Journal(path, retention_days=0)
        self.assertEqual(j2.connections(0)[0]["closed"], 1)
        j2.close()
        j3 = Journal(path, retention_days=30)
        self.assertEqual(j3.connections(0), [])
        j3.close()

    def test_since(self):
        self.assertEqual(parse_since("90m", now=10000), 10000 - 5400)
        self.assertEqual(parse_since("7d", now=1e6), 1e6 - 604800)
        self.assertEqual(parse_since("all"), 0.0)
        with self.assertRaises(ValueError):
            parse_since("yesterday")


class TestBeacon(unittest.TestCase):
    def test_regular_checkins_with_jitter_and_a_miss(self):
        starts = [0, 61, 119, 182, 240, 360, 421, 479]   # one missed beat
        interval, jitter = beacon_score(starts)
        self.assertAlmostEqual(interval, 60, delta=2)
        self.assertLess(jitter, 0.1)

    def test_human_traffic_is_not_a_beacon(self):
        self.assertIsNone(beacon_score([0, 3, 40, 41, 300, 310, 900, 905]))
        self.assertIsNone(beacon_score([0, 60, 120]))             # too few
        self.assertIsNone(beacon_score([i * 2 for i in range(10)]))  # < 5 s


class TestAlerts(unittest.TestCase):
    def engine(self, learned=True, **settings):
        base = Baseline(persist=False, learn_days=0 if learned else 3)
        sent = []
        eng = AlertEngine({"notify": True, **settings}, base,
                          notifier=lambda t, m: sent.append((t, m)) or True)
        return eng, sent

    def run_engine(self, eng, conns, now, verdicts=None, sigs=None, geo=None,
                   procs=None):
        eng.evaluate(unique_keys(conns), verdicts or {}, sigs or {},
                     geo or {}, procs or {}, {}, now)

    def test_first_sample_is_silent_then_novelties_alert_once(self):
        eng, sent = self.engine()
        base = [conn(1), Connection("TCP", "IPv4", "", 22, "", 0, "LISTEN", 1,
                                    "sshd")]
        self.run_engine(eng, base, 100)
        self.assertEqual(eng.snapshot(), [])
        new = base + [conn(2, pname="nc", raddr="203.0.114.9"),
                      Connection("TCP", "IPv4", "", 4444, "", 0, "LISTEN", 66,
                                 "nc")]
        self.run_engine(eng, new, 102)
        kinds = sorted(a.kind for a in eng.snapshot())
        self.assertEqual(kinds, ["new-listener", "new-process"])
        self.run_engine(eng, new, 104)
        self.assertEqual(len(eng.snapshot()), 2, "must not repeat")
        self.assertEqual(len(sent), 2)

    def test_learning_period_records_but_does_not_alert(self):
        eng, _ = self.engine(learned=False)
        self.run_engine(eng, [conn(1)], 100)
        self.run_engine(eng, [conn(1), conn(2, pname="nc")], 102)
        self.assertEqual(eng.snapshot(), [])
        self.assertIn("nc", eng.baseline.processes)

    def test_threat_alert_arrives_even_when_the_verdict_is_late(self):
        eng, sent = self.engine()
        c = conn(1, raddr=F.BAD)
        self.run_engine(eng, [c], 100)
        verdict = {F.BAD: NS(level="malicious", label="C2 Emotet")}
        self.run_engine(eng, [c], 102, verdicts=verdict)
        a = eng.snapshot()[0]
        self.assertEqual((a.kind, a.severity, a.raddr),
                         ("threat", "high", F.BAD))
        self.assertIn("C2 Emotet", sent[0][1])

    def test_unsigned_country_and_ignore_list(self):
        eng, _ = self.engine(allowed_countries=["PL"],
                             ignore_processes=["backup"])
        self.run_engine(eng, [conn(1)], 100)
        geo = {"5.5.5.5": GeoInfo("5.5.5.5", country="Russia",
                                  country_code="RU")}
        sig = {77: NS(verdict="suspicious", signing="unsigned",
                      path_flags=["runs from /tmp"], exe="/tmp/x")}
        self.run_engine(eng, [conn(1), conn(2, "5.5.5.5", pname="x", pid=77),
                              conn(3, "5.5.5.5", pname="backup", pid=78)],
                        102, sigs=sig, geo=geo)
        kinds = sorted(a.kind for a in eng.snapshot())
        self.assertEqual(kinds, ["new-country", "new-process", "unsigned"])
        self.assertTrue(all(a.pname != "backup" for a in eng.snapshot()))

    def test_upload_spike_needs_three_samples(self):
        eng, _ = self.engine(upload_spike_mbps=1.0)
        eng.baseline.upload["rsync"] = 2000.0
        p = {"rsync.5": NS(name="rsync", pid=5, out_rate=5e6)}
        self.run_engine(eng, [conn(1)], 99)            # first sample: quiet
        for i in range(2):
            self.run_engine(eng, [conn(1)], 100 + i, procs=p)
        self.assertEqual([a.kind for a in eng.snapshot()], [])
        self.run_engine(eng, [conn(1)], 103, procs=p)
        self.assertEqual([a.kind for a in eng.snapshot()], ["upload-spike"])
        self.assertLess(eng.baseline.upload["rsync"], 300000,
                        "one spike must not become the new normal")

    def test_beacon_alert(self):
        eng, _ = self.engine()
        self.run_engine(eng, [conn(1)], 0)
        for i in range(8):
            c = conn(1000 + i, raddr="203.0.114.50", pname="agent")
            self.run_engine(eng, [conn(1), c], 100 + i * 30)
            self.run_engine(eng, [conn(1)], 110 + i * 30)
        beacons = [a for a in eng.snapshot() if a.kind == "beacon"]
        self.assertEqual(len(beacons), 1)
        self.assertIn("every ~30s", beacons[0].detail)

    def test_dns_alerts(self):
        eng, _ = self.engine()
        store = FeedStore(keys=F.KEYS, directory=tmp(), fetch=F.fetch)
        store.update_due(force=True)
        recs = [DNSRecord(ts=1, name="cdn.bad.test", answers=["1.2.3.4"],
                          client="updater"),
                DNSRecord(ts=1, name="evil.example", client="x"),
                DNSRecord(ts=1, name="xkqpwzrtvbnmslqd.com", client="y"),
                DNSRecord(ts=1, name="github.com", client="git")]
        labels = eng.evaluate_dns(recs, store.lookup_domain, now=5)
        self.assertEqual(labels, {"cdn.bad.test": "MALWARE-HOST",
                                  "evil.example": "IOC",
                                  "xkqpwzrtvbnmslqd.com": "DGA?"})
        by_kind = {a.kind: a for a in eng.snapshot()}
        self.assertEqual(by_kind["bad-domain"].severity, "high")
        self.assertEqual(by_kind["dga-domain"].severity, "low")
        self.assertIn("parent bad.test listed",
                      [a for a in eng.snapshot()
                       if "cdn.bad.test" in a.subject][0].detail)

    def test_baseline_persists(self):
        path = tmp() / "b.json"
        b = Baseline(path, learn_days=3)
        b.learn(b.processes, "curl")
        b.save()
        again = Baseline(path, learn_days=3)
        self.assertEqual(again.processes, {"curl"})
        self.assertAlmostEqual(again.started, b.started, delta=1)
        self.assertTrue(again.learning)

    def test_notification_is_posted_as_the_user_and_quotes_are_escaped(self):
        calls = []
        notify_macos('a "quoted" title', 'back\\slash', run=lambda cmd, **k:
                     calls.append(cmd))
        script = calls[0][-1]
        self.assertIn('\\"quoted\\"', script)
        self.assertIn("back\\\\slash", script)


class TestDomains(unittest.TestCase):
    def test_lookup_and_address_verdict(self):
        from netmonguru.core.ti import ThreatIntel
        store = FeedStore(keys=F.KEYS, directory=tmp(), fetch=F.fetch)
        store.update_due(force=True)
        self.assertEqual(store.lookup_domain("bad.test").label,
                         "MALWARE-HOST")
        self.assertIsNone(store.lookup_domain("good.test"))
        self.assertIsNone(store.lookup_domain("test"))
        self.assertFalse(looks_generated("d1a2b3c4d5e6f7.cloudfront.net"))

        ti = ThreatIntel(keys={}, http=F.http, feed_store=store,
                         state_dir=tmp(), auto=False)
        c = conn(1, raddr="93.184.216.34")
        ti.submit([c])
        self.assertEqual(ti.verdicts["93.184.216.34"].level, "")
        ti.submit([c], {"93.184.216.34": "cdn.bad.test"})   # name learned
        v = ti.verdicts["93.184.216.34"]
        self.assertEqual((v.level, v.label), ("malicious", "MALWARE-HOST"))
        self.assertIn("cdn.bad.test", v.hits[0].detail)


class TestLimiter(unittest.TestCase):
    def test_fifth_call_waits_for_the_window(self):
        clock = [0.0]
        slept = []

        def sleep(s):
            slept.append(s)
            clock[0] += s
        lim = RateLimiter(4, 60.0, clock=lambda: clock[0], sleep=sleep)
        self.assertTrue(all(lim.acquire() for _ in range(4)))
        self.assertEqual(slept, [])
        self.assertTrue(lim.acquire())
        self.assertAlmostEqual(sum(slept), 60.05, places=2)
        self.assertTrue(all(lim.acquire() for _ in range(3)))
        self.assertFalse(lim.acquire(max_wait=5))     # would exceed the wait


class TestMacContext(unittest.TestCase):
    def test_launchd_index_matches_binary_and_bundle_helpers(self):
        d = tmp()
        (d / "com.evil.agent.plist").write_bytes(plistlib.dumps({
            "Label": "com.evil.agent", "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "ProgramArguments": ["/Users/p/.hidden/agent", "--quiet"]}))
        (d / "com.app.helper.plist").write_bytes(plistlib.dumps({
            "Label": "com.app.helper",
            "Program": "/Applications/App.app/Contents/Library/helper"}))
        (d / "broken.plist").write_bytes(b"not a plist")
        idx = LaunchdIndex([(str(d), "agent for this user")])
        self.assertEqual(len(idx.items()), 2)
        hit = idx.for_exe("/Users/p/.hidden/agent")[0]
        self.assertIn("RunAtLoad, KeepAlive", hit.describe())
        self.assertEqual(
            [i.label for i in
             idx.for_exe("/Applications/App.app/Contents/MacOS/App")],
            ["com.app.helper"])
        self.assertEqual(idx.for_exe("/bin/ls"), [])
        self.assertIsNone(parse_launchd_plist(b"junk", "x", "y"))

    def test_entitlements_with_legacy_binary_header(self):
        xml = plistlib.dumps({
            "com.apple.security.app-sandbox": True,
            "com.apple.security.get-task-allow": True,
            "com.apple.security.cs.disable-library-validation": True,
            "com.apple.security.network.client": False})
        notable, sandboxed = parse_entitlements(b"\xfa\xde\x71\x71\x00\x00"
                                                + xml)
        self.assertTrue(sandboxed)
        self.assertEqual(len(notable), 2)
        self.assertIn("get-task-allow", notable[0])
        self.assertEqual(parse_entitlements(b""), ([], None))

    def test_hardened_runtime_and_open_files(self):
        self.assertTrue(parse_hardened("CodeDirectory v=20500 "
                                       "flags=0x10000(runtime) hashes=1"))
        self.assertFalse(parse_hardened("flags=0x2(adhoc) hashes=3"))
        self.assertIsNone(parse_hardened("no such line"))
        out = ("p42\nf3\ntREG\nn/usr/lib/libobjc.A.dylib\nf4\ntREG\n"
               "n/Users/p/secrets.db\nf5\ntIPv4\nn10.0.0.2:5->1.1.1.1:443\n"
               "f6\ntREG\nn/Users/p/secrets.db\n")
        self.assertEqual(parse_lsof_files(out),
                         ["/Users/p/secrets.db", "/usr/lib/libobjc.A.dylib"])


class TestBlocklist(unittest.TestCase):
    def test_persist_validate_dedupe(self):
        path = tmp() / "blocklist.json"
        bl = BlockList(path)
        self.assertTrue(bl.add("185.220.101.7", "evil.test", "C2 Emotet"))
        self.assertFalse(bl.add("185.220.101.7"))
        with self.assertRaises(ValueError):
            bl.add("1.2.3.4 }\npass all")             # no rule injection
        self.assertEqual(BlockList(path).ips(), ["185.220.101.7"])
        self.assertTrue(bl.remove("185.220.101.7"))
        self.assertEqual(len(BlockList(path)), 0)

    def test_pf_table_is_loaded_with_the_cut_rules_and_released(self):
        calls = []

        def run(cmd, stdin=""):
            calls.append((cmd[1:], stdin))
            return 0, "Token : 42" if cmd[1] == "-E" else ""
        cutter = PfCutter(runner=run, is_root=True, pfctl="/sbin/pfctl")
        cutter.cut(conn(1))
        ok, msg = cutter.set_blocked(["185.220.101.7", "2606:4700::1"])
        self.assertTrue(ok, msg)
        load = [c for c in calls if "-f" in c[0]][-1][1]
        lines = load.strip().splitlines()
        self.assertEqual(lines[0], "table <nmg_block> persist "
                                   "{ 185.220.101.7, 2606:4700::1 }")
        self.assertEqual(len(lines), 5)               # table + 2 + 2 cut rules
        self.assertIn(["-k", "::/0", "-k", "2606:4700::1"],
                      [c[0] for c in calls])
        self.assertEqual(sum(1 for c in calls if c[0] == ["-E"]), 1)

        cutter.set_blocked([])                        # unblock everything
        load = [c for c in calls if "-f" in c[0]][-1][1]
        self.assertNotIn("nmg_block", load)
        cutter.release()
        self.assertEqual(calls[-1][0], ["-X", "42"])
        self.assertEqual(block_rules([]), [])

    def test_keep_on_exit_leaves_the_block_table(self):
        calls = []

        def run(cmd, stdin=""):
            calls.append((cmd[1:], stdin))
            return 0, "Token : 7" if cmd[1] == "-E" else ""
        cutter = PfCutter(runner=run, is_root=True, pfctl="/sbin/pfctl",
                          keep_on_exit=True)
        cutter.set_blocked(["185.220.101.7"])
        cutter.release()
        self.assertFalse(any("-X" in c[0] or "-F" in c[0] for c in calls))

    def test_without_root_nothing_runs(self):
        calls = []
        cutter = PfCutter(runner=lambda *a: calls.append(a) or (0, ""),
                          is_root=False, pfctl="/sbin/pfctl")
        ok, msg = cutter.set_blocked(["1.2.3.4"])
        self.assertFalse(ok)
        self.assertIn("sudo", msg)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
