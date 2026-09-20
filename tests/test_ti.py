"""Unit tests for threat intelligence: feeds, sources, verdicts, reports."""

import tempfile
import time
import unittest
from pathlib import Path

from netmonguru.core.models import Connection
from netmonguru.core.procsig import ProcSig, parse_codesign, path_flags
from netmonguru.core.ti import Report, ThreatIntel, Verdict, load_keys
from netmonguru.core.ti_feeds import FeedHit, FeedStore
from netmonguru.core.ti_sources import (Ctx, SourceResult, abuseipdb, crtsh,
                                        greynoise, internetdb, otx,
                                        parse_whois, rdap, threatfox,
                                        virustotal_file, virustotal_ip)
from tests import ti_fakes as F


def store(keys=F.KEYS, fetch=F.fetch):
    s = FeedStore(keys=keys, directory=Path(tempfile.mkdtemp()), fetch=fetch)
    s.update_due(force=True)
    return s


class TestFeeds(unittest.TestCase):
    def test_all_feeds_parse_and_match(self):
        s = store()
        self.assertEqual({st.status for st in s.feeds.values()}, {"ok"})
        hits = s.lookup(F.BAD, 443)
        self.assertEqual(hits[0].label, "C2 Emotet")
        self.assertEqual(hits[0].severity, "malicious")
        self.assertEqual({h.feed for h in hits}, {"feodo", "tor"})
        self.assertEqual(s.lookup("203.0.113.66", 4444)[0].label,
                         "IOC Cobalt Strike")
        self.assertEqual(s.lookup("45.9.148.77")[0].label, "DROP")
        self.assertIn("45.9.148.0/24", s.lookup("45.9.148.77")[0].detail)
        self.assertEqual(s.lookup("91.92.241.5")[0].label, "BLOCKLIST")
        self.assertEqual(s.lookup(F.GOOD), [])

    def test_port_mismatch_is_called_out(self):
        hit = store().lookup("203.0.113.50", 443)[0]
        self.assertIn("listed for port 8443", hit.detail)

    def test_bogons_in_aggregate_lists_are_ignored(self):
        s = store()
        self.assertEqual(len(s.feeds["firehol"].data.nets), 1)
        self.assertEqual(len(s.feeds["spamhaus"].data.nets), 1)

    def test_keyed_feed_skipped_without_key(self):
        s = store(keys={})
        self.assertIn("needs", s.feeds["threatfox"].status)
        self.assertEqual(s.lookup("203.0.113.66", 4444), [])

    def test_failure_keeps_old_data_and_cache_survives_restart(self):
        s = store()

        def broken(url, headers, body=None):
            raise OSError("network down")
        s.fetch = broken
        self.assertFalse(s.update("feodo"))
        self.assertEqual(s.feeds["feodo"].status, "stale")
        self.assertTrue(s.lookup(F.BAD))
        again = FeedStore(keys=F.KEYS, directory=s.dir, fetch=broken)
        self.assertEqual(again.lookup(F.BAD, 443)[0].label, "C2 Emotet")
        self.assertEqual(again.due(), [])          # fresh cache: no refetch

    def test_html_error_page_is_not_accepted_as_a_feed(self):
        s = FeedStore(keys={}, directory=Path(tempfile.mkdtemp()),
                      fetch=lambda *a: b"<html>blocked</html>")
        self.assertFalse(s.update("tor"))
        self.assertEqual(s.feeds["tor"].status, "error")


class TestSources(unittest.TestCase):
    ctx = Ctx(keys=F.KEYS, http=F.http, hostname="exit.example.net")

    def test_verdicts(self):
        for fn, bad, good in ((abuseipdb, "malicious", "clean"),
                              (virustotal_ip, "malicious", "clean"),
                              (threatfox, "malicious", "clean"),
                              (otx, "suspicious", "clean"),
                              (greynoise, "malicious", "clean")):
            self.assertEqual(fn(F.BAD, self.ctx).verdict, bad, fn.source)
            self.assertEqual(fn(F.GOOD, self.ctx).verdict, good, fn.source)

    def test_missing_key_is_skipped_not_an_error(self):
        r = abuseipdb(F.BAD, Ctx(keys={}, http=F.http))
        self.assertEqual((r.status, r.verdict), ("skipped", ""))

    def test_http_failures(self):
        for code, status in ((429, "limited"), (401, "error"), (500, "error")):
            r = abuseipdb(F.BAD, Ctx(keys=F.KEYS,
                                     http=lambda *a, c=code: (c, b"")))
            self.assertEqual(r.status, status)

        def boom(*a):
            raise TimeoutError("slow")
        self.assertEqual(rdap(F.BAD, Ctx(keys={}, http=boom)).status, "error")

    def test_rdap_whois_osint(self):
        r = rdap(F.BAD, self.ctx)
        self.assertIn("EXAMPLE-NET — 185.220.101.0/24", r.headline)
        self.assertIn(("abuse", "Abuse Desk · abuse@example.net"), r.facts)
        r = internetdb(F.BAD, self.ctx)
        self.assertIn("3 open port(s), 1 known CVE(s)", r.headline)
        self.assertEqual(internetdb(F.GOOD, self.ctx).status, "none")
        r = crtsh(F.BAD, self.ctx)
        self.assertIn("for example.net", r.headline)
        self.assertEqual(crtsh(F.BAD, Ctx(keys={}, http=F.http)).status,
                         "skipped")

    def test_unknown_hash(self):
        r = virustotal_file("ab" * 32, self.ctx)
        self.assertEqual((r.status, r.verdict), ("none", "info"))

    def test_parse_whois(self):
        facts = parse_whois("% comment\ninetnum: 1.2.3.0 - 1.2.3.255\n"
                            "netname: EX\nnetname: EX\nperson: Bob\n"
                            "abuse-mailbox: a@b.c\n")
        self.assertEqual(facts, [("inetnum", "1.2.3.0 - 1.2.3.255"),
                                 ("netname", "EX"),
                                 ("abuse-mailbox", "a@b.c")])


class TestProcSig(unittest.TestCase):
    def test_codesign_parsing(self):
        apple = ("Executable=/usr/bin/ssh\nIdentifier=com.apple.ssh\n"
                 "Authority=Software Signing\nAuthority=Apple Code Signing "
                 "Certification Authority\nAuthority=Apple Root CA\n"
                 "TeamIdentifier=not set\n")
        self.assertEqual(parse_codesign(0, apple)[:3],
                         ("apple", "Software Signing", ""))
        dev = ("Authority=Developer ID Application: Mozilla Corporation "
               "(43AQ936H96)\nAuthority=Developer ID Certification Authority\n"
               "Authority=Apple Root CA\nTeamIdentifier=43AQ936H96\n")
        self.assertEqual(parse_codesign(0, dev)[0], "devid")
        self.assertEqual(parse_codesign(0, dev)[2], "43AQ936H96")
        self.assertEqual(parse_codesign(0, "Signature=adhoc\n")[0], "adhoc")
        self.assertEqual(parse_codesign(
            1, "/tmp/x: code object is not signed at all")[0], "unsigned")
        self.assertEqual(parse_codesign(1, "No such file")[0], "unknown")

    def test_path_flags_and_verdict(self):
        flags = path_flags("/Users/p/Downloads/.cache/upd", home="/Users/p")
        self.assertIn("runs from Downloads", flags)
        self.assertIn("inside a hidden directory", flags)
        self.assertEqual(ProcSig(signing="unsigned",
                                 path_flags=flags).verdict, "suspicious")
        self.assertEqual(ProcSig(signing="adhoc").verdict, "")
        self.assertEqual(ProcSig(signing="devid").verdict, "clean")


class TestManager(unittest.TestCase):
    def engine(self, **kw):
        return ThreatIntel(keys=F.KEYS, http=F.http, feed_store=store(),
                           state_dir=Path(tempfile.mkdtemp()), **kw)

    @staticmethod
    def conn(ip, port=443):
        return Connection("TCP", "IPv4", "10.0.0.2", 50000, ip, port,
                          "ESTABLISHED", None, "curl")

    def test_feed_verdict_is_immediate_and_private_ips_never_leave(self):
        ti = self.engine(auto=False)
        ti.submit([self.conn(F.BAD), self.conn(F.GOOD),
                   self.conn("192.168.1.1")])
        verdicts, _ = ti.snapshot()
        self.assertEqual(verdicts[F.BAD].level, "malicious")
        self.assertEqual(verdicts[F.BAD].label, "C2 Emotet +1")
        self.assertEqual(verdicts[F.GOOD].label, "")
        self.assertNotIn("192.168.1.1", verdicts)
        self.assertTrue(ti._queue.empty())           # auto off: nothing queued

    def test_auto_check_budget_and_cache(self):
        ti = self.engine(budget=1)
        ti.submit([self.conn(F.GOOD), self.conn("8.8.8.8")])
        self.assertEqual(ti.verdicts[F.GOOD].label, "…")
        first, second = ti._queue.get()[2], ti._queue.get()[2]
        ti._auto_check(first)
        ti._auto_check(second)
        self.assertEqual(ti.verdicts[first].label, "ok")
        self.assertEqual(ti.verdicts[second].abuse_state, "limited")
        ti._save_state()
        # a restart must not spend quota on an address checked today
        again = ThreatIntel(keys=F.KEYS, http=F.http, feed_store=ti.feeds,
                            state_dir=ti.state_dir)
        again.submit([self.conn(first)])
        self.assertTrue(again._queue.empty())
        self.assertEqual(again.verdicts[first].label, "ok")

    def test_investigation_report(self):
        ti = self.engine(auto=False)
        r = ti.investigate(F.BAD, 443, "TCP", "exit.example.net",
                           context=[("connection", "x")])
        deadline = time.time() + 20
        while not r.done and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(r.done)
        level, reasons = r.overall()
        self.assertEqual(level, "malicious")
        self.assertTrue(any("C2 Emotet" in x for x in reasons))
        self.assertTrue(any("AbuseIPDB" in x for x in reasons))
        self.assertEqual(ti.verdicts[F.BAD].abuse_score, 100)
        md, js = ti.export(r, Path(tempfile.mkdtemp()))
        text = md.read_text()
        self.assertIn("**Verdict:** MALICIOUS", text)
        self.assertIn("abuse@example.net", text)
        self.assertIn('"verdict": "malicious"', js.read_text())
        ti.stop()

    def test_no_sources_means_unknown_not_clean(self):
        r = Report(ip="1.2.3.4")
        r.sources["abuseipdb"] = SourceResult("abuseipdb", "AbuseIPDB",
                                              status="skipped")
        r.finished = 1
        self.assertEqual(r.overall()[0], "unknown")

    def test_private_address_is_not_sent_anywhere(self):
        ti = self.engine(auto=False)
        r = ti.investigate("192.168.1.10")
        time.sleep(0.3)
        self.assertEqual(r.sources, {})
        self.assertIn("private", r.note)
        ti.stop()

    def test_verdict_label_combinations(self):
        v = Verdict("x", hits=[FeedHit("spamhaus", "DROP", "suspicious")],
                    abuse_score=80).recompute()
        self.assertEqual((v.level, v.label), ("malicious", "DROP abuse 80%"))
        v = Verdict("x", abuse_score=0).recompute()
        self.assertEqual((v.level, v.label), ("clean", "ok"))

    def test_keys_file_and_env(self):
        import os
        path = Path(tempfile.mkdtemp()) / "keys.toml"
        keys, _ = load_keys(path)
        self.assertEqual(keys, {})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)  # template made
        path.write_text('abuseipdb = "abc"  # mine\n# otx = "no"\n')
        path.chmod(0o644)
        os.environ["VT_API_KEY"] = "fromenv"
        try:
            keys, warn = load_keys(path)
        finally:
            del os.environ["VT_API_KEY"]
        self.assertEqual(keys, {"abuseipdb": "abc", "virustotal": "fromenv"})
        self.assertIn("chmod 600", warn)


if __name__ == "__main__":
    unittest.main()
