"""Unit tests for first-seen tracking and the traffic monitor rules."""

import tempfile
import unittest
from pathlib import Path

from netmonguru.core.models import Connection
from netmonguru.core.procs import aggregate, related_processes
from netmonguru.core.watch import (SeenIndex, WatchList, WatchRule,
                                   WatchTracker, unique_keys)


def c(lport=1, pname="curl", raddr="203.0.113.7", rport=443, pid=10,
      proto="TCP", state="ESTABLISHED"):
    return Connection(proto=proto, family="IPv4", laddr="10.0.0.2",
                      lport=lport, raddr=raddr, rport=rport, state=state,
                      pid=pid, pname=pname)


class TestWatch(unittest.TestCase):
    def test_unique_keys_disambiguates_duplicates(self):
        keys = [k for k, _ in unique_keys([c(), c(), c(lport=2)])]
        assert len(set(keys)) == 3
        assert keys[1].endswith("#1")


    def test_first_sample_is_not_new(self):
        idx = SeenIndex()
        assert idx.observe(["a", "b"], now=100) == []
        assert not idx.is_new("a", now=101)
        assert idx.observe(["a", "b", "c"], now=110) == ["c"]
        assert idx.is_new("c", now=115)
        assert not idx.is_new("c", now=200)
        assert idx.seq("c") > idx.seq("b") > idx.seq("a")


    def test_seen_index_forgets_closed_sockets(self):
        idx = SeenIndex()
        idx.observe(["a"], now=1)
        idx.observe(["a", "b"], now=2)
        idx.observe(["a"], now=3)
        assert idx.first_seen("b") == 0.0
        assert idx.observe(["a", "b"], now=4) == ["b"]      # reconnect is new again


    def test_endpoint_rule_survives_reconnect_but_not_other_process(self):
        rule = WatchRule.from_connection(c(lport=5000))
        assert rule.matches(c(lport=5001))
        assert not rule.matches(c(pname="wget"))
        assert not rule.matches(c(rport=80))
        assert not rule.matches(c(raddr="203.0.113.8"))


    def test_host_rule_matches_any_process_and_rotated_ip(self):
        rule = WatchRule.from_connection(c(), "host", hostname="api.example.com")
        assert rule.matches(c(pname="wget", rport=80))
        assert rule.matches(c(raddr="198.51.100.1"), hostname="API.example.com")
        assert not rule.matches(c(raddr="198.51.100.1"), hostname="other.test")


    def test_process_and_listen_rules(self):
        proc = WatchRule.from_connection(c(), "process")
        assert proc.matches(c(raddr="1.2.3.4", rport=22))
        assert not proc.matches(c(pname="ssh"))
        listener = c(lport=8080, raddr="", rport=0, state="LISTEN", pname="nginx")
        rule = WatchRule.from_connection(listener)
        assert rule.scope == "listen" and rule.matches(listener)
        assert not rule.matches(c(lport=8080, pname="nginx"))


    def test_unattributed_socket_rule_does_not_pin_the_question_mark(self):
        rule = WatchRule.from_connection(c(pname="?", pid=None))
        assert rule.pname == ""
        assert rule.matches(c(pname="curl"))


    def test_watchlist_dedup_and_persistence(self):
        tmp_path = Path(tempfile.mkdtemp())
        path = tmp_path / "cfg" / "monitor.json"
        wl = WatchList(path)
        assert wl.add(WatchRule.from_connection(c()))
        assert not wl.add(WatchRule.from_connection(c(lport=99)))   # same rule
        assert wl.add(WatchRule.from_connection(c(), "host"))
        again = WatchList(path)
        assert [r.ident for r in again] == [r.ident for r in wl]
        again.remove(0)
        assert len(WatchList(path)) == 1


    def test_watchlist_tolerates_corrupt_file(self):
        tmp_path = Path(tempfile.mkdtemp())
        path = tmp_path / "monitor.json"
        path.write_text("{not json")
        wl = WatchList(path)
        assert len(wl) == 0 and wl.error


    def test_tracker_history_and_ordering(self):
        wl = WatchList()
        wl.add(WatchRule.from_connection(c()))
        tr = WatchTracker(wl)
        tr.observe(unique_keys([c(lport=1), c(lport=2, pname="other")]), now=10)
        assert [e.conn.lport for e in tr.rows()] == [1]

        tr.observe(unique_keys([c(lport=1), c(lport=3)]), now=20)
        assert [e.conn.lport for e in tr.rows()] == [3, 1]       # newest first

        tr.observe(unique_keys([c(lport=3)]), now=30)
        rows = tr.rows()
        assert [(e.conn.lport, e.closed) for e in rows] == [(3, False), (1, True)]
        assert rows[1].duration == 10
        assert tr.live_count(wl.rules[0]) == 1
        assert tr.totals[wl.rules[0].ident] == 2

        tr.clear_history()
        assert [e.conn.lport for e in tr.rows()] == [3]


    def test_tracker_prune_after_rule_removed(self):
        wl = WatchList()
        wl.add(WatchRule.from_connection(c()))
        wl.add(WatchRule.from_connection(c(pname="ssh", rport=22)))
        tr = WatchTracker(wl)
        tr.observe(unique_keys([c(), c(lport=2, pname="ssh", rport=22)]), now=1)
        assert len(tr.rows()) == 2
        wl.remove(0)
        tr.prune()
        assert [e.conn.pname for e in tr.rows()] == ["ssh"]


    def test_tracker_history_is_bounded(self):
        wl = WatchList()
        wl.add(WatchRule.from_connection(c(), "process"))
        tr = WatchTracker(wl, history=5)
        for i in range(20):
            tr.observe(unique_keys([c(lport=100 + i)]), now=i)
        assert len(tr.rows()) == 6                     # 1 live + 5 closed


    def test_related_processes(self):
        conns = [c(pid=10), c(lport=2, pid=11, pname="wget"),
                 c(lport=3, pid=12, pname="curl", raddr="9.9.9.9"),
                 c(lport=4, pid=13, pname="ssh", raddr="8.8.8.8")]
        rel = related_processes(conns[0], conns, aggregate(conns, {}))
        assert [(r, row.pid) for r, row in rel] == [
            ("owner", 10), ("same peer", 11), ("same app", 12)]


if __name__ == "__main__":
    unittest.main()
