"""Unit tests for ending connections (process signals and pf rules)."""

import os
import subprocess
import sys
import unittest

from netmonguru.core.killer import PfCutter, pf_rules, terminate_process
from netmonguru.core.models import Connection


def c(laddr="192.168.1.24", lport=51344, raddr="142.250.203.110", rport=443,
      proto="TCP", family="IPv4"):
    return Connection(proto=proto, family=family, laddr=laddr, lport=lport,
                      raddr=raddr, rport=rport, state="ESTABLISHED", pid=1,
                      pname="x")


class FakePfctl:
    def __init__(self, fail_load=False):
        self.calls = []
        self.fail_load = fail_load

    def __call__(self, cmd, stdin=""):
        self.calls.append((cmd[1:], stdin))
        if cmd[1] == "-E":
            return 0, "pf enabled\nToken : 1234567890"
        if "-f" in cmd and self.fail_load:
            return 1, "stdin:1: syntax error"
        return 0, ""


class TestRules(unittest.TestCase):
    def test_both_directions_exact_tuple(self):
        a, b = pf_rules(c())
        self.assertEqual(a, "block return quick inet proto tcp from "
                            "192.168.1.24 port 51344 to 142.250.203.110 "
                            "port 443")
        self.assertEqual(b, "block return quick inet proto tcp from "
                            "142.250.203.110 port 443 to 192.168.1.24 "
                            "port 51344")

    def test_ipv6_brackets_scope_and_udp(self):
        a, _ = pf_rules(c(laddr="[fe80::1%en0]", raddr="2606:4700::1",
                          proto="UDP", family="IPv6"))
        self.assertIn("inet6 proto udp from fe80::1 port", a)

    def test_wildcard_local(self):
        self.assertIn("from any port 51344", pf_rules(c(laddr="*"))[0])

    def test_rejects_listeners_and_garbage(self):
        with self.assertRaises(ValueError):
            pf_rules(c(raddr="", rport=0))
        with self.assertRaises(ValueError):          # no rule injection
            pf_rules(c(raddr="1.2.3.4 port 1\npass all"))


class TestCutter(unittest.TestCase):
    def test_unavailable_without_root(self):
        fake = FakePfctl()
        cutter = PfCutter(runner=fake, is_root=False, pfctl="/sbin/pfctl")
        ok, msg = cutter.cut(c())
        self.assertFalse(ok)
        self.assertIn("sudo", msg)
        self.assertEqual(fake.calls, [])

    def test_cut_enables_loads_kills_states_and_releases(self):
        fake = FakePfctl()
        cutter = PfCutter(runner=fake, is_root=True, pfctl="/sbin/pfctl")
        ok, _ = cutter.cut(c())
        self.assertTrue(ok)
        self.assertEqual(fake.calls[0][0], ["-E"])
        self.assertEqual(cutter.token, "1234567890")
        load = fake.calls[1]
        self.assertEqual(load[0], ["-a", "com.apple/250.NetMonGuru",
                                   "-f", "-"])
        self.assertEqual(load[1].count("\n"), 2)
        self.assertIn(["-k", "192.168.1.24", "-k", "142.250.203.110"],
                      [x[0] for x in fake.calls])

        # second cut: no second -E, rules accumulate (a load replaces the set)
        cutter.cut(c(lport=51345))
        self.assertEqual(sum(1 for x in fake.calls if x[0] == ["-E"]), 1)
        loads = [x for x in fake.calls if "-f" in x[0]]
        self.assertEqual(loads[-1][1].count("\n"), 4)

        cutter.release()
        tail = [x[0] for x in fake.calls[-2:]]
        self.assertEqual(tail, [["-a", "com.apple/250.NetMonGuru", "-F",
                                 "all"], ["-X", "1234567890"]])
        self.assertEqual(cutter.rules, [])

    def test_failed_load_keeps_state_clean(self):
        cutter = PfCutter(runner=FakePfctl(fail_load=True), is_root=True,
                          pfctl="/sbin/pfctl")
        ok, msg = cutter.cut(c())
        self.assertFalse(ok)
        self.assertIn("syntax error", msg)
        self.assertEqual(cutter.rules, [])


class TestTerminate(unittest.TestCase):
    def test_refuses_dangerous_pids(self):
        for pid in (None, 0, 1, os.getpid(), os.getppid()):
            self.assertFalse(terminate_process(pid)[0])

    def test_terminates_child(self):
        child = subprocess.Popen([sys.executable, "-c",
                                  "import time; time.sleep(60)"])
        try:
            ok, msg = terminate_process(child.pid)
            self.assertTrue(ok, msg)
            self.assertIsNotNone(child.wait(timeout=5))
        finally:
            if child.poll() is None:
                child.kill()


if __name__ == "__main__":
    unittest.main()
