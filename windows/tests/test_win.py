"""Windows backends: parsers, struct layout, collectors (run on any OS)."""

import ctypes
import json
import unittest

from netmonguru.core import win
from netmonguru.core.bandwidth import WindowsNetCollector, flow_key
from netmonguru.core.killer import WinCutter, make_cutter
from netmonguru.core.models import Connection, FlowNet
from netmonguru.core.procsig import ProcSigner


class TestStructs(unittest.TestCase):
    def test_sizes_match_the_windows_sdk(self):
        self.assertEqual(ctypes.sizeof(win.MIB_TCPROW), 20)
        self.assertEqual(ctypes.sizeof(win.MIB_TCP6ROW), 52)
        self.assertEqual(win.MIB_TCP6ROW.State.offset, 0)
        self.assertEqual(ctypes.sizeof(win.TCP_ESTATS_DATA_RW_v0), 1)
        self.assertEqual(ctypes.sizeof(win.TCP_ESTATS_DATA_ROD_v0), 96)
        self.assertEqual(win.TCP_ESTATS_DATA_ROD_v0.DataBytesIn.offset, 16)
        self.assertEqual(win.TCP_ESTATS_DATA_ROD_v0.ThruBytesAcked.offset, 72)

    def test_rows_use_network_byte_order(self):
        row = win.tcp_row("192.168.1.24", 51344, "142.250.203.110", 443)
        self.assertEqual(bytes(row)[4:8], bytes([192, 168, 1, 24]))
        self.assertEqual(bytes(row)[8:10], (51344).to_bytes(2, "big"))
        self.assertEqual(bytes(row)[12:16], bytes([142, 250, 203, 110]))
        self.assertEqual(bytes(row)[16:18], (443).to_bytes(2, "big"))
        self.assertEqual(row.dwState, win.MIB_TCP_STATE_ESTAB)
        six = win.tcp6_row("fe80::1%12", 5000, "2606:4700::1", 443)
        self.assertEqual(six.dwLocalScopeId, 12)
        self.assertEqual(bytes(six.RemoteAddr)[:4], bytes([0x26, 6, 0x47, 0]))
        self.assertEqual(bytes(six)[48:50], (443).to_bytes(2, "big"))
        self.assertEqual(bytes(six)[24:26], (5000).to_bytes(2, "big"))


class TestAuthenticode(unittest.TestCase):
    ROWS = json.dumps([
        {"Path": r"C:\Windows\System32\svchost.exe", "Status": "Valid",
         "Subject": "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond",
         "Issuer": "CN=Microsoft Windows Production PCA 2011, O=Microsoft",
         "OSBinary": True, "Type": "Catalog"},
        {"Path": r"C:\Program Files\Mozilla Firefox\firefox.exe",
         "Status": "Valid", "OSBinary": False, "Type": "Authenticode",
         "Subject": 'CN="Mozilla Corporation", O=Mozilla Corporation, C=US',
         "Issuer": "CN=DigiCert Trusted G4 Code Signing, O=DigiCert"},
        {"Path": r"C:\Users\p\Downloads\upd.exe", "Status": "NotSigned",
         "Subject": "", "Issuer": "", "OSBinary": False, "Type": "None"},
        {"Path": r"C:\x\patched.exe", "Status": "HashMismatch",
         "Message": "The contents of the file might have been changed",
         "Subject": "CN=Vendor", "Issuer": "CN=CA", "OSBinary": False},
    ])

    def test_classification(self):
        got = win.parse_authenticode(self.ROWS)
        self.assertEqual(got[r"C:\Windows\System32\svchost.exe"][:2],
                         ("microsoft", "Microsoft Windows"))
        self.assertEqual(got[r"C:\Windows\System32\svchost.exe"][3],
                         "catalog-signed")
        self.assertEqual(
            got[r"C:\Program Files\Mozilla Firefox\firefox.exe"][:2],
            ("signed", "Mozilla Corporation"))
        self.assertEqual(got[r"C:\Users\p\Downloads\upd.exe"][0], "unsigned")
        self.assertEqual(got[r"C:\x\patched.exe"][0], "invalid")

    def test_single_object_and_garbage(self):
        one = json.dumps({"Path": "a.exe", "Status": "Valid", "Subject": "CN=X"})
        self.assertEqual(win.parse_authenticode(one)["a.exe"][0], "signed")
        self.assertEqual(win.parse_authenticode("not json"), {})

    def test_paths_with_quotes_are_escaped(self):
        self.assertEqual(win.ps_quote("C:\\it's here\\a.exe"),
                         "'C:\\it''s here\\a.exe'")

    def test_signer_batches_and_flags(self):
        calls = []

        def fake_ps(script, timeout):
            calls.append(script)
            return 0, self.ROWS
        signer = ProcSigner()
        signer.force_windows = True
        signer.ps_run = fake_ps
        import os
        import tempfile
        exe = os.path.join(tempfile.mkdtemp(), "upd.exe")
        open(exe, "wb").write(b"MZ demo")

        def fake_ps_for(script, timeout):
            calls.append(script)
            return 0, json.dumps([{"Path": exe, "Status": "NotSigned"}])
        signer.ps_run = fake_ps_for
        sig = signer.inspect(42, exe, deep=True)
        self.assertEqual((sig.pid, sig.signing, sig.short),
                         (42, "unsigned", "UNSIGNED"))
        self.assertEqual(len(sig.sha256), 64)
        self.assertIn("Mark-of-the-Web", sig.gatekeeper)
        signer.inspect(43, exe)
        self.assertEqual(len(calls), 1, "second look-up must hit the cache")


class TestPathFlags(unittest.TestCase):
    ENV = {"USERPROFILE": r"C:\Users\piotr",
           "TEMP": r"C:\Users\piotr\AppData\Local\Temp"}

    def test_flags(self):
        f = lambda p: win.windows_path_flags(p, self.ENV)          # noqa: E731
        self.assertEqual(f(r"C:\Users\piotr\AppData\Local\Temp\a\x.exe"),
                         ["runs from %TEMP%"])
        self.assertEqual(f(r"C:\Users\piotr\Downloads\setup.exe"),
                         ["runs from Downloads"])
        self.assertEqual(f(r"C:\Program Files\App\app.exe"), [])
        self.assertEqual(f(r"C:\Users\piotr\AppData\Local\Slack\slack.exe"),
                         [])
        self.assertIn("masquerading", f(r"C:\Users\Public\svchost.exe")[1])
        self.assertEqual(f(r"\\server\share\tool.exe"),
                         ["runs from a network share"])

    def test_zone_identifier(self):
        text = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.test/a.exe\r\n"
        self.assertEqual(win.parse_zone_identifier(text),
                         "downloaded — zone INTERNET, from "
                         "https://evil.test/a.exe")


class TestDns(unittest.TestCase):
    def test_cache_lines(self):
        line = json.dumps([
            {"Entry": "github.com", "Name": "github.com", "Type": 1,
             "TimeToLive": 42, "Data": "140.82.121.4"},
            {"Entry": "www.example.com", "Type": 5, "Data": "edge.example.net."},
            {"Entry": "x.test", "Type": 28, "TimeToLive": 5, "Data": "2a00::1"},
            {"Entry": "_srv.test", "Type": 33, "Data": "whatever"},
            {"Entry": "empty.test", "Type": 1, "Data": ""}])
        self.assertEqual(win.parse_dns_cache_line(line), [
            ("github.com", "A", ["140.82.121.4"], 42),
            ("www.example.com", "CNAME", ["edge.example.net"], 0),
            ("x.test", "AAAA", ["2a00::1"], 5)])
        self.assertEqual(win.parse_dns_cache_line("garbage"), [])

    def test_event_lines(self):
        line = json.dumps({"pid": 4321, "name": "Teams.Microsoft.com.",
                           "qtype": "1", "status": "0",
                           "results": "type:  5 s-0005.s-msedge.net;"
                                      "::ffff:52.113.194.132;2603:1063::1;"})
        self.assertEqual(win.parse_dns_event_line(line),
                         ("teams.microsoft.com", "A",
                          ["52.113.194.132", "2603:1063::1"], 4321))
        failed = json.dumps({"pid": 1, "name": "nx.test", "status": "9003",
                             "results": ""})
        self.assertIsNone(win.parse_dns_event_line(failed))

    def test_watcher_reports_a_cached_answer_once(self):
        from netmonguru.core.dnswatch import DNSWatcher
        w = DNSWatcher(mode="off")
        w.mode = "cache"
        line = json.dumps([{"Entry": "github.com", "Type": 1,
                            "Data": "140.82.121.4", "TimeToLive": 30}])
        self.assertEqual(len(w._windows_records(line)), 1)
        self.assertEqual(w._windows_records(line), [])
        w.mode = "etw"
        rec = w._windows_records(json.dumps(
            {"pid": 0, "name": "a.test", "qtype": 28, "status": 0,
             "results": "2a00::5;"}))[0]
        self.assertEqual((rec.name, rec.rtype, rec.source),
                         ("a.test", "AAAA", "etw"))


class TestCollector(unittest.TestCase):
    @staticmethod
    def flow(lport, b_in, b_out, pid=10, pname="app"):
        key = flow_key("TCP", "10.0.0.2", lport, "1.1.1.1", 443)
        return key, FlowNet(key=key, proto="TCP", family="IPv4",
                            laddr="10.0.0.2", lport=lport, raddr="1.1.1.1",
                            rport=443, pid=pid, pname=pname, bytes_in=b_in,
                            bytes_out=b_out)

    def test_process_rate_is_the_sum_of_flow_rates(self):
        c = WindowsNetCollector(enabled=False)
        c.ingest_flows(dict([self.flow(1, 1000, 100), self.flow(2, 500, 50)]),
                       now=10.0)
        procs = c.ingest_flows(dict([self.flow(1, 3000, 300),
                                     self.flow(2, 1500, 150)]), now=12.0)
        self.assertEqual(procs["app.10"].in_rate, 1500.0)
        self.assertEqual(procs["app.10"].out_rate, 150.0)
        self.assertEqual(c.proc_history("app.10")[0], [0.0, 1500.0])

        # a connection closes: the process rate must not go negative / spike
        procs = c.ingest_flows(dict([self.flow(1, 5000, 500)]), now=14.0)
        self.assertEqual(procs["app.10"].in_rate, 1000.0)

    def test_disabled_off_windows(self):
        c = WindowsNetCollector()
        if not win.IS_WINDOWS:
            self.assertFalse(c.enabled)
            self.assertEqual(c.collect_for([]), {})


class TestCutter(unittest.TestCase):
    def test_refusals(self):
        cutter = WinCutter()
        udp = Connection("UDP", "IPv4", "10.0.0.2", 5000, "1.1.1.1", 53)
        self.assertIn("only TCP", cutter.cut(udp)[1])
        listener = Connection("TCP", "IPv4", "", 80, "", 0, "LISTEN")
        self.assertIn("not a connected", cutter.cut(listener)[1])
        ok, msg = win.close_tcp_connection("::1", 1, "2606::1", 443)
        self.assertFalse(ok)
        if win.IS_WINDOWS:
            self.assertIn("IPv4", msg)

    def test_factory(self):
        name = type(make_cutter()).__name__
        self.assertEqual(name, "WinCutter" if win.IS_WINDOWS else "PfCutter")


class TestWhois(unittest.TestCase):
    def test_follows_referral(self):
        import socket
        import threading

        def serve(sock, payload):
            conn, _ = sock.accept()
            conn.recv(1024)
            conn.sendall(payload)
            conn.close()

        # a fake registry on localhost that answers without a referral
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        threading.Thread(target=serve, daemon=True, args=(
            srv, b"inetnum: 1.2.3.0 - 1.2.3.255\nnetname: EXAMPLE\n")).start()
        real = socket.create_connection

        def fake(addr, timeout=None):
            return real(("127.0.0.1", port), timeout=timeout)
        socket.create_connection = fake
        try:
            text = win.whois_query("1.2.3.4")
        finally:
            socket.create_connection = real
        self.assertIn("netname: EXAMPLE", text)


if __name__ == "__main__":
    unittest.main()
