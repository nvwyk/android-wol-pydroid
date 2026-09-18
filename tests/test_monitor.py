"""PC reachability checks: states, transitions, probes. Kept apart from Wake-on-LAN."""
import socket
import subprocess
import unittest
from unittest import mock

from helpers import AppTestCase
from wol import db, monitor, settings


def completed(code, output):
    return subprocess.CompletedProcess([], code, stdout=output.encode(), stderr=None)


class ProbeTest(unittest.TestCase):
    def test_ping_needs_a_real_echo_reply(self):
        with mock.patch("subprocess.run", return_value=completed(
                0, "64 bytes from 192.168.1.25: icmp_seq=1 ttl=128 time=0.4 ms")):
            self.assertEqual(monitor.ping("192.168.1.25")[0], True)
        # Windows exits 0 when the router answers "destination host unreachable".
        with mock.patch("subprocess.run", return_value=completed(
                0, "Reply from 192.168.1.1: Destination host unreachable.")):
            self.assertEqual(monitor.ping("192.168.1.25")[0], False)
        with mock.patch("subprocess.run", return_value=completed(1, "1 packets transmitted, 0 received")):
            self.assertEqual(monitor.ping("192.168.1.25"), (False, "No answer to ping"))
        with mock.patch("subprocess.run", return_value=completed(2, "ping: socket: Operation not permitted")):
            self.assertIsNone(monitor.ping("192.168.1.25")[0])
        with mock.patch("subprocess.run", side_effect=FileNotFoundError()):
            answered, detail = monitor.ping("192.168.1.25")
            self.assertIsNone(answered)
            self.assertIn("TCP check", detail)

    def test_tcp_probe(self):
        with mock.patch("socket.create_connection", return_value=mock.Mock()):
            self.assertEqual(monitor.tcp_probe("192.168.1.25", 3389)[0], True)
        with mock.patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            self.assertEqual(monitor.tcp_probe("192.168.1.25", 3389)[0], True)   # the PC said no
        with mock.patch("socket.create_connection", side_effect=socket.timeout()):
            self.assertEqual(monitor.tcp_probe("192.168.1.25", 3389)[0], False)
        with mock.patch("socket.create_connection", side_effect=OSError(113, "No route to host")):
            self.assertEqual(monitor.tcp_probe("192.168.1.25", 3389)[0], False)


class StatusTest(AppTestCase):
    def setUp(self):
        super(StatusTest, self).setUp()
        self.complete_setup()
        self.pc = dict(monitor._current_pcs()[0])

    def events(self, kind):
        with db.session() as conn:
            return conn.execute("SELECT count(*) FROM events WHERE type = ?", (kind,)).fetchone()[0]

    def test_states(self):
        self.assertEqual(monitor.status_of(self.pc)["state"], "unknown")        # not checked yet
        monitor._record_result(self.pc, True, "Answered ping")
        self.assertEqual(monitor.status_of(self.pc)["label"], "Online")
        self.assertEqual(monitor.status_of(dict(self.pc, enabled=False))["state"], "disabled")
        self.assertEqual(monitor.status_of(dict(self.pc, status_method="none"))["label"], "Not checked")
        monitor._record_result(self.pc, None, "ping could not run")
        self.assertEqual(monitor.status_of(self.pc)["state"], "unknown")

    def test_one_lost_probe_does_not_take_a_pc_offline(self):
        monitor._record_result(self.pc, True, "Answered ping")
        monitor._record_result(self.pc, False, "No answer to ping")
        self.assertEqual(monitor.status_of(self.pc)["state"], "online")
        monitor._record_result(self.pc, False, "No answer to ping")
        self.assertEqual(monitor.status_of(self.pc)["state"], "unreachable")
        self.assertEqual(self.events("status.offline"), 1)
        monitor._record_result(self.pc, True, "Answered ping")
        self.assertEqual(self.events("status.online"), 1)
        with db.session() as conn:
            self.assertTrue(conn.execute("SELECT last_seen_at FROM pcs").fetchone()[0])

    def test_first_result_after_start_is_not_an_event(self):
        monitor._record_result(self.pc, False, "No answer to ping")
        self.assertEqual(self.events("status.offline") + self.events("status.online"), 0)

    def test_waking_until_the_pc_answers(self):
        monitor._record_result(self.pc, False, "No answer to ping")
        monitor._record_result(self.pc, False, "No answer to ping")
        monitor.watch_after_wake(self.pc["id"])
        self.assertEqual(monitor.status_of(self.pc)["state"], "waking")
        monitor._record_result(self.pc, True, "Answered ping")
        self.assertEqual(monitor.status_of(self.pc)["state"], "online")
        with db.session() as conn:
            message = conn.execute("SELECT message FROM events WHERE type = 'status.online'").fetchone()[0]
        self.assertIn("after the wake request", message)

    def test_checks_follow_the_interval_and_can_be_turned_off(self):
        with mock.patch("wol.monitor.ping", return_value=(True, "Answered ping")) as ping:
            self.assertEqual(monitor.check_due_pcs(), 1)
            self.assertEqual(monitor.check_due_pcs(), 0)         # not due again yet
            monitor.watch_after_wake(self.pc["id"])
            self.assertEqual(monitor.check_due_pcs(), 0)         # within the 10 s wake interval
            with db.session() as conn:
                settings.save(conn, {"status_checks_enabled": False})
            monitor._status.clear()
            self.assertEqual(monitor.check_due_pcs(), 0)
        self.assertEqual(ping.call_count, 1)


if __name__ == "__main__":
    unittest.main()
