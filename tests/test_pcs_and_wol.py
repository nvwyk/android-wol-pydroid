"""PC management and Wake-on-LAN: validation, CRUD, packets, partial failures, isolation."""
import unittest
from unittest import mock

from helpers import AppTestCase, FakeSocket, fake_socket_module
from wol import db, pcs, wake

MAC = bytes.fromhex("244BFE070CE2")


class ValidationTest(unittest.TestCase):
    def test_mac_formats(self):
        for text in ("24-4B-FE-07-0C-E2", "24:4b:fe:07:0c:e2", "244B.FE07.0CE2", "244bfe070ce2",
                     " 24 4B FE 07 0C E2 "):
            self.assertEqual(pcs.parse_mac(text), MAC, text)
        for text in ("", "24-4B-FE-07-0C", "24-4B-FE-07-0C-E2-00", "ZZ-4B-FE-07-0C-E2", None, 12):
            self.assertIsNone(pcs.parse_mac(text), text)
        self.assertEqual(pcs.format_mac(MAC), "24-4B-FE-07-0C-E2")

    def test_addresses(self):
        self.assertEqual(pcs.check_address(" 192.168.1.25 "), "192.168.1.25")
        self.assertEqual(pcs.check_address("255.255.255.255"), "255.255.255.255")
        for bad in ("0.0.0.0", "127.0.0.1", "224.0.0.1", "192.168.1.256", "fe80::1", "pc.local",
                    "192.168.1", ""):
            with self.assertRaises(ValueError, msg=bad):
                pcs.check_address(bad)

    def test_ports(self):
        self.assertEqual(pcs.check_port(" 9 "), 9)
        for bad in ("0", "65536", "-1", "nine", ""):
            with self.assertRaises(ValueError, msg=bad):
                pcs.check_port(bad)

    def test_form(self):
        values, errors = pcs.validate({"name": "  Office   PC ", "mac": "244bfe070ce2",
                                       "hosts": "192.168.1.25", "broadcasts": "192.168.1.255, 192.168.1.255",
                                       "ports": "7 9;9", "status_method": "ping", "enabled": "1"})
        self.assertEqual(errors, {})
        self.assertEqual(values["name"], "Office PC")
        self.assertEqual(values["mac"], "24-4B-FE-07-0C-E2")
        self.assertEqual(values["broadcasts"], ["192.168.1.255"])
        self.assertEqual(values["ports"], [7, 9])

    def test_form_errors(self):
        _, errors = pcs.validate({"name": "", "mac": "xx", "hosts": "", "broadcasts": "",
                                  "ports": "", "status_method": "tcp", "status_port": ""})
        self.assertEqual(set(errors), {"name", "mac", "broadcasts", "ports", "status_port",
                                       "status_method"})
        _, errors = pcs.validate({"name": "A", "mac": "24-4B-FE-07-0C-E2",
                                  "broadcasts": "192.168.1.255", "ports": "9",
                                  "status_method": "ping"})
        self.assertIn("status_method", errors)          # ping needs the PC's own address


class WakePlanTest(unittest.TestCase):
    def pc(self, **values):
        pc = {"id": 1, "name": "PC", "mac": "24-4B-FE-07-0C-E2", "hosts": ["192.168.1.25"],
              "broadcasts": ["192.168.1.255"], "ports": [7, 9]}
        pc.update(values)
        return pc

    def test_every_address_gets_every_port(self):
        mac, targets, problems = pcs.wake_plan(self.pc())
        self.assertEqual(mac, MAC)
        self.assertEqual(targets, [("192.168.1.25", 7), ("192.168.1.25", 9),
                                   ("192.168.1.255", 7), ("192.168.1.255", 9)])
        self.assertEqual(problems, [])

    def test_bad_stored_values_are_skipped_and_reported(self):
        # What a hand-edited or imported database may contain.
        mac, targets, problems = pcs.wake_plan(self.pc(hosts=["not-an-ip", "127.0.0.1"],
                                                       ports=[9, 70000]))
        self.assertEqual(targets, [("192.168.1.255", 9)])
        self.assertEqual(len(problems), 3)
        mac, targets, problems = pcs.wake_plan(self.pc(mac="garbage"))
        self.assertIsNone(mac)
        self.assertIn("MAC address garbage is not valid", problems[0])
        _, targets, problems = pcs.wake_plan(self.pc(hosts=[], broadcasts=[], ports=[]))
        self.assertEqual(targets, [])
        self.assertEqual(len(problems), 2)

    def test_magic_packet(self):
        packet = wake.magic_packet(MAC)
        self.assertEqual(len(packet), 102)
        self.assertEqual(packet[:6], b"\xff" * 6)
        self.assertEqual(packet[6:], MAC * 16)


class PcAdminTest(AppTestCase):
    def setUp(self):
        super(PcAdminTest, self).setUp()
        self.complete_setup()
        FakeSocket.sent, FakeSocket.fail = [], {}
        self.socket = mock.patch.object(wake, "socket", fake_socket_module())
        self.socket.start()

    def tearDown(self):
        self.socket.stop()
        super(PcAdminTest, self).tearDown()

    def test_add_edit_disable_delete(self):
        response = self.add_pc()
        self.assertEqual(response.status_code, 302)
        pc_id = int(response.headers["Location"].rstrip("/").split("/")[-1])
        page = self.get("/admin/pcs/%d" % pc_id).get_data(as_text=True)
        self.assertIn("Lab PC", page)
        self.assertIn("02-00-00-00-00-02", page)

        response = self.post("/admin/pcs/%d/edit" % pc_id, {
            "name": "Lab PC 2", "mac": "02:00:00:00:00:03", "broadcasts": "10.0.0.255",
            "hosts": "", "ports": "9, 7", "status_method": "none", "enabled": "1",
            "description": "Bench"})
        self.assertEqual(response.status_code, 302)
        with db.session() as conn:
            pc = pcs.get(conn, pc_id)
        self.assertEqual((pc["name"], pc["mac"], pc["broadcasts"], pc["ports"], pc["hosts"]),
                         ("Lab PC 2", "02-00-00-00-00-03", ["10.0.0.255"], [9, 7], []))

        self.post("/admin/pcs/%d/enabled" % pc_id, {"enabled": "0"}, token_from="/admin/pcs")
        with db.session() as conn:
            self.assertFalse(pcs.get(conn, pc_id)["enabled"])
        response = self.post("/pcs/%d/wake" % pc_id, token_from="/")
        self.assertIn("disabled", self.get("/").get_data(as_text=True))
        self.assertEqual(FakeSocket.sent, [])

        self.assertEqual(self.get("/admin/pcs/%d/delete" % pc_id).status_code, 200)   # confirm page
        self.post("/admin/pcs/%d/delete" % pc_id, token_from="/admin/pcs/%d/delete" % pc_id)
        with db.session() as conn:
            self.assertIsNone(pcs.get(conn, pc_id))
            self.assertEqual(pcs.counts(conn), (1, 1))          # the other PC is untouched
            types = [row[0] for row in conn.execute("SELECT type FROM events")]
        for kind in ("pc.created", "pc.updated", "pc.disabled", "pc.deleted"):
            self.assertIn(kind, types)
        self.assertEqual(self.get("/admin/pcs/%d" % pc_id).status_code, 404)

    def test_invalid_input_is_refused(self):
        response = self.add_pc(mac="24-4B-FE-07-0C", hosts="192.168.1.500", ports="99999")
        self.assertEqual(response.status_code, 400)
        page = response.get_data(as_text=True)
        self.assertIn("six pairs of hex digits", page)
        self.assertIn("192.168.1.500 is not an IPv4 address", page)
        self.assertIn("Ports go from 1 to 65535", page)
        self.assertEqual(self.add_pc(name="office pc").status_code, 400)   # names are unique
        with db.session() as conn:
            self.assertEqual(pcs.counts(conn), (1, 1))

    def test_dashboard_with_zero_one_and_many_pcs(self):
        with db.session() as conn:
            conn.execute("DELETE FROM pcs")
        self.assertIn("No PCs yet", self.get("/").get_data(as_text=True))
        self.add_pc(name="Alpha", mac="02-00-00-00-00-0A")
        page = self.get("/").get_data(as_text=True)
        self.assertIn("Alpha", page)
        self.assertEqual(page.count('class="card pc'), 1)
        for index in range(4):
            self.add_pc(name="Rack %d" % index, mac="02-00-00-00-01-%02X" % index)
        page = self.get("/").get_data(as_text=True)
        self.assertEqual(page.count('class="card pc'), 5)
        data = self.get("/api/dashboard").get_json()
        self.assertEqual(len(data["chip"]), 5)

    def test_wake_sends_only_this_pcs_packets(self):
        self.add_pc(name="Second", mac="02-00-00-00-00-99", broadcasts="10.9.9.255", hosts="10.9.9.9",
                    ports="4000")
        response = self.post("/pcs/1/wake", token_from="/")
        self.assertEqual(response.status_code, 302)
        packets = FakeSocket.sent
        self.assertEqual(len(packets), 4)
        self.assertTrue(all(packet == wake.magic_packet(MAC) for packet, _ in packets))
        self.assertEqual(sorted(target for _, target in packets),
                         [("192.168.1.25", 7), ("192.168.1.25", 9),
                          ("192.168.1.255", 7), ("192.168.1.255", 9)])
        page = self.get("/").get_data(as_text=True)
        self.assertIn("Wake packet sent to Office PC (4 packets)", page)
        with db.session() as conn:
            row = conn.execute("SELECT * FROM wol_requests").fetchone()
        self.assertEqual((row["pc_id"], row["result"], row["packets_sent"], row["packets_total"],
                          row["source"]), (1, "sent", 4, 4, "dashboard"))

    def test_partial_failure_is_reported(self):
        FakeSocket.fail = {("192.168.1.255", 7): "Network is unreachable"}
        self.post("/pcs/1/wake", token_from="/")
        page = self.get("/").get_data(as_text=True)
        self.assertIn("partly sent", page)
        self.assertIn("3 of 4 packets", page)
        self.assertIn("192.168.1.255:7: Network is unreachable", page)
        with db.session() as conn:
            row = conn.execute("SELECT result, packets_sent, error FROM wol_requests").fetchone()
            event = conn.execute("SELECT level, success FROM events WHERE type = 'wol.partial'").fetchone()
        self.assertEqual((row[0], row[1]), ("partial", 3))
        self.assertIn("Network is unreachable", row[2])
        self.assertEqual((event[0], event[1]), ("warning", 0))

    def test_total_failure_does_not_crash(self):
        FakeSocket.fail = dict(((address, port), "No route to host")
                               for address in ("192.168.1.25", "192.168.1.255") for port in (7, 9))
        response = self.post("/pcs/1/wake", token_from="/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("did not go out", self.get("/").get_data(as_text=True))
        with db.session() as conn:
            self.assertEqual(conn.execute("SELECT result FROM wol_requests").fetchone()[0], "failed")

    def test_malformed_stored_pc_fails_gracefully(self):
        with db.session() as conn:
            conn.execute("UPDATE pcs SET mac = 'broken' WHERE id = 1")
        response = self.post("/pcs/1/wake", token_from="/")
        self.assertEqual(response.status_code, 302)
        page = self.get("/").get_data(as_text=True)
        self.assertIn("MAC address broken is not valid", page)
        self.assertEqual(FakeSocket.sent, [])
        detail = self.get("/admin/pcs/1").get_data(as_text=True)
        self.assertIn("is-error", detail)                       # the configuration check says so

    def test_test_packet_shows_its_result(self):
        response = self.post("/admin/pcs/1/test", token_from="/admin/pcs/1")
        self.assertIn("test=", response.headers["Location"])
        page = self.get(response.headers["Location"]).get_data(as_text=True)
        self.assertIn("Test packet result", page)
        self.assertIn("4 of 4 packets left this device", page)
        with db.session() as conn:
            self.assertEqual(conn.execute("SELECT source FROM wol_requests").fetchone()[0], "test")

    def test_wake_never_claims_the_pc_is_online(self):
        with mock.patch("wol.monitor.ping", return_value=(False, "No answer to ping")):
            self.post("/pcs/1/wake", token_from="/")
            data = self.get("/api/dashboard").get_json()
        self.assertEqual(data["chip"]["pc-1"]["state"], "waking")
        self.assertEqual(data["chip"]["pc-1"]["label"], "Waiting for reply")

    def test_client_address_is_not_stored_when_turned_off(self):
        self.post("/admin/settings/history", {"event_retention_days": "90", "wol_retention_days": "365"},
                  token_from="/admin/settings")
        self.post("/pcs/1/wake", token_from="/")
        with db.session() as conn:
            self.assertIsNone(conn.execute("SELECT client_ip FROM wol_requests").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
