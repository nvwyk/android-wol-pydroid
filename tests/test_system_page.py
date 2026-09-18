"""The System page: device readers that work where Android hides /proc, and insights."""
import unittest
from unittest import mock

from helpers import AppTestCase
from wol import db, insights, monitor, pcs, system


class ReaderTest(unittest.TestCase):
    def test_cores_online(self):
        for text, count in (("0-7\n", 8), ("0-3,6\n", 5), ("0\n", 1), ("", None), ("x", None)):
            with mock.patch("wol.system.read_file", return_value=text):
                self.assertEqual(system.cores_online(), count, text)

    def test_default_route(self):
        table = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
                 "wlan0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
                 "wlan0\t00000000\t0102000A\t0003\t0\t0\t0\t00000000\n")
        with mock.patch("wol.system.read_file", return_value=table):
            self.assertEqual(system.default_route(), ("wlan0", "10.0.2.1"))
        with mock.patch("wol.system.read_file", return_value=None):
            self.assertIsNone(system.default_route())

    def test_temperatures_accept_degrees_and_millidegrees(self):
        files = {"/sys/class/thermal/thermal_zone0/temp": "41000",
                 "/sys/class/thermal/thermal_zone0/type": "cpu0",
                 "/sys/class/thermal/thermal_zone1/temp": "33",
                 "/sys/class/thermal/thermal_zone1/type": "battery",
                 "/sys/class/thermal/thermal_zone2/temp": "-40000"}      # a sensor that is off
        with mock.patch("wol.system.read_file", side_effect=files.get), \
                mock.patch("os.path.isdir", side_effect=lambda path: "zone3" not in path):
            self.assertEqual(system.temperatures(), [("cpu0", 41.0), ("battery", 33.0)])

    def test_cpu_clock(self):
        files = {"/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq": "1000000",
                 "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq": "2000000",
                 "/sys/devices/system/cpu/cpu1/cpufreq/scaling_cur_freq": "500000",
                 "/sys/devices/system/cpu/cpu1/cpufreq/cpuinfo_max_freq": "1000000"}
        with mock.patch("wol.system.read_file", side_effect=files.get), \
                mock.patch("os.cpu_count", return_value=4):
            average, share, top = system.cpu_clock()
        self.assertEqual((average, round(share), top), (750e6, 50, 2e9))
        self.assertEqual(system.format_hz(750e6), "750 MHz")
        self.assertEqual(system.format_hz(2e9), "2.00 GHz")

    def test_uptime_needs_no_proc(self):
        with mock.patch("wol.system.read_file", return_value=None):
            self.assertIsNotNone(system.device_uptime())


class SystemPageTest(AppTestCase):
    def setUp(self):
        super(SystemPageTest, self).setUp()
        self.complete_setup(mac="02-00-00-00-00-07", hosts="192.0.2.7", broadcasts="192.0.2.255")

    def test_page_shows_groups_and_insights(self):
        html = self.get("/system").get_data(as_text=True)
        for heading in ("Insights", "Device", "Network", "Reachability checks", "This server"):
            self.assertIn(">%s</h2>" % heading, html)
        self.assertIn("Nothing needs attention.", html)
        self.assertIn("Not tried yet", html)            # ping capability before any check

    def test_system_page_needs_sign_in(self):
        self.client.post("/logout", data={"csrf_token": self.token("/")})
        self.assertEqual(self.get("/system").status_code, 302)

    def test_duplicate_mac_is_pointed_out(self):
        self.add_pc(name="Twin", mac="02:00:00:00:00:07", hosts="192.0.2.8")
        html = self.get("/system").get_data(as_text=True)
        self.assertIn("share one MAC address", html)
        with db.session() as conn:
            everything = pcs.load_all(conn)
        twin = [pc for pc in everything if pc["name"] == "Twin"][0]
        self.assertTrue(any("same MAC address" in hint for hint in pcs.hints(twin, None, everything)))

    def test_firewalled_pc_and_missing_android_figures(self):
        with db.session() as conn:
            pc = pcs.load_all(conn)[0]
        monitor._record_result(pc, True, "Seen on the network (ARP). It does not answer ping, "
                                         "probably its firewall.")
        with mock.patch("wol.system.android_name", return_value="Android 8.0.0 (PRA-LX1)"), \
                mock.patch.object(system.host, "cpu", None), \
                mock.patch.object(system.host, "battery", None):
            with db.session() as conn:
                found = insights.collect(conn)
        messages = " ".join(message for _, message in found)
        self.assertIn("blocks ping", messages)
        self.assertIn("Echo Request - ICMPv4-In", messages)
        self.assertIn("does not let apps read the total CPU load and the battery", messages)
        self.assertEqual(found[0], ("success", "Nothing needs attention."))

    def test_failed_sign_ins_are_a_warning(self):
        self.client.post("/logout", data={"csrf_token": self.token("/")})
        self.post("/login", {"password": "wrong password"}, token_from="/login")
        with db.session() as conn:
            found = insights.collect(conn)
        self.assertEqual(found[0][0], "warning")
        self.assertIn("1 failed sign-in", found[0][1])

    def test_live_figures_include_server_cpu(self):
        with mock.patch.object(system.host, "server_cpu", 1.5), \
                mock.patch.object(system.host, "sampled_at", system.runtime.now_local()):
            data = self.get("/system.json").get_json()
        self.assertEqual(data["text"]["server-cpu"], "1.5%")
        self.assertIn("threads", data["text"])


if __name__ == "__main__":
    unittest.main()
