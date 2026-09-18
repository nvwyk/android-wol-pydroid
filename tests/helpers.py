"""Shared test harness: a fresh installation in a temporary folder for every test.

Run the suite from the repository root with:  python -m unittest discover -s tests -v
"""
import os
import re
import shutil
import socket
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from wol import db, main, monitor, passwords, runtime, settings, web  # noqa: E402

PASSWORD = "correct horse 42"
SETUP_CODE = "TEST-CODE"


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def csrf_from(html):
    found = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert found, "no CSRF token on the page"
    return found.group(1)


def reset_process_state():
    """Module-level state that a real server sets once per process."""
    runtime.database_error = runtime.database_warning = None
    runtime.setup_done = False
    runtime.setup_code = SETUP_CODE
    runtime.listening_port = 5000
    runtime.internet = runtime.internet_since = None
    runtime.restart_hook = None
    for table in (monitor._status, monitor._watch_until, monitor._woken_at):
        table.clear()
    monitor._pc_list[0], monitor._pc_list[1] = 0.0, None
    settings._cache.clear()
    passwords._cost = 4                 # the minimum bcrypt cost keeps the suite fast


class AppTestCase(unittest.TestCase):
    """A temporary installation with a database and a Flask test client."""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="wol-test-")
        reset_process_state()
        self.prepare()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def prepare(self):
        """Open the database in self.base the way the server does at startup."""
        secret = main.prepare(self.base)
        self.app = web.create_app(secret or "degraded", testing=True)
        self.client = self.app.test_client()
        return secret

    def conn(self):
        return db.connect()

    def get(self, path, **kwargs):
        return self.client.get(path, **kwargs)

    def token(self, path="/"):
        response = self.client.get(path)
        return csrf_from(response.get_data(as_text=True))

    def post(self, path, data=None, token_from=None, **kwargs):
        """POST with a valid CSRF token taken from `token_from` (or the path itself)."""
        data = dict(data or {})
        data.setdefault("csrf_token", self.token(token_from or path))
        return self.client.post(path, data=data, **kwargs)

    def complete_setup(self, add_pc=True, **pc):
        form = {"code": SETUP_CODE, "password": PASSWORD, "confirm": PASSWORD}
        if add_pc:
            form.update(add_pc="1", name="Office PC", mac="24:4b:fe:07:0c:e2",
                        broadcasts="192.168.1.255", hosts="192.168.1.25", ports="7, 9")
            form.update(pc)
        response = self.post("/setup", form)
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True)[:2000])
        return response

    def login(self, password=PASSWORD):
        return self.post("/login", {"password": password}, token_from="/login")

    def add_pc(self, **values):
        form = {"name": "Lab PC", "mac": "02-00-00-00-00-02", "broadcasts": "192.168.1.255",
                "hosts": "192.168.1.30", "ports": "9", "status_method": "ping", "enabled": "1"}
        form.update(values)
        return self.post("/admin/pcs/new", form)


class FakeSocket(object):
    """Stands in for socket.socket in wake.send_packets(). Records every packet and
    fails for the targets listed in `fail`."""
    sent = []
    fail = {}

    def __init__(self, *args):
        pass

    def setsockopt(self, *args):
        pass

    def sendto(self, packet, target):
        if target in FakeSocket.fail:
            raise OSError(101, FakeSocket.fail[target])
        FakeSocket.sent.append((packet, target))

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def fake_socket_module():
    """A stand-in for the socket module as wol.wake sees it, so only wake packets are
    captured and every other socket in the process keeps working."""
    import types
    return types.SimpleNamespace(socket=FakeSocket, AF_INET=socket.AF_INET,
                                 SOCK_DGRAM=socket.SOCK_DGRAM, SOL_SOCKET=socket.SOL_SOCKET,
                                 SO_BROADCAST=socket.SO_BROADCAST)
