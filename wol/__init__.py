"""WOL Controller: wakes PCs on the local network with Wake-on-LAN magic packets.

server.py is the entry point. launcher.py runs it, restarts it and updates server.py
together with this whole folder from GitHub. Everything the device owns (settings, PCs,
the admin password hash, history) lives in wol.db next to server.py, which updates
never touch.
"""
import hashlib
import os

APP_NAME = "WOL Controller"
APP_VERSION = "3.0.0"

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(PACKAGE_DIR)


def blob_sha(data):
    """The hash git and the GitHub API use for file contents."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def is_managed(path):
    """True for the files an update replaces. launcher.py keeps its own copy of this rule."""
    if path == "server.py":
        return True
    return (path.startswith("wol/") and "/__pycache__/" not in path
            and not path.endswith((".pyc", ".pyo")))


def managed_files(base_dir=BASE_DIR):
    """Relative paths, with forward slashes, of the application files present on disk."""
    found = ["server.py"] if os.path.isfile(os.path.join(base_dir, "server.py")) else []
    for root, dirs, files in os.walk(os.path.join(base_dir, "wol")):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(files):
            relative = os.path.relpath(os.path.join(root, name), base_dir).replace(os.sep, "/")
            if is_managed(relative):
                found.append(relative)
    return found


def release_id(base_dir=BASE_DIR):
    """Identifies this exact set of application files; launcher.py computes the same value
    from a GitHub tree, so both sides agree on which release is installed."""
    digest = hashlib.sha1()
    for path in sorted(managed_files(base_dir)):
        with open(os.path.join(base_dir, path), "rb") as f:
            digest.update(("%s\0%s\n" % (path, blob_sha(f.read()))).encode())
    return digest.hexdigest()
