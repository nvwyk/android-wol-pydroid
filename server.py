"""WOL Controller entry point. launcher.py runs this file; it can also be run directly.

The application lives in the wol/ folder next to this file, and its data in wol.db.
launcher.py updates this file and wol/ together and never touches wol.db.

    python server.py                     run the server
    python server.py --reset-password    set a new admin password from the console
    python server.py --set-port 5000     change the server port from the console
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

if not os.path.isfile(os.path.join(BASE_DIR, "wol", "__init__.py")):
    # An older launcher.py only downloads server.py. It will restore the previous
    # version by itself; this message says how to move on.
    sys.exit("WOL Controller: the wol folder is missing next to server.py. This version is "
             "several files: copy server.py, the wol folder and launcher.py from GitHub. An "
             "older launcher.py only downloads server.py; replace it with the current one.")

from wol.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
