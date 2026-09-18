# WOL Controller

Wake the computers on your network from any browser, using Wake-on-LAN magic packets sent by
an always-on device such as an old Android phone running Pydroid 3.

- **Several PCs**, each with its own MAC address, target addresses, UDP ports, reachability
  check, history and on/off switch.
- **Honest status.** A sent packet is reported as sent. A PC is only called *Online* after it
  answers a ping, a TCP probe, or ARP with its own MAC address.
- **Admin panel** for everything: PCs, settings, security, activity log, backups. There is no
  configuration file to edit.
- **SQLite database** (`wol.db`) as the single source of truth, with a one-time migration from
  the old `config.json`.
- **bcrypt password hashes**, brute-force lockout, CSRF protection, strict security headers.
- **Public status page** whose content you choose, plus a JSON version for other tools.
- **Self-updating**: `launcher.py` installs new releases from GitHub, checks them before
  switching, and rolls back a release that does not come up healthy. It never touches your data.

It runs entirely on the local network and needs no internet connection to wake PCs. Updates are
the only thing that uses the internet.

---

## Contents

1. [Requirements and dependencies](#requirements-and-dependencies)
2. [Installation](#installation)
3. [First-run setup](#first-run-setup)
4. [Upgrading from an older version](#upgrading-from-an-older-version)
5. [Using the dashboard](#using-the-dashboard)
6. [Setting up PCs](#setting-up-pcs)
7. [Admin panel](#admin-panel)
8. [Public status page](#public-status-page)
9. [Sign-in and security](#sign-in-and-security)
10. [Settings reference](#settings-reference)
11. [The database](#the-database)
12. [launcher.py: watchdog, updates and rollback](#launcherpy-watchdog-updates-and-rollback)
13. [Health endpoint](#health-endpoint)
14. [Console commands](#console-commands)
15. [Troubleshooting](#troubleshooting)
16. [Backup, recovery and reset](#backup-recovery-and-reset)
17. [Files and development](#files-and-development)

---

## Requirements and dependencies

| Package | Needed | What for |
|---|---|---|
| Python 3.7 or newer | Yes | Pydroid 3 currently ships Python 3.13 |
| [Flask](https://pypi.org/project/Flask/) | Yes | The web interface. Pure Python, installs everywhere |
| [bcrypt](https://pypi.org/project/bcrypt/) | Recommended | Fast, compiled bcrypt for password hashes |

Everything else (SQLite, networking, the updater) comes from the Python standard library.

### About bcrypt on Pydroid 3

Passwords are always stored as bcrypt password hashes. How fast that hashing is depends on
whether the `bcrypt` package can be installed:

- **bcrypt 4 and newer** are written in Rust. PyPI has no Android builds of them, and Pydroid 3
  ships C, C++ and Fortran compilers but no Rust compiler, so a plain `pip install bcrypt`
  usually fails on the phone.
- **bcrypt 3.2.2** (the last C release) needs only a C compiler, which Pydroid has.
- **Neither installed?** The server then uses its own built-in bcrypt, written in plain Python.
  It writes the same standard `$2b$` hashes and passes the same test vectors as the package, but
  it is about a hundred times slower, so it uses a lower cost factor (it picks the highest cost
  that still takes about a second on the device, never below 5).

Try these in order in the Pydroid terminal, and stop at the first that works:

```bash
pip install bcrypt
```

```bash
pip install "bcrypt<4"
```

With Pydroid's **Use prebuilt libraries repository** option enabled in its Pip screen, the first
command may also find a ready-made build. If none of them work, nothing is lost: the built-in
bcrypt is used automatically, and Admin > Overview says so. Once the package is installed later,
your password hash is upgraded to the stronger cost the next time you sign in.

---

## Installation

### Android with Pydroid 3

1. Install **Pydroid 3** from Google Play.
2. In Pydroid, open **Menu > Pip**, then install `flask`. Then try `bcrypt` as described above.
3. Copy these onto the phone, into one folder:
   - `launcher.py`
   - `server.py`
   - the whole `wol` folder

   For example, clone or download this repository and copy it to
   `/storage/emulated/0/Documents/wol-controller/`.
4. Open `launcher.py` in Pydroid and run it with the `--selftest` argument once (or run
   `python launcher.py --selftest` in the Pydroid terminal). Every required check should say
   `PASS`. The `bcrypt` and `ping` lines are informational.
5. Open `launcher.py` in Pydroid and press **Run**. Keep it running; it starts `server.py`
   itself, restarts it if it stops, and installs updates.
6. The console shows the address and a **setup code**. Continue with
   [First-run setup](#first-run-setup).

Keep the phone on the same Wi-Fi network as the PCs, and stop Android from putting Pydroid to
sleep (Settings > Battery > Pydroid 3 > no restrictions).

### Linux, macOS or Windows

```bash
pip install -r requirements.txt
```

```bash
python launcher.py
```

Or without the watchdog and updater: `python server.py`.

The server listens on port 5000 on every network interface. Open `http://<device-address>:5000`
from any device on the network.

---

## First-run setup

A new installation shows a setup page instead of the login page, on any address you open.

1. Open `http://<device-address>:5000`. The console prints the exact address.
2. Enter the **setup code** from the console. It looks like `KXQ4-7MPA`. It makes sure that you,
   the person who can see the console, claim the server, and not someone else on the network who
   opens the page first. A restart prints a new code.
3. Choose the **admin password**: at least 8 characters, at most 72 bytes. It is stored only as a
   bcrypt password hash.
4. Optionally **add your first PC**: a name, its MAC address, your network's broadcast address and
   the UDP port. You can also skip this and add PCs in Admin afterwards.
5. Press **Finish setup**. You are signed in and taken to the dashboard.

Setup is a single database transaction: either everything is saved or nothing is. Reloading the
page, a wrong field or a server restart halfway through simply leaves setup open. Once finished,
the setup page is closed for good and only redirects.

There is no default password. The old `CHANGE_YOUR_PASSWORD` placeholder is gone.

---

## Upgrading from an older version

Earlier versions stored everything in `config.json` (and before that, inside `server.py`).
Updating is automatic, with one manual step.

### Step 1: replace launcher.py

`launcher.py` never updates itself, and the old one only knows how to download `server.py`. The
application now consists of `server.py` plus the `wol` folder, so copy the new `launcher.py` onto
the phone over the old one, then run it.

If you skip this, nothing breaks: the old launcher downloads the new `server.py`, sees it cannot
start without the `wol` folder, restores your previous version and keeps running it. The
console tells you to update `launcher.py`.

### Step 2: the automatic migration

On its first start the new version finds `config.json` and imports it into `wol.db` in one
transaction:

| In config.json | Becomes |
|---|---|
| `password` | The admin password, stored as a bcrypt password hash |
| `secret_key` | Kept, so the session cookie format stays valid |
| `server_port` | The Server port setting |
| `target_mac`, `target_ips`, `wol_ports` | A PC named **My PC**. Addresses ending in `.255` become broadcast addresses, the others the PC's IP addresses |

Keys missing from the file get the values the old version used for them. A MAC address that is
not valid is kept as it was and the PC is imported *disabled*, so you can correct it in Admin;
ports that are not valid are left out. The activity log notes every such case.

If the old password was still `CHANGE_YOUR_PASSWORD`, it is not imported: the setup page opens and
asks for a new password. Your PC settings are already imported at that point.

After the upgrade you sign in once with your existing password. Old browser sessions do not carry
over.

### What happens to config.json

The server never reads `config.json` again after the import. The file itself is left untouched
for ten minutes, because during that time `launcher.py` may still roll the update back, and the
old version needs the file. After that it is renamed to **`config.json.migrated`**, with the
password and secret key removed, so no plaintext password remains on the device. The other
values stay in it for reference.

If the old launcher is still running the new version, `config.json` is kept (the old launcher
reads the port from it) until you replace `launcher.py`.

### Very old versions

If your `server.py` still has `PASSWORD = ...` lines at the top (the first single-file version),
`launcher.py` first copies those values into `config.json`, and the import above takes it from
there.

---

## Using the dashboard

The **Wake** page shows one card per PC with its MAC address, where its packets go, a large
**Wake** button and three figures: the last wake request, the number of requests kept in the
history, and when the PC last answered a check.

Each card has a status chip:

| Status | Meaning |
|---|---|
| **Online** | The PC answered its last check: ping, ARP with its own MAC address, or TCP |
| **Waiting for reply** | A wake packet was sent in the last three minutes and the PC has not answered yet. The card also shows what the last check found |
| **Unreachable** | The PC did not answer its last two checks. It is off, asleep, or blocks the probe |
| **Not checked** | Reachability checks are off, for this PC or everywhere |
| **Checking** | The first check since the server started is on its way |
| **Unknown** | The check itself could not run, for example because `ping` is not allowed |
| **Disabled** | The PC is switched off in Admin: no Wake button, no checks |

Pressing **Wake** sends the magic packet to every address and port of that PC only, then shows
exactly how many packets left the device. A sent packet does not prove the PC woke up. After a
wake request the PC is checked every 10 seconds for three minutes, and the card turns Online
when it answers. The page refreshes itself while it is open.

### How the automatic check works

Windows drops ping on networks it calls **Public**, which is its default for a new network, so
ping alone often says a running PC is off. The automatic check therefore works in two steps:

1. It pings the PC's IP address. An answer means Online.
2. Without an answer, it looks the IP address up in this device's network address table (ARP).
   Every PC has to answer ARP to be on the network at all, whatever its firewall does. The
   entry only counts when it carries **this PC's MAC address**, so another device that got the
   same IP address is reported as such, never as your PC. An entry that was already cached has
   to survive the kernel re-checking it (about 9 seconds), so a PC that just shut down is not
   reported as Online.

Android 9 and older let apps read the table (`ip neigh` or `/proc/net/arp`). Android 10 and
later do not; there the check uses ping alone, and a TCP check is the alternative. The System
page shows which of the two this device allows.

### The System page

**System** shows the device running the server, its network and the PC checks:

- **Insights** at the top: plain-language notes about anything that needs attention, such as
  low storage or memory, a hot phone, the internet being down, failed sign-ins, a failed
  update, two PCs sharing one MAC address, or a PC that blocks ping (with how to allow it).
- **Live figures**, refreshed every few seconds with a 5-minute trend line: CPU load, this
  server's own CPU use, memory, storage and battery. Android 8 and later do not let apps read the
  total CPU load or the battery; there the page shows the CPU clock speed instead, which rises
  and falls with the load.
- **Device**: model, Android version and API level, security patch, processor, cores online,
  clock speed, uptime and the hottest temperature sensor, where Android allows reading them.
- **Network**: address and port, network interface, gateway, internet reachability with its
  latency, and traffic since boot.
- **Reachability checks**: how many PCs are online, the check interval, the latest round, and
  whether this device allows ping and reading the address table.
- **This server**: version, start time, uptime, memory and CPU time used, threads, and the
  Python, Flask and SQLite versions, plus the latest automatic update check.

---

## Setting up PCs

**Admin > PCs > Add PC**. Every field is checked before anything is saved.

| Field | What to enter |
|---|---|
| Name | Anything you recognise, unique among your PCs |
| MAC address | The network adapter's hardware address. On Windows, `ipconfig /all` lists it as *Physical Address*; on Linux, `ip link`. Any common format works: `24-4B-FE-07-0C-E2`, `24:4b:fe:07:0c:e2`, `244BFE070CE2` |
| Broadcast addresses | Your network address ending in `.255`, for example `192.168.1.255`. This reaches a sleeping PC most reliably |
| PC's IP addresses | The PC's own address. It also gets a packet, and the reachability check probes it |
| UDP ports | Usually `9`. Some PCs also listen on `7`. Separate several with commas |
| Reachability check | **Automatic** (ping, then ARP; see [How the automatic check works](#how-the-automatic-check-works)), **TCP port** (connects to a port such as 3389 for Remote Desktop, 445 for file sharing or 22 for SSH) or **Off** |
| Enabled | A disabled PC keeps its settings and history but has no Wake button and is not checked |

Every address gets a packet on every port, so two addresses and two ports make four packets.
Packets never go to another PC's addresses.

The PC's page shows a **configuration check** (errors and advice, such as a missing broadcast
address or an address outside this device's network), a **Send test packet** button that shows
exactly which packets went out, a **Check now** button, its wake history and its activity.

**Deleting a PC** asks for confirmation on its own page. It removes the PC and its settings only.
Its wake history and activity stay in the log under its name. Nothing else is touched.

### Making Wake-on-LAN work on the PC

- Enable Wake-on-LAN (sometimes *Power On By PCI-E* or *Wake on PME*) in the BIOS or UEFI.
- On Windows, in Device Manager, open the network adapter's properties: under *Power Management*
  allow the device to wake the computer, and under *Advanced* enable *Wake on Magic Packet*.
- Windows *Fast Startup* can stop wake from a full shutdown. Turn it off if waking only works
  from sleep.
- The phone and the PC must be on the same network (the same subnet). Magic packets do not cross
  routers.

---

## Admin panel

Everything is configured here. Each section is one tab:

- **Overview**: version and build, uptime, the port and interfaces the server listens on, the
  password hashing in use, database health and size, launcher, watchdog and update status, wake
  statistics, recent activity, and notices (for example a pending restart or a missing bcrypt
  package).
- **PCs**: add, edit, enable, disable, delete, send test packets, check reachability, and view
  each PC's history and activity.
- **Activity**: the persistent log of sign-ins, wake requests, changes, reachability changes,
  migrations and errors. Filter by event type, PC, time range and result.
- **Security**: change the password, sign out every other device, see the last sign-in, recent
  sign-ins, failed attempts and security events. Neither the password nor its hash is ever shown.
- **Settings**: every application setting (see the [reference](#settings-reference)), plus
  database backup and server restart.

Every change is recorded in the activity log with the time, what changed and the device address.
Passwords, hashes and secret keys never appear in it.

---

## Public status page

`/status` works without signing in, so anyone who can reach the server can read it. By default it
shows:

- that the server is online, its version, uptime, start time and current time
- that the database is healthy
- how many PCs are configured, enabled and online, and whether the wake service is ready
- the number of wake requests, the time and result of the latest one and of the latest
  successful one
- whether the internet is reachable
- the device's CPU, memory, battery and uptime
- whether automatic updates are on

**Admin > Settings > Public status page** controls each part, and can turn the page off entirely.
PCs can be shown as counts only (the default), as a status per PC without names, or with names.
MAC addresses, IP addresses, file paths, account details and secrets are never shown there.

`/status.json` returns the same information as JSON, for Home Assistant, uptime monitors or scripts.

---

## Sign-in and security

- **Password hashes.** The admin password is stored only as a bcrypt password hash (see
  [About bcrypt on Pydroid 3](#about-bcrypt-on-pydroid-3)). The check uses bcrypt's own
  constant-time comparison. Plaintext passwords are never stored or logged.
- **Sessions.** Signing in sets a signed, HTTP-only session cookie that lasts 30 days without use
  (configurable). Changing the password, or **Security > Sign out other devices**, invalidates
  every other session at once; the browser you are using stays signed in. **Log out** ends the
  current one.
- **Brute-force protection.** Five wrong passwords (or setup codes) from one address within 15
  minutes lock that address out until the oldest attempt is 15 minutes old. The attempts are
  stored in the database, so a restart does not reset the count. At most two password checks run
  at once, so a flood of guesses cannot tie up the phone.
- **CSRF.** Every form carries a per-session token, and every state-changing request without a
  valid one is refused.
- **Headers.** A strict Content Security Policy (no inline scripts or styles, no external
  resources), clickjacking protection, `no-referrer`, and `noindex` everywhere.
- **Errors** show a plain message. Details go to the console only.
- **Transport.** The server speaks plain HTTP, like most LAN appliances. Use it on a network you
  trust, and do not forward its port to the internet.
- **The database file** holds the password hash and the session key. On shared Android storage
  other apps with storage permission can read files, so keep the phone to yourself, and keep
  downloaded backups private.

### Change the password

**Admin > Security > Change password**: enter the current password and the new one twice. Every
other device is signed out.

### Forgot the password

Run this in the Pydroid terminal, in the application folder:

```bash
python server.py --reset-password
```

It asks for a new password, stores its bcrypt hash and signs every browser out. The running
server picks it up at the next sign-in; no restart is needed. PCs, settings and history are kept.

---

## Settings reference

All settings live in the database and are edited in **Admin > Settings**. Changes apply
immediately, except the server port.

| Setting | Default | Notes |
|---|---|---|
| Server port | 5000 | Needs a restart. The port is test-bound before it is saved, so a port that is in use or not allowed is refused |
| Stay signed in for | 30 days | 1 to 365 days of inactivity |
| Publish the status page | On | Off hides `/status` and `/status.json` |
| PCs on the status page | Counts only | Or status per PC without names, or names and status |
| Show wake activity / device load / internet connectivity / version and update status | On | Each part of the status page |
| Check whether PCs are reachable | On | Master switch for the automatic and TCP checks |
| PC check interval | 60 s | 15 to 3600. Every 10 s for three minutes after a wake request |
| Check internet connectivity | On | Connects to 1.1.1.1 and 8.8.8.8 on port 53 |
| Internet check interval | 60 s | 15 to 3600 |
| Device load sample interval | 5 s | For the System page |
| Live page refresh | 10 s | Dashboard and status page; 0 turns it off |
| Keep activity for | 90 days | Older events are deleted hourly (at most 20,000 are kept) |
| Keep wake history for | 365 days | |
| Record which device sent a wake | On | Stores the browser's IP address with each wake request. Sign-in attempts always record it, for the lockout |
| Install updates automatically | On | Read by `launcher.py` |

### Restarting

Changing the port needs a restart. **Settings > Restart server** (or the button on the Overview)
makes `server.py` exit with a special code, and `launcher.py` starts it again straight away. The
page follows the server to its new port by itself. Without `launcher.py`, stop the server and
start it again.

---

## The database

Everything the device owns lives in **`wol.db`**, a SQLite file next to `server.py`:

| Table | Holds |
|---|---|
| `settings` | Every setting, one row each |
| `users` | The admin account: username, bcrypt password hash, session epoch, last sign-in |
| `pcs` | Each PC: name, MAC, notes, enabled, reachability check, last seen |
| `pc_addresses`, `pc_ports` | Each PC's addresses (IP or broadcast) and UDP ports |
| `wol_requests` | Every wake request: time, PC, result, packets sent, targets, errors, source |
| `events` | The activity log |
| `meta` | Installation facts: the session secret key, setup and migration times |

The schema version is stored in the file (`PRAGMA user_version`). Upgrades are applied
automatically at startup, inside a transaction, and only ever add tables, columns and indexes,
so an older release can still use a database a newer one has upgraded. `wol.db` is ignored by
git and never replaced by updates.

---

## launcher.py: watchdog, updates and rollback

Run `launcher.py` instead of `server.py`. It:

- **starts** `server.py` and **restarts** it when it exits, waiting 5 s, then doubling up to 5
  minutes if it keeps crashing (reset after 10 minutes of stable running). A restart requested
  from the admin panel happens at once.
- **checks GitHub** for a new commit on `main` every 5 minutes (a 40-byte answer; about 12 of the
  60 unauthenticated requests GitHub allows per hour). Commits that do not change the application
  (for example README edits) cause no restart.
- **installs a new release** safely:
  1. Downloads the changed files, pinned to the commit, each verified against GitHub's hash,
     into `.update/`, next to copies of the unchanged ones.
  2. Validates the complete release there: every Python file must compile, and
     `server.py --check` must import the whole application and compile every template. A
     release that fails is never installed, and the running server is not even stopped.
  3. Copies the running release to `.backup/`.
  4. Stops the server, copies `wol.db` to `wol.db.pre-update`, records the update in
     `state.json`, then installs the new files.
  5. Starts the new release and waits up to 120 s for `/health` to answer from that exact process.
  6. If it does not, restores `.backup/`, restarts the previous release and remembers the failed
     release, so it is not retried until a newer one is published.
- **protects the database**: `wol.db` is never replaced by an update. It is put back from
  `wol.db.pre-update` only when a failed release had already changed its schema. Otherwise
  everything written in the meantime is kept.
- **recovers from interruptions**: if the phone dies halfway through an install, the next start
  sees the unfinished entry in `state.json` and puts the previous release back.

**Admin > Settings > Updates** can pause automatic updates, for example while you change files
by hand. Local edits to `server.py` or `wol/` are otherwise replaced by the next update.
`launcher.py` never updates itself; the admin overview tells you when GitHub has a newer one.

Output goes to the Pydroid console only. `state.json` holds the updater's state; the admin
overview shows the installed commit, the last check and its result.

### Self-test

```bash
python launcher.py --selftest
```

Checks that this device can start processes and import Flask, reach GitHub and download from it,
replace files atomically, use SQLite and its backup API, and run the installed application's
self-check. It also reports whether the bcrypt package and `ping` are available.

### Limits

- Updates only happen while Pydroid is running. If Android kills Pydroid, or the phone reboots,
  nothing runs until you press Run on `launcher.py` again. An automation app that relaunches
  Pydroid would be needed for that; it is not part of this project.
- If the launcher is killed, `server.py` notices within 5 seconds and exits, so a new Run does
  not hit "address already in use".
- Without internet, update checks fail quietly and are retried every 5 minutes; waking PCs on
  the LAN keeps working.

---

## Health endpoint

`GET /health` answers:

```json
{"ok": true, "status": "ok", "version": "3.0.0", "build": "45a6a2c", "database": "ok",
 "schema": 1, "initialized": true, "uptime": 3605}
```

It returns HTTP 503 with `"ok": false` when the database cannot be read. Requests from the
device itself also get the per-process `token` that `launcher.py` uses to tell its own server
apart from anything else holding the port. Nothing secret is included.

---

## Console commands

Run these in the application folder, in the Pydroid terminal or any shell:

| Command | Does |
|---|---|
| `python server.py` | Runs the server without the launcher |
| `python server.py --reset-password` | Sets a new admin password and signs every browser out. Also finishes an unfinished setup |
| `python server.py --set-port 5000` | Changes the server port, for when the web interface cannot be reached |
| `python server.py --check` | Checks that this copy of the application can start. Touches no data |
| `python launcher.py --selftest` | Checks the device, see above |

---

## Troubleshooting

**The page does not load.** Check the Pydroid console: it prints the address and port. The phone
and your browser must be on the same network. If you changed the port and lost track of it, run
`python server.py --set-port 5000` and restart the launcher.

**"That form had expired".** The browser's session or form was out of date (for example after a
restart or a sign-out elsewhere). Reload the page and try again.

**Too many wrong passwords.** Wait the minutes shown, or sign in from another device.
[Forgot the password?](#forgot-the-password)

**Wake packet sent, but the PC does not start.** See
[Making Wake-on-LAN work on the PC](#making-wake-on-lan-work-on-the-pc). Add the broadcast
address if the PC has none. Use **Send test packet** on the PC's page to see exactly where the
packets went.

**The PC is on but shows Unreachable.** With the automatic check this means neither ping nor
ARP found it. Check that the PC's IP address in Admin is still correct (the router may have
given it a new one; reserve a fixed address in the router). On Android 10 and later, where the
address table is closed to apps, the PC also has to answer ping: set its network to Private, or
allow *File and Printer Sharing (Echo Request - ICMPv4-In)* in Windows Defender Firewall. Or
choose a TCP check on a port the PC answers on.

**"Another device has this IP address now".** The PC's IP address changed and something else
uses the old one. Update the address in Admin > PCs.

**Status Unknown, "can neither ping nor read the network's address table".** This Android build
allows neither. Choose a TCP check for the PC.

**Signing in takes minutes.** The bcrypt package was installed when the password was set and is
missing now (for example after Pydroid upgraded its Python). Reinstall it, or reset the password,
which re-hashes it with whatever is available.

**Admin says the bcrypt package is not installed.** See
[About bcrypt on Pydroid 3](#about-bcrypt-on-pydroid-3). Everything works without it.

**"Database unavailable".** `wol.db` could not be read: the storage is full, the file was
damaged, or it was replaced by something that is not a database. The server keeps running and
shows this page instead of crashing. Restore a backup (see below).

**An update was rolled back.** The console and **Admin > Overview** say why. The failed release
is skipped until a newer one is published. Nothing needs to be done.

**The old launcher keeps restoring the old version.** Replace `launcher.py` with the current one
([Upgrading](#step-1-replace-launcherpy)).

**Changes to config.json have no effect.** Expected: the database is the source of truth now.
Make the change in Admin instead.

---

## Backup, recovery and reset

### Back up

**Admin > Settings > Download backup** (or the button on the Overview) downloads a complete,
consistent copy of `wol.db`, made with SQLite's backup API while the server keeps running. It
contains your PCs, settings, history and the admin password hash, so keep it private.

You can also copy `wol.db` itself while the launcher is stopped.

`launcher.py` also keeps `wol.db.pre-update`, a copy taken just before the last update.

### Restore a backup

1. Stop the launcher (press Stop in Pydroid).
2. Rename the current `wol.db` to something like `wol.db.broken`. If a `wol.db-journal` file
   sits next to it, rename that to `wol.db.broken-journal`: it belongs to the old file, and left
   in place it would be applied to the backup.
3. Copy the backup into the application folder as `wol.db`.
4. Start the launcher again. Sign in with the password that was set when the backup was made.

### Reset the installation

To start over with the setup page, while keeping the old data just in case:

1. Stop the launcher.
2. Rename `wol.db` to `wol.db.old`, and `wol.db-journal` too if it exists. If a `config.json`
   (not `config.json.migrated`) is still in the folder, rename it as well, or its settings are
   imported again.
3. Start the launcher. The console shows a new setup code.

To only regain access, [reset the password](#forgot-the-password) instead; that keeps
everything else.

---

## Files and development

```
launcher.py          Supervisor: watchdog, updates, rollback (run this)
server.py            Entry point; also the console commands
wol/                 The application, updated together with server.py
  __init__.py        Version and release identity
  main.py            Startup and console commands
  web.py             Flask app, security headers, error pages
  views.py           Dashboard, sign-in, setup, System, status, health
  admin.py           Admin panel
  auth.py            Sessions, CSRF, lockout
  passwords.py       bcrypt password hashes
  bcrypt_py.py       Built-in bcrypt, used without the bcrypt package
  db.py              SQLite connections, transactions, schema migrations
  settings.py        Setting definitions and the settings cache
  pcs.py             PCs: validation, storage, wake targets
  wake.py            Magic packets
  monitor.py         Background checks: PCs (ping, ARP, TCP), internet, cleanup
  insights.py        Plain-language notes for the System page
  system.py          Device load figures
  activity.py        Activity log and wake history
  legacy.py          One-time config.json import
  templates/, static/  Pages, stylesheet and script (no CDN, works offline)
tests/               Test suite (not installed on the device)
requirements.txt     Dependencies
```

Created on the device, ignored by git, never touched by updates: `wol.db` (and SQLite's
`wol.db-journal`), `wol.db.pre-update`, `state.json`, `.backup/`, `.update/`,
`config.json.migrated`.

### Running the tests

```bash
python -m unittest discover -s tests -v
```

The suite covers the setup flow, sign-in and lockout, CSRF, admin authorization, bcrypt (the
built-in version is compared byte for byte with the bcrypt package when it is installed), the
`config.json` migration, PC management, magic packets and partial failures, reachability checks,
the public status page, backups, database errors, and `launcher.py` updates, rollbacks and
database restores with real server processes. It needs Flask; `git` history is used for the test
that upgrades from the old single-file `server.py`.

## License

This project is open source. Modify and distribute freely.

Icons: [Phosphor Icons](https://phosphoricons.com) (MIT).
