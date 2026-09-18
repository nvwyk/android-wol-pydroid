"""PCs. Each one has its own MAC address, wake targets, ports and reachability check.

Form input is validated here before it is stored, and everything read back is validated
again before a packet is sent: a PC imported from an old config.json, or edited by hand
in the database, can hold values that were never checked.
"""
import ipaddress
import re
import string

from . import db

NAME_MAX = 60
DESCRIPTION_MAX = 500
MAX_ADDRESSES = 8
MAX_PORTS = 8
DEFAULT_PORTS = [9]
# "ping" is stored for the automatic check (ping, then ARP); the value predates ARP.
STATUS_METHODS = [("ping", "Automatic"), ("tcp", "TCP port"), ("none", "Off")]

_SEPARATORS = re.compile(r"[\s,;]+")


def parse_mac(value):
    """The 6 bytes of 24-4B-FE-07-0C-E2, 24:4b:fe:07:0c:e2, 244b.fe07.0ce2 or 244BFE070CE2."""
    digits = "".join(c for c in str(value) if c not in "-:. ")
    if len(digits) != 12 or not all(c in string.hexdigits for c in digits):
        return None
    return bytes.fromhex(digits)


def format_mac(mac):
    return "-".join("%02X" % byte for byte in mac)


def split_list(text):
    return [part for part in _SEPARATORS.split(str(text or "").strip()) if part]


def check_address(text):
    """A normalized IPv4 address that can receive a UDP packet, else ValueError."""
    try:
        address = ipaddress.IPv4Address(text.strip())
    except (ValueError, ipaddress.AddressValueError):
        raise ValueError("%s is not an IPv4 address." % text)
    if address.is_unspecified:
        raise ValueError("%s cannot receive packets." % address)
    if address.is_loopback:
        raise ValueError("%s is this device itself, not the PC." % address)
    if address.is_multicast:
        raise ValueError("%s is a multicast address." % address)
    return str(address)


def check_port(text):
    try:
        port = int(str(text).strip())
    except ValueError:
        raise ValueError("%s is not a port number." % text)
    if not 1 <= port <= 65535:
        raise ValueError("Ports go from 1 to 65535, not %d." % port)
    return port


def _unique(items):
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def validate(form):
    """(values, errors) from the PC form. errors maps field name to a message."""
    errors = {}
    name = " ".join(form.get("name", "").split())
    if not name:
        errors["name"] = "Give the PC a name."
    elif len(name) > NAME_MAX:
        errors["name"] = "Use at most %d characters." % NAME_MAX

    mac = parse_mac(form.get("mac", ""))
    if not form.get("mac", "").strip():
        errors["mac"] = "Enter the MAC address of the PC's network adapter."
    elif mac is None:
        errors["mac"] = "Write it as six pairs of hex digits, like 24-4B-FE-07-0C-E2."

    lists = {}
    for field, label in (("hosts", "IP addresses"), ("broadcasts", "Broadcast addresses")):
        items, problems = [], []
        for part in split_list(form.get(field, "")):
            try:
                items.append(check_address(part))
            except ValueError as e:
                problems.append(str(e))
        items = _unique(items)
        if problems:
            errors[field] = problems[0]
        elif len(items) > MAX_ADDRESSES:
            errors[field] = "Use at most %d %s." % (MAX_ADDRESSES, label.lower())
        lists[field] = items
    if not lists["hosts"] and not lists["broadcasts"] and "hosts" not in errors \
            and "broadcasts" not in errors:
        errors["broadcasts"] = ("Add at least one address to send the packet to. The "
                                "network's broadcast address, such as 192.168.1.255, "
                                "works best.")

    ports = []
    try:
        ports = _unique(check_port(part) for part in split_list(form.get("ports", "")))
        if not ports:
            errors["ports"] = "Add at least one UDP port. Most PCs listen on 9."
        elif len(ports) > MAX_PORTS:
            errors["ports"] = "Use at most %d ports." % MAX_PORTS
    except ValueError as e:
        errors["ports"] = str(e)

    method = form.get("status_method", "ping")
    if method not in dict(STATUS_METHODS):
        method = "ping"
    status_port = None
    if method == "tcp":
        try:
            status_port = check_port(form.get("status_port", ""))
        except ValueError:
            errors["status_port"] = "Enter the TCP port to probe, for example 3389 or 22."
    if method != "none" and not lists["hosts"] and "hosts" not in errors:
        errors["status_method"] = ("Checking needs the PC's own IP address. Add it above, "
                                   "or turn the check off.")

    description = form.get("description", "").strip()
    if len(description) > DESCRIPTION_MAX:
        errors["description"] = "Use at most %d characters." % DESCRIPTION_MAX

    values = {
        "name": name,
        "mac": format_mac(mac) if mac else form.get("mac", "").strip(),
        "hosts": lists["hosts"],
        "broadcasts": lists["broadcasts"],
        "ports": ports,
        "description": description,
        "enabled": bool(form.get("enabled")),
        "status_method": method,
        "status_port": status_port,
    }
    return values, errors


def form_values(pc):
    """The form's text fields for an existing PC."""
    return {
        "name": pc["name"], "mac": pc["mac"], "description": pc["description"],
        "hosts": ", ".join(pc["hosts"]), "broadcasts": ", ".join(pc["broadcasts"]),
        "ports": ", ".join(str(port) for port in pc["ports"]),
        "enabled": pc["enabled"], "status_method": pc["status_method"],
        "status_port": pc["status_port"] or "",
    }


def _assemble(rows, conn):
    pcs = []
    by_id = {}
    for row in rows:
        pc = dict(row)
        pc["enabled"] = bool(pc["enabled"])
        pc["hosts"], pc["broadcasts"], pc["ports"] = [], [], []
        pcs.append(pc)
        by_id[pc["id"]] = pc
    if by_id:
        placeholders = ",".join("?" * len(by_id))
        ids = list(by_id)
        for row in conn.execute("SELECT pc_id, kind, address FROM pc_addresses WHERE pc_id IN "
                                "(%s) ORDER BY position, id" % placeholders, ids):
            by_id[row["pc_id"]]["hosts" if row["kind"] == "host" else "broadcasts"].append(
                row["address"])
        for row in conn.execute("SELECT pc_id, port FROM pc_ports WHERE pc_id IN (%s) "
                                "ORDER BY position, id" % placeholders, ids):
            by_id[row["pc_id"]]["ports"].append(row["port"])
    return pcs


def load_all(conn):
    return _assemble(conn.execute(
        "SELECT * FROM pcs ORDER BY sort_order, name COLLATE NOCASE, id").fetchall(), conn)


def get(conn, pc_id):
    found = _assemble(conn.execute("SELECT * FROM pcs WHERE id = ?", (pc_id,)).fetchall(), conn)
    return found[0] if found else None


def counts(conn):
    row = conn.execute("SELECT count(*) AS total, sum(enabled) AS enabled FROM pcs").fetchone()
    return row["total"] or 0, row["enabled"] or 0


def name_taken(conn, name, exclude_id=None):
    row = conn.execute("SELECT id FROM pcs WHERE name = ? COLLATE NOCASE AND id != ?",
                       (name, exclude_id or 0)).fetchone()
    return row is not None


def _write_children(conn, pc_id, values):
    conn.execute("DELETE FROM pc_addresses WHERE pc_id = ?", (pc_id,))
    conn.execute("DELETE FROM pc_ports WHERE pc_id = ?", (pc_id,))
    position = 0
    for kind, field in (("host", "hosts"), ("broadcast", "broadcasts")):
        for address in values[field]:
            conn.execute("INSERT INTO pc_addresses (pc_id, kind, address, position) "
                         "VALUES (?, ?, ?, ?)", (pc_id, kind, address, position))
            position += 1
    for position, port in enumerate(values["ports"]):
        conn.execute("INSERT INTO pc_ports (pc_id, port, position) VALUES (?, ?, ?)",
                     (pc_id, port, position))


def create(conn, values):
    stamp = db.now()
    with db.transaction(conn):
        order = conn.execute("SELECT coalesce(max(sort_order), 0) + 1 FROM pcs").fetchone()[0]
        pc_id = conn.execute(
            "INSERT INTO pcs (name, mac, description, enabled, status_method, status_port, "
            "sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (values["name"], values["mac"], values["description"], int(values["enabled"]),
             values["status_method"], values["status_port"], order, stamp, stamp)).lastrowid
        _write_children(conn, pc_id, values)
    return pc_id


def update(conn, pc_id, values):
    with db.transaction(conn):
        conn.execute(
            "UPDATE pcs SET name = ?, mac = ?, description = ?, enabled = ?, status_method = ?, "
            "status_port = ?, updated_at = ? WHERE id = ?",
            (values["name"], values["mac"], values["description"], int(values["enabled"]),
             values["status_method"], values["status_port"], db.now(), pc_id))
        _write_children(conn, pc_id, values)


def set_enabled(conn, pc_id, enabled):
    conn.execute("UPDATE pcs SET enabled = ?, updated_at = ? WHERE id = ?",
                 (int(enabled), db.now(), pc_id))


def delete(conn, pc_id):
    """Remove the PC, its addresses and ports. Its history stays, with the PC's name."""
    conn.execute("DELETE FROM pcs WHERE id = ?", (pc_id,))


def changes(old, new):
    """What an edit changed, in words, for the activity log."""
    labels = [("name", "name"), ("mac", "MAC address"), ("hosts", "IP addresses"),
              ("broadcasts", "broadcast addresses"), ("ports", "ports"),
              ("description", "description"), ("enabled", "enabled"),
              ("status_method", "reachability check"), ("status_port", "check port")]
    return [label for key, label in labels if old.get(key) != new.get(key)]


def wake_plan(pc):
    """(mac bytes or None, [(address, port)], [problems]) from a PC's stored values.

    Only this PC's own MAC and addresses go into the plan, and every value is checked
    again, so one bad entry is skipped and reported instead of stopping the others.
    """
    problems = []
    mac = parse_mac(pc["mac"])
    if mac is None:
        problems.append("The MAC address %s is not valid." % pc["mac"])
    addresses = []
    for address in pc["hosts"] + pc["broadcasts"]:
        try:
            addresses.append(check_address(address))
        except ValueError as e:
            problems.append(str(e))
    ports = []
    for port in pc["ports"]:
        try:
            ports.append(check_port(port))
        except ValueError as e:
            problems.append(str(e))
    if not addresses:
        problems.append("There is no valid address to send the packet to.")
    if not ports:
        problems.append("There is no valid UDP port to send the packet to.")
    targets = [(address, port) for address in _unique(addresses) for port in _unique(ports)]
    return mac, targets[:MAX_ADDRESSES * 2 * MAX_PORTS], problems


def check_host(pc):
    """The address the reachability check probes: the PC's first valid IP address."""
    for address in pc["hosts"]:
        try:
            return check_address(address)
        except ValueError:
            continue
    return None


def hints(pc, lan_address=None, others=()):
    """Advice about a PC's wake setup that is not strictly an error. `others` are the
    other PCs, to spot two entries for the same network adapter."""
    advice = []
    twins = [other["name"] for other in others
             if other["id"] != pc["id"] and parse_mac(other["mac"]) == parse_mac(pc["mac"])]
    if twins:
        advice.append("%s has the same MAC address. Both entries wake the same network "
                      "adapter; delete one, or correct the MAC if they are different PCs."
                      % " and ".join(twins))
    if not pc["broadcasts"]:
        advice.append("No broadcast address. A sleeping PC often misses packets sent to its "
                      "own IP, because the network forgets where that IP lives. Add the "
                      "broadcast address, for example 192.168.1.255.")
    if lan_address:
        try:
            local = ipaddress.IPv4Network(lan_address + "/24", strict=False)
            for address in pc["hosts"] + pc["broadcasts"]:
                ip = ipaddress.IPv4Address(address)
                if ip != ipaddress.IPv4Address("255.255.255.255") and ip not in local:
                    advice.append("%s is outside this device's network (%s). Wake packets "
                                  "normally do not cross routers." % (address, local))
                    break
        except ValueError:
            pass
    return advice
