"""Wake-on-LAN: the magic packet and sending it to one PC's own targets.

A sent packet only means the packet left this device. Whether the PC woke up is for the
reachability check in monitor.py to find out, so nothing here calls a PC online.
"""
import socket

from . import activity, db, monitor, pcs


class Outcome(object):
    """What happened to one wake request."""

    def __init__(self, pc, result, sent, total, targets, failures, problems, request_id):
        self.pc, self.result, self.sent, self.total = pc, result, sent, total
        self.targets, self.failures, self.problems = targets, failures, problems
        self.request_id = request_id

    @property
    def errors(self):
        return self.problems + ["%s: %s" % failure for failure in self.failures]


def magic_packet(mac):
    """Six 0xFF bytes, then the 6-byte MAC address sixteen times."""
    return b"\xff" * 6 + mac * 16


def send_packets(packet, targets):
    """Send `packet` to every (address, port). Returns (sent, [(target, reason)]).

    One failing target never stops the rest, and nothing here raises.
    """
    sent, failures = 0, []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as e:
        return 0, [("%s:%d" % target, e.strerror or str(e)) for target in targets]
    try:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass                        # unicast targets still work without it
        for address, port in targets:
            try:
                sock.sendto(packet, (address, port))
                sent += 1
            except (OSError, OverflowError) as e:
                failures.append(("%s:%d" % (address, port), getattr(e, "strerror", None) or str(e)))
    finally:
        sock.close()
    return sent, failures


def wake(conn, pc, source, client_ip=None):
    """Send one PC's magic packets, record the attempt and return an Outcome.

    source is "dashboard" for the Wake button and "test" for Admin > PCs > Send test packet.
    """
    mac, targets, problems = pcs.wake_plan(pc)
    if mac is None or not targets:
        sent, failures = 0, []
    else:
        sent, failures = send_packets(magic_packet(mac), targets)
    total = len(targets)
    if sent and sent == total and not problems:
        result = "sent"
    elif sent:
        result = "partial"
    else:
        result = "failed"
    labels = ["%s:%d" % target for target in targets]
    errors = problems + ["%s: %s" % failure for failure in failures]
    what = "Test packet" if source == "test" else "Wake packet"
    with db.transaction(conn):
        request_id = activity.record_wol(conn, pc, source, result, sent, total, labels,
                                         "; ".join(errors) or None, client_ip)
        if result == "sent":
            activity.record(conn, "wol.sent", "%s sent to %s (%d packets)" % (what, pc["name"], sent),
                            success=True, pc=pc, client_ip=client_ip)
        elif result == "partial":
            activity.record(conn, "wol.partial", "%s sent to %s, %d of %d packets: %s"
                            % (what, pc["name"], sent, total, "; ".join(errors)),
                            level="warning", success=False, pc=pc, client_ip=client_ip)
        else:
            activity.record(conn, "wol.failed", "%s for %s not sent: %s"
                            % (what, pc["name"], "; ".join(errors) or "nothing to send"),
                            level="error", success=False, pc=pc, client_ip=client_ip)
    if sent:
        monitor.watch_after_wake(pc["id"])
    return Outcome(pc, result, sent, total, labels, failures, problems, request_id)
