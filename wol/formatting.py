"""How numbers and times read on the pages. Values keep their unit on one line."""
from datetime import datetime, timezone

from . import db

BYTE_UNITS = ["B", "kB", "MB", "GB", "TB", "PB"]


def local(moment):
    """An aware local datetime from a datetime or a stored timestamp, or None."""
    if isinstance(moment, str):
        text = moment
        moment = db.parse_time(text)
        if moment is None:
            try:
                moment = datetime.fromisoformat(text)     # "2026-09-18T14:02:11+02:00"
            except ValueError:
                return None
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone()


def clock(moment):
    """19:12:28 for today, 2026-09-16 19:12 for earlier days."""
    moment = local(moment)
    if moment is None:
        return ""
    today = datetime.now(timezone.utc).astimezone().date()
    return moment.strftime("%H:%M:%S" if moment.date() == today else "%Y-%m-%d %H:%M")


def duration(seconds):
    """45 s, 12 min, 3 h 5 min or 2 d 4 h."""
    minutes, seconds = divmod(int(max(0, seconds)), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return "%d d %d h" % (days, hours)
    if hours:
        return "%d h %d min" % (hours, minutes)
    return "%d min" % minutes if minutes else "%d s" % seconds


def ago(moment):
    """just now, 4 min ago, 3 h ago, 2 d ago."""
    moment = local(moment)
    if moment is None:
        return ""
    seconds = (datetime.now(timezone.utc) - moment).total_seconds()
    if seconds < 45:
        return "just now"
    return " ".join(duration(seconds).split(" ")[:2]) + " ago"   # "3 h 5 min" -> "3 h ago"


def format_bytes(count):
    """340 MB, 1.2 GB, 57 GB."""
    if count is None:
        return None
    size = float(count)
    for unit in BYTE_UNITS:
        if size < 1000 or unit == BYTE_UNITS[-1]:
            return "%.*f %s" % (1 if size < 10 and unit != "B" else 0, size, unit)
        size /= 1000.0


def format_rate(per_second):
    return None if per_second is None else format_bytes(per_second) + "/s"


def format_percent(value):
    """Whole percent, except below 10 %, where one decimal keeps small loads visible."""
    if value is None:
        return None
    return "%.1f%%" % value if 0 < value < 9.95 and round(value, 1) != round(value) else "%d%%" % round(value)


def plural(count, singular, plural_form=None):
    return "%d %s" % (count, singular if count == 1 else (plural_form or singular + "s"))
