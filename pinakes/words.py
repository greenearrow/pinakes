"""Ages and intervals in words (ROADMAP 79), for the command line and the web alike: standard library only."""


def _n(n, unit):
    return "%d %s%s" % (n, unit, "" if n == 1 else "s")


def ago(seconds):
    """How long ago, from seconds: "just now", "5 minutes ago", "3 hours ago", "4 days ago"; None: "never"."""
    if seconds is None:
        return "never"
    s = max(0, int(seconds))
    if s < 60:
        return "just now"
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if s >= size:
            return _n(s // size, unit) + " ago"


def every(seconds):
    """An interval: "every day", "every 6 hours", "every 36 hours", "every 90 seconds"; None: "never"."""
    if seconds is None:
        return "never"
    s = int(seconds)
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute"), (1, "second")):
        if s and s % size == 0:
            return "every " + (unit if s == size else _n(s // size, unit))
    return "every 0 seconds"
