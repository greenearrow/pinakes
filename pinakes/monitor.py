"""The agent reports each `run` to a push monitor (ROADMAP 51): `[monitor] url_file` in agent.toml names a file
holding the push URL; the agent calls it at the end of every run, up with a summary in counts, down with the
reason. The URL is a secret (whoever has it can mark the host up), so it lives only in that file: never in the
config, the command line or a message. A report that fails is one line on stderr, without the URL, and never
changes the run's exit status.

The URL's form is the push form with the state in its query (status=up or down, msg=...): the agent replaces
those, and ping, in the URL it reads, and keeps the rest. What it says is counts and reasons from a fixed set (a
root's label, a protocol, a batch count), never a path, a file's name or an error's text.
"""

import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 10        # seconds for the whole call
MSG_MAX = 250


class NoURL(Exception):
    pass


def read_url(path):
    """The push URL in that file: its first line that isn't empty or a # comment, http or https with a host."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f]
    except FileNotFoundError:
        raise NoURL("no push URL file at %s" % path)
    except (OSError, UnicodeDecodeError) as e:
        raise NoURL("the push URL file %s can't be read (%s)" % (path, type(e).__name__))
    url = next((l for l in lines if l and not l.startswith("#")), "")
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise NoURL("the push URL file %s holds no http or https URL" % path)
    return url


def push_url(url, up, msg):
    p = urllib.parse.urlsplit(url)
    q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
         if k not in ("status", "msg", "ping")]
    q += [("status", "up" if up else "down"), ("msg", msg[:MSG_MAX])]
    return urllib.parse.urlunsplit(p._replace(query=urllib.parse.urlencode(q)))


def _why(e):
    """Why a call failed, in words that can't hold the URL: a status code, an errno's text or the error's kind."""
    if isinstance(e, urllib.error.HTTPError):
        return "HTTP %d" % e.code
    if isinstance(e, urllib.error.URLError):
        e = e.reason if isinstance(e.reason, BaseException) else e
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "timed out"
    if isinstance(e, OSError) and e.strerror and not e.filename:
        return e.strerror.lower()
    return type(e).__name__


def push(url, up, msg, timeout=None):
    """Call the monitor. None if it answered 2xx, else why not (never the URL)."""
    req = urllib.request.Request(push_url(url, up, msg), headers={"User-Agent": "pinakes-agent"})
    try:
        with urllib.request.urlopen(req, timeout=timeout or TIMEOUT) as r:
            r.read(4096)
            return None if 200 <= r.status < 300 else "HTTP %d" % r.status
    except Exception as e:                      # nothing about the call may fail the run
        return _why(e)


def report(path, up, msg, err=None):
    """Report a run, if the agent has a [monitor]: one line on err (stderr) if it couldn't."""
    if not path:
        return
    err = err or sys.stderr
    try:
        url = read_url(path)
    except NoURL as e:
        print("pinakes-agent: monitor: not reported: %s" % e, file=err, flush=True)
        return
    why = push(url, up, msg)
    if why:
        print("pinakes-agent: monitor: not reported: %s" % why, file=err, flush=True)
