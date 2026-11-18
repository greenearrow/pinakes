"""pinakes-agent: scan this machine's roots and send what changed.

  pinakes-agent [--config FILE] run            check conditions, scan every root, send
  pinakes-agent [--config FILE] scan [--root LABEL] [--full] [--accept-gone]
  pinakes-agent [--config FILE] send
  pinakes-agent [--config FILE] status
  pinakes-agent [--config FILE] check [--root LABEL]   count each root as a scan sees it, with this process's
                                                      rights, beside the last scan (compare: pinakes-ingest totals)
  pinakes-agent [--config FILE] renumber --after N     number the waiting batches, and the next ones, after N (the
                                                      server's last for this host; check-in does it by itself)
  pinakes-agent [--config FILE] scrub [status]         read files again and check their hashes, each filesystem's
                                                      share (run and scan do it after a scan); status: per
                                                      filesystem, its days, bytes, a night's share and oldest check

The scrub (DESIGN.md "Scrub") runs after the scans, per filesystem under the roots whose scans are all complete, as
the scrub file says (`[agent] scrub`, by default scrub.toml beside this config): the agent writes that file itself,
one block per filesystem with days = 30 (0 for a network filesystem), and the person edits the numbers. It sends its
findings only to a server that takes them (protocol 3 or later, known from the last check-in); until then it waits.

scan --full resends every file; when a scan was full from start to end, the server retires what it has of the root
that the scan didn't send: after a new machine takes over a host, the old one's files. Most of a root goes only with
--accept-gone as well.

run and send check in with the server first (ssh transport). If the two don't work together (pinakes/compat.py), the
agent is locked: it still scans and keeps its batches, sends nothing, says so in one line naming both sides and which
must update, and exits 4. The next run checks again and sends what it held once the server answers in range. A
server it can't reach is held for and retried as before. Check-in also answers the last batch number the server
applied for this host: an agent whose numbering is behind it (a new or restored state, as on a new machine) renumbers
its waiting batches to follow, and says so, rather than send numbers the server would refuse.
"""

import argparse
import glob
import os
import subprocess
import sys

from . import compat, config, fsinfo, outbox, scrub, transport
from .scan import Scanner, TooManyGone, check, check_verdict
from .state import State

DEFAULT_CONFIGS = ("~/.config/pinakes/agent.toml", "/etc/pinakes/agent.toml")


def on_ac_power():
    """True if mains power is present, or if the machine has no battery at all."""
    supplies = glob.glob("/sys/class/power_supply/*")
    mains = [s for s in supplies if _read(s + "/type") == "Mains"]
    if not mains:
        return True
    return any(_read(s + "/online") == "1" for s in mains)


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def busy(cfg):
    if not cfg.busy_command:
        return False
    return subprocess.run(cfg.busy_command, shell=True, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def find_config(given):
    if given:
        return given
    for c in DEFAULT_CONFIGS:
        c = os.path.expanduser(c)
        if os.path.exists(c):
            return c
    sys.exit("pinakes-agent: no config (looked in %s)" % ", ".join(DEFAULT_CONFIGS))


def cmd_scan(cfg, args):
    st = State(cfg.state)
    rc = 0
    try:
        sc = Scanner(cfg, st, progress=lambda m: print(m, flush=True))
        roots = [cfg.root(args.root)] if getattr(args, "root", None) else cfg.roots
        for root in roots:
            if getattr(args, "check_busy", False) and busy(cfg):
                print("busy: stopping before %s" % root.label)
                return 0
            try:
                s = sc.scan(root, full=getattr(args, "full", False), accept_gone=getattr(args, "accept_gone", False))
            except (TooManyGone, FileNotFoundError) as e:
                print("pinakes-agent: %s" % e, file=sys.stderr)
                rc = 2
                continue
            print("%(root)s: scan %(scan)d%(r)s, %(sent)d sent, %(gone)d gone, %(errors)d errors, %(batches)d batches"
                  % dict(s, r=" (resumed)" if s["resumed"] else ""))
            m = s.get("manifests")
            if m and m["manifests"]:
                print("%s: %d checksum manifest(s): %d line(s) wrong, %d listing a file not there"
                      % (root.label, m["manifests"], m["wrong"], m["missing"]))
            elif s.get("manifests_wait"):
                print("%s: manifests not checked: %s" % (root.label, s["manifests_wait"]))
        if getattr(args, "check_busy", False) and busy(cfg):
            print("busy: no scrub")
            return rc
        rc = max(rc, run_scrub(cfg, st, [r.label for r in roots] if getattr(args, "root", None) else None))
    finally:
        st.close()
    return rc


SCRUB_PROTOCOL = 3      # the oldest server that takes the scrub's batches (the "scrub" header, mismatch, unreadable)


def scrub_waits(cfg, st):
    """Why the scrub can't send to this agent's server yet, or None. An agent on the server itself (directory
    transport) is from the same install; over ssh, the protocol its last check-in answered."""
    if cfg.transport["kind"] != "ssh":
        return None
    p = st.get_meta("server_protocol")
    if p is not None and int(p) >= SCRUB_PROTOCOL:
        return None
    return ("the server %s; the scrub waits for one of protocol %d or later"
            % ("hasn't checked in yet" if p is None else "is at protocol %s" % p, SCRUB_PROTOCOL))


def _gb(n):
    return "%.1f GB" % (n / 1e9)


def run_scrub(cfg, st, only_roots=None):
    """The scrub after a scan (or alone): one line per filesystem. Returns an exit status."""
    why = scrub_waits(cfg, st)
    if why:
        print("scrub: not run: %s" % why)
        return 0
    sc = scrub.Scrubber(cfg, st, progress=lambda m: print(m, flush=True))
    try:
        results = sc.run(cfg.scrub_max_minutes, only_roots=only_roots)
    except config.ConfigError as e:
        print("pinakes-agent: scrub: %s" % e, file=sys.stderr)
        return 2
    for line in sc.notes:
        print(line)
    for r in results:
        if r["skipped"]:
            print("scrub %s (%s): %s" % (r["mount"], r["id"], r["skipped"]))
        else:
            print("scrub %s (%s): %d files, %s of %s, %d mismatch(es), %d unreadable" % (
                r["mount"], r["id"], r["files"], _gb(r["bytes"]), _gb(r["budget"]), r["mismatches"],
                r["unreadable"]))
    return 0


def cmd_scrub(cfg, args):
    st = State(cfg.state)
    try:
        if args.what != "status":
            return run_scrub(cfg, st)
        sc = scrub.Scrubber(cfg, st)
        try:
            rows = sc.status()
        except config.ConfigError as e:
            print("pinakes-agent: scrub: %s" % e, file=sys.stderr)
            return 2
        for line in sc.notes:
            print(line)
        print("scrub file: %s" % cfg.scrub)
        why = scrub_waits(cfg, st)
        if why:
            print("not running: %s" % why)
        for r in rows:
            last = r["last"]
            print("%s (%s, %s; root%s %s): days %s, %s, %s a night; oldest check %s, %d file(s) never checked; "
                  "last run %s" % (
                      r["mount"], r["id"], r["fstype"], "s" if len(r["roots"]) > 1 else "", ", ".join(r["roots"]),
                      r["days"] if r["days"] else "0 (off)", _gb(r["bytes"]), _gb(r["per_night"]),
                      r["oldest"] or "never", r["never"],
                      "%s: %d files, %s, %d mismatch(es), %d unreadable" % (
                          _utc(last["at"]), last["files"], _gb(last["bytes"]), last["mismatches"],
                          last["unreadable"]) if last else "never"))
    finally:
        st.close()
    return 0


def next_number(cfg):
    """The number of the next batch to send, and its header's digest (hex): the first waiting, else the next to be
    written (no digest)."""
    pend = outbox.pending(cfg.outbox)
    if pend:
        return pend[0][0], outbox.header_digest(outbox.read(pend[0][1])[0]).hex()
    st = State(cfg.state)
    try:
        return st.next_seq(), None
    finally:
        st.close()


def follow(cfg, last_seq, last_digest=None):
    """Number the waiting batches, and the next ones, after last_seq, the server's last for this host, if they
    aren't already. A first waiting batch that is that last one sent again (the same header: its acknowledgement was
    lost) keeps its number; the server acknowledges it as a duplicate. Returns a line saying what changed, or None."""
    st = State(cfg.state)
    try:
        st.begin()                                  # a scan writing a batch meanwhile waits, then is renumbered too
        pend = outbox.pending(cfg.outbox)
        if (pend and last_digest and pend[0][0] == last_seq
                and outbox.header_digest(outbox.read(pend[0][1])[0]).hex() == last_digest):
            pend = pend[1:]
        nxt = st.next_seq()
        low = pend[0][0] if pend else nxt
        if low > last_seq:
            st.rollback()
            return None
        shift = last_seq + 1 - low
        if pend:
            for seq, path in reversed(pend):
                header, records = outbox.read(path)
                outbox.write_as(cfg.outbox, seq + shift, header, records)
                os.remove(path)
        st.set_next_seq(max(nxt + shift, last_seq + 1))
        st.commit()
    except BaseException:
        st.rollback()
        raise
    finally:
        st.close()
    return ("the server has applied this host's batches up to %d and this agent's numbering was behind it (a new or "
            "restored state): %s; it continues after %d" % (
                last_seq, "%d waiting batch(es) renumbered %d-%d to %d-%d" % (
                    len(pend), pend[0][0], pend[-1][0], pend[0][0] + shift, pend[-1][0] + shift)
                if pend else "no batch waiting", last_seq))


def check_in(cfg):
    """Ask the server what it runs, before sending: ("ok", None), ("locked", why) or ("unreachable", why). The
    directory transport is an agent on the server itself, from the same install: ("ok", None). A server that answers
    its last batch number for this host has the agent follow it (follow())."""
    if cfg.transport["kind"] != "ssh":
        return "ok", None
    try:
        srv = transport.hello(cfg.transport, *next_number(cfg))
    except (OSError, transport.SendError) as e:
        return "unreachable", str(e)
    s_proto = compat.as_int(srv.get("protocol"))
    st = State(cfg.state)
    try:
        st.set_meta("server_protocol", str(s_proto))      # whether the scrub's batches can go (scrub_waits())
    finally:
        st.close()
    v = compat.verdict(compat.PROTOCOL, compat.MIN_SERVER_PROTOCOL, s_proto,
                       compat.as_int(srv.get("min_agent_protocol")))
    if v is None and srv.get("schema_applied") is False:
        v = "server", "its catalog lacks %s" % ", ".join(map(str, srv.get("upgrades_missing") or ["an upgrade"]))
    if v is None:
        last = compat.as_int(srv.get("last_seq"), None)
        if last is not None:
            said = follow(cfg, last, srv.get("last_header_sha256") if isinstance(srv.get("last_header_sha256"), str)
                          else None)
            if said:
                print("pinakes-agent: %s" % said, file=sys.stderr, flush=True)
        return "ok", None
    s_rel = srv.get("release")
    return "locked", "agent release %d protocol %d, server %s protocol %d: the %s must update (%s)" % (
        compat.RELEASE, compat.PROTOCOL, "release %s" % s_rel if s_rel is not None else "from before check-in",
        s_proto, v[0], v[1])


def cmd_send(cfg, args, checked=None):
    status, why = checked or check_in(cfg)
    if status == "locked":
        print("pinakes-agent: locked: %s; scanning goes on, %d batch(es) held, nothing sent until then"
              % (why, len(outbox.pending(cfg.outbox))), file=sys.stderr, flush=True)
        return compat.LOCKED_EXIT
    if status == "unreachable":
        print("pinakes-agent: %s; batches are kept, and sent once the server answers" % why, file=sys.stderr,
              flush=True)
    sent, err = transport.send_pending(cfg)
    print("sent %d batch(es)" % sent)
    if err:
        print("pinakes-agent: %s" % err, file=sys.stderr)
        return 1
    return 0


def cmd_renumber(cfg, args):
    said = follow(cfg, args.after)
    print(said or "nothing to do: the next batch is already after %d" % args.after)
    return 0


def cmd_status(cfg, args):
    st = State(cfg.state)
    try:
        for r in cfg.roots:
            n = st.db.execute("SELECT count(*) FROM files WHERE root = ?", (r.label,)).fetchone()[0]
            last = st.db.execute("SELECT max(finished) FROM scans WHERE root = ?", (r.label,)).fetchone()[0]
            open_ = st.db.execute("SELECT count(*) FROM scans WHERE root = ? AND finished IS NULL",
                                  (r.label,)).fetchone()[0]
            print("%-20s %8d files  last complete scan %s%s" % (
                r.label, n, _fmt(last), "  (one unfinished)" if open_ else ""))
    finally:
        st.close()
    print("%d batch(es) waiting; statx %s" % (len(outbox.pending(cfg.outbox)),
                                              "available" if fsinfo.has_statx() else "missing (no birth times)"))
    return 0


def cmd_check(cfg, args):
    st = State(cfg.state)
    rc = 0
    try:
        for r in [cfg.root(args.root)] if args.root else cfg.roots:
            try:
                c = check(r, st)
            except OSError as e:
                print("%s: %s" % (r.label, e), file=sys.stderr)
                rc = 2
                continue
            errs = ", ".join("%s %d" % kv for kv in sorted(c["errors"].items())) or "none"
            print("%s: disk %d files %d bytes; last scan (started %s UTC) %d files %d bytes; changed since %d files "
                  "%d bytes; errors %s: %s"
                  % (r.label, c["files"], c["bytes"], _utc(c["since"]), c["state_files"], c["state_bytes"],
                     c["changed"], c["changed_bytes"], errs, check_verdict(c)))
    finally:
        st.close()
    return rc


def _utc(t):
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t)) if t else "never"


def _fmt(t):
    import time
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "never"


def cmd_run(cfg, args):
    if cfg.only_on_ac and not on_ac_power():
        print("on battery: not scanning")
        return 0
    if busy(cfg):
        print("busy: not scanning")
        return 0
    args.check_busy = True
    checked = check_in(cfg)                     # before anything is sent; a locked agent still scans
    rc = cmd_scan(cfg, args)
    return max(rc, cmd_send(cfg, args, checked))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pinakes-agent", description=__doc__.split("\n")[0])
    ap.add_argument("--config")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    s = sub.add_parser("scan")
    s.add_argument("--root")
    s.add_argument("--full", action="store_true", help="also resend unchanged records (after a server restore)")
    s.add_argument("--accept-gone", action="store_true", help="report files gone even if most of a root is missing")
    sub.add_parser("send")
    sub.add_parser("status")
    c = sub.add_parser("check")
    c.add_argument("--root")
    r = sub.add_parser("renumber", help="number the waiting batches and the next ones after N")
    r.add_argument("--after", type=int, required=True, metavar="N")
    b = sub.add_parser("scrub", help="read files again and check their hashes; status: what it does where")
    b.add_argument("what", nargs="?", choices=["status"])
    args = ap.parse_args(argv)
    cfg = config.load(find_config(args.config))
    os.makedirs(os.path.dirname(os.path.abspath(cfg.state)), exist_ok=True)
    commands = {"run": cmd_run, "scan": cmd_scan, "send": cmd_send, "status": cmd_status, "check": cmd_check,
                "renumber": cmd_renumber, "scrub": cmd_scrub}
    return commands[args.cmd](cfg, args)


if __name__ == "__main__":
    sys.exit(main())
