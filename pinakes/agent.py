"""pinakes-agent: scan this machine's roots and send what changed.

  pinakes-agent [--config FILE] run            check conditions, scan every root, send
  pinakes-agent [--config FILE] scan [--root LABEL] [--full] [--accept-gone]
  pinakes-agent [--config FILE] send
  pinakes-agent [--config FILE] status
  pinakes-agent [--config FILE] check [--root LABEL]   count each root as a scan sees it, with this process's
                                                      rights, beside the last scan (compare: pinakes-ingest totals)
"""

import argparse
import glob
import os
import subprocess
import sys

from . import config, fsinfo, outbox, transport
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
    finally:
        st.close()
    return rc


def cmd_send(cfg, args):
    sent, err = transport.send_pending(cfg)
    print("sent %d batch(es)" % sent)
    if err:
        print("pinakes-agent: %s" % err, file=sys.stderr)
        return 1
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
    rc = cmd_scan(cfg, args)
    return max(rc, cmd_send(cfg, args))


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
    args = ap.parse_args(argv)
    cfg = config.load(find_config(args.config))
    os.makedirs(os.path.dirname(os.path.abspath(cfg.state)), exist_ok=True)
    commands = {"run": cmd_run, "scan": cmd_scan, "send": cmd_send, "status": cmd_status, "check": cmd_check}
    return commands[args.cmd](cfg, args)


if __name__ == "__main__":
    sys.exit(main())
