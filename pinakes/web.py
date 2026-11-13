"""pinakes-web: the web UI (Flask, served by waitress). Read-only on the catalog for now, plus sign-in, a second
factor, and the administrator's step-up.

  pinakes-web --config /etc/pinakes/server.toml

/health answers without sign-in, for monitoring: whether the database is reachable, and per host its newest batch,
last complete scan, whether it is stale, whether its batches are being refused (protocol or sequence) and when its
agent's numbering last went back (200 when all is well, 503 when a host is stale or refused). It names hosts, never
a root, person or file. [web] health_listen serves it alone on a second address, for a monitor that can't reach the
UI's.
"""

import argparse
import datetime
import functools
import json
from urllib.parse import urlencode
import os
import secrets
import sys
import time

import psycopg
from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for

from . import auth, queries, registry
from .server_config import load as load_server_config

LOGIN_LIMIT = 5          # failed sign-ins per address
PER_PAGE = (50, 100, 250, 500)   # the page sizes offered; the first after 50 is the default
LOGIN_WINDOW = 15 * 60   # seconds


class Pager:
    """One paged list on a page: its page number comes from the query parameter `param`, the page size from `per`
    (shared by every list on the page), its sort from `sort` and `dir` (`<param>_sort` and `<param>_dir` for a list
    with its own page parameter). `sorts` is the query's whitelist (queries.*_SORT): a column it doesn't name is no
    sort, the query's default order. Call done() with the rows the query returned."""

    def __init__(self, param="page", default_per=100, sorts=None):
        self.param = param
        self.sort_param, self.dir_param = ("sort", "dir") if param == "page" else (param + "_sort", param + "_dir")
        sort = request.args.get(self.sort_param)
        self.sort = sort if sorts and sort in sorts else None
        self.dir = "desc" if self.sort and request.args.get(self.dir_param) == "desc" else "asc"
        try:
            self.page = max(1, int(request.args.get(param, 1)))
        except ValueError:
            self.page = 1
        try:
            per = int(request.args.get("per", default_per))
        except ValueError:
            per = default_per
        self.per = per if per in PER_PAGE else default_per
        self.offset = (self.page - 1) * self.per
        self.total = self.shown = 0

    def done(self, result):
        self.total = queries.page_total(result)
        self.shown = len(result)
        return result

    @property
    def pages(self):
        return max(1, -(-self.total // self.per))

    @property
    def first(self):
        return self.offset + 1 if self.shown else 0

    @property
    def last(self):
        return self.offset + self.shown

    @property
    def order(self):
        """The query's sort arguments: sort=, direction=."""
        return {"sort": self.sort, "direction": self.dir}

    def url(self, page=None, per=None, sort=None, dir="asc"):
        """This page with another page, page size or sort of this list; the others stay. A new size or sort starts
        at page 1. sort= a column, dir= "asc" or "desc"."""
        args = request.args.to_dict()
        args[self.param] = page if page is not None else self.page
        if self.sort:
            args[self.sort_param], args[self.dir_param] = self.sort, self.dir
        else:
            args.pop(self.sort_param, None)
            args.pop(self.dir_param, None)
        if per is not None:
            args["per"] = per
            args[self.param] = 1
        if sort is not None:
            args[self.sort_param] = sort
            args[self.dir_param] = "desc" if dir == "desc" else "asc"
            args[self.param] = 1
        return request.path + "?" + urlencode(args)

    @property
    def needed(self):
        return self.total > self.per or self.page > 1


LINKS_SHOWN = 200  # symlinks into a folder listed on its safe-to-delete page; the total is said


def _iso(t):
    return t.isoformat() if t else None


def health_report(connect):
    """(HTTP status, body) for /health."""
    try:
        db = connect()
    except psycopg.Error:
        return 503, {"status": "down", "database": "unreachable", "hosts": []}
    try:
        hosts = queries.health(db)
    except psycopg.Error:
        return 503, {"status": "down", "database": "error", "hosts": []}
    finally:
        db.close()
    status = ("refused" if any(h["refused"] for h in hosts) else "stale" if any(h["stale"] for h in hosts)
              else "ok")
    body = {"status": status, "database": "ok",
            "hosts": [{"host": h["host"], "newest_batch": _iso(h["newest_batch"]), "last_scan": _iso(h["last_scan"]),
                       "expected_every_s": int(h["expected_every"].total_seconds()) if h["expected_every"] else None,
                       "stale": h["stale"], "refused": h["refused"], "seq_reset": _iso(h["seq_reset_at"])}
                      for h in hosts]}
    return (200 if body["status"] == "ok" else 503), body


def _health_response(connect):
    code, body = health_report(connect)
    resp = jsonify(body)
    resp.status_code = code
    resp.headers["Cache-Control"] = "no-store"
    return resp


def create_health_app(cfg, connect=None):
    """An app with /health only, for [web] health_listen."""
    app = Flask(__name__)
    connect = connect or _connector(cfg.web)

    @app.route("/health")
    def health():
        return _health_response(connect)

    return app


def _connector(web):
    def default_connect():
        kw = {"conninfo": web.get("dsn", ""), "connect_timeout": 5}
        pw = web.get("password_file")
        if pw and os.path.exists(pw):
            with open(pw) as f:
                kw["password"] = f.read().strip()
        return psycopg.connect(**kw)
    return default_connect


def create_app(cfg, connect=None):
    app = Flask(__name__)
    web = cfg.web
    if web.get("behind_proxy"):
        # One reverse proxy in front (it sets X-Forwarded-For and -Proto): without this every visitor is the proxy's
        # address, and the per-address sign-in limit becomes one limit for everybody. Trust exactly one hop.
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    key_file = web.get("session_key_file")
    if key_file and os.path.exists(key_file):
        with open(key_file, "rb") as f:
            app.secret_key = f.read().strip()
    else:
        app.secret_key = web.get("session_key") or secrets.token_bytes(32)  # tests and first runs only
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      SESSION_COOKIE_SECURE=web.get("secure_cookies", True),
                      PERMANENT_SESSION_LIFETIME=_seconds(web.get("idle_timeout", "30m")))
    step_minutes = _seconds(web.get("step_up_duration", "15m")) // 60
    failures = {}

    connect = connect or _connector(web)
    reg = registry.load(getattr(cfg, "schemas_dir", None))     # what metadata is shown by; a bad schema stops startup
    mapped = {c: [(registry.COMMON, c)] + [(s.name, s.common[c]) for s in reg if c in s.common]
              for c in ("creator", "date")}

    @app.route("/health")
    def health():
        return _health_response(connect)

    @app.before_request
    def open_db():
        if request.endpoint == "health":
            return                      # no session, no form; it opens its own connection, and reports a failed one
        g.db = connect()
        g.person = session.get("person")
        g.stepped_up = False
        if g.person:
            session.permanent = True
            g.db.execute("SELECT set_config('pinakes.person', %s, true), set_config('pinakes.session', %s, true)",
                         (str(g.person), session["sid"]))
            g.stepped_up = g.db.execute("SELECT pinakes.stepped_up()").fetchone()[0]
            g.roles = g.db.execute("SELECT pinakes.my_roles()").fetchone()[0] or []
            g.display = session.get("display")
        if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
            abort(400, "stale form: reload the page")

    @app.teardown_request
    def close_db(exc):
        db = g.pop("db", None)
        if db is not None:
            if exc is None:
                db.commit()
            db.close()

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def common():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return {"csrf": session["csrf"], "person": g.get("person"), "display": g.get("display"),
                "stepped_up": g.get("stepped_up"), "roles": g.get("roles", []), "fmt_size": fmt_size,
                "fmt_meta": fmt_meta, "show_hidden": bool(session.get("show_hidden")),
                "per_page": PER_PAGE}

    def show_hidden():
        return bool(session.get("show_hidden"))

    def signed_in(view):
        @functools.wraps(view)
        def wrapper(*a, **kw):
            if not g.person:
                return redirect(url_for("login", next=request.full_path))
            return view(*a, **kw)
        return wrapper

    def audit_shown(file_ids, page):
        """In a step-up, record whose records were just shown (the people affected see it on their page)."""
        if not g.stepped_up:
            return
        audit_people(queries.owners_of(g.db, file_ids), page, len(file_ids))

    def audit_people(owners, page, records):
        """In a step-up, record that records of these owners were just shown."""
        if not g.stepped_up:
            return
        others = sorted(o for o in owners if o != g.person)
        if others:
            g.db.execute("SELECT pinakes.audit_view(%s, %s::jsonb)",
                         (others, json.dumps({"page": page, "records": records})))

    # sign-in -------------------------------------------------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            addr = request.remote_addr or "?"
            recent = [t for t in failures.get(addr, []) if t > time.time() - LOGIN_WINDOW]
            if len(recent) >= LOGIN_LIMIT:
                abort(429, "too many attempts; wait a few minutes")
            name = request.form.get("name", "")
            row = g.db.execute("SELECT * FROM pinakes.login_material(%s)", (name,)).fetchone()
            ok = auth.check_password(request.form.get("password", ""), row[1] if row and row[1] else auth.DUMMY_HASH)
            if row and row[1] and ok:
                session.clear()
                session["person"] = row[0]
                session["sid"] = secrets.token_urlsafe(24)
                session["csrf"] = secrets.token_urlsafe(24)
                session["display"] = g.db.execute("SELECT display FROM pinakes.people WHERE person_id = %s",
                                                  (row[0],)).fetchone()[0]
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("home"))
            failures[addr] = recent + [time.time()]
            error = "That name and password don't match."
        return render_template("login.html", error=error)

    @app.route("/logout", methods=["POST"])
    def logout():
        if g.person:
            g.db.execute("SELECT pinakes.end_step_up()")
        session.clear()
        return redirect(url_for("login"))

    # pages ---------------------------------------------------------------------------------------------------
    @app.route("/")
    @signed_in
    def home():
        roots = queries.roots(g.db, hidden=show_hidden())
        hidden_left_out = 0 if show_hidden() else sum(r["hidden_files"] for r in roots)
        return render_template("home.html", roots=roots, stale=queries.stale(g.db), hidden_left_out=hidden_left_out)

    @app.route("/find")
    @signed_in
    def find():
        q = request.args.get("q", "").strip()
        by = request.args.get("by", "").strip()
        since, until = request.args.get("from", "").strip(), request.args.get("to", "").strip()
        pg = Pager(sorts=queries.FILE_SORT)
        error, dated = None, None
        try:
            if since or until:
                dated = (queries.date_bounds(since)[0] if since else None,
                         queries.date_bounds(until)[1] if until else None)
        except ValueError:
            error = "A date is a year, a month or a day: 2019, 2019-06 or 2019-06-01."
        searched = bool(q or by or dated) and not error
        results = []
        if searched:
            results = pg.done(queries.find_by(g.db, q, by, mapped["creator"], dated, mapped["date"],
                                              pg.per, pg.offset, hidden=show_hidden(), **pg.order))
        audit_shown([r["file_id"] for r in results], "find")
        return render_template("find.html", q=q, by=by, since=since, until=until, error=error, searched=searched,
                               results=results, pg=pg)

    @app.route("/browse/<root>/", defaults={"path": ""})
    @app.route("/browse/<root>/<path:path>")
    @signed_in
    def browse(root, path):
        pg = Pager(sorts=queries.LISTING_SORT)
        loc = "%s:%s" % (root, path)
        entries = pg.done(queries.listing(g.db, loc, pg.per, pg.offset, hidden=show_hidden(), **pg.order))
        hidden_left_out = 0 if show_hidden() else queries.hidden_in(g.db, loc)
        audit_shown([e["file_id"] for e in entries if e["file_id"]], "browse %s:%s" % (root, path))
        crumbs = []
        acc = ""
        for part in [p for p in path.split("/") if p]:
            acc = acc + "/" + part if acc else part
            crumbs.append((part, acc))
        return render_template("browse.html", root=root, path=path, entries=entries, crumbs=crumbs, pg=pg,
                               hidden_left_out=hidden_left_out)

    @app.route("/hidden-files", methods=["POST"])
    @signed_in
    def hidden_files():
        """Show or leave out hidden files in roots, browse and find, for this session. Reports always count them."""
        session["show_hidden"] = request.form.get("show") == "1"
        nxt = request.form.get("next", "")
        # this site's own path only: "//host" and "/\\host" are other sites to a browser
        return redirect(nxt if nxt[:1] == "/" and nxt[1:2] not in ("/", "\\") else url_for("home"))

    @app.route("/file/<int:file_id>")
    @signed_in
    def file(file_id):
        f = queries.file_by_id(g.db, file_id)
        if f is None:
            abort(404)  # not there, or not yours to see: the same answer
        pc = Pager("copies", 50, queries.FILE_SORT)
        pv = Pager("versions", 50, queries.VERSIONS_SORT)
        ph = Pager("history", 50, queries.HISTORY_SORT)
        copies = pc.done(queries.where(g.db, file_id, pc.per, pc.offset, **pc.order)) if f["content_id"] else []
        page = {"f": f, "copies": copies, "pc": pc,
                "versions": pv.done(queries.versions(g.db, file_id, pv.per, pv.offset, **pv.order)), "pv": pv,
                "history": ph.done(queries.history(g.db, file_id, ph.per, ph.offset, **ph.order)), "ph": ph,
                "up": queries.lineage(g.db, file_id, "up"), "down": queries.lineage(g.db, file_id, "down")}
        meta = queries.file_metadata(g.db, file_id, f["content_id"])
        page["metadata"] = metadata_view(reg, meta)
        # a note for those who can't see the sensitive fields: the same whether this file has any or not
        page["sensitive_hidden"] = [] if queries.sensitive_visible(g.db, file_id, f["content_id"]) else sorted(
            {fd.description or fd.name for s in page["metadata"] if s["schema"]
             for fd in s["schema"].fields.values() if fd.sensitive})
        shown = "file %d" % file_id + (", with sensitive metadata" if any(m["sensitive"] for m in meta) else "")
        audit_shown([file_id] + [c["file_id"] for c in copies], shown)
        return render_template("file.html", **page)

    @app.route("/reports/<name>")
    @signed_in
    def report(name):
        loc = request.args.get("loc", "").strip()
        rows, error, ch, links = [], None, None, []
        pg = Pager(sorts={"backed-up": queries.BACKED_UP_SORT, "dupes": queries.DUPES_SORT,
                          "changes": queries.CHANGES_SORT, "restore": queries.RESTORE_SORT,
                          "only-here": queries.COPY_SORT,
                          "safe-to-delete": queries.COPY_SORT}.get(name, queries.FILE_SORT))
        lim = (pg.per, pg.offset)
        try:
            if name == "only-here" and loc:
                rows = queries.only_here(g.db, loc, *lim, **pg.order)
            elif name == "safe-to-delete" and loc:
                rows = queries.not_safe_to_delete(g.db, loc, *lim, **pg.order)
                links = queries.links_into(g.db, loc, LINKS_SHOWN)
            elif name == "backed-up" and loc:
                rows = queries.backed_up(g.db, loc, *lim, **pg.order)
            elif name == "dupes":
                rows = queries.dupes(g.db, *lim, **pg.order)
            elif name == "changes":
                kinds = [k for k in request.args.getlist("what") if k in queries.KINDS]
                review = request.args.get("review") if request.args.get("review") in queries.REVIEWS else None
                ch = {"days": _int_arg("days", 7, 1, 3650), "depth": _int_arg("depth", 3, 1, 8), "kinds": kinds,
                      "review": review, "today": queries.today().isoformat(),
                      "marked": _int_arg("marked", None, 0, 10 ** 9), "asked": _int_arg("asked", None, 0, 10 ** 9)}
                tree = queries.change_tree(g.db, ch["days"], loc or None, ch["depth"], kinds, review)
                ch["tree_cut"] = len(tree) > queries.TREE_LIMIT
                ch["tree"] = tree[:queries.TREE_LIMIT]
                audit_people({o for t in ch["tree"] for o in t["owners"] or ()}, "report changes tree %s" % loc,
                             len(ch["tree"]))
                rows = queries.changes(g.db, ch["days"], None, *lim, **pg.order, kinds=kinds, loc=loc or None,
                                       review=review)
                ch["unreviewed"] = queries.page_total(queries.changes(g.db, ch["days"], None, 1, kinds=kinds,
                                                                      loc=loc or None, review="unreviewed"))
            elif name == "restore":
                rows = queries.restores(g.db, loc or None, bool(request.args.get("back")), *lim, **pg.order)
            elif name not in ("only-here", "safe-to-delete", "backed-up"):
                abort(404)
        except ValueError as e:
            error = str(e)
        pg.done(rows)
        audit_shown([r["file_id"] for r in rows + links if r.get("file_id")], "report %s %s" % (name, loc))
        return render_template("report.html", name=name, loc=loc, rows=rows, error=error, pg=pg, ch=ch,
                               kinds=queries.KINDS, links=links, links_total=queries.page_total(links))

    @app.route("/reports/changes/mark", methods=["POST"])
    @signed_in
    def mark_changes():
        """Mark changes reviewed: the ticked rows, or every unreviewed gone file and move the filters select, seen up
        to a date. The database skips what the person may not mark, and audits an administrator's step-up marks."""
        f = request.form
        mark = {"intended": "intended", "restore": "restore", "clear": None}.get(f.get("mark"), "?")
        if mark == "?":
            abort(400, "a mark is intended, restore or clear")
        kinds = [k for k in f.getlist("what") if k in queries.KINDS]
        days = _int(f.get("days"), 7, 1, 3650)
        loc = f.get("loc", "").strip()
        back = {"days": days, "depth": _int(f.get("depth"), 3, 1, 8), "loc": loc, "what": kinds}
        if f.get("review") in queries.REVIEWS:
            back["review"] = f["review"]
        if f.get("scope") == "all":
            if mark is None:
                abort(400, "marks are cleared row by row")
            try:
                until = datetime.date.fromisoformat(f.get("until", ""))
                ids = [r["history_id"] for r in queries.changes(g.db, days, None, kinds=kinds, loc=loc or None,
                                                                review="unreviewed", until=until,
                                                                elsewhere=bool(f.get("elsewhere")))]
            except ValueError as e:
                abort(400, str(e))
        else:
            try:
                ids = [int(x) for x in f.getlist("id")]
            except ValueError:
                abort(400, "a change is a number")
        n = queries.mark_changes(g.db, ids, mark) if ids else 0
        return redirect(url_for("report", name="changes", marked=n, asked=len(ids), **back))

    # second factor and step-up -------------------------------------------------------------------------------
    @app.route("/account", methods=["GET", "POST"])
    @signed_in
    def account():
        msg = None
        pending = session.get("totp_pending")
        if request.method == "POST":
            action = request.form.get("action")
            if action == "start-totp":
                pending = session["totp_pending"] = auth.new_totp_secret()
            elif action == "confirm-totp" and pending:
                if auth.check_totp(pending, request.form.get("code", "")):
                    g.db.execute("SELECT pinakes.set_my_totp(%s)", (pending,))
                    session.pop("totp_pending")
                    pending = None
                    msg = "Second factor saved."
                else:
                    msg = "That code didn't match; try the next one."
            elif action == "password":
                new = request.form.get("new", "")
                row = g.db.execute("SELECT * FROM pinakes.login_material(%s)",
                                   (g.db.execute("SELECT name FROM pinakes.people WHERE person_id = %s",
                                                 (g.person,)).fetchone()[0],)).fetchone()
                if not auth.check_password(request.form.get("current", ""), row[1] or auth.DUMMY_HASH):
                    msg = "The current password is wrong."
                elif len(new) < 12:
                    msg = "Use at least 12 characters."
                else:
                    g.db.execute("SELECT pinakes.set_my_password(%s)", (auth.hash_password(new),))
                    msg = "Password changed."
        has_totp = g.db.execute("SELECT pinakes.my_totp_secret() IS NOT NULL").fetchone()[0]
        return render_template("account.html", msg=msg, has_totp=has_totp, pending=pending,
                               uri=auth.otpauth_uri(pending, g.display or "me") if pending else None)

    @app.route("/step-up", methods=["GET", "POST"])
    @signed_in
    def step_up():
        if "administrator" not in g.roles:
            abort(403)
        error = None
        if request.method == "POST":
            if request.form.get("action") == "end":
                g.db.execute("SELECT pinakes.end_step_up()")
                return redirect(url_for("home"))
            secret = g.db.execute("SELECT pinakes.my_totp_secret()").fetchone()[0]
            reason = request.form.get("reason", "").strip()
            if not secret:
                error = "Set up a second factor on your account page first."
            elif not reason:
                error = "Give a reason: the people whose records you see will read it."
            elif not auth.check_totp(secret, request.form.get("code", "")):
                error = "That code didn't match."
            else:
                g.db.execute("SELECT pinakes.begin_step_up(%s, %s)", (reason, step_minutes))
                return redirect(url_for("home"))
        return render_template("step_up.html", error=error, minutes=step_minutes)

    @app.route("/access")
    @signed_in
    def access():
        pg = Pager(sorts=queries.AUDIT_SORT)
        rows = pg.done(queries.audit_mine(g.db, pg.per, pg.offset, **pg.order))
        return render_template("access.html", rows=rows, pg=pg)

    return app


SOURCES = ("person", "sidecar", "embedded", "derived")   # the order searches use (METADATA.md "Where values come from")


def metadata_view(reg, rows):
    """A file's metadata for its page: per schema (the registry's order, then any it no longer has), per field (the
    schema's order), every value with its source, first source first: when sources disagree, all are shown."""
    by = {}
    for r in rows:
        by.setdefault(r["schema"], []).append(r)
    out = []
    for name in [s.name for s in reg if s.name in by] + sorted(n for n in by if n not in reg.schemas):
        schema = reg.schemas.get(name)
        values = {}
        for r in sorted(by[name], key=lambda r: SOURCES.index(r["source"]) if r["source"] in SOURCES else 9):
            for k, v in r["vals"].items():
                values.setdefault(k, []).append({"value": v, "source": r["source"], "version": r["version"],
                                                 "author": r["author"], "at": r["at"]})
        known = schema.fields if schema else {}
        names = [k for k in known if k in values] + sorted(k for k in values if k not in known)
        out.append({"name": name, "title": schema.title if schema else name, "schema": schema,
                    "fields": [{"name": k, "field": known.get(k), "values": values[k]} for k in names]})
    return out


def fmt_meta(value, field=None):
    """A metadata value as text, by its field's type (registry.TYPES); a value of no known field as it came."""
    typ = field.type if field else None
    if typ == "list" and isinstance(value, list):
        item = registry.Field("", field.of or "text")
        return ", ".join(fmt_meta(v, item) for v in value)
    if typ == "point" and isinstance(value, dict):
        try:
            return "%.5f, %.5f" % (float(value["lat"]), float(value["lon"]))
        except (KeyError, TypeError, ValueError):
            pass
    if typ == "duration" and isinstance(value, (int, float)) and not isinstance(value, bool):
        s = int(round(value))
        return "%d:%02d:%02d" % (s // 3600, s // 60 % 60, s % 60)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _int_arg(name, default, lo, hi):
    """An integer query parameter, clamped to lo..hi; the default when missing or not a number."""
    return _int(request.args.get(name), default, lo, hi)


def _int(value, default, lo, hi):
    try:
        return min(hi, max(lo, int(value)))
    except (TypeError, ValueError):
        return default


def fmt_size(n):
    if n is None:
        return ""
    n = float(n)  # a SQL sum() of bigints comes back as Decimal
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1000 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1000.0


def _seconds(v):
    s = str(v).strip()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(s[-1:], None)
    return int(s[:-1]) * mult if mult else int(s)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pinakes-web", description=__doc__.split("\n")[0])
    ap.add_argument("--config", default="/etc/pinakes/server.toml")
    args = ap.parse_args(argv)
    cfg = load_server_config(args.config)
    app = create_app(cfg)
    listen = cfg.web.get("listen", "127.0.0.1:8080")
    host, port = listen.rsplit(":", 1)
    from waitress import serve
    if cfg.web.get("health_listen"):
        import threading
        from waitress.server import create_server
        hhost, hport = cfg.web["health_listen"].rsplit(":", 1)
        hs = create_server(create_health_app(cfg), host=hhost, port=int(hport), threads=1)
        threading.Thread(target=hs.run, name="pinakes-health", daemon=True).start()
    serve(app, host=host, port=int(port), threads=4)
    return 0


if __name__ == "__main__":
    sys.exit(main())
