"""pinakes-web: the web UI (Flask, served by waitress). Read-only on the catalog but for review marks, lineage
decisions, a person's own metadata on a file (their tags and notes by token too) and sharing its sensitive fields,
each through its database function; plus sign-in, a second factor, the administrator's step-up, and API tokens;
and the JSON API.

  pinakes-web --config /etc/pinakes/server.toml

/api/v1/ is the JSON API (ROADMAP 34): every call carries a person's token (`Authorization: Bearer ...`), made and
revoked on the account page, never the session cookie. It acts as that person under row-level security, sees only
the roots the token may (every root but the protected ones unless it names them), never steps up, and is recorded
for the person. GET only for now; a token needs the `read` scope for these calls:

  whoami                          the token's person, kind, scopes and roots (any token)
  roots, stale, dupes             as the CLI's commands (stale: an ops token too)
  releases                        (ops tokens only) this server's release, protocol and schema, and each agent's
                                  last check-in: hosts, numbers and times, never a root, person or file
  find?q=NAME-OR-GLOB
  where|history|versions?loc=ROOT:PATH (or ?file=ID)      lineage?loc=...&down=1
  only-here|safe-to-delete|backed-up|folder-copies?loc=ROOT:PATH
  changes?days=N&host=NAME&loc=ROOT:PATH&review=unreviewed|reviewed&what=KIND...
  meta?field=SCHEMA.FIELD&value=VALUE
  POST review {"mark": "intended"|"restore", "ids": [...]}  (scope review) mark those changes, as on the web:
                                  only gone files and moves, only the person's own or co-owned, only in the
                                  token's roots; {"asked", "marked"}
  tags?loc=ROOT:PATH              (scope read or tag) the files under it (or that file) with the person's role,
                                  their own tags and note, and others' they can see (ROADMAP 37)
  POST tag {"ids": [...], "add": [...], "remove": [...], "note": TEXT}   (scope tag; a person's token) the
                                  person's own tags (dc.subject) and note (dc.description, "" removes it) on those
                                  files: only where they are the owner, a co-owner or an annotator, only in the
                                  token's roots; {"asked", "tagged"}
  relatives?loc=ROOT:PATH (or ?file=ID)   the file's direct relatives both ways, rejected ones too, with each
                                  edge's ends (from_file_id, to_file_id), confidence and decision (ROADMAP 9)
  POST decide {"files": [A, B], "decision": "confirmed"|"rejected"|null}   (scope review; a person's token) every
                                  edge between A and B (each a file number or ROOT:PATH) but certain ones, decided
                                  or cleared: only where the descendant is the person's own or co-owned, only in
                                  the token's roots; {"files", "decision", "decided"}
  host-roots?host=NAME            the roots a host reports, with their paths there (for a folder's ROOT:PATH)
  backups?loc=ROOT:PATH&show=N    the folder's files, fewest backups first, and how many have none
  export?part=PART&format=json|csv  (a person's token) the files the person owns and what the catalog holds about
                                  them, under row-level security: parts files, history, reviews, metadata, lineage;
                                  JSON without part= is every part, a CSV is one ({"person", "exported", PART: [...]})
  POST session {"name", "password", "code"}   pinakes --as: the person's password, and their second factor if
                                  they have one, for a read-only token of minutes ({"token", "until"}); limited
                                  like the web sign-in, and recorded for the person
  POST session/end                that token, revoked (its command is done)
  POST is for these five; every other call is GET
  A list answers one page (ROADMAP 61): 100 rows, or limit= (at most 10000) from offset=, as {"rows": [...], "total",
  "limit", "offset"}, the total being the whole list's (safe-to-delete: {"not_safe", "total", "limit", "offset",
  "links_into", "links_into_total"}, the first 200 links; export: a page of each part, its last shorter than the
  limit). roots, stale, host-roots, lineage and relatives are not paged (a site's roots and hosts, one file's
  relatives); at-risk, growth and change-tree have their own limits. Errors are {"error": "..."} with 400, 401, 403,
  404 or 429.

/health answers without sign-in, for monitoring: whether the database is reachable, and per host its newest batch,
last complete scan, whether it is stale, whether its batches are being refused (protocol or sequence), when its
agent's numbering last went back, and its scrub's oldest check and whether the scrub is behind (200 when all is
well, 503 when a host is stale, refused or its scrub behind). It names hosts, never a root, person or file. [web] health_listen serves it alone on a second address, for a monitor that can't reach the
UI's.
"""

import argparse
import csv
import datetime
import functools
import hashlib
import io
import json
from urllib.parse import unquote, urlencode
import os
import secrets
import sys
import time

import psycopg
from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException, NotFound

from . import auth, compat, extract, queries, registry
from .server_config import load as load_server_config

LOGIN_LIMIT = 5          # failed sign-ins per address
PER_PAGE = (50, 100, 250, 500)   # the page sizes offered; the first after 50 is the default
LOGIN_WINDOW = 15 * 60   # seconds
API = "/api/v1/"
API_PAGE = 100           # rows a list call of the API answers without limit= (ROADMAP 61)
API_MAX = 10000          # the most it answers with one
SCOPES = ("read", "review", "tag")      # what a token may be given (the database checks the same list)
TOKEN_PREFIX = "pinakes_"
CLI_SESSION_MINUTES = 10  # pinakes --as: a session lasts this long at most; the command ends it sooner


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
        self.total = self.shown = self.folded = 0

    def done(self, result):
        self.total = queries.page_total(result)
        self.folded = queries.folded(result)
        self.shown = len(result)
        return result

    @property
    def all_backups(self):
        """Whether this page lists every backup copy (backups=all), not a count per row (ROADMAP 68)."""
        return request.args.get("backups") == "all"

    def backups_url(self, every):
        """This page with every backup copy listed, or folded into a count; from the list's first page."""
        return self.url(page=1, backups="all" if every else "")

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

    def url(self, page=None, per=None, sort=None, dir="asc", backups=None):
        """This page with another page, page size or sort of this list; the others stay. A new size or sort starts
        at page 1. sort= a column, dir= "asc" or "desc"; backups= "all", or "" to fold them (ROADMAP 68)."""
        args = request.args.to_dict()
        if backups is not None:
            args.pop("backups", None)
            if backups:
                args["backups"] = backups
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
              else "roots unreported" if any(h["roots_unreported"] for h in hosts)
              else "scrub behind" if any(h["scrub_behind"] for h in hosts) else "ok")
    body = {"status": status, "database": "ok",
            "hosts": [{"host": h["host"], "newest_batch": _iso(h["newest_batch"]), "last_scan": _iso(h["last_scan"]),
                       "expected_every_s": int(h["expected_every"].total_seconds()) if h["expected_every"] else None,
                       "stale": h["stale"], "refused": h["refused"], "seq_reset": _iso(h["seq_reset_at"]),
                       "scrub_oldest": _iso(h["scrub_oldest"]), "scrub_behind": h["scrub_behind"],
                       "roots_unreported": h["roots_unreported"]}
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
    # The longest one statement may run (0: no limit). The command gives up at 60 s; a query running on after that
    # held a thread and the database's time, and one slow call blocked everybody's for minutes.
    statement_limit = _seconds(web.get("statement_timeout", "55s"))
    failures = {}
    api_failures = {}

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
        # No JIT: row-level security's subplans make the planner's costs high, so PostgreSQL compiles short queries,
        # and compiling took longer than running them (ROADMAP 61: folder copies 1.6 s, 0.1 s without)
        g.db.execute("SET jit = off")
        if statement_limit:
            g.db.execute("SELECT set_config('statement_timeout', %s, false)", (str(statement_limit * 1000),))
        if request.path.startswith(API):
            return api_begin()          # by token only: no session cookie, so no form to forge
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

    # the API ---------------------------------------------------------------------------------------------------
    def api_answer(body, status=200):
        return Response(json.dumps(body, default=queries.json_default), status=status, mimetype="application/json")

    def api_begin():
        """Authenticate an API call by its bearer token, before anything else: the database checks the token, sets
        its person for this transaction and records the call. A refused token counts toward the address's limit."""
        g.person, g.api, g.stepped_up, g.roles, g.scopes, g.kind, g.group = None, True, False, [], (), None, None
        if request.path == API + "session" and request.method == "POST":
            return                      # signing in: by password, with no token yet
        addr = request.remote_addr or "?"
        recent = [t for t in api_failures.get(addr, []) if t > time.time() - LOGIN_WINDOW]
        if len(recent) >= LOGIN_LIMIT:
            return api_answer({"error": "too many refused tokens; wait a few minutes"}, 429)
        kind, _, secret = request.headers.get("Authorization", "").partition(" ")
        row = None
        if kind.lower() == "bearer" and secret.strip():
            call = request.path[len(API):]
            if request.query_string:
                call += "?" + unquote(request.query_string.decode("utf-8", "replace"))     # readable
            row = g.db.execute("SELECT * FROM pinakes.begin_token_call(%s, %s)",
                               (hashlib.sha256(secret.strip().encode()).digest(), call)).fetchone()
        if not row:
            api_failures[addr] = recent + [time.time()]
            return api_answer({"error": "a valid token is needed (Authorization: Bearer ...)"}, 401)
        g.person, g.scopes, g.kind, g.group = row[0], tuple(row[1]), row[2], row[3]

    @app.errorhandler(psycopg.errors.QueryCanceled)
    def too_long(e):
        db = g.get("db")
        if db is not None:
            db.rollback()
        msg = ("this took longer than %d s and was stopped: ask for less (a folder, fewer days, a smaller page)"
               % statement_limit)
        if request.path.startswith(API):
            return api_answer({"error": msg}, 503)
        return Response(msg + "\n", status=503, mimetype="text/plain")

    @app.errorhandler(HTTPException)
    def http_error(e):
        if request.path.startswith(API):
            no_call = isinstance(e, NotFound) and e.description == NotFound.description
            return api_answer({"error": "no such call" if no_call else e.description}, e.code)
        return e

    def api(rule, scope="read"):
        """An API call: GET only (none of them steps up or changes anything), the token's scope checked (one of
        them, for a tuple), the answer as JSON, a bad argument a 400."""
        allowed = (scope,) if isinstance(scope, str) else scope

        def deco(view):
            @functools.wraps(view)
            def wrapper(*a, **kw):
                if not set(allowed) & set(g.scopes):
                    return api_answer({"error": "this token doesn't have the %s scope" % " or ".join(allowed)}, 403)
                try:
                    return api_answer(view(*a, **kw))
                except ValueError as e:
                    return api_answer({"error": str(e)}, 400)
            app.add_url_rule(API + rule, "api_" + view.__name__, wrapper, methods=["GET"])
            return wrapper
        return deco

    def arg(name, what=None):
        v = request.args.get(name, "").strip()
        if not v:
            raise ValueError("%s is needed" % (what or name))
        return v

    def lim(paged=True):
        """limit= and offset=: a list call's page (API_PAGE rows without limit=), or without `paged` every row."""
        return _int_arg("limit", API_PAGE if paged else None, 1, API_MAX), _int_arg("offset", 0, 0, 10 ** 12)

    def page(query, *a, **kw):
        """A list call's answer (ROADMAP 61): one page of query(g.db, *a, limit=, offset=, **kw), API_PAGE rows unless
        limit= asks for another number (at most API_MAX), with the whole list's total, read from the window count in
        its rows (queries.TOTAL); a page past the end asks once more for the total alone."""
        limit, offset = lim()
        got = query(g.db, *a, limit=limit, offset=offset, **kw)
        whole = got if got or not offset else query(g.db, *a, limit=1, offset=0, **kw)
        out = {"rows": [{k: v for k, v in r.items() if k not in ("total_rows", "folded_rows")} for r in got],
               "total": queries.page_total(whole), "limit": limit, "offset": offset}
        if kw.get("backups"):
            out["folded"] = queries.folded(whole)
        return out

    def backups():
        """backups=all lists every backup copy; without it, a list that holds copies folds them (ROADMAP 68)."""
        v = request.args.get("backups", "").strip()
        if v not in ("", "all"):
            raise ValueError("backups is all, or left out to fold the backup copies into a count")
        return v or "fold"

    def target():
        """The file a call names, by ?file=ID or ?loc=ROOT:PATH; 404 when the token's person can't see it."""
        if request.args.get("file"):
            fid = _int_arg("file", None, 1, 2 ** 62)
            f = queries.file_by_id(g.db, fid) if fid else None
        else:
            f = queries.file_at(g.db, arg("loc", "loc=ROOT:PATH or file=ID"))
        if not f:
            abort(404, "no file you can see there")
        return f["file_id"]

    @app.route(API + "session", methods=["POST"])
    def api_sign_in():
        """pinakes --as NAME: the same checks as the web sign-in, and the second factor too when the person has one;
        a failure counts toward the address's sign-in limit. The answer is a token for one command."""
        addr = request.remote_addr or "?"
        recent = [t for t in failures.get(addr, []) if t > time.time() - LOGIN_WINDOW]
        if len(recent) >= LOGIN_LIMIT:
            return api_answer({"error": "too many attempts; wait a few minutes"}, 429)
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        name, password, code = (str(body.get(k) or "") for k in ("name", "password", "code"))
        row = g.db.execute("SELECT * FROM pinakes.login_material(%s)", (name,)).fetchone()
        ok = auth.check_password(password, row[1] if row and row[1] else auth.DUMMY_HASH) and bool(row and row[1])
        if ok:
            g.db.execute("SELECT set_config('pinakes.person', %s, true)", (str(row[0]),))
            if row[2]:
                ok = auth.check_totp(g.db.execute("SELECT pinakes.my_totp_secret()").fetchone()[0], code)
        if not ok:
            failures[addr] = recent + [time.time()]
            return api_answer({"error": "that name, password and code don't match"}, 401)
        secret = TOKEN_PREFIX + secrets.token_urlsafe(32)
        until = g.db.execute("SELECT pinakes.begin_cli_session(%s, %s, %s)",
                             (hashlib.sha256(secret.encode()).digest(), CLI_SESSION_MINUTES, addr)).fetchone()[0]
        return api_answer({"token": secret, "until": until})

    @app.route(API + "session/end", methods=["POST"])
    def api_sign_out():
        return api_answer({"ended": bool(g.db.execute("SELECT pinakes.end_cli_session()").fetchone()[0])})

    @api("whoami", SCOPES + ("ops",))
    def whoami():
        if g.kind == "ops":                     # no person, no root
            return {"person": None, "kind": "ops", "scopes": list(g.scopes), "roots": []}
        if g.kind == "group":                   # the group, and no member
            return {"person": None, "group": g.group, "kind": "group", "scopes": list(g.scopes),
                    "roots": [r["label"] for r in queries.roots(g.db)]}
        me = g.db.execute("SELECT name, display FROM pinakes.people WHERE person_id = %s", (g.person,)).fetchone()
        return {"person": me[0], "display": me[1], "kind": "person", "scopes": list(g.scopes),
                "roots": [r["label"] for r in queries.roots(g.db)]}

    @api("releases", "ops")
    def api_releases():
        """This server's release and protocol, whether its schema is applied, and each agent's last check-in: host
        names, numbers and times only (ROADMAP 39: what pinakes --versions read from the database)."""
        from .ingest import schema_missing
        missing = schema_missing(g.db)
        return {"server": {"release": compat.RELEASE, "protocol": compat.PROTOCOL,
                           "min_agent_protocol": compat.MIN_AGENT_PROTOCOL, "schema_applied": not missing,
                           "upgrades_missing": missing},
                "agents": queries.agent_versions(g.db)}

    @api("roots")
    def api_roots():
        return {"rows": queries.roots(g.db)}

    @api("stale", ("read", "ops"))
    def api_stale():
        return {"rows": queries.stale(g.db)}

    @api("find")
    def api_find():
        return page(queries.find, arg("q", "q=NAME-OR-GLOB"), backups=backups())

    @api("where")
    def api_where():
        return page(queries.where, target(), backups=backups())

    @api("history")
    def api_history():
        return page(queries.history, target())

    @api("versions")
    def api_versions():
        return page(queries.versions, target())

    @api("lineage")
    def api_lineage():
        return {"rows": queries.lineage(g.db, target(), "down" if request.args.get("down") else "up")}

    @api("only-here")
    def api_only_here():
        return page(queries.only_here, arg("loc", "loc=ROOT:PATH"))

    @api("safe-to-delete")
    def api_safe_to_delete():
        loc = arg("loc", "loc=ROOT:PATH")
        got = page(queries.not_safe_to_delete, loc)
        links = queries.links_into(g.db, loc, LINKS_SHOWN)
        return {"not_safe": got["rows"], "total": got["total"], "limit": got["limit"], "offset": got["offset"],
                "links_into": [{k: v for k, v in r.items() if k != "total_rows"} for r in links],
                "links_into_total": queries.page_total(links)}

    @api("backed-up")
    def api_backed_up():
        loc = arg("loc", "loc=ROOT:PATH")
        got = page(queries.backed_up, loc)
        first = got["rows"][:1] or queries.backed_up(g.db, loc, limit=1, offset=0)   # a page past the end
        n = int(first[0]["with_backup"]) if first else 0
        for r in got["rows"]:
            del r["with_backup"]
        return dict(got, with_backup=n, without_backup=got["total"] - n)    # of every file, not only the page's

    @api("manifests")
    def api_manifests():
        return page(queries.manifests, request.args.get("loc") or None)

    @api("folder-copies")
    def api_folder_copies():
        return page(queries.folder_copies, arg("loc", "loc=ROOT:PATH"))

    @api("dupes")
    def api_dupes():
        return page(queries.dupes)

    @api("changes")
    def api_changes():
        review = request.args.get("review")
        if review and review not in queries.REVIEWS:
            raise ValueError("review is %s" % " or ".join(queries.REVIEWS))
        kinds = request.args.getlist("what")
        if set(kinds) - set(queries.KINDS):
            raise ValueError("what is one of %s" % ", ".join(queries.KINDS))
        return page(queries.changes, _int_arg("days", 7, 1, 3650), request.args.get("host") or None,
                    loc=request.args.get("loc") or None, review=review or None, kinds=kinds or None)

    @app.route(API + "review", methods=["POST"])
    def api_review():
        """Mark changes reviewed, by their ids (as `changes` listed them): the database skips what this person, this
        token's roots or its scope don't allow, and answers how many it marked."""
        if "review" not in g.scopes:
            return api_answer({"error": "this token doesn't have the review scope"}, 403)
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        mark, ids = body.get("mark"), body.get("ids")
        if mark not in ("intended", "restore"):
            return api_answer({"error": "a mark is intended or restore"}, 400)
        if not isinstance(ids, list) or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
            return api_answer({"error": "ids is a list of change numbers"}, 400)
        return api_answer({"asked": len(ids), "marked": queries.mark_changes(g.db, ids, mark) if ids else 0})

    @api("tags", ("read", "tag"))
    def api_tags():
        return page(queries.tags, arg("loc", "loc=ROOT:PATH"))

    @app.route(API + "tag", methods=["POST"])
    def api_tag():
        """Tag files and note on them (ROADMAP 37), by their ids (as `tags` listed them): the person's own tags (their
        dc.subject) get `add` and lose `remove`, and their note (dc.description) becomes `note` ("" removes it; none:
        unchanged). Files the person may not enter on (only the owner, a co-owner or an annotator; only in the token's
        roots) are skipped, and the database checks the same; answers how many of the files asked it tagged."""
        if "tag" not in g.scopes:
            return api_answer({"error": "this token doesn't have the tag scope"}, 403)
        if g.kind != "person":
            return api_answer({"error": "tags and notes are a person's own: use a person's token"}, 403)
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        ids, note = body.get("ids"), body.get("note")
        add, remove = body.get("add") or [], body.get("remove") or []
        if not isinstance(ids, list) or len(ids) > TAG_BATCH or not all(
                isinstance(i, int) and not isinstance(i, bool) and 0 < i < 2 ** 62 for i in ids):
            return api_answer({"error": "ids is a list of at most %d file numbers" % TAG_BATCH}, 400)
        try:
            add, remove = [_tag(t) for t in _list(add)], [_tag(t) for t in _list(remove)]
            if note is not None and not isinstance(note, str):
                raise ValueError("a note is text")
        except ValueError as e:
            return api_answer({"error": str(e)}, 400)
        if not add and not remove and note is None:
            return api_answer({"error": "nothing to do: add, remove or note"}, 400)
        schema = reg.schemas[registry.COMMON]
        _, problems = extract.check_vals(schema, {"subject": add or None,
                                                  "description": (note or "").strip() or None})
        if problems:
            return api_answer({"error": "; ".join(problems)}, 400)
        tagged = 0
        for fid in ids:
            if queries.my_file_role(g.db, fid) not in ENTERS:
                continue
            vals = queries.my_entered(g.db, fid, registry.COMMON)
            was = dict(vals)
            subject = [t for t in vals.get("subject") or [] if t not in remove]
            subject += [t for t in add if t not in subject]
            vals["subject"] = subject or None
            if note is not None:
                vals["description"] = note.strip() or None
            keep, problems = extract.check_vals(schema, vals)
            if problems:
                return api_answer({"error": "file %d: %s" % (fid, "; ".join(problems))}, 400)
            if keep != was:
                queries.set_file_metadata(g.db, fid, schema, keep)
            tagged += 1
        return api_answer({"asked": len(ids), "tagged": tagged})

    @api("relatives")
    def api_relatives():
        return {"rows": queries.relatives(g.db, target())}

    @app.route(API + "decide", methods=["POST"])
    def api_decide():
        """Confirm, reject or clear (decision null) the link between two files (ROADMAP 9), each a file number or
        ROOT:PATH: the database decides only what this person, this token's roots and its review scope allow, and
        answers how many edges it decided."""
        if "review" not in g.scopes:
            return api_answer({"error": "this token doesn't have the review scope"}, 403)
        if g.group:
            return api_answer({"error": "a group token doesn't decide lineage"}, 403)
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        decision, files = body.get("decision"), body.get("files")
        if decision not in queries.DECISIONS + (None,):
            return api_answer({"error": "a decision is confirmed, rejected or null (clear)"}, 400)
        if not isinstance(files, list) or len(files) != 2:
            return api_answer({"error": "files is two files, each a number or ROOT:PATH"}, 400)
        ids = []
        for x in files:
            if isinstance(x, int) and not isinstance(x, bool) and 0 < x < 2 ** 62:
                f = queries.file_by_id(g.db, x)
            elif isinstance(x, str) and ":" in x:
                try:
                    f = queries.file_at(g.db, x)
                except ValueError as e:
                    return api_answer({"error": str(e)}, 400)
            else:
                return api_answer({"error": "files is two files, each a number or ROOT:PATH"}, 400)
            if not f:
                return api_answer({"error": "no file you can see at %s" % x}, 404)
            ids.append(f["file_id"])
        return api_answer({"files": ids, "decision": decision, "decided": queries.decide_lineage(g.db, *ids, decision)})

    @api("edits", ("read", "review", "tag"))
    def api_edits():
        """The person's own writes (ROADMAP 62), on the web and by their tokens, and their groups': a page of edits,
        the newest first, in the last days= (7), only token=CLIENT's if given. An ops token has none of the scopes."""
        return page(queries.edits, _int_arg("days", 7, 1, 3650), request.args.get("token") or None)

    @app.route(API + "undo", methods=["POST"])
    def api_undo():
        """Undo edits by their numbers (as `edits` listed them): each put back whole or refused, the database
        deciding by the same rules as the writes (and, under a token, its scope of each edit's kind)."""
        if not {"review", "tag"} & set(g.scopes):
            return api_answer({"error": "this token has neither the review nor the tag scope"}, 403)
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        ids = body.get("edits")
        if not isinstance(ids, list) or not ids or len(ids) > queries.UNDO_LIMIT or not all(
                isinstance(i, int) and not isinstance(i, bool) and 0 < i < 2 ** 62 for i in ids):
            return api_answer({"error": "edits is a list of 1 to %d edit numbers" % queries.UNDO_LIMIT}, 400)
        got = queries.undo_edits(g.db, ids)
        return api_answer({"asked": len(set(ids)), "undone": [r for r in got if "undone_by" in r],
                           "refused": [r for r in got if "refused" in r]})

    @app.route(API + "export")
    def api_export():
        """A person's export of their own records (ROADMAP 45): the files they own and what the catalog holds about
        them, as the person under row-level security; the call is recorded like any other. JSON: every part, or one
        with part=; CSV (format=csv): one part. A page of each part (ROADMAP 61): API_PAGE rows, or limit= from offset=;
        a part's page shorter than the limit is its last."""
        if "read" not in g.scopes:
            return api_answer({"error": "this token doesn't have the read scope"}, 403)
        if g.kind != "person":
            return api_answer({"error": "an export is a person's own records: use a person's token"}, 403)
        part, fmt = request.args.get("part") or None, request.args.get("format") or "json"
        try:
            if fmt not in ("json", "csv"):
                raise ValueError("format is json or csv")
            if fmt == "csv" and not part:
                raise ValueError("a CSV is one part: part=%s" % "|".join(queries.EXPORT))
            parts = [part] if part else list(queries.EXPORT)
            limit, offset = lim()
            got = {p: queries.export(g.db, p, limit, offset) for p in parts}
        except ValueError as e:
            return api_answer({"error": str(e)}, 400)
        if fmt == "csv":
            return Response(_csv(*got[part]), mimetype="text/csv")
        me = g.db.execute("SELECT name FROM pinakes.people WHERE person_id = %s", (g.person,)).fetchone()[0]
        return api_answer(dict({"person": me, "exported": datetime.datetime.now(datetime.timezone.utc),
                                "limit": limit, "offset": offset}, **{p: rows for p, (_, rows) in got.items()}))

    @api("host-roots")
    def api_host_roots():
        return {"rows": queries.roots_of_host(g.db, arg("host", "host=NAME"))}

    @api("backups")
    def api_backups():
        loc = arg("loc", "loc=ROOT:PATH")
        shown = queries.backed_up(g.db, loc, _int_arg("show", 50, 1, 10000), 0, sort="copies", direction="asc")
        return {"folder": loc, "files": shown[0]["total_rows"] if shown else 0, "unbacked": queries.unbacked(g.db, loc),
                "shown": shown}

    @api("meta")
    def api_meta():
        schema, dot, field = arg("field", "field=SCHEMA.FIELD").partition(".")
        if not dot or not field:
            raise ValueError("field is SCHEMA.FIELD")
        known = reg.schemas.get(schema)
        known = known.fields.get(field) if known else None
        return page(queries.meta, schema, field, request.args.get("value", ""),
                    sensitive=known.sensitive if known else None, backups=backups())

    # the web's reports, for `pinakes` (ROADMAP 55 to 59): the same queries under row-level security, without the
    # owner ids the web keeps for its step-up audit (a token never steps up)
    def no_owners(rows, key="owners"):
        return [{k: v for k, v in r.items() if k != key} for r in rows]

    @api("at-risk")
    def api_at_risk():
        r = queries.at_risk(g.db)
        return {"disks": r["disks"], "hosts": r["hosts"], "folders": no_owners(r["folders"], "owner_id"),
                "folders_total": r["folders_total"], "folders_shown": queries.AT_RISK_FOLDERS}

    @api("growth")
    def api_growth():
        rows = queries.growth(g.db, _int_arg("weeks", 8, 1, 520), request.args.get("loc") or None)
        return {"rows": no_owners(rows[:queries.GROWTH_LIMIT]), "cut": len(rows) > queries.GROWTH_LIMIT}

    @api("restores")
    def api_restores():
        return page(queries.restores, request.args.get("loc") or None, bool(request.args.get("back")))

    @api("change-tree")
    def api_change_tree():
        review = request.args.get("review")
        if review and review not in queries.REVIEWS:
            raise ValueError("review is %s" % " or ".join(queries.REVIEWS))
        kinds = request.args.getlist("what")
        if set(kinds) - set(queries.KINDS):
            raise ValueError("what is one of %s" % ", ".join(queries.KINDS))
        rows = queries.change_tree(g.db, _int_arg("days", 7, 1, 3650), request.args.get("loc") or None,
                                   _int_arg("depth", 3, 1, 8), kinds or None, review or None)
        return {"rows": no_owners(rows[:queries.TREE_LIMIT]), "cut": len(rows) > queries.TREE_LIMIT}

    @api("access")
    def api_access():
        """The person's access record, as on the access page: who saw their records, and their own calls."""
        if g.kind != "person":
            abort(403, "an access record is a person's own: use a person's token")
        return page(queries.audit_mine)

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
                                              pg.per, pg.offset, hidden=show_hidden(),
                                              backups="all" if pg.all_backups else "fold", **pg.order))
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
        copies = pc.done(queries.where(g.db, file_id, pc.per, pc.offset, backups="all" if pc.all_backups else "fold",
                                       **pc.order)) if f["content_id"] else []
        page = {"f": f, "copies": copies, "pc": pc,
                "versions": pv.done(queries.versions(g.db, file_id, pv.per, pv.offset, **pv.order)), "pv": pv,
                "history": ph.done(queries.history(g.db, file_id, ph.per, ph.offset, **ph.order)), "ph": ph,
                "up": queries.lineage(g.db, file_id, "up"), "down": queries.lineage(g.db, file_id, "down"),
                "relatives": queries.relatives(g.db, file_id),
                "decided": _int_arg("decided", None, 0, 10 ** 9)}
        meta = queries.file_metadata(g.db, file_id, f["content_id"])
        page["metadata"] = metadata_view(reg, meta)
        page["extractions"] = [dict(e, title=reg.schemas[e["schema"]].title if e["schema"] in reg.schemas
                                    else e["schema"]) for e in queries.file_extractions(g.db, f["content_id"])]
        # a note for those who can't see the sensitive fields: the same whether this file has any or not
        page["sensitive_hidden"] = [] if queries.sensitive_visible(g.db, file_id, f["content_id"]) else sorted(
            {fd.description or fd.name for s in page["metadata"] if s["schema"]
             for fd in s["schema"].fields.values() if fd.sensitive})
        # entering metadata (owner, co-owner, annotator) and sharing the sensitive fields (owner, co-owner): ROADMAP 16
        page["role"] = queries.my_file_role(g.db, file_id)
        page["enterable"] = enterable(f) if page["role"] in ENTERS else []
        page["sharing"] = queries.sensitive_sharing(g.db, file_id) if page["role"] in SHARES else []
        page["entered"] = request.args.get("entered")
        page["shared"] = request.args.get("shared")
        shown = "file %d" % file_id + (", with sensitive metadata" if any(m["sensitive"] for m in meta) else "")
        audit_shown([file_id] + [c["file_id"] for c in copies]
                    + [r["file_id"] for r in page["up"] + page["down"] + page["relatives"]], shown)
        return render_template("file.html", **page)

    @app.route("/file/<int:file_id>/decide", methods=["POST"])
    @signed_in
    def decide(file_id):
        """Confirm, reject or clear the link between this file and a direct relative (ROADMAP 9). The database
        decides only what the person may (the descendant's owner or co-owner, or an administrator in a step-up)."""
        decision = {"confirmed": "confirmed", "rejected": "rejected", "clear": None}.get(request.form.get("decision"),
                                                                                         "?")
        if decision == "?":
            abort(400, "a decision is confirmed, rejected or clear")
        other = _int(request.form.get("other"), None, 1, 2 ** 62)
        if other is None:
            abort(400, "a relative is a file number")
        n = queries.decide_lineage(g.db, file_id, other, decision)
        return redirect(url_for("file", file_id=file_id, decided=n) + "#relatives")

    def enterable(f):
        """The schemas a person may enter on this file, with their fields: those whose MIME types fit its name's, as
        the agent picks extractors (the common schema fits every file); fields of a person or a file left out (the
        catalog names those)."""
        mime = extract.mime_of(f["relpath"]) or ""
        out = []
        for s in reg:
            if s.name != registry.COMMON and not extract._mime_fits(s.mime, mime):
                continue
            fields = [fd for fd in s.fields.values() if fd.type not in REFS and (fd.of or "text") not in REFS]
            if fields:
                out.append({"schema": s, "fields": fields})
        return out

    @app.route("/file/<int:file_id>/metadata", methods=["POST"])
    @signed_in
    def enter_metadata(file_id):
        """Set or remove one field of the person's own metadata on a file (ROADMAP 16). The database decides who
        may (the owner, a co-owner or an annotator); the registry decides what a value is."""
        f = queries.file_by_id(g.db, file_id)
        if f is None:
            abort(404)
        if queries.my_file_role(g.db, file_id) not in ENTERS:
            abort(403, "only the owner, a co-owner or an annotator of a file enters its metadata")
        name, dot, fname = request.form.get("field", "").partition(".")
        allowed = {(e["schema"].name, fd.name) for e in enterable(f) for fd in e["fields"]}
        if (name, fname) not in allowed:
            abort(400, "not a field entered on this file")
        schema = reg.schemas[name]
        vals = queries.my_entered(g.db, file_id, name)
        if request.form.get("remove"):
            vals.pop(fname, None)
        else:
            try:
                vals[fname] = parse_entry(schema.fields[fname], request.form.get("value", ""))
            except ValueError as e:
                abort(400, "%s: %s" % (fname, e))
        keep, problems = extract.check_vals(schema, vals)
        if problems:
            abort(400, "; ".join(problems))
        queries.set_file_metadata(g.db, file_id, schema, keep)
        return redirect(url_for("file", file_id=file_id, entered=fname) + "#metadata")

    @app.route("/file/<int:file_id>/share-sensitive", methods=["POST"])
    @signed_in
    def share_sensitive(file_id):
        """Share the file's sensitive fields with one of its readers or annotators, or stop (ROADMAP 16): by its
        owner or a co-owner only, as the database checks; it shares no file, only the fields of one already seen."""
        if queries.file_by_id(g.db, file_id) is None:
            abort(404)
        who = _int(request.form.get("person"), None, 1, 2 ** 31 - 1)
        give = {"share": True, "stop": False}.get(request.form.get("do"))
        if who is None or give is None:
            abort(400, "a person, and share or stop")
        if queries.my_file_role(g.db, file_id) not in SHARES:
            abort(403, "only the owner or a co-owner of a file shares its sensitive fields")
        if who not in {r["person_id"] for r in queries.sensitive_sharing(g.db, file_id)}:
            abort(400, "sensitive fields are shared only with a reader or annotator of the file")
        queries.share_sensitive(g.db, file_id, who, give)
        return redirect(url_for("file", file_id=file_id, shared="1" if give else "0") + "#sensitive")

    @app.route("/reports/at-risk")
    @signed_in
    def at_risk():
        """What losing a disk or a machine would cost the person (ROADMAP 42): their files with no copy they can see
        on another disk, per disk and per host, and by top folder with names."""
        r = queries.at_risk(g.db)
        audit_people(r["owners"], "report at-risk", r["folders_total"])
        return render_template("at_risk.html", r=r, shown=queries.AT_RISK_FOLDERS)

    @app.route("/reports/growth")
    @signed_in
    def growth():
        """Growth by folder over time (ROADMAP 47): per root and folder under a chosen one, per week, the files and
        bytes that came and went, of the files the person can see."""
        loc = request.args.get("loc", "").strip()
        weeks = _int_arg("weeks", 8, 1, 520)
        rows, error = [], None
        try:
            rows = queries.growth(g.db, weeks, loc or None)
        except ValueError as e:
            error = str(e)
        cut = len(rows) > queries.GROWTH_LIMIT
        rows = rows[:queries.GROWTH_LIMIT]
        audit_people({o for r in rows for o in r["owners"] or ()}, "report growth %s" % loc, len(rows))
        return render_template("growth.html", rows=rows, loc=loc, weeks=weeks, error=error, cut=cut)

    @app.route("/operator")
    @signed_in
    def operator():
        """The operator page (ROADMAP 10): every root's totals and what a disk's loss would cost, without a path or
        a person (the database refuses anyone but an operator)."""
        if "operator" not in g.roles:
            abort(403, "The operator page is for operators.")
        return render_template("operator.html", roots=queries.operator_roots(g.db),
                               risk=queries.operator_at_risk(g.db))

    @app.route("/reports/<name>")
    @signed_in
    def report(name):
        loc = request.args.get("loc", "").strip()
        rows, error, ch, links = [], None, None, []
        pg = Pager(sorts={"backed-up": queries.BACKED_UP_SORT, "dupes": queries.DUPES_SORT,
                          "changes": queries.CHANGES_SORT, "restore": queries.RESTORE_SORT,
                          "only-here": queries.COPY_SORT, "manifests": queries.MANIFEST_SORT,
                          "safe-to-delete": queries.COPY_SORT,
                          "folder-copies": queries.FOLDER_COPIES_SORT}.get(name, queries.FILE_SORT))
        lim = (pg.per, pg.offset)
        try:
            if name == "only-here" and loc:
                rows = queries.only_here(g.db, loc, *lim, **pg.order)
            elif name == "safe-to-delete" and loc:
                rows = queries.not_safe_to_delete(g.db, loc, *lim, **pg.order)
                links = queries.links_into(g.db, loc, LINKS_SHOWN)
            elif name == "backed-up" and loc:
                rows = queries.backed_up(g.db, loc, *lim, **pg.order)
            elif name == "folder-copies" and loc:
                rows = queries.folder_copies(g.db, loc, *lim, **pg.order)
                audit_people(queries.folder_owners(g.db, {r[k] for r in rows for k in ("folder", "other")}),
                             "report folder-copies %s" % loc, len(rows))
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
            elif name == "manifests":
                rows = queries.manifests(g.db, loc or None, *lim, **pg.order)
            elif name not in ("only-here", "safe-to-delete", "backed-up", "folder-copies"):
                abort(404)
        except ValueError as e:
            error = str(e)
        pg.done(rows)
        audit_shown([r["file_id"] for r in rows + links if r.get("file_id")]
                    + [r["manifest_id"] for r in rows if r.get("manifest_id")], "report %s %s" % (name, loc))
        backed = int(rows[0]["with_backup"]) if name == "backed-up" and rows else None    # of all, not the page
        return render_template("report.html", name=name, loc=loc, rows=rows, error=error, pg=pg, ch=ch,
                               kinds=queries.KINDS, links=links, links_total=queries.page_total(links),
                               backed=backed)

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
        msg, new_token, msg_at = None, None, None     # msg_at: the token form whose result it is, shown by it
        pending = session.get("totp_pending")
        if request.method == "POST":
            action = request.form.get("action")
            if action in ("make-token", "make-ops-token"):
                msg, new_token = make_token(request.form, ops=action == "make-ops-token")
                msg_at = action if action == "make-token" or "operator" in g.roles else None   # no form: top
            elif action == "revoke-token":
                ok = g.db.execute("SELECT pinakes.revoke_token(%s)",
                                  (_int(request.form.get("token"), 0, 0, 2 ** 31 - 1),)).fetchone()[0]
                msg = "Token revoked." if ok else "No such token of yours to revoke."
            elif action == "start-totp":
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
        name = g.db.execute("SELECT name FROM pinakes.people WHERE person_id = %s", (g.person,)).fetchone()[0]
        return render_template("account.html", msg=msg, msg_at=msg_at, name=name, has_totp=has_totp, pending=pending,
                               uri=auth.otpauth_uri(pending, g.display or "me") if pending else None,
                               new_token=new_token, tokens=queries.rows(g.db, "SELECT * FROM pinakes.my_tokens()"),
                               root_choices=queries.root_choices(g.db), scopes=SCOPES,
                               my_groups=queries.rows(g.db, "SELECT * FROM pinakes.my_groups()"))

    def make_token(form, ops=False):
        """A new token for the signed-in person, from the account page's form: the current password again (a
        borrowed session can't mint itself a lasting key), a client name, whether it acts as them or as one of their
        groups, scopes, every root but the protected ones or the roots ticked, and a lifetime in days or none.
        Returns (message, the secret: shown once, never kept)."""
        name = g.db.execute("SELECT name FROM pinakes.people WHERE person_id = %s", (g.person,)).fetchone()[0]
        row = g.db.execute("SELECT * FROM pinakes.login_material(%s)", (name,)).fetchone()
        if not auth.check_password(form.get("current", ""), row[1] or auth.DUMMY_HASH):
            return "The current password is wrong.", None
        client = form.get("client", "").strip()[:100]
        scopes = ["ops"] if ops else [sc for sc in SCOPES if sc in form.getlist("scope")]
        if ops and "operator" not in g.roles:
            return "Only an operator makes ops tokens.", None
        try:
            days = int(form["days"]) if form.get("days", "").strip() else None
        except ValueError:
            return "Expires after is a number of days, or empty for until revoked.", None
        try:
            roots = None if ops or form.get("roots") != "some" else sorted({int(x) for x in form.getlist("root")})
            group = None if ops or form.get("as", "me") == "me" else min(int(form["as"]), 2 ** 31 - 1)
        except ValueError:
            return "Roots and the group are numbers.", None
        if not client:
            return "Name the client the token is for (a machine, a script).", None
        if not scopes:
            return "Give the token at least one scope.", None
        if roots == []:
            return "Tick at least one root, or give it every root but the protected ones.", None
        if days is not None and not 1 <= days <= 3650:
            return "A token lasts 1 to 3650 days, or until revoked.", None
        secret = TOKEN_PREFIX + secrets.token_urlsafe(32)
        try:
            with g.db.transaction():
                g.db.execute("SELECT pinakes.make_token(%s, %s, %s, %s, %s, %s)",
                             (client, hashlib.sha256(secret.encode()).digest(), scopes, roots, days, group))
        except psycopg.errors.RaiseException as e:
            return "Not made: %s." % e.diag.message_primary, None
        kind = "Ops token" if ops else "Group token" if group is not None else "Token"
        return "%s made for %s. Copy it now: it isn't shown again." % (kind, client), secret

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


ENTERS = ("owner", "co-owner", "annotator")      # who enters metadata on a file (ROADMAP 16)
SHARES = ("owner", "co-owner")                   # who shares its sensitive fields
REFS = ("person", "file")                        # types the catalog names, not a person typing


TAG_BATCH = 1000                                 # files one POST tag may name


def _list(v):
    if not isinstance(v, list):
        raise ValueError("add and remove are lists of tags")
    return v


def _tag(t):
    """One tag as given: text, trimmed, with no comma (the web form takes a list's items separated by commas)."""
    if not isinstance(t, str) or not t.strip():
        raise ValueError("a tag is some text")
    if "," in t:
        raise ValueError("a tag has no comma: %s" % t)
    return t.strip()


def parse_entry(field, text):
    """A value a person typed for a field (registry.Field), as the registry stores it: a list's items separated by
    commas, a point as "LAT, LON", a duration in seconds or as H:MM:SS, a date as ISO 8601. ValueError if not."""
    text = text.strip()
    if not text:
        raise ValueError("no value (remove the field instead)")
    if field.type == "list":
        item = registry.Field("", field.of or "text")
        return [parse_entry(item, t) for t in text.split(",") if t.strip()]
    if field.type == "text":
        return text
    if field.type == "date":
        if not extract._DATE.match(text):
            raise ValueError("a date is ISO 8601: YYYY, YYYY-MM, YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ")
        return text
    if field.type == "point":
        lat, comma, lon = text.partition(",")
        try:
            if not comma:
                raise ValueError
            return {"lat": float(lat), "lon": float(lon)}
        except ValueError:
            raise ValueError("a place is LAT, LON in degrees") from None
    if field.type == "duration" and ":" in text:
        parts = text.split(":")
        if len(parts) > 3 or not all(p.isdigit() for p in parts):
            raise ValueError("a duration is seconds or H:MM:SS")
        n = 0
        for p in parts:
            n = n * 60 + int(p)
        return n
    if field.type in ("number", "duration"):
        try:
            v = float(text)
        except ValueError:
            raise ValueError("not a number") from None
        return int(v) if v.is_integer() and abs(v) < 2 ** 53 else v
    raise ValueError("a %s isn't entered here" % field.type)


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


def _csv(columns, rows):
    """Rows as CSV with a header: times as ISO 8601, JSON values (metadata) as JSON text, NULL as an empty field."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(columns)
    for r in rows:
        w.writerow("" if r[c] is None else json.dumps(r[c], sort_keys=True) if isinstance(r[c], (dict, list))
                   else queries.json_default(r[c]) if isinstance(r[c], (datetime.date, bytes, memoryview)) else r[c]
                   for c in columns)
    return out.getvalue()


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
