"""pinakes-web: the web UI (Flask, served by waitress). Read-only on the catalog for now, plus sign-in, a second
factor, and the administrator's step-up.

  pinakes-web --config /etc/pinakes/server.toml
"""

import argparse
import functools
import os
import secrets
import sys
import time

import psycopg
from flask import Flask, abort, g, redirect, render_template, request, session, url_for

from . import auth, queries
from .server_config import load as load_server_config

LOGIN_LIMIT = 5          # failed sign-ins per address
LOGIN_WINDOW = 15 * 60   # seconds


def create_app(cfg, connect=None):
    app = Flask(__name__)
    web = cfg.web
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

    def default_connect():
        kw = {"conninfo": web.get("dsn", "")}
        pw = web.get("password_file")
        if pw and os.path.exists(pw):
            with open(pw) as f:
                kw["password"] = f.read().strip()
        return psycopg.connect(**kw)

    connect = connect or default_connect

    @app.before_request
    def open_db():
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
                "stepped_up": g.get("stepped_up"), "roles": g.get("roles", []), "fmt_size": fmt_size}

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
        others = [o for o in queries.owners_of(g.db, file_ids) if o != g.person]
        if others:
            g.db.execute("SELECT pinakes.audit_view(%s, %s::jsonb)",
                         (others, '{"page": "%s", "records": %d}' % (page.replace('"', ""), len(file_ids))))

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
        return render_template("home.html", roots=queries.roots(g.db), stale=queries.stale(g.db))

    @app.route("/find")
    @signed_in
    def find():
        q = request.args.get("q", "").strip()
        results = queries.find(g.db, q) if q else []
        audit_shown([r["file_id"] for r in results], "find")
        return render_template("find.html", q=q, results=results)

    @app.route("/browse/<root>/", defaults={"path": ""})
    @app.route("/browse/<root>/<path:path>")
    @signed_in
    def browse(root, path):
        entries = queries.listing(g.db, "%s:%s" % (root, path))
        audit_shown([e["file_id"] for e in entries if e["file_id"]], "browse %s:%s" % (root, path))
        crumbs = []
        acc = ""
        for part in [p for p in path.split("/") if p]:
            acc = acc + "/" + part if acc else part
            crumbs.append((part, acc))
        return render_template("browse.html", root=root, path=path, entries=entries, crumbs=crumbs)

    @app.route("/file/<int:file_id>")
    @signed_in
    def file(file_id):
        f = queries.file_by_id(g.db, file_id)
        if f is None:
            abort(404)  # not there, or not yours to see: the same answer
        copies = queries.where(g.db, file_id) if f["content_id"] else []
        page = {"f": f, "copies": copies, "versions": queries.versions(g.db, file_id),
                "history": queries.history(g.db, file_id), "up": queries.lineage(g.db, file_id, "up"),
                "down": queries.lineage(g.db, file_id, "down")}
        audit_shown([file_id] + [c["file_id"] for c in copies], "file %d" % file_id)
        return render_template("file.html", **page)

    @app.route("/reports/<name>")
    @signed_in
    def report(name):
        loc = request.args.get("loc", "").strip()
        rows, error = [], None
        try:
            if name == "only-here" and loc:
                rows = queries.only_here(g.db, loc)
            elif name == "safe-to-delete" and loc:
                rows = queries.not_safe_to_delete(g.db, loc)
            elif name == "backed-up" and loc:
                rows = queries.backed_up(g.db, loc)
            elif name == "dupes":
                rows = queries.dupes(g.db)
            elif name == "changes":
                rows = queries.changes(g.db, days=int(request.args.get("days", 7)))
            elif name not in ("only-here", "safe-to-delete", "backed-up"):
                abort(404)
        except ValueError as e:
            error = str(e)
        audit_shown([r["file_id"] for r in rows if r.get("file_id")], "report %s %s" % (name, loc))
        return render_template("report.html", name=name, loc=loc, rows=rows, error=error)

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
        rows = queries.rows(g.db, """SELECT a.at, a.action, p.display AS actor, a.detail,
                                            a.actor = pinakes.current_person() AS mine
                                     FROM pinakes.audit a LEFT JOIN pinakes.people p ON p.person_id = a.actor
                                     ORDER BY a.at DESC LIMIT 500""")
        return render_template("access.html", rows=rows)

    return app


def fmt_size(n):
    if n is None:
        return ""
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
    serve(app, host=host, port=int(port), threads=4)
    return 0


if __name__ == "__main__":
    sys.exit(main())
