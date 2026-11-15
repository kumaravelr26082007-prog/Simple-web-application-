import os
import re
import hmac
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, abort, g)
from werkzeug.security import generate_password_hash, check_password_hash

from database import get_db, init_db

app = Flask(__name__)
app.config.update(
    # Set SECRET_KEY in the environment for persistent sessions.
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,      # JS cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",     # limits cross-site sending
    SESSION_COOKIE_SECURE=False,       # set True when served over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

init_db()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- CSRF protection ----------
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400)


# ---------- Validation ----------
def validate_registration(username, email, password, confirm):
    errors = []
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-20 characters: letters, numbers, underscore.")
    if len(email) > 120 or not EMAIL_RE.match(email):
        errors.append("Enter a valid email address.")
    if len(password) < 8 or len(password) > 128:
        errors.append("Password must be 8-128 characters.")
    elif not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)
              and re.search(r"\d", password)):
        errors.append("Password needs uppercase, lowercase and a number.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


# ---------- Access control ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        conn = get_db()
        # Role is re-read from the database on every request (server-side check)
        g.user = conn.execute(
            "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        conn.close()
        if g.user is None:
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ---------- Routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = validate_registration(username, email, password, confirm)
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html"), 400

        conn = get_db()
        try:
            # Parameterized query prevents SQL injection; role is always 'user'
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')",
                (username, email, generate_password_hash(password)),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username or email is already in use.", "error")
            return render_template("register.html"), 400
        finally:
            conn.close()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()                # prevents session fixation
            session.permanent = True
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

        # Same message for unknown user and wrong password
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=g.user)


@app.route("/admin")
@admin_required
def admin():
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, email, role, created_at FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return render_template("admin.html", user=g.user, users=users)


if __name__ == "__main__":
    app.run(debug=False)   # keep debug off: it exposes an interactive console
