import base64
import os
import secrets
import smtplib
import socket
import time
from email.message import EmailMessage
from io import BytesIO

import pyotp
import qrcode
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session

# Load variables from a local .env file (SMTP creds, SECRET_KEY, ...) when
# present. Real environment variables always take precedence, so this is a
# no-op in production where the platform injects them directly.
load_dotenv()
from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    inspect,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# In production set SECRET_KEY to a long random value (e.g. `python -c "import secrets; print(secrets.token_hex(32))"`).
# The fallback exists only so local development works out of the box.
app.secret_key = os.environ.get("SECRET_KEY", "dev-insecure-secret-change-me")


metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("email", String(255), unique=True, nullable=False),
    Column("password", String(255), nullable=False),
    Column("two_factor_enabled", Integer, nullable=False, server_default=text("0")),
    Column("two_factor_secret", String(64)),
)


def _resolve_database_url():
    """Choose the database from the environment.

    Prefers DATABASE_URL (set automatically by Render/Heroku for managed
    Postgres). Falls back to a local SQLite file so development and tests work
    with zero setup. DATABASE keeps backwards compatibility for the SQLite path.
    """
    url = os.environ.get("DATABASE_URL")
    if url:
        return _normalize_database_url(url)

    sqlite_path = os.environ.get("DATABASE", "users.db")
    return f"sqlite:///{sqlite_path}"


def _normalize_database_url(url):
    """Render/Heroku hand out `postgres://...`, but SQLAlchemy needs an explicit
    driver. Rewrite to the psycopg (v3) dialect."""
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def _build_engine(url):
    connect_args = {}
    if url.startswith("sqlite"):
        # Flask/gunicorn touch the connection from multiple threads.
        connect_args["check_same_thread"] = False
    return create_engine(url, connect_args=connect_args, pool_pre_ping=True, future=True)


engine = _build_engine(_resolve_database_url())


def configure_database(url):
    """(Re)point the app at a different database. Used by tests."""
    global engine
    engine = _build_engine(_normalize_database_url(url))
    return engine


def init_db():
    metadata.create_all(engine)
    ensure_user_columns()


def ensure_user_columns():
    """Add the 2FA columns to pre-existing tables that predate them."""
    existing = {col["name"] for col in inspect(engine).get_columns("users")}

    with engine.begin() as conn:
        if "two_factor_enabled" not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0"))
        if "two_factor_secret" not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN two_factor_secret VARCHAR(64)"))


def create_user(email, password):
    hashed_password = generate_password_hash(password)
    secret = pyotp.random_base32()

    with engine.begin() as conn:
        result = conn.execute(
            insert(users).values(
                email=email,
                password=hashed_password,
                two_factor_enabled=0,
                two_factor_secret=secret,
            )
        )
        user_id = result.inserted_primary_key[0]

    return user_id, secret


def _fetch_user(where_clause):
    query = select(
        users.c.id,
        users.c.email,
        users.c.password,
        users.c.two_factor_enabled,
        users.c.two_factor_secret,
    ).where(where_clause)

    with engine.connect() as conn:
        row = conn.execute(query).first()

    return tuple(row) if row is not None else None


def get_user_by_email(email):
    return _fetch_user(users.c.email == email)


def get_user_by_id(user_id):
    return _fetch_user(users.c.id == user_id)


def update_two_factor_setup(user_id, secret):
    with engine.begin() as conn:
        conn.execute(
            update(users)
            .where(users.c.id == user_id)
            .values(two_factor_enabled=1, two_factor_secret=secret)
        )


def build_qr_code(secret, email):
    totp = pyotp.totp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="Login App")
    image = qrcode.make(uri)
    buffered = BytesIO()
    image.save(buffered, format="PNG")
    encoded = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"


EMAIL_OTP_TTL_SECONDS = 300  # email codes are valid for 5 minutes


def generate_email_otp():
    return f"{secrets.randbelow(1_000_000):06d}"


def send_otp_email(to_email, code):
    """Email a one-time login code.

    Falls back to printing the code to the server console when SMTP isn't
    configured, so local development works without a real email account. Set
    SMTP_HOST (and friends) to send real email in production.
    """
    host = os.environ.get("SMTP_HOST")
    if not host:
        print(f"[DEV] Email OTP for {to_email}: {code}")
        return

    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("SMTP_FROM", username or "no-reply@login-app.local")

    message = EmailMessage()
    message["Subject"] = "Your login verification code"
    message["From"] = sender
    message["To"] = to_email
    message.set_content(
        f"Your verification code is {code}.\n\n"
        f"It expires in {EMAIL_OTP_TTL_SECONDS // 60} minutes. "
        "If you didn't try to sign in, you can ignore this email."
    )

    with smtplib.SMTP(host, port) as smtp:
        smtp.starttls()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(message)


def start_email_otp(email):
    """Generate a fresh code, store it hashed with an expiry in the session, and
    email it. The plaintext code never touches server-side storage."""
    code = generate_email_otp()
    session["email_otp_hash"] = generate_password_hash(code)
    session["email_otp_expires"] = time.time() + EMAIL_OTP_TTL_SECONDS
    send_otp_email(email, code)


def verify_email_otp(code):
    stored_hash = session.get("email_otp_hash")
    expires = session.get("email_otp_expires", 0)
    if not stored_hash or time.time() > expires:
        return False
    return check_password_hash(stored_hash, code)


def clear_email_otp():
    session.pop("email_otp_hash", None)
    session.pop("email_otp_expires", None)


def find_available_port(start_port=5000, max_tries=10):
    for port in range(start_port, start_port + max_tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    return start_port + max_tries


# Ensure the schema exists at import time so the app works under any WSGI
# server (gunicorn, uWSGI, ...), not just when run directly via `python app.py`.
init_db()


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            return render_template("register.html", error="Please enter an email and password")

        try:
            user_id, secret = create_user(email, password)
            session["pending_2fa_user_id"] = user_id
            session["pending_2fa_email"] = email
            session["pending_2fa_secret"] = secret
            return redirect(url_for("two_factor_choose"))
        except IntegrityError:
            return render_template("register.html", error="Email already exists")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_user_by_email(email)

        if user and check_password_hash(user[2], password):
            session["pending_2fa_user_id"] = user[0]
            session["pending_2fa_email"] = user[1]
            session["pending_2fa_secret"] = user[4] or pyotp.random_base32()
            return redirect(url_for("two_factor_choose"))

        return render_template("login.html", error="Invalid email or password")

    return render_template("login.html")


@app.route("/two-factor/choose", methods=["GET", "POST"])
def two_factor_choose():
    if "pending_2fa_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        method = request.form.get("method")

        if method == "authenticator":
            user = get_user_by_id(session["pending_2fa_user_id"])
            if user and user[3] == 1:
                return redirect(url_for("two_factor_verify"))
            return redirect(url_for("two_factor_setup"))

        if method == "email":
            start_email_otp(session["pending_2fa_email"])
            return redirect(url_for("two_factor_email"))

        return render_template(
            "two_factor_choose.html", error="Please choose a verification method."
        )

    return render_template("two_factor_choose.html")


@app.route("/two-factor/setup", methods=["GET", "POST"])
def two_factor_setup():
    if "pending_2fa_user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["pending_2fa_user_id"]
    user = get_user_by_id(user_id)

    if user and user[3] == 1:
        session["user_id"] = user[0]
        session["email"] = user[1]
        session.pop("pending_2fa_user_id", None)
        session.pop("pending_2fa_secret", None)
        return redirect(url_for("dashboard"))

    secret = session.get("pending_2fa_secret") or user[4]
    email = session.get("pending_2fa_email") or user[1]

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(secret)

        if totp.verify(code, valid_window=1):
            update_two_factor_setup(user_id, secret)
            session["user_id"] = user_id
            session["email"] = email
            session.pop("pending_2fa_user_id", None)
            session.pop("pending_2fa_secret", None)
            return redirect(url_for("dashboard"))

        return render_template(
            "two_factor_setup.html",
            email=email,
            qr_code=build_qr_code(secret, email),
            secret=secret,
            error="Invalid code. Please try again.",
        )

    return render_template(
        "two_factor_setup.html",
        email=email,
        qr_code=build_qr_code(secret, email),
        secret=secret,
    )


@app.route("/two-factor/verify", methods=["GET", "POST"])
def two_factor_verify():
    if "pending_2fa_user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["pending_2fa_user_id"]
    user = get_user_by_id(user_id)

    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = user[4]
        totp = pyotp.TOTP(secret)

        if totp.verify(code, valid_window=1):
            session["user_id"] = user[0]
            session["email"] = user[1]
            session.pop("pending_2fa_user_id", None)
            session.pop("pending_2fa_secret", None)
            return redirect(url_for("dashboard"))

        return render_template("two_factor_verify.html", error="Invalid code. Please try again.")

    return render_template("two_factor_verify.html")


@app.route("/two-factor/email", methods=["GET", "POST"])
def two_factor_email():
    if "pending_2fa_user_id" not in session:
        return redirect(url_for("login"))

    user = get_user_by_id(session["pending_2fa_user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        if verify_email_otp(code):
            session["user_id"] = user[0]
            session["email"] = user[1]
            clear_email_otp()
            session.pop("pending_2fa_user_id", None)
            session.pop("pending_2fa_email", None)
            session.pop("pending_2fa_secret", None)
            return redirect(url_for("dashboard"))

        return render_template(
            "two_factor_email.html",
            email=user[1],
            error="Invalid or expired code. Please try again.",
        )

    return render_template("two_factor_email.html", email=user[1])


@app.route("/two-factor/email/resend")
def two_factor_email_resend():
    if "pending_2fa_user_id" not in session:
        return redirect(url_for("login"))

    start_email_otp(session["pending_2fa_email"])
    return redirect(url_for("two_factor_email"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", email=session["email"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    configured_port = int(os.environ.get("PORT", "5000"))
    selected_port = configured_port if os.environ.get("PORT") else find_available_port(configured_port)

    if not os.environ.get("PORT") and selected_port != configured_port:
        print(f"Port {configured_port} is busy. Starting on port {selected_port} instead.")

    debug = os.environ.get("FLASK_DEBUG", "1").lower() in ("1", "true", "yes")
    app.run(debug=debug, host="0.0.0.0", port=selected_port)