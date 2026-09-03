import base64
import os
import secrets
import smtplib
import socket
import time
from datetime import datetime
from email.message import EmailMessage
from functools import wraps
from io import BytesIO

import pyotp
import qrcode
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

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
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB per upload request

# Uploaded files live in a dedicated folder inside the user's Downloads
# directory, so they're easy to find outside the app too.
UPLOAD_DIR = os.path.join(os.path.expanduser("~"), "Downloads", "upload_login_app")
os.makedirs(UPLOAD_DIR, exist_ok=True)


metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("email", String(255), unique=True, nullable=False),
    Column("password", String(255), nullable=False),
    Column("two_factor_enabled", Integer, nullable=False, server_default=text("0")),
    Column("two_factor_secret", String(64)),
    Column("email_2fa_enabled", Integer, nullable=False, server_default=text("1")),
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
        if "email_2fa_enabled" not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN email_2fa_enabled INTEGER NOT NULL DEFAULT 1"))


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
                email_2fa_enabled=1,
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
        users.c.email_2fa_enabled,
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


def update_password(user_id, new_password):
    with engine.begin() as conn:
        conn.execute(
            update(users)
            .where(users.c.id == user_id)
            .values(password=generate_password_hash(new_password))
        )


def disable_authenticator(user_id):
    """Turn off the authenticator method and roll the secret, so a
    previously-scanned QR code can't be used to re-enable it silently."""
    with engine.begin() as conn:
        conn.execute(
            update(users)
            .where(users.c.id == user_id)
            .values(two_factor_enabled=0, two_factor_secret=pyotp.random_base32())
        )


def set_email_2fa(user_id, enabled):
    with engine.begin() as conn:
        conn.execute(
            update(users)
            .where(users.c.id == user_id)
            .values(email_2fa_enabled=1 if enabled else 0)
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


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def format_file_size(num_bytes):
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def list_uploaded_files():
    """Files currently sitting in UPLOAD_DIR, newest first."""
    entries = []
    for name in os.listdir(UPLOAD_DIR):
        path = os.path.join(UPLOAD_DIR, name)
        if not os.path.isfile(path):
            continue
        stat = os.stat(path)
        entries.append(
            {
                "name": name,
                "size": stat.st_size,
                "size_display": format_file_size(stat.st_size),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%b %d, %Y %H:%M"),
                "modified_ts": stat.st_mtime,
            }
        )
    entries.sort(key=lambda entry: entry["modified_ts"], reverse=True)
    return entries


def unique_filename(directory, filename):
    """Avoid clobbering an existing file by appending ' (1)', ' (2)', ..."""
    base, ext = os.path.splitext(filename)
    candidate = filename
    counter = 1
    while os.path.exists(os.path.join(directory, candidate)):
        candidate = f"{base} ({counter}){ext}"
        counter += 1
    return candidate


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

    user = get_user_by_id(session["pending_2fa_user_id"])
    email_enabled = bool(user[5]) if user else True

    if request.method == "POST":
        method = request.form.get("method")

        if method == "authenticator":
            if user and user[3] == 1:
                return redirect(url_for("two_factor_verify"))
            return redirect(url_for("two_factor_setup"))

        if method == "email" and email_enabled:
            start_email_otp(session["pending_2fa_email"])
            return redirect(url_for("two_factor_email"))

        return render_template(
            "two_factor_choose.html",
            email_enabled=email_enabled,
            error="Please choose a verification method.",
        )

    return render_template("two_factor_choose.html", email_enabled=email_enabled)


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
@login_required
def dashboard():
    files = list_uploaded_files()
    return render_template(
        "dashboard.html",
        email=session["email"],
        file_count=len(files),
        total_size=format_file_size(sum(f["size"] for f in files)),
        recent_files=files[:5],
    )


@app.route("/files")
@login_required
def files_home():
    files = list_uploaded_files()
    return render_template(
        "files.html",
        email=session["email"],
        file_count=len(files),
        total_size=format_file_size(sum(f["size"] for f in files)),
    )


@app.route("/files/upload", methods=["GET", "POST"])
@login_required
def files_upload():
    if request.method == "POST":
        uploaded = [f for f in request.files.getlist("files") if f and f.filename]
        saved, skipped = [], []

        for file in uploaded:
            filename = secure_filename(file.filename)
            if not filename:
                skipped.append(file.filename)
                continue
            filename = unique_filename(UPLOAD_DIR, filename)
            file.save(os.path.join(UPLOAD_DIR, filename))
            saved.append(filename)

        is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
        if is_ajax:
            return jsonify(saved=saved, skipped=skipped, files=list_uploaded_files())

        if saved:
            flash(f"Uploaded {len(saved)} file(s) successfully.", "success")
        if skipped:
            flash(f"Skipped {len(skipped)} file(s) with an invalid name.", "error")
        return redirect(url_for("files_upload"))

    return render_template("files_upload.html", email=session["email"], files=list_uploaded_files())


@app.route("/files/download")
@login_required
def files_download():
    return render_template("files_download.html", email=session["email"], files=list_uploaded_files())


@app.route("/files/download/<path:filename>")
@login_required
def files_download_file(filename):
    safe_name = os.path.basename(filename)
    if safe_name != filename or not os.path.isfile(os.path.join(UPLOAD_DIR, safe_name)):
        flash("That file could not be found.", "error")
        return redirect(url_for("files_download"))

    return send_from_directory(UPLOAD_DIR, safe_name, as_attachment=True)


@app.route("/about")
@login_required
def about():
    return render_template("about.html", email=session["email"])


@app.route("/contact", methods=["GET", "POST"])
@login_required
def contact():
    if request.method == "POST":
        flash("Thanks for reaching out — our team will get back to you shortly.", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html", email=session["email"])


@app.route("/profile")
@login_required
def profile():
    user = get_user_by_id(session["user_id"])
    files = list_uploaded_files()
    return render_template(
        "profile.html",
        email=session["email"],
        two_factor_enabled=bool(user[3]) if user else False,
        email_2fa_enabled=bool(user[5]) if user else False,
        file_count=len(files),
        total_size=format_file_size(sum(f["size"] for f in files)),
    )


@app.route("/profile/change-password", methods=["POST"])
@login_required
def change_password():
    user = get_user_by_id(session["user_id"])
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not user or not check_password_hash(user[2], current_password):
        flash("Current password is incorrect.", "error")
    elif len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
    elif new_password != confirm_password:
        flash("New password and confirmation do not match.", "error")
    else:
        update_password(user[0], new_password)
        flash("Password updated successfully.", "success")

    return redirect(url_for("profile"))


@app.route("/profile/2fa/authenticator/setup", methods=["GET", "POST"])
@login_required
def profile_authenticator_setup():
    user = get_user_by_id(session["user_id"])
    if not user:
        return redirect(url_for("login"))

    if user[3] == 1:
        return redirect(url_for("profile"))

    secret = user[4] or pyotp.random_base32()
    email = user[1]

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(secret)

        if totp.verify(code, valid_window=1):
            update_two_factor_setup(user[0], secret)
            flash("Authenticator app enabled.", "success")
            return redirect(url_for("profile"))

        return render_template(
            "profile_authenticator_setup.html",
            email=email,
            qr_code=build_qr_code(secret, email),
            secret=secret,
            error="Invalid code. Please try again.",
        )

    return render_template(
        "profile_authenticator_setup.html",
        email=email,
        qr_code=build_qr_code(secret, email),
        secret=secret,
    )


@app.route("/profile/2fa/authenticator/disable", methods=["POST"])
@login_required
def profile_authenticator_disable():
    user = get_user_by_id(session["user_id"])
    if not user:
        return redirect(url_for("login"))

    if not user[5]:
        flash("You need at least one two-factor method enabled. Enable email verification first.", "error")
        return redirect(url_for("profile"))

    disable_authenticator(user[0])
    flash("Authenticator app disabled.", "success")
    return redirect(url_for("profile"))


@app.route("/profile/2fa/email/enable", methods=["POST"])
@login_required
def profile_email_2fa_enable():
    set_email_2fa(session["user_id"], True)
    flash("Email verification enabled.", "success")
    return redirect(url_for("profile"))


@app.route("/profile/2fa/email/disable", methods=["POST"])
@login_required
def profile_email_2fa_disable():
    user = get_user_by_id(session["user_id"])
    if not user or user[3] != 1:
        flash("You need at least one two-factor method enabled. Set up an authenticator app first.", "error")
        return redirect(url_for("profile"))

    set_email_2fa(session["user_id"], False)
    flash("Email verification disabled.", "success")
    return redirect(url_for("profile"))


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