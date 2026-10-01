import base64
import logging
import os
import re
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
    g, render_template,
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
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

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
    Column("phone_number", String(20)),
    Column("sms_2fa_enabled", Integer, nullable=False, server_default=text("0")),
)


def _resolve_database_url():
    """Choose the database from the environment.

    Prefers DATABASE_URL (set automatically by Render/Heroku for managed
    Postgres). Falls back to a local SQLite file so development and tests work
    with zero setup. DATABASE keeps backwards compatibility for the SQLite path.
    """
    url = os.environ.get("DATABASE_URL")
    if url:
        logger.info("database_configured backend=environment_url")
        return _normalize_database_url(url)

    sqlite_path = os.environ.get("DATABASE", "users.db")
    logger.info("database_configured backend=sqlite path=%s", sqlite_path)
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
    logger.info("database_reconfigured")
    return engine


def init_db():
    logger.info("database_initialization_started")
    metadata.create_all(engine)
    ensure_user_columns()
    logger.info("database_initialization_completed")


def ensure_user_columns():
    """Add the 2FA columns to pre-existing tables that predate them."""
    existing = {col["name"] for col in inspect(engine).get_columns("users")}

    with engine.begin() as conn:
        if "two_factor_enabled" not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0"))
            logger.info("database_schema_updated column=two_factor_enabled")
        if "two_factor_secret" not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN two_factor_secret VARCHAR(64)"))
            logger.info("database_schema_updated column=two_factor_secret")
        if "email_2fa_enabled" not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN email_2fa_enabled INTEGER NOT NULL DEFAULT 1"))
            logger.info("database_schema_updated column=email_2fa_enabled")
        if "phone_number" not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN phone_number VARCHAR(20)"))
            logger.info("database_schema_updated column=phone_number")
        if "sms_2fa_enabled" not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN sms_2fa_enabled INTEGER NOT NULL DEFAULT 0"))
            logger.info("database_schema_updated column=sms_2fa_enabled")


def _mask_email(email):
    """Mask the local part of an email address for logging."""
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def _mask_phone(phone):
    """Show only the last two digits of a phone number, for logs and UI."""
    if not phone:
        return phone
    return "*" * (len(phone) - 2) + phone[-2:]


def create_user(email, password):
    logger.info("user_creation_started email=%s", _mask_email(email))
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

    logger.info("user_creation_completed user_id=%s email=%s", user_id, _mask_email(email))
    return user_id, secret


def _fetch_user(where_clause):
    query = select(
        users.c.id,
        users.c.email,
        users.c.password,
        users.c.two_factor_enabled,
        users.c.two_factor_secret,
        users.c.email_2fa_enabled,
        users.c.phone_number,
        users.c.sms_2fa_enabled,
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
    logger.info("two_factor_setup_saved user_id=%s", user_id)



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


def set_sms_2fa(user_id, phone_number):
    """Enable SMS codes for a verified phone number, or disable them (and
    forget the number) when phone_number is None."""
    with engine.begin() as conn:
        conn.execute(
            update(users)
            .where(users.c.id == user_id)
            .values(phone_number=phone_number, sms_2fa_enabled=1 if phone_number else 0)
        )
    logger.info("sms_2fa_updated user_id=%s enabled=%s", user_id, bool(phone_number))


def enabled_method_count(user):
    """How many 2FA methods a user row has switched on."""
    return sum(1 for flag in (user[3], user[5], user[7]) if flag)


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
        logger.warning("otp_delivery_fallback email=%s", _mask_email(to_email))
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
    logger.info("otp_email_sent email=%s host=%s", _mask_email(to_email), host)


def start_email_otp(email):
    """Generate a fresh code, store it hashed with an expiry in the session, and
    email it. The plaintext code never touches server-side storage."""
    code = generate_email_otp()
    session["email_otp_hash"] = generate_password_hash(code)
    session["email_otp_expires"] = time.time() + EMAIL_OTP_TTL_SECONDS
    send_otp_email(email, code)
    logger.info("email_otp_started email=%s ttl_seconds=%s", _mask_email(email), EMAIL_OTP_TTL_SECONDS)


def verify_email_otp(code):
    stored_hash = session.get("email_otp_hash")
    expires = session.get("email_otp_expires", 0)
    if not stored_hash or time.time() > expires:
        logger.warning("email_otp_verification_failed reason=missing_or_expired")
        return False
    verified = check_password_hash(stored_hash, code)
    logger.info("email_otp_verification_completed success=%s", verified)
    return verified


def clear_email_otp():
    session.pop("email_otp_hash", None)
    session.pop("email_otp_expires", None)


E164_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")
SMS_OTP_TTL_SECONDS = 600  # matches Twilio Verify's default code lifetime


class SmsDeliveryError(Exception):
    """Raised when Twilio refuses to send a verification SMS."""


def normalize_phone_number(raw):
    """Strip formatting characters and return an E.164 number (e.g.
    +14155552671), or None if the input isn't one. Twilio requires E.164."""
    phone = re.sub(r"[\s\-().]", "", raw or "")
    return phone if E164_PATTERN.match(phone) else None


def _twilio_verify_service():
    """Return the Twilio Verify service, or None when Twilio isn't configured.

    Prefers an API Key (TWILIO_API_KEY_SID + TWILIO_API_KEY_SECRET), which can
    be restricted and revoked on its own; falls back to the account Auth Token.
    """
    account_sid = os.environ.get("TWILIO_ACCOUNT_SID")
    service_sid = os.environ.get("TWILIO_VERIFY_SERVICE_SID")
    api_key_sid = os.environ.get("TWILIO_API_KEY_SID")
    api_key_secret = os.environ.get("TWILIO_API_KEY_SECRET")
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
    if not (account_sid and service_sid):
        return None

    from twilio.rest import Client

    if api_key_sid and api_key_secret:
        credentials = {"TWILIO_API_KEY_SID": api_key_sid, "TWILIO_API_KEY_SECRET": api_key_secret}
        client_args = (api_key_sid, api_key_secret, account_sid)
    elif auth_token:
        credentials = {"TWILIO_AUTH_TOKEN": auth_token}
        client_args = (account_sid, auth_token)
    else:
        return None

    # Twilio credentials are plain ASCII letters and digits. Anything else is a
    # copy/paste or keyboard-layout mistake, and would otherwise crash deep in
    # the HTTP client while building the Authorization header.
    credentials.update(TWILIO_ACCOUNT_SID=account_sid, TWILIO_VERIFY_SERVICE_SID=service_sid)
    for name, value in credentials.items():
        if not (value.isascii() and value.isalnum()):
            logger.error("twilio_config_invalid variable=%s reason=non_alphanumeric_characters", name)
            raise SmsDeliveryError(f"{name} contains invalid characters")

    return Client(*client_args).verify.v2.services(service_sid)


def start_sms_otp(phone):
    """Text a one-time code to `phone` via Twilio Verify.

    Twilio generates, delivers, and later checks the code, so nothing is stored
    here. When Twilio isn't configured, a local code is generated and printed to
    the server console instead (hashed in the session, like email OTP), so local
    development works without a Twilio account.
    """
    service = _twilio_verify_service()
    if service is None:
        code = generate_email_otp()
        session["sms_otp_hash"] = generate_password_hash(code)
        session["sms_otp_expires"] = time.time() + SMS_OTP_TTL_SECONDS
        logger.warning("otp_delivery_fallback phone=%s", _mask_phone(phone))
        print(f"[DEV] SMS OTP for {phone}: {code}")
        return

    from twilio.base.exceptions import TwilioRestException

    try:
        service.verifications.create(to=phone, channel="sms")
    except TwilioRestException as exc:
        logger.error("sms_otp_send_failed phone=%s status=%s code=%s", _mask_phone(phone), exc.status, exc.code)
        raise SmsDeliveryError(str(exc.msg)) from exc
    logger.info("sms_otp_started phone=%s", _mask_phone(phone))


def verify_sms_otp(phone, code):
    if not code.isdigit():
        logger.warning("sms_otp_verification_failed reason=malformed_code")
        return False

    try:
        service = _twilio_verify_service()
    except SmsDeliveryError:
        return False
    if service is None:
        stored_hash = session.get("sms_otp_hash")
        expires = session.get("sms_otp_expires", 0)
        if not stored_hash or time.time() > expires:
            logger.warning("sms_otp_verification_failed reason=missing_or_expired")
            return False
        verified = check_password_hash(stored_hash, code)
        logger.info("sms_otp_verification_completed success=%s", verified)
        return verified

    from twilio.base.exceptions import TwilioRestException

    try:
        check = service.verification_checks.create(to=phone, code=code)
    except TwilioRestException as exc:
        # Twilio answers 404 once a verification has expired, been approved,
        # or exceeded its attempt limit.
        logger.warning("sms_otp_verification_failed status=%s code=%s", exc.status, exc.code)
        return False

    verified = check.status == "approved"
    logger.info("sms_otp_verification_completed success=%s", verified)
    return verified


def clear_sms_otp():
    session.pop("sms_otp_hash", None)
    session.pop("sms_otp_expires", None)


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
    logger.info("home_redirected")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            logger.warning("registration_rejected reason=missing_credentials")
            return render_template("register.html", error="Please enter an email and password")

        try:
            user_id, secret = create_user(email, password)
            session["pending_2fa_user_id"] = user_id
            session["pending_2fa_email"] = email
            session["pending_2fa_secret"] = secret
            logger.info("registration_accepted user_id=%s email=%s", user_id, _mask_email(email))
            return redirect(url_for("two_factor_choose"))
        except IntegrityError:
            logger.warning("registration_rejected reason=email_exists email=%s", _mask_email(email))
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
            logger.info("login_password_verified user_id=%s email=%s", user[0], _mask_email(email))
            return redirect(url_for("two_factor_choose"))

        logger.warning("login_rejected email=%s", _mask_email(email))
        return render_template("login.html", error="Invalid email or password")

    return render_template("login.html")


@app.route("/two-factor/choose", methods=["GET", "POST"])
def two_factor_choose():
    if "pending_2fa_user_id" not in session:
        logger.warning("two_factor_choose_rejected reason=no_pending_user")
        return redirect(url_for("login"))

    user = get_user_by_id(session["pending_2fa_user_id"])
    email_enabled = bool(user[5]) if user else True
    sms_enabled = bool(user and user[7] and user[6])
    choose_context = {
        "email_enabled": email_enabled,
        "sms_enabled": sms_enabled,
        "masked_phone": _mask_phone(user[6]) if sms_enabled else None,
    }

    if request.method == "POST":
        method = request.form.get("method")

        if method == "authenticator":
            if user and user[3] == 1:
                logger.info("two_factor_method_selected method=authenticator user_id=%s", user[0])
                return redirect(url_for("two_factor_verify"))
            logger.info("two_factor_method_selected method=authenticator action=setup")
            return redirect(url_for("two_factor_setup"))

        if method == "email" and email_enabled:
            logger.info("two_factor_method_selected method=email")
            start_email_otp(session["pending_2fa_email"])
            return redirect(url_for("two_factor_email"))

        if method == "sms" and user:
            if not sms_enabled:
                # No verified phone yet: ask for one on the SMS page.
                logger.info("two_factor_method_selected method=sms action=enroll user_id=%s", user[0])
                return redirect(url_for("two_factor_sms"))
            logger.info("two_factor_method_selected method=sms user_id=%s", user[0])
            try:
                start_sms_otp(user[6])
            except SmsDeliveryError:
                return render_template(
                    "two_factor_choose.html",
                    **choose_context,
                    error="We couldn't send a text message right now. Please try another method.",
                )
            return redirect(url_for("two_factor_sms"))

        logger.warning("two_factor_method_rejected reason=invalid_method")
        return render_template(
            "two_factor_choose.html",
            **choose_context,
            error="Please choose a verification method.",
        )

    return render_template("two_factor_choose.html", **choose_context)


@app.route("/two-factor/setup", methods=["GET", "POST"])
def two_factor_setup():
    if "pending_2fa_user_id" not in session:
        logger.warning("two_factor_setup_rejected reason=no_pending_user")
        return redirect(url_for("login"))

    user_id = session["pending_2fa_user_id"]
    user = get_user_by_id(user_id)

    if user and user[3] == 1:
        session["user_id"] = user[0]
        session["email"] = user[1]
        session.pop("pending_2fa_user_id", None)
        session.pop("pending_2fa_secret", None)
        logger.info("two_factor_setup_skipped user_id=%s reason=already_enabled", user[0])
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
            logger.info("two_factor_setup_verified user_id=%s", user_id)
            return redirect(url_for("dashboard"))

        logger.warning("two_factor_setup_rejected user_id=%s reason=invalid_code", user_id)
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
        logger.warning("two_factor_verify_rejected reason=no_pending_user")
        return redirect(url_for("login"))

    user_id = session["pending_2fa_user_id"]
    user = get_user_by_id(user_id)

    if not user:
        logger.error("two_factor_verify_failed reason=user_not_found user_id=%s", user_id)
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
            logger.info("two_factor_verified user_id=%s", user_id)
            return redirect(url_for("dashboard"))

        logger.warning("two_factor_verify_rejected user_id=%s reason=invalid_code", user_id)
        return render_template("two_factor_verify.html", error="Invalid code. Please try again.")

    return render_template("two_factor_verify.html")


@app.route("/two-factor/email", methods=["GET", "POST"])
def two_factor_email():
    if "pending_2fa_user_id" not in session:
        logger.warning("two_factor_email_rejected reason=no_pending_user")
        return redirect(url_for("login"))

    user = get_user_by_id(session["pending_2fa_user_id"])
    if not user:
        logger.error("two_factor_email_failed reason=user_not_found")
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
            logger.info("two_factor_email_verified user_id=%s", user[0])
            return redirect(url_for("dashboard"))

        logger.warning("two_factor_email_rejected user_id=%s reason=invalid_or_expired_code", user[0])
        return render_template(
            "two_factor_email.html",
            email=user[1],
            error="Invalid or expired code. Please try again.",
        )

    return render_template("two_factor_email.html", email=user[1])


@app.route("/two-factor/email/resend")
def two_factor_email_resend():
    if "pending_2fa_user_id" not in session:
        logger.warning("otp_resend_rejected reason=no_pending_user")
        return redirect(url_for("login"))

    start_email_otp(session["pending_2fa_email"])
    logger.info("otp_resent")
    return redirect(url_for("two_factor_email"))


@app.route("/two-factor/sms", methods=["GET", "POST"])
def two_factor_sms():
    if "pending_2fa_user_id" not in session:
        logger.warning("two_factor_sms_rejected reason=no_pending_user")
        return redirect(url_for("login"))

    user = get_user_by_id(session["pending_2fa_user_id"])
    if not user:
        logger.error("two_factor_sms_failed reason=user_not_found")
        session.clear()
        return redirect(url_for("login"))

    # Users with a verified phone get a code straight away (sent from the
    # choose page). Users without one first enter a number here; it's saved to
    # their account only after they prove they own it by entering the code.
    enrolled_phone = user[6] if user[7] else None
    target_phone = enrolled_phone or session.get("pending_sms_phone")

    def render(error=None):
        return render_template(
            "two_factor_sms.html",
            needs_phone=target_phone is None,
            masked_phone=_mask_phone(target_phone) if target_phone else None,
            can_change_number=enrolled_phone is None,
            error=error,
        )

    if request.method == "POST":
        step = request.form.get("step", "verify")

        if step == "send" and not enrolled_phone:
            phone = normalize_phone_number(request.form.get("phone", ""))
            if not phone:
                return render("Enter your number in international format, e.g. +14155552671.")
            try:
                start_sms_otp(phone)
            except SmsDeliveryError:
                return render("We couldn't send a text to that number. Check it and try again.")
            session["pending_sms_phone"] = phone
            logger.info("two_factor_sms_enroll_code_sent user_id=%s phone=%s", user[0], _mask_phone(phone))
            return redirect(url_for("two_factor_sms"))

        if step == "restart" and not enrolled_phone:
            clear_sms_otp()
            session.pop("pending_sms_phone", None)
            return redirect(url_for("two_factor_sms"))

        if step == "verify" and target_phone:
            code = request.form.get("code", "").strip()

            if verify_sms_otp(target_phone, code):
                if not enrolled_phone:
                    set_sms_2fa(user[0], target_phone)
                session["user_id"] = user[0]
                session["email"] = user[1]
                clear_sms_otp()
                session.pop("pending_sms_phone", None)
                session.pop("pending_2fa_user_id", None)
                session.pop("pending_2fa_email", None)
                session.pop("pending_2fa_secret", None)
                logger.info("two_factor_sms_verified user_id=%s enrolled=%s", user[0], not enrolled_phone)
                return redirect(url_for("dashboard"))

            logger.warning("two_factor_sms_rejected user_id=%s reason=invalid_or_expired_code", user[0])
            return render("Invalid or expired code. Please try again.")

    return render()


@app.route("/two-factor/sms/resend")
def two_factor_sms_resend():
    if "pending_2fa_user_id" not in session:
        logger.warning("sms_otp_resend_rejected reason=no_pending_user")
        return redirect(url_for("login"))

    user = get_user_by_id(session["pending_2fa_user_id"])
    if not user:
        return redirect(url_for("login"))

    phone = (user[6] if user[7] else None) or session.get("pending_sms_phone")
    if not phone:
        return redirect(url_for("two_factor_sms"))

    try:
        start_sms_otp(phone)
    except SmsDeliveryError:
        flash("We couldn't send a new code right now. Please try again shortly.", "error")
        return redirect(url_for("two_factor_sms"))
    logger.info("sms_otp_resent user_id=%s", user[0])
    return redirect(url_for("two_factor_sms"))


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
        sms_2fa_enabled=bool(user and user[7] and user[6]),
        masked_phone=_mask_phone(user[6]) if user and user[6] else None,
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

    if enabled_method_count(user) < 2:
        flash("You need at least one two-factor method enabled. Enable email or SMS verification first.", "error")
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
    if not user or enabled_method_count(user) < 2:
        flash("You need at least one two-factor method enabled. Set up an authenticator app or SMS first.", "error")
        return redirect(url_for("profile"))

    set_email_2fa(session["user_id"], False)
    flash("Email verification disabled.", "success")
    return redirect(url_for("profile"))


@app.route("/profile/2fa/sms/setup", methods=["GET", "POST"])
@login_required
def profile_sms_setup():
    """Two steps on one page: enter a phone number (we text it a code), then
    enter that code to prove ownership before SMS is enabled."""
    user = get_user_by_id(session["user_id"])
    if not user:
        return redirect(url_for("login"))

    pending_phone = session.get("sms_setup_phone")

    if request.method == "POST":
        step = request.form.get("step")

        if step == "send":
            phone = normalize_phone_number(request.form.get("phone", ""))
            if not phone:
                return render_template(
                    "profile_sms_setup.html",
                    email=user[1],
                    error="Enter your number in international format, e.g. +14155552671.",
                )
            try:
                start_sms_otp(phone)
            except SmsDeliveryError:
                return render_template(
                    "profile_sms_setup.html",
                    email=user[1],
                    error="We couldn't send a text to that number. Check it and try again.",
                )
            session["sms_setup_phone"] = phone
            return redirect(url_for("profile_sms_setup"))

        if step == "verify" and pending_phone:
            code = request.form.get("code", "").strip()
            if verify_sms_otp(pending_phone, code):
                set_sms_2fa(user[0], pending_phone)
                clear_sms_otp()
                session.pop("sms_setup_phone", None)
                flash("SMS verification enabled.", "success")
                return redirect(url_for("profile"))

            return render_template(
                "profile_sms_setup.html",
                email=user[1],
                pending_phone=pending_phone,
                error="Invalid or expired code. Please try again.",
            )

        if step == "restart":
            clear_sms_otp()
            session.pop("sms_setup_phone", None)
            return redirect(url_for("profile_sms_setup"))

    return render_template("profile_sms_setup.html", email=user[1], pending_phone=pending_phone)


@app.route("/profile/2fa/sms/disable", methods=["POST"])
@login_required
def profile_sms_disable():
    user = get_user_by_id(session["user_id"])
    if not user or enabled_method_count(user) < 2:
        flash("You need at least one two-factor method enabled. Enable another method first.", "error")
        return redirect(url_for("profile"))

    set_sms_2fa(user[0], None)
    flash("SMS verification disabled and phone number removed.", "success")
    return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    logger.info("logout user_id=%s", session.get("user_id", "<anonymous>"))
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    configured_port = int(os.environ.get("PORT", "5000"))
    selected_port = configured_port if os.environ.get("PORT") else find_available_port(configured_port)

    if not os.environ.get("PORT") and selected_port != configured_port:
        logger.warning("port_in_use configured_port=%s selected_port=%s", configured_port, selected_port)

    debug = os.environ.get("FLASK_DEBUG", "1").lower() in ("1", "true", "yes")
    logger.info("server_starting host=0.0.0.0 port=%s debug=%s", selected_port, debug)
    app.run(debug=debug, host="0.0.0.0", port=selected_port)