"""Meme reactions for the messages the app shows users.

Images come from memegen.link, an open-source meme API meant for embedding:
each meme is a plain image URL with the caption in the path, so the captions
here are written for this app. Set MEMES_ENABLED=0 to turn them off.
"""

import os
from urllib.parse import quote

MEMEGEN_BASE = "https://api.memegen.link/images"
MEME_WIDTH = 360

# key -> (memegen template id, caption lines, alt text)
MEMES = {
    # --- errors ---
    "wrong_login": ("fry", ["Not sure if wrong password", "or wrong email"], "Futurama Fry squinting suspiciously"),
    "missing_fields": ("yuno", ["Empty form?", "Y U NO type something"], "Y U NO guy throwing his hands up"),
    "invalid_email": ("wonka", ["Oh, that's an email address?", "Tell me more about where the @ goes"], "Condescending Willy Wonka"),
    "email_exists": ("spiderman", ["Your new account", "Your old account"], "Spider-Man pointing at Spider-Man"),
    "wrong_code": ("mordor", ["One does not simply", "guess a 6-digit code"], "Boromir: one does not simply walk into Mordor"),
    "wrong_authenticator_code": ("older", ["An older code, sir", "but it doesn't check out"], "Star Wars officer: an older code, sir"),
    "send_failed": ("fine", ["Sending your code", "This is fine"], "Dog sitting in a burning room saying this is fine"),
    "method_not_set_up": ("gandalf", ["That verification method?", "I have no memory of this"], "Confused Gandalf"),
    "choose_method": ("drake", ["Clicking nothing", "Clicking a button"], "Drake rejecting one thing and approving another"),
    "phone_format": ("aag", ["I'm not saying it's the country code", "but it's the country code"], "Ancient Aliens guy"),
    "rate_limited": ("stop-it", ["Stop it", "Get some help"], "Michael Jordan: stop it, get some help"),
    "not_found": ("pigeon", ["You", "This link", "Is this a page?"], "Anime guy asking: is this a pigeon?"),
    "not_allowed": ("officespace", ["Yeah, if you could not do that", "that would be great"], "Office Space boss with a coffee mug"),
    "too_large": ("toohigh", ["The file size", "is too damn high"], "The rent is too damn high guy"),
    "server_error": ("noidea", ["Our server right now", "I have no idea what I'm doing"], "Dog at a computer: I have no idea what I'm doing"),
    "db_down": ("harold", ["Database is down", "Everything is fine"], "Hide the Pain Harold smiling through it"),
    "wrong_current_password": ("facepalm", ["Forgot your password", "while you're logged in"], "Captain Picard facepalm"),
    "password_too_short": ("cmm", ["8 characters is not that many"], "Change my mind sign"),
    "password_mismatch": ("same", ["New password", "Confirm password", "They're NOT the same picture"], "Pam from The Office: they're the same picture"),
    "last_method": ("ackbar", ["Turning off your last 2FA method?", "It's a trap!"], "Admiral Ackbar: it's a trap"),
    "upload_failed": ("fwp", ["Uploaded my files", "Server ran out of space"], "First world problems crying woman"),
    "invalid_filename": ("spongebob", ["That file name", "tHaT fIlE nAmE"], "Mocking SpongeBob"),
    "file_not_found": ("pigeon", ["You", "That file", "Is this still here?"], "Anime guy asking: is this a pigeon?"),
    "session_expired": ("whatyear", ["What year is it?", "Your session expired, sign in again"], "Robin Williams in Jumanji: what year is it?"),
    "generic_error": ("tried", ["At least", "you tried"], "At least you tried, with a gold star"),
    # --- successes ---
    "password_updated": ("success", ["Changed my password", "and already remember it"], "Success Kid clenching a fist"),
    "method_enabled": ("stonks", ["Account security", "Stonks"], "Stonks meme man in front of a rising chart"),
    "method_disabled": ("kermit", ["Turned off a 2FA method", "but that's none of my business"], "Kermit sipping tea"),
    "uploaded": ("doge", ["such upload", "very file wow"], "Doge"),
    "message_sent": ("soa", ["Message received", "We'll get back to you"], "Seal of approval"),
    "generic_success": ("success", ["Nailed it", ""], "Success Kid clenching a fist"),
}

# (message kind, words to look for in the message, meme key). First match wins,
# so more specific phrases come first.
RULES = [
    ("error", ("too many attempts",), "rate_limited"),
    ("error", ("invalid email or password",), "wrong_login"),
    ("error", ("enter an email and password",), "missing_fields"),
    ("error", ("valid email address",), "invalid_email"),
    ("error", ("already exists",), "email_exists"),
    ("error", ("isn't set up",), "method_not_set_up"),
    ("error", ("choose a verification method",), "choose_method"),
    ("error", ("couldn't send",), "send_failed"),
    ("error", ("international format",), "phone_format"),
    ("error", ("invalid or expired code",), "wrong_code"),
    ("error", ("invalid code",), "wrong_authenticator_code"),
    ("error", ("current password is incorrect",), "wrong_current_password"),
    ("error", ("at least 8 characters",), "password_too_short"),
    ("error", ("do not match",), "password_mismatch"),
    ("error", ("at least one two-factor method",), "last_method"),
    ("error", ("limited to", "too large"), "too_large"),
    ("error", ("out of space", "couldn't save", "upload failed"), "upload_failed"),
    ("error", ("invalid name",), "invalid_filename"),
    ("error", ("could not be found",), "file_not_found"),
    ("error", ("session has expired",), "session_expired"),
    ("success", ("password updated", "password changed"), "password_updated"),
    ("success", ("disabled",), "method_disabled"),
    ("success", ("enabled",), "method_enabled"),
    ("success", ("uploaded",), "uploaded"),
    ("success", ("thanks for reaching out",), "message_sent"),
]

DEFAULT_FOR_KIND = {"error": "generic_error", "success": "generic_success"}

STATUS_MEMES = {
    400: "generic_error",
    403: "not_allowed",
    404: "not_found",
    405: "not_allowed",
    413: "too_large",
    429: "rate_limited",
    500: "server_error",
    503: "db_down",
}


def memes_enabled():
    return os.environ.get("MEMES_ENABLED", "1").strip().lower() not in ("0", "false", "no", "off")


def _escape_line(line):
    """Encode one caption line for a memegen URL path (see memegen.link docs:
    underscores are spaces, and special characters use ~ escapes)."""
    if not line:
        return "_"  # memegen's placeholder for an empty line
    replacements = [
        ("_", "__"),
        ("-", "--"),
        (" ", "_"),
        ("?", "~q"),
        ("&", "~a"),
        ("%", "~p"),
        ("#", "~h"),
        ("/", "~s"),
        ("\\", "~b"),
        ("<", "~l"),
        (">", "~g"),
        ('"', "''"),
    ]
    for old, new in replacements:
        line = line.replace(old, new)
    return quote(line, safe="_~'.,!@:()")


def meme_url(key):
    template, lines, _ = MEMES[key]
    path = "/".join(_escape_line(line) for line in lines)
    return f"{MEMEGEN_BASE}/{template}/{path}.jpg?width={MEME_WIDTH}"


def meme_by_key(key):
    """{"url", "alt"} for a meme key, or None when memes are off or unknown."""
    if not memes_enabled() or key not in MEMES:
        return None
    return {"url": meme_url(key), "alt": "Meme: " + MEMES[key][2]}


def meme_for(message, kind="error"):
    """The meme for a message shown to the user. `kind` is the flash category
    ("error" or "success"); unknown categories get no meme."""
    if kind not in DEFAULT_FOR_KIND:
        return None
    text = (message or "").lower()
    for rule_kind, needles, key in RULES:
        if rule_kind == kind and any(needle in text for needle in needles):
            return meme_by_key(key)
    return meme_by_key(DEFAULT_FOR_KIND[kind])


def meme_for_status(status):
    return meme_by_key(STATUS_MEMES.get(status, "generic_error"))
