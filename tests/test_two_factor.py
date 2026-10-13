import io
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import markupsafe
import pyotp

import app as auth_module
import memes


class TwoFactorAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        auth_module.configure_database(f"sqlite:///{self.temp_db.name}")
        auth_module.init_db()
        auth_module.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = auth_module.app.test_client()

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def test_new_user_is_redirected_to_choose_verification(self):
        response = self.client.post(
            "/register",
            data={"email": "new@example.com", "password": "secret123"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/two-factor/choose")

        conn = sqlite3.connect(self.temp_db.name)
        row = conn.execute(
            "SELECT two_factor_enabled, two_factor_secret FROM users WHERE email=?",
            ("new@example.com",),
        ).fetchone()
        conn.close()

        self.assertEqual(row[0], 0)
        self.assertTrue(row[1])

    def test_existing_user_is_prompted_to_choose_on_first_login(self):
        auth_module.create_user("existing@example.com", "password123")

        response = self.client.post(
            "/login",
            data={"email": "existing@example.com", "password": "password123"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/two-factor/choose")

    def _log_in_with_password(self, email):
        self.client.post("/login", data={"email": email, "password": "password123"})

    def _email_only_user(self, email):
        """An established account whose only method is email codes."""
        user_id, secret = auth_module.create_user(email, "password123")
        auth_module.set_email_2fa(user_id, True)
        return user_id, secret

    def test_new_account_starts_with_no_method_and_may_choose_any(self):
        user_id, _ = auth_module.create_user("new@example.com", "password123")
        self._log_in_with_password("new@example.com")

        user = auth_module.get_user_by_id(user_id)
        self.assertEqual((user[3], user[5], user[7]), (0, 0, 0))

        page = self.client.get("/two-factor/choose").data
        self.assertIn(b"Secure your account", page)
        for method in (b"email", b"sms", b"authenticator"):
            self.assertIn(b'value="' + method + b'" class="method-choice">', page)

    def test_new_account_can_enroll_authenticator(self):
        user_id, secret = auth_module.create_user("auth@example.com", "password123")
        self._log_in_with_password("auth@example.com")

        choose = self.client.post("/two-factor/choose", data={"method": "authenticator"})
        self.assertEqual(choose.headers["Location"], "/two-factor/setup")
        self.assertIn(secret.encode(), self.client.get("/two-factor/setup").data)

        setup = self.client.post("/two-factor/setup", data={"code": pyotp.TOTP(secret).now()})

        self.assertEqual(setup.headers["Location"], "/dashboard")
        user = auth_module.get_user_by_id(user_id)
        self.assertEqual((user[3], user[5]), (1, 0))

    def test_new_account_enrolling_email_turns_email_on(self):
        user_id, _ = auth_module.create_user("mail@example.com", "password123")
        self._log_in_with_password("mail@example.com")

        with patch.object(auth_module, "send_otp_email") as mock_send:
            self.client.post("/two-factor/choose", data={"method": "email"})
            code = mock_send.call_args.args[1]
        verify = self.client.post("/two-factor/email", data={"code": code})

        self.assertEqual(verify.headers["Location"], "/dashboard")
        self.assertEqual(auth_module.get_user_by_id(user_id)[5], 1)

    def test_methods_not_enabled_are_disabled_on_choose_page(self):
        self._email_only_user("old@example.com")
        self._log_in_with_password("old@example.com")

        page = self.client.get("/two-factor/choose").data

        self.assertIn(b'value="email" class="method-choice">', page)
        self.assertIn(b'value="sms" class="method-choice" disabled', page)
        self.assertIn(b'value="authenticator" class="method-choice" disabled', page)

    def test_choosing_authenticator_that_is_not_enabled_is_rejected(self):
        self._email_only_user("auth@example.com")
        self._log_in_with_password("auth@example.com")

        response = self.client.post("/two-factor/choose", data={"method": "authenticator"})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"isn&#39;t set up for your account", response.data)

    def test_authenticator_cannot_be_enrolled_or_used_during_login_when_not_enabled(self):
        _, secret = self._email_only_user("auth@example.com")
        self._log_in_with_password("auth@example.com")

        setup_page = self.client.get("/two-factor/setup")
        setup_post = self.client.post("/two-factor/setup", data={"code": pyotp.TOTP(secret).now()})
        verify = self.client.post("/two-factor/verify", data={"code": pyotp.TOTP(secret).now()})

        for response in (setup_page, setup_post, verify):
            self.assertEqual(response.headers["Location"], "/two-factor/choose")
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

    def test_enabled_authenticator_requires_a_code(self):
        user_id, secret = auth_module.create_user("auth@example.com", "password123")
        auth_module.update_two_factor_setup(user_id, secret)
        self._log_in_with_password("auth@example.com")

        choose = self.client.post("/two-factor/choose", data={"method": "authenticator"})
        setup = self.client.get("/two-factor/setup")

        self.assertEqual(choose.headers["Location"], "/two-factor/verify")
        # Visiting the old setup URL must not sign the user in.
        self.assertEqual(setup.headers["Location"], "/two-factor/verify")
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

        verify = self.client.post("/two-factor/verify", data={"code": pyotp.TOTP(secret).now()})
        self.assertEqual(verify.headers["Location"], "/dashboard")

    def test_email_codes_are_refused_when_email_is_disabled(self):
        user_id, secret = auth_module.create_user("noemail@example.com", "password123")
        auth_module.update_two_factor_setup(user_id, secret)
        auth_module.set_email_2fa(user_id, False)
        self._log_in_with_password("noemail@example.com")

        with patch.object(auth_module, "start_email_otp") as send:
            choose = self.client.post("/two-factor/choose", data={"method": "email"})
            resend = self.client.get("/two-factor/email/resend")
            page = self.client.get("/two-factor/email")

        send.assert_not_called()
        self.assertIn(b"isn&#39;t set up for your account", choose.data)
        self.assertEqual(resend.headers["Location"], "/two-factor/choose")
        self.assertEqual(page.headers["Location"], "/two-factor/choose")

    def test_email_otp_flow_logs_user_in(self):
        auth_module.create_user("mailer@example.com", "password123")
        self.client.post(
            "/login",
            data={"email": "mailer@example.com", "password": "password123"},
        )

        with patch.object(auth_module, "send_otp_email") as mock_send:
            choose = self.client.post(
                "/two-factor/choose",
                data={"method": "email"},
                follow_redirects=False,
            )
            code = mock_send.call_args.args[1]

        self.assertEqual(choose.headers["Location"], "/two-factor/email")

        verify = self.client.post(
            "/two-factor/email",
            data={"code": code},
            follow_redirects=False,
        )
        self.assertEqual(verify.headers["Location"], "/dashboard")

    def test_email_otp_rejects_wrong_code(self):
        auth_module.create_user("wrong@example.com", "password123")
        self.client.post(
            "/login",
            data={"email": "wrong@example.com", "password": "password123"},
        )

        with patch.object(auth_module, "send_otp_email"):
            self.client.post("/two-factor/choose", data={"method": "email"})

        response = self.client.post(
            "/two-factor/email",
            data={"code": "000000"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Location", response.headers)


class SmsTwoFactorTests(unittest.TestCase):
    PHONE = "+14155552671"
    TWILIO_ENV_KEYS = (
        "TWILIO_ACCOUNT_SID",
        "TWILIO_VERIFY_SERVICE_SID",
        "TWILIO_API_KEY_SID",
        "TWILIO_API_KEY_SECRET",
        "TWILIO_AUTH_TOKEN",
    )

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        auth_module.configure_database(f"sqlite:///{self.temp_db.name}")
        auth_module.init_db()
        auth_module.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = auth_module.app.test_client()
        # Force the local (non-Twilio) code path regardless of the dev's .env.
        env = patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for key in self.TWILIO_ENV_KEYS:
            os.environ.pop(key, None)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def _capture_sms_code(self, fn):
        """Run fn and return the dev-fallback code it printed."""
        with patch("builtins.print") as mock_print:
            fn()
        return mock_print.call_args.args[0].rsplit(" ", 1)[-1]

    def _login_with_password(self, email):
        self.client.post("/login", data={"email": email, "password": "password123"})

    def _log_in_fully(self, email):
        with self.client.session_transaction() as sess:
            user = auth_module.get_user_by_email(email)
            sess["user_id"] = user[0]
            sess["email"] = user[1]

    def test_normalize_phone_number(self):
        self.assertEqual(auth_module.normalize_phone_number("+1 (415) 555-2671"), self.PHONE)
        self.assertIsNone(auth_module.normalize_phone_number("4155552671"))
        self.assertIsNone(auth_module.normalize_phone_number("+0123456789"))

    def test_new_account_can_enroll_sms(self):
        user_id, _ = auth_module.create_user("nophone@example.com", "password123")
        self._login_with_password("nophone@example.com")

        choose = self.client.post("/two-factor/choose", data={"method": "sms"})
        self.assertEqual(choose.headers["Location"], "/two-factor/sms")
        self.assertIn(b'name="phone"', self.client.get("/two-factor/sms").data)

        bad = self.client.post("/two-factor/sms", data={"step": "send", "phone": "12345"})
        self.assertIn(b"international format", bad.data)

        code = self._capture_sms_code(
            lambda: self.client.post("/two-factor/sms", data={"step": "send", "phone": "+1 415 555 2671"})
        )
        # Number isn't saved until the code is verified.
        self.assertIsNone(auth_module.get_user_by_id(user_id)[6])

        wrong = self.client.post("/two-factor/sms", data={"step": "verify", "code": "000000"})
        self.assertEqual(wrong.status_code, 200)
        self.assertIsNone(auth_module.get_user_by_id(user_id)[6])

        verify = self.client.post("/two-factor/sms", data={"step": "verify", "code": code})
        self.assertEqual(verify.headers["Location"], "/dashboard")

        user = auth_module.get_user_by_id(user_id)
        self.assertEqual((user[6], user[7], user[5]), (self.PHONE, 1, 0))

    def test_sms_cannot_be_enrolled_during_login_once_another_method_exists(self):
        user_id, _ = auth_module.create_user("nophone@example.com", "password123")
        auth_module.set_email_2fa(user_id, True)
        self._login_with_password("nophone@example.com")

        self.assertIn(b'value="sms" class="method-choice" disabled', self.client.get("/two-factor/choose").data)

        with patch.object(auth_module, "start_sms_otp") as send:
            choose = self.client.post("/two-factor/choose", data={"method": "sms"})
            page = self.client.get("/two-factor/sms")
            enroll = self.client.post("/two-factor/sms", data={"step": "send", "phone": "+1 415 555 2671"})
            resend = self.client.get("/two-factor/sms/resend")

        send.assert_not_called()
        self.assertIn(b"isn&#39;t set up for your account", choose.data)
        for response in (page, enroll, resend):
            self.assertEqual(response.headers["Location"], "/two-factor/choose")
        self.assertIsNone(auth_module.get_user_by_id(user_id)[6])

    def test_profile_enrollment_then_sms_login(self):
        user_id, _ = auth_module.create_user("sms@example.com", "password123")
        self._log_in_fully("sms@example.com")

        code = self._capture_sms_code(
            lambda: self.client.post("/profile/2fa/sms/setup", data={"step": "send", "phone": "+1 415 555 2671"})
        )
        verify = self.client.post("/profile/2fa/sms/setup", data={"step": "verify", "code": code})
        self.assertEqual(verify.headers["Location"], "/profile")

        user = auth_module.get_user_by_id(user_id)
        self.assertEqual(user[6], self.PHONE)
        self.assertEqual(user[7], 1)

        self.client.get("/logout")
        self._login_with_password("sms@example.com")
        self.assertIn(b'value="sms"', self.client.get("/two-factor/choose").data)

        code = self._capture_sms_code(
            lambda: self.client.post("/two-factor/choose", data={"method": "sms"})
        )
        response = self.client.post("/two-factor/sms", data={"code": code})
        self.assertEqual(response.headers["Location"], "/dashboard")

    def test_sms_login_rejects_wrong_code(self):
        user_id, _ = auth_module.create_user("wrongsms@example.com", "password123")
        auth_module.set_sms_2fa(user_id, self.PHONE)
        self._login_with_password("wrongsms@example.com")

        self._capture_sms_code(lambda: self.client.post("/two-factor/choose", data={"method": "sms"}))
        response = self.client.post("/two-factor/sms", data={"code": "000000"})

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Location", response.headers)

    def test_enrollment_rejects_invalid_phone(self):
        auth_module.create_user("badphone@example.com", "password123")
        self._log_in_fully("badphone@example.com")

        response = self.client.post("/profile/2fa/sms/setup", data={"step": "send", "phone": "12345"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"international format", response.data)

    def test_cannot_disable_last_method(self):
        user_id, _ = auth_module.create_user("last@example.com", "password123")
        auth_module.set_sms_2fa(user_id, self.PHONE)
        auth_module.set_email_2fa(user_id, False)
        self._log_in_fully("last@example.com")

        self.client.post("/profile/2fa/sms/disable")
        self.assertEqual(auth_module.get_user_by_id(user_id)[7], 1)

        # With SMS on, email can now be turned off and back on, and SMS off.
        auth_module.set_email_2fa(user_id, True)
        self.client.post("/profile/2fa/sms/disable")
        user = auth_module.get_user_by_id(user_id)
        self.assertEqual(user[7], 0)
        self.assertIsNone(user[6])

    def test_uses_twilio_verify_when_configured(self):
        user_id, _ = auth_module.create_user("twilio@example.com", "password123")
        auth_module.set_sms_2fa(user_id, self.PHONE)
        self._login_with_password("twilio@example.com")

        service = unittest.mock.MagicMock()
        service.verification_checks.create.return_value.status = "approved"
        with patch.object(auth_module, "_twilio_verify_service", return_value=service):
            self.client.post("/two-factor/choose", data={"method": "sms"})
            response = self.client.post("/two-factor/sms", data={"code": "123456"})

        service.verifications.create.assert_called_once_with(to=self.PHONE, channel="sms")
        service.verification_checks.create.assert_called_once_with(to=self.PHONE, code="123456")
        self.assertEqual(response.headers["Location"], "/dashboard")

    def test_twilio_client_credential_selection(self):
        os.environ["TWILIO_ACCOUNT_SID"] = "AC" + "0" * 32
        os.environ["TWILIO_VERIFY_SERVICE_SID"] = "VA" + "0" * 32

        with patch("twilio.rest.Client") as client:
            self.assertIsNone(auth_module._twilio_verify_service())

            os.environ["TWILIO_AUTH_TOKEN"] = "token"
            auth_module._twilio_verify_service()
            self.assertEqual(client.call_args.args, ("AC" + "0" * 32, "token"))

            os.environ["TWILIO_API_KEY_SID"] = "SK" + "0" * 32
            os.environ["TWILIO_API_KEY_SECRET"] = "secret"
            auth_module._twilio_verify_service()
            self.assertEqual(client.call_args.args, ("SK" + "0" * 32, "secret", "AC" + "0" * 32))
            # Calls to Twilio must not be able to hang a request thread.
            self.assertEqual(
                client.call_args.kwargs["http_client"].timeout, auth_module.NETWORK_TIMEOUT_SECONDS
            )

    def test_garbled_twilio_secret_shows_error_instead_of_crashing(self):
        os.environ["TWILIO_ACCOUNT_SID"] = "AC" + "0" * 32
        os.environ["TWILIO_VERIFY_SERVICE_SID"] = "VA" + "0" * 32
        os.environ["TWILIO_API_KEY_SID"] = "SK" + "0" * 32
        os.environ["TWILIO_API_KEY_SECRET"] = "abcdefghijąklmnop"

        user_id, _ = auth_module.create_user("garbled@example.com", "password123")
        auth_module.set_sms_2fa(user_id, self.PHONE)
        self._login_with_password("garbled@example.com")

        response = self.client.post("/two-factor/choose", data={"method": "sms"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"couldn&#39;t send a text", response.data)


class RateLimitAndDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        auth_module.configure_database(f"sqlite:///{self.temp_db.name}")
        auth_module.init_db()
        auth_module.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = auth_module.app.test_client()
        self.user_id, _ = auth_module.create_user("limit@example.com", "password123")
        auth_module.set_email_2fa(self.user_id, True)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def _login(self, password="password123", email="limit@example.com"):
        return self.client.post("/login", data={"email": email, "password": password})

    def test_password_guessing_on_one_account_is_limited(self):
        for _ in range(10):
            self.assertEqual(self._login(password="wrong").status_code, 200)

        blocked = self._login()  # even the right password, once over the limit

        self.assertEqual(blocked.status_code, 429)
        self.assertIn(b"Too many attempts", blocked.data)
        # Other accounts aren't affected by one account's limit.
        auth_module.create_user("other@example.com", "password123")
        self.assertEqual(self._login(email="other@example.com").status_code, 302)

    def test_code_guessing_is_limited(self):
        self._login()
        with patch.object(auth_module, "send_otp_email") as send:
            self.client.post("/two-factor/choose", data={"method": "email"})
            code = send.call_args.args[1]

        for _ in range(10):
            self.assertEqual(self.client.post("/two-factor/email", data={"code": "000000"}).status_code, 200)
        blocked = self.client.post("/two-factor/email", data={"code": code})

        self.assertEqual(blocked.status_code, 429)
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

    def test_code_sending_is_limited(self):
        self._login()
        with patch.object(auth_module, "send_otp_email") as send:
            self.client.post("/two-factor/choose", data={"method": "email"})
            for _ in range(4):
                self.client.get("/two-factor/email/resend")
            blocked = self.client.get("/two-factor/email/resend")

        self.assertEqual(send.call_count, 5)
        self.assertEqual(blocked.status_code, 429)

    def test_email_failure_shows_a_message_instead_of_crashing(self):
        self._login()
        with patch.object(
            auth_module, "send_otp_email", side_effect=auth_module.EmailDeliveryError("timed out")
        ):
            response = self.client.post("/two-factor/choose", data={"method": "email"})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"couldn&#39;t send an email", response.data)

    def test_smtp_timeout_becomes_delivery_error(self):
        env = {"SMTP_HOST": "smtp.example.com", "SMTP_PORT": "587"}
        with patch.dict(os.environ, env), patch.object(
            auth_module.smtplib, "SMTP", side_effect=TimeoutError("timed out")
        ) as smtp:
            with self.assertRaises(auth_module.EmailDeliveryError):
                auth_module.send_otp_email("someone@example.com", "123456")

        self.assertEqual(smtp.call_args.kwargs["timeout"], auth_module.NETWORK_TIMEOUT_SECONDS)

    def test_limiter_fails_open_when_the_database_errors(self):
        with patch.object(
            auth_module, "_increment_counter", side_effect=auth_module.SQLAlchemyError("down")
        ):
            self.assertFalse(auth_module.hit_rate_limit("test", "x", 0, 60))


class ErrorHandlingTests(unittest.TestCase):
    XHR = {"X-Requested-With": "XMLHttpRequest"}

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        auth_module.configure_database(f"sqlite:///{self.temp_db.name}")
        auth_module.init_db()
        auth_module.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = auth_module.app.test_client()
        upload_dir = tempfile.TemporaryDirectory()
        self.addCleanup(upload_dir.cleanup)
        upload_patch = patch.object(auth_module, "UPLOAD_DIR", upload_dir.name)
        upload_patch.start()
        self.addCleanup(upload_patch.stop)
        self.user_id, _ = auth_module.create_user("errors@example.com", "password123")
        auth_module.set_email_2fa(self.user_id, True)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def _sign_in(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user_id
            sess["email"] = "errors@example.com"

    def _upload(self, headers=None, name="a.txt"):
        return self.client.post(
            "/files/upload",
            data={"files": (io.BytesIO(b"hello world"), name)},
            content_type="multipart/form-data",
            headers=headers or {},
        )

    # --- app-wide handlers ---

    def test_unknown_page_shows_friendly_404(self):
        response = self.client.get("/no-such-page")
        self.assertEqual(response.status_code, 404)
        self.assertIn(b"Page not found", response.data)

    def test_wrong_method_shows_friendly_405(self):
        self._sign_in()
        response = self.client.get("/profile/change-password")
        self.assertEqual(response.status_code, 405)
        self.assertIn(b"isn&#39;t available here", response.data)

    def test_database_failure_shows_503_page(self):
        failure = auth_module.SQLAlchemyError("database is locked")
        with patch.object(auth_module, "get_user_by_email", side_effect=failure):
            response = self.client.post("/login", data={"email": "errors@example.com", "password": "x"})

        self.assertEqual(response.status_code, 503)
        self.assertIn(b"trouble reaching our database", response.data)

    def test_unexpected_exception_shows_friendly_500_page(self):
        self._sign_in()
        with patch.dict(auth_module.app.config, {"PROPAGATE_EXCEPTIONS": False}), patch.object(
            auth_module, "list_uploaded_files", side_effect=RuntimeError("boom")
        ):
            response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 500)
        self.assertIn(b"Something went wrong", response.data)
        self.assertNotIn(b"boom", response.data)

    # --- uploads ---

    def test_too_large_upload_returns_json_for_the_upload_script(self):
        self._sign_in()
        with patch.dict(auth_module.app.config, {"MAX_CONTENT_LENGTH": 10}):
            response = self._upload(headers=self.XHR)

        self.assertEqual(response.status_code, 413)
        self.assertIn("limited to", response.get_json()["error"])

    def test_too_large_upload_from_plain_form_redirects_with_message(self):
        self._sign_in()
        with patch.dict(auth_module.app.config, {"MAX_CONTENT_LENGTH": 10}):
            response = self._upload()

        self.assertEqual(response.headers["Location"], "/files/upload")
        with self.client.session_transaction() as sess:
            self.assertIn("limited to", sess["_flashes"][0][1])

    def test_disk_full_during_upload_is_reported_and_leaves_no_partial_file(self):
        self._sign_in()
        disk_full = OSError(28, "No space left on device")
        with patch("werkzeug.datastructures.FileStorage.save", side_effect=disk_full):
            response = self._upload(headers=self.XHR)

        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["failed"], ["a.txt"])
        self.assertIn("out of space", data["error"])
        self.assertEqual(os.listdir(auth_module.user_upload_dir(self.user_id)), [])

    def test_upload_script_gets_401_when_session_has_expired(self):
        response = self._upload(headers=self.XHR)
        self.assertEqual(response.status_code, 401)
        self.assertIn("session has expired", response.get_json()["error"])

    def test_file_vanishing_while_listing_is_skipped(self):
        with patch.object(auth_module.os.path, "isfile", return_value=True), patch.object(
            auth_module.os, "stat", side_effect=FileNotFoundError()
        ), patch.object(auth_module.os, "listdir", return_value=["gone.txt"]):
            self.assertEqual(auth_module.list_uploaded_files("/anywhere"), [])

    # --- sessions and accounts ---

    def test_partial_session_is_sent_to_login_instead_of_crashing(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user_id  # no "email" key
        response = self.client.get("/dashboard")
        self.assertEqual(response.headers["Location"], "/login")

    def test_unreadable_password_hash_is_a_failed_login(self):
        with auth_module.engine.begin() as conn:
            conn.execute(auth_module.update(auth_module.users).values(password="sha256$abc$def"))

        response = self.client.post("/login", data={"email": "errors@example.com", "password": "x"})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid email or password", response.data)

    def test_invalid_email_is_rejected_at_registration(self):
        for email in ("not-an-email", "a@b.com\nBcc: c@d.com", "x" * 250 + "@example.com"):
            response = self.client.post("/register", data={"email": email, "password": "password123"})
            self.assertIn(b"valid email address", response.data)
        self.assertIsNone(auth_module.get_user_by_email("not-an-email"))

    def test_account_without_secret_can_set_up_authenticator_from_profile(self):
        with auth_module.engine.begin() as conn:
            conn.execute(auth_module.update(auth_module.users).values(two_factor_secret=None))
        self._sign_in()

        self.client.get("/profile/2fa/authenticator/setup")
        secret = auth_module.get_user_by_id(self.user_id)[4]
        self.assertTrue(secret)  # saved, so the next request uses the same one
        response = self.client.post(
            "/profile/2fa/authenticator/setup", data={"code": pyotp.TOTP(secret).now()}
        )

        self.assertEqual(response.headers["Location"], "/profile")
        self.assertEqual(auth_module.get_user_by_id(self.user_id)[3], 1)

    # --- outside services ---

    def test_twilio_network_errors_show_a_message(self):
        import requests

        auth_module.set_sms_2fa(self.user_id, "+14155552671")
        self.client.post("/login", data={"email": "errors@example.com", "password": "password123"})
        service = unittest.mock.MagicMock()
        service.verifications.create.side_effect = requests.ConnectionError("unreachable")
        service.verification_checks.create.side_effect = requests.Timeout("slow")

        with patch.object(auth_module, "_twilio_verify_service", return_value=service):
            choose = self.client.post("/two-factor/choose", data={"method": "sms"})
            with auth_module.app.test_request_context():
                self.assertFalse(auth_module.verify_sms_otp("+14155552671", "123456"))

        self.assertEqual(choose.status_code, 200)
        self.assertIn(b"couldn&#39;t send a text", choose.data)

    def test_bad_smtp_port_setting_falls_back_to_587(self):
        env = {"SMTP_HOST": "smtp.example.com", "SMTP_PORT": "not-a-number"}
        with patch.dict(os.environ, env), patch.object(auth_module.smtplib, "SMTP") as smtp:
            auth_module.send_otp_email("someone@example.com", "123456")

        self.assertEqual(smtp.call_args.args, ("smtp.example.com", 587))

    def test_newline_in_address_becomes_delivery_error(self):
        with patch.dict(os.environ, {"SMTP_HOST": "smtp.example.com"}), patch.object(auth_module.smtplib, "SMTP"):
            with self.assertRaises(auth_module.EmailDeliveryError):
                auth_module.send_otp_email("a@b.com\nBcc: c@d.com", "123456")


class MemeTests(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        auth_module.configure_database(f"sqlite:///{self.temp_db.name}")
        auth_module.init_db()
        auth_module.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = auth_module.app.test_client()
        env = patch.dict(os.environ, {"MEMES_ENABLED": "1"})
        env.start()
        self.addCleanup(env.stop)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def _url(self, key):
        return memes.meme_url(key).replace("&", "&amp;").encode()

    def test_every_rule_and_status_points_at_a_real_meme(self):
        for _, _, key in memes.RULES:
            self.assertIn(key, memes.MEMES)
        for key in list(memes.STATUS_MEMES.values()) + list(memes.DEFAULT_FOR_KIND.values()):
            self.assertIn(key, memes.MEMES)

    def test_messages_map_to_their_memes(self):
        cases = [
            ("Invalid email or password", "error", "wrong_login"),
            ("Invalid or expired code. Please try again.", "error", "wrong_code"),
            ("Invalid code. Please try again.", "error", "wrong_authenticator_code"),
            ("We couldn't send a text message right now.", "error", "send_failed"),
            ("New password and confirmation do not match.", "error", "password_mismatch"),
            ("Something nobody planned for", "error", "generic_error"),
            ("Password updated successfully.", "success", "password_updated"),
            ("SMS verification disabled and phone number removed.", "success", "method_disabled"),
            ("Email verification enabled.", "success", "method_enabled"),
        ]
        for message, kind, key in cases:
            self.assertEqual(memes.meme_for(message, kind)["url"], memes.meme_url(key), message)

    def test_every_message_in_the_app_has_its_own_meme(self):
        """Scans app.py for messages shown to users, so a new message without
        a matching meme rule fails here instead of falling back silently."""
        import re

        source = open(os.path.join(os.path.dirname(auth_module.__file__), "app.py")).read()
        messages = {(m, "error") for m in re.findall(r'error\s*=\s*"([^"]+)"', source)}
        messages |= set(re.findall(r'flash\(\s*f?"([^"]+)",\s*"(error|success)"', source))
        self.assertGreater(len(messages), 25)
        generic = {memes.meme_url("generic_error"), memes.meme_url("generic_success")}
        for message, kind in messages:
            self.assertNotIn(memes.meme_for(message, kind)["url"], generic, message)

    def test_captions_are_escaped_for_memegen(self):
        self.assertEqual(memes._escape_line("Why? 50% off_now - #1/2"), "Why~q_50~p_off__now_--_~h1~s2")
        self.assertEqual(memes._escape_line(""), "_")

    def test_wrong_password_shows_a_meme(self):
        auth_module.create_user("meme@example.com", "password123")
        response = self.client.post("/login", data={"email": "meme@example.com", "password": "nope"})
        self.assertIn(self._url("wrong_login"), response.data)
        self.assertIn(b"referrerpolicy=\"no-referrer\"", response.data)

    def test_flash_messages_in_the_app_show_memes(self):
        user_id, _ = auth_module.create_user("meme@example.com", "password123")
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["email"] = "meme@example.com"
        response = self.client.post(
            "/profile/change-password",
            data={"current_password": "password123", "new_password": "newpassword1", "confirm_password": "newpassword1"},
            follow_redirects=True,
        )
        self.assertIn(self._url("password_updated"), response.data)

    def test_error_and_rate_limit_pages_show_memes(self):
        self.assertIn(self._url("not_found"), self.client.get("/no-such-page").data)
        with patch.object(auth_module, "hit_rate_limit", return_value=True):
            limited = self.client.post("/login", data={"email": "x@example.com", "password": "x"})
        self.assertIn(self._url("rate_limited"), limited.data)

    def test_json_errors_include_a_meme(self):
        response = self.client.post("/files/upload", headers={"X-Requested-With": "XMLHttpRequest"})
        self.assertEqual(response.get_json()["meme"]["url"], memes.meme_url("session_expired"))

    def test_memes_can_be_turned_off(self):
        auth_module.create_user("meme@example.com", "password123")
        with patch.dict(os.environ, {"MEMES_ENABLED": "0"}):
            response = self.client.post("/login", data={"email": "meme@example.com", "password": "nope"})
        self.assertIn(b"Invalid email or password", response.data)
        self.assertNotIn(b"memegen", response.data)


class ProfileMfaStatusTests(unittest.TestCase):
    PHONE = "+14155552671"

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        auth_module.configure_database(f"sqlite:///{self.temp_db.name}")
        auth_module.init_db()
        auth_module.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = auth_module.app.test_client()
        upload_dir = tempfile.TemporaryDirectory()
        self.addCleanup(upload_dir.cleanup)
        upload_patch = patch.object(auth_module, "UPLOAD_DIR", upload_dir.name)
        upload_patch.start()
        self.addCleanup(upload_patch.stop)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def _user_with(self, email=False, sms=False, authenticator=False):
        user_id, secret = auth_module.create_user(f"u{email}{sms}{authenticator}@example.com", "password123")
        if email:
            auth_module.set_email_2fa(user_id, True)
        if sms:
            auth_module.set_sms_2fa(user_id, self.PHONE)
        if authenticator:
            auth_module.update_two_factor_setup(user_id, secret)
        return user_id

    def _profile_badge(self, user_id):
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["email"] = "someone@example.com"
        return self.client.get("/profile").data

    def test_status_for_every_combination(self):
        cases = [
            ({"email": True, "sms": True, "authenticator": True}, "MFA fully setup", "badge-mfa-full"),
            ({"email": True, "sms": True}, "MFA not set for authenticator app", "badge-mfa-partial"),
            ({"email": True, "authenticator": True}, "MFA not set for mobile number", "badge-mfa-partial"),
            ({"sms": True, "authenticator": True}, "MFA not set for email", "badge-mfa-partial"),
            ({"email": True}, "MFA set for only email", "badge-mfa-single"),
            ({"sms": True}, "MFA set for only mobile number", "badge-mfa-single"),
            ({"authenticator": True}, "MFA set for only authenticator app", "badge-mfa-single"),
            ({}, "MFA not set", "badge-mfa-none"),
        ]
        for methods, label, badge in cases:
            user = auth_module.get_user_by_id(self._user_with(**methods))
            self.assertEqual(auth_module.mfa_status(user), (label, badge), methods)

    def test_profile_header_shows_the_status(self):
        user_id = self._user_with(email=True)
        page = self._profile_badge(user_id)
        self.assertIn(b'<span class="badge badge-mfa-single">MFA set for only email</span>', page)

    def test_missing_user_counts_as_not_set(self):
        self.assertEqual(auth_module.mfa_status(None), ("MFA not set", "badge-mfa-none"))


class PasswordResetTests(unittest.TestCase):
    PHONE = "+14155552671"

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        auth_module.configure_database(f"sqlite:///{self.temp_db.name}")
        auth_module.init_db()
        auth_module.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = auth_module.app.test_client()
        env = patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for key in SmsTwoFactorTests.TWILIO_ENV_KEYS:
            os.environ.pop(key, None)
        self.user_id, self.secret = auth_module.create_user("forgot@example.com", "oldpassword")

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def _start(self, email="forgot@example.com"):
        return self.client.post("/forgot-password", data={"email": email})

    def _set_new_password(self, password="newpassword1", confirm=None):
        return self.client.post(
            "/forgot-password/new",
            data={"new_password": password, "confirm_password": confirm or password},
        )

    def _can_log_in(self, password):
        client = auth_module.app.test_client()
        response = client.post("/login", data={"email": "forgot@example.com", "password": password})
        return response.status_code == 302

    def test_forgot_password_page_has_its_own_meme(self):
        meme = str(markupsafe.escape(memes.meme_url("forgot_password"))).encode()
        self.assertIn(meme, self.client.get("/forgot-password").data)
        # With an error showing, only the error's meme appears.
        bad = self.client.post("/forgot-password", data={"email": "not-an-email"}).data
        self.assertNotIn(meme, bad)
        self.assertIn(str(markupsafe.escape(memes.meme_url("invalid_email"))).encode(), bad)

    def test_sign_in_page_links_to_forgot_password(self):
        self.assertIn(b'href="/forgot-password"', self.client.get("/login").data)

    def test_full_reset_by_email_then_sign_in_again(self):
        auth_module.set_email_2fa(self.user_id, True)
        self.assertEqual(self._start().headers["Location"], "/forgot-password/verify")

        page = self.client.get("/forgot-password/verify").data
        self.assertIn(b'value="email" class="method-choice">', page)
        self.assertIn(b'value="sms" class="method-choice" disabled', page)

        with patch.object(auth_module, "send_otp_email") as send:
            choose = self.client.post("/forgot-password/verify", data={"method": "email"})
            code = send.call_args.args[1]
        self.assertEqual(choose.headers["Location"], "/forgot-password/code")

        verify = self.client.post("/forgot-password/code", data={"code": code})
        self.assertEqual(verify.headers["Location"], "/forgot-password/new")

        done = self._set_new_password()
        self.assertEqual(done.headers["Location"], "/login")
        login_page = self.client.get("/login").data
        self.assertIn(b"Password changed", login_page)
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
            self.assertNotIn("reset_user_id", sess)

        self.assertTrue(self._can_log_in("newpassword1"))
        self.assertFalse(self._can_log_in("oldpassword"))

    def test_reset_with_authenticator(self):
        auth_module.update_two_factor_setup(self.user_id, self.secret)
        self._start()
        self.client.post("/forgot-password/verify", data={"method": "authenticator"})

        verify = self.client.post("/forgot-password/code", data={"code": pyotp.TOTP(self.secret).now()})

        self.assertEqual(verify.headers["Location"], "/forgot-password/new")

    def test_reset_with_sms(self):
        auth_module.set_sms_2fa(self.user_id, self.PHONE)
        self._start()
        with patch("builtins.print") as printed:
            self.client.post("/forgot-password/verify", data={"method": "sms"})
        code = printed.call_args.args[0].rsplit(" ", 1)[-1]

        verify = self.client.post("/forgot-password/code", data={"code": code})

        self.assertEqual(verify.headers["Location"], "/forgot-password/new")

    def test_methods_not_enabled_are_rejected(self):
        auth_module.set_email_2fa(self.user_id, True)
        self._start()
        response = self.client.post("/forgot-password/verify", data={"method": "authenticator"})
        self.assertIn(b"isn&#39;t set up for your account", response.data)

    def test_account_with_no_methods_can_verify_by_email(self):
        self._start()
        page = self.client.get("/forgot-password/verify").data
        self.assertIn(b'value="email" class="method-choice">', page)

    def test_unknown_email_looks_the_same_but_never_verifies(self):
        self.assertEqual(self._start("nobody@example.com").headers["Location"], "/forgot-password/verify")
        page = self.client.get("/forgot-password/verify").data
        self.assertIn(b'value="email" class="method-choice">', page)

        with patch.object(auth_module, "send_otp_email") as send:
            choose = self.client.post("/forgot-password/verify", data={"method": "email"})
        send.assert_not_called()
        self.assertEqual(choose.headers["Location"], "/forgot-password/code")

        verify = self.client.post("/forgot-password/code", data={"code": "123456"})
        self.assertIn(b"Invalid or expired code", verify.data)
        self.assertEqual(self._set_new_password().headers["Location"], "/forgot-password")

    def test_cannot_skip_verification(self):
        auth_module.set_email_2fa(self.user_id, True)
        self._start()
        self.assertEqual(self._set_new_password().headers["Location"], "/forgot-password")
        self.assertTrue(self._can_log_in("oldpassword"))

    def test_verification_expires(self):
        auth_module.update_two_factor_setup(self.user_id, self.secret)
        self._start()
        self.client.post("/forgot-password/verify", data={"method": "authenticator"})
        self.client.post("/forgot-password/code", data={"code": pyotp.TOTP(self.secret).now()})
        with self.client.session_transaction() as sess:
            sess["reset_verified_until"] = 0

        self.assertEqual(self._set_new_password().headers["Location"], "/forgot-password")
        self.assertTrue(self._can_log_in("oldpassword"))

    def _verified_by_authenticator(self):
        auth_module.update_two_factor_setup(self.user_id, self.secret)
        self._start()
        self.client.post("/forgot-password/verify", data={"method": "authenticator"})
        self.client.post("/forgot-password/code", data={"code": pyotp.TOTP(self.secret).now()})

    def test_missing_method_choice_asks_to_choose(self):
        self._start()
        response = self.client.post("/forgot-password/verify", data={})
        self.assertIn(b"Please choose a verification method", response.data)

    def test_method_switched_off_mid_reset_no_longer_verifies(self):
        auth_module.update_two_factor_setup(self.user_id, self.secret)
        auth_module.set_email_2fa(self.user_id, True)
        self._start()
        self.client.post("/forgot-password/verify", data={"method": "authenticator"})
        auth_module.disable_authenticator(self.user_id)
        old_secret_code = pyotp.TOTP(self.secret).now()

        response = self.client.post("/forgot-password/code", data={"code": old_secret_code})

        self.assertIn(b"Invalid code", response.data)

    def test_account_deleted_mid_reset_is_reported(self):
        self._verified_by_authenticator()
        with auth_module.engine.begin() as conn:
            conn.execute(auth_module.users.delete())

        response = self._set_new_password()

        self.assertEqual(response.headers["Location"], "/forgot-password")
        page = self.client.get("/forgot-password").data
        self.assertIn(b"couldn&#39;t find that account", page)
        self.assertIn(memes.meme_url("not_found").replace("&", "&amp;").encode(), page)

    def test_send_failures_show_a_message_and_meme(self):
        import requests

        auth_module.set_email_2fa(self.user_id, True)
        auth_module.set_sms_2fa(self.user_id, self.PHONE)
        self._start()
        with patch.object(auth_module, "send_otp_email", side_effect=auth_module.EmailDeliveryError("down")):
            email = self.client.post("/forgot-password/verify", data={"method": "email"})
        service = unittest.mock.MagicMock()
        service.verifications.create.side_effect = requests.ConnectionError("unreachable")
        with patch.object(auth_module, "_twilio_verify_service", return_value=service):
            sms = self.client.post("/forgot-password/verify", data={"method": "sms"})

        self.assertIn(b"couldn&#39;t send an email", email.data)
        self.assertIn(b"couldn&#39;t send a text", sms.data)
        self.assertIn(memes.meme_url("send_failed").replace("&", "&amp;").encode(), sms.data)

    def test_database_failure_during_reset_shows_503(self):
        with patch.object(auth_module, "get_user_by_email", side_effect=auth_module.SQLAlchemyError("down")):
            response = self._start()
        self.assertEqual(response.status_code, 503)

    def test_expired_verification_shows_its_meme(self):
        self._verified_by_authenticator()
        with self.client.session_transaction() as sess:
            sess["reset_verified_until"] = 0
        page = self.client.get("/forgot-password/new", follow_redirects=True).data
        self.assertIn(b"verification has expired", page)
        self.assertIn(memes.meme_url("reset_expired").replace("&", "&amp;").encode(), page)

    def test_new_password_is_validated(self):
        auth_module.update_two_factor_setup(self.user_id, self.secret)
        self._start()
        self.client.post("/forgot-password/verify", data={"method": "authenticator"})
        self.client.post("/forgot-password/code", data={"code": pyotp.TOTP(self.secret).now()})

        self.assertIn(b"at least 8 characters", self._set_new_password("short").data)
        self.assertIn(b"do not match", self._set_new_password("longenough1", "different1").data)
        self.assertTrue(self._can_log_in("oldpassword"))


class PerUserFileTests(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        auth_module.configure_database(f"sqlite:///{self.temp_db.name}")
        auth_module.init_db()
        auth_module.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = auth_module.app.test_client()
        # Keep test uploads out of the real upload folder.
        upload_dir = tempfile.TemporaryDirectory()
        self.addCleanup(upload_dir.cleanup)
        upload_patch = patch.object(auth_module, "UPLOAD_DIR", upload_dir.name)
        upload_patch.start()
        self.addCleanup(upload_patch.stop)
        self.upload_root = upload_dir.name

        self.alice_id, _ = auth_module.create_user("alice@example.com", "password123")
        self.bob_id, _ = auth_module.create_user("bob@example.com", "password123")

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def _log_in_as(self, user_id, email):
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["email"] = email

    def _upload(self, name, content=b"hello"):
        return self.client.post(
            "/files/upload",
            data={"files": (io.BytesIO(content), name)},
            content_type="multipart/form-data",
        )

    def test_upload_goes_into_the_users_own_folder(self):
        self._log_in_as(self.alice_id, "alice@example.com")
        self._upload("notes.txt")

        self.assertTrue(
            os.path.isfile(os.path.join(self.upload_root, str(self.alice_id), "notes.txt"))
        )
        self.assertFalse(os.path.exists(os.path.join(self.upload_root, "notes.txt")))

    def test_user_can_download_their_own_file(self):
        self._log_in_as(self.alice_id, "alice@example.com")
        self._upload("notes.txt", b"alice's notes")

        response = self.client.get("/files/download/notes.txt")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"alice's notes")

    def test_other_users_files_are_not_listed_or_downloadable(self):
        self._log_in_as(self.alice_id, "alice@example.com")
        self._upload("secret.txt")

        self._log_in_as(self.bob_id, "bob@example.com")
        listing = self.client.get("/files/download")
        download = self.client.get("/files/download/secret.txt")

        self.assertNotIn(b"secret.txt", listing.data)
        self.assertEqual(download.status_code, 302)

    def test_path_traversal_into_another_users_folder_is_rejected(self):
        self._log_in_as(self.alice_id, "alice@example.com")
        self._upload("secret.txt")

        self._log_in_as(self.bob_id, "bob@example.com")
        response = self.client.get(f"/files/download/../{self.alice_id}/secret.txt")

        self.assertNotEqual(response.status_code, 200)

    def test_same_filename_for_two_users_does_not_collide(self):
        self._log_in_as(self.alice_id, "alice@example.com")
        self._upload("report.txt", b"alice")
        self._log_in_as(self.bob_id, "bob@example.com")
        self._upload("report.txt", b"bob")

        self.assertEqual(self.client.get("/files/download/report.txt").data, b"bob")
        self._log_in_as(self.alice_id, "alice@example.com")
        self.assertEqual(self.client.get("/files/download/report.txt").data, b"alice")


if __name__ == "__main__":
    unittest.main()
