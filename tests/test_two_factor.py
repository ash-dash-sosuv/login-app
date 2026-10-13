import io
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import app as auth_module


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

    def test_choosing_authenticator_goes_to_setup(self):
        auth_module.create_user("auth@example.com", "password123")
        self.client.post(
            "/login",
            data={"email": "auth@example.com", "password": "password123"},
        )

        response = self.client.post(
            "/two-factor/choose",
            data={"method": "authenticator"},
            follow_redirects=False,
        )

        self.assertEqual(response.headers["Location"], "/two-factor/setup")

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

    def test_sms_login_asks_for_number_when_none_enrolled(self):
        user_id, _ = auth_module.create_user("nophone@example.com", "password123")
        self._login_with_password("nophone@example.com")

        self.assertIn(b'value="sms"', self.client.get("/two-factor/choose").data)

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
        self.assertEqual(user[6], self.PHONE)
        self.assertEqual(user[7], 1)

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
            client.assert_called_with("AC" + "0" * 32, "token")

            os.environ["TWILIO_API_KEY_SID"] = "SK" + "0" * 32
            os.environ["TWILIO_API_KEY_SECRET"] = "secret"
            auth_module._twilio_verify_service()
            client.assert_called_with("SK" + "0" * 32, "secret", "AC" + "0" * 32)

    def test_garbled_twilio_secret_shows_error_instead_of_crashing(self):
        os.environ["TWILIO_ACCOUNT_SID"] = "AC" + "0" * 32
        os.environ["TWILIO_VERIFY_SERVICE_SID"] = "VA" + "0" * 32
        os.environ["TWILIO_API_KEY_SID"] = "SK" + "0" * 32
        os.environ["TWILIO_API_KEY_SECRET"] = "abcdefghijąklmnop"

        auth_module.create_user("garbled@example.com", "password123")
        self._login_with_password("garbled@example.com")
        self.client.post("/two-factor/choose", data={"method": "sms"})

        response = self.client.post("/two-factor/sms", data={"step": "send", "phone": self.PHONE})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"couldn&#39;t send a text", response.data)


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
