import json
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

    def test_send_otp_email_uses_brevo_http_api_when_key_set(self):
        captured = {}

        class FakeResponse:
            def read(self):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(request_obj, timeout=None):
            captured["url"] = request_obj.full_url
            captured["api_key"] = request_obj.get_header("Api-key")
            captured["body"] = json.loads(request_obj.data.decode("utf-8"))
            return FakeResponse()

        env = {"BREVO_API_KEY": "test-key", "SMTP_FROM": "sender@example.com"}
        with patch.dict(os.environ, env), patch("urllib.request.urlopen", fake_urlopen):
            auth_module.send_otp_email("recipient@example.com", "123456")

        self.assertEqual(captured["url"], "https://api.brevo.com/v3/smtp/email")
        self.assertEqual(captured["api_key"], "test-key")
        self.assertEqual(captured["body"]["to"][0]["email"], "recipient@example.com")
        self.assertEqual(captured["body"]["sender"]["email"], "sender@example.com")

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


if __name__ == "__main__":
    unittest.main()
