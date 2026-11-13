"""Local behavior checks; these tests never contact an SNMP device."""

import http.client
import re
import threading
import unittest
from urllib.parse import urlencode

from pysnmp.proto import errind
from pysnmp.proto.rfc1905 import NoSuchInstance

from app import Outcome, ProbeServer, classify_reply


class ReplyClassificationTests(unittest.TestCase):
    def test_timeout_is_inconclusive(self):
        outcome = classify_reply(errind.requestTimedOut, 0, 0, [])
        self.assertEqual(outcome.kind, "inconclusive")
        self.assertIn("this computer", outcome.title)

    def test_wrong_digest_is_not_reported_as_success(self):
        outcome = classify_reply(errind.wrongDigest, 0, 0, [])
        self.assertEqual(outcome.kind, "failure")
        self.assertIn("authentication", outcome.title)

    def test_missing_oid_is_an_authenticated_reply(self):
        outcome = classify_reply(None, 0, 0, [(None, NoSuchInstance())])
        self.assertEqual(outcome.kind, "response")
        self.assertIn("unavailable", outcome.detail)


class BrowserFormTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def fake_runner(profile, auth_password, priv_password):
            self.calls.append((profile, auth_password, priv_password))
            return Outcome("success", "Authenticated read succeeded", "sysUpTime.0 = 42")

        self.server = ProbeServer(runner=fake_runner)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=5
        )
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def csrf(self):
        status, headers, page = self.request("GET", self.server.session_path)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store, no-cache, must-revalidate")
        return re.search(r'name="csrf" value="([^"]+)"', page).group(1)

    def post(self, csrf, *, headers=None, **changes):
        fields = {
            "csrf": csrf,
            "device": "192.0.2.10",
            "port": "161",
            "username": "example-user",
            "timeout": "5",
            "auth_protocol": "SHA256",
            "priv_protocol": "CISCO_AES256",
            "auth_password": "example-auth",
            "priv_password": "example-priv",
        }
        fields.update(changes)
        request_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        request_headers.update(headers or {})
        return self.request(
            "POST",
            self.server.session_path + "/probe",
            body=urlencode(fields),
            headers=request_headers,
        )

    def test_repeated_reads_keep_passwords_out_of_result_page(self):
        csrf = self.csrf()
        for _ in range(2):
            status, headers, _ = self.post(csrf)
            self.assertEqual(status, 303)
            self.assertEqual(headers["Location"], self.server.session_path)
            status, _, page = self.request("GET", self.server.session_path)
            self.assertEqual(status, 200)
            self.assertIn("Authenticated read succeeded", page)
            self.assertIn('value="example-user"', page)
            self.assertNotIn("example-auth", page)
            self.assertNotIn("example-priv", page)
        self.assertEqual(len(self.calls), 2)

    def test_cross_origin_and_foreign_host_are_rejected(self):
        csrf = self.csrf()
        status, _, _ = self.post(csrf, headers={"Origin": "https://example.net"})
        self.assertEqual(status, 403)
        status, _, _ = self.post(csrf, headers={"Host": "example.net"})
        self.assertEqual(status, 403)
        self.assertEqual(self.calls, [])

    def test_invalid_token_and_duplicate_fields_are_rejected(self):
        self.csrf()
        status, _, _ = self.post("wrong-token")
        self.assertEqual(status, 400)
        self.assertEqual(self.calls, [])
        body = (
            "csrf=" + self.server.csrf_token + "&device=192.0.2.10&device=192.0.2.11"
            "&port=161&username=example-user&timeout=5&auth_protocol=SHA256"
            "&priv_protocol=CISCO_AES256&auth_password=example-auth"
            "&priv_password=example-priv"
        )
        status, _, _ = self.request(
            "POST",
            self.server.session_path + "/probe",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
