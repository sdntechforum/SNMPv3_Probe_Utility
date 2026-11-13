"""Local behavior checks; these tests never contact an SNMP device."""

import asyncio
import http.client
import re
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from pysnmp.proto import errind
from pysnmp.proto.rfc1902 import ObjectIdentifier, OctetString
from pysnmp.proto.rfc1905 import NoSuchInstance, NoSuchObject

from app import Outcome, ProbeServer, Profile, ReadValue, _snmp_get, classify_reply

UPTIME_OID = "1.3.6.1.2.1.1.3.0"
DESCR_OID = "1.3.6.1.2.1.1.1.0"
OBJECT_OID = "1.3.6.1.2.1.1.2.0"
ENGINE_OID = "1.3.6.1.6.3.10.2.1.1.0"


def binding(oid, value):
    return ObjectIdentifier(oid), value


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
        outcome = classify_reply(None, 0, 0, [binding(UPTIME_OID, NoSuchInstance())])
        self.assertEqual(outcome.kind, "response")
        self.assertIn("unavailable", outcome.detail)

    def test_basic_profile_reports_each_value_and_hex_engine_id(self):
        outcome = classify_reply(
            None,
            0,
            0,
            [
                binding(UPTIME_OID, OctetString("12345")),
                binding(DESCR_OID, OctetString("Example switch")),
                binding(OBJECT_OID, ObjectIdentifier("1.3.6.1.4.1.9.1.1")),
                binding(ENGINE_OID, OctetString(hexValue="800000000102030405")),
            ],
            "BASIC",
        )
        self.assertEqual(outcome.kind, "success")
        self.assertEqual(len(outcome.readings), 4)
        self.assertEqual(outcome.readings[3].name, "snmpEngineID.0")
        self.assertEqual(outcome.readings[3].value, "0x800000000102030405")

    def test_basic_profile_keeps_unavailable_objects_separate(self):
        outcome = classify_reply(
            None,
            0,
            0,
            [
                binding(UPTIME_OID, OctetString("12345")),
                binding(DESCR_OID, NoSuchObject()),
                binding(OBJECT_OID, ObjectIdentifier("1.3.6.1.4.1.9.1.1")),
                binding(ENGINE_OID, NoSuchInstance()),
            ],
            "BASIC",
        )
        self.assertEqual(outcome.kind, "response")
        self.assertEqual(
            [item.status for item in outcome.readings],
            ["value", "unavailable", "value", "unavailable"],
        )

    def test_short_reply_and_error_status_are_not_full_success(self):
        short = classify_reply(None, 0, 0, [binding(UPTIME_OID, OctetString("12345"))], "BASIC")
        self.assertEqual(short.kind, "inconclusive")
        self.assertIn("Expected 4", short.detail)

        error = classify_reply(None, OctetString("noAccess"), 3, [], "BASIC")
        self.assertEqual(error.kind, "response")
        self.assertIn("sysObjectID.0", error.detail)

    def test_mismatched_returned_oid_is_inconclusive(self):
        outcome = classify_reply(
            None,
            0,
            0,
            [
                binding(UPTIME_OID, OctetString("12345")),
                binding(OBJECT_OID, OctetString("wrong object")),
                binding(DESCR_OID, OctetString("wrong object")),
                binding(ENGINE_OID, OctetString(hexValue="800000000102030405")),
            ],
            "BASIC",
        )
        self.assertEqual(outcome.kind, "inconclusive")
        self.assertEqual(outcome.readings, ())

    def test_protocol_failure_takes_precedence_over_returned_values(self):
        outcome = classify_reply(
            errind.wrongDigest,
            0,
            0,
            [binding(UPTIME_OID, OctetString("untrusted"))],
            "BASIC",
        )
        self.assertEqual(outcome.kind, "failure")
        self.assertEqual(outcome.readings, ())

    def test_long_value_is_capped(self):
        outcome = classify_reply(None, 0, 0, [binding(UPTIME_OID, OctetString("x" * 500))])
        self.assertEqual(len(outcome.readings[0].value), 301)
        self.assertTrue(outcome.readings[0].value.endswith("…"))


class RequestConstructionTests(unittest.TestCase):
    def test_profiles_send_one_get_with_exact_fixed_oids(self):
        calls = []

        async def fake_target(*args, **kwargs):
            return object()

        async def fake_get(*args, **kwargs):
            calls.append((args[4:], kwargs))
            return None, 0, 0, []

        with (
            patch("app.SnmpEngine") as engine_class,
            patch("app.UdpTransportTarget.create", new=fake_target),
            patch("app.ObjectIdentity", side_effect=lambda oid: oid),
            patch("app.ObjectType", side_effect=lambda oid: oid),
            patch("app.get_cmd", new=fake_get),
        ):
            for name in ("UPTIME", "BASIC"):
                asyncio.run(
                    _snmp_get(
                        Profile(device="192.0.2.10", username="example-user", read_profile=name),
                        "example-auth",
                        "example-priv",
                    )
                )
            self.assertEqual(engine_class.return_value.close_dispatcher.call_count, 2)

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], ("1.3.6.1.2.1.1.3.0",))
        self.assertEqual(
            calls[1][0],
            (
                "1.3.6.1.2.1.1.3.0",
                "1.3.6.1.2.1.1.1.0",
                "1.3.6.1.2.1.1.2.0",
                "1.3.6.1.6.3.10.2.1.1.0",
            ),
        )
        self.assertTrue(all(options["lookupMib"] is False for _, options in calls))


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
        self.assertEqual(headers["Referrer-Policy"], "same-origin")
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
            "read_profile": "UPTIME",
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

    def test_basic_profile_is_selected_and_retained(self):
        csrf = self.csrf()
        status, _, _ = self.post(csrf, read_profile="BASIC")
        self.assertEqual(status, 303)
        self.assertEqual(self.calls[-1][0].read_profile, "BASIC")
        status, _, page = self.request("GET", self.server.session_path)
        self.assertEqual(status, 200)
        self.assertIn('value="BASIC" selected', page)

    def test_read_values_are_escaped_in_html(self):
        self.server.last_outcome = Outcome(
            "success",
            "Authenticated read succeeded",
            "Received all 1 requested values.",
            (ReadValue("sysDescr.0", "1.3.6.1.2.1.1.1.0", "value", "<script>alert(1)</script>"),),
        )
        status, _, page = self.request("GET", self.server.session_path)
        self.assertEqual(status, 200)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<script>alert(1)</script>", page)

    def test_cross_origin_and_foreign_host_are_rejected(self):
        csrf = self.csrf()
        status, _, _ = self.post(csrf, headers={"Origin": "https://example.net"})
        self.assertEqual(status, 403)
        status, _, _ = self.post(csrf, headers={"Host": "example.net"})
        self.assertEqual(status, 403)
        self.assertEqual(self.calls, [])

    def test_same_origin_form_post_is_accepted(self):
        csrf = self.csrf()
        origin = f"http://127.0.0.1:{self.server.server_port}"
        status, _, _ = self.post(csrf, headers={"Origin": origin}, read_profile="BASIC")
        self.assertEqual(status, 303)
        self.assertEqual(self.calls[-1][0].read_profile, "BASIC")

    def test_invalid_token_and_duplicate_fields_are_rejected(self):
        self.csrf()
        status, _, _ = self.post("wrong-token")
        self.assertEqual(status, 400)
        self.assertEqual(self.calls, [])
        body = (
            "csrf=" + self.server.csrf_token + "&device=192.0.2.10&device=192.0.2.11"
            "&port=161&username=example-user&timeout=5&auth_protocol=SHA256"
            "&priv_protocol=CISCO_AES256&read_profile=UPTIME&auth_password=example-auth"
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

    def test_unknown_profile_is_rejected(self):
        csrf = self.csrf()
        status, _, _ = self.post(csrf, read_profile="CUSTOM")
        self.assertEqual(status, 400)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
