#!/usr/bin/env python3
"""Local browser form for repeatable, read-only SNMPv3 credential checks."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import re
import secrets
from urllib.parse import parse_qs
import webbrowser

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_HMAC192_SHA256,
    USM_PRIV_CFB128_AES,
    USM_PRIV_CFB256_AES,
    USM_PRIV_CFB256_AES_BLUMENTHAL,
    get_cmd,
)
from pysnmp.proto import errind
from pysnmp.proto.rfc1905 import NoSuchInstance, NoSuchObject


UPTIME_OID = "1.3.6.1.2.1.1.3.0"
MAX_BODY = 8192
AUTH_PROTOCOLS = {
    "SHA256": ("SHA256", USM_AUTH_HMAC192_SHA256),
    "SHA1": ("SHA1", USM_AUTH_HMAC96_SHA),
}
PRIV_PROTOCOLS = {
    "CISCO_AES256": ("AES256 (Cisco/Reeder)", USM_PRIV_CFB256_AES),
    "AES128": ("AES128", USM_PRIV_CFB128_AES),
    "BLUMENTHAL_AES256": ("AES256 (Blumenthal)", USM_PRIV_CFB256_AES_BLUMENTHAL),
}


@dataclass(frozen=True)
class Profile:
    device: str = ""
    port: int = 161
    username: str = ""
    auth_protocol: str = "SHA256"
    priv_protocol: str = "CISCO_AES256"
    timeout: int = 5


@dataclass(frozen=True)
class Outcome:
    kind: str
    title: str
    detail: str


def _valid_device(device: str) -> bool:
    if not device or len(device) > 253 or device != device.strip():
        return False
    try:
        ipaddress.IPv4Address(device)
        return True
    except ValueError:
        pass
    if all(character.isdigit() or character == "." for character in device):
        return False
    labels = device.rstrip(".").split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


def parse_submission(body: bytes, csrf_token: str) -> tuple[Profile, str, str]:
    try:
        fields = parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=9,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("The submitted form could not be read.") from exc

    def one(name: str) -> str:
        values = fields.get(name, [])
        if len(values) != 1:
            raise ValueError("The submitted form is incomplete or ambiguous.")
        return values[0]

    if not secrets.compare_digest(one("csrf"), csrf_token):
        raise ValueError("The page session expired. Reload the page and try again.")
    device = one("device")
    if not _valid_device(device):
        raise ValueError("Enter an IPv4 address or a valid DNS hostname.")
    username = one("username")
    if (
        not 1 <= len(username) <= 64
        or username != username.strip()
        or not all(character.isprintable() for character in username)
    ):
        raise ValueError("Enter a printable SNMPv3 username, up to 64 characters.")
    try:
        port = int(one("port"))
        timeout = int(one("timeout"))
    except ValueError as exc:
        raise ValueError("Port and timeout must be whole numbers.") from exc
    if not 1 <= port <= 65535 or not 1 <= timeout <= 15:
        raise ValueError("Port must be 1–65535 and timeout must be 1–15 seconds.")
    auth_protocol = one("auth_protocol")
    priv_protocol = one("priv_protocol")
    if auth_protocol not in AUTH_PROTOCOLS or priv_protocol not in PRIV_PROTOCOLS:
        raise ValueError("Select a supported authentication and privacy protocol.")
    auth_password = one("auth_password")
    priv_password = one("priv_password")
    if not all(8 <= len(value.encode("utf-8")) <= 255 for value in (auth_password, priv_password)):
        raise ValueError("Each passphrase must be 8–255 bytes.")
    return (
        Profile(device, port, username, auth_protocol, priv_protocol, timeout),
        auth_password,
        priv_password,
    )


async def _snmp_get(profile: Profile, auth_password: str, priv_password: str):
    engine = SnmpEngine()

    async def exchange():
        target = await UdpTransportTarget.create(
            (profile.device, profile.port), timeout=profile.timeout, retries=0
        )
        return await get_cmd(
            engine,
            UsmUserData(
                profile.username,
                authKey=auth_password,
                privKey=priv_password,
                authProtocol=AUTH_PROTOCOLS[profile.auth_protocol][1],
                privProtocol=PRIV_PROTOCOLS[profile.priv_protocol][1],
            ),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(UPTIME_OID)),
            lookupMib=False,
        )

    try:
        return await asyncio.wait_for(
            exchange(),
            timeout=profile.timeout * 3 + 5,
        )
    finally:
        engine.close_dispatcher()


def classify_reply(indication, status, index, bindings) -> Outcome:
    if isinstance(indication, errind.RequestTimedOut):
        return Outcome(
            "inconclusive",
            "No response from this computer",
            "The timeout does not prove the credentials are wrong. Check this computer's route, "
            "UDP port 161, source ACLs, and the device's SNMP settings.",
        )
    if isinstance(indication, errind.WrongDigest):
        return Outcome(
            "failure",
            "SNMPv3 authentication rejected",
            "The device reported WrongDigest. Check the username, authentication "
            "passphrase, authentication protocol, and device-side user state.",
        )
    if isinstance(indication, errind.UnknownUserName):
        return Outcome(
            "failure",
            "SNMPv3 username not accepted",
            "The device reported UnknownUserName. Check the username and the device's SNMPv3 users.",
        )
    if isinstance(indication, errind.DecryptionError):
        return Outcome(
            "failure",
            "SNMPv3 privacy check failed",
            "The device reported DecryptionError. Check the privacy passphrase and protocol.",
        )
    if isinstance(indication, (errind.NotInTimeWindow, errind.UnknownEngineID)):
        return Outcome(
            "inconclusive",
            "SNMPv3 engine synchronization failed",
            "Check the device's engine ID and time state, then retry.",
        )
    if indication:
        return Outcome(
            "failure",
            "SNMPv3 request failed",
            "PySNMP reported " + type(indication).__name__ + ".",
        )
    if status:
        return Outcome(
            "response",
            "Authenticated SNMP reply received",
            "The device returned SNMP error status "
            + status.prettyPrint()
            + " at index "
            + str(int(index))
            + ".",
        )
    if not bindings:
        return Outcome(
            "inconclusive",
            "No requested value returned",
            "The SNMP exchange completed without a value for sysUpTime.0.",
        )
    value = bindings[0][1]
    if isinstance(value, (NoSuchObject, NoSuchInstance)):
        return Outcome(
            "response",
            "Authenticated SNMP reply received",
            "The device replied, but sysUpTime.0 is unavailable in this SNMP view.",
        )
    return Outcome(
        "success",
        "Authenticated read succeeded",
        "sysUpTime.0 = " + value.prettyPrint()[:300],
    )


def run_probe(profile: Profile, auth_password: str, priv_password: str) -> Outcome:
    try:
        return classify_reply(
            *asyncio.run(_snmp_get(profile, auth_password, priv_password))
        )
    except (TimeoutError, asyncio.TimeoutError):
        return Outcome(
            "inconclusive",
            "No response from this computer",
            "The local probe timed out. Check the route, UDP port, source ACLs, "
            "and device settings before judging the credentials.",
        )
    except Exception as exc:
        return Outcome(
            "failure",
            "Local probe error",
            "The probe could not complete (" + type(exc).__name__ + ").",
        )


class ProbeServer(HTTPServer):
    def __init__(self, runner=run_probe):
        super().__init__(("127.0.0.1", 0), ProbeHandler)
        self.session_path = "/" + secrets.token_urlsafe(18)
        self.csrf_token = secrets.token_urlsafe(32)
        self.last_profile = Profile()
        self.last_outcome: Outcome | None = None
        self.runner = runner

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}{self.session_path}"


class ProbeHandler(BaseHTTPRequestHandler):
    server: ProbeServer

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, *args):
        pass  # Do not write requests or form data to access logs.

    def _host_ok(self) -> bool:
        return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

    def _send_html(self, code: int, body: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(data)

    def _render_page(self, outcome: Outcome | None = None) -> str:
        profile = self.server.last_profile
        result = ""
        if outcome:
            result = (
                f'<section class="result {escape(outcome.kind)}" role="status">'
                f"<h2>{escape(outcome.title)}</h2><p>{escape(outcome.detail)}</p></section>"
            )

        def options(choices, selected):
            return "".join(
                f'<option value="{escape(key)}"'
                + (" selected" if key == selected else "")
                + f">{escape(label)}</option>"
                for key, (label, _) in choices.items()
            )

        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local SNMPv3 read test</title>
<style>
body {{ font: 16px system-ui, sans-serif; color: #18212e; background: #f4f7fb;
  max-width: 52rem; margin: 2rem auto; padding: 0 1rem; }}
main {{ background: white; padding: 1.5rem; border-radius: 12px;
  box-shadow: 0 2px 14px #1c355014; }}
h1 {{ margin-top: 0; }} h2 {{ font-size: 1.1rem; }}
.grid {{ display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 0 1rem; }}
label {{ display: block; margin: .9rem 0; font-weight: 600; }}
input, select {{ display: block; width: 100%; box-sizing: border-box; margin-top: .3rem;
  padding: .65rem; font: inherit; border: 1px solid #9aa8b7; border-radius: 6px; }}
button {{ padding: .72rem 1.2rem; border: 0; border-radius: 6px;
  color: white; background: #1257a6; font: inherit; cursor: pointer; }}
small, .hint {{ color: #425466; }} .result {{ padding: .8rem 1rem; border-radius: 6px;
  margin: 1rem 0; background: #eaf3ff; }}
.result.success, .result.response {{ background: #e4f5e9; }}
.result.failure {{ background: #fde8e7; }}
.result.inconclusive {{ background: #fff2d8; }}
@media (max-width: 640px) {{ .grid {{ grid-template-columns: 1fr; }} }}
</style></head><body><main>
<h1>SNMPv3 credential read test</h1>
<p class="hint">Runs one read-only GET for sysUpTime.0 from this computer. It does not
change the device. A timeout is inconclusive because this computer may have different
network access than your management system.</p>
{result}
<form method="post" action="{self.server.session_path}/probe" autocomplete="off">
<input type="hidden" name="csrf" value="{self.server.csrf_token}">
<div class="grid">
<label>Device IPv4 address or hostname
<input name="device" value="{escape(profile.device, quote=True)}" required autofocus
  spellcheck="false" autocomplete="off"></label>
<label>UDP port
<input name="port" type="number" min="1" max="65535" value="{profile.port}" required></label>
<label>SNMPv3 username
<input name="username" value="{escape(profile.username, quote=True)}" required
  spellcheck="false" autocomplete="off"></label>
<label>Timeout (seconds)
<input name="timeout" type="number" min="1" max="15" value="{profile.timeout}" required></label>
<label>Authentication protocol
<select name="auth_protocol">{options(AUTH_PROTOCOLS, profile.auth_protocol)}</select></label>
<label>Privacy protocol
<select name="priv_protocol">{options(PRIV_PROTOCOLS, profile.priv_protocol)}</select></label>
<label>Authentication passphrase
<input name="auth_password" type="password" minlength="8" required autocomplete="off"></label>
<label>Privacy passphrase
<input name="priv_password" type="password" minlength="8" required autocomplete="off"></label>
</div>
<button type="submit">Run read test</button>
</form>
<p><small>Passphrases are used in this process for the test and are not intentionally
saved to files or printed. Keep this Terminal window open while using the form;
press Control-C there to stop the local server.</small></p>
</main></body></html>"""

    def do_GET(self):
        if not self._host_ok():
            self._send_html(403, "Request rejected.")
        elif self.path != self.server.session_path:
            self._send_html(404, "Not found.")
        else:
            self._send_html(200, self._render_page(self.server.last_outcome))

    def do_POST(self):
        if not self._host_ok() or self.path != self.server.session_path + "/probe":
            self._send_html(403, "Request rejected.")
            return
        origin = self.headers.get("Origin")
        if origin and origin != f"http://127.0.0.1:{self.server.server_port}":
            self._send_html(403, "Request rejected.")
            return
        if (
            self.headers.get("Transfer-Encoding")
            or self.headers.get("Content-Type", "").split(";", 1)[0].lower()
            != "application/x-www-form-urlencoded"
        ):
            self._send_html(415, "Unsupported request.")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 1 <= length <= MAX_BODY:
            self._send_html(400, "Invalid request size.")
            return
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("The form was incomplete.")
            profile, auth_password, priv_password = parse_submission(
                body, self.server.csrf_token
            )
        except (ValueError, TimeoutError) as exc:
            self._send_html(
                400,
                self._render_page(
                    Outcome("failure", "Form not submitted", str(exc))
                ),
            )
            return
        self.server.last_profile = profile
        try:
            self.server.last_outcome = self.server.runner(
                profile, auth_password, priv_password
            )
        except Exception as exc:
            self.server.last_outcome = Outcome(
                "failure",
                "Local probe error",
                "The probe could not complete (" + type(exc).__name__ + ").",
            )
        finally:
            auth_password = None
            priv_password = None
            body = None
        self.send_response(303)
        self.send_header("Location", self.server.session_path)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-browser", action="store_true", help="print the local URL without opening it"
    )
    args = parser.parse_args()
    server = ProbeServer()
    print("Local SNMPv3 read test: " + server.url, flush=True)
    print("Press Control-C to stop. No device changes are made.", flush=True)
    try:
        if not args.no_browser:
            webbrowser.open(server.url, new=2)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
