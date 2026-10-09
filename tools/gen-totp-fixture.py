#!/usr/bin/env python3
"""Creates core/tests/fixtures/totp-entries.kdbx with keepassxc-cli.

One entry per way KeePassXC stores TOTP settings, with made-up secrets
(the RFC 6238 seeds and the Key URI format example). Entry CustomData
makes KeePassXC write KDBX 4.0. The password is the one of the other
fixtures.

Usage: tools/gen-totp-fixture.py
"""

import base64
import pathlib
import subprocess
import tempfile
from xml.sax.saxutils import escape

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = ROOT / "core/tests/fixtures/totp-entries.kdbx"
PASSWORD = "sailvault-fixture"
DECRYPTION_TIME_MS = "100"
TIMESTAMP = "2026-01-01T10:00:00Z"
PROTECTED = ' ProtectInMemory="True"'

EXAMPLE = "JBSWY3DPEHPK3PXP"
SEED_SHA1 = base64.b32encode(b"12345678901234567890").decode()
SEED_SHA256 = base64.b32encode(b"12345678901234567890123456789012").decode().rstrip("=")
SEED_SHA512 = base64.b32encode(b"1234567890" * 6 + b"1234").decode()

ENTRIES = [
    ("SHA-1 six digits", "alice@example.org", {
        "otp": f"otpauth://totp/Example:alice%40example.org?secret={EXAMPLE}"
               "&period=30&digits=6&issuer=Example"}),
    ("SHA-256 eight digits", "bob", {
        "otp": f"otpauth://totp/Example:bob?secret={SEED_SHA256}&period=30&digits=8"
               "&issuer=Example&algorithm=SHA256"}),
    ("SHA-512 sixty seconds", "carol", {
        "otp": f"otpauth://totp/Example:carol?secret={SEED_SHA512.replace('=', '%3D')}"
               "&period=60&digits=6&issuer=Example&algorithm=SHA512"}),
    ("Nine digits", "dave", {
        "otp": f"otpauth://totp/Example:dave?secret={SEED_SHA1}&period=30&digits=9"}),
    ("Steam", "gamer", {
        "otp": f"otpauth://totp/Steam:gamer?secret={SEED_SHA1}&period=30&digits=5"
               "&issuer=Steam&encoder=steam"}),
    ("Lenient secret", "erin", {
        "otp": "otpauth://totp/Example:erin?secret=jbsw%20y3dp%20ehpk%203pxp"}),
    ("Legacy settings", "frank", {
        "TOTP Seed": SEED_SHA1, "TOTP Settings": "45;8"}),
    ("Legacy Steam", "grace", {
        "TOTP Seed": SEED_SHA1, "TOTP Settings": "30;S"}),
    ("KeeOtp", "heidi", {
        "otp": f"key={SEED_SHA1}&size=7&step=40&otpHashMode=SHA256"}),
    ("KeePass 2", "ivan", {
        "TimeOtp-Secret-Base32": SEED_SHA1, "TimeOtp-Algorithm": "HMAC-SHA-512",
        "TimeOtp-Length": "8", "TimeOtp-Period": "20"}),
    ("Counter based", "judy", {
        "otp": f"otpauth://hotp/Example:judy?secret={EXAMPLE}&counter=0"}),
    ("No code", "mallory", {}),
]


def entry_xml(index, title, user_name, attributes):
    uuid = base64.b64encode(bytes([index + 1]) * 16).decode()
    strings = [("Title", title, False), ("UserName", user_name, False), ("Password", "", True)]
    strings += [(key, value, key in ("otp", "TOTP Seed", "TimeOtp-Secret-Base32"))
                for key, value in attributes.items()]
    fields = "".join(
        f"<String><Key>{escape(key)}</Key>"
        f"<Value{PROTECTED if protected else ''}>{escape(value)}</Value></String>"
        for key, value, protected in strings)
    return (f"<Entry><UUID>{uuid}</UUID><Times><LastModificationTime>{TIMESTAMP}"
            f"</LastModificationTime><CreationTime>{TIMESTAMP}</CreationTime></Times>{fields}"
            "<CustomData><Item><Key>SailTokenFixture</Key><Value>totp</Value></Item>"
            "</CustomData></Entry>")


def content():
    entries = "".join(entry_xml(i, *entry) for i, entry in enumerate(ENTRIES))
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            "<KeePassFile><Meta><Generator>SailToken TOTP fixture</Generator>"
            "<DatabaseName>SailToken TOTP fixture</DatabaseName></Meta><Root><Group>"
            "<UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Name>Root</Name>"
            f"{entries}</Group></Root></KeePassFile>")


def main():
    with tempfile.TemporaryDirectory() as work:
        xml = pathlib.Path(work) / "content.xml"
        xml.write_text(content(), encoding="utf-8")
        TARGET.unlink(missing_ok=True)
        subprocess.run(
            ["keepassxc-cli", "import", "-q", "-p", "-t", DECRYPTION_TIME_MS, str(xml), str(TARGET)],
            input=f"{PASSWORD}\n{PASSWORD}\n", text=True, check=True)
    version = TARGET.read_bytes()[8:12][::-1].hex()
    if version != "00040000":
        raise SystemExit(f"{TARGET.name}: expected KDBX 4.0, got {version}")
    print(subprocess.run(["keepassxc-cli", "--version"], capture_output=True, text=True).stdout.strip())


if __name__ == "__main__":
    main()
