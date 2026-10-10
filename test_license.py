"""test_license.py — unit tests for the offline license system."""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import license as L  # noqa: E402

PASS = 0
FAIL = 0


def t(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name}")


# isolated secret for tests (temp dir, never the real one)
tmpdir = tempfile.mkdtemp()
L.SECRET_PATH = os.path.join(tmpdir, ".license_secret")
L.LICENSE_PATH = os.path.join(tmpdir, "license")

# --- generate & verify round-trip
key = L.generate_key("Faisal", "faisal@example.com", tier="pro", exp=None)
t("key has 3 parts", len(key.split("-")) == 3)
t("key prefixed AL1", key.startswith("AL1-"))
payload = L.verify_key(key)
t("round-trip name", payload["name"] == "Faisal")
t("round-trip tier", payload["tier"] == "pro")

# --- tamper: flip a byte in payload
parts = key.split("-")
bad = parts[0] + "-" + (parts[1][:-2] + "XX") + "-" + parts[2]
try:
    L.verify_key(bad)
    t("tampered payload rejected", False)
except ValueError as e:
    t("tampered payload rejected", "signature" in str(e) or "corrupt" in str(e))

# --- tamper: wrong signature
bad = parts[0] + "-" + parts[1] + "-" + ("0" * 32)
try:
    L.verify_key(bad)
    t("forged signature rejected", False)
except ValueError as e:
    t("forged signature rejected", "signature" in str(e))

# --- expiry: past → invalid
exp_past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
key_exp = L.generate_key("A", "a@b.c", exp=exp_past)
try:
    L.verify_key(key_exp)
    t("expired key rejected", False)
except ValueError as e:
    t("expired key rejected", "expired" in str(e))

# --- expiry: future → valid
exp_future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
key_ok = L.generate_key("A", "a@b.c", exp=exp_future)
t("future expiry valid", L.verify_key(key_ok)["exp"] == exp_future)

# --- malformed keys
for bad_key in ["", "garbage", "XX2-abc-def", "AL1-notbase64!-abc",
                "AL1-abc"]:
    try:
        L.verify_key(bad_key)
        t(f"malformed '{bad_key[:15]}' rejected", False)
    except ValueError:
        t(f"malformed '{bad_key[:15]}' rejected", True)

# --- missing payload fields
key_np = L.generate_key("", "a@b.c")
try:
    L.verify_key(key_np)
    t("missing name rejected", False)
except ValueError as e:
    t("missing name rejected", "name" in str(e))

# --- check_license: no file → None
try:
    os.remove(L.LICENSE_PATH)
except OSError:
    pass
t("no license file → None", L.check_license() is None)
t("enforcement not allowed", L.enforcement_allowed() is False)

# --- check_license: valid file → payload
with open(L.LICENSE_PATH, "w") as f:
    f.write(key)
got = L.check_license()
t("valid license file → payload", got and got["name"] == "Faisal")
t("enforcement allowed", L.enforcement_allowed() is True)

# --- check_license: expired file → None
with open(L.LICENSE_PATH, "w") as f:
    f.write(key_exp)
t("expired file → None", L.check_license() is None)
t("enforcement not allowed on expired", L.enforcement_allowed() is False)

# --- secret persistence: same secret across calls (deterministic keys)
k1 = L.generate_key("X", "x@y.z")
k2 = L.generate_key("X", "x@y.z")
t("deterministic keys (stable secret)", k1 == k2)

# --- secret file permissions
mode = os.stat(L.SECRET_PATH).st_mode & 0o777
t("secret is 0600", mode == 0o600)

print(f"\n{'='*40}")
print(f"PASS {PASS} / FAIL {FAIL}")
print("RESULT:", "PASS ✅" if FAIL == 0 else "FAIL ❌")
sys.exit(0 if FAIL == 0 else 1)
