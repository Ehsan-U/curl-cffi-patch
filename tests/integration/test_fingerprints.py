import pytest

from curl_cffi import requests

JA3_URL = "https://tls.browserleaks.com/json"
PEET_URL = "https://tls.peet.ws/api/all"
# Copied from my browser on macOS
CHROME_JA3_HASH = "53ff64ddf993ca882b70e1c82af5da49"
# Edge 101 is the same as Chrome 101
EDGE_JA3_HASH = "53ff64ddf993ca882b70e1c82af5da49"
# Same as safari 16.x
SAFARI_JA3_HASH = "8468a1ef6cb71b13e1eef8eadf786f7d"
OKHTTP50A2_JA3_HASH = "f87c133faa73000b308cb1a1328b4ac0"
OKHTTP50A2_JA4 = "t13d1613h2_46e7e9700bed_40271e0a5736"
OKHTTP50A2_PEETPRINT_HASH = "0ca0dcff01d340b1f8fc09d0dcaa533f"
OKHTTP_AKAMAI = "4:16777216|16711681|0|m,p,a,s"
OKHTTP_ANDROID11_JA3_HASH = "1d714db2228763eab228fc28ce7f8e4f"
OKHTTP_ANDROID11_JA4 = "t13d1513h2_8daaf6152771_40271e0a5736"
OKHTTP_ANDROID11_PEETPRINT_HASH = "fd69d4edcd69c9ff33c9452042930e32"


def test_not_impersonate():
    r = requests.get(JA3_URL)
    assert r.json()["ja3_hash"] != CHROME_JA3_HASH


def test_impersonate():
    r = requests.get(JA3_URL, impersonate="chrome101")
    assert r.json()["ja3_hash"] == CHROME_JA3_HASH


def test_impersonate_edge():
    r = requests.get(JA3_URL, impersonate="edge101")
    assert r.json()["ja3_hash"] == EDGE_JA3_HASH


def test_impersonate_safari():
    r = requests.get(JA3_URL, impersonate="safari15_5")
    assert r.json()["ja3_hash"] == SAFARI_JA3_HASH


def test_impersonate_okhttp50a2():
    data = requests.get(PEET_URL, impersonate="okhttp50a2").json()

    assert data["tls"]["ja3_hash"] == OKHTTP50A2_JA3_HASH
    assert data["tls"]["ja4"] == OKHTTP50A2_JA4
    assert data["tls"]["peetprint_hash"] == OKHTTP50A2_PEETPRINT_HASH
    assert data["http2"]["akamai_fingerprint"] == OKHTTP_AKAMAI
    assert data["http2"]["sent_frames"][-1]["headers"] == [":method: GET", ":path: /api/all", ":authority: tls.peet.ws", ":scheme: https", "accept-encoding: gzip", "user-agent: okhttp/5.0.0-alpha2"]  # noqa: E501


def test_impersonate_okhttp51_android11():
    data = requests.get(PEET_URL, impersonate="okhttp51_android11").json()

    assert data["tls"]["ja3_hash"] == OKHTTP_ANDROID11_JA3_HASH
    assert data["tls"]["ja4"] == OKHTTP_ANDROID11_JA4
    assert data["tls"]["peetprint_hash"] == OKHTTP_ANDROID11_PEETPRINT_HASH
    assert data["http2"]["akamai_fingerprint"] == OKHTTP_AKAMAI
    assert data["http2"]["sent_frames"][-1]["headers"] == [":method: GET", ":path: /api/all", ":authority: tls.peet.ws", ":scheme: https", "accept-encoding: gzip", "user-agent: okhttp/5.1.0"]  # noqa: E501


def test_impersonate_okhttp_alias_uses_okhttp54_android11():
    data = requests.get(PEET_URL, impersonate="okhttp").json()

    assert data["tls"]["ja3_hash"] == OKHTTP_ANDROID11_JA3_HASH
    assert data["tls"]["ja4"] == OKHTTP_ANDROID11_JA4
    assert data["tls"]["peetprint_hash"] == OKHTTP_ANDROID11_PEETPRINT_HASH
    assert data["http2"]["akamai_fingerprint"] == OKHTTP_AKAMAI
    assert data["http2"]["sent_frames"][-1]["headers"] == [":method: GET", ":path: /api/all", ":authority: tls.peet.ws", ":scheme: https", "accept-encoding: gzip", "user-agent: okhttp/5.4.0"]  # noqa: E501


def test_impersonate_unknown():
    with pytest.raises(requests.RequestsError, match="not supported"):
        requests.get(JA3_URL, impersonate="unknown")
