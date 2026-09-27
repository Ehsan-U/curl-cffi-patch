import json
import re
from contextlib import closing
from pathlib import Path

import pytest

from curl_cffi import Curl, CurlError, CurlMime, CurlOpt, get_fingerprint, requests


CAPTURE = json.loads((Path(__file__).parents[1] / "fixtures/firefox156_win_capabilities.json").read_text())  # noqa: E501


@pytest.mark.parametrize("http_version,protocol", [("v2", "h2"), ("v3only", "h3")])
def test_firefox_windows_cookies_multipart_and_reuse(browser_echo, http_version, protocol):  # noqa: E501
    url, certificate = browser_echo
    expected = CAPTURE[protocol]
    with requests.Session(impersonate="firefox156_win", http_version=http_version, verify=certificate, cookies={"alpha": "one", "beta": "two", "gamma": "three"}) as session:  # noqa: E501
        response = session.get(url + "/cookies", timeout=5).json()
        assert response["protocol"] == protocol
        cookies = [value for key, value in response["headers"] if key == "cookie"]
        assert len(cookies) == len(expected["cookie_fields"])
        assert sorted("; ".join(cookies).split("; ")) == sorted("; ".join(expected["cookie_fields"]).split("; "))  # noqa: E501
        names = [key for key, _ in response["headers"]]
        assert names.index("accept-encoding") < names.index("cookie") < names.index("upgrade-insecure-requests")  # noqa: E501
        if protocol == "h3":
            assert "te" not in names
            assert dict(response["headers"])["alt-used"] == url.removeprefix("https://")  # noqa: E501
            assert response["quic_version"] == 0x6B3343CF
        else:
            assert dict(response["headers"])["te"] == "trailers"
            assert "alt-used" not in names
        boundaries = []
        for _ in range(2):
            with closing(CurlMime()) as multipart:
                multipart.addpart(name="field", data="value")
                multipart.addpart(name="upload", content_type="text/plain", filename="sample.txt", data=b"fingerprint-test\n")  # noqa: E501
                upload = session.post(url + "/multipart", multipart=multipart, timeout=5).json()  # noqa: E501
            boundary = dict(upload["headers"])["content-type"].split("boundary=", 1)[1]  # noqa: E501
            assert re.fullmatch(re.escape(expected["boundary_prefix"]) + r"[0-9a-f]{32}", boundary)  # noqa: E501
            assert upload["body"].replace(boundary, "<BOUNDARY>") == expected["multipart_body_template"]  # noqa: E501
            assert upload["connection"] == response["connection"]
            boundaries.append(boundary)
        assert boundaries[0] != boundaries[1]


@pytest.mark.parametrize("connection", range(2))
def test_firefox_windows_http3_matches_capture(connection):
    expected = CAPTURE["http3_fingerprint"]
    data = requests.get("https://fp.impersonate.pro/api/http3", impersonate="firefox156_win", http_version="v3only", timeout=30).json()  # noqa: E501
    assert data["protocol"] == "http3"
    assert 1 <= data["quic"]["initial_packet_number"] <= 1024
    assert data["quic"]["client_connection_id_length"] == 3
    assert data["tls"]["ja3n"] == expected["ja3n"]
    assert data["http3"]["settings"] == expected["settings"]
    assert data["http3"]["headers"] == expected["headers"]
    extensions = {item["id"]: item["data"] for item in data["tls"]["extensions"]}
    assert [item["id"] for item in data["tls"]["extensions"]][-2:] == [57, 65037]
    for identifier, value in expected["extensions"].items():
        assert extensions[int(identifier)] == value
    assert extensions[65037]["payload"]["length"] == expected["ech_grease_payload_size"]  # noqa: E501
    parameters = [{"id": item["id"], "value": "AUTO" if item["id"] == 15 else item["value"]} for item in extensions[57]]  # noqa: E501
    assert parameters == expected["transport_parameters"]
    # 0xff02de1a is min_ack_delay, despite this endpoint labeling it GREASE.
    assert next(item["value"] for item in parameters if item["id"] == 0xFF02DE1A) == "0x43e8"  # noqa: E501


@pytest.mark.parametrize("http_version", ["v2", "v3only"])
def test_firefox_explicit_cookie_and_alt_used_remain_caller_controlled(browser_echo, http_version):  # noqa: E501
    url, certificate = browser_echo
    data = requests.get(url, impersonate="firefox156_win", http_version=http_version, verify=certificate, headers={"Cookie": "alpha=one; beta=two", "Alt-Used": "example.test:443"}, timeout=5).json()  # noqa: E501
    assert [value for key, value in data["headers"] if key == "cookie"] == ["alpha=one; beta=two"]  # noqa: E501
    assert [value for key, value in data["headers"] if key == "alt-used"] == ["example.test:443"]  # noqa: E501


def test_legacy_firefox_multipart_mode_is_unchanged(browser_echo):
    url, certificate = browser_echo
    fingerprint = get_fingerprint("firefox156_win")
    fingerprint.form_boundary = "firefox"
    with closing(CurlMime()) as multipart:
        multipart.addpart(name="field", data="value")
        data = requests.post(url, impersonate=fingerprint, http_version="v2", verify=certificate, multipart=multipart, timeout=5).json()  # noqa: E501
    assert re.fullmatch(r"multipart/form-data; boundary=------geckoformboundary[0-9a-f]{32}", dict(data["headers"])["content-type"])  # noqa: E501


@pytest.mark.parametrize("option,value", [(CurlOpt.HTTP3_SPLIT_COOKIES, -2), (CurlOpt.HTTP3_SPLIT_COOKIES, 2), (CurlOpt.HTTP3_TLS_ECH_GREASE_PAYLOAD_SIZE, -1), (CurlOpt.HTTP3_TLS_ECH_GREASE_PAYLOAD_SIZE, 15), (CurlOpt.HTTP3_TLS_ECH_GREASE_PAYLOAD_SIZE, 65494)])  # noqa: E501
def test_firefox_http3_controls_reject_invalid_values(option, value):
    with closing(Curl()) as curl, pytest.raises(CurlError) as error:
        curl.setopt(option, value)
    assert error.value.code == 43


@pytest.mark.parametrize("order", ["SHUFFLE:99:0-57", "SHUFFLE:3:0-57", "SHUFFLE:2", "SHUFFLE:2:0-0"])  # noqa: E501
def test_invalid_shuffled_extension_order_is_rejected(browser_echo, order):
    url, certificate = browser_echo
    fingerprint = get_fingerprint("firefox156_win")
    fingerprint.http3_tls_extension_order = order
    with pytest.raises(CurlError) as error:
        requests.get(url, impersonate=fingerprint, http_version="v3only", verify=certificate, timeout=5)  # noqa: E501
    assert error.value.code == 35
