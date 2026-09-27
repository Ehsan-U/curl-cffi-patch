import json
import re
from contextlib import closing
from pathlib import Path

import pytest
from aioquic.buffer import Buffer

from curl_cffi import Curl, CurlError, CurlMime, CurlOpt, get_fingerprint, requests


CAPTURE = json.loads((Path(__file__).parents[1] / "fixtures/chrome153_win_capabilities.json").read_text())  # noqa: E501


@pytest.mark.parametrize("http_version,protocol", [("v2", "h2"), ("v3only", "h3")])
def test_chrome_windows_cookies_multipart_and_reuse(browser_echo, http_version, protocol):  # noqa: E501
    url, certificate = browser_echo
    expected = CAPTURE[protocol]
    with requests.Session(impersonate="chrome153_win", http_version=http_version, verify=certificate, cookies={"alpha": "one", "beta": "two", "gamma": "three"}) as session:  # noqa: E501
        response = session.get(url + "/cookies", timeout=5).json()
        assert response["protocol"] == protocol
        assert sorted(value for key, value in response["headers"] if key == "cookie") == sorted(expected["cookie_pairs"])  # noqa: E501
        assert response["headers"][-1][0] == "priority"
        with closing(CurlMime()) as multipart:
            multipart.addpart(name="field", data="value")
            multipart.addpart(name="upload", content_type="text/plain", filename="sample.txt", data=b"fingerprint-test\n")  # noqa: E501
            upload = session.post(url + "/multipart", multipart=multipart, timeout=5).json()  # noqa: E501
        content_type = next(value for key, value in upload["headers"] if key == "content-type")  # noqa: E501
        boundary = content_type.split("boundary=", 1)[1]
        assert re.fullmatch(re.escape(expected["boundary_prefix"]) + r"[A-Za-z0-9]{16}", boundary)  # noqa: E501
        assert upload["body"].replace(boundary, "<BOUNDARY>") == expected["multipart_body_template"]  # noqa: E501
        assert upload["connection"] == response["connection"]
        assert session.get(url + "/again", timeout=5).json()["connection"] == response["connection"]  # noqa: E501


def test_chrome_windows_http3_matches_capture():
    expected = CAPTURE["http3_fingerprint"]
    orders = set()
    for _ in range(3):
        data = requests.get("https://fp.impersonate.pro/api/http3", impersonate="chrome153_win", http_version="v3only", timeout=30).json()  # noqa: E501
        assert data["protocol"] == "http3"
        assert data["quic"] == expected["quic"]
        assert data["tls"]["ja3n"] == expected["ja3n"]
        assert data["http3"]["perk_text_normalized"] == expected["perk_text_normalized"]
        assert data["http3"]["headers"] == expected["headers"]
        order = tuple(item["id"] for item in data["tls"]["extensions"])
        assert sorted(order) == sorted(expected["extension_orders"][0])
        orders.add(order)
        extensions = {item["id"]: item for item in data["tls"]["extensions"]}
        assert extensions[13]["data"]["algorithms"] == expected["signature_algorithms"]
        settings = []
        for setting in data["http3"]["settings"]:
            if setting["name"] == "GREASE":
                assert (setting["id"] - 33) % 31 == 0
                assert 0 <= (setting["id"] - 33) // 31 <= 0xFFFFFFFF
                assert 0 <= setting["value"] <= 0xFFFFFFFF
                settings.append({"id": "GREASE", "value": "UINT32"})
            else:
                settings.append({"id": setting["id"], "value": setting["value"]})
        assert settings == expected["settings"]
        parameters = extensions[57]["data"]
        versions = next(item["value"] for item in parameters if item["id"] == 17)
        assert versions["chosen_version"] == 1
        assert set(versions["available_versions"]) == {1, "GREASE"}
        grease = next(item for item in parameters if item["name"] == "GREASE")
        assert grease["id"] % 31 == 27
        assert 0 <= len(bytes.fromhex(grease["value"][2:])) <= 15
        assert not any(item["id"] == 12583 for item in parameters)
    assert len(orders) > 1


@pytest.mark.parametrize("value", [-1, 2147483648])
def test_initial_quic_packet_number_rejects_invalid_values(value):
    with closing(Curl()) as curl, pytest.raises(CurlError) as error:
        curl.setopt(CurlOpt.QUIC_INITIAL_PACKET_NUMBER, value)
    assert error.value.code == 43


def test_explicit_cookie_header_remains_caller_controlled(browser_echo):
    url, certificate = browser_echo
    data = requests.get(url, impersonate="chrome153_win", http_version="v2", verify=certificate, headers={"Cookie": "alpha=one; beta=two"}, timeout=5).json()  # noqa: E501
    assert [value for key, value in data["headers"] if key == "cookie"] == ["alpha=one; beta=two"]  # noqa: E501


def test_legacy_multipart_mode_is_unchanged(browser_echo):
    url, certificate = browser_echo
    fingerprint = get_fingerprint("chrome153_win")
    fingerprint.form_boundary = "webkit"
    with closing(CurlMime()) as multipart:
        multipart.addpart(name="field", data="value")
        data = requests.post(url, impersonate=fingerprint, http_version="v2", verify=certificate, multipart=multipart, timeout=5).json()  # noqa: E501
    content_type = next(value for key, value in data["headers"] if key == "content-type")  # noqa: E501
    assert re.fullmatch(r"multipart/form-data; boundary=------WebKitFormBoundary[A-Za-z0-9]{16}", content_type)  # noqa: E501


def test_chrome_windows_http3_fresh_connections(browser_echo):
    url, certificate = browser_echo
    connections = set()
    saw_empty_grease = False
    for _ in range(512):
        data = requests.get(url, impersonate="chrome153_win", http_version="v3only", verify=certificate, timeout=5).json()  # noqa: E501
        assert data["protocol"] == "h3"
        assert data["connection"] not in connections
        connections.add(data["connection"])
        parameters = Buffer(data=bytes.fromhex(data["quic_transport_parameters"]))
        while not parameters.eof():
            identifier = parameters.pull_uint_var()
            value = parameters.pull_bytes(parameters.pull_uint_var())
            if identifier % 31 == 27:
                assert len(value) <= 15
                saw_empty_grease |= not value
        if saw_empty_grease and len(connections) >= 8:
            break
    assert saw_empty_grease
