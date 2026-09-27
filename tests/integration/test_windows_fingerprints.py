import json
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest
import trustme

from curl_cffi import Curl, CurlError, CurlOpt, requests


CAPTURES = json.loads((Path(__file__).parents[1] / "fixtures/windows_fingerprints.json").read_text())  # noqa: E501


@pytest.mark.parametrize("target", ["chrome153_win", "firefox156_win"])
def test_windows_fingerprint_matches_capture(target):
    expected = CAPTURES[target]
    data = requests.get("https://tls.peet.ws/api/all", impersonate=target, http_version="v2", timeout=30).json()  # noqa: E501

    assert data["http_version"] == "h2"
    assert data["tls"]["ja4"] == expected["ja4"]
    assert data["tls"]["peetprint"] == expected["peetprint"]
    assert data["http2"] == expected["http2"]
    actual_ja3 = data["tls"]["ja3"].split(",")
    expected_ja3 = expected["ja3"].split(",")
    if target == "chrome153_win":
        actual_ja3[2] = "-".join(sorted(actual_ja3[2].split("-")))
        expected_ja3[2] = "-".join(sorted(expected_ja3[2].split("-")))
    assert actual_ja3 == expected_ja3

    extensions = {item["name"]: item for item in data["tls"]["extensions"]}
    shares = {key: value for item in extensions["key_share (51)"]["shared_keys"] for key, value in item.items()}  # noqa: E501
    assert [{"group": "GREASE" if key.startswith("TLS_GREASE") else key, "length": len(value) // 2} for key, value in shares.items()] == expected["key_shares"]  # noqa: E501
    assert (shares["X25519MLKEM768 (4588)"][-64:] == shares["X25519 (29)"]) == expected["reuse_x25519_key_share"]  # noqa: E501
    ech = bytes.fromhex(extensions["extensionEncryptedClientHello (boringssl) (65037)"]["data"])  # noqa: E501
    assert ech[:5] == bytes.fromhex("0000010001")
    enc_length = int.from_bytes(ech[6:8], "big")
    assert enc_length == 32
    assert int.from_bytes(ech[8 + enc_length:10 + enc_length], "big") in expected["ech_grease_payload_sizes"]  # noqa: E501

    if target == "chrome153_win":
        anchors = bytes.fromhex(extensions["Unknown extension 51764"]["data"])
        assert int.from_bytes(anchors[:2], "big") == len(anchors) - 2
        ids = []
        position = 2
        while position < len(anchors):
            size = anchors[position]
            ids.append(anchors[position + 1:position + 1 + size].hex())
            position += size + 1
        assert sorted(ids) == expected["trust_anchor_ids"]


@pytest.mark.parametrize("group", ["X25519", "prime256v1"])
def test_firefox_windows_key_shares_complete_tls_handshake(group, tmp_path):
    authority = trustme.CA()
    certificate = authority.issue_cert("localhost")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_ecdh_curve(group)
    certificate.configure_cert(context)
    authority.cert_pem.write_to_path(tmp_path / "ca.pem")

    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(10)


        def serve():
            connection, _ = server.accept()
            connection.settimeout(10)
            with context.wrap_socket(connection, server_side=True) as tls:
                assert tls.recv(8192).startswith(b"GET / HTTP/1.1")
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")  # noqa: E501

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(serve)
            response = requests.get(f"https://localhost:{server.getsockname()[1]}/", impersonate="firefox156_win", http_version="v1", verify=str(tmp_path / "ca.pem"), timeout=5)  # noqa: E501
            assert response.text == "ok"
            future.result(timeout=10)


@pytest.mark.parametrize("value", [-1, 2, 2147483648])
def test_first_http2_stream_id_rejects_invalid_values(value):
    with closing(Curl()) as curl, pytest.raises(CurlError) as error:
        curl.setopt(CurlOpt.HTTP2_FIRST_STREAM_ID, value)
    assert error.value.code == 43


@pytest.mark.parametrize("value", [-1, 1, 15, 65494])
def test_ech_grease_payload_rejects_invalid_sizes(value):
    with closing(Curl()) as curl, pytest.raises(CurlError) as error:
        curl.setopt(CurlOpt.TLS_ECH_GREASE_PAYLOAD_SIZE, value)
    assert error.value.code == 43
