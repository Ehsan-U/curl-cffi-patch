import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import trustme
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, StreamEnded

from curl_cffi import Curl, get_fingerprint, requests
from curl_cffi.requests.utils import _apply_fingerprint


@pytest.mark.parametrize("target,stream_id", [("chrome153_win", 1), ("firefox156_win", 3)])  # noqa: E501
def test_installed_profiles_use_patched_native_library(target, stream_id, tmp_path):
    # Applying the full profile also verifies every new HTTP/3 native option.
    curl = Curl()
    try:
        _apply_fingerprint(curl, get_fingerprint(target), set(), True)
    finally:
        curl.close()
    authority = trustme.CA()
    certificate = authority.issue_cert("localhost")
    authority.cert_pem.write_to_path(tmp_path / "ca.pem")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(context)
    context.set_alpn_protocols(["h2"])
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_ecdh_curve("prime256v1")
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(10)


        def serve():
            connection, _ = server.accept()
            connection.settimeout(10)
            with context.wrap_socket(connection, server_side=True) as tls:
                assert tls.selected_alpn_protocol() == "h2"
                h2 = H2Connection(config=H2Configuration(client_side=False))
                h2.initiate_connection()
                tls.sendall(h2.data_to_send())
                while data := tls.recv(65536):
                    for event in h2.receive_data(data):
                        if isinstance(event, RequestReceived):
                            assert event.stream_id == stream_id
                        if isinstance(event, StreamEnded):
                            h2.send_headers(event.stream_id, [(":status", "200")])
                            h2.send_data(event.stream_id, b"patched", end_stream=True)
                            tls.sendall(h2.data_to_send())
                            return
                    tls.sendall(h2.data_to_send())

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(serve)
            response = requests.get(f"https://localhost:{server.getsockname()[1]}", impersonate=target, http_version="v2", verify=str(tmp_path / "ca.pem"), timeout=5)  # noqa: E501
            assert response.text == "patched"
            future.result(timeout=10)


def test_native_dependency_licenses_are_bundled():
    import curl_cffi

    licenses = Path(curl_cffi.__file__).parent / "native_licenses"
    assert (licenses / "LICENSE_BORINGSSL").is_file()
    assert (licenses / "LICENSE_NGTCP2").is_file()
