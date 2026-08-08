from unittest.mock import Mock

from curl_cffi.const import CurlOpt
from curl_cffi.fingerprints import Fingerprint
from curl_cffi.requests.impersonate import ExtraFingerprints
from curl_cffi.requests.utils import _apply_fingerprint
from curl_cffi.requests.utils import set_extra_fp


class FakeCurl:
    def __init__(self):
        self.options = {}



    def setopt(self, option, value):
        self.options[option] = value


def test_apply_fingerprint_does_not_select_http_version():
    curl = FakeCurl()
    fingerprint = Fingerprint(http_version="v2")

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=False, request_url="https://example.com")  # noqa: E501

    assert CurlOpt.HTTP_VERSION not in curl.options


def test_apply_fingerprint_strips_padding_extension_from_tls_extension_order():
    curl = FakeCurl()
    fingerprint = Fingerprint(tls_extension_order="0-21-11")

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=False, request_url="https://example.com")  # noqa: E501

    assert curl.options[CurlOpt.TLS_EXTENSION_ORDER] == "0-11"


def test_apply_fingerprint_skips_extension_order_when_permuting():
    curl = FakeCurl()
    fingerprint = Fingerprint(
        tls_extension_order="0-23-65281-11",
        tls_permute_extensions=True,
    )
    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=False, request_url="https://example.com")  # noqa: E501

    assert CurlOpt.TLS_EXTENSION_ORDER not in curl.options
    assert curl.options[CurlOpt.SSL_PERMUTE_EXTENSIONS] == 1


def test_apply_fingerprint_rewrites_kyber_supported_group_alias():
    curl = FakeCurl()
    fingerprint = Fingerprint(tls_supported_groups=["X25519Kyber768", "P-256"])

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=False, request_url="https://example.com")  # noqa: E501

    assert curl.options[CurlOpt.SSL_EC_CURVES] == "X25519Kyber768Draft00:P-256"


def test_apply_fingerprint_with_tls_extension_order_respects_cert_compression():
    curl = FakeCurl()
    fingerprint = Fingerprint(
        tls_extension_order="0-23-65281-10-11-16-5-13-18-51-45-43-27",
        tls_cert_compression=["zlib"],
    )

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=False, request_url="https://example.com")  # noqa: E501

    assert curl.options[CurlOpt.SSL_CERT_COMPRESSION] == "zlib"


def test_apply_fingerprint_empty_host_uses_curl_generated_host():
    curl = FakeCurl()
    fingerprint = Fingerprint(
        headers={
            "User-Agent": "test-agent",
            "Host": "",
            "Connection": "Keep-Alive",
        },
        header_order="User-Agent,Host,Connection",
    )

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=True, request_url="https://example.com")  # noqa: E501

    assert curl.options[CurlOpt.HTTPHEADER] == [
        b"User-Agent: test-agent",
        b"Connection: Keep-Alive",
    ]
    assert curl.options[CurlOpt.HTTPHEADER_ORDER] == "User-Agent,Host,Connection"


def test_apply_fingerprint_sets_http3_and_websocket_options():
    curl = FakeCurl()
    fingerprint = Fingerprint(
        http3_headers={"User-Agent": "h3-agent", "Accept": "text/html"},
        http3_header_order="User-Agent,Accept",
        http3_tls_extension_order="10-45-13-16-65037-51-17613-27-57-43-0",
        http3_tls_supported_groups=["X25519Kyber768", "P-256"],
        ws_headers={"User-Agent": "ws-agent", "Origin": "https://example.com"},
        ws_header_order="User-Agent,Origin",
        ws_disable_session_ticket=True,
        ws_tls_cert_compression=["zlib", "brotli"],
    )

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=True, request_url="https://example.com")  # noqa: E501

    assert curl.options[CurlOpt.HTTP3_HTTPHEADER] == [
        b"User-Agent: h3-agent",
        b"Accept: text/html",
    ]
    assert curl.options[CurlOpt.HTTP3_HTTPHEADER_ORDER] == "User-Agent,Accept"
    assert curl.options[CurlOpt.HTTP3_TLS_EXTENSION_ORDER] == (
        "10-45-13-16-65037-51-17613-27-57-43-0"
    )
    assert curl.options[CurlOpt.HTTP3_SSL_EC_CURVES] == "X25519Kyber768Draft00:P-256"
    assert curl.options[CurlOpt.WS_HTTPHEADER] == [
        b"User-Agent: ws-agent",
        b"Origin: https://example.com",
    ]
    assert curl.options[CurlOpt.WS_HTTPHEADER_ORDER] == "User-Agent,Origin"
    assert curl.options[CurlOpt.WS_SSL_DISABLE_TICKET] == 1
    assert curl.options[CurlOpt.WS_SSL_CERT_COMPRESSION] == "zlib,brotli"


def test_apply_fingerprint_sets_and_permutes_chrome_http3_options(monkeypatch):
    curl = FakeCurl()
    randomizer = Mock()
    randomizer.shuffle.side_effect = lambda values: values.reverse()
    monkeypatch.setattr("curl_cffi.requests.utils.SystemRandom", lambda: randomizer)
    fingerprint = Fingerprint(http3_signature_hashes=["ecdsa_secp256r1_sha256", "rsa_pkcs1_sha1"], http3_tls_extension_order="0-10-13", http3_tls_permute_extensions=True, quic_transport_parameters="1:30000;17:1@1,GREASE;32:65536", quic_permute_version_information=True)  # noqa: E501

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=False, request_url="https://example.com")  # noqa: E501

    assert curl.options[CurlOpt.HTTP3_SIG_HASH_ALGS] == "ecdsa_secp256r1_sha256:rsa_pkcs1_sha1"  # noqa: E501
    assert curl.options[CurlOpt.HTTP3_TLS_EXTENSION_ORDER] == "13-10-0"
    assert curl.options[CurlOpt.QUIC_TRANSPORT_PARAMETERS] == "1:30000;17:1@GREASE,1;32:65536"  # noqa: E501
    assert randomizer.shuffle.call_count == 2


def test_apply_fingerprint_keeps_firefox_http3_extension_suffix_and_sets_alt_used(monkeypatch):  # noqa: E501
    curl = FakeCurl()
    randomizer = Mock()
    randomizer.shuffle.side_effect = lambda values: values.reverse()
    monkeypatch.setattr("curl_cffi.requests.utils.SystemRandom", lambda: randomizer)
    fingerprint = Fingerprint(http3_tls_extension_order="0-5-10-57-65037", http3_tls_permute_extensions=True, http3_tls_fixed_extension_suffix=2, http3_headers={"User-Agent": "agent", "Alt-Used": ""}, http3_alt_used=True)  # noqa: E501

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=True, request_url="https://user:password@example.com:8443/path")  # noqa: E501

    assert curl.options[CurlOpt.HTTP3_TLS_EXTENSION_ORDER] == "10-5-0-57-65037"
    assert curl.options[CurlOpt.HTTP3_HTTPHEADER] == [b"User-Agent: agent", b"Alt-Used: example.com:8443"]  # noqa: E501
    randomizer.shuffle.assert_called_once()


def test_apply_fingerprint_can_disable_websocket_cert_compression():
    curl = FakeCurl()
    fingerprint = Fingerprint(ws_tls_cert_compression=[])

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=False, request_url="https://example.com")  # noqa: E501

    assert curl.options[CurlOpt.WS_SSL_CERT_COMPRESSION] == ""


def test_set_extra_fp_sets_header_order():
    curl = FakeCurl()
    extra_fp = ExtraFingerprints(header_order="User-Agent,Host,Connection")

    set_extra_fp(curl, extra_fp)

    assert curl.options[CurlOpt.HTTPHEADER_ORDER] == "User-Agent,Host,Connection"


def test_apply_fingerprint_http3_headers_give_way_to_user_headers():
    curl = FakeCurl()
    fingerprint = Fingerprint(
        headers={"User-Agent": "h1-agent"},
        http3_headers={"User-Agent": "h3-agent", "Accept": "text/html"},
    )

    _apply_fingerprint(curl, fingerprint, existing_header_names={"user-agent"}, default_headers=True, request_url="https://example.com")  # noqa: E501

    assert curl.options[CurlOpt.HTTP3_HTTPHEADER] == [b"Accept: text/html"]


def test_apply_fingerprint_websocket_headers_give_way_to_user_headers():
    curl = FakeCurl()
    fingerprint = Fingerprint(
        headers={"User-Agent": "h1-agent"},
        ws_headers={"User-Agent": "ws-agent", "Origin": "https://example.com"},
    )

    _apply_fingerprint(curl, fingerprint, existing_header_names={"user-agent"}, default_headers=True, request_url="https://example.com")  # noqa: E501

    assert curl.options[CurlOpt.WS_HTTPHEADER] == [b"Origin: https://example.com"]


def test_apply_fingerprint_http3_headers_survive_its_own_http1_headers():
    """Only user headers suppress the http/3 set, the http/1.1 set must not."""
    curl = FakeCurl()
    fingerprint = Fingerprint(
        headers={"User-Agent": "h1-agent", "Accept": "text/html"},
        http3_headers={"User-Agent": "h3-agent"},
        ws_headers={"User-Agent": "ws-agent"},
    )

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=True, request_url="https://example.com")  # noqa: E501

    assert curl.options[CurlOpt.HTTP3_HTTPHEADER] == [b"User-Agent: h3-agent"]
    assert curl.options[CurlOpt.WS_HTTPHEADER] == [b"User-Agent: ws-agent"]
