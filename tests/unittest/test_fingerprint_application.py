from curl_cffi import get_fingerprint
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

    _apply_fingerprint(
        curl,
        fingerprint,
        existing_header_names=set(),
        default_headers=False,
    )

    assert CurlOpt.HTTP_VERSION not in curl.options


def test_apply_fingerprint_strips_padding_extension_from_tls_extension_order():
    curl = FakeCurl()
    fingerprint = Fingerprint(tls_extension_order="0-21-11")

    _apply_fingerprint(
        curl,
        fingerprint,
        existing_header_names=set(),
        default_headers=False,
    )

    assert curl.options[CurlOpt.TLS_EXTENSION_ORDER] == "0-11"


def test_apply_fingerprint_skips_extension_order_when_permuting():
    curl = FakeCurl()
    fingerprint = Fingerprint(
        tls_extension_order="0-23-65281-11",
        tls_permute_extensions=True,
    )
    _apply_fingerprint(
        curl,
        fingerprint,
        existing_header_names=set(),
        default_headers=False,
    )

    assert CurlOpt.TLS_EXTENSION_ORDER not in curl.options
    assert curl.options[CurlOpt.SSL_PERMUTE_EXTENSIONS] == 1


def test_apply_fingerprint_rewrites_kyber_supported_group_alias():
    curl = FakeCurl()
    fingerprint = Fingerprint(tls_supported_groups=["X25519Kyber768", "P-256"])

    _apply_fingerprint(
        curl,
        fingerprint,
        existing_header_names=set(),
        default_headers=False,
    )

    assert curl.options[CurlOpt.SSL_EC_CURVES] == "X25519Kyber768Draft00:P-256"


def test_apply_fingerprint_with_tls_extension_order_respects_cert_compression():
    curl = FakeCurl()
    fingerprint = Fingerprint(
        tls_extension_order="0-23-65281-10-11-16-5-13-18-51-45-43-27",
        tls_cert_compression=["zlib"],
    )

    _apply_fingerprint(
        curl,
        fingerprint,
        existing_header_names=set(),
        default_headers=False,
    )

    assert curl.options[CurlOpt.SSL_CERT_COMPRESSION] == "zlib"


def test_apply_fingerprint_sets_tls_trust_anchors():
    curl = FakeCurl()
    fingerprint = Fingerprint(tls_trust_anchors=["2.5.4.3", "2.5.4.10"])

    _apply_fingerprint(
        curl,
        fingerprint,
        existing_header_names=set(),
        default_headers=False,
    )

    assert curl.options[CurlOpt.TLS_TRUST_ANCHORS] == "2.5.4.3,2.5.4.10"


def test_apply_fingerprint_does_not_set_unspecified_tls_trust_anchors():
    curl = FakeCurl()

    _apply_fingerprint(
        curl,
        Fingerprint(),
        existing_header_names=set(),
        default_headers=False,
    )

    assert CurlOpt.TLS_TRUST_ANCHORS not in curl.options


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

    _apply_fingerprint(
        curl,
        fingerprint,
        existing_header_names=set(),
        default_headers=True,
    )

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

    _apply_fingerprint(
        curl,
        fingerprint,
        existing_header_names=set(),
        default_headers=True,
    )

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


def test_apply_fingerprint_can_disable_websocket_cert_compression():
    curl = FakeCurl()
    fingerprint = Fingerprint(ws_tls_cert_compression=[])

    _apply_fingerprint(
        curl,
        fingerprint,
        existing_header_names=set(),
        default_headers=False,
    )

    assert curl.options[CurlOpt.WS_SSL_CERT_COMPRESSION] == ""


def test_set_extra_fp_sets_header_order():
    curl = FakeCurl()
    extra_fp = ExtraFingerprints(header_order="User-Agent,Host,Connection")

    set_extra_fp(curl, extra_fp)

    assert curl.options[CurlOpt.HTTPHEADER_ORDER] == "User-Agent,Host,Connection"


def test_apply_fingerprint_sets_windows_native_options():
    curl = FakeCurl()
    fingerprint = Fingerprint(tls_grease_signature_algorithms=True, tls_reuse_x25519_key_share=True, tls_ech_grease_payload_size=240, http2_first_stream_id=3)  # noqa: E501

    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=False)  # noqa: E501

    assert curl.options[CurlOpt.TLS_GREASE_SIGNATURE_ALGORITHMS] == 1
    assert curl.options[CurlOpt.TLS_REUSE_X25519_KEY_SHARE] == 1
    assert curl.options[CurlOpt.TLS_ECH_GREASE_PAYLOAD_SIZE] == 240
    assert curl.options[CurlOpt.HTTP2_FIRST_STREAM_ID] == 3


def test_apply_fingerprint_leaves_unspecified_windows_options_unset():
    curl = FakeCurl()
    _apply_fingerprint(curl, Fingerprint(), existing_header_names=set(), default_headers=False)  # noqa: E501

    assert CurlOpt.TLS_GREASE_SIGNATURE_ALGORITHMS not in curl.options
    assert CurlOpt.TLS_REUSE_X25519_KEY_SHARE not in curl.options
    assert CurlOpt.TLS_ECH_GREASE_PAYLOAD_SIZE not in curl.options
    assert CurlOpt.HTTP2_FIRST_STREAM_ID not in curl.options


def test_apply_http3_controls_without_changing_tcp_signatures():
    curl = FakeCurl()
    fingerprint = Fingerprint(tls_signature_hashes=["mldsa44"], tls_permute_extensions=True, http3_tls_signature_hashes=["rsa_pkcs1_sha1"], http3_tls_permute_extensions=False, quic_initial_packet_number=1)  # noqa: E501
    _apply_fingerprint(curl, fingerprint, existing_header_names=set(), default_headers=False)  # noqa: E501

    assert curl.options[CurlOpt.SSL_SIG_HASH_ALGS] == "mldsa44"
    assert curl.options[CurlOpt.HTTP3_SIG_HASH_ALGS] == "rsa_pkcs1_sha1"
    assert curl.options[CurlOpt.SSL_PERMUTE_EXTENSIONS] == 1
    assert curl.options[CurlOpt.HTTP3_SSL_PERMUTE_EXTENSIONS] == 0
    assert curl.options[CurlOpt.QUIC_INITIAL_PACKET_NUMBER] == 1


def test_apply_default_fingerprint_leaves_http3_controls_unset():
    curl = FakeCurl()
    _apply_fingerprint(curl, Fingerprint(), existing_header_names=set(), default_headers=False)  # noqa: E501

    assert CurlOpt.HTTP3_SIG_HASH_ALGS not in curl.options
    assert CurlOpt.HTTP3_SSL_PERMUTE_EXTENSIONS not in curl.options
    assert CurlOpt.QUIC_INITIAL_PACKET_NUMBER not in curl.options



def test_apply_firefox_http3_overrides_are_separate_from_tcp():
    curl = FakeCurl()
    _apply_fingerprint(curl, get_fingerprint("firefox156_win"), existing_header_names=set(), default_headers=True)  # noqa: E501

    assert curl.options[CurlOpt.SPLIT_COOKIES] == 1
    assert curl.options[CurlOpt.HTTP3_SPLIT_COOKIES] == 0
    assert curl.options[CurlOpt.SSL_CERT_COMPRESSION] == "zlib,brotli,zstd"
    assert curl.options[CurlOpt.HTTP3_SSL_CERT_COMPRESSION] == "zlib,zstd,brotli"
    assert "mldsa44" not in curl.options[CurlOpt.TLS_DELEGATED_CREDENTIALS]
    assert "mldsa44" in curl.options[CurlOpt.HTTP3_TLS_DELEGATED_CREDENTIALS]
    assert curl.options[CurlOpt.HTTP3_TLS_REUSE_X25519_KEY_SHARE] == 1
    assert curl.options[CurlOpt.HTTP3_TLS_ECH_GREASE_PAYLOAD_SIZE] == 240
    assert curl.options[CurlOpt.QUIC_FIREFOX_INITIAL_PACKET_NUMBER] == 1
    assert curl.options[CurlOpt.QUIC_V2] == 1
    assert curl.options[CurlOpt.HTTP3_ALT_USED] == 1
    assert curl.options[CurlOpt.HTTP3_TLS_EXTENSION_ORDER].startswith("SHUFFLE:13:")


def test_apply_default_fingerprint_leaves_firefox_http3_overrides_unset():
    curl = FakeCurl()
    _apply_fingerprint(curl, Fingerprint(), existing_header_names=set(), default_headers=False)  # noqa: E501

    for option in (CurlOpt.HTTP3_SPLIT_COOKIES, CurlOpt.HTTP3_ALT_USED, CurlOpt.HTTP3_TLS_REUSE_X25519_KEY_SHARE, CurlOpt.HTTP3_TLS_ECH_GREASE_PAYLOAD_SIZE, CurlOpt.HTTP3_SSL_CERT_COMPRESSION, CurlOpt.HTTP3_TLS_DELEGATED_CREDENTIALS, CurlOpt.QUIC_FIREFOX_INITIAL_PACKET_NUMBER, CurlOpt.QUIC_V2):  # noqa: E501
        assert option not in curl.options



def test_apply_http3_headers_keep_request_overrides_and_additions():
    curl = FakeCurl()
    fingerprint = Fingerprint(http3_headers={"User-Agent": "browser", "Accept": "text/html"})  # noqa: E501
    _apply_fingerprint(curl, fingerprint, {"user-agent", "cookie"}, True, ["user-agent: caller", "Cookie: a=1; b=2"])  # noqa: E501

    assert curl.options[CurlOpt.HTTP3_HTTPHEADER] == [b"Accept: text/html", b"user-agent: caller", b"Cookie: a=1; b=2"]  # noqa: E501
