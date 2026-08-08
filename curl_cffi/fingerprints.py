import json
import os
from copy import deepcopy
from dataclasses import dataclass, field, fields
from datetime import datetime
from functools import cache
from io import BytesIO
from typing import Literal
from urllib.parse import urlencode

from .const import CurlInfo, CurlOpt
from .curl import Curl, CurlError

__all__ = [
    "Fingerprint",
    "FingerprintUpdateError",
    "FingerprintSpec",
    "FingerprintManager",
    "get_fingerprint",
]

FINGERPRINT_PAGE_LIMIT = 100


"""
config example
{
    "api_key": "imp_xxxxxx",
    "updated_at": "2025-08-26 18:01:01"
}
"""

NATIVE_IMPERSONATE_TARGETS = [
    {
        "browser": "Chrome",
        "version": "99",
        "os": "Windows",
        "os_version": "10",
        "target_name": "chrome99",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "100",
        "os": "Windows",
        "os_version": "10",
        "target_name": "chrome100",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "101",
        "os": "Windows",
        "os_version": "10",
        "target_name": "chrome101",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "104",
        "os": "Windows",
        "os_version": "10",
        "target_name": "chrome104",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "107",
        "os": "Windows",
        "os_version": "10",
        "target_name": "chrome107",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "110",
        "os": "Windows",
        "os_version": "10",
        "target_name": "chrome110",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "116",
        "os": "Windows",
        "os_version": "10",
        "target_name": "chrome116",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "119",
        "os": "macOS",
        "os_version": "Sonoma",
        "target_name": "chrome119",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "120",
        "os": "macOS",
        "os_version": "Sonoma",
        "target_name": "chrome120",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "123",
        "os": "macOS",
        "os_version": "Sonoma",
        "target_name": "chrome123",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "124",
        "os": "macOS",
        "os_version": "Sonoma",
        "target_name": "chrome124",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "131",
        "os": "macOS",
        "os_version": "Sonoma",
        "target_name": "chrome131",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "133",
        "os": "macOS",
        "os_version": "Sequoia",
        "target_name": "chrome133a",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "136",
        "os": "macOS",
        "os_version": "Sequoia",
        "target_name": "chrome136",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "142",
        "os": "macOS",
        "os_version": "Tahoe",
        "target_name": "chrome142",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "145",
        "os": "macOS",
        "os_version": "Tahoe",
        "target_name": "chrome145",
        "h3_fingerprints": True,
    },
    {
        "browser": "Chrome",
        "version": "146",
        "os": "macOS",
        "os_version": "Tahoe",
        "target_name": "chrome146",
        "h3_fingerprints": True,
    },
    {
        "browser": "Chrome",
        "version": "99",
        "os": "Android",
        "os_version": "12",
        "target_name": "chrome99_android",
        "h3_fingerprints": False,
    },
    {
        "browser": "Chrome",
        "version": "131",
        "os": "Android",
        "os_version": "14",
        "target_name": "chrome131_android",
        "h3_fingerprints": False,
    },
    {
        "browser": "Edge",
        "version": "99",
        "os": "Windows",
        "os_version": "10",
        "target_name": "edge99",
        "h3_fingerprints": False,
    },
    {
        "browser": "Edge",
        "version": "101",
        "os": "Windows",
        "os_version": "10",
        "target_name": "edge101",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "15.3",
        "os": "macOS",
        "os_version": "Big Sur",
        "target_name": "safari153",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "15.5",
        "os": "macOS",
        "os_version": "Monterey",
        "target_name": "safari155",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "17.0",
        "os": "macOS",
        "os_version": "Sonoma",
        "target_name": "safari170",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "17.2",
        "os": "iOS",
        "os_version": "17.2",
        "target_name": "safari172_ios",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "18.0",
        "os": "macOS",
        "os_version": "Sequoia",
        "target_name": "safari180",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "18.0",
        "os": "iOS",
        "os_version": "18.0",
        "target_name": "safari180_ios",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "18.4",
        "os": "macOS",
        "os_version": "Sequoia",
        "target_name": "safari184",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "18.4",
        "os": "iOS",
        "os_version": "18.4",
        "target_name": "safari184_ios",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "26.0",
        "os": "macOS",
        "os_version": "Tahoe",
        "target_name": "safari260",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "26.0.1",
        "os": "macOS",
        "os_version": "Tahoe",
        "target_name": "safari2601",
        "h3_fingerprints": False,
    },
    {
        "browser": "Safari",
        "version": "26.0",
        "os": "iOS",
        "os_version": "26.0",
        "target_name": "safari260_ios",
        "h3_fingerprints": False,
    },
    {
        "browser": "Firefox",
        "version": "133.0",
        "os": "macOS",
        "os_version": "Sonoma",
        "target_name": "firefox133",
        "h3_fingerprints": False,
    },
    {
        "browser": "Firefox",
        "version": "135.0",
        "os": "macOS",
        "os_version": "Sonoma",
        "target_name": "firefox135",
        "h3_fingerprints": False,
    },
    {
        "browser": "Firefox",
        "version": "144.0",
        "os": "macOS",
        "os_version": "Tahoe",
        "target_name": "firefox144",
        "h3_fingerprints": False,
    },
    {
        "browser": "Firefox",
        "version": "147.0",
        "os": "macOS",
        "os_version": "Tahoe",
        "target_name": "firefox147",
        "h3_fingerprints": True,
    },
    {
        "browser": "Tor",
        "version": "14.5",
        "os": "macOS",
        "os_version": "Sonoma",
        "target_name": "tor145",
        "h3_fingerprints": False,
    },
]


DEFAULT_API_ROOT = "https://api.impersonate.pro/v1"


class FingerprintUpdateError(RuntimeError, CurlError):
    """Raised when fingerprint update fails."""


def _get_default_config_dir() -> str:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return os.path.join(appdata, "impersonate")
        userprofile = os.environ.get("USERPROFILE")
        if userprofile:
            return os.path.join(userprofile, "AppData", "Roaming", "impersonate")
        home = os.path.expanduser("~")
        return os.path.join(home, "AppData", "Roaming", "impersonate")

    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return os.path.join(xdg_config_home, "impersonate")
    return os.path.expanduser("~/.config/impersonate")


@dataclass
class Fingerprint:
    client: str = ""
    client_version: str = ""
    os: str = ""
    os_version: str = ""

    # Describes the default HTTP version associated with this fingerprint. The
    # version used for a request is selected separately with ``http_version``.
    http_version: str = "v2"

    tls_version: str = "1.2"
    tls_ciphers: list[str] = field(default_factory=list)
    # the value is [h2, http/1.1], which will be filled by libcurl
    tls_alpn: bool = False
    tls_alps: bool = False
    tls_cert_compression: list[str] = field(default_factory=list)
    tls_signature_hashes: list[str] = field(default_factory=list)  # .sig_hash_args
    tls_key_shares_limit: int = 2  # the default key shares length is 2
    tls_supported_groups: list[str] = field(default_factory=list)  # .curves
    tls_session_ticket: bool = False
    tls_extension_order: str = ""
    tls_delegated_credentials: list[str] = field(default_factory=list)
    tls_record_size_limit: int | None = None
    tls_grease: bool = False
    tls_use_new_alps_codepoint: bool = False
    tls_signed_cert_timestamps: bool = False
    tls_ech: str | None = None
    tls_permute_extensions: bool = False

    headers: dict[str, str] = field(default_factory=dict)
    header_order: str = ""
    split_cookies: bool = False
    form_boundary: str = ""

    http2_settings: str = ""
    http2_window_update: int = 0
    http2_pseudo_headers_order: str = ""
    http2_stream_weight: int | None = None
    http2_stream_exclusive: int | None = None
    http2_no_priority: bool = False

    http3_settings: str = ""
    http3_pseudo_headers_order: str = ""
    http3_signature_hashes: list[str] = field(default_factory=list)
    http3_tls_extension_order: str = ""
    http3_tls_permute_extensions: bool = False
    http3_tls_fixed_extension_suffix: int = 0
    http3_headers: dict[str, str] = field(default_factory=dict)
    http3_header_order: str = ""
    http3_alt_used: bool = False
    http3_tls_supported_groups: list[str] = field(default_factory=list)
    quic_transport_parameters: str = ""
    quic_permute_version_information: bool = False

    ws_headers: dict[str, str] = field(default_factory=dict)
    ws_header_order: str = ""
    ws_disable_session_ticket: bool = False
    ws_tls_cert_compression: list[str] | None = None

    header_lang: str = ""


BUILTIN_FINGERPRINTS: dict[str, Fingerprint] = {
    "chrome151": Fingerprint(
        client="chrome",
        client_version="151",
        os="Linux",
        os_version="25.10",
        http_version="v2",
        tls_version="1.2",
        tls_ciphers=[
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
        ],
        tls_alpn=True,
        tls_alps=True,
        tls_cert_compression=["brotli"],
        tls_signature_hashes=[
            "mldsa44",
            "mldsa65",
            "mldsa87",
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ],
        tls_supported_groups=["X25519MLKEM768", "X25519", "P-256", "P-384"],
        tls_session_ticket=True,
        tls_grease=True,
        tls_use_new_alps_codepoint=True,
        tls_signed_cert_timestamps=True,
        tls_ech="true",
        tls_permute_extensions=True,
        headers={
            "sec-ch-ua": '"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"',  # noqa: E501
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Linux"',
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",  # noqa: E501
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",  # noqa: E501
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Priority": "u=0, i",
        },
        header_order="sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Priority",
        split_cookies=True,
        form_boundary="webkit",
        http2_settings="1:65536;2:0;4:6291456;6:262144",
        http2_window_update=15663105,
        http2_pseudo_headers_order="m,a,s,p",
        http2_stream_weight=256,
        http2_stream_exclusive=1,
        http3_settings="1:65536;6:262144;7:100;51:1;GREASE",
        http3_pseudo_headers_order="m,a,s,p",
        http3_signature_hashes=[
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ],
        http3_tls_extension_order="0-10-13-16-27-43-45-51-57-17613-65037",
        http3_tls_permute_extensions=True,
        http3_header_order="sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Priority",
        quic_transport_parameters="1:30000;3:1472;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;15:;17:1@1,GREASE;32:65536;12584:0x4f524947;GREASE",
        quic_permute_version_information=True,
    ),
    # Captured from Google Chrome 151.0.7922.83 (x86_64, installed from Play) running on
    # Android 11. Its ClientHello and HTTP/2 preface are byte for byte identical to the
    # desktop chrome151 above, only the headers differ. Chrome's user agent reduction
    # pins the reported Android version to 10 and the model to "K" on every device, so
    # these headers do not leak the capture host.
    # HTTP/3 and QUIC parameters were not captured and are deliberately left unset.
    "chrome151_android": Fingerprint(
        client="chrome",
        client_version="151",
        os="Android",
        os_version="10",
        http_version="v2",
        tls_version="1.2",
        tls_ciphers=[
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
        ],
        tls_alpn=True,
        tls_alps=True,
        tls_cert_compression=["brotli"],
        tls_signature_hashes=[
            "mldsa44",
            "mldsa65",
            "mldsa87",
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ],
        tls_supported_groups=["X25519MLKEM768", "X25519", "P-256", "P-384"],
        tls_session_ticket=True,
        tls_grease=True,
        tls_use_new_alps_codepoint=True,
        tls_signed_cert_timestamps=True,
        tls_ech="true",
        tls_permute_extensions=True,
        headers={
            "sec-ch-ua": '"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"',  # noqa: E501
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36",  # noqa: E501
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",  # noqa: E501
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Priority": "u=0, i",
        },
        header_order="sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Priority",
        split_cookies=True,
        form_boundary="webkit",
        http2_settings="1:65536;2:0;4:6291456;6:262144",
        http2_window_update=15663105,
        http2_pseudo_headers_order="m,a,s,p",
        http2_stream_weight=256,
        http2_stream_exclusive=1,
    ),
    "firefox152": Fingerprint(
        client="firefox",
        client_version="152",
        os="Linux",
        os_version="25.10",
        http_version="v2",
        tls_version="1.2",
        tls_ciphers=[
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
        ],
        tls_alpn=True,
        tls_cert_compression=["zlib", "brotli", "zstd"],
        tls_signature_hashes=[
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
            "ecdsa_sha1",
            "rsa_pkcs1_sha1",
        ],
        tls_key_shares_limit=3,
        tls_supported_groups=["X25519MLKEM768", "X25519", "P-256", "P-384", "P-521", "ffdhe2048", "ffdhe3072"],  # noqa: E501
        tls_session_ticket=True,
        tls_extension_order="0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037",
        tls_delegated_credentials=["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512", "ecdsa_sha1"],  # noqa: E501
        tls_record_size_limit=16385,
        tls_signed_cert_timestamps=True,
        tls_ech="true",
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",  # noqa: E501
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",  # noqa: E501
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Priority": "u=0, i",
            "TE": "trailers",
        },
        header_order="User-Agent,Accept,Accept-Language,Accept-Encoding,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Priority,TE",
        http2_settings="1:65536;2:0;4:131072;5:16384",
        http2_window_update=12517377,
        http2_pseudo_headers_order="m,p,a,s",
        http2_stream_weight=42,
        http2_stream_exclusive=0,
        http3_settings="1:65536;7:20;727725890:0;16765559:1;51:1;8:1",
        http3_pseudo_headers_order="m,s,a,p",
        http3_signature_hashes=[
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "ecdsa_sha1",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ],
        http3_tls_extension_order="0-5-10-13-16-23-27-28-34-43-45-51-65281-57-65037",
        http3_tls_permute_extensions=True,
        http3_tls_fixed_extension_suffix=2,
        http3_headers={
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",  # noqa: E501
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",  # noqa: E501
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Alt-Used": "",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Priority": "u=0, i",
        },
        http3_header_order="User-Agent,Accept,Accept-Language,Accept-Encoding,Alt-Used,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Priority",
        http3_alt_used=True,
        http3_tls_supported_groups=["X25519MLKEM768", "X25519", "P-256", "P-384", "P-521"],  # noqa: E501
        quic_transport_parameters="1:30000;4:25165824;5:12582912;6:1048576;7:1048576;8:100;9:100;11:20;14:8;15:;17:1@GREASE,1;GREASE;32:65535",
    ),
    "okhttp50a2": Fingerprint(
        client="okhttp",
        client_version="5.0.0-alpha2",
        os="Android",
        os_version="provider-dependent",
        http_version="v2",
        tls_version="1.2",
        tls_ciphers=[
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        ],
        tls_alpn=True,
        tls_signature_hashes=[
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ],
        tls_key_shares_limit=1,
        tls_supported_groups=["X25519", "P-256", "P-384"],
        tls_session_ticket=True,
        tls_extension_order="0-23-65281-10-11-35-16-5-13-51-45-43-21",
        headers={"Accept-Encoding": "gzip", "User-Agent": "okhttp/5.0.0-alpha2"},
        http2_settings="4:16777216",
        http2_window_update=16711681,
        http2_pseudo_headers_order="m,p,a,s",
        http2_no_priority=True,
    ),
    "okhttp51_android11": Fingerprint(
        client="okhttp",
        client_version="5.1.0",
        os="Android",
        os_version="11",
        http_version="v2",
        tls_version="1.2",
        tls_ciphers=[
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
        ],
        tls_alpn=True,
        tls_signature_hashes=[
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ],
        tls_key_shares_limit=1,
        tls_supported_groups=["X25519", "P-256", "P-384"],
        tls_session_ticket=True,
        tls_extension_order="0-23-65281-10-11-35-16-5-13-51-45-43-21",
        headers={"Accept-Encoding": "gzip", "User-Agent": "okhttp/5.1.0"},
        http2_settings="4:16777216",
        http2_window_update=16711681,
        http2_pseudo_headers_order="m,p,a,s",
        http2_no_priority=True,
    ),
    "okhttp54_android11": Fingerprint(
        client="okhttp",
        client_version="5.4.0",
        os="Android",
        os_version="11",
        http_version="v2",
        tls_version="1.2",
        tls_ciphers=[
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
        ],
        tls_alpn=True,
        tls_signature_hashes=[
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ],
        tls_key_shares_limit=1,
        tls_supported_groups=["X25519", "P-256", "P-384"],
        tls_session_ticket=True,
        tls_extension_order="0-23-65281-10-11-35-16-5-13-51-45-43-21",
        headers={"Accept-Encoding": "gzip", "User-Agent": "okhttp/5.4.0"},
        http2_settings="4:16777216",
        http2_window_update=16711681,
        http2_pseudo_headers_order="m,p,a,s",
        http2_no_priority=True,
    ),
}


# fmt: off
ClientLiteral = Literal[
    # browsers
    "chrome", "firefox", "edge", "brave", "opera", "brave", "operamini",
    "qihoo", "qq", "quark", "samsung", "sogou", "sogou_ie",
    # http client
    "volley", "okhttp", "webview",
    # app with general web view
    "baidu", "wechat", "bing", "duckduckgo", "google", "yandex",
]
# fmt: on
PlatformLiteral = ["macos", "windows", "linux", "ios", "android"]


@dataclass
class FingerprintSpec:
    platform: str | None = None
    client: ClientLiteral | None = None
    strategy: Literal["uniform"] | None = "uniform"


class FingerprintManager:
    @classmethod
    def get_config_dir(cls) -> str:
        return os.environ.get("IMPERSONATE_CONFIG_DIR", _get_default_config_dir())

    @classmethod
    def get_config_path(cls) -> str:
        return os.path.join(cls.get_config_dir(), "config.json")

    @classmethod
    def get_fingerprint_path(cls) -> str:
        return os.path.join(cls.get_config_dir(), "fingerprints.json")

    @classmethod
    def get_api_root(cls) -> str:
        return (
            os.environ.get("IMPERSONATE_API_ROOT", DEFAULT_API_ROOT) or DEFAULT_API_ROOT
        )

    @classmethod
    def get_api_key(cls) -> str | None:
        api_key = os.environ.get("IMPERSONATE_API_KEY")
        if api_key:
            return api_key
        config_path = cls.get_config_path()
        if not os.path.exists(config_path):
            return None
        with open(config_path) as f:
            try:
                config = json.load(f)
            except json.JSONDecodeError:
                return None
        api_key = config.get("api_key")
        if isinstance(api_key, str) and api_key:
            return api_key
        return None

    @classmethod
    def set_api_key(cls, api_key: str) -> None:
        """Persist the API key for impersonate.pro."""
        config_dir = cls.get_config_dir()
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        config_file = cls.get_config_path()
        if os.path.exists(config_file):
            with open(config_file) as f:
                try:
                    config = json.load(f)
                except json.JSONDecodeError:
                    config = {}
        else:
            config = {}
        config["api_key"] = api_key
        config["update_time"] = datetime.utcnow().isoformat()
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)

    @staticmethod
    def _fetch_fingerprint_payload(url: str, headers: dict[str, str]) -> bytes:
        curl = Curl()
        buffer = BytesIO()
        try:
            curl.setopt(CurlOpt.URL, url.encode())
            if headers:
                curl.setopt(
                    CurlOpt.HTTPHEADER,
                    [f"{key}: {value}".encode() for key, value in headers.items()],
                )
            curl.setopt(CurlOpt.WRITEDATA, buffer)
            curl.perform()
            status_code = int(curl.getinfo(CurlInfo.RESPONSE_CODE))
        except CurlError as exc:
            raise FingerprintUpdateError(
                f"Failed to access fingerprint endpoint at {url}: {exc}"
            ) from exc
        finally:
            curl.close()

        payload = buffer.getvalue()
        if status_code >= 400:
            body = payload.decode("utf-8", errors="replace")
            raise FingerprintUpdateError(
                f"Failed to access fingerprint endpoint at {url}: "
                f"HTTP {status_code}: {body}"
            )
        return payload

    @classmethod
    def update_fingerprints(cls, api_root: str | None = None) -> int:
        """Get the latest fingerprints for impersonating."""
        api_root = api_root or cls.get_api_root()
        base_url = f"{api_root.rstrip('/')}/fingerprints"
        headers = {}
        api_key = cls.get_api_key()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        fingerprints: dict[str, dict] = {}
        skip = 0
        limit = FINGERPRINT_PAGE_LIMIT
        while True:
            url = f"{base_url}?{urlencode({'skip': skip, 'limit': limit})}"
            payload = cls._fetch_fingerprint_payload(url, headers)

            try:
                data = json.loads(payload)
                if not isinstance(data, dict):
                    raise FingerprintUpdateError(
                        f"Invalid fingerprint response from {url}: expected object"
                    )
                items = data.get("items", data.get("data"))
            except json.JSONDecodeError as exc:
                raise FingerprintUpdateError(
                    f"Invalid fingerprint response from {url}: {exc}"
                ) from exc

            if not isinstance(items, list):
                raise FingerprintUpdateError(f"No fingerprints found at {url}")

            for item in items:
                if not isinstance(item, dict):
                    continue
                name = item.get("name") or item.get("target")
                if not name:
                    continue
                raw = item.get("data", item.get("fingerprint", {}))
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                if isinstance(raw, dict):
                    fingerprints[name] = raw

            pagination = data.get("pagination")
            if not isinstance(pagination, dict) or not pagination.get("has_more"):
                break
            next_skip = pagination.get("next_skip")
            if not isinstance(next_skip, int) or next_skip <= skip:
                raise FingerprintUpdateError(
                    f"Invalid fingerprint pagination from {url}: "
                    "expected increasing next_skip"
                )
            skip = next_skip

        config_dir = cls.get_config_dir()
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        with open(cls.get_fingerprint_path(), "w") as wf:
            json.dump(fingerprints, wf, indent=2)
        cls.load_fingerprints.cache_clear()
        return len(fingerprints)

    @staticmethod
    def _parse_fingerprints(payload: dict[str, object]) -> dict[str, Fingerprint]:
        allowed = {item.name for item in fields(Fingerprint)}
        parsed: dict[str, Fingerprint] = {}
        for key, value in payload.items():
            if not isinstance(value, dict):
                continue
            filtered = {k: v for k, v in value.items() if k in allowed}
            parsed[key] = Fingerprint(**filtered)
        return parsed

    @classmethod
    def _load_native_fingerprints(cls) -> dict[str, Fingerprint]:
        native_payload: dict[str, dict[str, str]] = {}
        for item in NATIVE_IMPERSONATE_TARGETS:
            target_name = item.get("target_name")
            if not isinstance(target_name, str) or not target_name:
                continue
            browser = item.get("browser")
            version = item.get("version")
            os_name = item.get("os")
            os_version = item.get("os_version")
            native_payload[target_name] = {
                "client": browser.lower() if isinstance(browser, str) else "",
                "client_version": version if isinstance(version, str) else "",
                "os": os_name if isinstance(os_name, str) else "",
                "os_version": os_version if isinstance(os_version, str) else "",
            }
        return cls._parse_fingerprints(native_payload)

    @classmethod
    @cache
    def load_fingerprints(cls) -> dict[str, Fingerprint]:
        parsed = cls._load_native_fingerprints()
        parsed.update(deepcopy(BUILTIN_FINGERPRINTS))
        fingerprint_path = cls.get_fingerprint_path()
        if os.path.exists(fingerprint_path):
            with open(fingerprint_path) as f:
                fingerprints = json.loads(f.read())
            if isinstance(fingerprints, dict):
                parsed.update(cls._parse_fingerprints(fingerprints))
        return parsed

    @classmethod
    def get_fingerprint(cls, target: str) -> Fingerprint:
        """Return a deep-copied fingerprint that callers can edit safely."""
        fingerprints = cls.load_fingerprints()
        if target not in fingerprints:
            raise KeyError(f"Fingerprint target not found: {target}")
        return deepcopy(fingerprints[target])

    @classmethod
    def list_fingerprints(cls) -> list[dict[str, object]]:
        native_lookup = {
            item["target_name"]: item for item in NATIVE_IMPERSONATE_TARGETS
        }
        rows: list[dict[str, object]] = []
        for name, fingerprint in sorted(cls.load_fingerprints().items()):
            native = native_lookup.get(name)
            if native:
                rows.append(
                    {
                        "type": "builtin",
                        "name": name,
                        "browser": native.get("browser", ""),
                        "version": native.get("version", ""),
                        "os": native.get("os", ""),
                        "os_version": native.get("os_version", ""),
                        "h3_fingerprints": bool(native.get("h3_fingerprints", False)),
                    }
                )
            elif name in BUILTIN_FINGERPRINTS:
                rows.append(
                    {
                        "type": "builtin",
                        "name": name,
                        "browser": fingerprint.client,
                        "version": fingerprint.client_version,
                        "os": fingerprint.os,
                        "os_version": fingerprint.os_version,
                        "h3_fingerprints": bool(fingerprint.http3_settings),
                    }
                )
            else:
                rows.append(
                    {
                        "type": "custom",
                        "name": name,
                        "browser": fingerprint.client,
                        "version": fingerprint.client_version,
                        "os": fingerprint.os,
                        "os_version": fingerprint.os_version,
                        "h3_fingerprints": fingerprint.http_version in ("v3", "v3only"),
                    }
                )
        return rows


def get_fingerprint(target: str) -> Fingerprint:
    """Return a deep-copied fingerprint that callers can edit safely."""
    return FingerprintManager.get_fingerprint(target)
