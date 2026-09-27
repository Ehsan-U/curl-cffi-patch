import json
import os

import pytest

import curl_cffi
from curl_cffi.fingerprints import (
    Fingerprint,
    FingerprintManager,
    _get_default_config_dir,
)
from curl_cffi.requests.impersonate import resolve_latest_browser_type


@pytest.fixture(autouse=True)
def clear_fingerprint_cache():
    FingerprintManager.load_fingerprints.cache_clear()
    yield
    FingerprintManager.load_fingerprints.cache_clear()


def test_get_default_config_dir_linux_xdg(monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX default config path test")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/xdg-config")

    assert _get_default_config_dir() == "/tmp/xdg-config/impersonate"


def test_get_default_config_dir_linux_fallback(monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX default config path test")
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", "/home/tester")

    assert _get_default_config_dir() == "/home/tester/.config/impersonate"


def test_get_default_config_dir_macos(monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX default config path test")
    monkeypatch.setenv("HOME", "/Users/tester")

    assert _get_default_config_dir() == "/Users/tester/.config/impersonate"


def test_get_default_config_dir_windows(monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows default config path test")
    monkeypatch.setenv("APPDATA", r"C:\Users\tester\AppData\Roaming")

    assert _get_default_config_dir() == r"C:\Users\tester\AppData\Roaming\impersonate"


def test_get_config_dir_prefers_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))

    assert FingerprintManager.get_config_dir() == str(tmp_path)


def test_get_api_key_prefers_environment_override(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"api_key": "imp_config"}))
    monkeypatch.setenv("IMPERSONATE_API_KEY", "imp_env")

    assert FingerprintManager.get_api_key() == "imp_env"


def test_get_api_key_falls_back_to_config_file(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"api_key": "imp_config"}))
    monkeypatch.delenv("IMPERSONATE_API_KEY", raising=False)

    assert FingerprintManager.get_api_key() == "imp_config"


def test_get_fingerprint_returns_editable_copy(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))
    fingerprint_path = tmp_path / "fingerprints.json"
    fingerprint_path.write_text(
        json.dumps(
            {
                "edge_146_macos_26": {
                    "headers": {
                        "User-Agent": "fingerprint-ua",
                        "Accept": "text/html",
                    }
                }
            }
        )
    )

    fingerprint = curl_cffi.get_fingerprint("edge_146_macos_26")

    assert fingerprint.headers["User-Agent"] == "fingerprint-ua"
    fingerprint.headers["User-Agent"] = "custom-ua"
    assert fingerprint.headers["User-Agent"] == "custom-ua"
    assert FingerprintManager.get_fingerprint("edge_146_macos_26").headers[
        "User-Agent"
    ] == ("fingerprint-ua")


def test_get_fingerprint_unknown_target_raises_key_error(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))

    with pytest.raises(KeyError, match="Fingerprint target not found"):
        curl_cffi.get_fingerprint("missing-target")


def test_get_fingerprint_returns_native_target_copy(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))

    fingerprint = curl_cffi.get_fingerprint("chrome120")

    assert fingerprint.client == "chrome"
    assert fingerprint.headers == {}


def test_parse_fingerprints_keeps_http3_and_websocket_fields():
    payload = {
        "custom": {
            "http3_headers": {"User-Agent": "h3-agent"},
            "http3_header_order": "User-Agent",
            "http3_tls_supported_groups": ["X25519", "P-256"],
            "ws_headers": {"User-Agent": "ws-agent"},
            "ws_header_order": "User-Agent",
            "ws_disable_session_ticket": True,
            "ws_tls_cert_compression": [],
        }
    }

    fingerprint = FingerprintManager._parse_fingerprints(payload)["custom"]

    assert fingerprint.http3_headers == {"User-Agent": "h3-agent"}
    assert fingerprint.http3_header_order == "User-Agent"
    assert fingerprint.http3_tls_supported_groups == ["X25519", "P-256"]
    assert fingerprint.ws_headers == {"User-Agent": "ws-agent"}
    assert fingerprint.ws_header_order == "User-Agent"
    assert fingerprint.ws_disable_session_ticket is True
    assert fingerprint.ws_tls_cert_compression == []


def test_get_fingerprint_returns_builtin_okhttp50a2_copy(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))

    fingerprint = curl_cffi.get_fingerprint("okhttp50a2")

    assert fingerprint.client == "okhttp"
    assert fingerprint.client_version == "5.0.0-alpha2"
    assert fingerprint.os == "Android"
    assert fingerprint.tls_ciphers[-1] == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    assert fingerprint.tls_key_shares_limit == 1
    assert fingerprint.headers == {"Accept-Encoding": "gzip", "User-Agent": "okhttp/5.0.0-alpha2"}  # noqa: E501
    assert fingerprint.http2_no_priority is True
    fingerprint.headers["User-Agent"] = "changed"
    assert curl_cffi.get_fingerprint("okhttp50a2").headers["User-Agent"] == "okhttp/5.0.0-alpha2"  # noqa: E501
    assert next(row for row in FingerprintManager.list_fingerprints() if row["name"] == "okhttp50a2") == {  # noqa: E501
        "type": "builtin",
        "name": "okhttp50a2",
        "browser": "okhttp",
        "version": "5.0.0-alpha2",
        "os": "Android",
        "os_version": "provider-dependent",
        "h3_fingerprints": False,
    }


def test_okhttp_alias_resolves_to_latest_captured_profile():
    assert resolve_latest_browser_type("okhttp") == "okhttp54_android11"


def test_get_fingerprint_ios27(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))

    fingerprint = curl_cffi.get_fingerprint("ios27")

    assert fingerprint.tls_signature_hashes.count("rsa_pss_rsae_sha384") == 2
    assert fingerprint.tls_session_ticket is False
    assert fingerprint.tls_permute_extensions is False
    assert fingerprint.headers == {
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "YourApp/1 CFNetwork/3896.100.1.2.1 Darwin/27.0.0",
    }
    assert fingerprint.header_order == ""
    assert fingerprint.split_cookies is False
    assert next(
        row for row in FingerprintManager.list_fingerprints()
        if row["name"] == "ios27"
    ) == {
        "type": "builtin",
        "name": "ios27",
        "browser": "cfnetwork",
        "version": "3896.100.1.2.1",
        "os": "iOS",
        "os_version": "27",
        "h3_fingerprints": False,
    }
    fingerprint.tls_signature_hashes.clear()
    fingerprint.headers.clear()
    restored = curl_cffi.get_fingerprint("ios27")
    assert restored.tls_signature_hashes.count("rsa_pss_rsae_sha384") == 2
    assert restored.headers == {
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "YourApp/1 CFNetwork/3896.100.1.2.1 Darwin/27.0.0",
    }


def test_get_fingerprint_okhttp51_android11(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))

    fingerprint = curl_cffi.get_fingerprint("okhttp51_android11")

    assert fingerprint.client == "okhttp"
    assert fingerprint.client_version == "5.1.0"
    assert fingerprint.os == "Android"
    assert fingerprint.os_version == "11"
    assert fingerprint.tls_ciphers[-1] == "TLS_RSA_WITH_AES_256_CBC_SHA"
    assert fingerprint.headers == {"Accept-Encoding": "gzip", "User-Agent": "okhttp/5.1.0"}  # noqa: E501
    assert fingerprint.http2_settings == "4:16777216"
    assert fingerprint.http2_window_update == 16711681
    assert fingerprint.http2_pseudo_headers_order == "m,p,a,s"
    assert fingerprint.http2_no_priority is True
    assert next(row for row in FingerprintManager.list_fingerprints() if row["name"] == "okhttp51_android11") == {  # noqa: E501
        "type": "builtin",
        "name": "okhttp51_android11",
        "browser": "okhttp",
        "version": "5.1.0",
        "os": "Android",
        "os_version": "11",
        "h3_fingerprints": False,
    }


def test_get_fingerprint_okhttp54_android11(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))

    fingerprint = curl_cffi.get_fingerprint("okhttp54_android11")

    assert fingerprint.client == "okhttp"
    assert fingerprint.client_version == "5.4.0"
    assert fingerprint.os == "Android"
    assert fingerprint.os_version == "11"
    assert fingerprint.tls_ciphers[-1] == "TLS_RSA_WITH_AES_256_CBC_SHA"
    assert fingerprint.headers == {"Accept-Encoding": "gzip", "User-Agent": "okhttp/5.4.0"}  # noqa: E501
    assert fingerprint.http2_settings == "4:16777216"
    assert fingerprint.http2_window_update == 16711681
    assert fingerprint.http2_pseudo_headers_order == "m,p,a,s"
    assert fingerprint.http2_no_priority is True
    assert next(row for row in FingerprintManager.list_fingerprints() if row["name"] == "okhttp54_android11") == {  # noqa: E501
        "type": "builtin",
        "name": "okhttp54_android11",
        "browser": "okhttp",
        "version": "5.4.0",
        "os": "Android",
        "os_version": "11",
        "h3_fingerprints": False,
    }


def test_parse_fingerprints_keeps_tls_trust_anchors():
    payload = {
        "custom": {
            "tls_trust_anchors": ["2.5.4.3", "2.5.4.10"],
        }
    }

    fingerprint = FingerprintManager._parse_fingerprints(payload)["custom"]

    assert fingerprint.tls_trust_anchors == ["2.5.4.3", "2.5.4.10"]
    assert Fingerprint().tls_trust_anchors is None


@pytest.mark.parametrize("target,version", [("chrome153_win", "153.0.8010.48"), ("firefox156_win", "156.0")])  # noqa: E501
def test_get_windows_fingerprint_is_builtin_and_independently_editable(monkeypatch, tmp_path, target, version):  # noqa: E501
    monkeypatch.setenv("IMPERSONATE_CONFIG_DIR", str(tmp_path))
    fingerprint = curl_cffi.get_fingerprint(target)

    assert fingerprint.client_version == version
    assert fingerprint.os == "Windows"
    assert fingerprint.os_version == "11"
    assert "Windows NT 10.0; Win64; x64" in fingerprint.headers["user-agent"]
    assert next(row for row in FingerprintManager.list_fingerprints() if row["name"] == target) == {"type": "builtin", "name": target, "browser": fingerprint.client, "version": version, "os": "Windows", "os_version": "11", "h3_fingerprints": True}  # noqa: E501
    fingerprint.headers.clear()
    fingerprint.tls_ciphers.clear()
    assert curl_cffi.get_fingerprint(target).headers
    assert curl_cffi.get_fingerprint(target).tls_ciphers


def test_windows_profiles_do_not_change_existing_browser_aliases():
    assert resolve_latest_browser_type("chrome") == "chrome150"
    assert resolve_latest_browser_type("firefox") == "firefox147"


def test_chrome_windows_http3_capabilities_keep_http2_as_default():
    fingerprint = curl_cffi.get_fingerprint("chrome153_win")

    assert fingerprint.http_version == "v2"
    assert fingerprint.split_cookies is True
    assert fingerprint.form_boundary == "webkit4"
    assert fingerprint.http3_tls_signature_hashes[-1] == "rsa_pkcs1_sha1"
    assert "mldsa44" in fingerprint.tls_signature_hashes
    assert "mldsa44" not in fingerprint.http3_tls_signature_hashes
    assert fingerprint.quic_initial_packet_number == 1
    assert "SHUFFLE:1,GREASE" in fingerprint.quic_transport_parameters
    assert "GREASE_CHROME" in fingerprint.quic_transport_parameters
    assert "12583:" not in fingerprint.quic_transport_parameters



def test_firefox_windows_http3_capabilities_are_protocol_specific():
    fingerprint = curl_cffi.get_fingerprint("firefox156_win")

    assert fingerprint.http_version == "v2"
    assert fingerprint.split_cookies is True
    assert fingerprint.http3_split_cookies is False
    assert fingerprint.form_boundary == "firefox4"
    assert fingerprint.headers["te"] == "trailers"
    assert "te" not in fingerprint.http3_headers
    assert "mldsa44" not in fingerprint.tls_signature_hashes
    assert "mldsa44" in fingerprint.http3_tls_signature_hashes
    assert fingerprint.quic_firefox_initial_packet_number is True
    assert fingerprint.quic_v2 is True
    assert "4278378010:1000" in fingerprint.quic_transport_parameters
