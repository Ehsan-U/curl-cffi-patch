import json
import os

import pytest

import curl_cffi
from curl_cffi.fingerprints import FingerprintManager, _get_default_config_dir
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
