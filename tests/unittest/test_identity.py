import pytest

from curl_cffi import FingerprintSpec
from curl_cffi.requests.exceptions import ImpersonateError
from curl_cffi.requests.identity import (
    candidate_targets,
    resolve_fingerprint_spec,
    supported_platforms,
    version_sort_key,
)


def test_captured_platform_is_left_alone():
    """A target asked for its own platform must send exactly the bytes it captured."""
    for client, platform, target in [
        ("chrome", "linux", "chrome151"),
        ("chrome", "android", "chrome131_android"),
        ("firefox", "linux", "firefox152"),
        ("safari", "macos", "safari2601"),
        ("safari", "ios", "safari260_ios"),
        ("okhttp", "android", "okhttp54_android11"),
        ("tor", "macos", "tor145"),
    ]:
        spec = FingerprintSpec(client=client, platform=platform)
        assert resolve_fingerprint_spec(spec) == (target, {})


def test_chromium_cross_platform_headers():
    spec = FingerprintSpec(client="chrome", platform="windows")
    target, headers = resolve_fingerprint_spec(spec)
    assert target == "chrome151"
    assert headers["sec-ch-ua-platform"] == '"Windows"'
    assert headers["sec-ch-ua-mobile"] == "?0"
    assert headers["User-Agent"].startswith("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    # The templated version has to agree with the brand list baked into the target.
    assert "Chrome/151.0.0.0" in headers["User-Agent"]


def test_edge_keeps_its_own_brand_token():
    spec = FingerprintSpec(client="edge", platform="macos")
    target, headers = resolve_fingerprint_spec(spec)
    assert target == "edge101"
    assert headers["sec-ch-ua-platform"] == '"macOS"'
    assert headers["User-Agent"].endswith("Safari/537.36 Edg/101.0.0.0")


def test_firefox_sends_no_client_hints():
    spec = FingerprintSpec(client="firefox", platform="windows")
    target, headers = resolve_fingerprint_spec(spec)
    assert target == "firefox152"
    assert list(headers) == ["User-Agent"]
    assert headers["User-Agent"] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"  # noqa: E501


def test_version_pinning_selects_the_native_target():
    spec = FingerprintSpec(client="chrome", platform="macos", version="136")
    assert resolve_fingerprint_spec(spec) == ("chrome136", {})

    spec = FingerprintSpec(client="chrome", platform="windows", version="136")
    target, headers = resolve_fingerprint_spec(spec)
    assert target == "chrome136"
    assert "Chrome/136.0.0.0" in headers["User-Agent"]


def test_latest_strategy_picks_the_newest_target():
    """okhttp50a2 and okhttp51_android11 are also candidates, 5.4.0 has to win."""
    candidates = candidate_targets("okhttp", "android", None)
    assert {"okhttp50a2", "okhttp51_android11", "okhttp54_android11"} <= set(candidates)

    spec = FingerprintSpec(client="okhttp", platform="android")
    assert resolve_fingerprint_spec(spec) == ("okhttp54_android11", {})


def test_prerelease_sorts_below_the_matching_release():
    assert version_sort_key("5.0.0-alpha2") < version_sort_key("5.0.0")
    assert version_sort_key("5.0.0") < version_sort_key("5.1.0")
    assert version_sort_key("5.1.0") < version_sort_key("5.4.0")
    assert version_sort_key("26.0") < version_sort_key("26.0.1")
    assert version_sort_key("99") < version_sort_key("151")


def test_mobile_and_desktop_captures_do_not_cross_over():
    assert supported_platforms("chrome", "android") == {"android"}
    assert supported_platforms("safari", "ios") == {"ios"}
    # Safari has no cross-platform header template, so it stays on its capture.
    assert supported_platforms("safari", "macos") == {"macos"}
    assert supported_platforms("chrome", "linux") == {"windows", "macos", "linux"}


def test_unsupported_platform_raises_and_lists_alternatives():
    with pytest.raises(ImpersonateError, match="available platforms: ios, macos"):
        resolve_fingerprint_spec(FingerprintSpec(client="safari", platform="windows"))

    with pytest.raises(ImpersonateError, match="available platforms: android"):
        resolve_fingerprint_spec(FingerprintSpec(client="okhttp", platform="linux"))

    with pytest.raises(ImpersonateError, match="available platforms: android, linux, macos, windows"):  # noqa: E501
        resolve_fingerprint_spec(FingerprintSpec(client="chrome", platform="ios"))


def test_unknown_client_raises_and_lists_alternatives():
    with pytest.raises(ImpersonateError, match="available clients: chrome, edge"):
        resolve_fingerprint_spec(FingerprintSpec(client="opera", platform="windows"))


def test_unknown_version_raises_and_lists_alternatives():
    with pytest.raises(ImpersonateError, match="available versions: .*151"):
        resolve_fingerprint_spec(FingerprintSpec(client="chrome", platform="windows", version="999"))  # noqa: E501


def test_unimplemented_strategy_raises_instead_of_falling_back():
    spec = FingerprintSpec(client="chrome", platform="windows", strategy="uniform")
    with pytest.raises(ImpersonateError, match="uniform.*not implemented"):
        resolve_fingerprint_spec(spec)


def test_candidate_filtering_is_independent_of_selection():
    """Filtering is the seam a future selection strategy plugs into."""
    candidates = candidate_targets("chrome", "windows", None)
    assert "chrome151" in candidates
    assert "chrome99" in candidates
    assert "chrome131_android" not in candidates

    pinned = candidate_targets("chrome", "windows", "136")
    assert list(pinned) == ["chrome136"]
