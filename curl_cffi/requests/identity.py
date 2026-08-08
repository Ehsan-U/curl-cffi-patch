"""Resolve a :class:`FingerprintSpec` into a concrete impersonate target.

Every impersonate target is a capture taken on one operating system, so the target
name alone decides the ``User-Agent`` and the client hints. This module lets callers
ask for a client on a platform instead, and keeps the resulting identity coherent.

A target always serves the platform it was captured on, with its own headers left
untouched. It additionally serves the other desktop platforms listed in
``CROSS_PLATFORM_HEADERS``, by overriding the few headers that carry the operating
system. Mobile captures are never re-targeted at a desktop platform, nor the other way
round, because those identities differ in TLS and HTTP/2 as well as in the user agent.
"""

import re

from ..fingerprints import Fingerprint, FingerprintManager, FingerprintSpec
from .exceptions import ImpersonateError

__all__ = [
    "CROSS_PLATFORM_HEADERS",
    "candidate_targets",
    "resolve_fingerprint_spec",
    "supported_platforms",
    "version_sort_key",
]


DESKTOP_PLATFORMS = {"windows", "macos", "linux"}


# Headers that carry the operating system, per client and platform. ``{version}`` is
# replaced with the major version of the resolved target, so the user agent always
# agrees with the ``sec-ch-ua`` brand list baked into that target.
# Clients absent from this table, such as safari and okhttp, can only be impersonated
# on the platform they were captured on.
CROSS_PLATFORM_HEADERS: dict[tuple[str, str], dict[str, str]] = {
    ("chrome", "windows"): {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",  # noqa: E501
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-mobile": "?0",
    },
    ("chrome", "macos"): {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",  # noqa: E501
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
    },
    ("chrome", "linux"): {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",  # noqa: E501
        "sec-ch-ua-platform": '"Linux"',
        "sec-ch-ua-mobile": "?0",
    },
    ("edge", "windows"): {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36 Edg/{version}.0.0.0",  # noqa: E501
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-mobile": "?0",
    },
    ("edge", "macos"): {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36 Edg/{version}.0.0.0",  # noqa: E501
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
    },
    ("edge", "linux"): {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36 Edg/{version}.0.0.0",  # noqa: E501
        "sec-ch-ua-platform": '"Linux"',
        "sec-ch-ua-mobile": "?0",
    },
    # Firefox sends no client hints, only the user agent carries the platform.
    ("firefox", "windows"): {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{version}.0) Gecko/20100101 Firefox/{version}.0",  # noqa: E501
    },
    ("firefox", "macos"): {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{version}.0) Gecko/20100101 Firefox/{version}.0",  # noqa: E501
    },
    ("firefox", "linux"): {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:{version}.0) Gecko/20100101 Firefox/{version}.0",  # noqa: E501
    },
}


def version_sort_key(version: str) -> tuple[tuple[int, ...], int]:
    """Order version strings, keeping pre-releases below the matching release."""
    release, _, pre_release = version.partition("-")
    numbers = tuple(int(part) for part in re.findall(r"\d+", release))
    return numbers, 0 if pre_release else 1


def supported_platforms(client: str, captured_platform: str) -> set[str]:
    """Return the platforms a target captured on ``captured_platform`` can serve."""
    if captured_platform not in DESKTOP_PLATFORMS:
        return {captured_platform}
    return {captured_platform} | {p for c, p in CROSS_PLATFORM_HEADERS if c == client}


def candidate_targets(
    client: str, platform: str, version: str | None
) -> dict[str, Fingerprint]:
    """Return every target able to impersonate ``client`` on ``platform``.

    Raises ``ImpersonateError`` describing the available alternatives when nothing
    matches. Selecting among the candidates is left to the caller, so that future
    selection strategies do not have to repeat the filtering.
    """
    fingerprints = FingerprintManager.load_fingerprints()

    by_client = {n: f for n, f in fingerprints.items() if f.client.lower() == client}
    if not by_client:
        available = sorted({f.client.lower() for f in fingerprints.values() if f.client})  # noqa: E501
        raise ImpersonateError(f"Impersonating client {client} is not supported, available clients: {', '.join(available)}")  # noqa: E501

    by_platform = {n: f for n, f in by_client.items() if platform in supported_platforms(client, f.os.lower())}  # noqa: E501
    if not by_platform:
        available = sorted({p for f in by_client.values() for p in supported_platforms(client, f.os.lower())})  # noqa: E501
        raise ImpersonateError(f"Impersonating {client} on {platform} is not supported, available platforms: {', '.join(available)}")  # noqa: E501

    if version is None:
        return by_platform

    by_version = {n: f for n, f in by_platform.items() if f.client_version == version}
    if not by_version:
        versions = {f.client_version for f in by_platform.values()}
        available = sorted(versions, key=version_sort_key)
        raise ImpersonateError(f"Impersonating {client} {version} on {platform} is not supported, available versions: {', '.join(available)}")  # noqa: E501
    return by_version


def resolve_fingerprint_spec(spec: FingerprintSpec) -> tuple[str, dict[str, str]]:
    """Resolve a spec into a target name and the headers that re-platform it.

    The headers are empty when the target was captured on the requested platform, so
    that path sends exactly the same bytes as passing the target name directly.
    """
    if spec.strategy != "latest":
        raise ImpersonateError(f"Fingerprint selection strategy {spec.strategy} is not implemented yet")  # noqa: E501

    client, platform = spec.client.lower(), spec.platform.lower()
    candidates = candidate_targets(client, platform, spec.version)
    # Break version ties on the target name so the choice never depends on dict order.
    target = max(candidates, key=lambda name: (version_sort_key(candidates[name].client_version), name))  # noqa: E501

    fingerprint = candidates[target]
    if fingerprint.os.lower() == platform:
        return target, {}

    major_version = fingerprint.client_version.partition(".")[0]
    headers = CROSS_PLATFORM_HEADERS[(client, platform)]
    return target, {k: v.format(version=major_version) for k, v in headers.items()}
