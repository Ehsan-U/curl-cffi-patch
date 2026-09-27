Captured Windows 11 profiles
============================

``chrome153_win`` and ``firefox156_win`` reproduce fresh-session TLS-over-TCP
and HTTP/2 profiles captured from Chrome 153.0.8010.48 and Firefox 156.0 on
Windows 11 Pro 25H2, build 26200.8037. They are explicit targets; ``chrome`` and
``firefox`` retain their existing aliases. Both profiles also include captured
cookie handling, multipart boundaries, and HTTP/3 support. Their default
HTTP-version metadata remains ``v2``; select HTTP/3 explicitly when needed.

.. code-block:: python

    from curl_cffi import requests

    chrome = requests.get("https://tls.peet.ws/api/all", impersonate="chrome153_win", http_version="v2")
    firefox = requests.get("https://tls.peet.ws/api/all", impersonate="firefox156_win", http_version="v2")
    http3 = requests.get("https://fp.impersonate.pro/api/http3", impersonate="firefox156_win", http_version="v3only")

Native library requirement
--------------------------

These profiles require the supplemental patches in ``ffi/patches/`` on top of
curl-impersonate **v2.2.2**. Wheels produced by this repository's build workflow
statically bundle that patched library. They do not depend on system curl or
an Impersonate Pro subscription. Older published releases do not acquire these
profiles automatically; publishing requires a new package version and release tag.
The upstream v2.2.2 binary alone is insufficient. Other profiles do not set the
new options.

The patches add:

* ``TLS_GREASE_SIGNATURE_ALGORITHMS`` (1041): Chrome's GREASE signature scheme.
* ``HTTP2_FIRST_STREAM_ID`` (1042): Firefox's first request stream, 3.
* ``TLS_REUSE_X25519_KEY_SHARE`` (1043): NSS-style reuse of the hybrid share's
  X25519 key for the standalone X25519 share, including its private key so a
  server selecting either share can complete the handshake.
* ``TLS_ECH_GREASE_PAYLOAD_SIZE`` (1044): Firefox's captured 240-byte GREASE ECH
  payload. Zero retains BoringSSL's randomized padding.
* ``QUIC_INITIAL_PACKET_NUMBER`` (1045): Chrome's initial packet number, 1.
  Zero preserves the previous ngtcp2 default.

The TCP-specific TLS controls are opt-in, are isolated in connection/session-cache
configuration, and do not alter QUIC. Firefox's HTTP/3 controls are separate:

* ``HTTP3_TLS_REUSE_X25519_KEY_SHARE`` (1046) and
  ``HTTP3_TLS_ECH_GREASE_PAYLOAD_SIZE`` (1047) apply the captured NSS key-share
  relationship and 240-byte GREASE ECH payload to QUIC.
* ``HTTP3_SSL_CERT_COMPRESSION`` (1048) and
  ``HTTP3_TLS_DELEGATED_CREDENTIALS`` (1049) configure QUIC's different algorithm
  lists without changing the TCP ClientHello.
* ``QUIC_FIREFOX_INITIAL_PACKET_NUMBER`` (1050) randomizes only the Initial
  packet-number space using Neqo's distribution: 1-1024, mostly 1-32.
  Handshake and application spaces still start at zero. The supplemental ngtcp2
  patch provides an initialization-only API and per-space ACK validation.
* ``HTTP3_SPLIT_COOKIES`` (1051) overrides cookie splitting for HTTP/3;
  its default -1 inherits the existing setting.
* ``HTTP3_ALT_USED`` (1052) generates Alt-Used from the connection authority,
  omitting port 443. Explicit caller values take precedence.
* ``QUIC_V2`` (1053) enables compatible QUIC v2 negotiation. Firefox advertises
  v2 in its version-information parameter, so the transport must support a
  server choosing it.

Unset controls preserve existing profiles. TLS overrides participate in
connection/session-cache configuration. The native library now needs all three
supplemental patches: curl, BoringSSL, and ngtcp2.
Chrome's 28 captured trust-anchor IDs use v2.2.2's existing
``TLS_TRUST_ANCHORS`` option, which shuffles their wire order.
The new option numbers belong to this patch; recheck them before rebasing onto
another curl-impersonate version.

Cookie and multipart behavior
-----------------------------

``chrome153_win`` sets ``split_cookies=True``. Cookies supplied through
``cookies=`` or the session cookie jar are emitted as separate cookie fields on
HTTP/2 and HTTP/3, placed before ``priority``. Cookie selection and ordering remain
libcurl cookie-jar behavior. An explicitly supplied ``Cookie`` header remains
caller-controlled and is not split.

The profile uses ``form_boundary="webkit4"``. This new opt-in mode produces the
captured ``----WebKitFormBoundary`` prefix plus 16 random alphanumeric characters.
The body delimiter adds the normal two leading hyphens. The old ``webkit`` mode
has two extra hyphens in its boundary value; it is preserved for compatibility
with existing profiles. Tests compare the entire captured multipart body after
normalizing only the random boundary suffix.

``firefox156_win`` splits cookies on HTTP/2 and keeps one combined cookie field
on HTTP/3. Its ``form_boundary="firefox4"`` produces the captured
``----geckoformboundary`` prefix plus 32 random lowercase hexadecimal characters.
Legacy ``firefox`` mode keeps its previous six-hyphen prefix. Firefox cookie
fields precede ``upgrade-insecure-requests`` for navigation. As with Chrome,
cookie-pair ordering remains libcurl behavior, and explicit Cookie headers are
preserved.

Use ``CurlMime`` for multipart requests. Default profile headers describe a
top-level navigation; provide the appropriate Origin, Referer, fetch metadata,
priority, and header order when reproducing another browser request context.

HTTP/3 behavior
---------------

Chrome 153 was observed using HTTP/3 after normal Alt-Svc discovery. A fresh
HTTP/3-first capture was also taken using Chrome's force-QUIC origin option.
The cold profile includes the captured HTTP/3 settings, HTTP/3-specific signature
algorithms, the trust-anchor extension, connection ID lengths, and QUIC transport
parameters. Cookies and multipart bodies were captured on a local HTTP/3 server;
its test certificate was allowed only for that server's SPKI during the capture.
The temporary Windows test CA and hosts entry were removed afterward.

The QUIC transport-parameter syntax now accepts two opt-in forms:

* ``17:1@SHUFFLE:1,GREASE`` varies the GREASE version's position when creating a
  connection, matching Chrome. It leaves the configured string stable so existing
  connections can be reused.
* ``GREASE_CHROME`` generates a reserved transport parameter with 0-15 bytes of
  random data, matching Quiche. The zero-length case returns success without
  calling curl's random-byte generator, which rejects an empty request.
  Existing ``GREASE`` behavior is unchanged.

The HTTP/3 TLS signature list differs from TCP: it contains the captured classical
algorithms including ``rsa_pkcs1_sha1``, and does not contain the TCP ML-DSA or GREASE
signature entries. ``http3_tls_signature_hashes`` configures this list separately.
Chrome uses ``http3_tls_extension_order="SHUFFLE:12:..."`` to shuffle all 12
captured extensions on each handshake. The generic permutation flag is disabled:
a plain explicit order takes precedence over that flag and would freeze the
wire order. The regression test checks multiple fresh ClientHellos, not only
JA3N, which sorts the extensions and cannot detect a frozen order.

The profile models a cold QUIC connection. Chrome's warm Alt-Svc capture also
included a cached initial-RTT transport parameter (12583); the cold capture did
not. The profile omits it instead of manufacturing an RTT estimate. HTTP/3 settings
are advertised by the profile catalog without changing the default HTTP version.

Firefox HTTP/3 specifics
------------------------

Firefox 156 was captured both after natural Alt-Svc discovery and with a fresh
profile using Firefox's test Alt-Svc mapping. Cookie and multipart requests were
also captured against a controlled local HTTP/3 server. The temporary Windows
CA and hosts entry were removed, and the retained VM was shut down.

The HTTP/3 signature list includes ML-DSA-44/65/87; Firefox's captured TCP list
does not. HTTP/3 certificate compression is ordered zlib, zstd, brotli, and its
delegated-credential list also includes ML-DSA. The native extension-order syntax
``SHUFFLE:13:...`` shuffles the first 13 listed TLS extensions on each handshake,
leaving QUIC transport parameters and GREASE ECH at the end. TCP order stays fixed.
The X25519 key is freshly generated for each handshake and shared only between
that handshake's hybrid and standalone key shares.

Firefox's HTTP/3 navigation headers use pseudo-header order ``m,s,a,p``, include
``alt-used``, and omit ``te``. Explicit request headers override HTTP/3 defaults;
when editing a fingerprint's default headers, update ``http3_headers`` as well.

The QUIC version list is GREASE, v2, v1, with initial version v1. Client connection
IDs are 3 bytes; initial destination IDs follow Neqo's 8-20 byte distribution.
Transport parameter 0xff02de1a contains min_ack_delay=1000 microseconds. The public
fingerprint endpoint labels this parameter GREASE because its number falls in a
reserved pattern; it is a fixed captured parameter, not randomized GREASE.
Parameter 29 is an empty RESET_STREAM_AT advertisement.

Both parameters are preserved in the reference capture but intentionally omitted
from ``firefox156_win``: the pinned transport cannot handle the corresponding
ACK_FREQUENCY and RESET_STREAM_AT frames. Advertising support can cause otherwise
valid HTTP/3 connections to fail when a server exercises either extension.
HTTP/3 remains supported without these optional capabilities; its QUIC fingerprint
therefore differs from Firefox 156 in these two parameters. HTTP/2 and Chrome's
configuration are unchanged.

Restore these advertisements only after implementing and validating the behavior,
tracking upstream `ACK_FREQUENCY <https://github.com/ngtcp2/ngtcp2/pull/1348>`_
and `reliable stream reset <https://github.com/ngtcp2/ngtcp2/pull/1097>`_.

Wheels and source builds
------------------------

The wheel matrix covers Linux x86_64 and ARM64 (manylinux2014 and musllinux), and
macOS ARM64 (Apple Silicon, macOS 11+). Regular CPython wheels use the stable ABI
for Python 3.10+; CPython 3.14 free-threaded builds have separate wheels. Windows,
macOS Intel, and other architectures are outside this distribution's build matrix.

Every wheel is installed into an isolated environment for unit tests and local
TLS/HTTP2 requests with both Windows profiles. These checks apply the profiles'
HTTP/3 native options as well, preventing an unpatched upstream library from
passing. The native manylinux and macOS abi3 wheels additionally run the local
HTTP/2 and HTTP/3 integration suites on their host runners. Live public collectors
are excluded from CI to avoid making release builds depend on external uptime.

Source installs also build the patched native library rather than downloading
an unpatched binary. They require CMake 3.20+, Ninja, GNU make, a C/C++ compiler,
``patch``, ``tar``, autotools, and pkg-config. Linux needs GCC/G++ and GNU ``ar``;
macOS uses the Xcode toolchain, Apple ``libtool``, and Homebrew ``gmake``.
The native project archive is checksum verified and cached with the patch/build
identity. Dependency license files are included in each wheel.

For an editable installation, activate the intended virtual environment and use
an absolute build directory outside the checkout:

.. code-block:: bash

    source .venv/bin/activate
    bash scripts/build_windows_fingerprints.sh /path/to/windows-fingerprint-build

The helper downloads the pinned native source, appends the three supplemental
patches to its upstream patchsets, builds all dependencies, verifies the native
binary's features, and installs an editable Python binding linked to a combined
static archive. It does not replace system curl, install system-wide libraries,
or start the Windows VM. Keep the archive directory if you will rebuild later.
The native build generates the patched headers used by the binding.

After the initial build, reinstall against the same archive with:

.. code-block:: bash

    IMPERSONATE_BUILD_DIR=/path/to/windows-fingerprint-build/archive \
      IMPERSONATE_LINK_TYPE=static uv pip install --reinstall-package curl-cffi-patch -e '.[test,dev,integration]'

When switching native archives, use a fresh Python build directory so a cached
extension cannot retain the previous library. ``IMPERSONATE_BUILD_DIR`` selects
the directory containing the archive, headers, licenses, and ``native-build.json``.
Without an override, source builds use a cache under
``~/.cache/curl-cffi-patch/native/``. Builds regenerate archives when the native
builder or patches change and do not fall back to upstream binaries.

CI builds the source distribution with ``CURL_CFFI_BUILD_SDIST=1`` to avoid
embedding host-specific artifacts. That flag is only for producing the source
archive, not for compiling a wheel.

Verification and scope
----------------------

The reference captures were made passively at the Windows VM's network
interface. Browser TLS key logs decrypted the packets without TLS interception.
Two successful fresh-profile captures per browser were checked. Sanitized
reference fields are in ``tests/fixtures/windows_fingerprints.json``; TLS secrets,
random key material, session IDs, IP addresses, and VM credentials are excluded.
Additional Chrome capability references are in
``tests/fixtures/chrome153_win_capabilities.json``; Firefox references are in
``tests/fixtures/firefox156_win_capabilities.json``.

.. list-table:: Captured TLS fingerprints
   :header-rows: 1

   * - Target
     - JA4
     - Peetprint hash
   * - ``chrome153_win``
     - ``t13d1517h2_8daaf6152771_cb7bf5808d99``
     - ``fc97c1cdfb1409c9a9326c1b726d1dee``
   * - ``firefox156_win``
     - ``t13d1517h2_8daaf6152771_3cbfd9057e0d``
     - ``a4bbbc7e3adf3db97d276fd0adb1efc4``

Chrome permutes TLS extensions, so its JA3 hash varies. Wireshark 4.6.4 also
includes a GREASE signature value when computing Chrome's JA4. The values above
exclude GREASE as required by the `JA4 specification
<https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>`_ and match the
server-observed values.

The ``integration`` extra supplies aioquic and h2 for the local protocol servers;
the ordinary ``test`` extra used by wheel CI does not need these dependencies.
The build helper installs all three extras. Run the capture comparison and local
TLS key-share fallback tests after building:

.. code-block:: bash

    uv run --no-sync python -m pytest tests/integration/test_windows_fingerprints.py tests/integration/test_chrome_capabilities.py tests/integration/test_firefox_capabilities.py
    uv run --no-sync make test PYTHON=python

The capture tests compare TLS fingerprints, key-share sizes and reuse, trust
anchor contents, GREASE ECH padding, and the complete reported HTTP/2 SETTINGS,
WINDOW_UPDATE, HEADERS, stream IDs, priorities, and header order. Local TLS 1.3
servers also verify handshakes when selecting X25519 or P-256. Local HTTP/2 and
HTTP/3 servers verify cookie fields, multipart bodies, explicit-header handling,
and connection reuse. HTTP/3 wire comparison includes initial packet numbers,
connection ID lengths, signature algorithms, transport parameters, settings,
and request headers. The local Firefox HTTP/3 test also verifies a server choosing
QUIC v2. The ngtcp2 patch includes a native test for Initial-only packet numbering
and rejection of changes after transmission.

This reproduces the captured fresh-session request profile. It does not emulate
Windows's TCP/IP stack or JavaScript, fonts, canvas, or GPU behavior.
These are fresh-request fingerprints; the underlying transport remains ngtcp2.
Packet scheduling and draft ACK_FREQUENCY/RESET_STREAM_AT behavior are not
reproduced or validated. Their transport-parameter advertisements are deliberately
omitted, as documented above; the profile does not implement Neqo's complete
state machine.
WebSockets, resumed-session fingerprints, 0-RTT, and site-specific browser state
were not captured or validated. The Firefox GREASE ECH size is the captured baseline,
not a general NSS inner-ClientHello padding implementation for every hostname
and resumption state.
