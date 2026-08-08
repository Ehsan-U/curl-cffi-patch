Consistent identity
===================

Every impersonate target is a capture taken on one operating system. ``chrome151`` was
captured on Linux, so it sends a Linux ``User-Agent`` and ``sec-ch-ua-platform: "Linux"``;
``chrome146`` was captured on macOS. Passing your own ``User-Agent`` only replaces that one
header, leaving the client hints behind to contradict it.

``FingerprintSpec`` lets you ask for a client on a platform instead of by target name, and
keeps the whole identity coherent. It is opt-in; passing a target name works exactly as
before.

.. code-block:: python

   from curl_cffi import requests, FingerprintSpec

   # Chrome, but reported as running on Windows
   requests.get(url, impersonate=FingerprintSpec(client="chrome", platform="windows"))

   # Pin a version instead of taking the newest
   requests.get(url, impersonate=FingerprintSpec(client="chrome", platform="macos", version="136"))

   # Works anywhere impersonate= is accepted
   session = requests.Session(impersonate=FingerprintSpec(client="firefox", platform="linux"))

Fields
------

.. list-table::
   :header-rows: 1

   * - Field
     - Meaning
   * - ``client``
     - Which client to impersonate, e.g. ``chrome``, ``firefox``, ``edge``, ``safari``,
       ``tor``, ``okhttp``. Required.
   * - ``platform``
     - ``windows``, ``macos``, ``linux``, ``android`` or ``ios``. Required.
   * - ``version``
     - Pin a specific version, e.g. ``"136"``. Defaults to the newest target that can serve
       the platform.
   * - ``strategy``
     - How to choose among the matching targets. Only ``"latest"`` is implemented.

How a target is chosen
----------------------

A target always serves the platform it was captured on, and in that case its headers are
sent untouched — the request is byte for byte what you would get from passing the target
name directly.

For the other desktop platforms, the few headers that carry the operating system are
overridden: ``User-Agent`` for every client, plus ``sec-ch-ua-platform`` and
``sec-ch-ua-mobile`` for Chromium-based ones. Firefox sends no client hints, so only its
user agent changes. The version templated into the user agent is taken from the resolved
target, so it always agrees with the ``sec-ch-ua`` brand list that target ships.

TLS and HTTP/2 fingerprints are **not** affected by the platform. Desktop Chrome shares one
TLS stack across Windows, macOS and Linux, so the JA3/JA4 hash of
``FingerprintSpec(client="chrome", platform="windows")`` is identical to that of
``impersonate="chrome151"``.

Mobile captures are never re-targeted at a desktop platform, nor the other way round —
those identities differ in TLS and HTTP/2, not just in a user agent token. Mobile platforms
resolve to dedicated targets instead, such as ``chrome131_android`` and ``safari260_ios``.

Nothing is chosen silently
--------------------------

A combination that no target can serve raises ``ImpersonateError`` naming the alternatives,
rather than quietly falling back to a different platform:

.. code-block:: python

   >>> requests.get(url, impersonate=FingerprintSpec(client="safari", platform="windows"))
   ImpersonateError: Impersonating safari on windows is not supported, available platforms: ios, macos

   >>> requests.get(url, impersonate=FingerprintSpec(client="okhttp", platform="linux"))
   ImpersonateError: Impersonating okhttp on linux is not supported, available platforms: android

The same applies to an unknown client, an unknown version, and to
``strategy="uniform"``, which is reserved for a future automatic selection mode and is not
implemented yet.

Precedence
----------

A header you set explicitly always wins over the platform override, which in turn wins over
the target's own default:

.. code-block:: python

   r = requests.get(
       url,
       impersonate=FingerprintSpec(client="chrome", platform="windows"),
       headers={"User-Agent": "mine"},
   )
   # User-Agent: mine, but sec-ch-ua-platform is still "Windows"

With ``default_headers=False`` no impersonation headers are sent at all, so the platform
overrides are skipped too. The target is still used for the TLS and HTTP/2 fingerprint.

Which platforms each client supports
------------------------------------

Depends on the targets available to you, including any from ``curl_cffi pro update``. The
built-in set supports:

.. list-table::
   :header-rows: 1

   * - Client
     - Platforms
   * - ``chrome``
     - ``windows``, ``macos``, ``linux``, ``android``
   * - ``edge``
     - ``windows``, ``macos``, ``linux``
   * - ``firefox``
     - ``windows``, ``macos``, ``linux``
   * - ``safari``
     - ``macos``, ``ios``
   * - ``tor``
     - ``macos``
   * - ``okhttp``
     - ``android``
