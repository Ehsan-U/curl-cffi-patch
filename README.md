# curl_cffi_patch

A patched version of [curl_cffi](https://github.com/lexiforest/curl_cffi), tracking upstream `main` with the following patches on top:

- **Fix resolve-list memory leak** in `Curl.reset()` — see [issue #677](https://github.com/lexiforest/curl_cffi/issues/677).
- **Add `CURLOPT_CONNECT_TO` support** — `setopt` builds a proper curl slist for `CONNECT_TO` (like `RESOLVE`/`HTTPHEADER`) instead of segfaulting, and the slist is freed in `clean_handles_and_buffers()` and `reset()`. Lets you pin a request's origin host/port (e.g. through a CONNECT proxy) via `curl_options={CurlOpt.CONNECT_TO: ["host:port:target:port"]}`.
