from importlib import metadata

__title__ = "curl_cffi_patch"
__description__ = metadata.metadata("curl_cffi_patch")["Summary"]
__version__ = metadata.version("curl_cffi_patch")


def _resolve_curl_version() -> str:
    """Read libcurl version without creating a curl easy handle at import time."""
    from ._wrapper import ffi, lib

    return ffi.string(lib.curl_version()).decode()


__curl_version__ = _resolve_curl_version()
