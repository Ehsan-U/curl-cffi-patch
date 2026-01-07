from importlib import metadata

from .curl import Curl

__title__ = "curl_cffi_patch"
__description__ = metadata.metadata("curl_cffi_patch")["Summary"]
__version__ = metadata.version("curl_cffi_patch")
__curl_version__ = Curl().version().decode()
