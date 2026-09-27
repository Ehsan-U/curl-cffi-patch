import json
import os
import platform
import struct
import sys
import subprocess
from pathlib import Path

from cffi import FFI

# this is the upstream libcurl-impersonate version
__version__ = "2.2.2"


def is_android_env() -> bool:
    return bool(
        sys.platform == "android"
        or os.environ.get("CIBW_PLATFORM") == "android"
        or os.environ.get("ANDROID_ROOT")
        or os.environ.get("ANDROID_DATA")
        or os.environ.get("TERMUX_VERSION")
    )


def detect_arch():
    with open(Path(__file__).parent.parent / "libs.json") as f:
        archs = json.loads(f.read())

    uname = platform.uname()
    uname_system = "Android" if is_android_env() else uname.system
    glibc_flavor = "gnueabihf" if uname.machine in ["armv7l", "armv6l"] else "gnu"

    libc, _ = platform.libc_ver()
    # https://github.com/python/cpython/issues/87414
    libc = glibc_flavor if libc == "glibc" else "musl"
    if is_android_env():
        libc = "android"
    pointer_size = struct.calcsize("P") * 8

    for arch in archs:
        if (
            arch["system"] == uname_system
            and arch["machine"] == uname.machine
            and arch["pointer_size"] == pointer_size
            and ("libc" not in arch or arch.get("libc") == libc)
        ):
            if build_dir := os.environ.get("IMPERSONATE_BUILD_DIR"):
                arch["libdir"] = os.path.expanduser(build_dir)
            else:
                arch["libdir"] = str(Path.home() / ".cache/curl-cffi-patch/native" / f"{uname_system}-{uname.machine}-{libc}")  # noqa: E501
            return arch
    raise Exception(f"Unsupported arch: {uname}")


def get_link_type(arch):
    link_type = os.environ.get("IMPERSONATE_LINK_TYPE", arch.get("link_type"))
    if link_type not in ("static", "dynamic"):
        raise ValueError(
            "IMPERSONATE_LINK_TYPE must be either 'static' or 'dynamic', "
            f"not {link_type!r}"
        )
    return link_type


def get_obj_name(arch, link_type):
    if link_type == arch.get("link_type"):
        return arch["obj_name"]
    if link_type == "static":
        if arch["system"] == "Windows":
            raise ValueError("Static linking is not supported on Windows")
        return "libcurl-impersonate.a"
    if arch["system"] == "Darwin":
        return "libcurl-impersonate.dylib"
    if arch["system"] == "Linux":
        return "libcurl-impersonate.so"
    return "libcurl-impersonate.dll"


arch = detect_arch()
link_type = get_link_type(arch)
obj_name = get_obj_name(arch, link_type)
libdir = Path(arch["libdir"])
is_static = link_type == "static"
is_dynamic = link_type == "dynamic"
is_android = arch.get("libc") == "android"
print(f"Using {libdir} to store libcurl-impersonate")


def prepare_libcurl():
    if os.environ.get("CURL_CFFI_BUILD_SDIST") == "1":
        return
    if not is_static:
        raise ValueError("Patched native builds require IMPERSONATE_LINK_TYPE=static")
    subprocess.run([sys.executable, str(root_dir / "scripts/build_native.py"), str(libdir)], check=True)  # noqa: E501


def get_curl_archives():
    if is_static:
        # note that the order of libraries matters
        # https://stackoverflow.com/a/36581865
        return [str(libdir / obj_name)]
    else:
        return []


def get_curl_libraries():
    if arch["system"] == "Windows":
        return [
            "Crypt32",
            "Secur32",
            "wldap32",
            "Normaliz",
            "libcurl-impersonate_imp",
            "iphlpapi",
        ]
    elif is_dynamic:
        return ["curl-impersonate"]
    else:
        return []


ffibuilder = FFI()
system = platform.system()
root_dir = Path(__file__).parent.parent
prepare_libcurl()

# With mega archive, we only have one to link
static_libs = get_curl_archives()
extra_link_args = []
if is_static:
    if system == "Darwin":
        extra_link_args = [
            f"-Wl,-force_load,{static_libs[0]}",
            "-lc++",
            "-framework", "CoreFoundation",
            "-framework", "Security",
            "-framework", "SystemConfiguration",
            "-liconv",
            "-licucore",
        ]
    elif is_android:
        extra_link_args = [
            "-Wl,--whole-archive",
            static_libs[0],
            "-Wl,--no-whole-archive",
            "-lc++",
        ]
    elif system == "Linux":
        extra_link_args = [
            "-Wl,--whole-archive",
            static_libs[0],
            "-Wl,--no-whole-archive",
        ]

libraries = get_curl_libraries()

ffibuilder.set_source(
    "curl_cffi._wrapper",
    """
        #include "shim.h"
    """,
    library_dirs=[str(libdir)],
    runtime_library_dirs=(
        [str(libdir)] if is_dynamic and arch["system"] != "Windows" else []
    ),
    libraries=get_curl_libraries(),
    extra_objects=[],  # linked via extra_link_args
    source_extension=".c",
    include_dirs=[
        str(libdir / "include"),
        str(root_dir / "ffi"),
    ],
    sources=[
        str(root_dir / "ffi/shim.c"),
    ],
    extra_compile_args=(
        ["-Wno-implicit-function-declaration"] if system == "Darwin" else []
    ),
    extra_link_args=extra_link_args,
)

with open(root_dir / "ffi/cdef.c") as f:
    cdef_content = f.read()
    ffibuilder.cdef(cdef_content)


if __name__ == "__main__":
    ffibuilder.compile(verbose=False)
