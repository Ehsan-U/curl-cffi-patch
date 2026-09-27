import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import urlretrieve


SOURCE_URL = "https://github.com/lexiforest/curl-impersonate/archive/refs/tags/v2.2.2.tar.gz"  # noqa: E501
SOURCE_SHA256 = "ac5dea9ac6f20f8061a26b9f5dea93a80ad9da18d04d24f9fb528ec26a0693bd"
ROOT = Path(__file__).resolve().parents[1]
PATCHES = [ROOT / "ffi/patches" / f"{name}-windows-fingerprints.patch" for name in ("curl", "boringssl", "ngtcp2")]  # noqa: E501


def run(*args, **kwargs):
    subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def build(libdir):
    system, machine = platform.system(), platform.machine()
    if (system, machine) not in {("Linux", "x86_64"), ("Linux", "aarch64"), ("Darwin", "arm64")}:  # noqa: E501
        raise RuntimeError("Patched native builds support Linux x86_64/ARM64 and macOS ARM64")  # noqa: E501
    digest = hashlib.sha256(Path(__file__).read_bytes())
    for patch in PATCHES:
        digest.update(patch.read_bytes())
    identity = {"source_sha256": SOURCE_SHA256, "patches_and_builder_sha256": digest.hexdigest(), "system": system, "machine": machine, "libc": platform.libc_ver()[0], "deployment_target": os.environ.get("MACOSX_DEPLOYMENT_TARGET", "11.0") if system == "Darwin" else ""}  # noqa: E501
    libdir = libdir.resolve()
    marker = libdir / "native-build.json"
    archive = libdir / "libcurl-impersonate.a"
    if marker.exists() and json.loads(marker.read_text()) == identity and archive.exists() and (libdir / "include/curl/curl.h").exists():  # noqa: E501
        print(f"Using verified patched native archive: {archive}", flush=True)
        return
    libdir.mkdir(parents=True, exist_ok=True)
    make = "gmake" if system == "Darwin" else "make"
    with tempfile.TemporaryDirectory(prefix="curl-cffi-native-") as temporary:
        work = Path(temporary)
        source, output, install = work / "source", work / "build", work / "install"
        source.mkdir()
        source_archive = work / "source.tar.gz"
        urlretrieve(SOURCE_URL, source_archive)
        if hashlib.sha256(source_archive.read_bytes()).hexdigest() != SOURCE_SHA256:
            raise RuntimeError("Native source archive checksum mismatch")
        run("tar", "-xf", source_archive, "-C", source, "--strip-components=1")
        for patch in PATCHES:
            upstream = source / "patches" / patch.name.replace("-windows-fingerprints", "")  # noqa: E501
            with upstream.open("ab") as file:
                file.write(patch.read_bytes())
        env = os.environ.copy()
        cmake_args = []
        if system == "Linux":
            run(make, "-C", source, "prepare-libidn2", f"BUILD_DIR={output}", "JOBS=4", env=env)  # noqa: E501
            env["PKG_CONFIG_LIBDIR"] = str(output / "deps/install/lib/pkgconfig")
        else:
            cmake_args = [f"-DCMAKE_OSX_DEPLOYMENT_TARGET={identity['deployment_target']}", "-DCMAKE_OSX_ARCHITECTURES=arm64"]  # noqa: E501
        run("cmake", "-S", source, "-B", output, "-G", "Unix Makefiles", f"-DCMAKE_MAKE_PROGRAM={shutil.which(make)}", f"-DCMAKE_INSTALL_PREFIX={install}", "-DSUBJOBS=4", *cmake_args, env=env)  # noqa: E501
        run("cmake", "--build", output, "--parallel", "2", env=env)
        run(make, "-C", source, "checkbuild", f"BUILD_DIR={output}", env=env)
        run("cmake", "--install", output, env=env)
        libraries = [install / "lib/libcurl-impersonate.a"]
        names = ["z", "zstd", "brotlidec", "brotlicommon", "brotlienc", "nghttp2", "nghttp3", "ngtcp2", "ngtcp2_crypto_boringssl", "ssl", "crypto"]  # noqa: E501
        if system == "Linux":
            names.append("idn2")
        libraries.extend(output / f"deps/install/lib/lib{name}.a" for name in names)
        combined = work / "libcurl-impersonate.a"
        if system == "Darwin":
            run("/usr/bin/libtool", "-static", "-o", combined, *libraries)
        else:
            runtimes = [subprocess.check_output([compiler, f"-print-file-name={name}"], text=True).strip() for compiler, name in [("g++", "libstdc++.a"), ("gcc", "libgcc_eh.a"), ("gcc", "libgcc.a")]]  # noqa: E501
            run("gcc", "-r", "-o", work / "combined.o", "-Wl,--whole-archive", *libraries, "-Wl,--no-whole-archive", "-Wl,--start-group", *runtimes, "-Wl,--end-group")  # noqa: E501
            run("ar", "rcs", combined, work / "combined.o")
        shutil.copytree(install / "include", libdir / "include", dirs_exist_ok=True)
        (libdir / "licenses").mkdir(exist_ok=True)
        for license_file in install.glob("LICENSE*"):
            shutil.copy2(license_file, libdir / "licenses" / license_file.name)
        if system == "Linux":
            runtime_license = libdir / "licenses/LICENSE_GCC_RUNTIME_EXCEPTION"
            urlretrieve("https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-14/COPYING.RUNTIME", runtime_license)  # noqa: E501
            if hashlib.sha256(runtime_license.read_bytes()).hexdigest() != "9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74":  # noqa: E501
                raise RuntimeError("GCC runtime license checksum mismatch")
        shutil.copy2(combined, archive)
        marker.write_text(json.dumps(identity, indent=2) + "\n")
        print(f"Built patched native archive: {archive}", flush=True)


if __name__ == "__main__":
    build(Path(sys.argv[1]))
