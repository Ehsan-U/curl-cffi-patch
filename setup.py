import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from wheel.bdist_wheel import bdist_wheel


class bdist_wheel_abi3(bdist_wheel):
    def get_tag(self):
        python, abi, plat = super().get_tag()

        # Android extension modules link libpython3.X.so by SONAME, so they are not
        # stable-ABI across minor versions even though they are built against the
        # limited API. Keep the real tag there and ship one wheel per CPython minor,
        # otherwise pip installs the 3.13 wheel on 3.14 and the import fails, see #824.
        if (
            python.startswith("cp")
            and not (python.endswith("t") or abi.endswith("t"))
            and "android" not in plat
        ):
            # On CPython, our wheels are abi3 and compatible back to 3.10.
            # Free-threaded builds ("t" tag) must keep their original tags (PEP 803).
            # Once PEP 803 is accepted, we may be able to build abi3t wheels.
            return "cp310", "abi3", plat

        return python, abi, plat


class build_py_with_native_licenses(build_py):
    def run(self):
        super().run()
        extension = next(item for item in self.distribution.ext_modules if item.name == "curl_cffi._wrapper")  # noqa: E501
        native_dir = Path(extension.library_dirs[0])
        shutil.copytree(native_dir / "licenses", Path(self.build_lib) / "curl_cffi/native_licenses", dirs_exist_ok=True)  # noqa: E501


setup(
    # this option is only valid in setup.py
    cffi_modules=["scripts/build.py:ffibuilder"],
    cmdclass={
        "bdist_wheel": bdist_wheel_abi3,
        "build_py": build_py_with_native_licenses,
    },
)
