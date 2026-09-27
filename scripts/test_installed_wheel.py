import os
import subprocess
import sys
from pathlib import Path


root = Path(__file__).resolve().parents[1]
wheels = [p.resolve() for p in Path(sys.argv[1]).glob("*cp310-abi3*.whl") if "musllinux" not in p.name]  # noqa: E501
if len(wheels) != 1:
    raise RuntimeError(f"Expected one native abi3 wheel, found {wheels}")
python = Path(sys.argv[2]).resolve() / "bin/python"
subprocess.run(["uv", "pip", "install", "--python", str(python), f"{wheels[0]}[test,integration]"], check=True)  # noqa: E501
subprocess.run([str(python), "-c", "import curl_cffi,sys; from pathlib import Path; assert Path(curl_cffi.__file__).is_relative_to(Path(sys.prefix)); print(curl_cffi.__file__)"], cwd=python.parent, check=True)  # noqa: E501
subprocess.run([str(python), "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", str(root / "tests/integration/test_windows_fingerprints.py"), str(root / "tests/integration/test_chrome_capabilities.py"), str(root / "tests/integration/test_firefox_capabilities.py"), "-k", "not matches_capture"], cwd=python.parent, env=os.environ | {"PYTHONDONTWRITEBYTECODE": "1"}, check=True)  # noqa: E501
