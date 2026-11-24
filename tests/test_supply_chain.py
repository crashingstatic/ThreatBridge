"""What CI and the container install is pinned (D24, SEC-3, SEC-4): Python packages from uv.lock,
Playwright from package-lock.json, base images by digest and GitHub Actions by commit."""
import glob
import json
import os
import re
import shutil
import subprocess
import tomllib

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def workflows():
    return {os.path.basename(p): read(p) for p in glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))}


def test_actions_are_pinned_to_commits():
    uses = [(name, line.strip()) for name, text in workflows().items()
            for line in text.splitlines() if re.match(r"\s*(- )?uses:", line)]
    assert len(uses) >= 10
    for name, line in uses:
        # owner/repo@<40 hex> # vX.Y.Z: the comment says which release the commit is, for review.
        assert re.fullmatch(r"(- )?uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+(\.\d+)*", line), f"{name}: {line}"


def test_base_images_are_pinned_by_digest():
    froms = [line for line in read("Dockerfile").splitlines() if line.startswith("FROM ")]
    assert froms
    for line in froms:
        assert re.fullmatch(r"FROM \S+:\S+@sha256:[0-9a-f]{64}( AS \w+)?", line), line


def test_one_uv_version_everywhere():
    uv = re.search(r"ghcr.io/astral-sh/uv:([\d.]+)@", read("Dockerfile")).group(1)
    found_any = False
    for name, text in workflows().items():
        for found in re.findall(r'setup-uv@\S+ # v[\d.]+\n\s+with:\n\s+version: "([\d.]+)"', text):
            assert found == uv, f"{name} installs uv {found}, the Dockerfile {uv}"
            found_any = True
    assert found_any
    project = tomllib.loads(read("pyproject.toml"))
    assert project["tool"]["uv"]["required-version"] == ">=" + ".".join(uv.split(".")[:2])


def test_the_container_and_ci_install_only_from_the_lock_file():
    docker = read("Dockerfile")
    assert "uv sync --frozen --no-default-groups" in docker and "pip install" not in docker
    for name, text in workflows().items():
        assert "pip install" not in text, name
        assert "npm install" not in text, name                    # npm ci: package-lock.json
    assert not os.path.exists(os.path.join(ROOT, "requirements.txt"))   # one source: uv.lock


def test_playwright_is_locked():
    wanted = json.loads(read("package.json"))["devDependencies"]["playwright"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", wanted)                 # an exact version
    lock = json.loads(read("package-lock.json"))
    assert lock["packages"]["node_modules/playwright"]["version"] == wanted
    assert all("integrity" in p for k, p in lock["packages"].items() if k)


def test_release_version_is_plain():
    assert re.fullmatch(r"\d+\.\d+\.\d+", tomllib.loads(read("pyproject.toml"))["project"]["version"])


# CI installs uv, so there a missing uv fails the test instead of skipping it.
@pytest.mark.skipif(not shutil.which("uv") and not os.environ.get("CI"), reason="uv not installed")
def test_the_lock_file_matches_pyproject():
    r = subprocess.run(["uv", "lock", "--check"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_the_package_version_is_the_projects():
    """The version /api/config and the report give is the one a release is tagged with."""
    from threatbridge import __version__
    assert __version__ == tomllib.loads(read("pyproject.toml"))["project"]["version"]
