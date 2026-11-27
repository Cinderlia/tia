"""Locate or install the pinned Chrome build used for execution confirmation.

TIA never guesses which browser to use. There are exactly two sources:

1. ``TIA_CHROME`` — an explicit path to the browser the operator wants to use
   (our lab machines already have one, so no download is needed there);
2. a build of the pinned version downloaded by ``tia-agent browser-install``.

The download lives inside the project (``impl/var/browsers/<version>/``), never in a
global location, so a checkout stays self-contained and removable. The browser itself
is an optional dependency: install it with ``uv sync --extra browser``.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import zipfile
from pathlib import Path
from typing import Any

import httpx

#: The single Chrome for Testing release TIA ships with. Pinned on purpose: a moving
#: version makes execution results and bug reports impossible to reproduce.
DEFAULT_CHROME_VERSION = "155.0.8059.39"

#: Official Chrome for Testing bucket. Downloads are one-shot and only happen in
#: ``browser-install``; there is deliberately no mirror configuration.
CHROME_BASE_URL = "https://storage.googleapis.com/chrome-for-testing-public"

_DOWNLOAD_TIMEOUT = 900.0


class BrowserSetupError(RuntimeError):
    """Raised when a browser cannot be installed or located."""


def platform_tag() -> str:
    """Return the Chrome-for-Testing platform tag for the current interpreter."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        return "linux64"
    if system == "darwin":
        return "mac-arm64" if machine in {"arm64", "aarch64"} else "mac-x64"
    if system == "windows":
        return "win64" if platform.architecture()[0] == "64bit" else "win32"
    raise BrowserSetupError(f"unsupported platform: {system}/{machine}")


def browsers_root() -> Path:
    """Directory that holds the pinned download (``TIA_BROWSERS`` overrides)."""
    override = os.environ.get("TIA_BROWSERS", "").strip()
    if override:
        return Path(override).expanduser()
    # impl/src/tia/inf/browser_setup.py -> impl/var/browsers
    return Path(__file__).resolve().parents[3] / "var" / "browsers"


def _binary_relative(platform_tag_: str) -> Path:
    if platform_tag_.startswith("mac"):
        return Path("chrome-mac-x64" if platform_tag_ == "mac-x64" else "chrome-mac-arm64") / (
            "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
        )
    if platform_tag_ == "win64":
        return Path("chrome-win64") / "chrome.exe"
    if platform_tag_ == "win32":
        return Path("chrome-win32") / "chrome.exe"
    return Path("chrome-linux64") / "chrome"


def chrome_binary(version: str | None = None) -> Path | None:
    """Return ``TIA_CHROME`` when set, otherwise the pinned downloaded build."""
    from tia.inf.settings import settings_file

    override = os.environ.get("TIA_CHROME", "").strip() or str(
        settings_file("app.yaml").get("chrome") or ""
    )
    if override:
        path = Path(override).expanduser()
        return path if path.is_file() else None
    candidate = browsers_root() / (version or DEFAULT_CHROME_VERSION) / _binary_relative(platform_tag())
    return candidate if candidate.is_file() else None


def installed_version() -> str | None:
    """Version of the downloaded build, if the pinned one is present."""
    binary = chrome_binary()
    if binary is None:
        return None
    try:
        return binary.parents[1].name
    except IndexError:  # pragma: no cover - defensive
        return None


def status() -> dict[str, Any]:
    """Describe browser availability without touching the network."""
    binary = chrome_binary()
    source = None
    if binary is not None:
        source = "TIA_CHROME" if os.environ.get("TIA_CHROME", "").strip() else "download"
    return {
        "available": binary is not None,
        "binary": str(binary) if binary else None,
        "version": installed_version() if source == "download" else None,
        "pinned_version": DEFAULT_CHROME_VERSION,
        "source": source,
        "root": str(browsers_root()),
        "platform": platform_tag(),
        "headless": os.environ.get("TIA_BROWSER_HEADED", "") != "1",
    }


def install_chrome(
    version: str | None = None,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Download and unpack the pinned Chrome for Testing build into the project."""
    version = version or os.environ.get("TIA_CHROME_VERSION", "").strip() or DEFAULT_CHROME_VERSION
    tag = platform_tag()
    root = browsers_root()
    target = root / version
    binary = target / _binary_relative(tag)
    if binary.is_file() and not force:
        return {"installed": True, "reused": True, "version": version, "binary": str(binary)}

    base = CHROME_BASE_URL
    folder = f"chrome-{tag}"
    url = f"{base}/{version}/{tag}/{folder}.zip"
    root.mkdir(parents=True, exist_ok=True)
    archive = root / f"{version}-{tag}.zip"

    try:
        with httpx.stream("GET", url, timeout=_DOWNLOAD_TIMEOUT, follow_redirects=True) as response:
            if response.status_code != 200:
                raise BrowserSetupError(f"download failed: HTTP {response.status_code} for {url}")
            with archive.open("wb") as handle:
                for chunk in response.iter_bytes(1024 * 1024):
                    handle.write(chunk)
        if force and target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(target)
        if not binary.is_file():
            raise BrowserSetupError(f"archive did not contain {binary}")
        mode = binary.stat().st_mode
        binary.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except (httpx.HTTPError, OSError, zipfile.BadZipFile) as exc:
        raise BrowserSetupError(f"cannot install Chrome: {exc}") from exc
    finally:
        archive.unlink(missing_ok=True)

    return {
        "installed": True,
        "reused": False,
        "version": version,
        "binary": str(binary),
        "url": url,
    }
