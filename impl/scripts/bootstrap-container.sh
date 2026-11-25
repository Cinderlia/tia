#!/usr/bin/env bash
# Run as root inside the test container: install the Python 3.13 toolchain and project dependencies in one go.
#   bash impl/scripts/bootstrap-container.sh
# Container name and mount paths are determined by the local environment; do not commit them to the repository.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMPL="$(cd "${HERE}/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3.13}"
PIP_INDEX="${PIP_INDEX:-https://mirrors.aliyun.com/pypi/simple/}"
export UV_LINK_MODE="${UV_LINK_MODE:-copy}"

echo "[bootstrap] impl=${IMPL} python=${PYTHON_BIN}"

# 1. apt dependencies
if [[ -f "${IMPL}/deploy/apt-packages.txt" ]]; then
  mapfile -t pkgs < <(grep -vE '^\s*(#|$)' "${IMPL}/deploy/apt-packages.txt")
  if ((${#pkgs[@]})); then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}"
  fi
fi

# 2. uv (system-level; do not install into venv)
if ! command -v uv >/dev/null 2>&1; then
  "${PYTHON_BIN}" -m pip install --break-system-packages -q -i "${PIP_INDEX}" uv
fi
echo "[bootstrap] uv $(uv --version)"

# 3. Project dependencies (use system Python 3.13 only; prohibit uv from downloading interpreters)
cd "${IMPL}"
uv lock --python "${PYTHON_BIN}"
uv sync --python "${PYTHON_BIN}"

# 4. Self-check
uv run --python "${PYTHON_BIN}" python -c 'import tia; print("[bootstrap] tia", tia.__version__)'
