#!/usr/bin/env bash
# 在测试容器内以 root 执行：一次装好 Python 3.13 工具链与项目依赖。
#   bash impl/scripts/bootstrap-container.sh
# 容器名与挂载路径由本地环境决定，不写进仓库。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMPL="$(cd "${HERE}/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3.13}"
PIP_INDEX="${PIP_INDEX:-https://mirrors.aliyun.com/pypi/simple/}"
export UV_LINK_MODE="${UV_LINK_MODE:-copy}"

echo "[bootstrap] impl=${IMPL} python=${PYTHON_BIN}"

# 1. apt 依赖
if [[ -f "${IMPL}/deploy/apt-packages.txt" ]]; then
  mapfile -t pkgs < <(grep -vE '^\s*(#|$)' "${IMPL}/deploy/apt-packages.txt")
  if ((${#pkgs[@]})); then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}"
  fi
fi

# 2. uv（系统级；不装进 venv）
if ! command -v uv >/dev/null 2>&1; then
  "${PYTHON_BIN}" -m pip install --break-system-packages -q -i "${PIP_INDEX}" uv
fi
echo "[bootstrap] uv $(uv --version)"

# 3. 项目依赖（Python 只用系统 3.13，禁止 uv 下载解释器）
cd "${IMPL}"
uv lock --python "${PYTHON_BIN}"
uv sync --python "${PYTHON_BIN}"

# 4. 自检
uv run --python "${PYTHON_BIN}" python -c 'import tia; print("[bootstrap] tia", tia.__version__)'
