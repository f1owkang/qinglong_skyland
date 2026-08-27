#!/usr/bin/env bash
# 森空岛自动签到 - Hermes 定时任务包装脚本
#
# 用法：
#   1. 将本文件与 skyland.py、requirements.txt 一起放到 Hermes 的 scripts 目录
#      （如 ~/scripts/skyland/）
#   2. 准备 token 文件 ~/.config/skyland/tokens（每行一个 token，# 开头为注释）
#   3. 在 Hermes 中创建定时任务，script 指向本文件，no_agent 模式：
#      stdout 会被原样投递到目标会话；全部成功且 SKYLAND_SILENT_OK=on 时
#      无输出，即不投递任何消息
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# 首次运行：创建 venv 并安装依赖（优先 uv，回退 python3 venv + pip）
if [ ! -x ".venv/bin/python" ]; then
  echo "[skyland] 首次运行，初始化 venv 并安装依赖..." >&2
  if command -v uv >/dev/null 2>&1; then
    uv venv .venv >&2
    uv pip install --python .venv/bin/python -r requirements.txt >&2
  else
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt >&2
  fi
fi

# 默认配置：Hermes 模式 + token 文件
export SKYLAND_MODE="${SKYLAND_MODE:-hermes}"
export SKYLAND_TOKEN_FILE="${SKYLAND_TOKEN_FILE:-$HOME/.config/skyland/tokens}"

exec .venv/bin/python skyland.py
