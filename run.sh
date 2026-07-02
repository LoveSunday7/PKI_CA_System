#!/bin/bash
# PKI/CA System - Start Script
# Usage: ./run.sh [port]

PORT=${1:-8000}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "========================================="
echo "  PKI/CA 数字证书管理系统"
echo "========================================="

# Activate virtual environment
source "${SCRIPT_DIR}/.venv/bin/activate"

# Ensure data directory exists
mkdir -p "${SCRIPT_DIR}/data/pki"

echo ""
echo "  启动服务: http://127.0.0.1:${PORT}"
echo "  API 文档: http://127.0.0.1:${PORT}/docs"
echo ""
echo "========================================="

cd "${SCRIPT_DIR}"
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT}" --reload
