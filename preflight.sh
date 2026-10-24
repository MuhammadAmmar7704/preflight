#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(pwd)"
PKG="${1:-}"
MODE="${2:-status}"

# Load local secrets without committing them.
if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

if [[ -z "$PKG" || "$PKG" == "-h" || "$PKG" == "--help" ]]; then
  cat <<'EOF'
Usage:
  ./preflight.sh <package[@version]> [status|--verbose|--json]

Examples:
  ./preflight.sh ms
  ./preflight.sh vm2@3.9.16
  ./preflight.sh lodash@4.17.20 --verbose
  ./preflight.sh express@4.17.1 --json

Environment:
  GEMINI_API_KEY      Enables the Gemma 4 tool-calling agent
  PREFLIGHT_TARGET    Override target preset (ubuntu22-node20, alpine-node20, ...)
  PREFLIGHT_SANDBOX_IMAGE  Override sandbox image

Output:
  status (default)    {"status":"SAFE"} or {"status":"VULNERABLE"}
  --verbose           full trace, evidence, and policy
  --json              machine-readable verdict + trace
EOF
  exit 2
fi

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[preflight] missing required command: $1" >&2
    exit 1
  }
}

need node
need docker
docker info >/dev/null 2>&1 || {
  echo "[preflight] Docker daemon is not running or not accessible" >&2
  exit 1
}

# Install scanner dependencies once.
if [[ ! -x "$ROOT/node_modules/.bin/tsx" ]]; then
  echo "[preflight] installing scanner dependencies..." >&2
  (cd "$ROOT" && npm install --ignore-scripts --no-audit --no-fund >/dev/null)
fi

# Build the sandbox image once.
if ! docker image inspect preflight-sandbox:dev >/dev/null 2>&1; then
  echo "[preflight] building sandbox image..." >&2
  docker build -t preflight-sandbox:dev "$ROOT/preflight-sandbox" >/dev/null
fi

ARGS=(scan "$PKG" --project "$PROJECT_DIR")

if [[ -n "${PREFLIGHT_TARGET:-}" ]]; then
  ARGS+=(--target "$PREFLIGHT_TARGET")
elif [[ "$(uname -s)" == "Linux" ]]; then
  read -r GLIBC NODE_MAJOR ABI ARCH <<EOF
$(node -e 'const r=process.report.getReport(); console.log([r.header.glibcVersionRuntime || "", process.versions.node.split(".")[0], process.versions.modules, process.arch].join(" "))')
EOF
  if [[ -n "$GLIBC" ]]; then
    ARGS+=(--libc glibc --glibc "$GLIBC")
  else
    ARGS+=(--libc musl)
  fi
  ARGS+=(--node "$NODE_MAJOR" --abi "$ABI" --arch "$ARCH")
else
  ARGS+=(--target ubuntu22-node20)
fi

if [[ -z "${GEMINI_API_KEY:-}" ]]; then
  ARGS+=(--no-gemma)
fi

case "$MODE" in
  status) ;;
  --verbose|verbose) ;;
  --json|json) ARGS+=(--json) ;;
  *)
    echo "[preflight] unknown mode: $MODE" >&2
    exit 2
    ;;
esac

if [[ "$MODE" == "status" ]]; then
  ARGS+=(--status)
fi

cd "$ROOT"
exec ./node_modules/.bin/tsx src/index.ts "${ARGS[@]}"
