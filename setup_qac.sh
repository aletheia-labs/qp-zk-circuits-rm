#!/usr/bin/env bash
# setup_qac.sh
set -euo pipefail

# 1) Clone or update the repo one level up from zk-circuits root
ZK_ROOT="$(pwd)"
PARENT_DIR="$(cd "$ZK_ROOT/.." && pwd)"
QAC_DIR="$PARENT_DIR/quantus-api-client"
REPO_URL="https://github.com/ethan-crypto/quantus-api-client"
REPO_BRANCH="sample-proof-script"

if [ ! -d "$QAC_DIR/.git" ]; then
  echo "Cloning $REPO_URL (branch: $REPO_BRANCH) into $QAC_DIR..."
  git clone --branch "$REPO_BRANCH" --single-branch "$REPO_URL" "$QAC_DIR"
else
  echo "Repository already exists at $QAC_DIR; updating..."
  git -C "$QAC_DIR" fetch origin
  git -C "$QAC_DIR" checkout "$REPO_BRANCH"
  git -C "$QAC_DIR" pull --ff-only origin "$REPO_BRANCH"
fi

# 2) Set env vars for the checkout and the example dir
export QUANTUS_API_CLIENT_DIR="$QAC_DIR"
export QUANTUS_API_CLIENT_EXAMPLE_DIR="$QAC_DIR/examples/async"

echo "QUANTUS_API_CLIENT_DIR=$QUANTUS_API_CLIENT_DIR"
echo "QUANTUS_API_CLIENT_EXAMPLE_DIR=$QUANTUS_API_CLIENT_EXAMPLE_DIR"

# 3) Persist if script was *executed* (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  ENV_FILE="$ZK_ROOT/.env.qac"
  {
    echo "export QUANTUS_API_CLIENT_DIR=\"$QUANTUS_API_CLIENT_DIR\""
    echo "export QUANTUS_API_CLIENT_EXAMPLE_DIR=\"$QUANTUS_API_CLIENT_EXAMPLE_DIR\""
  } > "$ENV_FILE"
  echo
  echo "Wrote $ENV_FILE"
  echo "Load these vars in your current shell with:"
  echo "  source \"$ENV_FILE\""
  echo "Or re-run this setup with:"
  echo "  source scripts/setup_qac.sh"
fi
