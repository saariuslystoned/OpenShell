#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: OPENSHELL_OAUTH_RUNTIME_ROOT=<path> $0 <codex|grok>" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 64
fi

case "$1" in
  codex)
    sandbox_name="oauth-codex-e2e"
    expected_openclaw_provider="openai"
    expected_openclaw_model="gpt-5.6-sol"
    ;;
  grok)
    sandbox_name="oauth-grok-e2e"
    expected_openclaw_provider="inference"
    expected_openclaw_model="grok-4.6"
    ;;
  *)
    usage
    exit 64
    ;;
esac

runtime_root="${OPENSHELL_OAUTH_RUNTIME_ROOT:?set OPENSHELL_OAUTH_RUNTIME_ROOT}"
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
repo_root="$(cd "${script_dir}/../../.." && pwd -P)"
openshell_bin="${repo_root}/target/debug/openshell"

export XDG_CONFIG_HOME="${runtime_root}/xdg-config"
export XDG_STATE_HOME="${runtime_root}/xdg-state"
export XDG_CACHE_HOME="${runtime_root}/xdg-cache"
export OPENSHELL_GATEWAY_ENDPOINT="${OPENSHELL_GATEWAY_ENDPOINT:-http://127.0.0.1:27670}"

"$openshell_bin" sandbox exec \
  --name "$sandbox_name" \
  --no-tty \
  --timeout 180 \
  -- \
  sh -lc '
    set -eu
    assertion_path=/sandbox/openclaw-assertion.mjs
    if test -d "$assertion_path"; then
      assertion_path="${assertion_path}/assert-openclaw-result.mjs"
    fi
    result_path=/tmp/openclaw-result.json
    PATH=/sandbox:$PATH HOME=/sandbox JITI_FS_CACHE=false \
      /sandbox/openclaw-runtime/node_modules/.bin/openclaw agent \
      --local \
      --agent main \
      --message "Reply with exactly: OPENSHELL_OAUTH_ROUTE_OK" \
      --json >"$result_path"
    cat "$result_path"
    PATH=/sandbox:$PATH /sandbox/node "$assertion_path" "$result_path" \
      '"$expected_openclaw_provider"' '"$expected_openclaw_model"'
  '
