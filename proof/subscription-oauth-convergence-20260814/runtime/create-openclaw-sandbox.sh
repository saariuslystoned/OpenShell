#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

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
    selected_provider="codex-subscription-e2e"
    selected_model="gpt-5.6-sol"
    first_provider="grok-subscription-e2e"
    second_provider="codex-subscription-e2e"
    config_name="codex.json"
    expected_openclaw_provider="openai"
    expected_openclaw_model="gpt-5.6-sol"
    ;;
  grok)
    sandbox_name="oauth-grok-e2e"
    selected_provider="grok-subscription-e2e"
    selected_model="grok-4.6"
    first_provider="codex-subscription-e2e"
    second_provider="grok-subscription-e2e"
    config_name="grok.json"
    expected_openclaw_provider="inference"
    expected_openclaw_model="grok-4.6"
    ;;
  *)
    usage
    exit 64
    ;;
esac

runtime_root="${OPENSHELL_OAUTH_RUNTIME_ROOT:?set OPENSHELL_OAUTH_RUNTIME_ROOT}"
task_root="$(cd "${runtime_root}/.." && pwd -P)"
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
repo_root="$(cd "${script_dir}/../../.." && pwd -P)"
openshell_bin="${repo_root}/target/debug/openshell"
bundle="${task_root}/openclaw-runtime-2026.7.1-linux-arm64-node22.23.tgz"
config="${script_dir}/../openclaw/${config_name}"
assertion="${script_dir}/assert-openclaw-result.mjs"

if [[ ! -x "$openshell_bin" ]]; then
  echo "missing OpenShell binary: $openshell_bin" >&2
  exit 66
fi
if [[ ! -f "$bundle" ]]; then
  echo "missing reviewed OpenClaw runtime bundle: $bundle" >&2
  exit 66
fi
if [[ ! -f "$config" ]]; then
  echo "missing OpenClaw config: $config" >&2
  exit 66
fi
if [[ ! -f "$assertion" ]]; then
  echo "missing OpenClaw assertion: $assertion" >&2
  exit 66
fi

export XDG_CONFIG_HOME="${runtime_root}/xdg-config"
export XDG_STATE_HOME="${runtime_root}/xdg-state"
export XDG_CACHE_HOME="${runtime_root}/xdg-cache"
export OPENSHELL_GATEWAY_ENDPOINT="${OPENSHELL_GATEWAY_ENDPOINT:-http://127.0.0.1:27670}"

"$openshell_bin" sandbox create \
  --name "$sandbox_name" \
  --from base \
  --provider "$first_provider" \
  --provider "$second_provider" \
  --inference-provider "$selected_provider" \
  --inference-model "$selected_model" \
  --no-auto-providers \
  --no-tty \
  --upload "${bundle}:/sandbox/openclaw-runtime.tgz" \
  --upload "${config}:/sandbox/selected-openclaw.json" \
  --upload "${assertion}:/sandbox/openclaw-assertion.mjs" \
  -- \
  sh -lc '
    set -eu
    tar -xzf /sandbox/openclaw-runtime.tgz -C /sandbox
    mkdir -p /sandbox/.openclaw
    config_path=/sandbox/selected-openclaw.json
    if test -d "$config_path"; then
      config_path="${config_path}/'"$config_name"'"
    fi
    install -m 600 "$config_path" /sandbox/.openclaw/openclaw.json
    assertion_path=/sandbox/openclaw-assertion.mjs
    if test -d "$assertion_path"; then
      assertion_path="${assertion_path}/assert-openclaw-result.mjs"
    fi
    for variable in OPENAI_API_KEY XAI_API_KEY OPENAI_CODEX_OAUTH_ACCESS_TOKEN XAI_GROK_ACCESS_TOKEN OPENAI_REFRESH_TOKEN XAI_REFRESH_TOKEN; do
      if printenv "$variable" >/dev/null 2>&1; then
        printf "%s=present\n" "$variable"
        exit 70
      fi
      printf "%s=absent\n" "$variable"
    done
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
