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
    provider_type="codex-subscription"
    provider_name="codex-subscription-e2e"
    ;;
  grok)
    provider_type="grok-subscription"
    provider_name="grok-subscription-e2e"
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
status_dir="${runtime_root}/human-gate"
status_path="${status_dir}/${1}-login.status"

if [[ ! -x "$openshell_bin" ]]; then
  echo "missing OpenShell binary: $openshell_bin" >&2
  exit 66
fi
if [[ -e "$status_path" ]]; then
  echo "refusing to overwrite existing attended-login status: $status_path" >&2
  exit 73
fi

mkdir -p "$status_dir"
umask 077
export XDG_CONFIG_HOME="${runtime_root}/xdg-config"
export XDG_STATE_HOME="${runtime_root}/xdg-state"
export XDG_CACHE_HOME="${runtime_root}/xdg-cache"
export OPENSHELL_GATEWAY_ENDPOINT="${OPENSHELL_GATEWAY_ENDPOINT:-http://127.0.0.1:27670}"

echo "Starting attended ${provider_type} sign-in for ${provider_name}."
echo "Complete the browser consent yourself. This terminal output is not redirected or recorded."

set +e
"$openshell_bin" provider login --type "$provider_type" --name "$provider_name"
exit_code=$?
set -e

status_tmp="${status_path}.tmp.$$"
printf 'provider_type=%s\nprovider_name=%s\nexit_code=%s\ncompleted_at_utc=%s\n' \
  "$provider_type" \
  "$provider_name" \
  "$exit_code" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$status_tmp"
mv "$status_tmp" "$status_path"

if [[ $exit_code -eq 0 ]]; then
  echo "Attended sign-in completed. You may return to Codex."
else
  echo "Attended sign-in failed with exit code ${exit_code}. Return to Codex for diagnosis." >&2
fi
exit "$exit_code"
