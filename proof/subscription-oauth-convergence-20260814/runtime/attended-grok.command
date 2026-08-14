#!/usr/bin/env bash

set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
export OPENSHELL_OAUTH_RUNTIME_ROOT="/Users/cp-1/Developer/_machine-runs/openshell-oauth-convergence-20260814/runtime"
exec "${script_dir}/attended-login.sh" grok
