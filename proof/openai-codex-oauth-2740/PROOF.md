# OpenAI Codex Subscription OAuth Proof

This packet records the source-only implementation proposed by
[NVIDIA/OpenShell issue #2740](https://github.com/NVIDIA/OpenShell/issues/2740).

## Outcome

OpenShell now has an experimental `openai-codex-oauth` provider for a distinct,
attended **Sign in with ChatGPT** grant. The gateway owns the reusable OAuth
grant, refresh lifecycle, and short-lived access credential. Untrusted sandbox
workloads receive neither token. An attached sandbox can use the grant only
through its trusted `inference.local` route to the pinned Codex subscription
backend.

The branch remains source-only. No live OAuth login, Spark-2 mutation, deploy,
merge, or upstream pull request occurred.

## Provenance

- OpenShell source base and current upstream `main` at closeout:
  `c4b500a7de64d0b66e3ee8098f58d14299092162`.
- Source implementation commit:
  `3a321209d6ebe5980f833f9f20c9d8290cf42910` (tree
  `bf009fcb688e6b97b03b31f32cf31aade0aeefa9`).
- Self-review lifetime-cap repair:
  `67812dd51ae406e582aa62ebb3a9354f7de8d183` (tree
  `80e1ea447857a7479e0c010bec0e9fb79a043bde`).
- Self-review dedicated-strategy repair:
  `ec5fa30048b7fbde6a12d7f41f20909666963f28` (tree
  `8f5450df4898ffd0467545095da8cba1e7d3c0f4`).
- Public fork branch:
  <https://github.com/saariuslystoned/OpenShell/tree/codex/2740-openai-codex-oauth>.
- Official Codex source was initially audited at
  `3711943d11a1c69a65afe98757814b6b5244fbaf` and the relevant public client,
  issuer, device-flow, token, revocation, subscription-backend, account-header,
  FedRAMP-header, and Responses API shapes were rechecked at current Codex
  `main` `cbe85e117b1db59cdbe8175c59793c3cf2a4a7b8`.
- Official product documentation:
  <https://developers.openai.com/codex/auth>.
- The provider uses the reviewed public OAuth client contract shipped by
  official Codex. OpenShell does not claim ownership of that registration and
  deliberately identifies its requests as `openshell` rather than pretending
  to be the first-party Codex CLI.

## Implemented boundary

- Dedicated `openshell provider login` device authorization and
  `openshell provider logout` revocation commands; generic token-paste setup is
  rejected.
- Pinned authorization, token, revocation, and Codex subscription origins;
  redirects disabled and OAuth response bodies capped at 64 KiB.
- Refresh token, account identifier, and FedRAMP routing flag remain in
  gateway-secret refresh state. No provider environment variable exposes them
  to a sandbox.
- Exact provider attachment is required before route publication. Missing,
  empty, or mismatched attachment metadata fails closed.
- The router removes caller-provided authorization, account, FedRAMP, and
  originator headers, ignores caller base-URL overrides, injects gateway-owned
  values, and uses the Responses API wire shape.
- Refresh keeps the original ChatGPT account/workspace binding, classifies
  terminal versus retryable failures, uses a random generation fence, and
  serializes remote refresh/revoke operations.
- Route publication is two-phase (`publishing` then `refreshed`) so a crash or
  failed credential commit cannot expose mismatched token and route metadata.
  In-progress, failed, expired, revoked, or reauthorization-required state is
  not routable.
- Logout fences refresh, requires both remote revocation and local credential
  clearing, and preserves a retryable unavailable state on ambiguous failure.
  Generic deletion cannot orphan a live grant.
- Generic provider create/update cannot inject or replace Codex access tokens
  or routing metadata.
- The Codex provider and its stored route state must both use the dedicated
  `openai_codex_oauth` refresh strategy. Generic OAuth refresh material cannot
  activate the provider, and a mismatched persisted strategy is not routable.
- Supervisor and router enforce the credential expiry carried in a cached
  route, preventing use of stale short-lived credentials. OpenShell also caps
  local route lifetime to the reviewed one-hour maximum even when the token's
  unverified JWT payload claims a later expiry.

## Verification

All commands below completed with exit status 0 on macOS using the repository's
pinned toolchain and Homebrew library path where required.

- `mise run ci`: complete repository CI passed, including Rust format/check,
  clippy, unit/integration/doc tests, Go build/test/lint/generated-proto checks,
  Python 86/86 tests, TypeScript lint/typecheck and 68/68 tests, docs,
  licenses, Helm, and repository policy checks.
- Focused server Codex suite: 18 passed.
- Focused CLI Codex suites: 6 passed.
- Focused router gateway-owned suite: 2 passed.
- Cross-crate debug build for `openshell-server` and `openshell-cli`: passed.
- `git diff --check` and `cargo fmt --all -- --check`: passed.
- CLI help was exercised only; no login was initiated.

Built artifact evidence (debug, local proof only):

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `target/debug/openshell` | 71,778,280 | `90fc719015132e0f16b6df3d5f4856f05825a65eeead2015ed3111464e65fdd8` |
| `target/debug/openshell-gateway` | 161,941,968 | `a6261e318e11e0ff51636c970adaff422363847eeceaa646739f9f02c2ab5b1f` |

## Tested failure classes

- Device authorization pending/slow-down/success, redirect rejection, and
  oversized response rejection.
- Refresh rotation, account mismatch, terminal rejection, retryable timeout,
  rate-limit/server failure, two-phase recovery, and concurrent refresh/logout.
- Revocation failure, credential-clear failure, and generation mismatch.
- Attached versus unattached or malformed sandbox provider metadata.
- Hostile base URL and protected-header override attempts.
- Expired route and stale supervisor-bundle rejection.
- Direct Codex credential creation/update, generic refresh configuration,
  mismatched stored refresh strategy, and generic deletion bypass attempts.

## Human and upstream gates

- Live OAuth authorization: **NOT PERFORMED**; it remains a separate attended
  account/security approval.
- Spark-2/OpenClaw integration: **NOT PERFORMED**; no live system was changed.
- Upstream issue #2740 was still open with `state:triage-needed` at
  `2026-08-14T03:20:52Z`.
- Upstream PR creation remains held until OpenShell accepts the issue and
  `saariuslystoned` is vouched. The prepared body is in `UPSTREAM_DRAFT.md`.
- Public fork branch was pushed; no pull request was created.
- Independent exact-head semantic review remains required after the candidate
  commit exists; local CI is not being misrepresented as that review.
