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
- Self-review fail-closed route-cache repair:
  `4c1236f7ec20f42bc7c6ce4cc2c4676f4e7a4ca5` (tree
  `9cfe26f71e3c5e487350a247c0e14effb3cc650e`).
- Public source-and-proof checkpoint:
  `7ab45643cfd7c638089877193c89ffdd65ae0392` (tree
  `30e66f8b2392a93c98c89e0bdc9cd445696c613d`).
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
- If the supervisor loses the gateway bundle authority, it removes the
  gateway-owned Codex routes from both route caches while retaining unrelated
  inference routes. It invalidates the cached revision when a route is removed
  so the same authoritative revision can restore access after connectivity
  returns.

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
- Focused supervisor inference-route suites: 18 passed, including exact Codex
  provider-alias recognition and removal from user/system caches while an
  unrelated route remains available.
- Cross-crate debug build for `openshell-server` and `openshell-cli`: passed.
- `git diff --check` and `cargo fmt --all -- --check`: passed.
- CLI help was exercised only; no login was initiated.

Built artifact evidence (debug, local proof only):

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `target/debug/openshell` | 71,778,280 | `3bae11520dddbab9abfdfcb3866f3658579e3b4c7f679abb09d9fd1d9990215c` |
| `target/debug/openshell-gateway` | 161,941,968 | `41585670bd60a188cdc931a326c72b1f9acb4b82cf3aecc708d03e8dfe56341c` |

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
- Failed gateway bundle refresh with cached Codex user/system routes, provider
  alias normalization, and preservation of an unrelated inference route.

## Human and upstream gates

- Live OAuth authorization: **NOT PERFORMED**; it remains a separate attended
  account/security approval.
- Spark-2/OpenClaw integration: **NOT PERFORMED**; no live system was changed.
- Upstream issue #2740 was still open with `state:triage-needed` at
  `2026-08-14T04:12:08Z`. Vouch discussion #2741 still had zero replies, and
  `saariuslystoned` was absent from the upstream vouched-contributor list.
- Upstream PR creation remains held until OpenShell accepts the issue and
  `saariuslystoned` is vouched. The prepared body is in `UPSTREAM_DRAFT.md`.
- Public fork branch was pushed; no pull request was created.
- Independent exact-head semantic review remains required after the candidate
  commit exists; local CI is not being misrepresented as that review.
