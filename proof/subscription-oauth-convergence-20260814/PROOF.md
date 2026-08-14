# Subscription OAuth convergence proof

## Status

`IN_PROGRESS`

## Source identity

- Common upstream base: `c4b500a7de64d0b66e3ee8098f58d14299092162`
- Codex input: `6a2a3dc6f2f32bf47067a5ef15bf78f3bdec9cb5`
- Grok input: `da8bf1cda063cc309dde4c247218f0c9f062ec6c`
- Writable branch: `codex/subscription-oauth-convergence-20260814`
- Committed review head: `f8cbf77623559149e91c63385992e2acb9e8bda0`
- Review PR: `https://github.com/saariuslystoned/OpenShell/pull/1`
- Official xAI client reference (read-only):
  `xai-org/grok-build@eb267feff13129e568df38fb6fdf0ceb65f735d6`
- Official OpenAI Codex reference (read-only):
  `openai/codex@5bc8da6d78fe32343dc51eaf73b96fd288ae0e87`

## Evidence collected

- GitHub PR #6 is open, mergeable, and still points at the reviewed Grok head.
- `saariuslystoned/OpenShell` branch `codex/2740-openai-codex-oauth` is still at
  the reviewed Codex head and has no competing PR.
- Both branches are based directly on the current NVIDIA/OpenShell `main` head.
- The isolated coordinator worktree was created from the exact Codex head.
- The x-api landing checkout was not mutated; its pre-existing `bin/smoky`
  change was preserved.
- Extracted a provider-neutral subscription OAuth specification registry used
  by core routing, server lifecycle/CRUD checks, and CLI login/logout.
- Added a bounded, timeout-limited, redirect-denying OAuth HTTP path on both
  the attended CLI and Gateway refresh/revoke surfaces.
- Added the dedicated xAI Grok provider profile and refresh adapter without
  exposing access tokens to the sandbox or CLI-owned persistent state.
- Added an explicit sandbox-local provider/model selector so Codex and Grok can
  coexist without attachment-order routing.
- Reconciled the xAI adapter against the pinned official open-source client:
  the public client id and discovered OAuth authorities match; device requests
  send `referrer=grok-build`; displayed codes accept only ASCII alphanumeric
  and hyphen characters; refresh omits `scope`; and the local default remains
  `grok-4.6`. OpenShell intentionally requests only the six scopes required by
  its direct API route, not the official client's conversation/workspace
  read/write scopes.
- Added an insert-only scoped persistence write for first refresh generation
  creation and CAS replacement of `reauth_required` generations. Concurrent
  configure can no longer overwrite another gateway process while preserving
  provider-scoped enumeration and generic-delete protection.
- Added fail-closed consumed-token handling for an expired rotation lease,
  post-connect response loss, and a successful but unreadable/oversized refresh
  response. Clear 408/429/5xx responses remain retryable; ambiguous outcomes
  require a distinct attended grant and never reuse the predecessor token.
- Resolved routes now publish the earliest nonzero expiry reported by refresh
  state or credential storage, and the router retains its per-request expiry
  rejection.
- Added Rust SDK selection parity after confirming the Go and TypeScript
  surfaces; focused wire tests pass in all edited client layers run so far.
- `cargo check --workspace` passed at `2026-08-14T12:17:50Z` using task-local
  Rust 1.95 and protoc 29.6 with `RUSTC_WRAPPER=`. This establishes source
  compilation only.
- `cargo test -p openshell-server --lib` passed at `2026-08-14T12:38:25Z`:
  1,359 passed, zero failed, seven pre-existing ignored. A later focused
  server/CLI library rerun after the final lifecycle hardening passed 1,360
  server tests and 228 CLI tests with the same seven server ignores. These
  runs include the
  shared lifecycle, bounded/redirect-denying OAuth HTTP, Grok refresh/revoke,
  reauthentication, generation fencing, CRUD-bypass, expiry, and explicit
  dual-provider selection assertions.
- `cargo test -p openshell-cli` passed at `2026-08-14T12:52:13Z`: 228 library
  tests, 88 command-parser tests, and every executed integration test passed;
  two pre-existing flaky forwarding tests and four documentation examples were
  ignored by their existing annotations. This includes attended OAuth HTTP,
  best-effort revoke, paired selector parsing, and wire-level selector proof.
- The first Go SDK CI run correctly failed because the new protobuf selector
  fields were absent from the public `SandboxSpec` converter. The SDK type,
  both converter directions, reflection coverage guard, and round-trip tests
  were fixed. `mise run ci` in `sdk/go` then passed at
  `2026-08-14T12:58:45Z`: lint zero issues, build, race tests, generated-proto
  drift check, and public docs coverage all green.
- `mise run markdown:lint` passed at `2026-08-14T12:59:20Z` over 120 Markdown
  files and 165 Mermaid-scanned files. `mise run docs:build:strict` passed at
  `2026-08-14T13:00:01Z` with zero Fern errors (two existing warnings hidden
  by the repository task).
- Focused post-review regressions passed through `2026-08-14T13:51:24Z` for:
  terminal worker suppression, invalid-grant revoke status handling, xAI
  no-scope refresh and referrer form, displayed-code control characters,
  expired rotation leases without predecessor reuse, insert-only scoped
  persistence, earliest route expiry, idempotent/nonreplaceable Grok configure,
  ambiguous successful refresh responses, and Rust SDK selector transport.
- The first repository-wide terminal run found no source failure outside Go
  lint, whose task-local `golangci-lint` binary had been compiled with Go 1.25
  while the pinned repo toolchain requires Go 1.26. The isolated linter was
  rebuilt with the already-pinned Go 1.26.5 and reported zero issues. A later
  full run correctly caught one test-fixture helper visible in production as
  dead code; the helper is now `#[cfg(test)]`, and standalone workspace Clippy
  passes with `-D warnings`.
- The first complete `mise run ci` passed at `2026-08-14T14:01:28Z` with the task-local
  toolchain and `RUSTC_WRAPPER=`. It includes Rust workspace check, format,
  Clippy, dependency policy, all workspace tests and server tests with
  `test-support`; Go format, lint (`0 issues`), build, race tests, generated
  protobuf drift, and docs checks; TypeScript generation, lint, typecheck, and
  69 tests; Python checks and 86 tests; Helm variants; Markdown/Mermaid;
  license/SBOM/packaging/install checks. The terminal server result was 1,364
  passed, zero failed, seven pre-existing ignored. No credential material was
  used or observed.
- `mise run docs:build:strict` passed after that CI run at the same source state:
  zero Fern errors and two repository warnings hidden by the standard task.
- The final source review found one additional cross-process edge: logout could
  supersede a refresh after its intermediate `publishing` state while the
  losing process still completed its separate provider bearer write. Routing
  already failed closed, but that loser could leave locally stored bearer
  residue. Publication now returns a non-debuggable exact-value/handle receipt;
  a failed terminal state CAS conditionally removes only that mint, with a
  bounded CAS retry, without clobbering a newer winner. Test-only debug output
  reports only redacted presence/count metadata. Focused inline and
  credential-driver rollback regressions both pass.
- The decisive post-fix `mise run ci` passed at `2026-08-14T14:16:27Z` in
  221.97 seconds. Clippy, formatting, dependency policy, and all language and
  packaging gates remain green. The terminal server result is now 1,366
  passed, zero failed, and seven pre-existing ignored; both new publication
  rollback regressions are included. No credential material was used or
  observed.
- Post-fix `mise run markdown:lint` and `mise run docs:build:strict` passed at
  `2026-08-14T14:17:11Z`: 120 Markdown files and 165 Mermaid-scanned files had
  zero lint errors; Fern reported zero errors and two repository warnings.
- The exact-head proof-asset placement preflight passed with zero candidate
  media and zero required fixes for base `c4b500a7...` and head `f8cbf776...`.
  The first Spark materializer dry run exposed a partial-clone transport
  limitation: the source checkout could not serve missing promisor blobs into
  a Git bundle. A clean full clone of the already-pushed fork was detached at
  the same exact head, verified to have zero missing diff objects, and then
  passed both dry and live materialization. Terminal materializer proof:
  `runs/spark-openclaw-materialize-worktree-runs/spark-openclaw-materialize-worktree-20260814T142057Z-18372/PROOF.md`.
- The first blocking Spark review selected Claude for model diversity, but the
  engine performed zero turns and returned `Not logged in`; this was classified
  as a review-rail authentication failure, not a source finding or repair
  cycle. The authenticated Codex OpenClaw engine then completed two chunked
  passes against immutable base `c4b500a7...` and exact head `f8cbf776...`:
  TruffleHog clean, zero accepted/actionable findings, overall patch-correct
  confidence 0.98. Terminal proof:
  `runs/spark-openclaw-autoreview-runs/spark-openclaw-autoreview-20260814T142159Z-21933/PROOF.md`.
  Review cycle count remains zero.
- PR-visible exact-head review proof was posted at
  `https://github.com/saariuslystoned/OpenShell/pull/1#issuecomment-5294403795`.
  The standalone ClawSweeper trigger received no workflow run, acknowledgement
  reaction, or durable start placeholder in the immediate snapshot or the one
  permitted 60-second recheck. It was not reposted. The fork has no tracked
  ClawSweeper workflow on its base branch, so this is classified as external
  workflow wiring failure; it does not invalidate the completed official
  OpenClaw review.
- Attended OAuth completed without exposing any code, bearer, refresh token,
  auth store, or browser session to the agent: Grok exited zero at
  `2026-08-14T14:56:38Z`; Codex exited zero at `2026-08-14T14:58:35Z` after
  Bobby enabled ChatGPT device-code authorization. Both Gateway refresh workers
  reported active provider state.
- The live OpenClaw runtime is the official NVIDIA NemoClaw public image's
  OpenClaw `2026.7.1` lock (`a814d82a...`) combined with official Node
  `22.23.2`; the reviewed task bundle SHA-256 is
  `5b68f4fae75bf09118be78c4cb7a09ef19909b011d78a9f94fc388eb1c0d1b77`.
  The first dual-provider sandbox selected Grok second, exposed none of six
  checked credential variables, offered zero tools, used no fallback, and
  returned exactly `OPENSHELL_OAUTH_ROUTE_OK` over `/v1/chat/completions`.
- Codex's first native ChatGPT Responses turn failed closed with HTTP 400.
  Structural capture (never headers or message content) and same-route direct
  probes isolated the cause: OpenClaw emits `max_output_tokens`, while the
  ChatGPT Codex backend rejects that field; the otherwise identical list-form,
  stateless, streaming request succeeds. Official OpenClaw `2026.7.1` already
  strips this field only when it sees a `chatgpt.com` hostname, which the
  sandbox intentionally cannot see behind `inference.local`.
- The router now strips `max_output_tokens` only for the pinned Codex
  subscription endpoint/protocol/path tuple and uses the supported list-form,
  stateless validation probe. Generic API-key Responses routes retain the
  field. The two Codex tests and generic-route negative regression passed at
  `2026-08-14T15:28:51Z`.
- A fresh VM attempt correctly revealed that uncommitted builds retain the old
  `git describe` root-image cache identity and therefore still booted the prior
  supervisor. No cache was deleted. The compatibility change is being
  checkpoint-committed so the next VM image receives a distinct reproducible
  source identity before the terminal live matrix.

## Required terminal evidence

- Provider-neutral lifecycle and bounded OAuth HTTP tests
- Codex and Grok adapter tests
- Router expiry/stale-cache and deterministic multi-provider selection tests
- CRUD-bypass, fencing, revoke/retry, and bearer-isolation tests
- Required format, lint, unit, integration, and CI commands — complete
- Dual-provider runtime proof and attended login/OpenClaw proof — attended
  login and Grok baseline complete; corrected Codex/rotation/logout matrix next
- Exact-head independent review and adjudication — prior head clean; rerun
  required after the live compatibility fix

Commands, results, artifacts, and findings will be appended as the work
advances. No credential values or auth-bearing output belong in this proof.
