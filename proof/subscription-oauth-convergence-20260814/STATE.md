# State

- status: `active-progress`
- phase: `live-and-terminal-ci-complete; commit-review-next`
- updated_at_utc: `2026-08-14T15:51:22Z`
- writable_head: `6f3b41f736a590827d39014af741598b92e2d08c`
- grok_input_head: `da8bf1cda063cc309dde4c247218f0c9f062ec6c`
- common_base: `c4b500a7de64d0b66e3ee8098f58d14299092162`
- next: commit and push the proof closeout, rerun exact-head independent review, adjudicate, and audit every goal requirement
- blocker: live SwarmDash and canonical admission reads are unavailable; neither blocks source inspection or local implementation
- human_gate: none active; both attended grants were proved, remotely revoked, and locally cleared

## Current findings

- Both input branches are unchanged from the reviewed exact heads and share the
  same current upstream base.
- The Codex branch already contains the stronger cache-expiry, router, fencing,
  revocation, and concurrency machinery and is the extraction base.
- Grok PR #6 remains a read-only input until the foundation reaches a stable,
  tested checkpoint.
- A provider-neutral registry, bounded redirect-denying OAuth HTTP layer,
  shared refresh/revoke lifecycle, Grok profile/adapter, and sandbox-local
  provider/model selector now compile across the Rust workspace.
- The official `xai-org/grok-build` source was pinned read-only at
  `eb267feff13129e568df38fb6fdf0ceb65f735d6`. Its public-client id, endpoints,
  device `referrer`, displayed-code validation, refresh form, and rotation-race
  behavior were reconciled without copying its broader conversation/workspace
  scopes into this narrower route.
- Source review found and fixed four attributable fail-closed gaps: terminal
  refresh states being rescheduled, revocation error-body status confusion,
  earliest-expiry loss across refresh/credential stores, and ambiguous
  response-loss reuse of a possibly consumed rotating refresh token.
- Initial configure is now insert-only with its provider scope preserved, and
  reauthorization uses resource-version CAS. This closes the cross-process
  overwrite gap left by the process-local operation mutex.
- A final cross-process review closed the provider-publication/logout race:
  when the refresh-state CAS loses after bearer publication, the loser now
  conditionally removes only its exact inline values or stored handles and
  preserves any newer winner. Both storage modes have focused regressions, and
  credential-bearing structs have only redacted test debug output.
- Rust, Go, and TypeScript SDKs all carry the paired sandbox-local provider and
  model selection fields.
- The repository-wide `mise run ci` terminal gate passes after an isolated
  task-local Go 1.25/1.26 linter bootstrap mismatch was corrected and a
  test-only persistence fixture helper was scoped to test builds. This covers
  Rust check/format/Clippy/tests, Go format/lint/build/race tests/proto/docs,
  TypeScript install/generation/lint/typecheck/tests, Python tests/lint/format/
  typecheck, Helm, Markdown/Mermaid, licenses, dependency policy, SBOM, and
  packaging checks. The terminal post-runtime run passed in 299.32 seconds;
  its server result was 1,366 passed with seven pre-existing ignores. Strict
  Fern validation also passes with zero errors. Exact-head review remains.
- The branch is committed and pushed at `f8cbf776...`; PR #1 points at that
  exact head. Spark-2 OpenClaw completed two authenticated chunked passes with
  zero findings and confidence 0.98 against immutable base `c4b500a7...`.
  The earlier Claude engine attempt had no authenticated review turn, so it is
  rail evidence only and did not start a repair cycle.
- The PR's ClawSweeper command was not accepted after the immediate and single
  60-second checks, and the fork base contains no ClawSweeper workflow. This is
  recorded as external wiring failure without reposting; it does not block the
  clean official OpenClaw result.
- Both attended OAuth grants completed and were used for the terminal matrix.
  Codex and Grok each passed tool-free OpenClaw turns in reciprocal attachment
  order, with no credential environment, no fallback, and the exact expected
  response.
- The Codex turn exposed a live OpenClaw compatibility edge rather than an OAuth
  failure: OpenClaw sends `max_output_tokens` through `inference.local`, but the
  pinned ChatGPT Codex Responses backend rejects it. The router now removes
  that field only for the exact Codex subscription route and preserves it for
  generic Responses routes; all three focused regressions pass.
- The first post-fix VM used the prior root image because that cache identity is
  derived from committed `git describe` state. No cache deletion was performed.
- Checkpoint `6f3b41f7...` produced the required new VM identity. Both strict
  OpenClaw baselines, both independent rotations, Codex logout isolation, both
  fail-closed logout paths, remote revoke, local clear, and zero-credential
  terminal state are complete. The two task sandboxes were removed and the
  isolated Gateway was stopped; governed runtime logs remain hashed from
  `LIVE_RUNTIME.md`.
