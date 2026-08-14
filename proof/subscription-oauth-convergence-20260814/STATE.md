# State

- status: `active-progress`
- phase: `source-and-terminal-gates-green; exact-head-commit-and-independent-review-next`
- updated_at_utc: `2026-08-14T14:17:11Z`
- writable_head: `6a2a3dc6f2f32bf47067a5ef15bf78f3bdec9cb5`
- grok_input_head: `da8bf1cda063cc309dde4c247218f0c9f062ec6c`
- common_base: `c4b500a7de64d0b66e3ee8098f58d14299092162`
- next: inspect and commit the exact diff, obtain exact-head independent review and adjudicate it, then build the deterministic runtime evidence matrix and run the attended dual-provider proof
- blocker: live SwarmDash and canonical admission reads are unavailable; neither blocks source inspection or local implementation
- human_gate: none active; attended provider login will require Bobby later

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
  packaging checks. The decisive post-fix terminal server run passed 1,366 tests with seven
  pre-existing ignores. Strict Fern validation also passes with zero errors.
  Exact-head review and runtime proof remain.
