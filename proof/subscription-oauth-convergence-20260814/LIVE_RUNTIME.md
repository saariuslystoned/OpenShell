# Live dual-provider runtime proof

## Verdict

`PASS`

Codex and Grok both completed strict, tool-free OpenClaw turns through the
Gateway-owned subscription routes. Reverse attachment order did not affect the
explicitly selected provider. Each grant rotated independently. Codex logout
failed its selected route closed while Grok remained usable; Grok logout then
failed its own selected route closed. Both remote revoke commands succeeded,
both local credential publications were cleared, and neither refresh
configuration remained.

## Bound identities

- Source commit: `6f3b41f736a590827d39014af741598b92e2d08c`
- Source describe: `dev-13-g6f3b41f7`
- Isolated gateway: `oauth-e2e-20260814` at loopback-only
  `http://127.0.0.1:27670`
- OpenClaw: `2026.7.1` from the official NVIDIA NemoClaw public image lock
  `a814d82a36046bd7819d222337809ce80ccfd76b553cd17265ff64a527d3d095`
- OpenClaw/Node bundle SHA-256:
  `5b68f4fae75bf09118be78c4cb7a09ef19909b011d78a9f94fc388eb1c0d1b77`
- OpenAI Codex source reference:
  `openai/codex@5bc8da6d78fe32343dc51eaf73b96fd288ae0e87`
- xAI source reference:
  `xai-org/grok-build@eb267feff13129e568df38fb6fdf0ceb65f735d6`
- New VM bootstrap identity:
  `sandbox-bootstrap-rootfs-ext4-v3-openshell-0.0.106-dev.20-g6f3b41f7-*`

The previous uncommitted live attempt reused the prior `f8cbf776` root image
because VM root images use committed `git describe` identity. No cache was
deleted. Committing the focused fix produced the distinct `g6f3b41f7` image
above; the final Codex success ran only after that new image was built.

## Harness and secret boundary

- Grok attended login exited zero at `2026-08-14T14:56:38Z`.
- Codex attended login exited zero at `2026-08-14T14:58:35Z` after Bobby
  enabled ChatGPT device-code authorization.
- The agent never read a verification code, token, auth store, browser session,
  Keychain, `.env`, or credential-bearing process environment.
- Each sandbox checked and reported these variables absent:
  `OPENAI_API_KEY`, `XAI_API_KEY`, `OPENAI_CODEX_OAUTH_ACCESS_TOKEN`,
  `XAI_GROK_ACCESS_TOKEN`, `OPENAI_REFRESH_TOKEN`, and `XAI_REFRESH_TOKEN`.
- OpenClaw was configured with every tool denied. The strict assertion required
  one exact `OPENSHELL_OAUTH_ROUTE_OK` payload, both stop reasons equal to
  `stop`, the selected provider/model as winner, `fallbackUsed=false`, zero
  tool entries, and zero tool-schema characters.
- The tracked Codex OpenClaw config contains an inert, unsigned JWT-shaped
  sentinel only because OpenClaw's native ChatGPT transport parses the account
  id from that configuration field. It is public test data, not an access
  token. The sandbox router removes client-supplied authorization/account
  material and injects only the Gateway-owned route material upstream.

## Matrix

1. `oauth-codex-e2e` attached Grok first and Codex second, then explicitly
   selected `codex-subscription-e2e` / `gpt-5.6-sol`. OpenClaw used
   `openai-chatgpt-responses`, received HTTP 200, and passed every strict
   assertion.
2. `oauth-grok-e2e` attached Codex first and Grok second, then explicitly
   selected `grok-subscription-e2e` / `grok-4.6`. OpenClaw used
   `/v1/chat/completions`, received HTTP 200, and passed every strict assertion.
3. Codex rotation was requested at `2026-08-14T15:35:37Z`; its last-refresh
   generation advanced from `14:58:35Z` to `15:35:38Z`. Both the rotated Codex
   route and untouched Grok route then passed strict OpenClaw assertions.
4. Grok rotation was requested at `2026-08-14T15:36:04Z`; its last-refresh
   generation advanced from `14:56:38Z` to `15:36:04Z`. Grok passed. The first
   untouched Codex check reached HTTP 200 but received an upstream SSE
   `server_error`; OpenClaw surfaced it with no fallback candidate. One bounded
   retry passed at HTTP 200, classifying the event as transient service noise,
   not a refresh or routing failure.
5. Codex logout at `2026-08-14T15:37:04Z` reported successful remote revoke and
   local clear. Its refresh configuration disappeared, OpenClaw received 503
   with no fallback candidate, and a direct supported Responses request also
   received sanitized 503. Grok remained active and passed its strict turn.
6. Grok logout at `2026-08-14T15:37:48Z` reported successful remote revoke and
   local clear. Its refresh configuration disappeared, OpenClaw received 503
   with no fallback candidate, and a direct chat-completions request received
   the same sanitized 503.
7. Terminal provider inventory retained both provider records with zero
   credential keys and zero config keys. Both attached-provider orders remained
   visible, and both refresh-status queries returned no configuration.

The sanitized direct post-logout response for both routes was:

```json
{"error":"cluster inference is not configured","hint":"run: openshell cluster inference set --help"}
```

## Local immutable artifact hashes

The raw runtime logs remain in the governed task root
`/Users/cp-1/Developer/_machine-runs/openshell-oauth-convergence-20260814/runtime/live-proof/`.
They contain no credential values. This tracked table binds the evidence
without committing volatile runtime transcripts.

| Artifact | SHA-256 | Claim |
| --- | --- | --- |
| `final-create-codex-6f3b41f7.log` | `0a1c2a935ab6d3f3cd76a9621cd9a758029aa1aac092eeb759d604f2fd55516d` | Codex reverse-order baseline pass |
| `final-create-grok-6f3b41f7.log` | `30d6f7c599b92c91d806308c5b4e1ad42f6903827cdfe09d4d205bcdbee450ec` | Grok reverse-order baseline pass |
| `final-rotate-codex-6f3b41f7.log` | `7abf16dfeb1e572fd74078d799886fac698ff3d1e37225016bcde8aa33cf8161` | Codex generation advanced |
| `final-after-codex-rotate-codex.log` | `e0388c2599cb131b38187ec3f1a07248fdc9bb475a560e4c8a13711f76399362` | Rotated Codex pass |
| `final-after-codex-rotate-grok.log` | `d39824822b92273269236e1f2d4a2ad9d600e1cac3827cccbf2ab0e11c693d58` | Grok unaffected by Codex rotation |
| `final-rotate-grok-6f3b41f7.log` | `d639426bf9940e892927cc288952803a072aa52f0fdef5dc4d8304cb235383a9` | Grok generation advanced |
| `final-after-grok-rotate-grok.log` | `3b92c359df48348646d55f46446e2dea374aa5692b936f9a02c49f63b321902b` | Rotated Grok pass |
| `final-after-grok-rotate-codex.log` | `bd0bf9f974fa0c3da3fe2ce87a31c373cf299a8893ba2ed550134226078f4f34` | Bounded upstream Codex transient |
| `final-after-grok-rotate-codex-retry1.log` | `61a0d65e599271a9a52299328f3f9cce9efc3b73bb88b3ce9311f472e050555b` | Untouched Codex retry pass |
| `final-logout-codex-6f3b41f7.log` | `bae0a3d98969617560b76587f379c56fc639329448d1b4b85c8cc7ef6fd0920a` | Codex revoke and clear |
| `final-after-codex-logout-codex-openclaw.log` | `8a61b4cfe783d2377864376fdf08f24c61071aa81043495c6bfcbdb92ab94f22` | Codex OpenClaw fail-closed 503 |
| `final-after-codex-logout-grok.log` | `0530198c896e08b157d756efd4a1a0c4018999d96cd4f9056b6ded7931d67abb` | Grok survives Codex logout |
| `final-logout-grok-6f3b41f7.log` | `e03bba2b04ef9604c557689f216361091e4f928165d7ea2a570ac92ab4f5b343` | Grok revoke and clear |
| `final-after-grok-logout-grok-openclaw.log` | `20dce40d32ee11a315928a861554fd624da7ea113f3c4644515d8385b088a22d` | Grok OpenClaw fail-closed 503 |
| `final-fail-closed-direct-6f3b41f7.log` | `c4bfba94949a1d498fbf7f558ced9517a673e6ce6f2b07ae7a91282b3231ed19` | Both direct routes return sanitized 503 |
| `final-state-6f3b41f7.log` | `d79db96cfc750d93ae2d80e0542ee695f34874cb3597d51ec75a7d12babf2cd0` | Final attachment/provider/refresh inventory |

## Cleanup

The two task sandboxes were deleted and the isolated Gateway was shut down at
`2026-08-14T15:39:10Z`. No VM cache, provider record, repository history, or
unrelated runtime state was deleted. Both attended grants are revoked and
locally cleared; a future live use requires a new attended login.
