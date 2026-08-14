# Proposed upstream pull request

## Title

`feat(providers): add gateway-owned OpenAI Codex subscription OAuth`

## Body

Refs #2740.

## Summary

Add an experimental OpenAI Codex subscription provider backed by a distinct,
attended Sign in with ChatGPT grant owned by the OpenShell gateway.

- add dedicated `provider login` / `provider logout` commands
- keep reusable OAuth material out of sandbox workloads
- require exact provider attachment before publishing `inference.local`
- pin authorization, token, revocation, and Codex backend endpoints
- add fail-closed refresh, expiry, account-binding, revocation, and concurrency
  handling
- prevent generic provider APIs from injecting or orphaning Codex credentials
- document the subscription/API-key distinction and security boundary

The implementation follows the reviewed public OAuth client and Codex backend
contract used by the official open-source Codex client. It does not import an
existing Codex CLI/Desktop login, claim ownership of OpenAI's client
registration, or identify itself as the first-party Codex CLI.

## Security model

The gateway stores the refresh token and owns token rotation. A trusted
supervisor/router receives only the short-lived access material required for an
attached sandbox's route. The untrusted workload receives neither token and no
direct provider endpoint. Caller-supplied authorization, account, FedRAMP,
originator, and base-URL overrides are rejected or replaced by gateway-owned
values. Expired, in-progress, failed, revoked, or reauthorization-required
grants are not routable.

## Verification

- complete `mise run ci`
- focused server Codex tests: 16 passed
- focused CLI Codex tests: 6 passed
- focused router gateway-owned tests: 2 passed
- local CLI/gateway build
- formatting and diff checks

The committed proof packet is at
`proof/openai-codex-oauth-2740/PROOF.md`.

## Deliberate gate

No live account authorization is included in this source-only contribution.
That requires a separate attended account/security approval. The OAuth and
upstream HTTP behavior is covered with bounded local test servers.
