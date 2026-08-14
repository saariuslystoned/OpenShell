# OpenAI Codex OAuth #2740 — State

Status: PUBLIC_FORK_PUSHED_REVIEW_PENDING

Source base: `c4b500a7de64d0b66e3ee8098f58d14299092162`
(`NVIDIA/OpenShell` current `main` at closeout)

Branch: `codex/2740-openai-codex-oauth`

Worktree:
`/Users/bobbybones/Developer/side-quests/worktrees/openshell-2740-openai-codex-oauth`

Current boundary:

- Gateway-owned experimental `openai-codex-oauth` provider, attended CLI
  login/logout, fail-closed refresh/revocation, exact sandbox attachment,
  pinned routing, dedicated refresh-strategy enforcement, supervisor expiry,
  one-hour local lifetime cap, tests, and documentation are implemented.
- Full repository CI, focused security suites, binary build, formatting, and
  diff checks pass.
- Source implementation is committed at
  `3a321209d6ebe5980f833f9f20c9d8290cf42910`; the additive lifetime repair is
  `67812dd51ae406e582aa62ebb3a9354f7de8d183`; the additive dedicated-strategy
  repair is `ec5fa30048b7fbde6a12d7f41f20909666963f28`. The refreshed source and
  proof checkpoint is published at `7ab45643cfd7c638089877193c89ffdd65ae0392`;
  independent exact-head semantic review remains.
- Upstream PR creation remains gated on issue #2740 acceptance and contributor
  vouch; a draft body is prepared but no PR was opened.
- No live OAuth login, credential access, Spark-2 mutation, deploy, merge, or
  upstream PR occurred.
