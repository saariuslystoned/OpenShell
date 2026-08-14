# Subscription OAuth convergence route

- route_id: `openshell-subscription-oauth-convergence-20260814`
- lane_id: `cp1-codex-openshell-subscription-oauth`
- owner: `Codex goal thread 01a0000f-bd50-7cd1-8e1f-79153d2ee300`
- operator: `bobby`
- host_taxonomy: `operator_terminal`
- requested_surface: `Codex goal`
- repo: `saariuslystoned/OpenShell` with `saariuslystoned/OpenShell-grok` as the Grok remote
- branch: `codex/subscription-oauth-convergence-20260814`
- worktree: `/Users/cp-1/Developer/worktrees/OpenShell-subscription-oauth-convergence-20260814`
- base: `origin/codex/2740-openai-codex-oauth@6a2a3dc6f2f32bf47067a5ef15bf78f3bdec9cb5`
- common_upstream_base: `c4b500a7de64d0b66e3ee8098f58d14299092162`
- grok_input: `grok/feat/2742-xai-grok-oauth/saariuslystoned@da8bf1cda063cc309dde4c247218f0c9f062ec6c`
- proof_root: `proof/subscription-oauth-convergence-20260814`
- closer: exact-SHA committed proof plus review-ready PR surfaces; no merge or deploy
- dashboard_state: `active-progress`; live read unavailable because the fixed CP-1 broker points at another checkout
- allowed_task_type: source implementation, tests, docs, proof, and PR preparation
- allowed_mode: `mutate`
- mutation_owner: this coordinator worktree; Grok remains read-only until a recorded serial handoff
- review_rail: independent no-edit OpenClaw autoreview after a pushed exact head
- gates: attended OAuth/account use, upstream PR creation before issue acceptance/vouch, merge, deploy, account/security changes, and destructive operations
- stop_condition: the shared foundation and both adapters satisfy the linked review comment and issues #2740/#2742, all available checks and exact-head proof pass, attended proof is recorded, and review findings are adjudicated

The current explicit Codex goal is the human-authorized route. Canonical CP-1
admission was queried first and returned `authority_unavailable`; this packet
preserves the route fields locally without pretending the canonical ledger was
updated.
