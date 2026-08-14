// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider credential refresh state.

#![allow(clippy::result_large_err)]

use crate::persistence::{ObjectType, PersistenceError, Store, WriteCondition, current_time_ms};
use base64::Engine as _;
use openshell_core::ObjectWorkspace;
use openshell_core::proto::{
    CredentialHandle, Provider, ProviderCredentialRefreshStatus, ProviderCredentialRefreshStrategy,
    StoredProviderCredentialRefreshState,
};
use openshell_core::subscription_oauth;
use openshell_core::{ObjectId, ObjectName};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tonic::Status;
use tracing::{info, warn};

const DEFAULT_REFRESH_BEFORE_SECONDS: i64 = 300;
const DEFAULT_MAX_LIFETIME_SECONDS: i64 = 3600;
const REFRESH_ERROR_RETRY_SECONDS: i64 = 60;
const REFRESH_WORKER_PAGE_SIZE: u32 = 1000;
const SUBSCRIPTION_REMOTE_OPERATION_LEASE_SECONDS: i64 =
    subscription_oauth::HTTP_TIMEOUT_SECONDS.cast_signed() + 30;
#[cfg(test)]
pub const OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY: &str =
    subscription_oauth::OPENAI_CODEX_ACCESS_TOKEN_KEY;
#[cfg(test)]
pub const OPENAI_CODEX_OAUTH_CLIENT_ID: &str = subscription_oauth::OPENAI_CODEX_CLIENT_ID;
#[cfg(test)]
pub const OPENAI_CODEX_OAUTH_TOKEN_URL: &str = subscription_oauth::OPENAI_CODEX_TOKEN_URL;
#[cfg(test)]
const MAX_OPENAI_CODEX_OAUTH_RESPONSE_BYTES: usize = subscription_oauth::MAX_RESPONSE_BYTES;

impl ObjectType for StoredProviderCredentialRefreshState {
    fn object_type() -> &'static str {
        "provider_credential_refresh_state"
    }
}

pub fn refresh_state_name(provider_id: &str, credential_key: &str) -> String {
    let mut key = String::with_capacity(credential_key.len() * 2);
    for byte in credential_key.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut key, "{byte:02x}").expect("writing to String cannot fail");
    }
    format!("provider-refresh-{provider_id}-{key}")
}

#[cfg(test)]
pub async fn put_refresh_state(
    store: &Store,
    state: &StoredProviderCredentialRefreshState,
) -> Result<(), Status> {
    store
        .put_scoped_message(state, &state.provider_id)
        .await
        .map_err(|e| Status::internal(format!("persist provider refresh state failed: {e}")))
}

/// Create the first refresh generation without overwriting a concurrent
/// configure from another gateway process. The provider id remains the durable
/// scope used by grant enumeration and generic-delete protection.
pub async fn create_refresh_state_if_absent(
    store: &Store,
    state: &StoredProviderCredentialRefreshState,
) -> Result<Option<u64>, Status> {
    match store
        .create_scoped(
            StoredProviderCredentialRefreshState::object_type(),
            state.object_id(),
            state.object_name(),
            state.object_workspace(),
            &state.provider_id,
            &state.encode_to_vec(),
            None,
        )
        .await
    {
        Ok(result) => Ok(Some(result.resource_version)),
        Err(PersistenceError::UniqueViolation { .. }) => Ok(None),
        Err(error) => Err(Status::internal(format!(
            "persist provider refresh state failed: {error}"
        ))),
    }
}

/// Persist an updated refresh state only if the row still exists with the
/// generation read at the start of the rotation.
///
/// Uses a version-matched UPDATE, which never inserts — so a refresh deleted
/// while an STS (or OAuth) request was in flight is not resurrected, and its
/// stored source-credential material is not recreated (CWE-362). Returns the new
/// resource version when persisted, or `None` when the refresh was deleted or
/// superseded by a concurrent write (in which case nothing was written).
pub async fn persist_refresh_state_if_current(
    store: &Store,
    state: &StoredProviderCredentialRefreshState,
    expected_version: u64,
) -> Result<Option<u64>, Status> {
    match store
        .put_if(
            StoredProviderCredentialRefreshState::object_type(),
            state.object_id(),
            state.object_name(),
            state.object_workspace(),
            &state.encode_to_vec(),
            None,
            WriteCondition::MatchResourceVersion(expected_version),
        )
        .await
    {
        Ok(result) => Ok(Some(result.resource_version)),
        // The version-matched UPDATE matched no row: the refresh was deleted
        // (current version `None`) or superseded by a concurrent write (a
        // different current version). Either way nothing was written.
        Err(PersistenceError::Conflict { .. }) => Ok(None),
        Err(e) => Err(Status::internal(format!(
            "persist provider refresh state failed: {e}"
        ))),
    }
}

pub async fn list_refresh_states_for_provider(
    store: &Store,
    provider_id: &str,
) -> Result<Vec<StoredProviderCredentialRefreshState>, Status> {
    let records = store
        .list_by_scope(
            StoredProviderCredentialRefreshState::object_type(),
            provider_id,
            1000,
            0,
        )
        .await
        .map_err(|e| Status::internal(format!("list provider refresh states failed: {e}")))?;

    let mut states = Vec::with_capacity(records.len());
    for record in records {
        states.push(
            StoredProviderCredentialRefreshState::decode(record.payload.as_slice()).map_err(
                |e| Status::internal(format!("decode provider refresh state failed: {e}")),
            )?,
        );
    }
    Ok(states)
}

pub async fn list_all_refresh_states(
    store: &Store,
) -> Result<Vec<StoredProviderCredentialRefreshState>, Status> {
    let mut states = Vec::new();
    let mut offset = 0;
    loop {
        let records = store
            .list_by_type(
                StoredProviderCredentialRefreshState::object_type(),
                REFRESH_WORKER_PAGE_SIZE,
                offset,
            )
            .await
            .map_err(|e| Status::internal(format!("list provider refresh states failed: {e}")))?;
        if records.is_empty() {
            break;
        }
        offset = offset
            .checked_add(
                u32::try_from(records.len())
                    .map_err(|_| Status::internal("provider refresh page size exceeded u32"))?,
            )
            .ok_or_else(|| Status::internal("provider refresh pagination offset overflow"))?;
        for record in records {
            states.push(
                StoredProviderCredentialRefreshState::decode(record.payload.as_slice()).map_err(
                    |e| Status::internal(format!("decode provider refresh state failed: {e}")),
                )?,
            );
        }
    }
    Ok(states)
}

pub async fn get_refresh_state(
    store: &Store,
    workspace: &str,
    provider_id: &str,
    credential_key: &str,
) -> Result<Option<StoredProviderCredentialRefreshState>, Status> {
    let name = refresh_state_name(provider_id, credential_key);
    store
        .get_message_by_name::<StoredProviderCredentialRefreshState>(workspace, &name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider refresh state failed: {e}")))
}

pub async fn delete_refresh_state(
    store: &Store,
    workspace: &str,
    provider_id: &str,
    credential_key: &str,
) -> Result<bool, Status> {
    let name = refresh_state_name(provider_id, credential_key);
    store
        .delete_by_name(
            StoredProviderCredentialRefreshState::object_type(),
            workspace,
            &name,
        )
        .await
        .map_err(|e| Status::internal(format!("delete provider refresh state failed: {e}")))
}

pub async fn delete_refresh_states_for_provider(
    store: &Store,
    provider_id: &str,
) -> Result<u64, Status> {
    let states = list_refresh_states_for_provider(store, provider_id).await?;
    let mut deleted = 0;
    for state in &states {
        if store
            .delete_by_name(
                StoredProviderCredentialRefreshState::object_type(),
                state.object_workspace(),
                state.object_name(),
            )
            .await
            .map_err(|e| Status::internal(format!("delete provider refresh state failed: {e}")))?
        {
            deleted += 1;
        }
    }
    Ok(deleted)
}

pub fn refresh_status_from_state(
    state: &StoredProviderCredentialRefreshState,
) -> ProviderCredentialRefreshStatus {
    ProviderCredentialRefreshStatus {
        provider_name: state.provider_name.clone(),
        provider_id: state.provider_id.clone(),
        credential_key: state.credential_key.clone(),
        strategy: state.strategy,
        status: state.status.clone(),
        expires_at_ms: state.expires_at_ms,
        next_refresh_at_ms: state.next_refresh_at_ms,
        last_refresh_at_ms: state.last_refresh_at_ms,
        last_error: state.last_error.clone(),
        refresh_generation_id: state.refresh_generation_id.clone(),
    }
}

pub struct NewRefreshStateConfig {
    pub strategy: ProviderCredentialRefreshStrategy,
    pub material: HashMap<String, String>,
    pub secret_material_keys: Vec<String>,
    pub expires_at_ms: i64,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub refresh_before_seconds: i64,
    pub max_lifetime_seconds: i64,
    /// Resolved semantic output id -> concrete env key for credentials this
    /// refresh co-mints beyond its primary. Pinned from the profile's
    /// `additional_outputs` at configure time.
    pub additional_output_keys: HashMap<String, String>,
}

#[allow(clippy::unnecessary_wraps)]
pub fn new_refresh_state(
    provider: &Provider,
    workspace: &str,
    credential_key: &str,
    config: NewRefreshStateConfig,
) -> Result<StoredProviderCredentialRefreshState, Status> {
    let provider_id = provider.object_id().to_string();
    let provider_name = provider.object_name().to_string();
    let now_ms = current_time_ms();
    let next_refresh_at_ms = next_refresh_at_ms(
        config.expires_at_ms,
        config.refresh_before_seconds,
        config.max_lifetime_seconds,
        now_ms,
    );
    Ok(StoredProviderCredentialRefreshState {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: refresh_state_name(&provider_id, credential_key),
            created_at_ms: now_ms,
            labels: HashMap::new(),
            resource_version: 0,
            annotations: HashMap::new(),
            workspace: workspace.to_string(),
            deletion_timestamp_ms: 0,
        }),
        provider_id,
        provider_name,
        credential_key: credential_key.to_string(),
        strategy: config.strategy as i32,
        material: config.material,
        secret_material_keys: config.secret_material_keys,
        expires_at_ms: config.expires_at_ms,
        next_refresh_at_ms,
        last_refresh_at_ms: 0,
        status: "configured".to_string(),
        last_error: String::new(),
        token_url: config.token_url,
        scopes: config.scopes,
        refresh_before_seconds: config.refresh_before_seconds,
        max_lifetime_seconds: config.max_lifetime_seconds,
        additional_output_keys: config.additional_output_keys,
        refresh_generation_id: uuid::Uuid::new_v4().to_string(),
    })
}

struct MintedCredential {
    access_token: String,
    expires_at_ms: i64,
    refresh_token: Option<String>,
    additional_credentials: HashMap<String, String>,
    material_updates: HashMap<String, String>,
}

#[cfg(test)]
impl std::fmt::Debug for MintedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MintedCredential")
            .field("access_token", &"[redacted]")
            .field("expires_at_ms", &self.expires_at_ms)
            .field("refresh_token_present", &self.refresh_token.is_some())
            .field(
                "additional_credential_count",
                &self.additional_credentials.len(),
            )
            .field("material_update_count", &self.material_updates.len())
            .finish()
    }
}

/// Exact provider-side material written by one refresh publication attempt.
///
/// This deliberately does not implement `Debug`: inline values are bearer
/// credentials. The receipt exists only so a losing subscription refresh can
/// conditionally remove its own publication after a concurrent logout (or
/// newer refresh generation) supersedes the final state transition.
struct AppliedCredentialReceipt {
    inline_values: HashMap<String, String>,
    handles: HashMap<String, CredentialHandle>,
    expires_at_ms: i64,
}

#[cfg(test)]
impl std::fmt::Debug for AppliedCredentialReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppliedCredentialReceipt")
            .field("inline_value_count", &self.inline_values.len())
            .field("handle_count", &self.handles.len())
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct GoogleServiceAccountClaims<'a> {
    iss: &'a str,
    scope: String,
    aud: &'a str,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<&'a str>,
}

pub fn next_refresh_at_ms(
    expires_at_ms: i64,
    refresh_before_seconds: i64,
    _max_lifetime_seconds: i64,
    _now_ms: i64,
) -> i64 {
    let refresh_before_seconds = if refresh_before_seconds > 0 {
        refresh_before_seconds
    } else {
        DEFAULT_REFRESH_BEFORE_SECONDS
    };
    if expires_at_ms > 0 {
        return expires_at_ms.saturating_sub(refresh_before_seconds.saturating_mul(1000));
    }
    0
}

fn seconds_until_ms(now_ms: i64, target_ms: i64) -> i64 {
    if target_ms <= 0 {
        return 0;
    }
    target_ms.saturating_sub(now_ms).max(0) / 1000
}

pub fn refresh_strategy_name(strategy: i32) -> &'static str {
    match ProviderCredentialRefreshStrategy::try_from(strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified)
    {
        ProviderCredentialRefreshStrategy::Static => "static",
        ProviderCredentialRefreshStrategy::External => "external",
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken => "oauth2_refresh_token",
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials => "oauth2_client_credentials",
        ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt => "google_service_account_jwt",
        ProviderCredentialRefreshStrategy::AwsStsAssumeRole => "aws_sts_assume_role",
        ProviderCredentialRefreshStrategy::OpenaiCodexOauth => "openai_codex_oauth",
        ProviderCredentialRefreshStrategy::XaiGrokOauth => "xai_grok_oauth",
        ProviderCredentialRefreshStrategy::Unspecified => "unspecified",
    }
}

pub use openshell_providers::is_gateway_mintable_strategy;

pub async fn refresh_provider_credential(
    operation_mutex: &tokio::sync::Mutex<()>,
    store: &Store,
    workspace: &str,
    credentials: Option<&crate::credentials::CredentialRuntime>,
    provider_name: &str,
    credential_key: &str,
) -> Result<StoredProviderCredentialRefreshState, Status> {
    let _operation_guard = operation_mutex.lock().await;
    refresh_provider_credential_inner(store, workspace, credentials, provider_name, credential_key)
        .await
}

async fn refresh_provider_credential_inner(
    store: &Store,
    workspace: &str,
    credentials: Option<&crate::credentials::CredentialRuntime>,
    provider_name: &str,
    credential_key: &str,
) -> Result<StoredProviderCredentialRefreshState, Status> {
    let provider = store
        .get_message_by_name::<Provider>(workspace, provider_name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    let Some(mut state) =
        get_refresh_state(store, workspace, provider.object_id(), credential_key).await?
    else {
        return Err(Status::not_found("provider refresh state not found"));
    };
    // Generation of the refresh at the start of the rotation. Terminal persists
    // match on it so a concurrent delete or rotation is detected rather than
    // clobbered, and a deleted refresh is never recreated (CWE-362).
    let mut expected_version = state
        .metadata
        .as_ref()
        .map_or(0, |meta| meta.resource_version);

    let managed_subscription = ProviderCredentialRefreshStrategy::try_from(state.strategy)
        .is_ok_and(subscription_oauth::is_managed_strategy);
    if managed_subscription && state.status == "reauth_required" {
        return Err(Status::failed_precondition(
            "subscription OAuth authorization requires provider login",
        ));
    }
    if managed_subscription && matches!(state.status.as_str(), "revoking" | "revoke_failed") {
        return Err(Status::failed_precondition(
            "subscription OAuth grant revocation is pending",
        ));
    }
    if managed_subscription && state.status == "rotating" {
        if state.next_refresh_at_ms > current_time_ms() {
            return Err(Status::aborted(
                "subscription OAuth rotation is already in progress",
            ));
        }

        // A lease that expired while the row remained `rotating` is an
        // ambiguous-consumption event: the authority may have spent and
        // rotated the refresh token before the process died. Reusing the
        // predecessor can trigger token-family revocation. Fail closed and
        // require a distinct attended grant instead of making another remote
        // request with material whose consumption state is unknowable.
        state.status = "reauth_required".to_string();
        state.last_error =
            "subscription OAuth rotation outcome is unknown; provider login is required"
                .to_string();
        state.next_refresh_at_ms = 0;
        let Some(_) = persist_refresh_state_if_current(store, &state, expected_version).await?
        else {
            return Err(Status::aborted(
                "subscription OAuth refresh changed while fencing an ambiguous rotation",
            ));
        };
        return Err(Status::failed_precondition(
            "subscription OAuth rotation outcome is unknown; provider login is required",
        ));
    }

    info!(
        provider = %state.provider_name,
        credential_key = %state.credential_key,
        strategy = %refresh_strategy_name(state.strategy),
        status = %state.status,
        expires_at_ms = state.expires_at_ms,
        next_refresh_at_ms = state.next_refresh_at_ms,
        "provider credential refresh started"
    );

    // Enforce the providers_v2 gate on every mint, not just at configure time.
    // Otherwise disabling providers_v2_enabled leaves already-configured refresh
    // states that the worker and manual rotation keep minting from.
    if let Err(err) = ensure_refresh_providers_v2_gate(store, &state).await {
        let now_ms = current_time_ms();
        state.status = "error".to_string();
        state.last_error = err.message().to_string();
        state.next_refresh_at_ms =
            now_ms.saturating_add(REFRESH_ERROR_RETRY_SECONDS.saturating_mul(1000));
        persist_refresh_state_if_current(store, &state, expected_version).await?;
        warn!(
            provider = %state.provider_name,
            credential_key = %state.credential_key,
            strategy = %refresh_strategy_name(state.strategy),
            status = %state.status,
            error = %err,
            "provider credential refresh gate rejected"
        );
        return Err(err);
    }

    if managed_subscription {
        let now_ms = current_time_ms();
        state.status = "rotating".to_string();
        state.next_refresh_at_ms =
            now_ms.saturating_add(SUBSCRIPTION_REMOTE_OPERATION_LEASE_SECONDS.saturating_mul(1000));
        state.last_error.clear();
        let Some(claimed_version) =
            persist_refresh_state_if_current(store, &state, expected_version).await?
        else {
            return Err(Status::aborted(
                "subscription OAuth refresh changed while rotation started",
            ));
        };
        if let Some(metadata) = state.metadata.as_mut() {
            metadata.resource_version = claimed_version;
        }
        expected_version = claimed_version;
    }

    match mint_credential(&state).await {
        Ok(minted) => {
            let now_ms = current_time_ms();
            let subscription_publish = ProviderCredentialRefreshStrategy::try_from(state.strategy)
                .is_ok_and(subscription_oauth::is_managed_strategy);
            if let Some(ref refresh_token) = minted.refresh_token {
                state
                    .material
                    .insert("refresh_token".to_string(), refresh_token.clone());
                if !state
                    .secret_material_keys
                    .iter()
                    .any(|key| key == "refresh_token")
                {
                    state.secret_material_keys.push("refresh_token".to_string());
                }
            }
            for (key, value) in &minted.material_updates {
                state.material.insert(key.clone(), value.clone());
            }
            state.expires_at_ms = minted.expires_at_ms;
            state.next_refresh_at_ms = next_refresh_at_ms(
                minted.expires_at_ms,
                state.refresh_before_seconds,
                state.max_lifetime_seconds,
                now_ms,
            );
            state.last_refresh_at_ms = now_ms;
            // Codex route metadata (account/FedRAMP) lives in this state while
            // the access token lives on the provider. Publish an intermediate,
            // unroutable state first, then mark it refreshed only after the
            // provider credential commit succeeds. This prevents a bundle read
            // from combining new account routing with the predecessor token.
            state.status = if subscription_publish {
                "publishing".to_string()
            } else {
                "refreshed".to_string()
            };
            state.last_error.clear();

            // Claim the refresh generation with a version-matched write BEFORE
            // touching the provider. It succeeds only if the refresh still holds
            // the generation we started from; if it was deleted, recreated, or a
            // concurrent rotation won, it returns `None` and we leave both the
            // refresh state and the provider unchanged — no credentials minted
            // from a stale generation are written, and a deleted refresh is not
            // resurrected (CWE-362). This makes generation ownership the gate on
            // the provider credential write.
            let Some(new_version) =
                persist_refresh_state_if_current(store, &state, expected_version).await?
            else {
                warn!(
                    provider = %state.provider_name,
                    credential_key = %state.credential_key,
                    strategy = %refresh_strategy_name(state.strategy),
                    "provider credential refresh deleted or superseded during rotation; discarding minted credentials"
                );
                return Err(Status::aborted(
                    "provider refresh was deleted or superseded during rotation",
                ));
            };

            // Generation is ours; write the minted credentials into the provider.
            let applied_receipt = match apply_minted_credential(
                store,
                workspace,
                credentials,
                &provider,
                credential_key,
                &minted,
            )
            .await
            {
                Ok(receipt) => receipt,
                Err(err) => {
                    state.status = "error".to_string();
                    state.last_error = err.message().to_string();
                    state.next_refresh_at_ms =
                        now_ms.saturating_add(REFRESH_ERROR_RETRY_SECONDS.saturating_mul(1000));
                    // Reflect the failure on the state we just wrote; skip silently
                    // if it was deleted concurrently (it is not recreated).
                    persist_refresh_state_if_current(store, &state, new_version).await?;
                    warn!(
                        provider = %state.provider_name,
                        credential_key = %state.credential_key,
                        strategy = %refresh_strategy_name(state.strategy),
                        status = %state.status,
                        next_refresh_at_ms = state.next_refresh_at_ms,
                        seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
                        error = %err,
                        "provider credential refresh errored"
                    );
                    return Err(err);
                }
            };
            if subscription_publish {
                state.status = "refreshed".to_string();
                let Some(_) = persist_refresh_state_if_current(store, &state, new_version).await?
                else {
                    // The provider write and refresh-state write are separate
                    // records. A concurrent logout can claim `revoking` after
                    // the intermediate `publishing` state, clear the bearer,
                    // and then lose a race to this provider write. Remove only
                    // values/handles that still exactly match this mint so the
                    // losing refresh cannot leave credential residue and can
                    // never clobber a newer winner.
                    if let Err(cleanup_error) = rollback_applied_minted_credential(
                        store,
                        credentials,
                        &provider,
                        &applied_receipt,
                    )
                    .await
                    {
                        warn!(
                            provider = %state.provider_name,
                            credential_key = %state.credential_key,
                            strategy = %refresh_strategy_name(state.strategy),
                            error = %cleanup_error,
                            "failed to remove superseded subscription credential publication"
                        );
                    }
                    warn!(
                        provider = %state.provider_name,
                        credential_key = %state.credential_key,
                        strategy = %refresh_strategy_name(state.strategy),
                        "provider credential published but refresh state was superseded; route remains unavailable"
                    );
                    return Err(Status::aborted(
                        "provider refresh was superseded while publishing credentials",
                    ));
                };
            }
            info!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                expires_at_ms = state.expires_at_ms,
                next_refresh_at_ms = state.next_refresh_at_ms,
                seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
                "provider credential refresh completed"
            );
            Ok(state)
        }
        Err(err) => {
            let now_ms = current_time_ms();
            let terminal_subscription_grant =
                ProviderCredentialRefreshStrategy::try_from(state.strategy)
                    .is_ok_and(subscription_oauth::is_managed_strategy)
                    && err.code() == tonic::Code::FailedPrecondition;
            state.status = if terminal_subscription_grant {
                "reauth_required".to_string()
            } else {
                "error".to_string()
            };
            state.last_error = err.message().to_string();
            state.next_refresh_at_ms = if terminal_subscription_grant {
                0
            } else {
                now_ms.saturating_add(REFRESH_ERROR_RETRY_SECONDS.saturating_mul(1000))
            };
            persist_refresh_state_if_current(store, &state, expected_version).await?;
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                next_refresh_at_ms = state.next_refresh_at_ms,
                seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
                error = %err,
                "provider credential refresh errored"
            );
            Err(err)
        }
    }
}

async fn apply_minted_credential(
    store: &Store,
    workspace: &str,
    credentials: Option<&crate::credentials::CredentialRuntime>,
    provider: &Provider,
    credential_key: &str,
    minted: &MintedCredential,
) -> Result<AppliedCredentialReceipt, Status> {
    let mut updated = provider.clone();
    let mut inline_values =
        HashMap::from([(credential_key.to_string(), minted.access_token.clone())]);
    inline_values.extend(minted.additional_credentials.clone());
    let staging_id = format!("{}-refresh-{}", provider.object_id(), uuid::Uuid::new_v4());
    let staged_handles = if let Some(credentials) = credentials
        && credentials.stores_provider_credentials()
    {
        let mut creds_to_store =
            HashMap::from([(credential_key.to_string(), minted.access_token.clone())]);
        for (key, value) in &minted.additional_credentials {
            creds_to_store.insert(key.clone(), value.clone());
        }
        // Stage under new handles with a unique staging ID to ensure we don't overwrite
        // the still-committed values before validation/CAS succeeds
        let staged = credentials
            .store_provider_credentials_with_object_id(
                provider.object_name(),
                provider.object_workspace(),
                provider.object_id(),
                &staging_id,
                &creds_to_store,
                &HashMap::new(), // Empty map forces creation of new handles
            )
            .await?;
        if !staged.contains_key(credential_key) {
            cleanup_staged_refresh_handles(credentials, provider, &staged).await;
            return Err(Status::internal(
                "credential driver did not return refreshed credential handle",
            ));
        }
        for (key, handle) in &staged {
            updated.credentials.remove(key);
            updated
                .credential_handles
                .insert(key.clone(), handle.clone());
        }
        Some(staged)
    } else {
        updated
            .credentials
            .insert(credential_key.to_string(), minted.access_token.clone());
        for (key, value) in &minted.additional_credentials {
            updated.credentials.insert(key.clone(), value.clone());
        }
        None
    };
    if minted.expires_at_ms > 0 {
        updated
            .credential_expires_at_ms
            .insert(credential_key.to_string(), minted.expires_at_ms);
        for key in minted.additional_credentials.keys() {
            updated
                .credential_expires_at_ms
                .insert(key.clone(), minted.expires_at_ms);
        }
    } else {
        updated.credential_expires_at_ms.remove(credential_key);
        for key in minted.additional_credentials.keys() {
            updated.credential_expires_at_ms.remove(key);
        }
    }
    if let Err(err) = crate::grpc::provider::validate_provider_update_against_attached_sandboxes(
        store, workspace, &updated,
    )
    .await
    {
        if let Some(credentials) = credentials
            && let Some(handles) = &staged_handles
        {
            cleanup_staged_refresh_handles(credentials, provider, handles).await;
        }
        return Err(err);
    }

    // Capture only handles actually replaced in the CAS snapshot. This avoids
    // deleting unchanged sibling handles and remains correct if another refresh
    // updated the provider after this refresh began.
    let mut old_handles_to_delete = HashMap::new();
    let cas_result = store
        .update_message_cas::<Provider, _>(provider.object_id(), 0, |current| {
            if let Some(handles) = staged_handles.clone() {
                for (key, handle) in &handles {
                    current.credentials.remove(key);
                    if let Some(old_handle) = current
                        .credential_handles
                        .insert(key.clone(), handle.clone())
                        && old_handle != *handle
                    {
                        old_handles_to_delete.insert(key.clone(), old_handle);
                    }
                }
            } else {
                current
                    .credentials
                    .insert(credential_key.to_string(), minted.access_token.clone());
                for (key, value) in &minted.additional_credentials {
                    current.credentials.insert(key.clone(), value.clone());
                }
            }
            if minted.expires_at_ms > 0 {
                current
                    .credential_expires_at_ms
                    .insert(credential_key.to_string(), minted.expires_at_ms);
                for key in minted.additional_credentials.keys() {
                    current
                        .credential_expires_at_ms
                        .insert(key.clone(), minted.expires_at_ms);
                }
            } else {
                current.credential_expires_at_ms.remove(credential_key);
                for key in minted.additional_credentials.keys() {
                    current.credential_expires_at_ms.remove(key);
                }
            }
        })
        .await
        .map(|_| ())
        .map_err(|e| {
            Status::internal(format!("persist refreshed provider credential failed: {e}"))
        });
    if cas_result.is_err()
        && let Some(credentials) = credentials
        && let Some(ref handles) = staged_handles
    {
        cleanup_staged_refresh_handles(credentials, provider, handles).await;
    }

    // If CAS succeeded and we have old handles to delete, clean them up
    if cas_result.is_ok()
        && !old_handles_to_delete.is_empty()
        && let Some(credentials) = credentials
        && let Err(cleanup_err) = credentials
            .delete_provider_credential_handles(
                provider.object_name(),
                provider.object_workspace(),
                provider.object_id(),
                &old_handles_to_delete,
            )
            .await
    {
        warn!(
            provider_name = %provider.object_name(),
            error = %cleanup_err,
            "failed to clean up old provider credential handles after successful refresh"
        );
        // Don't fail the operation - the refresh succeeded, this is just cleanup
    }

    cas_result.map(|()| AppliedCredentialReceipt {
        inline_values: if staged_handles.is_some() {
            HashMap::new()
        } else {
            inline_values
        },
        handles: staged_handles.unwrap_or_default(),
        expires_at_ms: minted.expires_at_ms,
    })
}

fn receipt_expiry_matches(provider: &Provider, key: &str, expires_at_ms: i64) -> bool {
    if expires_at_ms > 0 {
        provider
            .credential_expires_at_ms
            .get(key)
            .is_some_and(|current| *current == expires_at_ms)
    } else {
        !provider.credential_expires_at_ms.contains_key(key)
    }
}

/// Remove a refresh publication only while the current provider still carries
/// the exact inline values or opaque handles written by that attempt. The
/// conditional comparison is evaluated inside the provider CAS closure, so a
/// newer provider update is preserved. A small bounded retry handles an
/// unrelated version race without turning cleanup into an unbounded worker.
async fn rollback_applied_minted_credential(
    store: &Store,
    credentials: Option<&crate::credentials::CredentialRuntime>,
    provider: &Provider,
    receipt: &AppliedCredentialReceipt,
) -> Result<(), Status> {
    const MAX_ROLLBACK_ATTEMPTS: usize = 3;

    for attempt in 1..=MAX_ROLLBACK_ATTEMPTS {
        let mut removed_handles = HashMap::new();
        let result = store
            .update_message_cas::<Provider, _>(provider.object_id(), 0, |current| {
                for (key, value) in &receipt.inline_values {
                    if current.credentials.get(key) == Some(value)
                        && receipt_expiry_matches(current, key, receipt.expires_at_ms)
                    {
                        current.credentials.remove(key);
                        current.credential_expires_at_ms.remove(key);
                    }
                }
                for (key, handle) in &receipt.handles {
                    if current.credential_handles.get(key) == Some(handle)
                        && receipt_expiry_matches(current, key, receipt.expires_at_ms)
                    {
                        current.credential_handles.remove(key);
                        current.credential_expires_at_ms.remove(key);
                        removed_handles.insert(key.clone(), handle.clone());
                    }
                }
            })
            .await;

        match result {
            Ok(_) => {
                if !removed_handles.is_empty()
                    && let Some(credentials) = credentials
                {
                    credentials
                        .delete_provider_credential_handles(
                            provider.object_name(),
                            provider.object_workspace(),
                            provider.object_id(),
                            &removed_handles,
                        )
                        .await?;
                }
                return Ok(());
            }
            Err(PersistenceError::Conflict { .. }) if attempt < MAX_ROLLBACK_ATTEMPTS => {}
            Err(error) => {
                return Err(Status::internal(format!(
                    "rollback superseded provider credential failed: {error}"
                )));
            }
        }
    }

    Err(Status::aborted(
        "provider changed while rolling back superseded credential publication",
    ))
}

async fn cleanup_staged_refresh_handles(
    credentials: &crate::credentials::CredentialRuntime,
    provider: &Provider,
    handles: &HashMap<String, CredentialHandle>,
) {
    if let Err(cleanup_err) = credentials
        .delete_provider_credential_handles(
            provider.object_name(),
            provider.object_workspace(),
            provider.object_id(),
            handles,
        )
        .await
    {
        warn!(
            provider_name = %provider.object_name(),
            error = %cleanup_err,
            "failed to clean up staged provider credentials after refresh failure"
        );
    }
}

/// Reject minting for strategies that require `providers_v2_enabled` when the
/// setting is off. Runs on every refresh (worker sweep and manual rotation), so
/// disabling the setting halts further mints from already-configured states.
async fn ensure_refresh_providers_v2_gate(
    store: &Store,
    state: &StoredProviderCredentialRefreshState,
) -> Result<(), Status> {
    let strategy = ProviderCredentialRefreshStrategy::try_from(state.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    if strategy != ProviderCredentialRefreshStrategy::AwsStsAssumeRole {
        return Ok(());
    }
    if !crate::grpc::policy::global_bool_setting_enabled(
        store,
        openshell_core::settings::PROVIDERS_V2_ENABLED_KEY,
    )
    .await?
    {
        return Err(Status::failed_precondition(
            "aws_sts_assume_role requires providers_v2_enabled=true",
        ));
    }
    Ok(())
}

async fn mint_credential(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    let strategy = ProviderCredentialRefreshStrategy::try_from(state.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    match strategy {
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken => {
            mint_oauth2_refresh_token(state).await
        }
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials => {
            mint_oauth2_client_credentials(state).await
        }
        ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt => {
            mint_google_service_account_jwt(state).await
        }
        ProviderCredentialRefreshStrategy::AwsStsAssumeRole => {
            mint_aws_sts_assume_role(state).await
        }
        ProviderCredentialRefreshStrategy::OpenaiCodexOauth => mint_openai_codex_oauth(state).await,
        ProviderCredentialRefreshStrategy::XaiGrokOauth => mint_xai_grok_oauth(state).await,
        ProviderCredentialRefreshStrategy::External
        | ProviderCredentialRefreshStrategy::Static
        | ProviderCredentialRefreshStrategy::Unspecified => Err(Status::failed_precondition(
            format!("refresh strategy '{strategy:?}' cannot be minted by the gateway"),
        )),
    }
}

async fn mint_oauth2_refresh_token(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    let token_url = oauth2_token_url(state)?;
    let client_id = required_material(&state.material, "client_id")?;
    let refresh_token = required_material(&state.material, "refresh_token")?;
    let mut form = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("client_id".to_string(), client_id),
        ("refresh_token".to_string(), refresh_token),
    ];
    if let Some(client_secret) = material_value(&state.material, &["client_secret"]) {
        form.push(("client_secret".to_string(), client_secret));
    }
    let scope = refresh_scopes(state).join(" ");
    if !scope.is_empty() {
        form.push(("scope".to_string(), scope));
    }

    request_token(&token_url, &form, state.max_lifetime_seconds).await
}

async fn mint_oauth2_client_credentials(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    let token_url = oauth2_token_url(state)?;
    let client_id = required_material(&state.material, "client_id")?;
    let client_secret = required_material(&state.material, "client_secret")?;
    let mut form = vec![
        ("grant_type".to_string(), "client_credentials".to_string()),
        ("client_id".to_string(), client_id),
        ("client_secret".to_string(), client_secret),
    ];
    let scope = refresh_scopes(state).join(" ");
    if !scope.is_empty() {
        form.push(("scope".to_string(), scope));
    }

    request_token(&token_url, &form, state.max_lifetime_seconds).await
}

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)]
struct OpenAiCodexRefreshResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct XaiGrokRefreshResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    token_type: Option<String>,
}

#[derive(Deserialize)]
struct JwtExpiryClaims {
    exp: i64,
}

#[derive(Deserialize)]
struct OpenAiCodexIdClaims {
    #[serde(rename = "https://api.openai.com/auth")]
    auth: Option<OpenAiCodexAuthClaims>,
}

#[derive(Deserialize)]
struct OpenAiCodexAuthClaims {
    chatgpt_account_id: Option<String>,
    #[serde(default)]
    chatgpt_account_is_fedramp: bool,
}

fn decode_jwt_claims<T: for<'de> Deserialize<'de>>(jwt: &str) -> Result<T, Status> {
    let mut parts = jwt.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Status::failed_precondition(
            "OpenAI Codex OAuth returned a malformed JWT; sign in again",
        ));
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(Status::failed_precondition(
            "OpenAI Codex OAuth returned a malformed JWT; sign in again",
        ));
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| {
            Status::failed_precondition(
                "OpenAI Codex OAuth returned a malformed JWT; sign in again",
            )
        })?;
    serde_json::from_slice(&decoded).map_err(|_| {
        Status::failed_precondition("OpenAI Codex OAuth returned invalid claims; sign in again")
    })
}

fn jwt_expiry_ms(jwt: &str, max_lifetime_seconds: i64) -> Result<i64, Status> {
    let claims: JwtExpiryClaims = decode_jwt_claims(jwt)?;
    let asserted_expiry_ms = claims.exp.saturating_mul(1000);
    let now_ms = current_time_ms();
    if asserted_expiry_ms <= now_ms {
        return Err(Status::failed_precondition(
            "OpenAI Codex OAuth returned an expired access token; sign in again",
        ));
    }
    // Treat the token's unverified JWT payload only as an upper bound supplied
    // by the pinned OAuth response. OpenShell owns the local routing lifetime:
    // a malformed or unexpectedly long `exp` must not extend a credential past
    // the reviewed refresh policy.
    let lifetime_cap_seconds = if max_lifetime_seconds > 0 {
        max_lifetime_seconds
    } else {
        DEFAULT_MAX_LIFETIME_SECONDS
    };
    let local_expiry_cap_ms = now_ms.saturating_add(lifetime_cap_seconds.saturating_mul(1000));
    Ok(asserted_expiry_ms.min(local_expiry_cap_ms))
}

fn codex_account_claims(id_token: &str) -> Result<(String, bool), Status> {
    let claims: OpenAiCodexIdClaims = decode_jwt_claims(id_token)?;
    let auth = claims.auth.ok_or_else(|| {
        Status::failed_precondition("OpenAI Codex OAuth response is missing account claims")
    })?;
    let account_id = auth
        .chatgpt_account_id
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            Status::failed_precondition("OpenAI Codex OAuth response is missing account id")
        })?;
    Ok((account_id, auth.chatgpt_account_is_fedramp))
}

/// Provider-specific refresh/revoke and identity behavior behind the shared,
/// bounded, redirect-denying subscription lifecycle.
trait SubscriptionOauthAdapter: Sync {
    fn spec(&self) -> &'static subscription_oauth::SubscriptionOauthSpec;

    fn build_refresh_request(
        &self,
        client: &reqwest::Client,
        endpoint: &str,
        state: &StoredProviderCredentialRefreshState,
    ) -> Result<reqwest::RequestBuilder, Status>;

    /// Parse the access token, expiry, rotated refresh token, and any
    /// provider-bound identity metadata.
    fn parse_refresh_response(
        &self,
        state: &StoredProviderCredentialRefreshState,
        body: &[u8],
    ) -> Result<MintedCredential, Status>;

    fn build_revoke_request(
        &self,
        client: &reqwest::Client,
        endpoint: &str,
        state: &StoredProviderCredentialRefreshState,
    ) -> Result<reqwest::RequestBuilder, Status>;

    fn terminal_refresh_codes(&self) -> &'static [&'static str];
}

struct OpenAiCodexOauthAdapter;
struct XaiGrokOauthAdapter;

static OPENAI_CODEX_ADAPTER: OpenAiCodexOauthAdapter = OpenAiCodexOauthAdapter;
static XAI_GROK_ADAPTER: XaiGrokOauthAdapter = XaiGrokOauthAdapter;

fn subscription_oauth_adapter(
    strategy: ProviderCredentialRefreshStrategy,
) -> Option<&'static dyn SubscriptionOauthAdapter> {
    match strategy {
        ProviderCredentialRefreshStrategy::OpenaiCodexOauth => Some(&OPENAI_CODEX_ADAPTER),
        ProviderCredentialRefreshStrategy::XaiGrokOauth => Some(&XAI_GROK_ADAPTER),
        _ => None,
    }
}

fn subscription_auth_endpoint(
    adapter: &dyn SubscriptionOauthAdapter,
    state: &StoredProviderCredentialRefreshState,
    revoke: bool,
) -> String {
    #[cfg(test)]
    if let Some(base) = state.material.get("test_auth_base_url") {
        let prefix = match adapter.spec().provider {
            subscription_oauth::SubscriptionOauthProvider::OpenAiCodex => "oauth",
            subscription_oauth::SubscriptionOauthProvider::XaiGrok => "oauth2",
        };
        return format!(
            "{}/{prefix}/{}",
            base.trim_end_matches('/'),
            if revoke { "revoke" } else { "token" }
        );
    }
    #[cfg(not(test))]
    let _ = (adapter, state);
    if revoke {
        adapter.spec().revocation_url.to_string()
    } else {
        adapter.spec().token_url.to_string()
    }
}

fn oauth_error_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|error| match error {
                    serde_json::Value::String(code) => Some(code.as_str()),
                    serde_json::Value::Object(object) => {
                        object.get("code").and_then(serde_json::Value::as_str)
                    }
                    _ => None,
                })
                .or_else(|| value.get("code").and_then(serde_json::Value::as_str))
                .map(str::to_ascii_lowercase)
        })
}

fn subscription_refresh_failure(
    adapter: &dyn SubscriptionOauthAdapter,
    status: reqwest::StatusCode,
    body: &[u8],
) -> Status {
    let code = oauth_error_code(body);
    let known_terminal = code
        .as_deref()
        .is_some_and(|code| adapter.terminal_refresh_codes().contains(&code));
    let name = adapter.spec().display_name;
    if known_terminal
        || status == reqwest::StatusCode::BAD_REQUEST
        || status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
    {
        return Status::failed_precondition(format!(
            "{name} subscription authorization requires sign-in"
        ));
    }
    if status == reqwest::StatusCode::REQUEST_TIMEOUT {
        return Status::deadline_exceeded(format!("{name} token refresh timed out"));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Status::resource_exhausted(format!("{name} token refresh was rate limited"));
    }
    Status::unavailable(format!(
        "{name} token refresh temporarily failed (HTTP {})",
        status.as_u16()
    ))
}

async fn bounded_subscription_response_body(
    mut response: reqwest::Response,
    provider_name: &str,
    operation: &str,
) -> Result<Vec<u8>, Status> {
    if response
        .content_length()
        .is_some_and(|length| length > subscription_oauth::MAX_RESPONSE_BYTES as u64)
    {
        return Err(Status::unavailable(format!(
            "{provider_name} {operation} response exceeded the size limit"
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Status::unavailable(format!("{provider_name} {operation} response failed")))?
    {
        if bytes.len().saturating_add(chunk.len()) > subscription_oauth::MAX_RESPONSE_BYTES {
            return Err(Status::unavailable(format!(
                "{provider_name} {operation} response exceeded the size limit"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn bounded_expires_at_ms(expires_in: i64, max_lifetime_seconds: i64) -> Result<i64, Status> {
    if expires_in <= 0 {
        return Err(Status::failed_precondition(
            "subscription OAuth token endpoint returned invalid expiry",
        ));
    }
    let lifetime_cap_seconds = if max_lifetime_seconds > 0 {
        max_lifetime_seconds
    } else {
        DEFAULT_MAX_LIFETIME_SECONDS
    };
    Ok(current_time_ms().saturating_add(expires_in.min(lifetime_cap_seconds).saturating_mul(1000)))
}

impl SubscriptionOauthAdapter for OpenAiCodexOauthAdapter {
    fn spec(&self) -> &'static subscription_oauth::SubscriptionOauthSpec {
        &subscription_oauth::OPENAI_CODEX_SPEC
    }

    fn build_refresh_request(
        &self,
        client: &reqwest::Client,
        endpoint: &str,
        state: &StoredProviderCredentialRefreshState,
    ) -> Result<reqwest::RequestBuilder, Status> {
        let refresh_token = required_material(&state.material, "refresh_token")?;
        Ok(client
            .post(endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({
                "client_id": self.spec().client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }))
            .header("originator", "openshell"))
    }

    fn parse_refresh_response(
        &self,
        state: &StoredProviderCredentialRefreshState,
        body: &[u8],
    ) -> Result<MintedCredential, Status> {
        let expected_account_id = required_material(&state.material, "account_id")?;
        let token: OpenAiCodexRefreshResponse = serde_json::from_slice(body).map_err(|_| {
            Status::failed_precondition("OpenAI Codex token endpoint returned invalid JSON")
        })?;
        let access_token = token
            .access_token
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                Status::failed_precondition("OpenAI Codex token endpoint returned no access token")
            })?;
        let expires_at_ms = jwt_expiry_ms(&access_token, state.max_lifetime_seconds)?;
        let mut material_updates = HashMap::new();
        if let Some(id_token) = token.id_token.filter(|value| !value.trim().is_empty()) {
            let (account_id, is_fedramp) = codex_account_claims(&id_token)?;
            if account_id != expected_account_id {
                return Err(Status::failed_precondition(
                    "OpenAI Codex refreshed a different account; sign in again",
                ));
            }
            material_updates.insert("account_id".to_string(), account_id);
            material_updates.insert("fedramp".to_string(), is_fedramp.to_string());
        }
        Ok(MintedCredential {
            access_token,
            expires_at_ms,
            refresh_token: token.refresh_token.filter(|value| !value.trim().is_empty()),
            additional_credentials: HashMap::new(),
            material_updates,
        })
    }

    fn build_revoke_request(
        &self,
        client: &reqwest::Client,
        endpoint: &str,
        state: &StoredProviderCredentialRefreshState,
    ) -> Result<reqwest::RequestBuilder, Status> {
        let refresh_token = required_material(&state.material, "refresh_token")?;
        Ok(client
            .post(endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({
                "client_id": self.spec().client_id,
                "token": refresh_token,
                "token_type_hint": "refresh_token",
            }))
            .header("originator", "openshell"))
    }

    fn terminal_refresh_codes(&self) -> &'static [&'static str] {
        &[
            "refresh_token_expired",
            "refresh_token_reused",
            "refresh_token_invalidated",
            "invalid_grant",
        ]
    }
}

impl SubscriptionOauthAdapter for XaiGrokOauthAdapter {
    fn spec(&self) -> &'static subscription_oauth::SubscriptionOauthSpec {
        &subscription_oauth::XAI_GROK_SPEC
    }

    fn build_refresh_request(
        &self,
        client: &reqwest::Client,
        endpoint: &str,
        state: &StoredProviderCredentialRefreshState,
    ) -> Result<reqwest::RequestBuilder, Status> {
        let refresh_token = required_material(&state.material, "refresh_token")?;
        let form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("client_id".to_string(), self.spec().client_id.to_string()),
            ("refresh_token".to_string(), refresh_token),
        ];
        Ok(client.post(endpoint).form(&form))
    }

    fn parse_refresh_response(
        &self,
        state: &StoredProviderCredentialRefreshState,
        body: &[u8],
    ) -> Result<MintedCredential, Status> {
        let token: XaiGrokRefreshResponse = serde_json::from_slice(body).map_err(|_| {
            Status::failed_precondition("xAI Grok token endpoint returned invalid JSON")
        })?;
        if token
            .token_type
            .as_deref()
            .is_some_and(|token_type| !token_type.eq_ignore_ascii_case("bearer"))
        {
            return Err(Status::failed_precondition(
                "xAI Grok token endpoint returned unsupported token type",
            ));
        }
        let access_token = token
            .access_token
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                Status::failed_precondition("xAI Grok token endpoint returned no access token")
            })?;
        let expires_at_ms = bounded_expires_at_ms(
            token.expires_in.ok_or_else(|| {
                Status::failed_precondition("xAI Grok token endpoint returned no expiry")
            })?,
            state.max_lifetime_seconds,
        )?;
        Ok(MintedCredential {
            access_token,
            expires_at_ms,
            refresh_token: token.refresh_token.filter(|value| !value.trim().is_empty()),
            additional_credentials: HashMap::new(),
            material_updates: HashMap::new(),
        })
    }

    fn build_revoke_request(
        &self,
        client: &reqwest::Client,
        endpoint: &str,
        state: &StoredProviderCredentialRefreshState,
    ) -> Result<reqwest::RequestBuilder, Status> {
        let refresh_token = required_material(&state.material, "refresh_token")?;
        let form = vec![
            ("client_id".to_string(), self.spec().client_id.to_string()),
            ("token".to_string(), refresh_token),
            ("token_type_hint".to_string(), "refresh_token".to_string()),
        ];
        Ok(client.post(endpoint).form(&form))
    }

    fn terminal_refresh_codes(&self) -> &'static [&'static str] {
        &[
            "invalid_grant",
            "invalid_client",
            "unauthorized_client",
            "access_denied",
            "expired_token",
        ]
    }
}

async fn mint_subscription_oauth(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    let strategy = ProviderCredentialRefreshStrategy::try_from(state.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    let adapter = subscription_oauth_adapter(strategy).ok_or_else(|| {
        Status::invalid_argument("refresh state is not a managed subscription OAuth strategy")
    })?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(
            subscription_oauth::HTTP_TIMEOUT_SECONDS,
        ))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Status::internal("build subscription OAuth client failed"))?;
    let endpoint = subscription_auth_endpoint(adapter, state, false);
    let response = adapter
        .build_refresh_request(&client, &endpoint, state)?
        .send()
        .await
        .map_err(|error| {
            if error.is_connect() {
                Status::unavailable(format!(
                    "{} token refresh connection failed",
                    adapter.spec().display_name
                ))
            } else {
                Status::failed_precondition(format!(
                    "{} token refresh outcome is unknown; provider login is required",
                    adapter.spec().display_name
                ))
            }
        })?;
    let status = response.status();
    let body = match bounded_subscription_response_body(
        response,
        adapter.spec().display_name,
        "token refresh",
    )
    .await
    {
        Ok(body) => body,
        Err(_) if status.is_success() => {
            return Err(Status::failed_precondition(format!(
                "{} token refresh outcome is unknown; provider login is required",
                adapter.spec().display_name
            )));
        }
        Err(_) => return Err(subscription_refresh_failure(adapter, status, &[])),
    };
    if !status.is_success() {
        return Err(subscription_refresh_failure(adapter, status, &body));
    }
    adapter.parse_refresh_response(state, &body)
}

async fn mint_openai_codex_oauth(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    if ProviderCredentialRefreshStrategy::try_from(state.strategy)
        != Ok(ProviderCredentialRefreshStrategy::OpenaiCodexOauth)
    {
        return Err(Status::invalid_argument(
            "refresh state is not openai_codex_oauth",
        ));
    }
    mint_subscription_oauth(state).await
}

async fn mint_xai_grok_oauth(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    if ProviderCredentialRefreshStrategy::try_from(state.strategy)
        != Ok(ProviderCredentialRefreshStrategy::XaiGrokOauth)
    {
        return Err(Status::invalid_argument(
            "refresh state is not xai_grok_oauth",
        ));
    }
    mint_subscription_oauth(state).await
}

fn revoke_is_idempotent_success(body: &[u8]) -> bool {
    matches!(
        oauth_error_code(body).as_deref(),
        Some(
            "invalid_token"
                | "invalid_grant"
                | "refresh_token_expired"
                | "refresh_token_reused"
                | "refresh_token_invalidated"
        )
    )
}

pub async fn revoke_subscription_oauth(
    state: &StoredProviderCredentialRefreshState,
) -> Result<(), Status> {
    let strategy = ProviderCredentialRefreshStrategy::try_from(state.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    let adapter = subscription_oauth_adapter(strategy).ok_or_else(|| {
        Status::invalid_argument(
            "remote revocation is supported only for managed subscription OAuth strategies",
        )
    })?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(
            subscription_oauth::HTTP_TIMEOUT_SECONDS,
        ))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Status::internal("build subscription OAuth revoke client failed"))?;
    let endpoint = subscription_auth_endpoint(adapter, state, true);
    let response = adapter
        .build_revoke_request(&client, &endpoint, state)?
        .send()
        .await
        .map_err(|_| {
            Status::unavailable(format!(
                "{} revoke request failed",
                adapter.spec().display_name
            ))
        })?;
    let status = response.status();
    let body =
        bounded_subscription_response_body(response, adapter.spec().display_name, "revoke").await?;
    if status.is_success() {
        return Ok(());
    }
    // RFC 7009 revocation is idempotent. Some authorities nevertheless report
    // an already-dead grant with an error code; treat only reviewed invalid-grant
    // codes as terminal success so a repeated logout can converge.
    if matches!(
        status,
        reqwest::StatusCode::BAD_REQUEST
            | reqwest::StatusCode::UNAUTHORIZED
            | reqwest::StatusCode::FORBIDDEN
    ) && revoke_is_idempotent_success(&body)
    {
        return Ok(());
    }
    if status == reqwest::StatusCode::BAD_REQUEST
        || status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
    {
        return Err(Status::failed_precondition(format!(
            "{} revoke request was rejected",
            adapter.spec().display_name
        )));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(Status::resource_exhausted(format!(
            "{} revoke request was rate limited",
            adapter.spec().display_name
        )));
    }
    Err(Status::unavailable(format!(
        "{} revoke temporarily failed (HTTP {})",
        adapter.spec().display_name,
        status.as_u16()
    )))
}

async fn mint_google_service_account_jwt(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    let token_url = google_token_url(state);
    let client_email = required_material(&state.material, "client_email")?;
    let private_key = required_material(&state.material, "private_key")?;
    let scopes = refresh_scopes(state);
    if scopes.is_empty() {
        return Err(Status::invalid_argument(
            "google_service_account_jwt requires at least one scope",
        ));
    }
    let now_ms = current_time_ms();
    let now_secs = now_ms / 1000;
    let lifetime_secs = if state.max_lifetime_seconds > 0 {
        state.max_lifetime_seconds.min(DEFAULT_MAX_LIFETIME_SECONDS)
    } else {
        DEFAULT_MAX_LIFETIME_SECONDS
    };
    let subject = material_value(&state.material, &["subject", "sub"]);
    let claims = GoogleServiceAccountClaims {
        iss: &client_email,
        scope: scopes.join(" "),
        aud: &token_url,
        iat: now_secs,
        exp: now_secs.saturating_add(lifetime_secs),
        sub: subject.as_deref(),
    };
    let assertion = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes()).map_err(|_| {
            Status::invalid_argument("google_service_account_jwt private_key must be RSA PEM")
        })?,
    )
    .map_err(|_| Status::internal("sign google service account jwt failed"))?;
    let form = vec![
        (
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
        ),
        ("assertion".to_string(), assertion),
    ];
    request_token(&token_url, &form, lifetime_secs).await
}

async fn mint_aws_sts_assume_role(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, Status> {
    let role_arn = required_material(&state.material, "role_arn")?;
    let session_name = material_value(&state.material, &["session_name"])
        .unwrap_or_else(|| "openshell-sandbox".to_string());
    let external_id = material_value(&state.material, &["external_id"]);
    let region =
        material_value(&state.material, &["aws_region"]).unwrap_or_else(|| "us-east-1".to_string());

    let region_provider = aws_sdk_sts::config::Region::new(region);
    let mut config_loader =
        aws_config::defaults(aws_config::BehaviorVersion::latest()).region(region_provider);

    // Explicit source credentials are all-or-nothing. A lone key must not
    // silently fall through to the gateway's ambient identity (CWE-20): the
    // caller asked for a specific principal, so an incomplete pair is an error.
    // An optional session token supports temporary source credentials (SSO or a
    // prior AssumeRole); it requires the access/secret pair.
    let session_token = material_value(&state.material, &["aws_session_token"]);
    match (
        material_value(&state.material, &["aws_access_key_id"]),
        material_value(&state.material, &["aws_secret_access_key"]),
    ) {
        (Some(access_key), Some(secret_key)) => {
            let creds = aws_sdk_sts::config::Credentials::new(
                access_key,
                secret_key,
                session_token,
                None,
                "openshell-provider-refresh",
            );
            config_loader = config_loader.credentials_provider(creds);
        }
        (None, None) if session_token.is_some() => {
            return Err(Status::invalid_argument(
                "aws_session_token requires aws_access_key_id and aws_secret_access_key",
            ));
        }
        (None, None) => {}
        _ => {
            return Err(Status::invalid_argument(
                "aws_access_key_id and aws_secret_access_key must both be set or both omitted",
            ));
        }
    }

    let sdk_config = config_loader.load().await;
    let sts_config = {
        let mut builder = aws_sdk_sts::config::Builder::from(&sdk_config);
        // Endpoint overrides exist only to point tests at a local mock STS. In
        // production the endpoint is always resolved from the region so a caller
        // cannot redirect an AWS-signed AssumeRole request at an arbitrary
        // service (CWE-918). See `test_sts_endpoint_override`.
        if let Some(endpoint) = test_sts_endpoint_override(state) {
            builder = builder.endpoint_url(endpoint);
        }
        builder.build()
    };
    let client = aws_sdk_sts::Client::from_conf(sts_config);

    let max_lifetime_i64 = if state.max_lifetime_seconds > 0 {
        state.max_lifetime_seconds
    } else {
        DEFAULT_MAX_LIFETIME_SECONDS
    };
    let max_lifetime = i32::try_from(max_lifetime_i64.min(i64::from(i32::MAX))).unwrap_or(i32::MAX);
    let max_lifetime_ms = i64::from(max_lifetime).saturating_mul(1000);

    let mut req = client
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name(&session_name)
        .duration_seconds(max_lifetime);

    if let Some(eid) = external_id {
        req = req.external_id(eid);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| Status::internal(format!("STS AssumeRole failed: {e}")))?;

    let creds = resp
        .credentials()
        .ok_or_else(|| Status::internal("STS AssumeRole response missing credentials"))?;

    let access_key_id = creds.access_key_id().to_string();
    let secret_access_key = creds.secret_access_key().to_string();
    let session_token = creds.session_token().to_string();

    let now_ms = current_time_ms();
    let max_expires = now_ms.saturating_add(max_lifetime_ms);
    let expires_at_ms = creds.expiration().to_millis().unwrap_or(max_expires);
    let expires_at_ms = expires_at_ms.min(max_expires);

    // Map STS response fields to the env keys the profile bound to each semantic
    // output. Configure pins these from the profile's additional_outputs, so a
    // missing mapping means the state was not configured against a valid AWS STS
    // profile binding; refuse rather than guessing standard AWS names.
    let output_values = [
        ("secret_access_key", secret_access_key),
        ("session_token", session_token),
    ];
    let mut additional = HashMap::new();
    for (output_id, value) in output_values {
        let env_key = state.additional_output_keys.get(output_id).ok_or_else(|| {
            Status::failed_precondition(format!(
                "refresh state missing resolved output key for '{output_id}'; reconfigure the AWS STS refresh"
            ))
        })?;
        additional.insert(env_key.clone(), value);
    }

    Ok(MintedCredential {
        access_token: access_key_id,
        expires_at_ms,
        refresh_token: None,
        additional_credentials: additional,
        material_updates: HashMap::new(),
    })
}

async fn request_token(
    token_url: &str,
    form: &[(String, String)],
    max_lifetime_seconds: i64,
) -> Result<MintedCredential, Status> {
    let parsed = reqwest::Url::parse(token_url)
        .map_err(|_| Status::invalid_argument("token_url must be an absolute URL"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if parsed.host_str().is_some_and(is_loopback_host) => {}
        _ => {
            return Err(Status::invalid_argument(
                "token_url must use https, except loopback http for local tests",
            ));
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Status::internal(format!("build refresh HTTP client failed: {e}")))?;
    let response = client
        .post(parsed)
        .form(form)
        .send()
        .await
        .map_err(|e| Status::unavailable(format!("token endpoint request failed: {e}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(Status::failed_precondition(format!(
            "token endpoint returned HTTP {status}"
        )));
    }
    let token = response
        .json::<TokenResponse>()
        .await
        .map_err(|_| Status::failed_precondition("token endpoint returned invalid JSON"))?;
    if token.access_token.trim().is_empty() {
        return Err(Status::failed_precondition(
            "token endpoint returned empty access_token",
        ));
    }
    let now_ms = current_time_ms();
    let lifetime_cap_seconds = if max_lifetime_seconds > 0 {
        max_lifetime_seconds
    } else {
        DEFAULT_MAX_LIFETIME_SECONDS
    };
    let lifetime_seconds = token
        .expires_in
        .filter(|value| *value > 0)
        .unwrap_or(lifetime_cap_seconds);
    let lifetime_seconds = lifetime_seconds.min(lifetime_cap_seconds);
    Ok(MintedCredential {
        access_token: token.access_token,
        expires_at_ms: now_ms.saturating_add(lifetime_seconds.saturating_mul(1000)),
        refresh_token: token
            .refresh_token
            .filter(|refresh_token| !refresh_token.trim().is_empty()),
        additional_credentials: HashMap::new(),
        material_updates: HashMap::new(),
    })
}

pub fn refresh_scopes(state: &StoredProviderCredentialRefreshState) -> Vec<String> {
    if !state.scopes.is_empty() {
        return state.scopes.clone();
    }
    material_scopes(&state.material)
}

pub fn material_scopes(material: &HashMap<String, String>) -> Vec<String> {
    material_value(material, &["scope", "scopes"])
        .map(|raw| {
            raw.split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_material_i64(
    material: &HashMap<String, String>,
    key: &str,
) -> Result<Option<i64>, Status> {
    let Some(value) = material_value(material, &[key]) else {
        return Ok(None);
    };
    value
        .parse::<i64>()
        .map(Some)
        .map_err(|_| Status::invalid_argument(format!("{key} material must be a signed integer")))
}

fn oauth2_token_url(state: &StoredProviderCredentialRefreshState) -> Result<String, Status> {
    if let Some(tenant_id) = material_value(&state.material, &["tenant_id"]) {
        return Ok(format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        ));
    }
    if !state.token_url.trim().is_empty() {
        return Ok(state.token_url.clone());
    }
    Err(Status::invalid_argument(
        "oauth2_client_credentials requires token_url or tenant_id material",
    ))
}

fn google_token_url(state: &StoredProviderCredentialRefreshState) -> String {
    if state.token_url.trim().is_empty() {
        "https://oauth2.googleapis.com/token".to_string()
    } else {
        state.token_url.clone()
    }
}

fn required_material(material: &HashMap<String, String>, key: &str) -> Result<String, Status> {
    material_value(material, &[key])
        .ok_or_else(|| Status::invalid_argument(format!("{key} material is required")))
}

fn material_value(material: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = material.get(*key).map(|value| value.trim())
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Test-only STS endpoint override. Reads the `sts_endpoint_url` material and
/// accepts it only when it is a loopback URL, so unit tests can target a local
/// mock STS. Compiled out of production builds entirely: the configure boundary
/// also rejects the `sts_endpoint_url` material key, so it can never reach a
/// stored refresh state outside tests.
#[cfg(test)]
fn test_sts_endpoint_override(state: &StoredProviderCredentialRefreshState) -> Option<String> {
    material_value(&state.material, &["sts_endpoint_url"]).filter(|endpoint| {
        reqwest::Url::parse(endpoint)
            .ok()
            .and_then(|parsed| parsed.host_str().map(is_loopback_host))
            .unwrap_or(false)
    })
}

#[cfg(not(test))]
#[allow(clippy::missing_const_for_fn)]
fn test_sts_endpoint_override(_state: &StoredProviderCredentialRefreshState) -> Option<String> {
    None
}

pub fn spawn_refresh_worker(state: std::sync::Arc<crate::ServerState>, interval: Duration) {
    info!(
        interval_seconds = interval.as_secs(),
        "provider credential refresh worker started"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(err) = run_refresh_worker_tick(
                &state.provider_refresh_mutex,
                state.store.as_ref(),
                Some(&state.credentials),
            )
            .await
            {
                warn!(error = %err, "provider credential refresh worker tick failed");
            }
        }
    });
}

fn subscription_refresh_requires_operator_action(
    state: &StoredProviderCredentialRefreshState,
) -> bool {
    ProviderCredentialRefreshStrategy::try_from(state.strategy)
        .is_ok_and(subscription_oauth::is_managed_strategy)
        && matches!(
            state.status.as_str(),
            "reauth_required" | "revoking" | "revoke_failed"
        )
}

#[tracing::instrument(
    name = "refresh",
    skip_all,
    fields(
        otel.name = "refresh.provider_credentials",
        watched_count = tracing::field::Empty,
        due_count = tracing::field::Empty,
    )
)]
async fn run_refresh_worker_tick(
    operation_mutex: &tokio::sync::Mutex<()>,
    store: &Store,
    credentials: Option<&crate::credentials::CredentialRuntime>,
) -> Result<(), Status> {
    let now_ms = current_time_ms();
    let states = list_all_refresh_states(store).await.inspect_err(|_| {
        crate::otel_tracing::mark_error(&tracing::Span::current());
    })?;
    let watched_count = states.len();
    let due_count = states
        .iter()
        .filter(|state| {
            !subscription_refresh_requires_operator_action(state)
                && (state.next_refresh_at_ms <= 0 || state.next_refresh_at_ms <= now_ms)
        })
        .count();
    let rotation_requested_count = states
        .iter()
        .filter(|state| state.status == "rotation_requested")
        .count();
    let incomplete_publish_count = states
        .iter()
        .filter(|state| state.status == "publishing")
        .count();
    let span = tracing::Span::current();
    span.record("watched_count", watched_count);
    span.record("due_count", due_count);
    info!(
        watched_count,
        due_count,
        rotation_requested_count,
        incomplete_publish_count,
        "provider credential refresh worker sweep"
    );
    for state in states {
        let strategy = ProviderCredentialRefreshStrategy::try_from(state.strategy)
            .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
        if subscription_refresh_requires_operator_action(&state) {
            info!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                "subscription OAuth refresh awaits provider login or logout retry"
            );
            continue;
        }
        let due = state.next_refresh_at_ms <= 0 || state.next_refresh_at_ms <= now_ms;
        let rotation_requested = state.status == "rotation_requested";
        let incomplete_publish = state.status == "publishing";
        info!(
            provider = %state.provider_name,
            credential_key = %state.credential_key,
            strategy = %refresh_strategy_name(state.strategy),
            status = %state.status,
            expires_at_ms = state.expires_at_ms,
            seconds_until_expiry = seconds_until_ms(now_ms, state.expires_at_ms),
            next_refresh_at_ms = state.next_refresh_at_ms,
            last_refresh_at_ms = state.last_refresh_at_ms,
            seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
            due,
            rotation_requested,
            incomplete_publish,
            "provider credential refresh watch"
        );
        if !due && !rotation_requested && !incomplete_publish {
            continue;
        }
        if !is_gateway_mintable_strategy(strategy) {
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                "skipping non-gateway-mintable provider credential refresh state"
            );
            continue;
        }
        info!(
            provider = %state.provider_name,
            credential_key = %state.credential_key,
            strategy = %refresh_strategy_name(state.strategy),
            status = %state.status,
            "refreshing provider credential"
        );
        if let Err(err) = refresh_provider_credential(
            operation_mutex,
            store,
            state.object_workspace(),
            credentials,
            &state.provider_name,
            &state.credential_key,
        )
        .await
        {
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                next_refresh_at_ms = state.next_refresh_at_ms,
                error = %err,
                "provider credential refresh failed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        NewRefreshStateConfig, delete_refresh_state, get_refresh_state, mint_openai_codex_oauth,
        mint_xai_grok_oauth, new_refresh_state, put_refresh_state,
        refresh_provider_credential_inner as refresh_provider_credential, refresh_state_name,
        refresh_strategy_name, revoke_subscription_oauth, run_refresh_worker_tick,
        seconds_until_ms,
    };
    use crate::credentials::CredentialRuntime;
    use crate::persistence::{current_time_ms, test_store};
    use openshell_core::Config;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{
        Provider, ProviderCredentialRefreshStrategy, Sandbox, SandboxSpec,
    };
    use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
    use std::collections::HashMap;
    use wiremock::matchers::{body_json, body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn refresh_state_name_preserves_distinct_credential_keys() {
        let provider_id = "provider-id";

        assert_ne!(
            refresh_state_name(provider_id, "API_KEY"),
            refresh_state_name(provider_id, "api_key")
        );
        assert_ne!(
            refresh_state_name(provider_id, " alex-api "),
            refresh_state_name(provider_id, " alex_api")
        );
        assert_ne!(
            refresh_state_name(provider_id, "Alex-API"),
            refresh_state_name(provider_id, "alex-api")
        );
    }

    #[test]
    fn refresh_log_helpers_format_safe_operational_fields() {
        assert_eq!(seconds_until_ms(1_000, 61_000), 60);
        assert_eq!(seconds_until_ms(61_000, 1_000), 0);
        assert_eq!(seconds_until_ms(1_000, 0), 0);
        assert_eq!(
            refresh_strategy_name(ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32),
            "oauth2_refresh_token"
        );
        assert_eq!(
            refresh_strategy_name(
                ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32
            ),
            "oauth2_client_credentials"
        );
        assert_eq!(
            refresh_strategy_name(
                ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt as i32
            ),
            "google_service_account_jwt"
        );
        assert_eq!(refresh_strategy_name(i32::MAX), "unspecified");
    }

    fn test_jwt(payload: serde_json::Value) -> String {
        use base64::Engine as _;
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        format!("header.{payload}.signature")
    }

    #[test]
    fn openai_codex_access_token_expiry_is_capped_by_reviewed_lifetime() {
        let now_ms = current_time_ms();
        let far_future_exp = now_ms / 1000 + 24 * 60 * 60;
        let token = test_jwt(serde_json::json!({"exp": far_future_exp}));

        let explicit_cap = super::jwt_expiry_ms(&token, 900).expect("explicit lifetime cap");
        assert!(explicit_cap > now_ms);
        assert!(explicit_cap.saturating_sub(now_ms) <= 901_000);

        let default_cap = super::jwt_expiry_ms(&token, 0).expect("default lifetime cap");
        assert!(default_cap > now_ms);
        assert!(
            default_cap.saturating_sub(now_ms)
                <= super::DEFAULT_MAX_LIFETIME_SECONDS * 1000 + 1_000
        );

        let expired = test_jwt(serde_json::json!({"exp": now_ms / 1000 - 1}));
        assert!(super::jwt_expiry_ms(&expired, 900).is_err());
    }

    fn codex_refresh_state(
        provider: &Provider,
        auth_base_url: &str,
        account_id: &str,
    ) -> openshell_core::proto::StoredProviderCredentialRefreshState {
        new_refresh_state(
            provider,
            "default",
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::OpenaiCodexOauth,
                material: HashMap::from([
                    ("refresh_token".to_string(), "old-refresh-token".to_string()),
                    ("account_id".to_string(), account_id.to_string()),
                    ("fedramp".to_string(), "false".to_string()),
                    ("test_auth_base_url".to_string(), auth_base_url.to_string()),
                ]),
                secret_material_keys: vec![
                    "refresh_token".to_string(),
                    "account_id".to_string(),
                    "fedramp".to_string(),
                ],
                expires_at_ms: 0,
                token_url: super::OPENAI_CODEX_OAUTH_TOKEN_URL.to_string(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 0,
            },
        )
        .expect("Codex refresh state")
    }

    fn grok_refresh_state(
        provider: &Provider,
        auth_base_url: &str,
    ) -> openshell_core::proto::StoredProviderCredentialRefreshState {
        new_refresh_state(
            provider,
            "default",
            openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::XaiGrokOauth,
                material: HashMap::from([
                    (
                        "refresh_token".to_string(),
                        "old-grok-refresh-token".to_string(),
                    ),
                    ("test_auth_base_url".to_string(), auth_base_url.to_string()),
                ]),
                secret_material_keys: vec!["refresh_token".to_string()],
                expires_at_ms: 0,
                token_url: openshell_core::subscription_oauth::XAI_GROK_TOKEN_URL.to_string(),
                scopes: openshell_core::subscription_oauth::XAI_GROK_SCOPES
                    .iter()
                    .map(|scope| (*scope).to_string())
                    .collect(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .expect("Grok refresh state")
    }

    #[tokio::test]
    async fn openai_codex_refresh_rotates_and_persists_gateway_only_material() {
        let mock_server = MockServer::start().await;
        let expires = current_time_ms() / 1000 + 3600;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(header("originator", "openshell"))
            .and(body_json(serde_json::json!({
                "client_id": super::OPENAI_CODEX_OAUTH_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": "old-refresh-token"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": test_jwt(serde_json::json!({"exp": expires})),
                "refresh_token": "rotated-refresh-token",
                "id_token": test_jwt(serde_json::json!({
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "account-123",
                        "chatgpt_account_is_fedramp": true
                    }
                }))
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("codex-subscription", "openai-codex-oauth");
        store.put_message(&provider).await.unwrap();
        let state = codex_refresh_state(&provider, &mock_server.uri(), "account-123");
        put_refresh_state(&store, &state).await.unwrap();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            None,
            "codex-subscription",
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
        )
        .await
        .expect("Codex credential should refresh");
        assert_eq!(refreshed.status, "refreshed");
        assert_eq!(refreshed.material["refresh_token"], "rotated-refresh-token");
        assert_eq!(refreshed.material["account_id"], "account-123");
        assert_eq!(refreshed.material["fedramp"], "true");
        assert!(refreshed.expires_at_ms > current_time_ms());

        let stored = store
            .get_message_by_name::<Provider>("default", "codex-subscription")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials[super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY],
            test_jwt(serde_json::json!({"exp": expires}))
        );
        assert_eq!(
            stored.credential_expires_at_ms[super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY],
            refreshed.expires_at_ms
        );
    }

    #[tokio::test]
    async fn refresh_worker_recovers_an_incomplete_codex_publish_before_its_deadline() {
        let mock_server = MockServer::start().await;
        let expires = current_time_ms() / 1000 + 3600;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": test_jwt(serde_json::json!({"exp": expires})),
                "refresh_token": "recovered-refresh-token",
                "id_token": test_jwt(serde_json::json!({
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "account-123",
                        "chatgpt_account_is_fedramp": false
                    }
                }))
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        crate::grpc::policy::set_global_bool_setting_for_test(
            &store,
            openshell_core::settings::PROVIDERS_V2_ENABLED_KEY,
            true,
        )
        .await
        .unwrap();
        let provider = provider("codex-subscription", "openai-codex-oauth");
        store.put_message(&provider).await.unwrap();
        let mut state = codex_refresh_state(&provider, &mock_server.uri(), "account-123");
        state.status = "publishing".to_string();
        state.next_refresh_at_ms = current_time_ms() + 3_600_000;
        put_refresh_state(&store, &state).await.unwrap();

        let operation_mutex = tokio::sync::Mutex::new(());
        run_refresh_worker_tick(&operation_mutex, &store, None)
            .await
            .unwrap();

        let refreshed = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert_eq!(
            refreshed.material["refresh_token"],
            "recovered-refresh-token"
        );
        let stored = store
            .get_message_by_name::<Provider>("default", "codex-subscription")
            .await
            .unwrap()
            .unwrap();
        assert!(
            stored
                .credentials
                .contains_key(super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY)
        );
    }

    #[tokio::test]
    async fn openai_codex_refresh_classifies_failures_without_echoing_response_secrets() {
        for (status, error_code, expected_code) in [
            (408, "timeout-canary", tonic::Code::DeadlineExceeded),
            (429, "rate-canary", tonic::Code::ResourceExhausted),
            (500, "server-canary", tonic::Code::Unavailable),
            (
                400,
                "refresh_token_invalidated",
                tonic::Code::FailedPrecondition,
            ),
        ] {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_json(serde_json::json!({
                        "error": {"code": error_code},
                        "detail": "response-secret-canary"
                    })),
                )
                .expect(1)
                .mount(&mock_server)
                .await;
            let provider = provider("codex-subscription", "openai-codex-oauth");
            let state = codex_refresh_state(&provider, &mock_server.uri(), "account-123");

            let error = mint_openai_codex_oauth(&state)
                .await
                .expect_err("refresh should fail");
            assert_eq!(error.code(), expected_code);
            assert!(!error.message().contains("response-secret-canary"));
            assert!(!error.message().contains(error_code));
        }
    }

    #[tokio::test]
    async fn openai_codex_refresh_rejects_oversized_response_without_echoing_it() {
        let mock_server = MockServer::start().await;
        let canary = format!(
            "oversized-response-secret-canary{}",
            "x".repeat(super::MAX_OPENAI_CODEX_OAUTH_RESPONSE_BYTES)
        );
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(canary.clone()))
            .expect(1)
            .mount(&mock_server)
            .await;
        let provider = provider("codex-subscription", "openai-codex-oauth");
        let state = codex_refresh_state(&provider, &mock_server.uri(), "account-123");

        let error = mint_openai_codex_oauth(&state)
            .await
            .expect_err("oversized token response must fail");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("outcome is unknown"));
        assert!(!error.message().contains("oversized-response-secret-canary"));
    }

    #[tokio::test]
    async fn terminal_openai_codex_refresh_persists_reauth_required_without_retry() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {"code": "refresh_token_reused"},
                "detail": "response-secret-canary"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let store = test_store().await;
        let provider = provider("codex-subscription", "openai-codex-oauth");
        store.put_message(&provider).await.unwrap();
        let state = codex_refresh_state(&provider, &mock_server.uri(), "account-123");
        put_refresh_state(&store, &state).await.unwrap();

        let error = refresh_provider_credential(
            &store,
            "default",
            None,
            "codex-subscription",
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
        )
        .await
        .expect_err("terminal grant rejection must fail");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        let stored = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored.status, "reauth_required");
        assert_eq!(stored.next_refresh_at_ms, 0);
        assert!(!stored.last_error.contains("response-secret-canary"));
        assert!(!stored.last_error.contains("refresh_token_reused"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn openai_codex_rotation_cannot_publish_after_revocation_claims_generation() {
        let mock_server = MockServer::start().await;
        let (hit_tx, hit_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let expires = current_time_ms() / 1000 + 3600;
        let body = serde_json::json!({
            "access_token": test_jwt(serde_json::json!({"exp": expires})),
            "refresh_token": "rotated-refresh-token",
            "id_token": test_jwt(serde_json::json!({
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "account-123",
                    "chatgpt_account_is_fedramp": false
                }
            }))
        })
        .to_string();
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(GatedStsResponder {
                hit: std::sync::Mutex::new(Some(hit_tx)),
                release: std::sync::Mutex::new(release_rx),
                body,
            })
            .expect(1)
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        crate::grpc::policy::set_global_bool_setting_for_test(
            &store,
            openshell_core::settings::PROVIDERS_V2_ENABLED_KEY,
            true,
        )
        .await
        .unwrap();
        let provider = provider("codex-subscription", "openai-codex-oauth");
        store.put_message(&provider).await.unwrap();
        let state = codex_refresh_state(&provider, &mock_server.uri(), "account-123");
        put_refresh_state(&store, &state).await.unwrap();

        let rotate = refresh_provider_credential(
            &store,
            "default",
            None,
            "codex-subscription",
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
        );
        let claim_revocation = async {
            tokio::time::timeout(std::time::Duration::from_secs(15), hit_rx)
                .await
                .expect("refresh should reach token endpoint")
                .expect("refresh hit sender should remain available");
            let mut current = get_refresh_state(
                &store,
                "default",
                provider.object_id(),
                super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
            )
            .await
            .unwrap()
            .unwrap();
            let expected_version = current.metadata.as_ref().unwrap().resource_version;
            current.status = "revoking".to_string();
            current.next_refresh_at_ms = 0;
            super::persist_refresh_state_if_current(&store, &current, expected_version)
                .await
                .unwrap()
                .expect("revocation must claim refresh generation");
            release_tx.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(rotate, claim_revocation);

        assert_eq!(result.unwrap_err().code(), tonic::Code::Aborted);
        let current = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(current.status, "revoking");
        assert_eq!(current.material["refresh_token"], "old-refresh-token");
        let stored = store
            .get_message_by_name::<Provider>("default", "codex-subscription")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored
                .credentials
                .contains_key(super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY)
        );
    }

    #[tokio::test]
    async fn openai_codex_refresh_rejects_account_switch() {
        let mock_server = MockServer::start().await;
        let expires = current_time_ms() / 1000 + 3600;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": test_jwt(serde_json::json!({"exp": expires})),
                "id_token": test_jwt(serde_json::json!({
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "different-account",
                        "chatgpt_account_is_fedramp": false
                    }
                }))
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let provider = provider("codex-subscription", "openai-codex-oauth");
        let state = codex_refresh_state(&provider, &mock_server.uri(), "account-123");

        let error = mint_openai_codex_oauth(&state)
            .await
            .expect_err("account switch must fail closed");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(!error.message().contains("different-account"));
        assert!(!error.message().contains("account-123"));
    }

    #[tokio::test]
    async fn xai_grok_refresh_uses_pinned_contract_and_persists_rotated_grant() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains(format!(
                "client_id={}",
                openshell_core::subscription_oauth::XAI_GROK_CLIENT_ID
            )))
            .and(body_string_contains("refresh_token=old-grok-refresh-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "grok-access-token-canary",
                "refresh_token": "rotated-grok-refresh-token",
                "expires_in": 7200,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider(
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_PROVIDER_TYPE,
        );
        store.put_message(&provider).await.unwrap();
        let state = grok_refresh_state(&provider, &mock_server.uri());
        put_refresh_state(&store, &state).await.unwrap();
        let before_ms = current_time_ms();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            None,
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
        )
        .await
        .expect("Grok credential should refresh");
        assert_eq!(refreshed.status, "refreshed");
        assert_eq!(
            refreshed.material["refresh_token"],
            "rotated-grok-refresh-token"
        );
        assert!(refreshed.expires_at_ms > before_ms);
        assert!(refreshed.expires_at_ms <= before_ms + 3_601_000);

        let stored = store
            .get_message_by_name::<Provider>("default", "grok-subscription")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials[openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY],
            "grok-access-token-canary"
        );
        assert_eq!(
            stored.credential_expires_at_ms
                [openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY],
            refreshed.expires_at_ms
        );
        assert!(
            !stored
                .credentials
                .values()
                .any(|value| value == "rotated-grok-refresh-token")
        );
        let requests = mock_server.received_requests().await.unwrap();
        let request_body = String::from_utf8_lossy(&requests[0].body);
        assert!(
            !request_body
                .split('&')
                .any(|parameter| parameter.starts_with("scope=")),
            "xAI refresh must preserve the original grant by omitting scope"
        );
    }

    #[tokio::test]
    async fn dual_subscription_rotation_is_provider_and_generation_isolated() {
        let mock_server = MockServer::start().await;
        let codex_expires = current_time_ms() / 1000 + 3600;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_json(serde_json::json!({
                "client_id": super::OPENAI_CODEX_OAUTH_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": "old-refresh-token"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": test_jwt(serde_json::json!({"exp": codex_expires})),
                "refresh_token": "rotated-codex-refresh-token",
                "id_token": test_jwt(serde_json::json!({
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "account-123",
                        "chatgpt_account_is_fedramp": false
                    }
                }))
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("refresh_token=old-grok-refresh-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "grok-access-token-canary",
                "refresh_token": "rotated-grok-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let codex = provider("codex-subscription", "openai-codex-oauth");
        let grok = provider(
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_PROVIDER_TYPE,
        );
        store.put_message(&codex).await.unwrap();
        store.put_message(&grok).await.unwrap();
        let codex_state = codex_refresh_state(&codex, &mock_server.uri(), "account-123");
        let grok_state = grok_refresh_state(&grok, &mock_server.uri());
        let codex_generation = codex_state.refresh_generation_id.clone();
        let grok_generation = grok_state.refresh_generation_id.clone();
        put_refresh_state(&store, &codex_state).await.unwrap();
        put_refresh_state(&store, &grok_state).await.unwrap();

        refresh_provider_credential(
            &store,
            "default",
            None,
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
        )
        .await
        .expect("Grok should rotate independently");
        let untouched_codex = get_refresh_state(
            &store,
            "default",
            codex.object_id(),
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(untouched_codex.refresh_generation_id, codex_generation);
        assert_eq!(
            untouched_codex.material["refresh_token"],
            "old-refresh-token"
        );
        let codex_record = store
            .get_message_by_name::<Provider>("default", "codex-subscription")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !codex_record
                .credentials
                .contains_key(super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY)
        );

        refresh_provider_credential(
            &store,
            "default",
            None,
            "codex-subscription",
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
        )
        .await
        .expect("Codex should rotate independently");
        let rotated_grok = get_refresh_state(
            &store,
            "default",
            grok.object_id(),
            openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(rotated_grok.refresh_generation_id, grok_generation);
        assert_eq!(
            rotated_grok.material["refresh_token"],
            "rotated-grok-refresh-token"
        );
        let grok_record = store
            .get_message_by_name::<Provider>("default", "grok-subscription")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            grok_record.credentials[openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY],
            "grok-access-token-canary"
        );
        let rotated_codex = get_refresh_state(
            &store,
            "default",
            codex.object_id(),
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(rotated_codex.refresh_generation_id, codex_generation);
        assert_eq!(
            rotated_codex.material["refresh_token"],
            "rotated-codex-refresh-token"
        );
    }

    #[tokio::test]
    async fn xai_grok_refresh_classifies_retryable_and_terminal_errors_without_leaks() {
        for (status, error_code, expected_code) in [
            (408, "timeout-canary", tonic::Code::DeadlineExceeded),
            (429, "rate-canary", tonic::Code::ResourceExhausted),
            (500, "server-canary", tonic::Code::Unavailable),
            (400, "invalid_grant", tonic::Code::FailedPrecondition),
        ] {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/oauth2/token"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_json(serde_json::json!({
                        "error": error_code,
                        "error_description": "grok-response-secret-canary"
                    })),
                )
                .expect(1)
                .mount(&mock_server)
                .await;
            let provider = provider(
                "grok-subscription",
                openshell_core::subscription_oauth::XAI_GROK_PROVIDER_TYPE,
            );
            let state = grok_refresh_state(&provider, &mock_server.uri());

            let error = mint_xai_grok_oauth(&state)
                .await
                .expect_err("Grok refresh should fail");
            assert_eq!(error.code(), expected_code);
            assert!(!error.message().contains("grok-response-secret-canary"));
            assert!(!error.message().contains(error_code));
        }
    }

    #[tokio::test]
    async fn xai_grok_gateway_http_denies_redirects_and_bounds_failures() {
        let redirect_target = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/stolen"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&redirect_target)
            .await;
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/stolen", redirect_target.uri()))
                    .set_body_string("redirect-response-secret-canary"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;
        let provider = provider(
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_PROVIDER_TYPE,
        );
        let state = grok_refresh_state(&provider, &mock_server.uri());

        let error = mint_xai_grok_oauth(&state)
            .await
            .expect_err("redirect must not be followed");
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(!error.message().contains("redirect-response-secret-canary"));
        assert!(!error.message().contains(&redirect_target.uri()));
    }

    #[tokio::test]
    async fn xai_grok_terminal_refresh_requires_reauthentication() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "terminal-response-secret-canary"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let store = test_store().await;
        let provider = provider(
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_PROVIDER_TYPE,
        );
        store.put_message(&provider).await.unwrap();
        let state = grok_refresh_state(&provider, &mock_server.uri());
        put_refresh_state(&store, &state).await.unwrap();

        let error = refresh_provider_credential(
            &store,
            "default",
            None,
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
        )
        .await
        .expect_err("terminal grant rejection must fail");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        let stored = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored.status, "reauth_required");
        assert_eq!(stored.next_refresh_at_ms, 0);
        assert!(
            !stored
                .last_error
                .contains("terminal-response-secret-canary")
        );
        assert!(!stored.last_error.contains("invalid_grant"));

        let retry = refresh_provider_credential(
            &store,
            "default",
            None,
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
        )
        .await
        .expect_err("terminal state must require a new attended login");
        assert_eq!(retry.code(), tonic::Code::FailedPrecondition);
        assert!(retry.message().contains("provider login"));
    }

    #[tokio::test]
    async fn refresh_worker_does_not_retry_terminal_subscription_grants() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;
        let store = test_store().await;
        let provider = provider(
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_PROVIDER_TYPE,
        );
        store.put_message(&provider).await.unwrap();
        let mut state = grok_refresh_state(&provider, &mock_server.uri());
        state.status = "reauth_required".to_string();
        state.next_refresh_at_ms = 0;
        put_refresh_state(&store, &state).await.unwrap();

        let operation_mutex = tokio::sync::Mutex::new(());
        run_refresh_worker_tick(&operation_mutex, &store, None)
            .await
            .unwrap();

        let stored = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored.status, "reauth_required");
        assert_eq!(stored.next_refresh_at_ms, 0);
        assert_eq!(stored.material["refresh_token"], "old-grok-refresh-token");
    }

    #[tokio::test]
    async fn expired_rotation_lease_requires_reauthentication_without_reusing_refresh_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "must-not-be-minted",
                "refresh_token": "must-not-be-rotated",
                "expires_in": 3600
            })))
            .expect(0)
            .mount(&mock_server)
            .await;
        let store = test_store().await;
        let provider = provider(
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_PROVIDER_TYPE,
        );
        store.put_message(&provider).await.unwrap();
        let mut state = grok_refresh_state(&provider, &mock_server.uri());
        state.status = "rotating".to_string();
        state.next_refresh_at_ms = current_time_ms() - 1;
        put_refresh_state(&store, &state).await.unwrap();

        let error = refresh_provider_credential(
            &store,
            "default",
            None,
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
        )
        .await
        .expect_err("an ambiguous spent-token outcome must fail closed");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("outcome is unknown"));

        let stored = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            openshell_core::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored.status, "reauth_required");
        assert_eq!(stored.next_refresh_at_ms, 0);
        assert_eq!(stored.material["refresh_token"], "old-grok-refresh-token");
        mock_server.verify().await;
    }

    #[tokio::test]
    async fn xai_grok_revoke_is_remote_bounded_and_idempotent() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/revoke"))
            .and(body_string_contains("token=old-grok-refresh-token"))
            .and(body_string_contains("token_type_hint=refresh_token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "already-dead-response-canary"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let provider = provider(
            "grok-subscription",
            openshell_core::subscription_oauth::XAI_GROK_PROVIDER_TYPE,
        );
        let state = grok_refresh_state(&provider, &mock_server.uri());
        revoke_subscription_oauth(&state)
            .await
            .expect("invalid_grant is an idempotent revoke success");

        let retry_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/revoke"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "revoke-response-secret-canary"
            })))
            .expect(1)
            .mount(&retry_server)
            .await;
        let retry_state = grok_refresh_state(&provider, &retry_server.uri());
        let error = revoke_subscription_oauth(&retry_state)
            .await
            .expect_err("transient revoke failure must remain retryable");
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(!error.message().contains("revoke-response-secret-canary"));
        assert!(!error.message().contains("invalid_grant"));
    }

    #[tokio::test]
    async fn oauth2_client_credentials_refresh_mints_and_persists_access_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("client_id=client-id"))
            .and(body_string_contains(
                "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-graph-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-graph", "outlook");
        store.put_message(&provider).await.unwrap();
        let before_refresh_ms = current_time_ms();
        let state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: vec!["https://graph.microsoft.com/.default".to_string()],
                refresh_before_seconds: 30,
                max_lifetime_seconds: 60,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            None,
            "my-graph",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);
        assert!(refreshed.next_refresh_at_ms > 0);
        assert!(refreshed.expires_at_ms <= before_refresh_ms + 120_000);
        assert!(refreshed.last_error.is_empty());

        let stored = store
            .get_message_by_name::<Provider>("default", "my-graph")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&"minted-graph-token".to_string())
        );
        assert_eq!(
            stored.credential_expires_at_ms.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&refreshed.expires_at_ms)
        );
    }

    #[tokio::test]
    async fn oauth2_client_credentials_refresh_stores_access_token_with_credential_runtime() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "stored-graph-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-stored-graph", "outlook");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: Vec::new(),
                refresh_before_seconds: 30,
                max_lifetime_seconds: 60,
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = CredentialRuntime::from_config(&config).unwrap();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            Some(&credentials),
            "my-stored-graph",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap();

        let stored = store
            .get_message_by_name::<Provider>("default", "my-stored-graph")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.credentials.contains_key("MS_GRAPH_ACCESS_TOKEN"));
        let handle = stored
            .credential_handles
            .get("MS_GRAPH_ACCESS_TOKEN")
            .unwrap();
        assert_eq!(handle.driver, "test-static");
        assert_eq!(
            stored.credential_expires_at_ms.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&refreshed.expires_at_ms)
        );

        let resolved = credentials
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&"stored-graph-token".to_string())
        );
    }

    #[tokio::test]
    async fn refresh_rejects_minted_credential_key_collision_for_attached_sandbox() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-graph-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let mut provider_a = provider("existing-graph", "outlook");
        provider_a.credentials.insert(
            "MS_GRAPH_ACCESS_TOKEN".to_string(),
            "existing-token".to_string(),
        );
        store.put_message(&provider_a).await.unwrap();
        let provider_b = provider("refreshing-graph", "outlook");
        store.put_message(&provider_b).await.unwrap();
        store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: "sandbox-collision".to_string(),
                    name: "collision".to_string(),
                    created_at_ms: 1,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["existing-graph".to_string(), "refreshing-graph".to_string()],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        let state = new_refresh_state(
            &provider_b,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: Vec::new(),
                refresh_before_seconds: 30,
                max_lifetime_seconds: 60,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let err = refresh_provider_credential(
            &store,
            "default",
            None,
            "refreshing-graph",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("MS_GRAPH_ACCESS_TOKEN"));
        let stored_state = get_refresh_state(
            &store,
            "default",
            provider_b.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored_state.status, "error");
        assert!(stored_state.last_error.contains("MS_GRAPH_ACCESS_TOKEN"));
        let stored_provider = store
            .get_message_by_name::<Provider>("default", "refreshing-graph")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored_provider
                .credentials
                .contains_key("MS_GRAPH_ACCESS_TOKEN")
        );
    }

    #[tokio::test]
    async fn oauth2_refresh_token_refresh_mints_access_token_and_persists_rotated_refresh_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("client_id=client-id"))
            .and(body_string_contains("refresh_token=old-refresh-token"))
            .and(body_string_contains(
                "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "delegated-graph-token",
                "refresh_token": "rotated-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-delegated-graph", "outlook");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("refresh_token".to_string(), "old-refresh-token".to_string()),
                ]),
                secret_material_keys: vec!["refresh_token".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: vec!["https://graph.microsoft.com/.default".to_string()],
                refresh_before_seconds: 30,
                max_lifetime_seconds: 60,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            None,
            "my-delegated-graph",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);

        let stored_provider = store
            .get_message_by_name::<Provider>("default", "my-delegated-graph")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_provider.credentials.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&"delegated-graph-token".to_string())
        );
        assert_eq!(
            stored_provider
                .credential_expires_at_ms
                .get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&refreshed.expires_at_ms)
        );

        let stored_state = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            stored_state.material.get("refresh_token"),
            Some(&"rotated-refresh-token".to_string())
        );
        assert!(
            stored_state
                .secret_material_keys
                .iter()
                .any(|key| key == "refresh_token")
        );
    }

    #[tokio::test]
    async fn google_service_account_refresh_mints_and_persists_access_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
            ))
            .and(body_string_contains("assertion="))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-drive-token",
                "expires_in": 1800,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-drive", "google-drive");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "default",
            "GOOGLE_DRIVE_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt,
                material: HashMap::from([
                    (
                        "client_email".to_string(),
                        "svc@example.iam.gserviceaccount.com".to_string(),
                    ),
                    ("private_key".to_string(), TEST_RSA_PRIVATE_KEY.to_string()),
                ]),
                secret_material_keys: vec!["private_key".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: vec!["https://www.googleapis.com/auth/drive.readonly".to_string()],
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            None,
            "my-drive",
            "GOOGLE_DRIVE_ACCESS_TOKEN",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);

        let stored = store
            .get_message_by_name::<Provider>("default", "my-drive")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("GOOGLE_DRIVE_ACCESS_TOKEN"),
            Some(&"minted-drive-token".to_string())
        );
    }

    #[tokio::test]
    async fn refresh_worker_skips_non_gateway_mintable_strategies() {
        let store = test_store().await;
        let provider = provider("my-external", "outlook");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::External,
                material: HashMap::new(),
                secret_material_keys: Vec::new(),
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 0,
                max_lifetime_seconds: 0,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let operation_mutex = tokio::sync::Mutex::new(());
        run_refresh_worker_tick(&operation_mutex, &store, None)
            .await
            .unwrap();

        let stored_state = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_ne!(stored_state.status, "error");
        assert!(stored_state.last_error.is_empty());

        let stored_provider = store
            .get_message_by_name::<Provider>("default", "my-external")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored_provider
                .credentials
                .contains_key("MS_GRAPH_ACCESS_TOKEN")
        );
    }

    /// The worker ticks on a timer with no inbound request, so without a span
    /// of its own its store reads export as anonymous single-span traces.
    #[tokio::test]
    #[ignore = "flaky under concurrent test execution"]
    async fn refresh_worker_ticks_are_roots_and_store_operations_have_parents() {
        use crate::otel_tracing::test_exporter;

        let store = test_store().await;

        let traced = test_exporter::install_traced();
        let operation_mutex = tokio::sync::Mutex::new(());
        run_refresh_worker_tick(&operation_mutex, &store, None)
            .await
            .unwrap();

        let spans = traced.finished_spans();
        let root = spans
            .iter()
            .find(|s| s.name == "refresh.provider_credentials")
            .unwrap_or_else(|| {
                panic!(
                    "the tick records a span of its own, got {:?}",
                    spans.iter().map(|s| &s.name).collect::<Vec<_>>()
                )
            });

        test_exporter::assert_is_root(root);
        let store_span = spans
            .iter()
            .find(|span| {
                span.name.starts_with("store.")
                    && span.span_context.trace_id() == root.span_context.trace_id()
            })
            .expect("the tick records its store operation");
        test_exporter::assert_has_parent(store_span);
    }

    #[test]
    fn refresh_strategy_name_includes_aws_sts() {
        assert_eq!(
            refresh_strategy_name(ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32),
            "aws_sts_assume_role"
        );
    }

    #[test]
    fn aws_sts_max_expires_saturates_on_saturated_clock() {
        assert_eq!(i64::MAX.saturating_add(3_600_000), i64::MAX);
        let now_ms = i64::MAX - 1_000;
        let max_lifetime_ms = 3_600_000;
        let max_expires = now_ms.saturating_add(max_lifetime_ms);
        assert_eq!(max_expires, i64::MAX);
        assert!(max_expires >= now_ms);
    }

    #[tokio::test]
    async fn aws_sts_assume_role_mints_three_credentials_from_mock_endpoint() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .and(body_string_contains("RoleArn=arn"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <AssumedRoleUser>
      <AssumedRoleId>AROA3XFRBF23:test-session</AssumedRoleId>
      <Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test-session</Arn>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>"#,
            ))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        crate::grpc::policy::set_global_bool_setting_for_test(
            &store,
            openshell_core::settings::PROVIDERS_V2_ENABLED_KEY,
            true,
        )
        .await
        .unwrap();
        let prov = provider("aws-sts-test", "aws");
        store.put_message(&prov).await.unwrap();

        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("session_name".to_string(), "test-session".to_string()),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "TestSecretKey".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec!["aws_secret_access_key".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            None,
            "aws-sts-test",
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);

        let stored = store
            .get_message_by_name::<Provider>("default", "aws-sts-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("AWS_ACCESS_KEY_ID"),
            Some(&"ASIAMOCKKEY".to_string())
        );
        assert_eq!(
            stored.credentials.get("AWS_SECRET_ACCESS_KEY"),
            Some(&"MockSecretAccessKey123".to_string())
        );
        assert_eq!(
            stored.credentials.get("AWS_SESSION_TOKEN"),
            Some(&"MockSessionTokenXYZ".to_string())
        );
    }

    #[tokio::test]
    async fn aws_sts_mint_writes_to_resolved_additional_output_keys() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#,
            ))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        crate::grpc::policy::set_global_bool_setting_for_test(
            &store,
            openshell_core::settings::PROVIDERS_V2_ENABLED_KEY,
            true,
        )
        .await
        .unwrap();
        let prov = provider("aws-sts-custom", "aws");
        store.put_message(&prov).await.unwrap();

        // The minter honors the resolved output->env-key map from state, not
        // hardcoded AWS names.
        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    ("secret_access_key".to_string(), "CUSTOM_SECRET".to_string()),
                    ("session_token".to_string(), "CUSTOM_SESSION".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "TestSecretKey".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec!["aws_secret_access_key".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        refresh_provider_credential(
            &store,
            "default",
            None,
            "aws-sts-custom",
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap();

        let stored = store
            .get_message_by_name::<Provider>("default", "aws-sts-custom")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("AWS_ACCESS_KEY_ID"),
            Some(&"ASIAMOCKKEY".to_string())
        );
        assert_eq!(
            stored.credentials.get("CUSTOM_SECRET"),
            Some(&"MockSecretAccessKey123".to_string())
        );
        assert_eq!(
            stored.credentials.get("CUSTOM_SESSION"),
            Some(&"MockSessionTokenXYZ".to_string())
        );
        assert!(!stored.credentials.contains_key("AWS_SECRET_ACCESS_KEY"));
    }

    #[tokio::test]
    async fn aws_sts_mint_rejects_partial_source_credentials() {
        let store = test_store().await;
        crate::grpc::policy::set_global_bool_setting_for_test(
            &store,
            openshell_core::settings::PROVIDERS_V2_ENABLED_KEY,
            true,
        )
        .await
        .unwrap();
        let prov = provider("aws-sts-partial", "aws");
        store.put_message(&prov).await.unwrap();

        // Only the access key half of the explicit source pair is present. The
        // mint must fail rather than fall back to the gateway's ambient identity.
        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                ]),
                secret_material_keys: Vec::new(),
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let err = refresh_provider_credential(
            &store,
            "default",
            None,
            "aws-sts-partial",
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("both be set or both omitted"));

        let stored = store
            .get_message_by_name::<Provider>("default", "aws-sts-partial")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.credentials.contains_key("AWS_ACCESS_KEY_ID"));
    }

    #[tokio::test]
    async fn apply_minted_credential_writes_additional_keys() {
        use super::apply_minted_credential;

        let store = test_store().await;
        let mut prov = provider("aws-test", "aws");
        prov.credentials
            .insert("AWS_ACCESS_KEY_ID".to_string(), "old-key".to_string());
        store.put_message(&prov).await.unwrap();

        let minted = super::MintedCredential {
            access_token: "AKIAIOSFODNN7EXAMPLE".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: None,
            additional_credentials: HashMap::from([
                (
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
                ),
                (
                    "AWS_SESSION_TOKEN".to_string(),
                    "FwoGZXIvYXdzEBYaDH...EXAMPLETOKEN".to_string(),
                ),
            ]),
            material_updates: HashMap::new(),
        };

        apply_minted_credential(&store, "default", None, &prov, "AWS_ACCESS_KEY_ID", &minted)
            .await
            .unwrap();

        let stored = store
            .get_message_by_name::<Provider>("default", "aws-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("AWS_ACCESS_KEY_ID"),
            Some(&"AKIAIOSFODNN7EXAMPLE".to_string())
        );
        assert_eq!(
            stored.credentials.get("AWS_SECRET_ACCESS_KEY"),
            Some(&"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string())
        );
        assert_eq!(
            stored.credentials.get("AWS_SESSION_TOKEN"),
            Some(&"FwoGZXIvYXdzEBYaDH...EXAMPLETOKEN".to_string())
        );
        assert_eq!(
            stored.credential_expires_at_ms.get("AWS_ACCESS_KEY_ID"),
            Some(&4_000_000_000_000)
        );
        assert_eq!(
            stored.credential_expires_at_ms.get("AWS_SECRET_ACCESS_KEY"),
            Some(&4_000_000_000_000)
        );
        assert_eq!(
            stored.credential_expires_at_ms.get("AWS_SESSION_TOKEN"),
            Some(&4_000_000_000_000)
        );
    }

    #[tokio::test]
    async fn subscription_publish_rollback_clears_only_its_losing_inline_mint() {
        use super::{apply_minted_credential, rollback_applied_minted_credential};

        let store = test_store().await;
        let prov = provider("codex-subscription", "openai-codex-oauth");
        store.put_message(&prov).await.unwrap();
        let minted = super::MintedCredential {
            access_token: "losing-access-token".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: Some("rotated-refresh-token".to_string()),
            additional_credentials: HashMap::new(),
            material_updates: HashMap::new(),
        };

        let receipt = apply_minted_credential(
            &store,
            "default",
            None,
            &prov,
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
            &minted,
        )
        .await
        .unwrap();
        rollback_applied_minted_credential(&store, None, &prov, &receipt)
            .await
            .unwrap();

        let cleared = store
            .get_message_by_name::<Provider>("default", "codex-subscription")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !cleared
                .credentials
                .contains_key(super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY)
        );
        assert!(
            !cleared
                .credential_expires_at_ms
                .contains_key(super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY)
        );

        // If another publication wins before cleanup, the receipt comparison
        // must preserve that newer value and its independently owned expiry.
        let receipt = apply_minted_credential(
            &store,
            "default",
            None,
            &cleared,
            super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY,
            &minted,
        )
        .await
        .unwrap();
        let winner_expires_at_ms = minted.expires_at_ms + 1;
        store
            .update_message_cas::<Provider, _>(prov.object_id(), 0, |current| {
                current.credentials.insert(
                    super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY.to_string(),
                    "winner-access-token".to_string(),
                );
                current.credential_expires_at_ms.insert(
                    super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY.to_string(),
                    winner_expires_at_ms,
                );
            })
            .await
            .unwrap();
        rollback_applied_minted_credential(&store, None, &prov, &receipt)
            .await
            .unwrap();

        let preserved = store
            .get_message_by_name::<Provider>("default", "codex-subscription")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            preserved
                .credentials
                .get(super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY),
            Some(&"winner-access-token".to_string())
        );
        assert_eq!(
            preserved
                .credential_expires_at_ms
                .get(super::OPENAI_CODEX_OAUTH_ACCESS_TOKEN_KEY),
            Some(&winner_expires_at_ms)
        );
    }

    #[tokio::test]
    async fn subscription_publish_rollback_removes_its_losing_stored_handle() {
        use super::{apply_minted_credential, rollback_applied_minted_credential};

        let store = test_store().await;
        let credentials = CredentialRuntime::from_config(
            &Config::new(None).with_credential_drivers(["test-static"]),
        )
        .unwrap();
        let prov = provider("grok-subscription", "xai-grok-oauth");
        store.put_message(&prov).await.unwrap();
        let minted = super::MintedCredential {
            access_token: "losing-grok-access-token".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: Some("rotated-grok-refresh-token".to_string()),
            additional_credentials: HashMap::new(),
            material_updates: HashMap::new(),
        };

        let receipt = apply_minted_credential(
            &store,
            "default",
            Some(&credentials),
            &prov,
            super::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY,
            &minted,
        )
        .await
        .unwrap();
        assert_eq!(credentials.stored_credential_count(), Some(1));
        rollback_applied_minted_credential(&store, Some(&credentials), &prov, &receipt)
            .await
            .unwrap();

        let cleared = store
            .get_message_by_name::<Provider>("default", "grok-subscription")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !cleared
                .credential_handles
                .contains_key(super::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY)
        );
        assert!(
            !cleared
                .credential_expires_at_ms
                .contains_key(super::subscription_oauth::XAI_GROK_ACCESS_TOKEN_KEY)
        );
        assert_eq!(credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn apply_minted_credential_replaces_only_refreshed_handles() {
        use super::apply_minted_credential;

        let store = test_store().await;
        let credentials = CredentialRuntime::from_config(
            &Config::new(None).with_credential_drivers(["test-static"]),
        )
        .unwrap();
        let mut prov = provider("stored-aws", "aws");
        let original_handles = credentials
            .store_provider_credentials(
                prov.object_name(),
                prov.object_workspace(),
                prov.object_id(),
                &HashMap::from([
                    ("AWS_ACCESS_KEY_ID".to_string(), "old-key".to_string()),
                    (
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                        "unchanged-secret".to_string(),
                    ),
                ]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        prov.credential_handles.clone_from(&original_handles);
        store.put_message(&prov).await.unwrap();

        let minted = super::MintedCredential {
            access_token: "new-key".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: None,
            additional_credentials: HashMap::new(),
            material_updates: HashMap::new(),
        };

        apply_minted_credential(
            &store,
            "default",
            Some(&credentials),
            &prov,
            "AWS_ACCESS_KEY_ID",
            &minted,
        )
        .await
        .unwrap();

        let stored = store
            .get_message_by_name::<Provider>("default", "stored-aws")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            stored.credential_handles.get("AWS_ACCESS_KEY_ID"),
            original_handles.get("AWS_ACCESS_KEY_ID")
        );
        assert_eq!(
            stored.credential_handles.get("AWS_SECRET_ACCESS_KEY"),
            original_handles.get("AWS_SECRET_ACCESS_KEY")
        );
        let resolved = credentials
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values.get("AWS_ACCESS_KEY_ID"),
            Some(&"new-key".to_string())
        );
        assert_eq!(
            resolved.values.get("AWS_SECRET_ACCESS_KEY"),
            Some(&"unchanged-secret".to_string())
        );

        let old_handle_provider = Provider {
            credential_handles: HashMap::from([(
                "AWS_ACCESS_KEY_ID".to_string(),
                original_handles["AWS_ACCESS_KEY_ID"].clone(),
            )]),
            ..prov
        };
        let err = credentials
            .resolve_provider_handles(&old_handle_provider, current_time_ms())
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn apply_minted_credential_validates_additional_keys_against_sandboxes() {
        use super::apply_minted_credential;

        let store = test_store().await;
        let mut existing_provider = provider("existing-aws", "aws");
        existing_provider
            .credentials
            .insert("AWS_SECRET_ACCESS_KEY".to_string(), "existing".to_string());
        store.put_message(&existing_provider).await.unwrap();

        let refreshing_provider = provider("refreshing-aws", "aws");
        store.put_message(&refreshing_provider).await.unwrap();

        store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: "sandbox-aws-collision".to_string(),
                    name: "aws-collision".to_string(),
                    created_at_ms: 1,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["existing-aws".to_string(), "refreshing-aws".to_string()],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let minted = super::MintedCredential {
            access_token: "AKIAIOSFODNN7EXAMPLE".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: None,
            additional_credentials: HashMap::from([
                (
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                    "secret-key".to_string(),
                ),
                ("AWS_SESSION_TOKEN".to_string(), "session-token".to_string()),
            ]),
            material_updates: HashMap::new(),
        };
        let credentials = CredentialRuntime::from_config(
            &Config::new(None).with_credential_drivers(["test-static"]),
        )
        .unwrap();

        let err = apply_minted_credential(
            &store,
            "default",
            Some(&credentials),
            &refreshing_provider,
            "AWS_ACCESS_KEY_ID",
            &minted,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(credentials.stored_credential_count(), Some(0));
    }

    // A wiremock responder that blocks the STS response until the test releases
    // it, so a delete-refresh can be interleaved deterministically while the
    // rotation is parked awaiting STS.
    struct GatedStsResponder {
        hit: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        body: String,
    }

    impl wiremock::Respond for GatedStsResponder {
        fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
            let hit = self.hit.lock().unwrap().take();
            if let Some(hit) = hit {
                let _ = hit.send(());
            }
            let _ = self.release.lock().unwrap().recv();
            ResponseTemplate::new(200).set_body_string(self.body.clone())
        }
    }

    #[tokio::test]
    async fn aws_sts_mint_accepts_session_token_with_source_pair() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#,
            ))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        crate::grpc::policy::set_global_bool_setting_for_test(
            &store,
            openshell_core::settings::PROVIDERS_V2_ENABLED_KEY,
            true,
        )
        .await
        .unwrap();
        let prov = provider("aws-sts-session", "aws");
        store.put_message(&prov).await.unwrap();

        // Temporary source credentials: access key + secret + session token.
        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "ASIASOURCEKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "SourceSecretKey".to_string(),
                    ),
                    (
                        "aws_session_token".to_string(),
                        "SourceSessionToken".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec![
                    "aws_secret_access_key".to_string(),
                    "aws_session_token".to_string(),
                ],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            None,
            "aws-sts-session",
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        let stored = store
            .get_message_by_name::<Provider>("default", "aws-sts-session")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("AWS_ACCESS_KEY_ID"),
            Some(&"ASIAMOCKKEY".to_string())
        );
    }

    #[tokio::test]
    async fn aws_sts_mint_rejects_session_token_without_source_pair() {
        let store = test_store().await;
        crate::grpc::policy::set_global_bool_setting_for_test(
            &store,
            openshell_core::settings::PROVIDERS_V2_ENABLED_KEY,
            true,
        )
        .await
        .unwrap();
        let prov = provider("aws-sts-lonesession", "aws");
        store.put_message(&prov).await.unwrap();

        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    (
                        "aws_session_token".to_string(),
                        "SourceSessionToken".to_string(),
                    ),
                ]),
                secret_material_keys: vec!["aws_session_token".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let err = refresh_provider_credential(
            &store,
            "default",
            None,
            "aws-sts-lonesession",
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("aws_session_token requires"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rotation_does_not_resurrect_refresh_deleted_mid_flight() {
        let mock_server = MockServer::start().await;
        let (hit_tx, hit_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .respond_with(GatedStsResponder {
                hit: std::sync::Mutex::new(Some(hit_tx)),
                release: std::sync::Mutex::new(release_rx),
                body: r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#
                    .to_string(),
            })
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        crate::grpc::policy::set_global_bool_setting_for_test(
            &store,
            openshell_core::settings::PROVIDERS_V2_ENABLED_KEY,
            true,
        )
        .await
        .unwrap();
        let prov = provider("aws-race", "aws");
        store.put_message(&prov).await.unwrap();
        let provider_id = prov.object_id().to_string();

        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "TestSecretKey".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec!["aws_secret_access_key".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let rotate =
            refresh_provider_credential(&store, "default", None, "aws-race", "AWS_ACCESS_KEY_ID");
        let interfere = async {
            // Wait until the rotation is inside the STS call (its state read has
            // already happened), then delete the refresh and release STS.
            if tokio::time::timeout(std::time::Duration::from_secs(15), hit_rx)
                .await
                .is_err()
            {
                return;
            }
            delete_refresh_state(&store, "default", &provider_id, "AWS_ACCESS_KEY_ID")
                .await
                .unwrap();
            let _ = release_tx.send(());
        };
        let (rotate_result, ()) = tokio::join!(rotate, interfere);

        // The rotation must fail rather than complete against a deleted refresh.
        assert!(
            rotate_result.is_err(),
            "rotation should abort when its refresh is deleted mid-flight"
        );
        // The deleted refresh state must not be resurrected.
        assert!(
            get_refresh_state(&store, "default", &provider_id, "AWS_ACCESS_KEY_ID")
                .await
                .unwrap()
                .is_none(),
            "deleted refresh state must not be recreated"
        );
        // No credentials were minted into the provider.
        let stored = store
            .get_message_by_name::<Provider>("default", "aws-race")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.credentials.contains_key("AWS_ACCESS_KEY_ID"));
        assert!(!stored.credentials.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!stored.credentials.contains_key("AWS_SESSION_TOKEN"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rotation_superseded_mid_flight_discards_credentials() {
        let mock_server = MockServer::start().await;
        let (hit_tx, hit_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .respond_with(GatedStsResponder {
                hit: std::sync::Mutex::new(Some(hit_tx)),
                release: std::sync::Mutex::new(release_rx),
                body: r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#
                    .to_string(),
            })
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        crate::grpc::policy::set_global_bool_setting_for_test(
            &store,
            openshell_core::settings::PROVIDERS_V2_ENABLED_KEY,
            true,
        )
        .await
        .unwrap();
        let prov = provider("aws-superseded", "aws");
        store.put_message(&prov).await.unwrap();
        let provider_id = prov.object_id().to_string();

        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "TestSecretKey".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec!["aws_secret_access_key".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let rotate = refresh_provider_credential(
            &store,
            "default",
            None,
            "aws-superseded",
            "AWS_ACCESS_KEY_ID",
        );
        let interfere = async {
            if tokio::time::timeout(std::time::Duration::from_secs(15), hit_rx)
                .await
                .is_err()
            {
                return;
            }
            // Simulate a concurrent rotation or reconfigure winning the
            // generation: any write to the refresh state bumps its version, so
            // the in-flight rotation's version-matched persist will lose.
            let mut winner =
                get_refresh_state(&store, "default", &provider_id, "AWS_ACCESS_KEY_ID")
                    .await
                    .unwrap()
                    .unwrap();
            winner.last_error = "won-by-concurrent-writer".to_string();
            put_refresh_state(&store, &winner).await.unwrap();
            let _ = release_tx.send(());
        };
        let (rotate_result, ()) = tokio::join!(rotate, interfere);

        // The superseded (losing) rotation must abort rather than complete.
        assert!(
            rotate_result.is_err(),
            "a rotation whose generation was superseded must abort"
        );
        // It must not write its stale-generation credentials into the provider.
        let stored = store
            .get_message_by_name::<Provider>("default", "aws-superseded")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.credentials.contains_key("AWS_ACCESS_KEY_ID"));
        assert!(!stored.credentials.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!stored.credentials.contains_key("AWS_SESSION_TOKEN"));
        // The concurrent writer's refresh state must survive untouched.
        let refresh = get_refresh_state(&store, "default", &provider_id, "AWS_ACCESS_KEY_ID")
            .await
            .unwrap()
            .expect("refresh state should still exist");
        assert_eq!(refresh.last_error, "won-by-concurrent-writer");
        assert_ne!(refresh.status, "refreshed");
    }

    fn provider(name: &str, provider_type: &str) -> Provider {
        Provider {
            metadata: Some(ObjectMeta {
                id: format!("{name}-id"),
                name: name.to_string(),
                created_at_ms: 1,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: provider_type.to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        }
    }

    const TEST_RSA_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvCoZ0mVHpCHsF
zeeqw2caNIe/eb4BQUccFPhZfRnF7sCfyB84zTBmuwG2umRBdjFnVsfIIZRp2HcD
OESrRYYiE1RGfjBXImGVg2Wtza0HYhL1sLyX1eaEefylxoilmApAgWDh9p36h8J2
s5YHwyXPTttx4DpdWDnxju1iNmwoIB8uVE/5amWgbNvlETMBOcB1RxDHtnVy+xJz
jjjrzK4Qz9WsUTHAvngdi4Yyxvci+yKpjYTg5+UWxmAN6iW522TpLe32MDb5Ug1d
trBvvepWmdQ6CBwPhBHCt/sMoSJAYSO4RKeBnBjeLQBXFTxaOv5iTGIsRTX3K471
epHp3cT5AgMBAAECggEASQlRv/4nZN5SgsH/K8v7zb3kdHsmUly8AJYpaCGgauvr
uN/mUyueyga2uNl+MqhQBef6VWHZjO6y/gdw86v/Q2GgVQebQQhKAnpAp2w+Ceoc
siKMFqi8VkOWLU+xPbM6d97kH3TpRxt1g1T8wYFmWeF0BEiE4eUJzGaQW14M9BJ+
G0QxmP/zjX9cNpVeApKTjBWKiH4CXG3DuI3pJ93VOMpUlOsrdLXvKGTze0e01itr
MX/MHHTE+VXB4FB+/zKSA4c36egi676OSXrGC/GDmM8ntJ4CUGeD5uZsMSADiAUn
iccv5iGRWVMIKxUS5Q4k0jy8uWuK+QVP4Y6cQWYArwKBgQDhuSNORBNpIGRfsKGN
iJo/h+qinz6pEIpa3D3oVl7rpkyvgIyaTwfXvC1vfdS9V5VIel2gV2Cx0OrI8yrr
nQu1JuNV/rLmtvqX321fgBLRdoiqF3pAy1gbmdUz1elerAIYL578gXQ6jg1bbdic
kJpn0MsoDUJGwvJnXcgLqG7q3wKBgQDGhRIa4oJsj1vqICc8zt8YsCAcot3vjWLH
588X7JdBGOWJdWxfdmGXQRn5Zw9UhMQnYa3uyTBPeVcXopThlPotYeuFhLSU856T
IJzfpzCJzC4zIQayoyvJFrKe7N70iUQ986dewYy9oxQhHvFKd/qe4ylbzZJXpthX
eWEuuBSjJwKBgGkqXt6qLPj/1IQYwUw15tfOtW0LEKCoSi3HCzjidNsJ4hSqqdeD
Fr5WuDyHvcRxt+XKzTBVRYHTOnBhiw+3XasK8UQxpJyFh/+WY1jpTNs2hLnqslTZ
6LUDWSgLc+1d6qPmHAa9Ma/OWz7L0O4xGR9hUiXY95YMYe/y668yzGq1AoGBAJyU
Gsqfu7U6gYmxoKEine6QBFPx1dD7GF2KJdq93jMXGvyHZFoLOkAdtgnz0rCcI0bY
kWKUxwj4MMxQjNM8OPMQl75xBCmz2XA8Od9htDQLmqjzNKAzePabc3lMZTJFDlE6
29kuGf79IIRbLn/JECDAFT/2baW60Ep2T0OVJ5njAoGAfaCaQ4aVgjI027q7Y5qP
KfNSI8uuA8PLqmUY30I9KFWzN6VDLu00eKa90F4w3CeWRRQWXW1+007tTz3V1mNw
20A24Fi3HGQmXc7NyuLDODTJsWBICuOemCnRkvcxIlxb+ec7jp+XRmzDwKkzSnVN
pM2zFU8SeVkvHKlEuoHaP0s=
-----END PRIVATE KEY-----";
}
