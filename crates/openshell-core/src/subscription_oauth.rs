// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral subscription OAuth compatibility registry.
//!
//! Subscription grants are more constrained than generic OAuth refresh
//! credentials: `OpenShell` owns the grant, pins every credential-bearing
//! authority, keeps all reusable material in the gateway, and exposes only a
//! reviewed inference route to explicitly attached sandboxes. Provider-specific
//! device login, refresh, revoke, identity, and route adapters consume this
//! registry rather than duplicating compatibility constants.

use crate::proto::ProviderCredentialRefreshStrategy;
use url::Url;

/// Maximum accepted OAuth response body at attended-login and gateway refresh
/// boundaries. Errors derived from those bodies must remain sanitized.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Shared timeout for a single OAuth HTTP request.
pub const HTTP_TIMEOUT_SECONDS: u64 = 30;

/// Compatibility snapshot for the experimental xAI contract.
pub const XAI_GROK_COMPAT_REVISION: &str = "2026-08-14.2";

/// Open-source Grok client snapshot used to review the public-client contract.
pub const XAI_GROK_BUILD_REFERENCE_REVISION: &str = "eb267feff13129e568df38fb6fdf0ceb65f735d6";

pub const OPENAI_CODEX_PROVIDER_TYPE: &str = "openai-codex-oauth";
pub const OPENAI_CODEX_ACCESS_TOKEN_KEY: &str = "OPENAI_CODEX_OAUTH_ACCESS_TOKEN";
pub const OPENAI_CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const OPENAI_CODEX_AUTH_BASE_URL: &str = "https://auth.openai.com";
pub const OPENAI_CODEX_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const OPENAI_CODEX_REVOCATION_URL: &str = "https://auth.openai.com/oauth/revoke";
pub const OPENAI_CODEX_INFERENCE_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";

pub const XAI_GROK_PROVIDER_TYPE: &str = "xai-grok-oauth";
pub const XAI_GROK_ACCESS_TOKEN_KEY: &str = "XAI_GROK_ACCESS_TOKEN";
pub const XAI_GROK_DEFAULT_MODEL: &str = "grok-4.6";
pub const XAI_GROK_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
pub const XAI_GROK_REFERRER: &str = "grok-build";
pub const XAI_GROK_DEVICE_AUTHORIZATION_URL: &str = "https://auth.x.ai/oauth2/device/code";
pub const XAI_GROK_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
pub const XAI_GROK_REVOCATION_URL: &str = "https://auth.x.ai/oauth2/revoke";
pub const XAI_GROK_INFERENCE_BASE_URL: &str = "https://api.x.ai/v1";
pub const XAI_GROK_DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const XAI_GROK_SCOPES: &[&str] = &[
    "openid",
    "profile",
    "email",
    "offline_access",
    "api:access",
    "grok-cli:access",
];

pub const OPENAI_CODEX_INFERENCE_PROTOCOLS: &[&str] = &["openai_responses"];
pub const XAI_GROK_INFERENCE_PROTOCOLS: &[&str] = &["openai_chat_completions", "model_discovery"];
pub const OPENAI_CODEX_ROUTE_HEADERS: &[(&str, &str)] = &[("originator", "openshell")];
pub const XAI_GROK_ROUTE_HEADERS: &[(&str, &str)] = &[];

const OPENAI_CODEX_ALIASES: &[&str] = &["openai-codex-oauth", "codex-subscription"];
const XAI_GROK_ALIASES: &[&str] = &[
    "xai-grok-oauth",
    "grok-subscription",
    "xai-oauth",
    "grok-oauth",
    "xai_grok_oauth",
];
const OPENAI_CODEX_MATERIAL_KEYS: &[&str] = &["refresh_token", "account_id", "fedramp"];
const OPENAI_CODEX_SECRET_MATERIAL_KEYS: &[&str] = &["refresh_token", "account_id", "fedramp"];
const XAI_GROK_MATERIAL_KEYS: &[&str] = &["refresh_token"];
const XAI_GROK_SECRET_MATERIAL_KEYS: &[&str] = &["refresh_token"];

/// Provider-specific adapter identity behind the common lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionOauthProvider {
    OpenAiCodex,
    XaiGrok,
}

/// Static contract consumed by CLI, gateway, supervisor, and profile checks.
#[derive(Debug, Clone, Copy)]
pub struct SubscriptionOauthSpec {
    pub provider: SubscriptionOauthProvider,
    pub provider_type: &'static str,
    pub aliases: &'static [&'static str],
    pub access_token_key: &'static str,
    pub strategy: ProviderCredentialRefreshStrategy,
    pub client_id: &'static str,
    pub token_url: &'static str,
    pub revocation_url: &'static str,
    pub scopes: &'static [&'static str],
    pub inference_base_url: &'static str,
    /// First model proven for this adapter, when the provider publishes one.
    /// Sandboxes still select a model explicitly; this is compatibility
    /// metadata, not an attachment-order default.
    pub default_model: Option<&'static str>,
    pub inference_protocols: &'static [&'static str],
    pub request_path_override: Option<&'static str>,
    pub route_default_headers: &'static [(&'static str, &'static str)],
    pub material_keys: &'static [&'static str],
    pub secret_material_keys: &'static [&'static str],
    pub display_name: &'static str,
    pub default_instance_name: &'static str,
}

pub const OPENAI_CODEX_SPEC: SubscriptionOauthSpec = SubscriptionOauthSpec {
    provider: SubscriptionOauthProvider::OpenAiCodex,
    provider_type: OPENAI_CODEX_PROVIDER_TYPE,
    aliases: OPENAI_CODEX_ALIASES,
    access_token_key: OPENAI_CODEX_ACCESS_TOKEN_KEY,
    strategy: ProviderCredentialRefreshStrategy::OpenaiCodexOauth,
    client_id: OPENAI_CODEX_CLIENT_ID,
    token_url: OPENAI_CODEX_TOKEN_URL,
    revocation_url: OPENAI_CODEX_REVOCATION_URL,
    scopes: &[],
    inference_base_url: OPENAI_CODEX_INFERENCE_BASE_URL,
    default_model: None,
    inference_protocols: OPENAI_CODEX_INFERENCE_PROTOCOLS,
    request_path_override: Some("/responses"),
    route_default_headers: OPENAI_CODEX_ROUTE_HEADERS,
    material_keys: OPENAI_CODEX_MATERIAL_KEYS,
    secret_material_keys: OPENAI_CODEX_SECRET_MATERIAL_KEYS,
    display_name: "OpenAI Codex",
    default_instance_name: "codex-subscription",
};

pub const XAI_GROK_SPEC: SubscriptionOauthSpec = SubscriptionOauthSpec {
    provider: SubscriptionOauthProvider::XaiGrok,
    provider_type: XAI_GROK_PROVIDER_TYPE,
    aliases: XAI_GROK_ALIASES,
    access_token_key: XAI_GROK_ACCESS_TOKEN_KEY,
    strategy: ProviderCredentialRefreshStrategy::XaiGrokOauth,
    client_id: XAI_GROK_CLIENT_ID,
    token_url: XAI_GROK_TOKEN_URL,
    revocation_url: XAI_GROK_REVOCATION_URL,
    scopes: XAI_GROK_SCOPES,
    inference_base_url: XAI_GROK_INFERENCE_BASE_URL,
    default_model: Some(XAI_GROK_DEFAULT_MODEL),
    inference_protocols: XAI_GROK_INFERENCE_PROTOCOLS,
    request_path_override: None,
    route_default_headers: XAI_GROK_ROUTE_HEADERS,
    material_keys: XAI_GROK_MATERIAL_KEYS,
    secret_material_keys: XAI_GROK_SECRET_MATERIAL_KEYS,
    display_name: "xAI Grok",
    default_instance_name: "grok-subscription",
};

const SPECS: &[SubscriptionOauthSpec] = &[OPENAI_CODEX_SPEC, XAI_GROK_SPEC];

#[must_use]
pub fn specs() -> &'static [SubscriptionOauthSpec] {
    SPECS
}

#[must_use]
pub fn spec_for_provider_type(input: &str) -> Option<&'static SubscriptionOauthSpec> {
    let normalized = input.trim().to_ascii_lowercase();
    SPECS
        .iter()
        .find(|spec| spec.aliases.iter().any(|alias| *alias == normalized))
}

#[must_use]
pub fn spec_for_strategy(
    strategy: ProviderCredentialRefreshStrategy,
) -> Option<&'static SubscriptionOauthSpec> {
    SPECS.iter().find(|spec| spec.strategy == strategy)
}

#[must_use]
pub fn spec_for_access_token_key(key: &str) -> Option<&'static SubscriptionOauthSpec> {
    SPECS.iter().find(|spec| spec.access_token_key == key)
}

#[must_use]
pub fn normalize_provider_type(input: &str) -> Option<&'static str> {
    spec_for_provider_type(input).map(|spec| spec.provider_type)
}

#[must_use]
pub fn is_managed_provider_type(input: &str) -> bool {
    spec_for_provider_type(input).is_some()
}

#[must_use]
pub fn is_managed_strategy(strategy: ProviderCredentialRefreshStrategy) -> bool {
    spec_for_strategy(strategy).is_some()
}

/// Subscription access and refresh material is gateway-only even when a
/// custom or stale profile declares an environment variable for it.
#[must_use]
pub fn is_non_injectable_credential(provider_type: &str, key: &str) -> bool {
    spec_for_provider_type(provider_type).is_some_and(|spec| {
        key == spec.access_token_key
            || spec.material_keys.contains(&key)
            || key.eq_ignore_ascii_case("client_secret")
    })
}

#[must_use]
pub fn xai_grok_scope_param() -> String {
    XAI_GROK_SCOPES.join(" ")
}

#[must_use]
pub fn is_allowed_xai_verification_url(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw.trim()) else {
        return false;
    };
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("auth.x.ai") || host.eq_ignore_ascii_case("accounts.x.ai")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_and_strategies_are_symmetric() {
        assert_eq!(
            normalize_provider_type("codex-subscription"),
            Some(OPENAI_CODEX_PROVIDER_TYPE)
        );
        assert_eq!(
            normalize_provider_type("GROK-SUBSCRIPTION"),
            Some(XAI_GROK_PROVIDER_TYPE)
        );
        assert_eq!(
            spec_for_strategy(ProviderCredentialRefreshStrategy::XaiGrokOauth)
                .map(|spec| spec.provider),
            Some(SubscriptionOauthProvider::XaiGrok)
        );
    }

    #[test]
    fn grants_are_gateway_only() {
        assert!(is_non_injectable_credential(
            OPENAI_CODEX_PROVIDER_TYPE,
            OPENAI_CODEX_ACCESS_TOKEN_KEY
        ));
        assert!(is_non_injectable_credential(
            XAI_GROK_PROVIDER_TYPE,
            XAI_GROK_ACCESS_TOKEN_KEY
        ));
        assert!(is_non_injectable_credential(
            XAI_GROK_PROVIDER_TYPE,
            "refresh_token"
        ));
        assert!(!is_non_injectable_credential(
            "openai",
            OPENAI_CODEX_ACCESS_TOKEN_KEY
        ));
    }

    #[test]
    fn xai_contract_requests_api_and_offline_access() {
        assert_eq!(XAI_GROK_COMPAT_REVISION, "2026-08-14.2");
        assert_eq!(
            XAI_GROK_BUILD_REFERENCE_REVISION,
            "eb267feff13129e568df38fb6fdf0ceb65f735d6"
        );
        assert!(XAI_GROK_SCOPES.contains(&"api:access"));
        assert!(XAI_GROK_SCOPES.contains(&"offline_access"));
        assert!(is_allowed_xai_verification_url(
            "https://accounts.x.ai/activate"
        ));
        assert!(!is_allowed_xai_verification_url(
            "https://accounts.x.ai.attacker.invalid/activate"
        ));
        assert_eq!(XAI_GROK_SPEC.default_model, Some("grok-4.6"));
        assert_eq!(
            XAI_GROK_SPEC.inference_protocols,
            &["openai_chat_completions", "model_discovery"]
        );
        assert!(XAI_GROK_SPEC.request_path_override.is_none());
    }
}
