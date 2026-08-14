// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Attended `OpenAI` Codex subscription device authorization.
//!
//! This flow intentionally creates a separate grant managed by `OpenShell`. It
//! never reads or imports Codex CLI/Desktop credential stores.

use base64::Engine as _;
use miette::{IntoDiagnostic, Result, miette};
use reqwest::StatusCode;
use serde::{Deserialize, Deserializer, Serialize};
use std::time::{Duration, Instant};

const OPENAI_AUTH_BASE_URL: &str = "https://auth.openai.com";
const OPENAI_CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const DEVICE_LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_OAUTH_RESPONSE_BYTES: usize = 64 * 1024;

pub struct DeviceCode {
    pub verification_url: String,
    pub user_code: String,
    device_auth_id: String,
    interval: Duration,
    auth_base_url: String,
}

pub struct OpenAiCodexGrant {
    pub refresh_token: String,
    pub account_id: String,
    pub fedramp: bool,
}

#[derive(Serialize)]
struct RevokeRequest<'a> {
    token: &'a str,
    token_type_hint: &'static str,
    client_id: &'a str,
}

#[derive(Serialize)]
struct UserCodeRequest<'a> {
    client_id: &'a str,
}

#[derive(Deserialize)]
struct UserCodeResponse {
    device_auth_id: String,
    #[serde(alias = "usercode")]
    user_code: String,
    #[serde(deserialize_with = "deserialize_interval")]
    interval: u64,
}

fn deserialize_interval<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Interval {
        Number(u64),
        String(String),
    }
    match Interval::deserialize(deserializer)? {
        Interval::Number(value) => Ok(value),
        Interval::String(value) => value.trim().parse().map_err(serde::de::Error::custom),
    }
}

#[derive(Serialize)]
struct TokenPollRequest<'a> {
    device_auth_id: &'a str,
    user_code: &'a str,
}

#[derive(Deserialize)]
struct TokenPollResponse {
    authorization_code: String,
    code_verifier: String,
}

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)]
struct TokenExchangeResponse {
    id_token: String,
    access_token: String,
    refresh_token: String,
}

#[derive(Deserialize)]
struct IdClaims {
    #[serde(rename = "https://api.openai.com/auth")]
    auth: Option<AuthClaims>,
}

#[derive(Deserialize)]
struct AuthClaims {
    chatgpt_account_id: Option<String>,
    #[serde(default)]
    chatgpt_account_is_fedramp: bool,
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .into_diagnostic()
}

async fn bounded_json<T: for<'de> Deserialize<'de>>(
    mut response: reqwest::Response,
    invalid_message: &'static str,
) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_OAUTH_RESPONSE_BYTES as u64)
    {
        return Err(miette!(invalid_message));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| miette!(invalid_message))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_OAUTH_RESPONSE_BYTES {
            return Err(miette!(invalid_message));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| miette!(invalid_message))
}

pub async fn request_device_code() -> Result<DeviceCode> {
    request_device_code_at(OPENAI_AUTH_BASE_URL).await
}

async fn request_device_code_at(auth_base_url: &str) -> Result<DeviceCode> {
    let response = client()?
        .post(format!(
            "{}/api/accounts/deviceauth/usercode",
            auth_base_url.trim_end_matches('/')
        ))
        .header("originator", "openshell")
        .json(&UserCodeRequest {
            client_id: OPENAI_CODEX_CLIENT_ID,
        })
        .send()
        .await
        .map_err(|_| miette!("could not start OpenAI Codex device authorization"))?;
    if !response.status().is_success() {
        return Err(miette!(
            "OpenAI Codex device authorization was rejected (HTTP {})",
            response.status().as_u16()
        ));
    }
    let response: UserCodeResponse = bounded_json(
        response,
        "OpenAI Codex returned an invalid device authorization response",
    )
    .await?;
    if response.device_auth_id.trim().is_empty()
        || response.user_code.trim().is_empty()
        || response.interval == 0
    {
        return Err(miette!(
            "OpenAI Codex returned an incomplete device authorization response"
        ));
    }
    Ok(DeviceCode {
        verification_url: format!("{}/codex/device", auth_base_url.trim_end_matches('/')),
        user_code: response.user_code,
        device_auth_id: response.device_auth_id,
        interval: Duration::from_secs(response.interval),
        auth_base_url: auth_base_url.trim_end_matches('/').to_string(),
    })
}

pub async fn complete_device_code(device: DeviceCode) -> Result<OpenAiCodexGrant> {
    complete_device_code_with_timeout(device, DEVICE_LOGIN_TIMEOUT).await
}

/// Best-effort cleanup for a grant that could not be handed to the gateway.
///
/// Production revocation after configuration is performed by the gateway so
/// the CLI never has to retrieve stored refresh material.
pub async fn revoke_unclaimed_grant(refresh_token: &str) -> Result<()> {
    let response = client()?
        .post(format!("{OPENAI_AUTH_BASE_URL}/oauth/revoke"))
        .header("originator", "openshell")
        .json(&RevokeRequest {
            token: refresh_token,
            token_type_hint: "refresh_token",
            client_id: OPENAI_CODEX_CLIENT_ID,
        })
        .send()
        .await
        .map_err(|_| miette!("could not revoke the unused OpenAI Codex grant"))?;
    if response.status().is_success() {
        return Ok(());
    }
    Err(miette!(
        "OpenAI Codex grant revocation was rejected (HTTP {})",
        response.status().as_u16()
    ))
}

async fn complete_device_code_with_timeout(
    device: DeviceCode,
    timeout: Duration,
) -> Result<OpenAiCodexGrant> {
    let client = client()?;
    let poll_url = format!("{}/api/accounts/deviceauth/token", device.auth_base_url);
    let started = Instant::now();
    let code = loop {
        let response = client
            .post(&poll_url)
            .header("originator", "openshell")
            .json(&TokenPollRequest {
                device_auth_id: &device.device_auth_id,
                user_code: &device.user_code,
            })
            .send()
            .await
            .map_err(|_| miette!("OpenAI Codex device authorization poll failed"))?;
        if response.status().is_success() {
            let code: TokenPollResponse = bounded_json(
                response,
                "OpenAI Codex returned an invalid authorization response",
            )
            .await?;
            if code.authorization_code.trim().is_empty() || code.code_verifier.trim().is_empty() {
                return Err(miette!(
                    "OpenAI Codex returned an incomplete authorization response"
                ));
            }
            break code;
        }
        if !matches!(
            response.status(),
            StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
        ) {
            return Err(miette!(
                "OpenAI Codex device authorization failed (HTTP {})",
                response.status().as_u16()
            ));
        }
        if started.elapsed() >= timeout {
            return Err(miette!("OpenAI Codex device authorization timed out"));
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        tokio::time::sleep(device.interval.min(remaining)).await;
    };

    let redirect_uri = format!("{}/deviceauth/callback", device.auth_base_url);
    let response = client
        .post(format!("{}/oauth/token", device.auth_base_url))
        .header("originator", "openshell")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.authorization_code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", OPENAI_CODEX_CLIENT_ID),
            ("code_verifier", code.code_verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|_| miette!("OpenAI Codex token exchange failed"))?;
    if !response.status().is_success() {
        return Err(miette!(
            "OpenAI Codex token exchange was rejected (HTTP {})",
            response.status().as_u16()
        ));
    }
    let tokens: TokenExchangeResponse =
        bounded_json(response, "OpenAI Codex returned an invalid token response").await?;
    if tokens.access_token.trim().is_empty() || tokens.refresh_token.trim().is_empty() {
        return Err(miette!(
            "OpenAI Codex returned an incomplete token response"
        ));
    }
    let (account_id, fedramp) = parse_account_claims(&tokens.id_token)?;
    Ok(OpenAiCodexGrant {
        refresh_token: tokens.refresh_token,
        account_id,
        fedramp,
    })
}

fn parse_account_claims(id_token: &str) -> Result<(String, bool)> {
    let mut parts = id_token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(miette!("OpenAI Codex returned a malformed ID token"));
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(miette!("OpenAI Codex returned a malformed ID token"));
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| miette!("OpenAI Codex returned a malformed ID token"))?;
    let claims: IdClaims = serde_json::from_slice(&payload)
        .map_err(|_| miette!("OpenAI Codex returned invalid ID token claims"))?;
    let auth = claims
        .auth
        .ok_or_else(|| miette!("OpenAI Codex ID token is missing account claims"))?;
    let account_id = auth
        .chatgpt_account_id
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| miette!("OpenAI Codex ID token is missing account id"))?;
    Ok((account_id, auth.chatgpt_account_is_fedramp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_id_token(account_id: &str, fedramp: bool) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": account_id,
                    "chatgpt_account_is_fedramp": fedramp
                }
            })
            .to_string(),
        );
        format!("header.{payload}.signature")
    }

    #[test]
    fn parses_reviewed_account_claims_without_exposing_token() {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "account-123",
                    "chatgpt_account_is_fedramp": true
                }
            })
            .to_string(),
        );
        let token = format!("header.{payload}.signature");
        assert_eq!(
            parse_account_claims(&token).expect("claims"),
            ("account-123".to_string(), true)
        );
    }

    #[test]
    fn rejects_missing_account_claim() {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({}).to_string());
        let token = format!("header.{payload}.signature");
        assert!(parse_account_claims(&token).is_err());
    }

    #[tokio::test]
    async fn device_flow_uses_pinned_shapes_and_returns_only_gateway_material() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .and(header("originator", "openshell"))
            .and(body_string_contains(OPENAI_CODEX_CLIENT_ID))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_auth_id": "device-auth-id",
                "user_code": "ABCD-EFGH",
                "interval": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/token"))
            .and(header("originator", "openshell"))
            .and(body_string_contains("device-auth-id"))
            .and(body_string_contains("ABCD-EFGH"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_code": "authorization-code",
                "code_verifier": "code-verifier"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(header("originator", "openshell"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=authorization-code"))
            .and(body_string_contains("code_verifier=code-verifier"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": test_id_token("account-123", true),
                "access_token": "discarded-login-access-token",
                "refresh_token": "gateway-owned-refresh-token"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let device = request_device_code_at(&server.uri())
            .await
            .expect("device authorization should start");
        assert_eq!(device.user_code, "ABCD-EFGH");
        let grant = complete_device_code_with_timeout(device, Duration::from_secs(5))
            .await
            .expect("device authorization should complete");
        assert_eq!(grant.refresh_token, "gateway-owned-refresh-token");
        assert_eq!(grant.account_id, "account-123");
        assert!(grant.fedramp);
    }

    #[tokio::test]
    async fn device_flow_rejects_redirects_and_does_not_echo_response_bodies() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "https://attacker.invalid/steal")
                    .set_body_string("response-secret-canary"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let Err(error) = request_device_code_at(&server.uri()).await else {
            panic!("redirect must not be followed");
        };
        let message = error.to_string();
        assert!(message.contains("HTTP 302"));
        assert!(!message.contains("response-secret-canary"));
        assert!(!message.contains("attacker.invalid"));
    }

    #[tokio::test]
    async fn device_flow_rejects_oversized_responses_without_echoing_them() {
        let server = MockServer::start().await;
        let canary = format!(
            "oversized-secret-canary{}",
            "x".repeat(MAX_OAUTH_RESPONSE_BYTES)
        );
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .respond_with(ResponseTemplate::new(200).set_body_string(canary.clone()))
            .expect(1)
            .mount(&server)
            .await;

        let Err(error) = request_device_code_at(&server.uri()).await else {
            panic!("oversized response must fail");
        };
        assert!(error.to_string().contains("invalid device authorization"));
        assert!(!error.to_string().contains("oversized-secret-canary"));
    }
}
