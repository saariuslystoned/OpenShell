// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Attended xAI device authorization for an OpenShell-owned Grok grant.
//!
//! This adapter never reads or imports `OpenClaw` authentication state. The
//! short-lived login access token is validated and discarded; only refresh
//! material crosses the secret CLI/gateway configuration boundary.

use miette::{Result, miette};
use openshell_core::subscription_oauth;
use owo_colors::OwoColorize;
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::{Duration, Instant};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(15);
const DEVICE_LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub struct XaiGrokGrant {
    pub refresh_token: String,
}

struct DeviceCode {
    code: String,
    user_code: String,
    verification_url: String,
    interval: Duration,
    expires_in: Duration,
}

#[derive(Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    verification_uri_complete: Option<String>,
    expires_in: Option<u64>,
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct TokenSuccess {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    token_type: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum DeviceCodePoll {
    Pending { slow_down: bool },
    Terminal(&'static str),
}

fn classify_device_code_error(status: StatusCode, body: &[u8]) -> DeviceCodePoll {
    let code = crate::oauth_http::error_code(body);
    match (status, code.as_deref()) {
        (_, Some("authorization_pending")) => DeviceCodePoll::Pending { slow_down: false },
        (_, Some("slow_down")) => DeviceCodePoll::Pending { slow_down: true },
        (StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS, _) => {
            DeviceCodePoll::Pending { slow_down: true }
        }
        (status, _) if status.is_server_error() => DeviceCodePoll::Pending { slow_down: false },
        (_, Some("expired_token" | "access_denied" | "invalid_grant")) => DeviceCodePoll::Terminal(
            "xAI Grok authorization was rejected or expired; run provider login again",
        ),
        _ => DeviceCodePoll::Terminal("xAI Grok authorization failed; run provider login again"),
    }
}

pub async fn run_device_code_login(no_open: bool) -> Result<XaiGrokGrant> {
    let client = crate::oauth_http::client()?;
    let device = request_device_code_at(
        &client,
        subscription_oauth::XAI_GROK_DEVICE_AUTHORIZATION_URL,
    )
    .await?;

    println!(
        "{}",
        "Sign in to xAI for an OpenShell-owned Grok grant (not an OpenClaw import)."
            .cyan()
            .bold()
    );
    println!("Open this URL:");
    println!("  {}", device.verification_url);
    println!("Enter this one-time code:");
    println!("  {}", device.user_code.bold());
    println!(
        "Continue only if you started this login in OpenShell. If another person or website gave you this code, cancel."
    );
    let browser_suppressed = no_open
        || std::env::var("OPENSHELL_NO_BROWSER")
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
    if !browser_suppressed
        && let Err(error) = crate::auth::open_browser_url(&device.verification_url)
    {
        eprintln!("Could not open the browser automatically ({error}).");
    }
    println!("Waiting for xAI authorization...");
    complete_device_code_at(
        &client,
        device,
        subscription_oauth::XAI_GROK_TOKEN_URL,
        DEVICE_LOGIN_TIMEOUT,
    )
    .await
}

async fn request_device_code_at(client: &reqwest::Client, endpoint: &str) -> Result<DeviceCode> {
    let scope = subscription_oauth::xai_grok_scope_param();
    let response = client
        .post(endpoint)
        .form(&[
            ("client_id", subscription_oauth::XAI_GROK_CLIENT_ID),
            ("scope", scope.as_str()),
            ("referrer", subscription_oauth::XAI_GROK_REFERRER),
        ])
        .send()
        .await
        .map_err(|_| miette!("could not start xAI Grok device authorization"))?;
    let status = response.status();
    if !status.is_success() {
        crate::oauth_http::bounded_bytes(
            response,
            "xAI Grok returned an invalid device authorization response",
        )
        .await?;
        return Err(miette!(
            "xAI Grok device authorization was rejected (HTTP {})",
            status.as_u16()
        ));
    }
    let response: DeviceAuthorizationResponse = crate::oauth_http::bounded_json(
        response,
        "xAI Grok returned an invalid device authorization response",
    )
    .await?;
    let device_code = response
        .device_code
        .and_then(nonempty)
        .ok_or_else(|| miette!("xAI Grok returned an incomplete device authorization response"))?;
    let user_code = response
        .user_code
        .and_then(nonempty)
        .filter(|code| {
            code.chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
        .ok_or_else(|| miette!("xAI Grok returned an incomplete device authorization response"))?;
    let verification_url = response
        .verification_uri_complete
        .and_then(nonempty)
        .or_else(|| response.verification_uri.and_then(nonempty))
        .filter(|url| subscription_oauth::is_allowed_xai_verification_url(url))
        .ok_or_else(|| miette!("xAI Grok returned an invalid device verification destination"))?;
    let expires_in = response
        .expires_in
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .ok_or_else(|| miette!("xAI Grok returned an invalid device authorization lifetime"))?;
    let interval = response
        .interval
        .filter(|seconds| *seconds > 0)
        .map_or(DEFAULT_POLL_INTERVAL, Duration::from_secs)
        .max(DEFAULT_POLL_INTERVAL)
        .min(MAX_POLL_INTERVAL);
    Ok(DeviceCode {
        code: device_code,
        user_code,
        verification_url,
        interval,
        expires_in,
    })
}

async fn complete_device_code_at(
    client: &reqwest::Client,
    device: DeviceCode,
    token_endpoint: &str,
    timeout: Duration,
) -> Result<XaiGrokGrant> {
    let deadline = Instant::now() + device.expires_in.min(timeout);
    let mut interval = device.interval;
    loop {
        if Instant::now() >= deadline {
            return Err(miette!(
                "xAI Grok device authorization timed out; run provider login again"
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::sleep(interval.min(remaining)).await;
        if Instant::now() >= deadline {
            return Err(miette!(
                "xAI Grok device authorization timed out; run provider login again"
            ));
        }
        match poll_token_at(client, token_endpoint, &device.code).await? {
            PollResult::Granted(grant) => return Ok(grant),
            PollResult::Pending { slow_down } => {
                if slow_down {
                    interval = (interval + Duration::from_secs(5)).min(MAX_POLL_INTERVAL);
                }
            }
        }
    }
}

enum PollResult {
    Granted(XaiGrokGrant),
    Pending { slow_down: bool },
}

async fn poll_token_at(
    client: &reqwest::Client,
    endpoint: &str,
    device_code: &str,
) -> Result<PollResult> {
    let response = client
        .post(endpoint)
        .form(&[
            (
                "grant_type",
                subscription_oauth::XAI_GROK_DEVICE_CODE_GRANT_TYPE,
            ),
            ("device_code", device_code),
            ("client_id", subscription_oauth::XAI_GROK_CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|_| miette!("xAI Grok device authorization poll failed"))?;
    let status = response.status();
    let body =
        crate::oauth_http::bounded_bytes(response, "xAI Grok returned an invalid token response")
            .await?;
    if status.is_success() {
        let token: TokenSuccess = serde_json::from_slice(&body)
            .map_err(|_| miette!("xAI Grok returned an invalid token response"))?;
        if token
            .token_type
            .as_deref()
            .is_some_and(|token_type| !token_type.eq_ignore_ascii_case("bearer"))
        {
            return Err(miette!("xAI Grok returned an unsupported token type"));
        }
        if token.access_token.and_then(nonempty).is_none() {
            return Err(miette!("xAI Grok returned no access token"));
        }
        if token.expires_in.is_none_or(|expires_in| expires_in <= 0) {
            return Err(miette!("xAI Grok returned an invalid token expiry"));
        }
        let refresh_token = token
            .refresh_token
            .and_then(nonempty)
            .ok_or_else(|| miette!("xAI Grok returned no gateway-owned refresh token"))?;
        return Ok(PollResult::Granted(XaiGrokGrant { refresh_token }));
    }
    match classify_device_code_error(status, &body) {
        DeviceCodePoll::Pending { slow_down } => Ok(PollResult::Pending { slow_down }),
        DeviceCodePoll::Terminal(message) => Err(miette!("{message}")),
    }
}

pub async fn revoke_unclaimed_grant(refresh_token: &str) -> Result<()> {
    revoke_unclaimed_grant_at(subscription_oauth::XAI_GROK_REVOCATION_URL, refresh_token).await
}

async fn revoke_unclaimed_grant_at(endpoint: &str, refresh_token: &str) -> Result<()> {
    let client = crate::oauth_http::client()?;
    let response = client
        .post(endpoint)
        .form(&[
            ("client_id", subscription_oauth::XAI_GROK_CLIENT_ID),
            ("token", refresh_token),
            ("token_type_hint", "refresh_token"),
        ])
        .send()
        .await
        .map_err(|_| miette!("could not revoke the unused xAI Grok grant"))?;
    let status = response.status();
    let body = crate::oauth_http::bounded_bytes(
        response,
        "xAI Grok returned an invalid revocation response",
    )
    .await?;
    if status.is_success()
        || (matches!(
            status,
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) && matches!(
            crate::oauth_http::error_code(&body).as_deref(),
            Some("invalid_token" | "invalid_grant")
        ))
    {
        return Ok(());
    }
    Err(miette!(
        "xAI Grok grant revocation was rejected (HTTP {})",
        status.as_u16()
    ))
}

fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn poll_classifier_separates_pending_retryable_and_terminal() {
        assert_eq!(
            classify_device_code_error(
                StatusCode::BAD_REQUEST,
                br#"{"error":"authorization_pending"}"#
            ),
            DeviceCodePoll::Pending { slow_down: false }
        );
        assert_eq!(
            classify_device_code_error(StatusCode::TOO_MANY_REQUESTS, b"{}"),
            DeviceCodePoll::Pending { slow_down: true }
        );
        assert!(matches!(
            classify_device_code_error(
                StatusCode::BAD_REQUEST,
                br#"{"error":"invalid_grant","error_description":"secret-canary"}"#
            ),
            DeviceCodePoll::Terminal(message) if !message.contains("secret-canary")
        ));
    }

    #[tokio::test]
    async fn device_request_is_pinned_bounded_and_redirect_denying() {
        let server = MockServer::start().await;
        let client = crate::oauth_http::client().unwrap();
        Mock::given(method("POST"))
            .and(path("/redirect"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "https://attacker.invalid/steal")
                    .set_body_string("response-secret-canary"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let Err(error) =
            request_device_code_at(&client, &format!("{}/redirect", server.uri())).await
        else {
            panic!("redirect must be denied");
        };
        assert!(error.to_string().contains("HTTP 302"));
        assert!(!error.to_string().contains("response-secret-canary"));
        assert!(!error.to_string().contains("attacker.invalid"));

        Mock::given(method("POST"))
            .and(path("/oversized"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "oversized-secret-canary{}",
                "x".repeat(subscription_oauth::MAX_RESPONSE_BYTES)
            )))
            .expect(1)
            .mount(&server)
            .await;
        let Err(error) =
            request_device_code_at(&client, &format!("{}/oversized", server.uri())).await
        else {
            panic!("oversized response must fail");
        };
        assert!(!error.to_string().contains("oversized-secret-canary"));

        Mock::given(method("POST"))
            .and(path("/invalid-code"))
            .and(body_string_contains(format!(
                "client_id={}",
                subscription_oauth::XAI_GROK_CLIENT_ID
            )))
            .and(body_string_contains("referrer=grok-build"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "device-code",
                "user_code": "CODE\nINJECTED",
                "verification_uri": "https://accounts.x.ai/activate",
                "expires_in": 900,
                "interval": 5
            })))
            .expect(1)
            .mount(&server)
            .await;
        let Err(error) =
            request_device_code_at(&client, &format!("{}/invalid-code", server.uri())).await
        else {
            panic!("control characters in the displayed user code must be rejected");
        };
        assert!(error.to_string().contains("incomplete"));
        assert!(!error.to_string().contains("INJECTED"));
    }

    #[tokio::test]
    async fn token_poll_returns_only_gateway_refresh_material() {
        let server = MockServer::start().await;
        let client = crate::oauth_http::client().unwrap();
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
            ))
            .and(body_string_contains("device_code=device-code"))
            .and(body_string_contains(format!(
                "client_id={}",
                subscription_oauth::XAI_GROK_CLIENT_ID
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "discarded-access-token",
                "refresh_token": "gateway-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let PollResult::Granted(grant) =
            poll_token_at(&client, &format!("{}/token", server.uri()), "device-code")
                .await
                .expect("grant")
        else {
            panic!("expected grant");
        };
        assert_eq!(grant.refresh_token, "gateway-refresh-token");
    }

    #[tokio::test]
    async fn unclaimed_grant_revoke_is_bounded_redirect_denying_and_retryable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/already-dead"))
            .and(body_string_contains("token=refresh-token-canary"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "already-dead-response-canary"
            })))
            .expect(1)
            .mount(&server)
            .await;
        revoke_unclaimed_grant_at(
            &format!("{}/already-dead", server.uri()),
            "refresh-token-canary",
        )
        .await
        .expect("an already-dead grant is a converged revoke");

        Mock::given(method("POST"))
            .and(path("/transient"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "transient-response-secret-canary"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let transient = revoke_unclaimed_grant_at(
            &format!("{}/transient", server.uri()),
            "refresh-token-canary",
        )
        .await
        .expect_err("a server failure must remain retryable regardless of its body");
        assert!(transient.to_string().contains("HTTP 500"));
        assert!(
            !transient
                .to_string()
                .contains("transient-response-secret-canary")
        );

        Mock::given(method("POST"))
            .and(path("/redirect"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "https://attacker.invalid/steal")
                    .set_body_string("redirect-response-secret-canary"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let redirect = revoke_unclaimed_grant_at(
            &format!("{}/redirect", server.uri()),
            "refresh-token-canary",
        )
        .await
        .expect_err("redirects must not be followed");
        assert!(redirect.to_string().contains("HTTP 302"));
        assert!(
            !redirect
                .to_string()
                .contains("redirect-response-secret-canary")
        );
        assert!(!redirect.to_string().contains("attacker.invalid"));
    }
}
