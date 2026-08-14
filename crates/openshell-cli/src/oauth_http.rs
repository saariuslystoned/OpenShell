// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared attended-OAuth HTTP boundary.

use miette::{IntoDiagnostic, Result, miette};
use serde::Deserialize;
use std::time::Duration;

pub fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(
            openshell_core::subscription_oauth::HTTP_TIMEOUT_SECONDS,
        ))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .into_diagnostic()
}

pub async fn bounded_bytes(
    mut response: reqwest::Response,
    invalid_message: &'static str,
) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|length| {
        length > openshell_core::subscription_oauth::MAX_RESPONSE_BYTES as u64
    }) {
        return Err(miette!(invalid_message));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| miette!(invalid_message))?
    {
        if bytes.len().saturating_add(chunk.len())
            > openshell_core::subscription_oauth::MAX_RESPONSE_BYTES
        {
            return Err(miette!(invalid_message));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub async fn bounded_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    invalid_message: &'static str,
) -> Result<T> {
    let bytes = bounded_bytes(response, invalid_message).await?;
    serde_json::from_slice(&bytes).map_err(|_| miette!(invalid_message))
}

pub fn error_code(body: &[u8]) -> Option<String> {
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
