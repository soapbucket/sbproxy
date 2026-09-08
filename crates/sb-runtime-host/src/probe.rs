// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Readiness probing for managed loopback processes.

use std::time::Duration;

use async_trait::async_trait;
use sb_runtime_core::{EngineDriverError, EngineFailureReason};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Readiness probe injected into the process runner.
#[async_trait]
pub trait EngineReadinessProbe: Send + Sync {
    /// Return whether the process's loopback health endpoint is ready.
    async fn ready(&self, port: u16, path: &str) -> Result<bool, EngineDriverError>;
}

/// Production bounded HTTP probe for a loopback-only health endpoint.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoopbackReadinessProbe;

#[async_trait]
impl EngineReadinessProbe for LoopbackReadinessProbe {
    async fn ready(&self, port: u16, path: &str) -> Result<bool, EngineDriverError> {
        if port == 0
            || !path.starts_with('/')
            || path.len() > 2_048
            || path
                .bytes()
                .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
        {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "managed-engine readiness endpoint is invalid",
                "use a bounded absolute HTTP path and a nonzero loopback port",
                false,
            ));
        }
        let attempt = async {
            let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .ok()?;
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes()).await.ok()?;
            let mut buffer = [0_u8; 64];
            let count = stream.read(&mut buffer).await.ok()?;
            let head = String::from_utf8_lossy(&buffer[..count]);
            Some(head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200"))
        };
        Ok(matches!(
            tokio::time::timeout(Duration::from_secs(2), attempt).await,
            Ok(Some(true))
        ))
    }
}
