//! Supervised local stdio transport for MCP servers.
//!
//! This transport starts one local process per JSON-RPC exchange,
//! writes one newline-delimited request to stdin, reads one response
//! line from stdout, and kills the child on timeout or oversized
//! output. It is deliberately simple and bounded.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use super::types::{JsonRpcRequest, JsonRpcResponse};

/// Local stdio process command.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StdioCommand {
    /// Executable path or name resolved by the OS.
    pub command: String,
    /// Command arguments.
    #[serde(default)]
    pub args: Vec<String>,
}

/// Encode a stdio command into the existing server-url slot.
pub fn encode_stdio_url(command: &str, args: &[String]) -> String {
    let payload = StdioCommand {
        command: command.to_string(),
        args: args.to_vec(),
    };
    format!(
        "stdio:{}",
        serde_json::to_string(&payload).expect("stdio command serializes")
    )
}

fn decode_stdio_url(raw: &str) -> anyhow::Result<StdioCommand> {
    let payload = raw
        .strip_prefix("stdio:")
        .ok_or_else(|| anyhow::anyhow!("stdio transport url must start with stdio:"))?;
    serde_json::from_str(payload).map_err(|e| anyhow::anyhow!("invalid stdio transport url: {e}"))
}

/// Send one JSON-RPC request through a supervised stdio child process.
pub async fn send_via_stdio(
    server_url: &str,
    request: &JsonRpcRequest,
    max_bytes: usize,
    timeout: Duration,
) -> anyhow::Result<JsonRpcResponse> {
    let cfg = decode_stdio_url(server_url)?;
    let mut child = Command::new(&cfg.command)
        .args(&cfg.args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow::anyhow!("starting stdio MCP server '{}': {e}", cfg.command))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("stdio MCP server stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("stdio MCP server stdout unavailable"))?;
    let line = serde_json::to_vec(request)?;

    let read = async move {
        stdin.write_all(&line).await?;
        stdin.write_all(b"\n").await?;
        drop(stdin);

        let mut reader = BufReader::new(stdout);
        let mut buf = Vec::new();
        let read = reader.read_until(b'\n', &mut buf).await?;
        if read == 0 {
            anyhow::bail!("stdio MCP server exited without a response");
        }
        if buf.len() > max_bytes {
            anyhow::bail!("stdio MCP response exceeded byte cap ({max_bytes} bytes)");
        }
        let response: JsonRpcResponse = serde_json::from_slice(&buf)?;
        Ok(response)
    };

    match tokio::time::timeout(timeout, read).await {
        Ok(result) => {
            let response = result?;
            let _ = child.wait().await;
            Ok(response)
        }
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("stdio MCP server timed out after {}ms", timeout.as_millis())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn supervised_stdio_round_trips_one_jsonrpc_line() {
        let script =
            "import sys\nline=sys.stdin.readline()\nsys.stdout.write(line)\nsys.stdout.flush()\n";
        let args = vec!["-c".to_string(), script.to_string()];
        let url = encode_stdio_url("python3", &args);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "ping".to_string(),
            params: None,
            id: Some(json!(1)),
        };

        let resp = send_via_stdio(&url, &req, 4096, Duration::from_secs(2))
            .await
            .expect("stdio response");
        assert_eq!(resp.id, Some(json!(1)));
        assert_eq!(resp.jsonrpc, "2.0");
    }
}
