// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Minimal OpenAI-compatible engine process for local end-to-end fixtures.
//!
//! Production drivers invoke this binary through their normal typed command
//! path. It only implements the readiness endpoint needed to prove process
//! ownership and rollout behavior, and is never linked into `sbproxy`.

use std::io::{Read, Write};
use std::net::TcpListener;

fn argument(name: &str) -> Option<String> {
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == name {
            return arguments.next();
        }
    }
    None
}

fn main() -> std::io::Result<()> {
    let port = argument("--port")
        .ok_or_else(|| std::io::Error::other("missing --port"))?
        .parse::<u16>()
        .map_err(|error| std::io::Error::other(format!("invalid --port: {error}")))?;
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    for connection in listener.incoming() {
        let mut connection = connection?;
        let mut request = [0u8; 4_096];
        let _ = connection.read(&mut request)?;
        connection.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"status\":\"ready\"}",
        )?;
    }
    Ok(())
}
