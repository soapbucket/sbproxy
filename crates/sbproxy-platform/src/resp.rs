//! Minimal RESP (REdis Serialization Protocol, RESP2) wire helpers.
//!
//! Shared by the raw-protocol Redis backends in [`crate::storage`] and
//! [`crate::messenger`], both of which speak RESP directly over a blocking
//! `TcpStream`. The two used to carry byte-identical copies of these helpers
//! (a comment in the messenger even noted the duplication "to avoid
//! cross-module coupling"); WOR-628 hoists the single source of truth here so
//! a fix lands in one place.
//!
//! Only the subset both callers need is implemented: simple strings, errors,
//! integers, bulk strings, and arrays.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

use anyhow::{bail, Context, Result};

/// A decoded RESP value.
///
/// Bulk and simple strings both decode to [`RespValue::Bytes`]; a null bulk or
/// null array decodes to [`RespValue::Nil`].
#[derive(Debug)]
#[allow(dead_code)] // `Integer` is part of the RESP spec; not every caller matches it.
pub(crate) enum RespValue {
    /// Null bulk string or null array (`$-1` / `*-1`).
    Nil,
    /// A bulk string or simple string payload.
    Bytes(Vec<u8>),
    /// An integer reply (`:`).
    Integer(i64),
    /// An array reply, with its elements decoded recursively.
    Array(Vec<RespValue>),
}

/// Write a RESP bulk-string array (the standard command format) to `w`.
pub(crate) fn write_command(w: &mut impl Write, args: &[&[u8]]) -> Result<()> {
    write!(w, "*{}\r\n", args.len())?;
    for arg in args {
        write!(w, "${}\r\n", arg.len())?;
        w.write_all(arg)?;
        w.write_all(b"\r\n")?;
    }
    w.flush()?;
    Ok(())
}

/// Read one RESP value from `r`.
///
/// Returns raw bytes for bulk and simple strings, the parsed integer for
/// integer replies, [`RespValue::Nil`] for null bulk/array, and a recursively
/// decoded list for arrays. A `-` error reply surfaces as an `Err`.
pub(crate) fn read_resp(r: &mut BufReader<TcpStream>) -> Result<RespValue> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let line = line.trim_end_matches("\r\n");

    let (prefix, rest) = line.split_at(1);
    match prefix {
        "+" => Ok(RespValue::Bytes(rest.as_bytes().to_vec())),
        "-" => bail!("Redis error: {}", rest),
        ":" => {
            let n: i64 = rest.parse().context("parse integer")?;
            Ok(RespValue::Integer(n))
        }
        "$" => {
            let len: i64 = rest.parse().context("parse bulk length")?;
            if len < 0 {
                return Ok(RespValue::Nil);
            }
            let len = len as usize;
            let mut buf = vec![0u8; len + 2]; // +2 for \r\n
            r.read_exact(&mut buf)?;
            buf.truncate(len);
            Ok(RespValue::Bytes(buf))
        }
        "*" => {
            let count: i64 = rest.parse().context("parse array length")?;
            if count < 0 {
                return Ok(RespValue::Nil);
            }
            let mut items = Vec::with_capacity(count as usize);
            for _ in 0..count {
                items.push(read_resp(r)?);
            }
            Ok(RespValue::Array(items))
        }
        _ => bail!("unexpected RESP prefix {:?}", prefix),
    }
}
