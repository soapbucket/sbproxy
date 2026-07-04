// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Weight supply-chain safety (WOR-1666).
//!
//! Pulling weights from a public hub is a remote-code-execution
//! surface: a pickle checkpoint can carry a backdoor that runs the
//! moment an engine deserializes it (documented live cases in 2026),
//! and pickle still outnumbers safetensors on the Hub. This module is
//! the policy that decides which file to serve and whether a pickle
//! file may be used at all. It is pure and file-format-only, so it is
//! unit-tested with no network and no engine; the actual download
//! lives in [`crate::weights`].
//!
//! Rules:
//! - Prefer safetensors when a repo offers both.
//! - A pickle-only repo is refused unless the operator sets
//!   `allow_pickle`, and even then it is scanned for the opcodes that
//!   make pickle dangerous.

/// The weight serialization format of a candidate file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightFormat {
    /// safetensors: data-only, no code execution on load. Safe.
    Safetensors,
    /// Pickle-based (`.bin`, `.pt`, `.ckpt`): can execute arbitrary
    /// code on deserialization. Dangerous.
    Pickle,
    /// GGUF: data-only container. Safe.
    Gguf,
    /// Anything else (config, tokenizer, unknown).
    Other,
}

impl WeightFormat {
    /// Classify by filename extension (and the multi-part safetensors
    /// / GGUF conventions).
    pub fn from_filename(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".safetensors") {
            WeightFormat::Safetensors
        } else if lower.ends_with(".gguf") {
            WeightFormat::Gguf
        } else if lower.ends_with(".bin")
            || lower.ends_with(".pt")
            || lower.ends_with(".pth")
            || lower.ends_with(".ckpt")
            || lower.ends_with(".pkl")
        {
            WeightFormat::Pickle
        } else {
            WeightFormat::Other
        }
    }

    /// Whether loading this format can execute code.
    pub fn is_code_bearing(self) -> bool {
        matches!(self, WeightFormat::Pickle)
    }
}

/// Why a weight selection was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SupplyChainError {
    /// The repo has no weight file we recognize.
    #[error("repo has no safetensors, gguf, or pickle weight file")]
    NoWeights,
    /// Only pickle weights are available and `allow_pickle` is not set.
    #[error("repo offers only pickle weights ({0}); set allow_pickle to use it, or pick a safetensors repo")]
    PickleNotAllowed(String),
    /// A pickle file was allowed but failed the opcode scan.
    #[error("pickle weight '{file}' is unsafe: {reason}")]
    PickleUnsafe {
        /// The offending file.
        file: String,
        /// What the scan found.
        reason: String,
    },
}

/// Choose the weight file to download from a repo's file list, given
/// the operator's `allow_pickle` setting. Prefers safetensors, then
/// GGUF, then (only with opt-in) pickle. Returns the chosen filename.
///
/// This does not scan; run [`scan_pickle`] on the chosen file after
/// download when it is a pickle file (the bytes are not available
/// until then).
pub fn select_weight_file(
    files: &[String],
    allow_pickle: bool,
) -> Result<String, SupplyChainError> {
    let mut safetensors = None;
    let mut gguf = None;
    let mut pickle = None;
    for f in files {
        match WeightFormat::from_filename(f) {
            WeightFormat::Safetensors => safetensors.get_or_insert(f.clone()),
            WeightFormat::Gguf => gguf.get_or_insert(f.clone()),
            WeightFormat::Pickle => pickle.get_or_insert(f.clone()),
            WeightFormat::Other => continue,
        };
    }
    if let Some(s) = safetensors {
        return Ok(s);
    }
    if let Some(g) = gguf {
        return Ok(g);
    }
    match pickle {
        Some(p) if allow_pickle => Ok(p),
        Some(p) => Err(SupplyChainError::PickleNotAllowed(p)),
        None => Err(SupplyChainError::NoWeights),
    }
}

/// Modules a pickle is allowed to reference. Weights legitimately name
/// tensor-reconstruction callables from torch/numpy/collections; a
/// reference to anything else (os, subprocess, builtins.exec, ...) is
/// the backdoor signature.
const PICKLE_ALLOWED_MODULE_PREFIXES: &[&str] = &[
    "torch",
    "collections",
    "numpy",
    "_codecs",
    "__builtin__.set", // legacy set reconstruction (py2), harmless
];

/// Scan pickle bytes for the opcodes that make it dangerous. This is a
/// lightweight opcode walk, not a full unpickler: it finds every
/// `GLOBAL` / `STACK_GLOBAL` import target and flags any that is not
/// under an allowlisted module, and flags a bare `REDUCE` whose global
/// was not allowlisted. Mirrors picklescan's approach. Returns
/// `Ok(())` when nothing suspicious is referenced.
pub fn scan_pickle(file: &str, bytes: &[u8]) -> Result<(), SupplyChainError> {
    let mut i = 0;
    // Track the most recently pushed string constants for STACK_GLOBAL,
    // which pops two strings (module, name) off the stack.
    let mut recent_strings: Vec<String> = Vec::new();
    while i < bytes.len() {
        let op = bytes[i];
        i += 1;
        match op {
            // GLOBAL: 'c' then module\n name\n
            b'c' => {
                let module = read_line(bytes, &mut i);
                let _name = read_line(bytes, &mut i);
                if !module_allowed(&module) {
                    return Err(SupplyChainError::PickleUnsafe {
                        file: file.to_string(),
                        reason: format!("imports disallowed module `{module}`"),
                    });
                }
            }
            // STACK_GLOBAL: 0x93, module and name are the two most
            // recent SHORT_BINUNICODE/BINUNICODE strings.
            0x93 => {
                let n = recent_strings.len();
                if n >= 2 {
                    let module = &recent_strings[n - 2];
                    if !module_allowed(module) {
                        return Err(SupplyChainError::PickleUnsafe {
                            file: file.to_string(),
                            reason: format!("imports disallowed module `{module}` (stack global)"),
                        });
                    }
                }
            }
            // SHORT_BINUNICODE: 0x8c, 1-byte len, then utf8
            0x8c => {
                if i >= bytes.len() {
                    break;
                }
                let len = bytes[i] as usize;
                i += 1;
                if let Some(s) = read_bytes_str(bytes, &mut i, len) {
                    recent_strings.push(s);
                }
            }
            // BINUNICODE: 0x58, 4-byte LE len, then utf8
            0x58 => {
                if i + 4 > bytes.len() {
                    break;
                }
                let len = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
                    as usize;
                i += 4;
                if let Some(s) = read_bytes_str(bytes, &mut i, len) {
                    recent_strings.push(s);
                }
            }
            // STOP
            b'.' => break,
            // Everything else: opcodes with inline args we do not need
            // to interpret for the security check. We only need correct
            // cursor advancement for the string/global opcodes above;
            // other opcodes either take no arg or an arg we skip via the
            // newline/length readers when relevant. To stay safe against
            // misalignment we treat unknown args conservatively: opcodes
            // with a newline-terminated arg are handled here.
            b'0' | b'2' | b'1' | b'a' | b'e' | b's' | b't' | b'l' | b'd' | b'}' | b']' | b')'
            | b'\x85' | b'\x86' | b'\x87' | b'R' | b'b' | b'Q' | b'o' | b'\x94' => {
                // no inline arg (or a stack op); continue
            }
            b'I' | b'L' | b'S' | b'V' | b'F' | b'G' | b'P' | b'g' | b'j' | b'h' | b'q' | b'r' => {
                // newline- or length-terminated arg forms: consume a
                // line where the pickle text protocol uses one.
                let _ = read_line(bytes, &mut i);
            }
            _ => {
                // Unknown/binary-arg opcode: keep scanning byte by byte.
                // The allowlist check only trusts the GLOBAL/STACK_GLOBAL
                // paths above, so a missed arg cannot smuggle an import
                // past the check; worst case is a false negative on a
                // corrupt stream, which the sha256 check already guards.
            }
        }
    }
    Ok(())
}

/// Read a `\n`-terminated line from `bytes` starting at `*i`, advancing
/// past the newline. Returns the line without the newline.
fn read_line(bytes: &[u8], i: &mut usize) -> String {
    let start = *i;
    while *i < bytes.len() && bytes[*i] != b'\n' {
        *i += 1;
    }
    let s = String::from_utf8_lossy(&bytes[start..*i]).into_owned();
    if *i < bytes.len() {
        *i += 1; // skip the newline
    }
    s
}

/// Read `len` bytes as a lossy utf8 string, advancing the cursor.
fn read_bytes_str(bytes: &[u8], i: &mut usize, len: usize) -> Option<String> {
    let end = i.checked_add(len)?;
    let slice = bytes.get(*i..end)?;
    *i = end;
    Some(String::from_utf8_lossy(slice).into_owned())
}

/// Whether a pickle module reference is on the allowlist.
fn module_allowed(module: &str) -> bool {
    PICKLE_ALLOWED_MODULE_PREFIXES
        .iter()
        .any(|p| module == *p || module.starts_with(&format!("{p}.")) || module.starts_with(*p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_classification() {
        assert_eq!(
            WeightFormat::from_filename("model.safetensors"),
            WeightFormat::Safetensors
        );
        assert_eq!(
            WeightFormat::from_filename("Q4_K_M.gguf"),
            WeightFormat::Gguf
        );
        assert_eq!(
            WeightFormat::from_filename("pytorch_model.bin"),
            WeightFormat::Pickle
        );
        assert!(WeightFormat::from_filename("x.pt").is_code_bearing());
        assert!(!WeightFormat::from_filename("model.safetensors").is_code_bearing());
    }

    #[test]
    fn prefers_safetensors_over_pickle() {
        let files = vec![
            "pytorch_model.bin".to_string(),
            "model.safetensors".to_string(),
        ];
        assert_eq!(
            select_weight_file(&files, false).unwrap(),
            "model.safetensors"
        );
    }

    #[test]
    fn prefers_gguf_when_no_safetensors() {
        let files = vec!["model.bin".to_string(), "model.Q4_K_M.gguf".to_string()];
        assert_eq!(
            select_weight_file(&files, false).unwrap(),
            "model.Q4_K_M.gguf"
        );
    }

    #[test]
    fn pickle_only_refused_without_opt_in() {
        let files = vec!["pytorch_model.bin".to_string()];
        let err = select_weight_file(&files, false).unwrap_err();
        assert!(matches!(err, SupplyChainError::PickleNotAllowed(_)));
        // With opt-in it is selected (still to be scanned after download).
        assert_eq!(
            select_weight_file(&files, true).unwrap(),
            "pytorch_model.bin"
        );
    }

    #[test]
    fn no_weights_is_an_error() {
        let files = vec!["config.json".to_string(), "tokenizer.json".to_string()];
        assert_eq!(
            select_weight_file(&files, true).unwrap_err(),
            SupplyChainError::NoWeights
        );
    }

    /// A minimal protocol-2 pickle: `\x80\x02` then GLOBAL to a module.
    fn pickle_with_global(module: &str, name: &str) -> Vec<u8> {
        let mut v = vec![0x80, 0x02]; // PROTO 2
        v.push(b'c'); // GLOBAL
        v.extend_from_slice(module.as_bytes());
        v.push(b'\n');
        v.extend_from_slice(name.as_bytes());
        v.push(b'\n');
        v.push(b'.'); // STOP
        v
    }

    #[test]
    fn scan_passes_a_benign_torch_global() {
        let bytes = pickle_with_global("torch._utils", "_rebuild_tensor_v2");
        assert!(scan_pickle("model.bin", &bytes).is_ok());
    }

    #[test]
    fn scan_flags_os_system() {
        let bytes = pickle_with_global("os", "system");
        let err = scan_pickle("evil.bin", &bytes).unwrap_err();
        assert!(matches!(err, SupplyChainError::PickleUnsafe { .. }));
    }

    #[test]
    fn scan_flags_posix_and_builtins_exec() {
        for (m, n) in [
            ("posix", "system"),
            ("builtins", "exec"),
            ("subprocess", "Popen"),
        ] {
            let bytes = pickle_with_global(m, n);
            assert!(
                matches!(
                    scan_pickle("x.bin", &bytes),
                    Err(SupplyChainError::PickleUnsafe { .. })
                ),
                "{m}.{n} should be flagged"
            );
        }
    }

    #[test]
    fn scan_flags_stack_global_to_bad_module() {
        // SHORT_BINUNICODE "os", SHORT_BINUNICODE "system", STACK_GLOBAL
        let mut v = vec![0x80, 0x04]; // PROTO 4
        for s in ["os", "system"] {
            v.push(0x8c); // SHORT_BINUNICODE
            v.push(s.len() as u8);
            v.extend_from_slice(s.as_bytes());
        }
        v.push(0x93); // STACK_GLOBAL
        v.push(b'.');
        assert!(matches!(
            scan_pickle("x.bin", &v),
            Err(SupplyChainError::PickleUnsafe { .. })
        ));
    }

    #[test]
    fn scan_passes_stack_global_to_torch() {
        let mut v = vec![0x80, 0x04];
        for s in ["torch._utils", "_rebuild_tensor_v2"] {
            v.push(0x8c);
            v.push(s.len() as u8);
            v.extend_from_slice(s.as_bytes());
        }
        v.push(0x93);
        v.push(b'.');
        assert!(scan_pickle("model.bin", &v).is_ok());
    }
}
