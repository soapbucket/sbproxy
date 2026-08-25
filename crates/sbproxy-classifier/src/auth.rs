//! Authentication and tenant-scoped authorization for sidecar admin surfaces.

use anyhow::{bail, Context as _};
use serde::Deserialize;
use std::collections::HashSet;
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
use subtle::ConstantTimeEq as _;

const MAX_AUTH_FILE_BYTES: u64 = 256 * 1024;

#[cfg(test)]
std::thread_local! {
    static AFTER_AUTH_FILE_METADATA: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_after_auth_file_metadata_hook() {
    AFTER_AUTH_FILE_METADATA.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[derive(Clone)]
pub struct AdminAuth {
    grants: Arc<Vec<TokenGrant>>,
}

#[derive(Clone, Deserialize)]
struct TokenGrant {
    token: String,
    tenants: Vec<String>,
}

#[derive(Deserialize)]
struct AuthFile {
    tokens: Vec<TokenGrant>,
}

impl std::fmt::Debug for AdminAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminAuth")
            .field("grants", &self.grants.len())
            .finish()
    }
}

impl AdminAuth {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("opening admin token file {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("reading admin token file metadata {}", path.display()))?;
        if !metadata.file_type().is_file() {
            bail!("admin token file {} must be a regular file", path.display());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                bail!(
                    "admin token file {} must not be readable or writable by group/other",
                    path.display()
                );
            }
        }
        #[cfg(test)]
        run_after_auth_file_metadata_hook();
        if metadata.len() > MAX_AUTH_FILE_BYTES {
            bail!("admin token file {} exceeds 256KB limit", path.display());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(MAX_AUTH_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading admin token file {}", path.display()))?;
        if bytes.len() as u64 > MAX_AUTH_FILE_BYTES {
            bail!("admin token file {} exceeds 256KB limit", path.display());
        }
        Self::from_json(&bytes)
            .with_context(|| format!("parsing admin token file {}", path.display()))
    }

    pub(crate) fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        let auth: AuthFile = serde_json::from_slice(bytes).context("invalid JSON")?;
        if auth.tokens.is_empty() {
            bail!("admin token file must contain at least one token grant");
        }
        if auth.tokens.len() > 1024 {
            bail!("admin token file exceeds 1024 grant limit");
        }
        for grant in &auth.tokens {
            if grant.token.len() > 256 {
                bail!("admin token exceeds 256 byte limit");
            }
            if grant.tenants.len() > 1024 {
                bail!("admin token grant exceeds 1024 tenant limit");
            }
            for tenant in &grant.tenants {
                if tenant.len() > 128 {
                    bail!("admin token grant tenant exceeds 128 byte limit");
                }
            }
        }
        let mut tokens = HashSet::new();
        for grant in &auth.tokens {
            if grant.token.is_empty() {
                bail!("admin token must not be empty");
            }
            if !tokens.insert(grant.token.as_str()) {
                bail!("admin token file contains a duplicate token");
            }
            if grant.tenants.is_empty() || grant.tenants.iter().any(String::is_empty) {
                bail!("each admin token must carry at least one non-empty tenant scope");
            }
            if grant.tenants.iter().any(|scope| scope == "*") && grant.tenants.len() != 1 {
                bail!("wildcard tenant scope must be the token's only scope");
            }
        }
        Ok(Self {
            grants: Arc::new(auth.tokens),
        })
    }

    pub fn authorize(&self, presented: Option<&str>, tenant: Option<&str>) -> bool {
        let Some(grant) = self.grant(presented) else {
            return false;
        };
        tenant.is_none_or(|tenant| {
            grant
                .tenants
                .iter()
                .any(|scope| scope == "*" || scope == tenant)
        })
    }

    pub fn authenticated(&self, presented: Option<&str>) -> bool {
        self.grant(presented).is_some()
    }

    fn grant(&self, presented: Option<&str>) -> Option<&TokenGrant> {
        let presented = presented?;
        let mut matched = None;
        for grant in self.grants.iter() {
            let equal = grant.token.len() == presented.len()
                && bool::from(grant.token.as_bytes().ct_eq(presented.as_bytes()));
            if equal {
                matched = Some(grant);
            }
        }
        matched
    }
}

#[derive(Clone)]
pub struct InferenceAuth {
    tokens: Arc<Vec<String>>,
}

#[derive(Deserialize)]
struct InferenceAuthFile {
    tokens: Vec<String>,
}

impl std::fmt::Debug for InferenceAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InferenceAuth")
            .field("tokens", &self.tokens.len())
            .finish()
    }
}

impl InferenceAuth {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("opening inference token file {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("reading inference token file metadata {}", path.display()))?;
        if !metadata.file_type().is_file() {
            bail!(
                "inference token file {} must be a regular file",
                path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                bail!(
                    "inference token file {} must not be readable or writable by group/other",
                    path.display()
                );
            }
        }
        #[cfg(test)]
        run_after_auth_file_metadata_hook();
        if metadata.len() > MAX_AUTH_FILE_BYTES {
            bail!(
                "inference token file {} exceeds 256KB limit",
                path.display()
            );
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(MAX_AUTH_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading inference token file {}", path.display()))?;
        if bytes.len() as u64 > MAX_AUTH_FILE_BYTES {
            bail!(
                "inference token file {} exceeds 256KB limit",
                path.display()
            );
        }
        Self::from_json(&bytes)
            .with_context(|| format!("parsing inference token file {}", path.display()))
    }

    pub(crate) fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        let auth: InferenceAuthFile = serde_json::from_slice(bytes).context("invalid JSON")?;
        if auth.tokens.is_empty() {
            bail!("inference token file must contain at least one token");
        }
        if auth.tokens.len() > 1024 {
            bail!("inference token file exceeds 1024 token limit");
        }
        let mut seen = HashSet::new();
        for token in &auth.tokens {
            if token.is_empty() {
                bail!("inference token must not be empty");
            }
            if token.len() > 256 {
                bail!("inference token exceeds 256 byte limit");
            }
            if !seen.insert(token.as_str()) {
                bail!("inference token file contains a duplicate token");
            }
        }
        Ok(Self {
            tokens: Arc::new(auth.tokens),
        })
    }

    pub fn authenticated(&self, presented: Option<&str>) -> bool {
        let Some(presented) = presented else {
            return false;
        };
        let mut matched = false;
        for token in self.tokens.iter() {
            let equal = token.len() == presented.len()
                && bool::from(token.as_bytes().ct_eq(presented.as_bytes()));
            if equal {
                matched = true;
            }
        }
        matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_token_cannot_administer_another_tenant() {
        let policy = AdminAuth::from_json(
            br#"{
          "tokens": [{"token":"secret-a","tenants":["tenant-a"]}]
        }"#,
        )
        .unwrap();

        assert!(policy.authorize(Some("secret-a"), Some("tenant-a")));
        assert!(!policy.authorize(Some("secret-a"), Some("tenant-b")));
        assert!(!policy.authorize(None, Some("tenant-a")));
    }

    #[test]
    fn oversized_auth_file_shape_is_rejected() {
        assert!(AdminAuth::from_json(b"").is_err());
        assert!(AdminAuth::from_json(b"{\"tokens\":[]}").is_err());
        let mut huge_tokens = String::new();
        for _ in 0..1025 {
            huge_tokens.push_str("{\"token\":\"a\",\"tenants\":[]},");
        }
        huge_tokens.pop();
        let json = format!("{{\"tokens\":[{}]}}", huge_tokens);
        assert!(AdminAuth::from_json(json.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("1024 grant limit"));
    }

    #[test]
    fn auth_shape_accepts_exact_maxima_and_rejects_each_max_plus_one() {
        fn auth_json(token: String, tenants: Vec<String>) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "tokens": [{"token": token, "tenants": tenants}]
            }))
            .unwrap()
        }

        let exact = auth_json("t".repeat(256), vec!["s".repeat(128); 1024]);
        AdminAuth::from_json(&exact).expect("exact auth shape maxima must be accepted");

        let token_error =
            AdminAuth::from_json(&auth_json("t".repeat(257), vec!["tenant-a".to_string()]))
                .unwrap_err();
        assert!(token_error.to_string().contains("256 byte limit"));

        let scope_count_error = AdminAuth::from_json(&auth_json(
            "token".to_string(),
            vec!["tenant-a".to_string(); 1025],
        ))
        .unwrap_err();
        assert!(scope_count_error.to_string().contains("1024 tenant limit"));

        let scope_length_error =
            AdminAuth::from_json(&auth_json("token".to_string(), vec!["s".repeat(129)]))
                .unwrap_err();
        assert!(scope_length_error.to_string().contains("128 byte limit"));

        let grants = |count| {
            (0..count)
                .map(|index| {
                    serde_json::json!({
                        "token": format!("token-{index}"),
                        "tenants": ["tenant-a"]
                    })
                })
                .collect::<Vec<_>>()
        };
        let exact_grants =
            serde_json::to_vec(&serde_json::json!({"tokens": grants(1024)})).unwrap();
        AdminAuth::from_json(&exact_grants).expect("exact grant maximum must be accepted");

        let grant_count_error = AdminAuth::from_json(
            &serde_json::to_vec(&serde_json::json!({"tokens": grants(1025)})).unwrap(),
        )
        .unwrap_err();
        assert!(grant_count_error.to_string().contains("1024 grant limit"));
    }

    #[test]
    fn inference_auth_debug_redacts_and_authenticates() {
        let auth = InferenceAuth::from_json(br#"{"tokens":["secret-a","secret-b"]}"#).unwrap();
        let debug = format!("{auth:?}");
        assert!(debug.contains("InferenceAuth"));
        assert!(debug.contains("2"));
        assert!(!debug.contains("secret-a"));
        assert!(!debug.contains("secret-b"));
        assert!(auth.authenticated(Some("secret-a")));
        assert!(!auth.authenticated(Some("missing")));
    }

    #[test]
    fn inference_auth_rejects_inline_shape_errors() {
        let exact_tokens = (0..1024)
            .map(|index| format!("{index:04x}{}", "t".repeat(252)))
            .collect::<Vec<_>>();
        let exact = serde_json::to_vec(&serde_json::json!({
            "tokens": exact_tokens
        }))
        .unwrap();
        InferenceAuth::from_json(&exact).expect("exact inference auth maxima must be accepted");

        let too_many = serde_json::to_vec(&serde_json::json!({
            "tokens": vec!["token"; 1025]
        }))
        .unwrap();
        assert!(InferenceAuth::from_json(&too_many)
            .unwrap_err()
            .to_string()
            .contains("1024 token limit"));

        let too_long = serde_json::to_vec(&serde_json::json!({
            "tokens": ["t".repeat(257)]
        }))
        .unwrap();
        assert!(InferenceAuth::from_json(&too_long)
            .unwrap_err()
            .to_string()
            .contains("256 byte limit"));
    }

    #[cfg(unix)]
    #[test]
    fn final_component_symlink_is_refused_without_following() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("real-admin-token.json");
        let link = directory.path().join("linked-admin-token.json");
        std::fs::write(
            &target,
            br#"{"tokens":[{"token":"target","tenants":["tenant-a"]}]}"#,
        )
        .unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();

        AdminAuth::from_file(&link)
            .expect_err("the final admin-token path component must not be followed");
    }

    #[cfg(unix)]
    #[test]
    fn post_open_path_replacement_cannot_change_auth_descriptor_identity() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin-token.json");
        let replacement = directory.path().join("replacement-admin-token.json");
        std::fs::write(
            &path,
            br#"{"tokens":[{"token":"original","tenants":["tenant-a"]}]}"#,
        )
        .unwrap();
        std::fs::write(
            &replacement,
            br#"{"tokens":[{"token":"replacement","tenants":["tenant-b"]}]}"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();

        let opened_path = path.clone();
        AFTER_AUTH_FILE_METADATA.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(replacement, opened_path).unwrap();
            }));
        });

        let auth = AdminAuth::from_file(&path).unwrap();
        assert!(auth.authorize(Some("original"), Some("tenant-a")));
        assert!(!auth.authenticated(Some("replacement")));
    }

    #[cfg(unix)]
    #[test]
    fn auth_file_read_is_capped_when_a_regular_file_grows_after_metadata() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("growing-auth-file.json");
        std::fs::write(
            &path,
            br#"{"tokens":[{"token":"small","tenants":["tenant-a"]}]}"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let growing_path = path.clone();
        AFTER_AUTH_FILE_METADATA.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::write(growing_path, vec![b'x'; MAX_AUTH_FILE_BYTES as usize + 1]).unwrap();
            }));
        });

        let error = AdminAuth::from_file(&path).unwrap_err();
        assert!(
            error.to_string().contains("exceeds 256KB limit"),
            "the bytes actually read must remain capped after metadata: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn admin_token_file_fifo_child() {
        let Some(path) = std::env::var_os("SBPROXY_AUTH_FIFO_CHILD_PATH") else {
            return;
        };
        let marker = std::env::var_os("SBPROXY_AUTH_FIFO_CHILD_MARKER").unwrap();
        let error = AdminAuth::from_file(Path::new(&path))
            .expect_err("a FIFO must not satisfy the admin-token file contract");
        assert!(
            error.to_string().contains("must be a regular file"),
            "non-regular descriptor refusal must be explicit: {error}"
        );
        std::fs::write(marker, b"regular-file-refused").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn mode_0600_fifo_without_a_writer_is_rejected_promptly() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("admin-token.fifo");
        let marker = directory.path().join("child-finished");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("auth::tests::admin_token_file_fifo_child")
            .arg("--nocapture")
            .env("SBPROXY_AUTH_FIFO_CHILD_PATH", &fifo)
            .env("SBPROXY_AUTH_FIFO_CHILD_MARKER", &marker)
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        let exit_status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        if exit_status.is_none() {
            child.kill().unwrap();
            let _ = child.wait();
        }
        assert!(
            exit_status.is_some(),
            "opening a mode-0600 FIFO without a writer blocked instead of refusing its descriptor"
        );
        assert!(
            exit_status.unwrap().success(),
            "FIFO helper did not observe the explicit regular-file refusal"
        );
        assert_eq!(std::fs::read(&marker).unwrap(), b"regular-file-refused");
    }
}
