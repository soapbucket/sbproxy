//! Authentication and tenant-scoped authorization for sidecar admin surfaces.

use anyhow::{bail, Context as _};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use subtle::ConstantTimeEq as _;

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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(path)
                .with_context(|| format!("reading admin token file metadata {}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                bail!(
                    "admin token file {} must not be readable or writable by group/other",
                    path.display()
                );
            }
        }
        let meta = std::fs::metadata(path).with_context(|| format!("reading admin token file metadata {}", path.display()))?;
        if meta.len() > 256 * 1024 {
            bail!("admin token file {} exceeds 256KB limit", path.display());
        }
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading admin token file {}", path.display()))?;
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

    pub fn visible_tenants(
        &self,
        presented: Option<&str>,
        tenants: impl IntoIterator<Item = String>,
    ) -> Option<Vec<String>> {
        let grant = self.grant(presented)?;
        let wildcard = grant.tenants.iter().any(|scope| scope == "*");
        Some(
            tenants
                .into_iter()
                .filter(|tenant| wildcard || grant.tenants.iter().any(|scope| scope == tenant))
                .collect(),
        )
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
        assert!(AdminAuth::from_json(json.as_bytes()).unwrap_err().to_string().contains("1024 grant limit"));
    }
}
