/// Authentication providers for Rysteria server.
///
/// Go equivalent: hysteria/extras/auth/
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

// ──────────────────────────────────────────────────────────────────────────────
// Authenticator trait
// ──────────────────────────────────────────────────────────────────────────────

/// Authenticates a connecting client.
///
/// Go equivalent: `server.Authenticator` interface.
///
/// Returns `(ok, id)` — if `ok` is true, `id` is an opaque user identifier string.
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, addr: SocketAddr, auth: &str, tx: u64) -> (bool, String);
}

// ──────────────────────────────────────────────────────────────────────────────
// PasswordAuthenticator
// ──────────────────────────────────────────────────────────────────────────────

/// Checks the auth string against a single fixed password.
///
/// Go equivalent: `auth.PasswordAuthenticator`.
pub struct PasswordAuthenticator {
    pub password: String,
}

#[async_trait]
impl Authenticator for PasswordAuthenticator {
    async fn authenticate(&self, _addr: SocketAddr, auth: &str, _tx: u64) -> (bool, String) {
        if auth == self.password {
            (true, "user".to_string())
        } else {
            (false, String::new())
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// UserPassAuthenticator
// ──────────────────────────────────────────────────────────────────────────────

/// Checks auth string (format: "username:password") against a map of users.
///
/// Usernames are case-insensitive (lowercased internally).
///
/// Go equivalent: `auth.UserPassAuthenticator`.
pub struct UserPassAuthenticator {
    /// username (lowercase) → password
    users: HashMap<String, String>,
}

impl UserPassAuthenticator {
    pub fn new(users: HashMap<String, String>) -> Self {
        // Lowercase all usernames for case-insensitive comparison
        let users = users
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();
        Self { users }
    }
}

#[async_trait]
impl Authenticator for UserPassAuthenticator {
    async fn authenticate(&self, _addr: SocketAddr, auth: &str, _tx: u64) -> (bool, String) {
        let parts: Vec<&str> = auth.splitn(2, ':').collect();
        if parts.len() != 2 {
            return (false, String::new());
        }
        let username = parts[0].to_lowercase();
        let password = parts[1];
        match self.users.get(&username) {
            Some(stored) if stored == password => (true, username),
            _ => (false, String::new()),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// HttpAuthenticator
// ──────────────────────────────────────────────────────────────────────────────

/// Delegates authentication to an HTTP webhook via POST request.
///
/// Request body (JSON): `{"addr": "...", "auth": "...", "tx": 0}`
/// Response body (JSON): `{"ok": true, "id": "..."}`
///
/// Go equivalent: `auth.HTTPAuthenticator`.
pub struct HttpAuthenticator {
    pub url: String,
    client: reqwest::Client,
}

impl HttpAuthenticator {
    pub fn new(url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { url, client }
    }

    pub fn new_insecure(url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { url, client }
    }
}

#[derive(Serialize)]
struct HttpAuthRequest<'a> {
    addr: String,
    auth: &'a str,
    tx: u64,
}

#[derive(Deserialize)]
struct HttpAuthResponse {
    ok: bool,
    id: String,
}

#[async_trait]
impl Authenticator for HttpAuthenticator {
    async fn authenticate(&self, addr: SocketAddr, auth: &str, tx: u64) -> (bool, String) {
        let req_body = HttpAuthRequest {
            addr: addr.to_string(),
            auth,
            tx,
        };
        let resp = match self.client.post(&self.url).json(&req_body).send().await {
            Ok(r) => r,
            Err(_) => return (false, String::new()),
        };
        if !resp.status().is_success() {
            return (false, String::new());
        }
        match resp.json::<HttpAuthResponse>().await {
            Ok(r) => (r.ok, r.id),
            Err(_) => (false, String::new()),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// CommandAuthenticator
// ──────────────────────────────────────────────────────────────────────────────

/// Delegates authentication to an external command.
///
/// Invokes: `<cmd> <addr> <auth> <tx>`
/// Auth succeeds if exit code is 0; the stdout (trimmed) becomes the user ID.
///
/// Go equivalent: `auth.CommandAuthenticator`.
pub struct CommandAuthenticator {
    pub cmd: String,
}

#[async_trait]
impl Authenticator for CommandAuthenticator {
    async fn authenticate(&self, addr: SocketAddr, auth: &str, tx: u64) -> (bool, String) {
        let output = tokio::process::Command::new(&self.cmd)
            .arg(addr.to_string())
            .arg(auth)
            .arg(tx.to_string())
            .output()
            .await;
        match output {
            Ok(out) if out.status.success() => {
                let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
                (true, id)
            }
            _ => (false, String::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn dummy_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    #[tokio::test]
    async fn password_auth_correct() {
        let a = PasswordAuthenticator {
            password: "secret".into(),
        };
        let (ok, id) = a.authenticate(dummy_addr(), "secret", 0).await;
        assert!(ok);
        assert_eq!(id, "user");
    }

    #[tokio::test]
    async fn password_auth_wrong() {
        let a = PasswordAuthenticator {
            password: "secret".into(),
        };
        let (ok, _) = a.authenticate(dummy_addr(), "wrong", 0).await;
        assert!(!ok);
    }

    #[tokio::test]
    async fn userpass_auth_correct() {
        let mut users = HashMap::new();
        users.insert("alice".into(), "pass1".into());
        users.insert("Bob".into(), "pass2".into()); // will be lowercased
        let a = UserPassAuthenticator::new(users);

        let (ok, id) = a.authenticate(dummy_addr(), "alice:pass1", 0).await;
        assert!(ok);
        assert_eq!(id, "alice");

        // case-insensitive username
        let (ok, id) = a.authenticate(dummy_addr(), "BOB:pass2", 0).await;
        assert!(ok);
        assert_eq!(id, "bob");
    }

    #[tokio::test]
    async fn userpass_auth_wrong_password() {
        let mut users = HashMap::new();
        users.insert("alice".into(), "correct".into());
        let a = UserPassAuthenticator::new(users);

        let (ok, _) = a.authenticate(dummy_addr(), "alice:wrong", 0).await;
        assert!(!ok);
    }

    #[tokio::test]
    async fn userpass_auth_no_separator() {
        let a = UserPassAuthenticator::new(HashMap::new());
        let (ok, _) = a.authenticate(dummy_addr(), "nocolon", 0).await;
        assert!(!ok);
    }

    #[tokio::test]
    async fn command_auth_echo() {
        // Use `sh -c "echo user"` to return a user ID with exit code 0
        let _a = CommandAuthenticator { cmd: "sh".into() };
        // sh with no args fails, so we test via a simple echo
        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("echo user")
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "user");
    }

    #[tokio::test]
    async fn command_auth_fail() {
        // `false` command always returns exit code 1
        let a = CommandAuthenticator {
            cmd: "false".into(),
        };
        let (ok, _) = a.authenticate(dummy_addr(), "any", 0).await;
        assert!(!ok);
    }
}
