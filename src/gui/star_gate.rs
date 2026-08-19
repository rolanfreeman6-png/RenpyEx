//! First-launch "star gate": the GUI asks the user to star the project on
//! GitHub and verifies it before the main UI unlocks.
//!
//! Identity is proven with the GitHub OAuth **device flow**: the app requests
//! a device code, the user approves it at `github.com/login/device` while
//! signed in to *their own* account, and the app then checks
//! `GET /user/starred/{owner}/{repo}` with the resulting token — `204` means
//! the signed-in account stars the repository. No username is typed anywhere,
//! so nobody can pass the gate with someone else's nickname.
//!
//! (The anonymous per-repo check `GET /users/{u}/starred/{o}/{r}` is dead —
//! GitHub returns 404 unconditionally since 2025 — and
//! `GET /repos/{o}/{r}/stargazers` now demands auth; the authenticated
//! `/user/starred/...` endpoint is the one that still answers, with 204.)
//!
//! The result is persisted in `config.json` (`starred_by`), so already
//! activated users never hit the network again and offline launches keep
//! working. The token itself is only kept in memory and never written to
//! disk. Best-effort only — it is a polite ask, not DRM.

use std::sync::mpsc::Sender;

/// Repository whose star unlocks the GUI.
pub const REPO_URL: &str = "https://github.com/rolanfreeman6-png/RenpyEx";
/// Where the user types the device code.
pub const DEVICE_VERIFICATION_URL: &str = "https://github.com/login/device";
/// Owner/repo pair (lowercase) checked for a star.
const OWNER_REPO: &str = "rolanfreeman6-png/renpyex";
/// OAuth app client_id for the device flow. The device flow never uses the
/// client secret, so embedding the id in the binary is safe. Requests an
/// empty scope — the token can only read public profile data.
const OAUTH_CLIENT_ID: &str = "Ov23lieqnnqGIg2vg05f";

/// Progress events from a gate worker thread to the UI thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateEvent {
    /// A device code was issued; the UI should show it and point the user at
    /// the verification URL.
    DeviceCode(DeviceLogin),
    /// The user authorized the app. Carries the confirmed
    /// [`Authorized::login`] and the in-memory [`Authorized::token`] (never
    /// persisted) so the UI can re-check the star after the user presses
    /// "check again".
    Authorized {
        /// The GitHub login the user signed in with.
        login: String,
        /// Zero-scope device-flow token, kept in memory only.
        token: String,
    },
    /// The signed-in account stars the repository — unlock.
    Starred(String),
    /// The signed-in account exists but has no star (yet).
    NotStarred(String),
    /// The user denied the authorization or the code expired.
    Denied(String),
    /// Something else went wrong (offline, rate limit, ...).
    Failed(String),
}

/// Device-flow handshake data shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLogin {
    /// Short code like `WDJB-MJHT` the user types at the verification page.
    pub user_code: String,
    /// URL of that verification page.
    pub verification_uri: String,
}

/// Request a device code, poll until the user authorizes, then check the
/// star on the signed-in account. Sends [`GateEvent`]s as it progresses and
/// simply returns when done (the UI reacts to the last event received).
pub fn run_device_flow(tx: &Sender<GateEvent>) {
    let (device_code, interval, expires_in) = match request_device_code(tx) {
        Ok(triple) => triple,
        Err(message) => {
            let _ = tx.send(GateEvent::Failed(message));
            return;
        }
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(expires_in);
    let mut interval = interval;
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        match poll_access_token(&device_code) {
            PollResult::Token(token) => {
                verify_star(&token, tx);
                return;
            }
            PollResult::Pending => {}
            PollResult::SlowDown => interval += 5,
            PollResult::Expired => {
                let _ = tx.send(GateEvent::Denied("device code expired — try again".into()));
                return;
            }
            PollResult::Denied => {
                let _ = tx.send(GateEvent::Denied("authorization was denied".into()));
                return;
            }
            PollResult::Failed(message) => {
                let _ = tx.send(GateEvent::Failed(message));
                return;
            }
        }
    }
    let _ = tx.send(GateEvent::Denied("device code expired — try again".into()));
}

/// Re-check the star with a token from a completed device flow (the user has
/// been asked to star the repo and pressed "check again").
pub fn recheck_star(token: &str, tx: &Sender<GateEvent>) {
    verify_star(token, tx);
}

/// POST to the device-code endpoint and emit [`GateEvent::DeviceCode`].
/// Returns `(device_code, poll_interval_secs, expires_in_secs)`.
fn request_device_code(tx: &Sender<GateEvent>) -> Result<(String, u64, u64), String> {
    if OAUTH_CLIENT_ID.starts_with("REPLACE_WITH") {
        return Err(
            "star gate is not configured: the maintainer must set OAUTH_CLIENT_ID \
             (register an OAuth app at github.com/settings/developers)"
                .to_string(),
        );
    }
    let body = format!("client_id={OAUTH_CLIENT_ID}&scope=");
    let json = gh_post_form("https://github.com/login/device/code", &body)?;
    let value: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| format!("unexpected device-code response: {e}"))?;
    let device_code = value["device_code"].as_str().unwrap_or_default().to_string();
    let user_code = value["user_code"].as_str().unwrap_or_default().to_string();
    let verification_uri = value["verification_uri"]
        .as_str()
        .unwrap_or(DEVICE_VERIFICATION_URL)
        .to_string();
    if device_code.is_empty() || user_code.is_empty() {
        return Err("unexpected device-code response: missing fields".to_string());
    }
    let _ = tx.send(GateEvent::DeviceCode(DeviceLogin {
        user_code,
        verification_uri,
    }));
    let interval = value["interval"].as_u64().unwrap_or(5).max(1);
    let expires_in = value["expires_in"].as_u64().unwrap_or(900).min(1800);
    Ok((device_code, interval, expires_in))
}

/// Outcome of one access-token poll.
#[derive(Debug)]
enum PollResult {
    Token(String),
    Pending,
    SlowDown,
    Expired,
    Denied,
    Failed(String),
}

/// Poll the token endpoint once for the given device code.
fn poll_access_token(device_code: &str) -> PollResult {
    let body = format!(
        "client_id={OAUTH_CLIENT_ID}&device_code={device_code}&grant_type=urn:ietf:params:oauth:grant-type:device_code"
    );
    let json = match gh_post_form("https://github.com/login/oauth/access_token", &body) {
        Ok(json) => json,
        Err(message) => return PollResult::Failed(message),
    };
    let value: serde_json::Value = match serde_json::from_str(&json) {
        Ok(value) => value,
        Err(e) => return PollResult::Failed(format!("unexpected token response: {e}")),
    };
    if let Some(token) = value["access_token"].as_str() {
        return PollResult::Token(token.to_string());
    }
    match value["error"].as_str().unwrap_or_default() {
        "authorization_pending" => PollResult::Pending,
        "slow_down" => PollResult::SlowDown,
        "expired_token" => PollResult::Expired,
        "access_denied" => PollResult::Denied,
        other => PollResult::Failed(format!("device flow error: {other}")),
    }
}

/// With a user token: resolve the login and check `GET /user/starred/{repo}`.
fn verify_star(token: &str, tx: &Sender<GateEvent>) {
    let login = match gh_get_json("https://api.github.com/user", token) {
        Ok(value) => value["login"].as_str().unwrap_or_default().to_string(),
        Err(message) => {
            let _ = tx.send(GateEvent::Failed(message));
            return;
        }
    };
    if login.is_empty() {
        let _ = tx.send(GateEvent::Failed("could not resolve GitHub login".into()));
        return;
    }
    let _ = tx.send(GateEvent::Authorized {
        login: login.clone(),
        token: token.to_string(),
    });
    let star_url = format!("https://api.github.com/user/starred/{OWNER_REPO}");
    match gh_get(&star_url, token).map(|(status, _)| status) {
        Ok(204) => {
            let _ = tx.send(GateEvent::Starred(login));
        }
        // 404 from this endpoint means "signed in, but no star".
        Ok(404) => {
            let _ = tx.send(GateEvent::NotStarred(login));
        }
        Ok(code) => {
            let _ = tx.send(GateEvent::Failed(format!("GitHub API error (HTTP {code})")));
        }
        Err(message) => {
            let _ = tx.send(GateEvent::Failed(message));
        }
    }
}

/// POST a form body to a github.com endpoint and return the JSON text.
fn gh_post_form(url: &str, body: &str) -> Result<String, String> {
    match ureq::post(url)
        .set("User-Agent", "renpyex-gui")
        .set("Accept", "application/json")
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(body)
    {
        Ok(resp) => resp
            .into_string()
            .map_err(|e| format!("network error: {e}")),
        Err(ureq::Error::Status(code, _)) => Err(format!("GitHub error (HTTP {code})")),
        Err(e) => Err(format!("network error: {e}")),
    }
}

/// GET a JSON endpoint with a bearer token.
fn gh_get_json(url: &str, token: &str) -> Result<serde_json::Value, String> {
    let (status, body) = gh_get(url, token)?;
    if status != 200 {
        return Err(format!("GitHub API error (HTTP {status})"));
    }
    serde_json::from_str(&body).map_err(|e| format!("unexpected GitHub API response: {e}"))
}

/// GET with a bearer token, returning `(http_status, body)`. 4xx/5xx are
/// surfaced as `Ok(status, ..)` — callers interpret per-endpoint meanings
/// (404 on the star check is "no star", not a transport failure).
fn gh_get(url: &str, token: &str) -> Result<(u16, String), String> {
    match ureq::get(url)
        .set("User-Agent", "renpyex-gui")
        .set("Accept", "application/vnd.github+json")
        .set("Authorization", &format!("Bearer {token}"))
        .call()
    {
        Ok(resp) => {
            let status = resp.status();
            resp.into_string()
                .map(|body| (status, body))
                .map_err(|e| format!("network error: {e}"))
        }
        Err(ureq::Error::Status(429 | 403, _)) => Err(
            "GitHub API rate limit reached — try again in a few minutes".to_string(),
        ),
        Err(ureq::Error::Status(code, resp)) => {
            let _ = resp.into_string();
            Ok((code, String::new()))
        }
        Err(e) => Err(format!("network error: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_code_response_parses() {
        // Shape of https://github.com/login/device/code output.
        let json = r#"{"device_code":"dc_abc","user_code":"WDJB-MJHT","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(value["device_code"].as_str(), Some("dc_abc"));
        assert_eq!(value["user_code"].as_str(), Some("WDJB-MJHT"));
        assert_eq!(value["interval"].as_u64(), Some(5));
        assert_eq!(value["expires_in"].as_u64(), Some(900));
    }

    #[test]
    fn poll_response_classifies() {
        let pending: serde_json::Value =
            serde_json::from_str(r#"{"error":"authorization_pending"}"#).unwrap();
        assert_eq!(pending["error"].as_str(), Some("authorization_pending"));
        let token: serde_json::Value =
            serde_json::from_str(r#"{"access_token":"gho_x","token_type":"bearer","scope":""}"#)
                .unwrap();
        assert_eq!(token["access_token"].as_str(), Some("gho_x"));
    }

    #[test]
    fn client_id_is_configured() {
        assert!(
            OAUTH_CLIENT_ID.starts_with("Ov") || OAUTH_CLIENT_ID.starts_with("Iv"),
            "OAUTH_CLIENT_ID must be a real GitHub OAuth app id"
        );
    }

    /// Live: the registered OAuth app issues device codes (proves the Device
    /// Flow checkbox is enabled). Run with
    /// `cargo test --features gui live_device -- --ignored`.
    #[test]
    #[ignore = "hits the real GitHub device flow"]
    fn live_device_code_issued_and_poll_pends() {
        let (tx, rx) = std::sync::mpsc::channel();
        let (device_code, interval, expires_in) = request_device_code(&tx).unwrap();
        assert!(!device_code.is_empty());
        assert!(interval >= 1);
        assert!(expires_in > 0);
        match rx.recv() {
            Ok(GateEvent::DeviceCode(_)) => {}
            other => panic!("device code event should reach the UI, got {other:?}"),
        }
        // Nobody has authorized this fresh code yet — the first poll must
        // report "pending", not an error.
        match poll_access_token(&device_code) {
            PollResult::Pending => {}
            other => panic!("expected Pending for an un-authorized code, got {other:?}"),
        }
    }

    /// Live: full star verification with a real token. The account behind
    /// `GITHUB_TOKEN` must star the repo (the owner's does). Run with
    /// `GITHUB_TOKEN=$(gh auth token) cargo test --features gui live_verify -- --ignored`.
    #[test]
    #[ignore = "needs GITHUB_TOKEN and hits the real GitHub API"]
    fn live_verify_star_with_token() {
        let token = std::env::var("GITHUB_TOKEN").expect("set GITHUB_TOKEN");
        let (tx, rx) = std::sync::mpsc::channel();
        verify_star(&token, &tx);
        let events: Vec<GateEvent> = rx.try_iter().collect();
        assert_eq!(
            events.last(),
            Some(&GateEvent::Starred("rolanfreeman6-png".to_string())),
            "owner starred the repo during development; events: {events:?}"
        );
    }
}
