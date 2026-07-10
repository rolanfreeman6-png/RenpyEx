//! Persisted GUI state: the last-used source/output paths.
//!
//! Stored as JSON at `%APPDATA%\renpyex\config.json` on Windows or
//! `$XDG_CONFIG_HOME/renpyex/config.json` (falling back to `~/.config`)
//! elsewhere. Best-effort only — a missing or corrupt file just falls back
//! to defaults rather than surfacing an error to the user.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Last-used paths, restored on the next launch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Last-used source (game) directory.
    #[serde(default)]
    pub last_source: String,
    /// Last-used output directory.
    #[serde(default)]
    pub last_output: String,
}

impl Config {
    /// Load the persisted config, or defaults if absent/corrupt.
    #[must_use]
    pub fn load() -> Self {
        config_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist this config to disk, creating parent directories as needed.
    pub fn save(&self) -> std::io::Result<()> {
        let path = config_path().ok_or_else(|| {
            std::io::Error::other("could not determine config directory")
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
    }
}

/// Resolve the config file path for the current platform.
fn config_path() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(|appdata| PathBuf::from(appdata).join("renpyex").join("config.json"))
    } else {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
        Some(base.join("renpyex").join("config.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_empty() {
        let cfg = Config::default();
        assert!(cfg.last_source.is_empty());
        assert!(cfg.last_output.is_empty());
    }

    #[test]
    fn round_trips_through_json() {
        let cfg = Config {
            last_source: "C:/games/foo".to_string(),
            last_output: "C:/out/foo".to_string(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.last_source, cfg.last_source);
        assert_eq!(back.last_output, cfg.last_output);
    }
}
