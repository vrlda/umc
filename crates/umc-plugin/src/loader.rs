//! Manifest loading (Phase 11 decision): the registry reads a plugin's
//! manifest JSON from disk and binds an in-process implementation to it.
//! dlopen-based loading is deferred until the spec freezes the plugin
//! security model.
use std::fs;
use std::path::Path;

use crate::contract::{PluginError, PluginManifest};

/// Reads and validates a plugin manifest from `path`.
///
/// # Errors
///
/// Returns [`PluginError::Manifest`] when the file cannot be read, is not
/// valid JSON, or fails validation.
pub fn load_manifest(path: &Path) -> Result<PluginManifest, PluginError> {
    let text = fs::read_to_string(path)
        .map_err(|e| PluginError::Manifest(format!("{}: {e}", path.display())))?;
    let manifest: PluginManifest = serde_json::from_str(&text)
        .map_err(|e| PluginError::Manifest(format!("{}: {e}", path.display())))?;
    validate(&manifest)?;
    Ok(manifest)
}

fn validate(manifest: &PluginManifest) -> Result<(), PluginError> {
    if manifest.id.is_empty() {
        return Err(PluginError::Manifest(
            "manifest id must not be empty".into(),
        ));
    }
    if manifest.entry_point.is_empty() {
        return Err(PluginError::Manifest(
            "manifest entry_point must not be empty".into(),
        ));
    }
    Ok(())
}
