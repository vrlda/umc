//! Plugin contract and registry (Phase 11 decision): in-process plugins
//! bound to JSON manifests. Dynamic (dlopen) loading lands after the spec
//! freezes the plugin security model.
pub mod contract;
pub mod loader;
pub mod registry;
