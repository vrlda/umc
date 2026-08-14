//! Compile-time edition selected by the daemon artifact.
//!
//! The runtime `edition` setting may select a lower profile than the artifact
//! that contains it, but it may never request capabilities that were not built
//! into that artifact. This keeps one source tree and one UMP wire contract
//! while making the three release profiles explicit and fail closed.

#[cfg(any(
    all(feature = "edition-lite", feature = "edition-standard"),
    all(feature = "edition-lite", feature = "edition-extended"),
    all(feature = "edition-standard", feature = "edition-extended"),
))]
compile_error!("umcd edition features are mutually exclusive");

#[cfg(feature = "edition-lite")]
#[must_use]
pub const fn compiled_edition() -> umc_types::edition::CoreEdition {
    umc_types::edition::CoreEdition::Lite
}

#[cfg(all(not(feature = "edition-lite"), feature = "edition-extended"))]
#[must_use]
pub const fn compiled_edition() -> umc_types::edition::CoreEdition {
    umc_types::edition::CoreEdition::Extended
}

#[cfg(all(not(feature = "edition-lite"), not(feature = "edition-extended")))]
#[must_use]
pub const fn compiled_edition() -> umc_types::edition::CoreEdition {
    umc_types::edition::CoreEdition::Standard
}

#[must_use]
pub const fn artifact_name() -> &'static str {
    match compiled_edition() {
        umc_types::edition::CoreEdition::Lite => "umcd-lite",
        umc_types::edition::CoreEdition::Standard => "umcd",
        umc_types::edition::CoreEdition::Extended => "umcd-extended",
    }
}

#[must_use]
pub const fn supports_runtime_edition(
    requested: umc_types::edition::CoreEdition,
) -> bool {
    matches!(
        (compiled_edition(), requested),
        (umc_types::edition::CoreEdition::Lite, umc_types::edition::CoreEdition::Lite)
            | (umc_types::edition::CoreEdition::Standard, umc_types::edition::CoreEdition::Lite | umc_types::edition::CoreEdition::Standard)
            | (umc_types::edition::CoreEdition::Extended, _)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::edition::CoreEdition;

    #[test]
    fn artifact_name_matches_compiled_edition() {
        let expected = match compiled_edition() {
            CoreEdition::Lite => "umcd-lite",
            CoreEdition::Standard => "umcd",
            CoreEdition::Extended => "umcd-extended",
        };
        assert_eq!(artifact_name(), expected);
    }

    #[test]
    fn lower_runtime_profiles_are_supported() {
        assert!(supports_runtime_edition(CoreEdition::Lite));
        assert!(supports_runtime_edition(compiled_edition()));
        if compiled_edition() != CoreEdition::Extended {
            assert!(!supports_runtime_edition(CoreEdition::Extended));
        }
    }
}
