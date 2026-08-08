//! Privacy profile policy primitives (privacy.md §41–43).

use std::fmt;
use std::str::FromStr;

/// Minimum behavior requested by an application or selected by local policy.
///
/// Profiles are ordered from the secure direct-communication baseline (`P0`)
/// to the most privacy-preserving profile (`P3`).  A higher profile includes
/// the requirements of every lower profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrivacyProfile {
    /// Authenticated encryption and metadata minimization.
    P0,
    /// Identity and topology minimization.
    P1,
    /// Layered private routing.
    P2,
    /// Traffic-analysis resistance.
    P3,
}

/// Error returned when a privacy profile string is not recognized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePrivacyProfileError {
    value: String,
}

impl fmt::Display for ParsePrivacyProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported privacy profile {:?}; expected p0, p1, p2, or p3",
            self.value
        )
    }
}

impl std::error::Error for ParsePrivacyProfileError {}

impl PrivacyProfile {
    /// Returns the stable lower-case configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P0 => "p0",
            Self::P1 => "p1",
            Self::P2 => "p2",
            Self::P3 => "p3",
        }
    }

    /// Returns whether this profile includes the requirements of `required`.
    #[must_use]
    pub const fn includes(self, required: Self) -> bool {
        self as u8 >= required as u8
    }

    /// Returns the stronger of two requested profiles.
    #[must_use]
    pub const fn max(self, other: Self) -> Self {
        if self as u8 >= other as u8 {
            self
        } else {
            other
        }
    }

    /// Returns the cumulative profile levels enabled by this profile.
    ///
    /// The tuple is ordered `(p0, p1, p2, p3)`.  For example, P2 enables
    /// P0, P1, and P2, but not P3.
    #[must_use]
    pub const fn cumulative(self) -> [bool; 4] {
        match self {
            Self::P0 => [true, false, false, false],
            Self::P1 => [true, true, false, false],
            Self::P2 => [true, true, true, false],
            Self::P3 => [true, true, true, true],
        }
    }

    /// Applies a local policy override without permitting a downgrade.
    #[must_use]
    pub const fn effective(self, policy_override: Option<Self>) -> Self {
        match policy_override {
            Some(policy) => self.max(policy),
            None => self,
        }
    }
}

impl FromStr for PrivacyProfile {
    type Err = ParsePrivacyProfileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "p0" => Ok(Self::P0),
            "p1" => Ok(Self::P1),
            "p2" => Ok(Self::P2),
            "p3" => Ok(Self::P3),
            _ => Err(ParsePrivacyProfileError {
                value: value.to_string(),
            }),
        }
    }
}

impl fmt::Display for PrivacyProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_strings_round_trip_case_insensitively() {
        for profile in [
            PrivacyProfile::P0,
            PrivacyProfile::P1,
            PrivacyProfile::P2,
            PrivacyProfile::P3,
        ] {
            assert_eq!(profile.as_str().parse::<PrivacyProfile>(), Ok(profile));
        }
        assert_eq!(" P2 ".parse::<PrivacyProfile>(), Ok(PrivacyProfile::P2));
        assert!("p4".parse::<PrivacyProfile>().is_err());
    }

    #[test]
    fn cumulative_levels_are_monotonic() {
        assert_eq!(PrivacyProfile::P0.cumulative(), [true, false, false, false]);
        assert_eq!(PrivacyProfile::P1.cumulative(), [true, true, false, false]);
        assert_eq!(PrivacyProfile::P2.cumulative(), [true, true, true, false]);
        assert_eq!(PrivacyProfile::P3.cumulative(), [true, true, true, true]);
        assert!(PrivacyProfile::P2.includes(PrivacyProfile::P1));
        assert!(!PrivacyProfile::P1.includes(PrivacyProfile::P2));
    }

    #[test]
    fn policy_override_can_only_raise_profile() {
        assert_eq!(
            PrivacyProfile::P0.effective(Some(PrivacyProfile::P1)),
            PrivacyProfile::P1
        );
        assert_eq!(
            PrivacyProfile::P2.effective(Some(PrivacyProfile::P1)),
            PrivacyProfile::P2
        );
        assert_eq!(PrivacyProfile::P3.effective(None), PrivacyProfile::P3);
    }
}
