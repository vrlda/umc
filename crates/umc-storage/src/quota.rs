//! Storage quotas (resource-limits.md §34): profile defaults and reserved capacity.
use crate::store::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Constrained,
    Standard,
    Relay,
}

/// Hard resource defaults shared by the daemon's profile enforcement points.
/// The storage quota and live-session/relay admission limits are kept in one
/// table so a profile cannot silently drift between subsystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceProfileLimits {
    pub managed_memory_bytes: u64,
    pub operational_storage_bytes: u64,
    pub bundle_storage_bytes: u64,
    pub active_sessions: usize,
    pub active_relay_circuits: usize,
}

impl Profile {
    #[must_use]
    pub const fn limits(self) -> ResourceProfileLimits {
        match self {
            Profile::Constrained => ResourceProfileLimits {
                managed_memory_bytes: 128 * 1024 * 1024,
                operational_storage_bytes: 512 * 1024 * 1024,
                bundle_storage_bytes: 0,
                active_sessions: 128,
                active_relay_circuits: 256,
            },
            Profile::Standard => ResourceProfileLimits {
                managed_memory_bytes: 512 * 1024 * 1024,
                operational_storage_bytes: 4 * 1024 * 1024 * 1024,
                bundle_storage_bytes: 1024 * 1024 * 1024,
                active_sessions: 1_024,
                active_relay_circuits: 4_096,
            },
            Profile::Relay => ResourceProfileLimits {
                managed_memory_bytes: 2 * 1024 * 1024 * 1024,
                operational_storage_bytes: 16 * 1024 * 1024 * 1024,
                bundle_storage_bytes: 10 * 1024 * 1024 * 1024,
                active_sessions: 8_192,
                active_relay_circuits: 16_384,
            },
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "constrained" => Some(Self::Constrained),
            "standard" => Some(Self::Standard),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Constrained => "constrained",
            Self::Standard => "standard",
            Self::Relay => "relay",
        }
    }

    #[must_use]
    pub const fn operational_storage_bytes(self) -> u64 {
        self.limits().operational_storage_bytes
    }

    #[must_use]
    pub const fn bundle_storage_bytes(self) -> u64 {
        self.limits().bundle_storage_bytes
    }
}

/// Standard profile reserves 64 MiB for critical transactions (resource-limits.md §34).
pub const CRITICAL_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct QuotaAccount {
    pub profile: Profile,
    used: u64,
    pub hard_limit: u64,
}

impl QuotaAccount {
    #[must_use]
    pub fn new(profile: Profile, used_bytes: u64, hard_limit: u64) -> Self {
        Self {
            profile,
            used: used_bytes,
            hard_limit,
        }
    }

    #[must_use]
    pub fn used(&self) -> u64 {
        self.used
    }

    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.hard_limit.saturating_sub(self.used)
    }

    /// Reserves `bytes` of capacity, rejecting over-limit or overflowing
    /// reservations.
    ///
    /// # Errors
    /// Returns [`StoreError::QuotaExceeded`] if the reservation would exceed
    /// the hard limit or overflow.
    pub fn reserve(&mut self, bytes: u64) -> Result<(), StoreError> {
        let new_used = self
            .used
            .checked_add(bytes)
            .ok_or(StoreError::QuotaExceeded)?;
        if new_used > self.hard_limit {
            return Err(StoreError::QuotaExceeded);
        }
        self.used = new_used;
        Ok(())
    }

    pub fn release(&mut self, bytes: u64) {
        self.used = self.used.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_defaults_match_resource_limits() {
        assert_eq!(
            Profile::Standard.operational_storage_bytes(),
            4 * 1024 * 1024 * 1024
        );
        assert_eq!(Profile::Standard.bundle_storage_bytes(), 1024 * 1024 * 1024);
        assert_eq!(Profile::Constrained.bundle_storage_bytes(), 0);
    }

    #[test]
    fn profile_limits_match_resource_profile_matrix() {
        let constrained = Profile::Constrained.limits();
        assert_eq!(constrained.managed_memory_bytes, 128 * 1024 * 1024);
        assert_eq!(constrained.active_sessions, 128);
        assert_eq!(constrained.active_relay_circuits, 256);

        let standard = Profile::Standard.limits();
        assert_eq!(standard.managed_memory_bytes, 512 * 1024 * 1024);
        assert_eq!(standard.active_sessions, 1_024);
        assert_eq!(standard.active_relay_circuits, 4_096);

        let relay = Profile::Relay.limits();
        assert_eq!(relay.managed_memory_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(relay.active_sessions, 8_192);
        assert_eq!(relay.active_relay_circuits, 16_384);
    }

    #[test]
    fn reserve_enforces_hard_limit() {
        let mut q = QuotaAccount::new(Profile::Standard, 0, 100);
        q.reserve(60).unwrap();
        q.reserve(40).unwrap();
        assert_eq!(q.reserve(1), Err(StoreError::QuotaExceeded));
        assert_eq!(q.used(), 100);
    }

    #[test]
    fn release_saturates() {
        let mut q = QuotaAccount::new(Profile::Standard, 0, 100);
        q.reserve(10).unwrap();
        q.release(50);
        assert_eq!(q.used(), 0);
    }

    #[test]
    fn critical_reserve_is_explicit() {
        assert_eq!(CRITICAL_RESERVE_BYTES, 64 * 1024 * 1024);
    }
}
