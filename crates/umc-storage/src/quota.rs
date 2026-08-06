//! Storage quotas (resource-limits.md §34): profile defaults and reserved capacity.
use crate::store::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Constrained,
    Standard,
    Relay,
}

impl Profile {
    #[must_use]
    pub fn operational_storage_bytes(self) -> u64 {
        match self {
            Profile::Constrained => 512 * 1024 * 1024,
            Profile::Standard => 4 * 1024 * 1024 * 1024,
            Profile::Relay => 16 * 1024 * 1024 * 1024,
        }
    }

    #[must_use]
    pub fn bundle_storage_bytes(self) -> u64 {
        match self {
            Profile::Constrained => 0,
            Profile::Standard => 1024 * 1024 * 1024,
            Profile::Relay => 10_737_418_240,
        }
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
        assert_eq!(
            Profile::Standard.bundle_storage_bytes(),
            1024 * 1024 * 1024
        );
        assert_eq!(Profile::Constrained.bundle_storage_bytes(), 0);
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
