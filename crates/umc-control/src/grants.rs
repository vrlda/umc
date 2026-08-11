//! Capability grants (control-api.md §12-14): an absent `ResourceConstraints`
//! means no restriction; a present but empty constraint list grants nothing
//! unless `all_resources` is set.
use crate::proto::umc::api::v1 as api;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    CannotDelegate,
    Expired,
    NotFound,
}

#[derive(Debug, Clone)]
pub struct GrantSet {
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub grant_id: u64,
    pub capabilities: Vec<api::Capability>,
    pub resource_constraints: Option<api::ResourceConstraints>,
    pub expires_at_ms: Option<u64>,
}

impl GrantSet {
    #[must_use]
    pub const fn empty() -> Self {
        Self { grants: Vec::new() }
    }

    pub fn add(&mut self, grant: Grant) {
        self.grants.push(grant);
    }

    /// Convert the wire representation used by `TokenService` into the
    /// runtime grant evaluator. Invalid or unspecified capabilities and
    /// negative expiry values are ignored rather than becoming authority.
    /// This keeps malformed delegated grants fail-closed at the authorization
    /// boundary (control-api.md §12-14).
    #[must_use]
    pub fn from_api(grants: &[api::CapabilityGrant]) -> Self {
        let mut set = Self::empty();
        for (index, grant) in grants.iter().enumerate() {
            let Ok(capability) = api::Capability::try_from(grant.capability) else {
                continue;
            };
            if capability == api::Capability::Unspecified || grant.expires_at_unix_ms < 0 {
                continue;
            }
            let expires_at_ms = if grant.expires_at_unix_ms == 0 {
                None
            } else {
                u64::try_from(grant.expires_at_unix_ms).ok()
            };
            set.add(Grant {
                grant_id: u64::try_from(index).unwrap_or(u64::MAX),
                capabilities: vec![capability],
                resource_constraints: grant.constraints.clone(),
                expires_at_ms,
            });
        }
        set
    }

    #[must_use]
    pub fn allows(&self, capability: api::Capability, now_ms: u64) -> bool {
        self.grants.iter().any(|g| {
            if let Some(exp) = g.expires_at_ms {
                if now_ms >= exp {
                    return false;
                }
            }
            g.capabilities.contains(&capability)
        })
    }

    /// The resource-constraint rule (control-api.md §14): an absent list is a
    /// wildcard; a present list grants only listed endpoints, and an empty
    /// list grants nothing unless `all_resources` is set.
    #[must_use]
    pub fn resource_allowed(
        &self,
        capability: api::Capability,
        endpoint_id: &[u8],
        now_ms: u64,
    ) -> bool {
        self.grants.iter().any(|g| {
            if let Some(exp) = g.expires_at_ms {
                if now_ms >= exp {
                    return false;
                }
            }
            if !g.capabilities.contains(&capability) {
                return false;
            }
            let Some(rc) = &g.resource_constraints else {
                return true; // no constraints: any resource within capability
            };
            if rc.all_resources {
                return true;
            }
            rc.endpoint_ids.iter().any(|id| id == endpoint_id)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_constraints_do_not_restrict() {
        let mut set = GrantSet::empty();
        set.add(Grant {
            grant_id: 1,
            capabilities: vec![api::Capability::NodeRead],
            resource_constraints: None,
            expires_at_ms: None,
        });
        assert!(set.resource_allowed(api::Capability::NodeRead, b"some-endpoint", 0));
        assert!(set.allows(api::Capability::NodeRead, 0));
    }

    #[test]
    fn empty_constraint_list_grants_nothing_without_all_resources() {
        let mut set = GrantSet::empty();
        set.add(Grant {
            grant_id: 2,
            capabilities: vec![api::Capability::NodeRead],
            resource_constraints: Some(api::ResourceConstraints {
                all_resources: false,
                ..Default::default()
            }),
            expires_at_ms: None,
        });
        assert!(!set.resource_allowed(api::Capability::NodeRead, b"some-endpoint", 0));
    }

    #[test]
    fn all_resources_grants_wildcard() {
        let mut set = GrantSet::empty();
        set.add(Grant {
            grant_id: 3,
            capabilities: vec![api::Capability::ApplicationConnect],
            resource_constraints: Some(api::ResourceConstraints {
                all_resources: true,
                ..Default::default()
            }),
            expires_at_ms: None,
        });
        assert!(set.resource_allowed(api::Capability::ApplicationConnect, b"anything", 0));
    }

    #[test]
    fn expiry_blocks() {
        let mut set = GrantSet::empty();
        set.add(Grant {
            grant_id: 4,
            capabilities: vec![api::Capability::NodeRead],
            resource_constraints: None,
            expires_at_ms: Some(10),
        });
        assert!(set.allows(api::Capability::NodeRead, 9));
        assert!(!set.allows(api::Capability::NodeRead, 10));
    }

    #[test]
    fn api_grants_fail_closed_for_invalid_and_expired_entries() {
        let grants = [
            api::CapabilityGrant {
                capability: api::Capability::NodeRead as i32,
                expires_at_unix_ms: 50,
                ..Default::default()
            },
            api::CapabilityGrant {
                capability: api::Capability::Unspecified as i32,
                ..Default::default()
            },
            api::CapabilityGrant {
                capability: 9_999,
                ..Default::default()
            },
            api::CapabilityGrant {
                capability: api::Capability::NodeAdmin as i32,
                expires_at_unix_ms: -1,
                ..Default::default()
            },
        ];
        let set = GrantSet::from_api(&grants);
        assert!(set.allows(api::Capability::NodeRead, 49));
        assert!(!set.allows(api::Capability::NodeRead, 50));
        assert!(!set.allows(api::Capability::NodeAdmin, 0));
    }
}
