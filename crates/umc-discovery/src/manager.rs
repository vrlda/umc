//! Provider lifecycle and bounded result aggregation (discovery.md §5, §17,
//! §23).
//!
//! The manager deliberately treats providers as independent failure domains:
//! one provider may fail to start or collect candidates while healthy
//! providers continue to contribute. It also verifies source attribution and
//! exposes an explicit diversity result instead of silently treating one
//! source as independent evidence.

use crate::provider::{CandidateSource, DiscoveryProvider, PeerCandidate};
use crate::table::CandidateTable;
use std::collections::BTreeMap;
use umc_types::runtime::Instant;

pub const DEFAULT_PROVIDER_CANDIDATE_LIMIT: usize = 256;
pub const DEFAULT_MINIMUM_SOURCES: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderState {
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReport {
    pub provider_index: usize,
    pub source: CandidateSource,
    pub state: ProviderState,
    pub admitted_candidates: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshReport {
    pub providers: Vec<ProviderReport>,
    pub admitted_candidates: usize,
    pub distinct_sources: usize,
    pub source_counts: BTreeMap<CandidateSource, usize>,
    pub diversity_satisfied: bool,
}

struct ProviderEntry {
    provider: Box<dyn DiscoveryProvider>,
    source: CandidateSource,
    state: ProviderState,
    last_error: Option<String>,
}

/// Coordinates discovery providers without making one provider's failure a
/// failure of the whole discovery subsystem.
pub struct ProviderManager {
    table: CandidateTable,
    providers: Vec<ProviderEntry>,
    candidate_limit: usize,
    minimum_sources: usize,
}

impl std::fmt::Debug for ProviderManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderManager")
            .field("table", &self.table)
            .field("provider_count", &self.providers.len())
            .field("candidate_limit", &self.candidate_limit)
            .field("minimum_sources", &self.minimum_sources)
            .finish()
    }
}

impl ProviderManager {
    #[must_use]
    pub fn new(table_capacity: usize) -> Self {
        Self::with_policy(
            table_capacity,
            DEFAULT_PROVIDER_CANDIDATE_LIMIT,
            DEFAULT_MINIMUM_SOURCES,
        )
    }

    #[must_use]
    pub fn with_policy(
        table_capacity: usize,
        candidate_limit: usize,
        minimum_sources: usize,
    ) -> Self {
        Self {
            table: CandidateTable::new(table_capacity),
            providers: Vec::new(),
            candidate_limit: candidate_limit.max(1),
            minimum_sources: minimum_sources.max(1),
        }
    }

    /// Registers a provider and returns its stable index for diagnostics.
    pub fn register(&mut self, provider: Box<dyn DiscoveryProvider>) -> usize {
        let index = self.providers.len();
        let source = provider.source();
        self.providers.push(ProviderEntry {
            provider,
            source,
            state: ProviderState::Stopped,
            last_error: None,
        });
        index
    }

    /// Starts every provider, retaining failures in the per-provider report so
    /// healthy providers remain usable.
    pub fn start_all(&mut self) -> Vec<ProviderReport> {
        for entry in &mut self.providers {
            match entry.provider.start() {
                Ok(()) => {
                    entry.state = ProviderState::Running;
                    entry.last_error = None;
                }
                Err(error) => {
                    entry.state = ProviderState::Failed;
                    entry.last_error = Some(error);
                }
            }
        }
        self.reports()
    }

    /// Stops every provider. A stop failure is recorded but does not prevent
    /// other providers from being stopped.
    pub fn stop_all(&mut self) -> Vec<ProviderReport> {
        for entry in &mut self.providers {
            match entry.provider.stop() {
                Ok(()) => {
                    entry.state = ProviderState::Stopped;
                    entry.last_error = None;
                }
                Err(error) => {
                    entry.state = ProviderState::Failed;
                    entry.last_error = Some(error);
                }
            }
        }
        self.reports()
    }

    /// Collects bounded candidates from running providers and merges them
    /// into the shared table. Candidates carrying a source different from the
    /// provider's declared source are rejected and fail that provider closed.
    #[must_use]
    pub fn refresh(&mut self, now: Instant) -> RefreshReport {
        let mut source_counts = BTreeMap::new();
        let mut admitted_total = 0;
        let candidate_limit = self.candidate_limit;

        for entry in &mut self.providers {
            if entry.state != ProviderState::Running {
                continue;
            }
            let result = entry.provider.collect_candidates(candidate_limit);
            let Ok(mut candidates) = result else {
                entry.state = ProviderState::Failed;
                entry.last_error = result.err();
                continue;
            };
            // A provider is expected to honor the bound, but truncating here
            // keeps a faulty implementation from influencing the table or
            // diagnostics beyond the configured resource limit.
            candidates.truncate(candidate_limit);
            let mut admitted = 0;
            let mut source_mismatch = None;
            for candidate in candidates {
                if candidate.source != entry.source {
                    source_mismatch = Some(format!(
                        "candidate source {:?} disagrees with provider source {:?}",
                        candidate.source, entry.source
                    ));
                    break;
                }
                if candidate.is_expired(now) {
                    continue;
                }
                if self.table.upsert(candidate, now).is_ok() {
                    admitted += 1;
                }
            }
            if let Some(error) = source_mismatch {
                entry.state = ProviderState::Failed;
                entry.last_error = Some(error);
                continue;
            }
            admitted_total += admitted;
            if admitted > 0 {
                *source_counts.entry(entry.source).or_insert(0) += admitted;
            }
            entry.last_error = None;
        }

        let distinct_sources = source_counts.len();
        RefreshReport {
            providers: self.reports_with_admitted(&source_counts),
            admitted_candidates: admitted_total,
            distinct_sources,
            diversity_satisfied: distinct_sources >= self.minimum_sources,
            source_counts,
        }
    }

    #[must_use]
    pub fn candidates(&self) -> Vec<PeerCandidate> {
        self.table.iter().cloned().collect()
    }

    #[must_use]
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    #[must_use]
    pub fn minimum_sources(&self) -> usize {
        self.minimum_sources
    }

    fn reports(&self) -> Vec<ProviderReport> {
        self.reports_with_admitted(&BTreeMap::new())
    }

    fn reports_with_admitted(
        &self,
        source_counts: &BTreeMap<CandidateSource, usize>,
    ) -> Vec<ProviderReport> {
        self.providers
            .iter()
            .enumerate()
            .map(|(provider_index, entry)| ProviderReport {
                provider_index,
                source: entry.source,
                state: entry.state,
                admitted_candidates: source_counts.get(&entry.source).copied().unwrap_or(0),
                error: entry.last_error.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{CandidateAuth, CandidateSource, SharingPolicy};

    #[derive(Debug)]
    struct FakeProvider {
        source: CandidateSource,
        values: Vec<PeerCandidate>,
        start_error: Option<String>,
        collect_error: Option<String>,
        running: bool,
    }

    impl FakeProvider {
        fn new(source: CandidateSource, values: Vec<PeerCandidate>) -> Self {
            Self {
                source,
                values,
                start_error: None,
                collect_error: None,
                running: false,
            }
        }
    }

    impl DiscoveryProvider for FakeProvider {
        fn source(&self) -> CandidateSource {
            self.source
        }

        fn start(&mut self) -> Result<(), String> {
            if let Some(error) = &self.start_error {
                return Err(error.clone());
            }
            self.running = true;
            Ok(())
        }

        fn stop(&mut self) -> Result<(), String> {
            self.running = false;
            Ok(())
        }

        fn candidates(&self, maximum: usize) -> Vec<PeerCandidate> {
            self.values.iter().take(maximum).cloned().collect()
        }

        fn collect_candidates(&self, maximum: usize) -> Result<Vec<PeerCandidate>, String> {
            if let Some(error) = &self.collect_error {
                return Err(error.clone());
            }
            Ok(self.candidates(maximum))
        }

        fn publish(&self, _hint: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    fn candidate(id: u64, source: CandidateSource) -> PeerCandidate {
        PeerCandidate {
            candidate_id: id,
            carrier_type: "ump.tcp/1".into(),
            connection_hint: vec![127, 0, 0, 1],
            source,
            created_at: Instant(0),
            expires_at: Instant(1_000),
            sharing_policy: SharingPolicy::ShareGeneral,
            authentication: CandidateAuth::Unauthenticated,
            local: false,
        }
    }

    #[test]
    fn lifecycle_isolated_and_diversity_reported() {
        let mut manager = ProviderManager::with_policy(16, 8, 2);
        manager.register(Box::new(FakeProvider::new(
            CandidateSource::Static,
            vec![candidate(1, CandidateSource::Static)],
        )));
        manager.register(Box::new(FakeProvider::new(
            CandidateSource::PeerHint,
            vec![candidate(2, CandidateSource::PeerHint)],
        )));

        let started = manager.start_all();
        assert!(started
            .iter()
            .all(|report| report.state == ProviderState::Running));
        let refreshed = manager.refresh(Instant(10));
        assert_eq!(refreshed.admitted_candidates, 2);
        assert_eq!(refreshed.distinct_sources, 2);
        assert!(refreshed.diversity_satisfied);
        assert_eq!(manager.candidates().len(), 2);

        let stopped = manager.stop_all();
        assert!(stopped
            .iter()
            .all(|report| report.state == ProviderState::Stopped));
    }

    #[test]
    fn failed_provider_does_not_block_healthy_source() {
        let mut manager = ProviderManager::with_policy(16, 8, 2);
        let mut failed = FakeProvider::new(
            CandidateSource::LocalDiscovery,
            vec![candidate(1, CandidateSource::LocalDiscovery)],
        );
        failed.start_error = Some("permission denied".into());
        manager.register(Box::new(failed));
        manager.register(Box::new(FakeProvider::new(
            CandidateSource::Static,
            vec![candidate(2, CandidateSource::Static)],
        )));

        let started = manager.start_all();
        assert_eq!(started[0].state, ProviderState::Failed);
        assert_eq!(started[1].state, ProviderState::Running);
        let refreshed = manager.refresh(Instant(10));
        assert_eq!(refreshed.admitted_candidates, 1);
        assert_eq!(refreshed.distinct_sources, 1);
        assert!(!refreshed.diversity_satisfied);
        assert_eq!(
            refreshed.providers[0].error.as_deref(),
            Some("permission denied")
        );
    }

    #[test]
    fn mismatched_source_fails_provider_without_admitting_candidate() {
        let mut manager = ProviderManager::new(16);
        manager.register(Box::new(FakeProvider::new(
            CandidateSource::Static,
            vec![candidate(7, CandidateSource::PeerHint)],
        )));
        assert_eq!(manager.start_all()[0].state, ProviderState::Running);
        let report = manager.refresh(Instant(10));
        assert_eq!(report.admitted_candidates, 0);
        assert_eq!(report.providers[0].state, ProviderState::Failed);
        assert!(report.providers[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("disagrees")));
        assert!(manager.candidates().is_empty());
    }
}
