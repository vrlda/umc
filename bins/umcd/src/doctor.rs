//! umc doctor checks (core.md §43): keystore health, database health,
//! carrier availability, clock anomalies, port conflicts.
use crate::config::NodeConfig;
use umc_storage::sqlite::{SqliteStore, SCHEMA_VERSION};

pub struct DoctorReport {
    pub checks: Vec<Check>,
}

pub struct Check {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

pub fn run_doctor(config: &NodeConfig) -> DoctorReport {
    let mut checks = Vec::new();

    // Database health.
    let data_dir = config.resolved_data_dir();
    match SqliteStore::open(&data_dir.join("node.db")) {
        Ok(store) => match store.schema_version() {
            Ok(v) if v == SCHEMA_VERSION => {
                checks.push(Check {
                    name: "database",
                    passed: true,
                    detail: format!("schema v{v}"),
                });
            }
            Ok(v) => {
                checks.push(Check {
                    name: "database",
                    passed: false,
                    detail: format!("schema v{v}, expected {SCHEMA_VERSION}"),
                });
            }
            Err(e) => checks.push(Check {
                name: "database",
                passed: false,
                detail: format!("{e:?}"),
            }),
        },
        Err(e) => checks.push(Check {
            name: "database",
            passed: false,
            detail: format!("{e:?}"),
        }),
    }

    // Keystore presence.
    let keystore_dir = data_dir.join("keystore");
    checks.push(Check {
        name: "keystore",
        passed: keystore_dir.exists(),
        detail: if keystore_dir.exists() {
            "present".into()
        } else {
            "missing".into()
        },
    });

    // Clock sanity: reject obviously wrong wall-clock (skew > 5 minutes is
    // tolerated by handshake.md §49; flag > 1 day).
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    let plausible = now_ms > 1_700_000_000_000 && now_ms < 1_900_000_000_000;
    checks.push(Check {
        name: "clock",
        passed: plausible,
        detail: if plausible {
            "plausible".into()
        } else {
            "implausible wall clock".into()
        },
    });

    // Carrier availability is a runtime check; report config only.
    checks.push(Check {
        name: "carriers",
        passed: !config.carriers.is_empty(),
        detail: config.carriers.join(", "),
    });

    DoctorReport { checks }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_reports_every_check() {
        // A data dir that does not exist: the keystore check must fail.
        let dir = std::env::temp_dir().join(format!("umcd-doctor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = NodeConfig {
            data_dir: dir,
            ..NodeConfig::default()
        };
        let report = run_doctor(&config);
        assert!(report.checks.iter().any(|c| c.name == "database"));
        assert!(report.checks.iter().any(|c| c.name == "clock"));
        assert!(report.checks.iter().any(|c| c.name == "carriers"));
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "keystore" && !c.passed));
    }
}
