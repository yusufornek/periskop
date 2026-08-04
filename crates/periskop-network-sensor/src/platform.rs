//! Which observation class this build can offer on this machine.
//!
//! The value this module produces ends up in the coverage statement, where it
//! answers a question a reader will otherwise answer wrongly: was there a
//! network sensor at all? A report with no flows and no platform class reads
//! like a clean run. A report that says `none` reads like what it is, a run
//! with no network observation in it, and the two must never look alike.
//!
//! So the sensor never returns quietly empty off Linux. It declares `none` and
//! carries that declaration into the coverage statement.

use serde::{Deserialize, Serialize};

use crate::flow::Mechanism;

/// The observation class a report declares.
///
/// Spellings are fixed by `schemas/coverage-statement.schema.json`. All four
/// values exist here because the contract closes the list at four and this
/// crate is the producer of the field; two of them are not reachable in v1, and
/// [`detect`] is where that is stated rather than left to be inferred from an
/// absent branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorPlatformClass {
    LinuxEbpf,
    MacosPcap,
    WindowsPcapEtw,
    None,
}

impl SensorPlatformClass {
    /// Which capture mechanism this class writes into a record.
    ///
    /// `None` yields no mechanism, which is what keeps a record from being
    /// built at all when nothing was observed: the contract requires
    /// `mechanism` on every flow, so a class with no mechanism cannot produce
    /// one.
    pub fn mechanism(self) -> Option<Mechanism> {
        match self {
            Self::LinuxEbpf => Some(Mechanism::Ebpf),
            Self::MacosPcap => Some(Mechanism::Pcap),
            Self::WindowsPcapEtw => Some(Mechanism::Etw),
            Self::None => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxEbpf => "linux_ebpf",
            Self::MacosPcap => "macos_pcap",
            Self::WindowsPcapEtw => "windows_pcap_etw",
            Self::None => "none",
        }
    }
}

/// What this build can observe on the machine it is running on.
///
/// ADR-008 fixes the mechanism per platform, and its D-21e revision fixes the
/// delivery scope separately: v1 ships the Linux eBPF sensor only. The pcap
/// paths for macOS and Windows are decided but not built, so claiming
/// `macos_pcap` here would put a capability into a report that no code in this
/// workspace can honour. Off Linux the answer is `none`, and the missing
/// coverage is declared rather than left as an empty flow list.
pub fn detect() -> SensorPlatformClass {
    if cfg!(target_os = "linux") {
        SensorPlatformClass::LinuxEbpf
    } else {
        SensorPlatformClass::None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const COVERAGE_SCHEMA: &str = include_str!("../../../schemas/coverage-statement.schema.json");

    #[test]
    fn detection_matches_the_machine_it_runs_on() {
        let detected = detect();
        if cfg!(target_os = "linux") {
            assert_eq!(detected, SensorPlatformClass::LinuxEbpf);
        } else {
            // The point of the test: off Linux there is a value, and it says
            // there was no sensor. Returning nothing at all would leave a
            // reader to guess.
            assert_eq!(detected, SensorPlatformClass::None);
        }
    }

    #[test]
    fn v1_detection_never_claims_a_platform_this_build_cannot_observe() {
        // The pcap paths are decided by ADR-008 and not built. A report that
        // named one of them would promise observation nothing here performs.
        assert!(!matches!(
            detect(),
            SensorPlatformClass::MacosPcap | SensorPlatformClass::WindowsPcapEtw
        ));
    }

    #[test]
    fn a_class_without_observation_offers_no_mechanism() {
        assert_eq!(SensorPlatformClass::None.mechanism(), None);
        assert_eq!(
            SensorPlatformClass::LinuxEbpf.mechanism(),
            Some(Mechanism::Ebpf)
        );
        assert_eq!(
            SensorPlatformClass::MacosPcap.mechanism(),
            Some(Mechanism::Pcap)
        );
        assert_eq!(
            SensorPlatformClass::WindowsPcapEtw.mechanism(),
            Some(Mechanism::Etw)
        );
    }

    #[test]
    fn class_spellings_match_the_coverage_contract() {
        // A misspelling here is not a cosmetic defect: the validator rejects
        // the record, and the one line that says whether a sensor ran drops out
        // of the report entirely.
        let schema: serde_json::Value = serde_json::from_str(COVERAGE_SCHEMA).unwrap();
        let allowed: Vec<&str> = schema
            .pointer("/properties/sensor_platform_class/enum")
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();

        let written = [
            SensorPlatformClass::LinuxEbpf,
            SensorPlatformClass::MacosPcap,
            SensorPlatformClass::WindowsPcapEtw,
            SensorPlatformClass::None,
        ];
        for class in written {
            assert!(
                allowed.contains(&class.as_str()),
                "{class:?} is not in the contract"
            );
            assert_eq!(
                serde_json::to_value(class).unwrap(),
                serde_json::json!(class.as_str())
            );
        }
        assert_eq!(written.len(), allowed.len());
    }
}
