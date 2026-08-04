//! Flow identity derivation.
//!
//! A flow identity answers *which connection is this*, and nothing else may
//! enter it. In particular no raw clock value does: the sensor sees a connection
//! start at a microsecond, but two runs over the same traffic have to produce
//! byte identical reports, and a stamp that ticks would give every record a new
//! identity every time it was written. The bucketed start time is what survives
//! into the hash, for the same reason `periskop_core::ids` keeps line numbers
//! out of a finding identity.
//!
//! Volume, duration and classification stay out too. They describe the same
//! connection more or less completely depending on when the sensor started
//! watching; letting them move the identity would turn one connection into two
//! records and inflate a count that reconciliation reads as evidence.
//!
//! # The ephemeral source port, and why it is still in here
//!
//! `five_tuple.src_port` is part of the hash, and it is the one input that does
//! not describe the connection so much as the moment it was opened. The kernel
//! hands out an ephemeral port from a rotating range, so the same application
//! talking to the same provider gets a different one every run. The consequence
//! is concrete and costs the product something real: an `unmatched_wire_traffic`
//! finding cannot be followed across two runs. A reader who triages the finding
//! on Monday and re-runs the scan on Tuesday sees a new `flow_id` for the same
//! conversation and has no way to say it is the same one, so the finding cannot
//! be suppressed, tracked, or shown to have been fixed. This is asserted below
//! in `an_ephemeral_source_port_gives_one_conversation_a_new_identity_each_run`
//! rather than only described, so the cost stays measured.
//!
//! It stays in because the derivation is not this crate's to change. The formula
//! is fixed by `docs/04-contracts/flow-schema.md` and `data-model.md` §2, both
//! contract documents, and a sensor that hashed a different field list would
//! write records the rest of the system reads under a formula nobody agreed to.
//! Two runs of *this* build would still agree with each other, which is exactly
//! how a silent divergence hides. The alternative is not free either: without
//! the port, two connections opened to one destination inside one bucket collapse
//! into a single identity, and the volume of one would be attributed to both. So
//! the choice is between tracking across runs and separating concurrent
//! connections, which is a contract decision with a real trade in it.
//!
//! The request is filed in `hub/memory/interfaces.md` against the owner of the
//! two contract documents. Until it is answered this build follows the contract.

use periskop_core::ids::{short_hash, FlowId};

use crate::flow::FiveTuple;

/// Domain tag for the flow identity space.
///
/// Keeps flow identities apart from point and event identities that might
/// otherwise be derived from overlapping host strings.
const ID_DOMAIN_TAG: &str = "fl/v1";

/// Renders the connection key as one unambiguous string.
///
/// The separator is `/`, which cannot appear in any of the four parts: ports
/// are decimal digits, the protocol is a lower case word, and an address is
/// dotted quad or colon separated hex. So no two different tuples can render
/// the same way.
pub fn canonical_five_tuple(five_tuple: &FiveTuple) -> String {
    format!(
        "{}/{}/{}/{}",
        five_tuple.src_port,
        five_tuple.dst_ip,
        five_tuple.dst_port,
        five_tuple.proto.as_str()
    )
}

/// Derives the identity the contract fixes.
///
/// An absent boot id hashes as the empty string. The field count is fixed at
/// four and `short_hash` separates the fields, so the boundary stays
/// unambiguous; a machine that cannot report a boot id simply loses the
/// protection boot id gives against a host id being reused across reboots.
pub fn derive_flow_id(
    host_id: &str,
    boot_id: Option<&str>,
    five_tuple: &FiveTuple,
    t_start_bucket: u64,
) -> Result<FlowId, periskop_core::Error> {
    let connection = canonical_five_tuple(five_tuple);
    let bucket = t_start_bucket.to_string();
    let hash = short_hash(
        ID_DOMAIN_TAG,
        &[host_id, boot_id.unwrap_or(""), &connection, &bucket],
    );
    FlowId::from_short_hash(&hash)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::tests::{five_tuple, full_observation};
    use crate::flow::{Flow, Mechanism};
    use crate::flow::{Proto, SniSource};
    use crate::observation::Observation;
    use crate::scope::FlowScope;

    fn id(host: &str, boot: Option<&str>, tuple: &FiveTuple, bucket: u64) -> String {
        derive_flow_id(host, boot, tuple, bucket)
            .unwrap()
            .to_string()
    }

    #[test]
    fn derivation_is_stable_across_calls() {
        let tuple = five_tuple();
        assert_eq!(
            id("h_1", Some("b_1"), &tuple, 1_785_834_000),
            id("h_1", Some("b_1"), &tuple, 1_785_834_000)
        );
    }

    #[test]
    fn rendered_id_matches_the_contract_pattern() {
        let rendered = id("h_1", None, &five_tuple(), 1);
        assert!(rendered.starts_with("fl_"));
        assert_eq!(rendered.len(), "fl_".len() + 16);
        assert!(rendered["fl_".len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn every_part_of_the_connection_key_moves_the_identity() {
        let base = five_tuple();
        let baseline = id("h_1", Some("b_1"), &base, 10);

        let mut other_port = base.clone();
        other_port.dst_port = 8443;
        let mut other_src = base.clone();
        other_src.src_port = 1234;
        let mut other_ip = base.clone();
        other_ip.dst_ip = "104.18.7.2".to_owned();
        let mut other_proto = base.clone();
        other_proto.proto = Proto::Udp;

        for changed in [other_port, other_src, other_ip, other_proto] {
            assert_ne!(baseline, id("h_1", Some("b_1"), &changed, 10));
        }
        assert_ne!(baseline, id("h_2", Some("b_1"), &base, 10));
        assert_ne!(baseline, id("h_1", Some("b_2"), &base, 10));
        assert_ne!(baseline, id("h_1", None, &base, 10));
        assert_ne!(baseline, id("h_1", Some("b_1"), &base, 11));
    }

    #[test]
    fn an_ephemeral_source_port_gives_one_conversation_a_new_identity_each_run() {
        // Critic round O3, measured rather than described. One application, one
        // provider, one machine, two runs: the kernel hands out a different
        // ephemeral port each time and the identity moves with it, so a wire
        // finding raised on Monday cannot be recognised on Tuesday. It cannot be
        // suppressed, tracked, or shown to have been fixed.
        //
        // The assertion is `ne` because that is what this build does and what
        // the contract says it must do. It is written as a named cost rather
        // than folded into `every_part_of_the_connection_key_moves_the_identity`
        // so that the day the contract changes, this test fails and says which
        // property was traded away, instead of a line quietly disappearing from
        // a loop over four fields.
        let monday = FiveTuple {
            src_port: 54_321,
            ..five_tuple()
        };
        let tuesday = FiveTuple {
            src_port: 41_007,
            ..five_tuple()
        };
        assert_eq!(monday.dst_ip, tuesday.dst_ip);
        assert_eq!(monday.dst_port, tuesday.dst_port);
        assert_ne!(
            id("h_1", Some("b_1"), &monday, 1_785_834_000),
            id("h_1", Some("b_1"), &tuesday, 1_785_834_000),
            "the same conversation kept its identity across an ephemeral port change, \
             so the contract's derivation has changed and the trade in the module \
             documentation needs revisiting"
        );
    }

    #[test]
    fn connection_key_boundaries_are_not_ambiguous() {
        // Without a separator that cannot occur inside a part, port 4 to
        // 43.0.0.1 and port 44 to 3.0.0.1 would render the same way and two
        // unrelated connections would share an identity.
        let a = FiveTuple {
            src_port: 4,
            dst_ip: "43.0.0.1".to_owned(),
            dst_port: 443,
            proto: Proto::Tcp,
        };
        let b = FiveTuple {
            src_port: 44,
            dst_ip: "3.0.0.1".to_owned(),
            dst_port: 443,
            proto: Proto::Tcp,
        };
        assert_ne!(canonical_five_tuple(&a), canonical_five_tuple(&b));
        assert_ne!(id("h", None, &a, 1), id("h", None, &b, 1));
    }

    #[test]
    fn identity_ignores_everything_that_is_not_the_connection() {
        // The same connection, observed twice: once completely, once seeded
        // from /proc after the sensor restarted so the volume is a lower bound
        // and the classification never resolved. One connection, one identity.
        let complete =
            Flow::from_observation(full_observation(), FlowScope::InScope, Mechanism::Ebpf)
                .unwrap();

        let partial = Observation::new(
            "h_9f2c4a17be0d5386",
            1_785_834_000,
            five_tuple(),
            SniSource::Absent,
        )
        .with_boot_id("b_3f0a91c7d4e28b56")
        .with_netns("4026531840")
        .with_duration_ms(1)
        .with_volume(1, 1)
        .degraded(vec![crate::flow::DegradedReason::PreExistingConnection]);
        let partial =
            Flow::from_observation(partial, FlowScope::Undetermined, Mechanism::Ebpf).unwrap();

        assert_eq!(complete.flow_id, partial.flow_id);
    }

    #[test]
    fn no_field_in_the_record_carries_a_raw_clock() {
        // t_start_bucket is a bucket by contract and pid_start_time guards pid
        // reuse; neither is a wall clock stamp. Anything that reads like one
        // would make a report differ from yesterday's on nothing.
        let json = serde_json::to_value(
            Flow::from_observation(full_observation(), FlowScope::InScope, Mechanism::Ebpf)
                .unwrap(),
        )
        .unwrap();
        let mut keys = Vec::new();
        collect_keys(&json, &mut keys);
        for key in keys {
            for banned in ["timestamp", "_us", "_ns", "monotonic", "epoch", "wall"] {
                assert!(!key.contains(banned), "{key} carries a clock value");
            }
        }
    }

    fn collect_keys(value: &serde_json::Value, into: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    into.push(key.clone());
                    collect_keys(child, into);
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    collect_keys(child, into);
                }
            }
            _ => {}
        }
    }
}
