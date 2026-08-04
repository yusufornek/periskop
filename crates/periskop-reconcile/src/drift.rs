//! `target_drift`: the code names one destination and the call reached another.
//!
//! The causes range from ordinary to serious and the finding does not choose
//! between them: an environment variable pointing at a gateway, a regional
//! endpoint, a proxy in the path, a misconfiguration, or a redirection nobody
//! intended. What they have in common is that reading the source would not have
//! revealed any of them, which is the whole reason two sources are being
//! compared.
//!
//! Three cases are explicitly not a drift, and each is a way of not knowing
//! that must not be spelled like knowing something else.
//!
//! When the scanner could not resolve the destination, the code declared
//! nothing to drift from, and reporting one would turn a gap in static analysis
//! into a claim about the system. What that case produces instead is an
//! enrichment: the observation supplies the destination the scanner could not
//! read, and the run says so where the coverage statement can pick it up.
//!
//! When the hook could not read where the call went, the observation side is the
//! one that established nothing. That case is handled before this module sees
//! it, in [`crate::join`]: such a record carries no destination at all, so there
//! is nothing here for a comparison to differ from.
//!
//! And when the only thing tying an observation to a code point is that both
//! name the same vendor, the call may have come from any other line reaching
//! that vendor. Comparing its destination against this line's would report a
//! drift for code that reached exactly what it declared, on the strength of
//! traffic it never produced.

use std::collections::BTreeSet;

use periskop_core::finding::{Confidence, Evidence, Finding, Kind};

use crate::declared::DeclaredPoint;
use crate::emit;
use crate::join::{J2Match, JoinResult};
use crate::outcome::ResolvedTarget;
use crate::settings::ReconcileSettings;
use crate::target::TargetId;

pub(crate) const RULE_ID: &str = "any.reconciled.target-drift";

/// How the destination that was reached differs from the one that was written.
///
/// Named because the reader acts on the difference: a regional subdomain is a
/// deployment question, a bare address is a question about what resolved it, and
/// another provider entirely is a question about where the data went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DriftKind {
    /// The call reached an address rather than a name.
    AddressLiteral,
    /// The same host on a different port.
    Port,
    /// One name sits under the other.
    Subdomain,
    /// An unrelated host.
    Host,
}

impl DriftKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::AddressLiteral => "address_literal",
            Self::Port => "port",
            Self::Subdomain => "subdomain",
            Self::Host => "host",
        }
    }

    fn of(declared: &TargetId, observed: &TargetId) -> Self {
        if observed.is_address_literal() && !declared.is_address_literal() {
            return Self::AddressLiteral;
        }
        if declared.host() == observed.host() {
            return Self::Port;
        }
        if declared.shares_name_with(observed) {
            return Self::Subdomain;
        }
        Self::Host
    }
}

#[derive(Debug, Default)]
pub(crate) struct Derived {
    pub findings: Vec<Finding>,
    /// Destinations an observation supplied for a point the scanner could not
    /// resolve. Not findings: nothing is wrong, something became known.
    pub resolved_targets: Vec<ResolvedTarget>,
    pub faults: Vec<String>,
}

/// Derives one finding per code point whose calls went somewhere else.
///
/// One finding per point rather than one per call. The identity of a derived
/// finding is anchored on the code point, so a point reaching three unexpected
/// destinations is one claim with three pieces of evidence; emitting three
/// findings would give them one identity between them and the report would keep
/// whichever survived deduplication.
pub(crate) fn derive(
    points: &[DeclaredPoint],
    join: &JoinResult,
    settings: &ReconcileSettings,
) -> Derived {
    let mut derived = Derived::default();

    for point in points {
        match point.target() {
            Some(declared) => drift_for(point, declared, join, settings, &mut derived),
            None => collect_resolved(point, join, &mut derived),
        }
    }

    derived.resolved_targets.sort();
    derived.resolved_targets.dedup();
    derived
}

fn drift_for(
    point: &DeclaredPoint,
    declared: &TargetId,
    join: &JoinResult,
    settings: &ReconcileSettings,
    derived: &mut Derived,
) {
    let drifting: Vec<&J2Match> = join
        .matches_for(point.egress_point_id())
        // Only a link that places the call at this point may accuse it. Without
        // this, a second module calling the same vendor at a regional endpoint
        // attaches itself to this line through the provider, and the report
        // states that code which reached exactly what it declared drifted
        // somewhere it never went.
        .filter(|m| m.tier.attributes_a_call())
        .filter(|m| m.observed_target.as_ref().is_some_and(|t| t != declared))
        .collect();
    if drifting.is_empty() {
        return;
    }

    // Deduplicated by destination: a point called a thousand times through one
    // gateway is one drift, and §6 of the spec asks for exactly that collapse.
    let mut details: BTreeSet<String> = BTreeSet::new();
    let mut event_ids: BTreeSet<String> = BTreeSet::new();
    for matched in &drifting {
        event_ids.insert(matched.egress_event_id.clone());
        if let Some(observed) = &matched.observed_target {
            details.insert(format!(
                "J2:{} declared={declared} observed={observed} drift={}",
                matched.tier.as_str(),
                DriftKind::of(declared, observed).as_str()
            ));
        }
    }

    let evidence: Vec<Evidence> = details.into_iter().map(emit::join_evidence).collect();
    // Every finding is built with one piece of evidence and the rest are
    // attached afterwards. The set above is already ordered, so which one leads
    // does not depend on anything the sources controlled.
    let Some((lead, rest)) = evidence.split_first() else {
        derived.faults.push(format!(
            "target drift derivation found no comparable destination for {}",
            point.egress_point_id()
        ));
        return;
    };

    // Every surviving link places the call at this point, because the filter
    // above admitted no other kind, so the claim rests on evidence that carries
    // it. The alternative considered and rejected was to keep the weaker links
    // and emit them as suspected drifts: a suspected finding is still a finding
    // in the report, and one that says a call went somewhere it did not is the
    // most expensive thing this tool can print.
    match emit::derived_finding(
        Kind::TargetDrift,
        Confidence::Confirmed,
        point.provider_ref(),
        point.egress_point_id(),
        lead.clone(),
        settings,
        RULE_ID,
    ) {
        Ok(finding) => {
            let mut finding = finding
                .with_location(emit::code_location(point.path()))
                .with_coverage_impact(periskop_core::finding::CoverageImpact::None);
            if let Some(kind) = point.egress_kind() {
                finding = finding.with_egress_kind(kind);
            }
            emit::attach_evidence(&mut finding, rest.to_vec());
            emit::attach_event_refs(&mut finding, &event_ids.into_iter().collect::<Vec<_>>());
            derived.findings.push(finding);
        }
        Err(error) => derived.faults.push(format!(
            "target drift derivation could not build a finding for {}: {error}",
            point.egress_point_id()
        )),
    }
}

/// Records the destinations observation supplied for an unresolved point.
///
/// Filtered by the same rule the accusation above is, because an enrichment is
/// a claim too: it says this line reaches that destination, and a reader who
/// sees the point leave the unresolved list will act on it. A provider level
/// tie would resolve every unread call site in the repository to whatever host
/// that vendor's busiest call happened to reach.
fn collect_resolved(point: &DeclaredPoint, join: &JoinResult, derived: &mut Derived) {
    for matched in join
        .matches_for(point.egress_point_id())
        .filter(|m| m.tier.attributes_a_call())
    {
        if let Some(observed) = &matched.observed_target {
            derived.resolved_targets.push(ResolvedTarget {
                egress_point_id: point.egress_point_id().to_owned(),
                observed_target: observed.clone(),
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::declared::tests::{point, point_without_operation, unresolved_point};
    use crate::join::{
        join,
        tests::{event, event_with_unresolved_target},
    };
    use periskop_runtime_collector::EgressEvent;

    const EP: &str = "ep_3f0a91c7d4e28b56";

    fn derive_with(points: &[DeclaredPoint], events: &[EgressEvent]) -> Derived {
        let result = join(points, events);
        derive(points, &result, &ReconcileSettings::default())
    }

    fn evidence_of(derived: &Derived) -> String {
        derived.findings[0]
            .evidence
            .iter()
            .map(|e| e.r#ref.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    #[test]
    fn a_call_that_went_elsewhere_is_reported_against_the_code_that_declared_it() {
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [event(
            "openai",
            "chat.completions.create",
            "llm-gateway.internal",
            "unknown",
        )];
        let derived = derive_with(&points, &events);

        assert_eq!(derived.findings.len(), 1);
        assert_eq!(derived.findings[0].kind, Kind::TargetDrift);
        assert_eq!(derived.findings[0].confidence, Confidence::Confirmed);
        let evidence = evidence_of(&derived);
        assert!(evidence.contains("declared=api.openai.com"), "{evidence}");
        assert!(
            evidence.contains("observed=llm-gateway.internal"),
            "{evidence}"
        );
        assert!(evidence.contains("drift=host"), "{evidence}");
    }

    #[test]
    fn a_call_that_went_where_the_code_said_produces_nothing() {
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        )];
        assert!(derive_with(&points, &events).findings.is_empty());
    }

    #[test]
    fn a_spelling_difference_is_not_a_drift() {
        // The normalisation earning its keep: a trailing dot, an upper case
        // letter and an explicit default port are the same destination.
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [event(
            "openai",
            "chat.completions.create",
            "API.OpenAI.com.",
            "openai",
        )];
        assert!(derive_with(&points, &events).findings.is_empty());
    }

    #[test]
    fn the_kind_of_difference_is_named() {
        let cases = [
            ("eu.api.openai.com", "drift=subdomain"),
            ("10.2.3.4", "drift=address_literal"),
            ("api.anthropic.com", "drift=host"),
        ];
        for (observed, expected) in cases {
            let points = [point(EP, "api.openai.com", "chat.completions.create")];
            let events = [event(
                "openai",
                "chat.completions.create",
                observed,
                "openai",
            )];
            let derived = derive_with(&points, &events);
            assert!(evidence_of(&derived).contains(expected), "{observed}");
        }
    }

    #[test]
    fn an_unresolved_declaration_is_enriched_rather_than_accused() {
        // The scanner could not read the destination. Reporting a drift here
        // would turn a gap in static analysis into a claim about the code.
        let points = [unresolved_point(EP, "openai").with_operation("chat.completions.create")];
        let events = [event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        )];
        let derived = derive_with(&points, &events);

        assert!(derived.findings.is_empty());
        assert_eq!(derived.resolved_targets.len(), 1);
        assert_eq!(
            derived.resolved_targets[0].observed_target.host(),
            "api.openai.com"
        );
    }

    #[test]
    fn a_provider_level_tie_does_not_resolve_a_destination_either() {
        // The quiet half of the same mistake. Nothing ties this call to this
        // line but the vendor, and letting it fill the destination in would
        // drop the point off the unresolved list on a guess: every unread call
        // site for that vendor would resolve to the same host.
        let points = [unresolved_point(EP, "openai").with_operation("embeddings.create")];
        let events = [event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        )];
        let derived = derive_with(&points, &events);

        assert!(derived.findings.is_empty());
        assert!(
            derived.resolved_targets.is_empty(),
            "{:?}",
            derived.resolved_targets
        );
    }

    #[test]
    fn a_provider_level_tie_produces_no_drift_at_all() {
        // Two modules, one vendor. This line calls the endpoint it declared and
        // a different line calls a regional one; the only thing joining the
        // second call to this point is the vendor name. Reporting it, even as a
        // suspicion, accuses code that did exactly what it said it would.
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [event(
            "openai",
            "embeddings.create",
            "eu.api.openai.com",
            "openai",
        )];
        let derived = derive_with(&points, &events);

        assert!(derived.findings.is_empty(), "{:?}", derived.findings);
        assert!(derived.faults.is_empty());
    }

    #[test]
    fn escape_a_point_that_names_no_operation_cannot_establish_a_drift() {
        // The known escape of this rule, and the price of refusing the weakest
        // rung. The destination is the only key such a point carries, and a
        // drift is precisely the case where the destination differs, so the
        // pair falls to the provider rung and no drift is stated. Catalogued as
        // KG-016 rather than closed by weakening the rule: a suspected drift
        // for every call a vendor received would cost more readers than this
        // silence does. The static side closes it by naming the operation,
        // which contract 1.1 lets it do.
        let points = [point_without_operation(EP, "api.openai.com")];
        let events = [event(
            "openai",
            "chat.completions.create",
            "llm-gateway.internal",
            "openai",
        )];
        let derived = derive_with(&points, &events);

        assert!(derived.findings.is_empty());
        assert!(derived.faults.is_empty());
    }

    #[test]
    fn a_destination_the_hook_could_not_read_is_not_a_drift() {
        // The sentinel a hook writes when it cannot see where a call went. It
        // is not a host, and treating it as one turns "I could not observe
        // this" into a confirmed claim that the call reached somewhere other
        // than the code says. A security reader opens an incident on that line.
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [event_with_unresolved_target(
            "chat.completions.create",
            "openai",
        )];
        let derived = derive_with(&points, &events);

        assert!(
            derived.findings.is_empty(),
            "an unobservable destination is a gap, not a drift: {:?}",
            derived.findings
        );
        assert!(derived.faults.is_empty());
    }

    #[test]
    fn an_unreadable_destination_does_not_resolve_an_unread_declaration_either() {
        // Neither side knows where the call went. The point stays unresolved,
        // which is the only honest outcome, rather than being resolved to a
        // word.
        let points = [unresolved_point(EP, "openai").with_operation("chat.completions.create")];
        let events = [event_with_unresolved_target(
            "chat.completions.create",
            "openai",
        )];
        let derived = derive_with(&points, &events);

        assert!(derived.findings.is_empty());
        assert!(derived.resolved_targets.is_empty());
    }

    #[test]
    fn one_point_reaching_several_destinations_stays_one_finding() {
        // Both calls invoke the operation this point invokes, which is the rung
        // that places them here. Two regions, one line of code, one claim.
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [
            event(
                "openai",
                "chat.completions.create",
                "eu.api.openai.com",
                "openai",
            ),
            event(
                "openai",
                "chat.completions.create",
                "us.api.openai.com",
                "openai",
            ),
        ];
        let derived = derive_with(&points, &events);

        assert_eq!(derived.findings.len(), 1);
        assert_eq!(derived.findings[0].evidence.len(), 2);
        // Both observations are referenced, and the code point still leads.
        assert_eq!(derived.findings[0].refs.len(), 3);
        assert_eq!(
            derived.findings[0].refs[0].ref_type,
            periskop_core::finding::RefType::EgressPoint
        );
    }

    /// The pipeline, end to end, with nothing hand built on the code side.
    ///
    /// Every other test in this module starts from a `DeclaredPoint` a test
    /// helper filled in. That is exactly how this component passed its tests for
    /// a whole phase while being unable to produce a single finding in a real
    /// run: the two fields the join compares were read by the scanner and
    /// dropped before its output, so a caller had to supply them and in a real
    /// run no caller could.
    ///
    /// So this one starts at Python source and the rule files as shipped, runs
    /// the real detector, and hands the resulting `Finding` to
    /// `DeclaredPoint::from_finding` and nothing else. If either field stops
    /// reaching the contract, this test fails and no other one does.
    mod pipeline {
        use super::*;
        use periskop_core::finding::Kind;
        use periskop_static_scanner::engine::detect;
        use periskop_static_scanner::language::Language;
        use periskop_static_scanner::parser::parse_as;
        use periskop_static_scanner::rules::{compile, load_directory};

        /// A client pointed at the vendor, and a call through it. The base url
        /// is written out because that is the case where the code states a
        /// destination at all; with the library default the scanner has nothing
        /// to state and drift cannot be claimed.
        const SOURCE: &str = r#"
from openai import OpenAI

client = OpenAI(base_url="https://api.openai.com/v1")


def summarize(record):
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": record}],
    )
"#;

        /// A raw HTTP call to a provider endpoint, no SDK involved. Kept
        /// separate because it exercises the other operation spelling: a hook
        /// sitting at the transport records `http.post`, and the code side has
        /// to reproduce that or the two never meet.
        const RAW_HTTP_SOURCE: &str = r#"
import requests


def summarize(record, token):
    return requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": token},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": record}]},
    )
"#;

        fn scanned_points() -> Vec<DeclaredPoint> {
            points_from(SOURCE)
        }

        fn points_from(source: &str) -> Vec<DeclaredPoint> {
            let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
            let (rules, errors) = load_directory(&rules_dir);
            assert!(errors.is_empty(), "rule load failed: {errors:?}");
            let python: Vec<_> = rules
                .into_iter()
                .filter(|r| r.language == "python")
                .collect();
            let compiled = match compile(Language::Python, &python) {
                Ok(compiled) => compiled,
                Err(error) => unreachable!("shipped rules did not compile: {error}"),
            };
            let parsed = match parse_as("services/customer.py", source, Language::Python) {
                Ok(parsed) => parsed,
                Err(error) => unreachable!("fixture did not parse: {error}"),
            };

            let scanned = detect(&parsed, &compiled, &python);
            assert!(
                scanned.engine_faults.is_empty(),
                "engine faults: {:?}",
                scanned.engine_faults
            );
            scanned
                .findings
                .iter()
                .filter(|finding| finding.kind == Kind::DeclaredEgressPoint)
                .map(|finding| DeclaredPoint::from_finding(finding).unwrap())
                .collect()
        }

        #[test]
        fn the_scanner_alone_supplies_both_keys_the_join_compares() {
            let points = scanned_points();
            let point = points
                .iter()
                .find(|point| point.provider_ref() == "openai")
                .unwrap();

            assert_eq!(point.target().map(TargetId::host), Some("api.openai.com"));
            assert_eq!(point.operation(), Some("chat.completions.create"));
        }

        #[test]
        fn a_call_the_scanner_found_and_a_gateway_it_reached_produce_a_target_drift() {
            // The event is spelled as the Python hook spells it, because the
            // whole join rests on the two sides agreeing on one operation name.
            let points = scanned_points();
            let events = [event(
                "openai",
                "chat.completions.create",
                "llm-gateway.internal",
                "unknown",
            )];

            let result = join(&points, &events);
            let derived = derive(&points, &result, &ReconcileSettings::default());

            let drifts: Vec<&Finding> = derived
                .findings
                .iter()
                .filter(|finding| finding.kind == Kind::TargetDrift)
                .collect();
            assert_eq!(drifts.len(), 1, "{:?}", derived.faults);
            assert_eq!(drifts[0].confidence, Confidence::Confirmed);

            let evidence: String = drifts[0]
                .evidence
                .iter()
                .map(|piece| piece.r#ref.clone())
                .collect::<Vec<_>>()
                .join(" | ");
            assert!(evidence.contains("declared=api.openai.com"), "{evidence}");
            assert!(
                evidence.contains("observed=llm-gateway.internal"),
                "{evidence}"
            );
            assert!(evidence.contains("drift=host"), "{evidence}");
        }

        #[test]
        fn a_raw_http_call_is_spelled_the_way_the_transport_hook_spells_it() {
            // The literal endpoint gives the destination and the verb gives the
            // operation. If the code side said `post` while the hook said
            // `http.post`, the two would only ever meet through the provider,
            // and this rule reports provider unknown.
            let points = points_from(RAW_HTTP_SOURCE);
            let point = points.first().unwrap();

            assert_eq!(point.target().map(TargetId::host), Some("api.openai.com"));
            assert_eq!(point.operation(), Some("http.post"));

            let events = [event(
                "requests",
                "http.post",
                "llm-gateway.internal",
                "unknown",
            )];
            let result = join(&points, &events);
            let derived = derive(&points, &result, &ReconcileSettings::default());

            let drifts: Vec<&Finding> = derived
                .findings
                .iter()
                .filter(|finding| finding.kind == Kind::TargetDrift)
                .collect();
            assert_eq!(drifts.len(), 1, "{:?}", derived.faults);
        }

        #[test]
        fn a_call_that_reached_what_the_code_named_produces_no_drift() {
            // The negative half. Without it the test above would still pass if
            // the deriver reported a drift for every matched call.
            let points = scanned_points();
            let events = [event(
                "openai",
                "chat.completions.create",
                "api.openai.com",
                "openai",
            )];

            let result = join(&points, &events);
            let derived = derive(&points, &result, &ReconcileSettings::default());
            assert!(derived
                .findings
                .iter()
                .all(|finding| finding.kind != Kind::TargetDrift));
        }
    }

    #[test]
    fn the_finding_does_not_depend_on_the_order_the_calls_arrived_in() {
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let one = event(
            "openai",
            "chat.completions.create",
            "eu.api.openai.com",
            "openai",
        );
        let other = event(
            "openai",
            "chat.completions.create",
            "us.api.openai.com",
            "openai",
        );

        let forward = derive_with(&points, &[one.clone(), other.clone()]);
        let backward = derive_with(&points, &[other, one]);

        // Both orders produce the finding, so the equality below is an
        // agreement rather than two empty lists comparing equal.
        assert_eq!(forward.findings.len(), 1);
        assert_eq!(forward.findings, backward.findings);
    }
}
