//! The observation half of a scan.
//!
//! Split out of `scan.rs` when the third source arrived. The walk and the report
//! assembly are one concern, reading what was observed and reconciling it
//! against the code is another, and the file that held both had stopped being
//! about one thing.
//!
//! Everything here is opt in and stays that way. A run with neither an event
//! directory nor a flow directory never builds a [`ReconciledStage`], so its
//! report comes out exactly as it did before any of this existed. That is not a
//! convenience: nearly every run of this tool is a plain static scan, and a
//! second source must not change what those runs say.
//!
//! The two directories are read the same way and for the same reason. `None` is
//! not an empty directory. An empty event directory means the hooks were
//! installed and the program made no calls; an empty flow directory means the
//! sensor watched and the machine stayed quiet. No directory at all means nobody
//! was watching, and only that one keeps `reconciliation_mode` from reading
//! `full`.

use std::path::Path;

use periskop_core::finding::{Finding, Kind};
use periskop_network_sensor::flow::Mechanism;
use periskop_network_sensor::Flow;
use periskop_reconcile::capability::Suppression;
use periskop_reconcile::settings::ReconcileSettings;
use periskop_reconcile::wire::WireCoverage;
use periskop_reconcile::{
    reconcile, DeclaredPoint, DeclaredSource, ObservationWindow, ReconcileInputs, RuntimeSource,
    Sources, WireSource,
};
use periskop_report::coverage::{ReconciliationMode, SensorPlatformClass};
use periskop_report::report::{Diagnostic, DiagnosticComponent};
use periskop_runtime_collector::ObservedWindow;

use super::internal_diagnostic;

/// What the report says when no hook stated how long it was watching.
///
/// Written out because it is the difference between two facts the coverage
/// statement cannot tell apart. `coverage.observation_window_ms` is an integer
/// with no absent value, so a run that measured nothing and a run that measured
/// zero both write `0` there; only this line says which happened, and the
/// dormancy suppression that follows it means the opposite thing in each case.
/// A field that can carry the difference is filed against the contract owner in
/// `hub/memory/interfaces.md`.
const WINDOW_NOT_MEASURED: &str =
    "observation window not measured: no hook stated how long it was watching, \
     so an unobserved call proves nothing";

/// What the report says when flows were read and nothing states the platform.
///
/// `sensor_platform_class` answers "was there a network sensor at all", and a
/// directory of records is not a machine. Only `ebpf` names a platform on its
/// own, because eBPF exists on one; a pcap capture could have been taken on any
/// of three, and guessing would put a capability into a report that nothing
/// backs. The gap is a wiring one rather than a contract one and is filed in
/// `hub/memory/interfaces.md`: a sensor run in the same process states its own
/// class, and a directory handed over after the fact does not.
const PLATFORM_NOT_STATED: &str =
    "sensor platform class not stated: the flow records name a capture mechanism \
     that does not identify a platform on its own, so the coverage statement \
     keeps none";

/// Where the observation sources are, if the caller has any.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanSources<'a> {
    /// Directory the runtime hook wrote its event stream into.
    pub event_dir: Option<&'a Path>,
    /// Directory holding the network sensor's flow records.
    pub flow_dir: Option<&'a Path>,
}

impl ScanSources<'_> {
    /// Whether anything at all was observed for this run.
    pub fn any(&self) -> bool {
        self.event_dir.is_some() || self.flow_dir.is_some()
    }
}

/// What the observation half of a run contributed.
///
/// Collected into one value rather than written into the report as it is
/// produced, so the static path cannot be reached by any of it.
pub(super) struct ReconciledStage {
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<Diagnostic>,
    pub dropped_events: u64,
    pub unlinked_events: u64,
    /// Observed calls whose destination the hook could not read. A coverage
    /// counter, and the reason an unexplained traffic claim in the same report
    /// may be stated as suspected rather than confirmed.
    pub unresolved_event_targets: u64,
    pub observation_window_ms: u64,
    pub reconciliation_mode: ReconciliationMode,
    /// The four buckets and the unclassified count, or `None` when no sensor fed
    /// the run. `None` and five zeros are different reports: the second says a
    /// sensor watched and saw nothing.
    pub wire: Option<WireCoverage>,
    pub sensor_platform_class: SensorPlatformClass,
}

/// Reads what was observed and reconciles it against the code side.
///
/// Returns a stage rather than a `Result` for the reason the collector states
/// one layer down: damaged records are data. A scan that abandoned its report
/// because one event line was truncated would hand any misbehaving hook the
/// power to blind the whole run, and the same is true of a sensor.
pub(super) fn run(
    sources: ScanSources<'_>,
    static_findings: &[Finding],
    settings: &ReconcileSettings,
) -> ReconciledStage {
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    let (runtime, dropped_events, window) = match sources.event_dir {
        Some(event_dir) => read_events(event_dir, &mut diagnostics),
        None => (RuntimeSource::Absent, 0, ObservationWindow::NONE),
    };
    let (wire, platform) = match sources.flow_dir {
        Some(flow_dir) => read_flows(flow_dir, &mut diagnostics),
        None => (WireSource::Absent, SensorPlatformClass::None),
    };

    let points = declared_points(static_findings, &mut diagnostics);
    let sources = Sources::new(DeclaredSource::Present(points), runtime, wire);
    let outcome = reconcile(&ReconcileInputs::new(sources, window).with_settings(settings.clone()));

    diagnostics.extend(outcome.suppressed.iter().map(suppression_diagnostic));
    // The engine disagreeing with itself, and the records it could not read. A
    // diagnostic, never a coverage counter: a derivation that failed is a
    // different thing from something the run could not see.
    diagnostics.extend(
        outcome
            .faults
            .iter()
            .map(|fault| internal_diagnostic(DiagnosticComponent::Reconciliation, fault.clone())),
    );
    // A rule that ran, produced nothing, and had a reason. Without these lines a
    // reader cannot tell a clean run from a run where one weak rung silenced
    // every accusation or no measurement allowed a single comparison
    // (`reconciliation/spec.md` §6: no class stays out of the report).
    diagnostics.extend(
        outcome.silences.iter().map(|silence| {
            internal_diagnostic(DiagnosticComponent::Reconciliation, silence.clone())
        }),
    );

    // Two parts of the outcome have no home in the report contract and are
    // therefore not written anywhere. `resolved_targets` is the destination an
    // observation supplied for a point the scanner could not read: dropping the
    // point from `coverage.unresolved_targets` on the strength of it would
    // delete a declared gap without recording what replaced it, since no field
    // carries the observed value. `matches` and `j1_matches` are the join
    // ladders, which the derived findings already carry in their own evidence.
    // Both are filed as contract requests in `hub/memory/interfaces.md` rather
    // than approximated here.
    ReconciledStage {
        findings: outcome.findings,
        diagnostics,
        dropped_events,
        unlinked_events: outcome.unlinked_events,
        unresolved_event_targets: outcome.unresolved_event_targets,
        observation_window_ms: outcome.observation_window_ms,
        reconciliation_mode: outcome.reconciliation_mode,
        wire: outcome.wire,
        sensor_platform_class: platform,
    }
}

/// Reads the hook's event stream, and how long it was watching.
fn read_events(
    event_dir: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) -> (RuntimeSource, u64, ObservationWindow) {
    let collected = periskop_runtime_collector::collect(event_dir);

    // Every line the collector could not read is named here. The count alone
    // reaches `dropped_events`, and a count with no location is a number nobody
    // can act on. Files it could not open at all raise no count, so without this
    // they would leave no trace anywhere.
    diagnostics.extend(collected.malformed.iter().map(|loss| {
        internal_diagnostic(
            DiagnosticComponent::RuntimeHooks,
            format!("event stream: {loss}"),
        )
    }));

    let window = observation_window(collected.window, diagnostics);
    (
        RuntimeSource::Present(collected.events),
        collected.dropped,
        window,
    )
}

/// Reads the sensor's flow records out of a directory.
///
/// Every file is read and every record is validated again, because a record read
/// back was written by a build that is not this one. A record this build rejects
/// is named rather than skipped: a contradictory flow is a loss like any other,
/// and a sensor whose output this build refuses would otherwise show up as a
/// quiet shortfall in the traffic nobody notices.
fn read_flows(
    flow_dir: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) -> (WireSource, SensorPlatformClass) {
    let mut names: Vec<std::path::PathBuf> = Vec::new();
    match std::fs::read_dir(flow_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                let is_record_file = path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension == "json" || extension == "jsonl");
                if is_record_file {
                    names.push(path);
                }
            }
        }
        Err(error) => {
            // The directory was there when the command resolved it. Failing to
            // read it now is a fact about the run, and reporting an absent
            // sensor instead would say nobody was watching.
            diagnostics.push(internal_diagnostic(
                DiagnosticComponent::NetworkSensor,
                format!("flow directory could not be read: {error}"),
            ));
            return (WireSource::Present(Vec::new()), SensorPlatformClass::None);
        }
    }
    // The order a directory hands its entries over in is not stable across
    // machines, and it decides nothing here, but the diagnostics it produces are
    // written in it.
    names.sort();

    let mut flows: Vec<Flow> = Vec::new();
    for path in &names {
        let name = file_name_of(path);
        match std::fs::read_to_string(path) {
            Ok(text) => read_records(&name, &text, &mut flows, diagnostics),
            Err(error) => diagnostics.push(internal_diagnostic(
                DiagnosticComponent::NetworkSensor,
                format!("flow record file {name} could not be read: {error}"),
            )),
        }
    }

    // Identity order, so two directories holding the same traffic under
    // different file names reconcile to the same bytes.
    flows.sort_by(|a, b| a.flow_id.cmp(&b.flow_id).then_with(|| a.cmp(b)));
    flows.dedup();

    let platform = platform_class(&flows, diagnostics);
    (WireSource::Present(flows), platform)
}

/// Reads one file's records, in whichever of the two shapes it holds.
///
/// The sensor writes one record per line, and that is the shape this expects. A
/// whole file holding one JSON value is accepted as well, because the contract
/// example is pretty printed and a record exported by hand is the ordinary way
/// somebody reproduces a report.
fn read_records(name: &str, text: &str, flows: &mut Vec<Flow>, diagnostics: &mut Vec<Diagnostic>) {
    if let Ok(whole) = serde_json::from_str::<Vec<Flow>>(text) {
        accept(name, 0, whole, flows, diagnostics);
        return;
    }
    if let Ok(single) = serde_json::from_str::<Flow>(text) {
        accept(name, 0, vec![single], flows, diagnostics);
        return;
    }
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Flow>(line) {
            Ok(flow) => accept(name, index + 1, vec![flow], flows, diagnostics),
            // The normal state of a file a live sensor is still appending to,
            // and the reason this is a count rather than a failure.
            Err(error) => diagnostics.push(internal_diagnostic(
                DiagnosticComponent::NetworkSensor,
                format!("flow record {name}:{} is unparsable: {error}", index + 1),
            )),
        }
    }
}

/// Keeps the records this build agrees with, and names the ones it does not.
fn accept(
    name: &str,
    line: usize,
    read: Vec<Flow>,
    flows: &mut Vec<Flow>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for flow in read {
        match flow.validate() {
            Ok(()) => flows.push(flow),
            // The reason label rather than the record: these are exactly the
            // records suspected of carrying something they should not, and a
            // diagnostic that quoted one would move the leak into the report.
            Err(error) => diagnostics.push(internal_diagnostic(
                DiagnosticComponent::NetworkSensor,
                format!("flow record {name}:{line} was refused: {}", error.reason()),
            )),
        }
    }
}

/// What the coverage statement may claim about the sensor behind these records.
///
/// Only eBPF names a platform on its own. A pcap capture could have come from
/// any of three, so a record that names it leaves the field at `none` and the
/// run says why; the alternative is a report promising an observation class
/// nothing on the machine backs.
fn platform_class(flows: &[Flow], diagnostics: &mut Vec<Diagnostic>) -> SensorPlatformClass {
    let mut kernel_capture = false;
    let mut unnameable = false;
    for flow in flows {
        match flow.mechanism {
            Mechanism::Ebpf => kernel_capture = true,
            Mechanism::Pcap | Mechanism::Etw => unnameable = true,
        }
    }

    if unnameable {
        diagnostics.push(internal_diagnostic(
            DiagnosticComponent::NetworkSensor,
            PLATFORM_NOT_STATED.to_owned(),
        ));
        return SensorPlatformClass::None;
    }
    if kernel_capture {
        SensorPlatformClass::LinuxEbpf
    } else {
        // An empty directory. The sensor watched and the machine stayed quiet,
        // which is a fact the flow counters carry; what no record can say is
        // which platform did the watching.
        SensorPlatformClass::None
    }
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("flow record")
        .to_owned()
}

/// What the hooks measured, in the vocabulary the reconciler takes.
///
/// The two answers are not two spellings of one thing. A measured window, zero
/// included, is a fact about the run: the hooks were watching, for that long. An
/// unmeasured one is the absence of that fact, and it arrives whenever a hook
/// died before it could flush its accounting, or was never installed at all.
///
/// Both reach the reconciler as a duration it can compare against the threshold,
/// because [`ObservationWindow`] has no third state, and an unmeasured window
/// therefore arrives as `NONE` and suppresses the dormancy claim exactly as a
/// zero one would. What must not also disappear is which of the two happened, so
/// the unmeasured case is written into the report before the value is flattened.
/// Without that line the reader sees `observation_window_ms: 0` and a dormancy
/// suppression, and cannot tell whether the hooks watched nothing or simply
/// never said. A third state on the reconciler's type is filed against its owner
/// in `hub/memory/interfaces.md`.
fn observation_window(
    observed: ObservedWindow,
    diagnostics: &mut Vec<Diagnostic>,
) -> ObservationWindow {
    match observed.duration_ms() {
        Some(duration_ms) => ObservationWindow::of_ms(duration_ms),
        None => {
            diagnostics.push(internal_diagnostic(
                DiagnosticComponent::RuntimeHooks,
                WINDOW_NOT_MEASURED.to_owned(),
            ));
            ObservationWindow::NONE
        }
    }
}

/// The code side of the join, read out of the findings the walk produced.
///
/// Suspected findings are included. A call site the scanner could not fully
/// prove is still a place in the code, and leaving it out would make it
/// invisible to reconciliation entirely; what it cannot do is strengthen a
/// derived claim, because a downgraded point carries no destination and the
/// drift rule has nothing to compare.
fn declared_points(findings: &[Finding], diagnostics: &mut Vec<Diagnostic>) -> Vec<DeclaredPoint> {
    findings
        .iter()
        .filter(|finding| finding.kind == Kind::DeclaredEgressPoint)
        .filter_map(|finding| match DeclaredPoint::from_finding(finding) {
            Ok(point) => Some(point),
            // A finding this build produced and cannot read back is the scanner
            // and the reconciler disagreeing about the contract between them.
            // Skipping it silently would drop a code point out of reconciliation
            // with nothing in the report to show it was ever there.
            Err(error) => {
                diagnostics.push(internal_diagnostic(
                    DiagnosticComponent::Reconciliation,
                    format!(
                        "{} could not be read as a code point: {error}",
                        finding.finding_id
                    ),
                ));
                None
            }
        })
        .collect()
}

/// A derived kind this run did not produce, written where a reader will find it.
///
/// The report has two places a statement like this can go and neither was built
/// for it. The coverage statement counts what the scan could not read and its
/// field list is closed, so a suppression has no counter there; `diagnostics[]`
/// is the block for everything the engine has to say about its own run, and its
/// `detail` field is free text. `INTERNAL` is the only code in the closed enum
/// not already claimed by a specific failure, so it is the one used, and the
/// detail carries the contract spelling of both the kind and the reason. A
/// dedicated code is filed against the contract owner in
/// `hub/memory/interfaces.md`; until it exists, this is the choice that loses
/// nothing.
fn suppression_diagnostic(suppression: &Suppression) -> Diagnostic {
    // Serialized rather than matched on, so a reason renamed in the contract
    // cannot leave this line reporting a vocabulary that no longer exists. The
    // fallback keeps the reason readable if it ever stops being a plain string.
    let reason = serde_json::to_value(suppression.reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{:?}", suppression.reason));

    internal_diagnostic(
        DiagnosticComponent::Reconciliation,
        format!(
            "not derived: {} ({reason})",
            suppression.kind.kind().as_str()
        ),
    )
}
