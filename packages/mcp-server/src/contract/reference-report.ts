// The report the tool surface is derived over.
//
// The contract gate has to see real answers, and a real answer needs a report to
// be an answer about. Running the engine here would tie the document to whatever
// tree the gate happened to run in: a repository with no reconciled finding
// produces no reconciliation trace, and the gate would then report the working
// directory rather than the contract.
//
// So the input is fixed and the output is not. Every value below is what an
// engine writes, valid against `schemas/finding.schema.json` down to the
// identity format, and nothing here describes a response. The responses are
// produced by running the handlers over this, which is what makes the document a
// derivation rather than a second copy of the contract.
//
// It is deliberately a report with something in every branch: two confidence
// lists, more than one provider, a provider that appears only in the suspected
// list, a reconciled finding with a join path under it, and a coverage statement
// naming all three sources. A fixture with fewer of those leaves parts of the
// surface unexercised, and an unexercised field is one the gate cannot check.

/** A 64 hex digest standing in for a rule hash. */
const RULE_HASH = "3b7d1e5f8a06c249de3f1b04a7c95d6e2f8013b4ca67d95e08f31a2b7c4d6e50";
/** A second one, so two detectors are not indistinguishable in the document. */
const JOIN_RULE_HASH = "9f2c4a17be0d5386ca71fd90e4b2385c6710dd42fa9b0c3e75184d6a2fb03c9e";

/**
 * A recorded scan report.
 *
 * Returned fresh on every call rather than shared: the detail tool hands the
 * engine's own finding object back to the caller, so a shared literal would let
 * one derivation mutate the input of the next and the document would depend on
 * the order the tools were run in.
 */
export function referenceReport(): Record<string, unknown> {
  return {
    report_id: "rpt_5d3f8a01c76b249e",
    scan_run_id: "scan_a1b2c3d4e5f60718",
    verdict: "warn",
    findings: [
      {
        schema_version: "1.1",
        finding_id: "fnd_7c1e4a90b3d25f61",
        kind: "declared_egress_point",
        source: "declared",
        confidence: "confirmed",
        provider_ref: "openai",
        egress_kind: "llm_chat",
        detector_severity: "medium",
        declared_target: { host: "api.openai.com" },
        operation: "chat.completions.create",
        refs: [{ ref_type: "egress_point", ref_id: "ep_3f0a91c7d4e28b56" }],
        evidence: [
          {
            evidence_type: "ast_node",
            ref: "call_expression@services/customer.py",
            hash: JOIN_RULE_HASH,
          },
        ],
        detector: {
          component: "static-scanner",
          rule_id: "python.static.openai-chat-completions",
          rule_version: "1.0.0",
          rule_hash: RULE_HASH,
        },
        location: {
          component: "static-scanner",
          path: "services/customer.py",
          span: { start_line: 14, start_col: 12, end_line: 17, end_col: 6 },
          symbol: "summarize_customer",
        },
        coverage_impact: "none",
        data_sources: [{ source: "declared", detector_id: "static-scanner/python" }],
      },
      {
        // A derived finding, which is the only kind trace_reconciliation answers
        // for. It carries both halves the trace projects: the references it was
        // joined from, and the join rungs themselves as evidence.
        schema_version: "1.1",
        finding_id: "fnd_2b64c1d70e9a3f85",
        kind: "target_drift",
        source: "reconciled",
        confidence: "confirmed",
        provider_ref: "openai",
        egress_kind: "llm_chat",
        detector_severity: "high",
        declared_target: { host: "api.openai.com" },
        operation: "chat.completions.create",
        refs: [
          { ref_type: "egress_point", ref_id: "ep_3f0a91c7d4e28b56" },
          { ref_type: "egress_event", ref_id: "ee_81c0d54b3f7a29e6" },
        ],
        evidence: [
          {
            evidence_type: "reconciliation_join",
            ref: "J2:target_only declared=api.openai.com observed=gateway.internal.example",
          },
        ],
        detector: {
          component: "reconciliation",
          rule_id: "reconciliation.join.target-drift",
          rule_version: "1.0.0",
          rule_hash: JOIN_RULE_HASH,
        },
        location: {
          component: "reconciliation",
          path: "services/customer.py",
          span: { start_line: 14, start_col: 12, end_line: 17, end_col: 6 },
        },
        coverage_impact: "none",
        data_sources: [
          { source: "declared", detector_id: "static-scanner/python" },
          { source: "observed-app", detector_id: "runtime-hooks/python" },
        ],
      },
    ],
    suspect_findings: [
      {
        // A provider that appears in this list and nowhere else. It is here so
        // the document shows what `by_provider` counting over both lists is for:
        // answered from the confirmed list alone, this name disappears and the
        // project reads as one that talks to nobody but openai.
        schema_version: "1.1",
        finding_id: "fnd_4e07a3b95c218dfa",
        kind: "unmatched_wire_traffic",
        source: "reconciled",
        confidence: "suspect",
        provider_ref: "acme",
        detector_severity: "medium",
        refs: [{ ref_type: "flow", ref_id: "fl_6a2d09e4b81c73f5" }],
        evidence: [{ evidence_type: "sni", ref: "sni=api.acme.example" }],
        detector: {
          component: "reconciliation",
          rule_id: "reconciliation.join.unmatched-wire",
          rule_version: "1.0.0",
          rule_hash: RULE_HASH,
        },
        location: { component: "network-sensor", host: "api.acme.example", port: 443 },
        coverage_impact: "unlinked_event",
        data_sources: [{ source: "observed-wire", detector_id: "network-sensor/pcap" }],
      },
    ],
    coverage: {
      parsed_files: 1180,
      unparsed_files: [{ path: "vendor/generated.min.js", reason: "skipped_too_large" }],
      undetected_libraries: ["some-sdk"],
      runtime_coverage: [
        { language: "python", status: "instrumented", hook_mechanism: "middleware" },
        { language: "go", status: "not_instrumented" },
      ],
      reconciliation_mode: "full",
      sensor_platform_class: "linux_ebpf",
      in_scope_flows: 30,
      out_of_scope_flows: 9,
      known_benign_flows: 4,
      unattributed_flows: 2,
      unclassified_flows: 1,
    },
  };
}
