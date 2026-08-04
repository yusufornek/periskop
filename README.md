# periskop

Find out where your code sends data to LLM providers, and prove the answer.

periskop scans a codebase and reports every call site that sends data to an external
model API. Each finding carries its evidence and its confidence. Every report also
states what the scanner could not read, so a clean result never quietly means an
unscanned file.

There is a second source. Runtime hooks for Python and Node record the calls a
process actually made, and reconciling the two produces findings neither yields
alone: a call site nothing was seen to use, and a call that reached a destination
the code does not name.

A third source reconciles both of those against the wire, and the pipeline for it
is built: flows are recorded, scoped, joined against the other two sources and
turned into findings, including traffic that no call site and no runtime call
accounts for. What is not built is the part that watches a real kernel. Until it
is, the flow records have to come from somewhere, and a run handed none says so
instead of reporting a quiet clean.

## Status

Pre-alpha. Nothing here is released yet, and the API is not stable.

Implemented:

- Static scanning for Python, TypeScript/JavaScript, Go and Java.
- Runtime hooks for Python and Node. They record the shape of an outgoing call,
  never its content, and they are fail-open: the application runs whether or not
  the hook does.
- Reconciliation across all three sources, deriving `dormant_egress_point`,
  `target_drift`, `unmatched_wire_traffic` and `volume_anomaly`. The last two
  need flow records, and `volume_anomaly` also needs a band declared in policy.
  With no band declared it produces nothing rather than inventing the threshold
  it is supposed to measure against.
- Detached Ed25519 signing, and verification that fails closed. The signature
  covers the bytes on disk rather than a reserialised value, so nothing a lenient
  parser would forgive can travel between what was signed and what a reader sees.
- A command line interface and an MCP server, both thin clients over one engine.

Not implemented:

- Kernel capture. Nothing in this tree attaches to a kernel and watches traffic.
  The DNS and TLS parsers, the scoping rules, the record decoder and the
  privilege gate are written and tested; the eBPF program they would read from is
  not, and the loader crate carries no kernel dependency yet (ADR-014). Asked to
  observe, `periskop sensor` reports what it could not do and why, rather than
  returning an empty result that reads like a quiet network.
- The masking proxy. Nothing here intercepts, rewrites or masks a request.

See "Scope" below for what the implemented half does not cover.

## Why not just grep

A regular expression finds the string `openai`. It also finds it in a comment, misses
a client stored in a variable, and says nothing about what data reaches the call.
periskop parses each file with tree-sitter and matches on the syntax tree, so a
detection is a structural fact rather than a text coincidence.

Detection rules are declarative TOML, versioned alongside the code. Every rule is
compiled in CI, so a rule that would fail at runtime fails the pull request instead.

## Scope

periskop does not claim to find everything, and the report says so in numbers.

Static analysis cannot resolve a call whose target is built at runtime, whose method
name lives in a variable, or which hides behind an opaque in-house wrapper. Rather
than hiding those cases, the scanner counts them: files it could not parse, targets
it could not resolve, libraries it has no detector for. A finding is an assertion
with evidence. A blind spot is not an assertion, so it is reported as coverage, not
as a result.

A hook has the opposite blind spot and the same accounting. It sees only what
ran: a code path nobody exercised leaves no event, a process the hook was never
loaded into leaves none either, and a language it does not exist for is not
observed at all. So the coverage block records which runtimes were instrumented
and which were not, and an empty event stream is reported as an empty event
stream rather than as a process that made no calls.

The threat model is accidental exposure. Someone deliberately hiding an egress path
is a matter for enforcement, not detection.

## Design principles

Detection belongs to the engine, interpretation to the reader. Tools return facts and
structured context; they do not generate prose explanations, because a report that
changes wording between runs cannot be diffed or audited.

Reports are deterministic. The same tree and the same rules produce byte-identical
output. Adding a line to a file does not create a new finding identity, because
identities are content addressed and carry no line numbers.

periskop sends no telemetry, downloads nothing at runtime and never phones home. A
tool that exists to tell you where your data goes cannot itself be a source of egress.

## Repository layout

```
crates/     Rust workspace: engine, scanner, event collector, reconciliation, CLI
hooks/      Runtime hooks: python package and node preload, installed into an app
packages/   TypeScript workspace: MCP server
schemas/    JSON Schema contracts, single source for every side
rules/      Declarative detector rules, one directory per language
```

`schemas/` is the contract both sides are written against. Rust and TypeScript
types mirror it by hand today, and every example under `schemas/examples/` is
validated in CI, including negative ones that must fail for the stated reason.
Generating the types instead is the plan; until that lands, a schema change and
the code that reads it belong in the same commit.

## Building

Requires a Rust toolchain as pinned in `rust-toolchain.toml`.

```bash
cargo build --workspace
```

```bash
cargo test --workspace
```

## Using it

Scan a project and read the summary:

```bash
periskop scan path/to/project
```

The output leads with a verdict, lists confirmed findings, keeps weaker ones in
their own section, and ends with what the scan could not see. That last part is
not decoration. A run with no findings over a tree it could barely read is a
different result from a clean one, and the coverage block is how you tell them
apart.

For a machine readable report:

```bash
periskop scan path/to/project --json
```

The JSON validates against `schemas/report.schema.json`. Two runs over an
unchanged tree produce identical bytes apart from the envelope, which holds the
timestamp, so reports can be committed and diffed.

In continuous integration, coverage can gate the result:

```bash
periskop scan . --max-unparsed-ratio 500
```

That exits with code 3 when more than five percent of the code surface was
unreadable, which is distinct from the code for a policy failure. A pipeline
needs to tell "clean" apart from "did not look".

### Recording what actually ran

A scan reads code. The hook records calls. Installing one is optional, and a
scan reports the same code side with or without it; what the hook adds is the
second source the first is compared against.

Print what an application needs, and change nothing on disk:

```bash
periskop hook install --language python --print-env
```

That writes the variables to stdout and a note about them to stderr, so the
output can be evaluated by a shell. To place the hook as well, name a directory
to copy it into:

```bash
periskop hook install --language node \
  --target node_modules --event-dir .periskop/events
```

Python is loaded through a `.pth` file in a site-packages directory, or through
`PYTHONPATH` as a fallback; Node through `--require` in `NODE_OPTIONS`. Neither
modifies the application. The hook writes one JSON Lines file per process into
the event directory, holding the destination, the operation, the library and the
shape of the payload. The shape is a list of field paths and a size, never a
value: a tool that recorded what you sent to a provider would be the leak it
exists to find.

Then scan with both sources:

```bash
periskop scan . --events .periskop/events
```

The directory is also read from `PERISKOP_EVENT_DIR`, which is what `hook
install` prints, so a hooked project need not repeat it. With events the report
declares itself reconciled rather than static only, and a path that does not
resolve stops the run instead of being read as a stream with nothing in it.

### Watching the wire

Both sources above look out from inside the process. The third looks in from
outside, and it is the only one that can see a connection neither the code nor a
hooked call accounts for.

```bash
periskop sensor --out .periskop/flows --scope-process ./my-service
```

Naming the processes that belong to the codebase is what makes attribution
possible. With none named, every flow lands in `out_of_scope_process` and no
unmatched traffic finding can come out of the pass. That is still a legitimate
way to run it, so the flag is not required, but the status document says what it
cost rather than leaving an empty result to be read as a quiet machine.

This wants `CAP_BPF` and `CAP_PERFMON` on a Linux host with BTF, and the kernel
side is not written yet. Anywhere else it writes an empty record set, says why,
and exits non zero.

```bash
periskop scan . --events .periskop/events --flows .periskop/flows
```

With three sources the report says `full` and can derive traffic nothing in the
codebase explains. `volume_anomaly` additionally needs a band, which is the one
threshold with no engine default:

```toml
[reconciliation.volume_band]
min_basis_points = 5000
max_basis_points = 30000
```

That goes in `periskop-policy.toml` at the project root, or a file named with
`--policy`. Undeclared, the rule reports as suppressed rather than measuring
against a number periskop made up.

### Signing a report

```bash
periskop key generate --secret-key signing.key --public-key signing.pub
periskop sign --report report.json --key signing.key
periskop verify --report report.json --public-key signing.pub
```

Both paths are required and there is no default location, because a key written
somewhere you did not name is a key you will not think to protect. `verify` exits
non zero for every outcome but one: an unsigned report, an altered one, a key
that was not named and an envelope that fails its schema are all refusals, and
none of them can be mistaken for a pass.

The signature says the report came from the named key unaltered. It says nothing
about whether the scan was complete or correct, which is what the coverage block
is for.

### Editor integration

The MCP server exposes the scanner to an editor. It is a thin client over the
same engine, so detection has one implementation rather than two.

```bash
cd packages/mcp-server && npm install && npx tsc
```

Point it at the binary with `PERISKOP_BINARY`. Four tools are available:
`scan_project` returns a summary with a first page of findings, and
`get_finding_detail` and `get_coverage_report` fetch what the reader asks for
next. `trace_reconciliation` answers the question a derived finding raises,
which is what tied a call site and an observed call together and where they
disagreed. Results are paginated on purpose; a scan of a large repository should
not consume a context window in one response.

## Contributing

Issues and pull requests are welcome. Two expectations worth stating up front.

Every detector rule ships with three test cases: one that must match, one that must
not, and one known evasion that the rule cannot catch. The third is not a failure. It
is documentation of a limit, and it belongs in the known gaps catalogue.

Anything that changes a schema starts in `schemas/`, not in the code that reads it.

## License

Apache License 2.0. See [LICENSE](LICENSE).
