# periskop

Find out where your code sends data to LLM providers, and prove the answer.

periskop scans a codebase and reports every call site that sends data to an external
model API. Each finding carries its evidence and its confidence. Every report also
states what the scanner could not read, so a clean result never quietly means an
unscanned file.

There is a second source. Runtime hooks for Python and Node record the calls a
process actually made, and reconciling the two produces findings neither yields
alone: a call site nothing was seen to use, and a call that reached a destination
the code does not name. A third source, a network sensor, is designed and not
built, so periskop today compares what the code says against what the process
observed about itself. That is not the same as what left the machine, and the
report does not pretend otherwise.

## Status

Pre-alpha. Nothing here is released yet, and the API is not stable.

Implemented:

- Static scanning for Python, TypeScript/JavaScript, Go and Java.
- Runtime hooks for Python and Node. They record the shape of an outgoing call,
  never its content, and they are fail-open: the application runs whether or not
  the hook does.
- Reconciliation of those two sources, deriving `dormant_egress_point` and
  `target_drift`.
- A command line interface and an MCP server, both thin clients over one engine.

Not implemented:

- The network sensor. Nothing in this tree captures traffic. The two derived
  finding kinds that need the wire, `unmatched_wire_traffic` and
  `volume_anomaly`, are therefore never produced, and a run states that in its
  diagnostics rather than leaving the absence to be inferred. The record schema
  and its Rust data model exist ahead of the sensor itself; no component reads
  them yet.
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
