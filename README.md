# periskop

Find out where your code sends data to LLM providers, and prove the answer.

periskop scans a codebase and reports every call site that sends data to an external
model API. Each finding carries its evidence and its confidence. Every report also
states what the scanner could not read, so a clean result never quietly means an
unscanned file.

Later phases add runtime instrumentation and a network sensor, then reconcile the
three sources against each other. That reconciliation is the point: static analysis
alone can be evaded by indirection, but traffic leaving the machine cannot. What the
wire shows and the code does not explain is the finding nobody else can produce.

## Status

Pre-alpha. Nothing here is released yet, and the API is not stable.

The current phase covers static scanning for Python and TypeScript/JavaScript, a
command line interface, and an MCP server. Runtime hooks, the network sensor, the
reconciliation core and the masking proxy are designed but not implemented. See
"Scope" below for what that means in practice.

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
crates/     Rust workspace: engine, scanner, CLI
packages/   TypeScript workspace: MCP server
schemas/    JSON Schema contracts, single source for both sides
rules/      Declarative detector rules, one directory per language
```

Types are generated from `schemas/` on both sides. Hand written parallel type
definitions are rejected in review.

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

### Editor integration

The MCP server exposes the scanner to an editor. It is a thin client over the
same engine, so detection has one implementation rather than two.

```bash
cd packages/mcp-server && npm install && npx tsc
```

Point it at the binary with `PERISKOP_BINARY`. Three tools are available:
`scan_project` returns a summary with a first page of findings, and
`get_finding_detail` and `get_coverage_report` fetch what the reader asks for
next. Results are paginated on purpose; a scan of a large repository should not
consume a context window in one response.

## Contributing

Issues and pull requests are welcome. Two expectations worth stating up front.

Every detector rule ships with three test cases: one that must match, one that must
not, and one known evasion that the rule cannot catch. The third is not a failure. It
is documentation of a limit, and it belongs in the known gaps catalogue.

Anything that changes a schema starts in `schemas/`, not in the code that reads it.

## License

Apache License 2.0. See [LICENSE](LICENSE).
