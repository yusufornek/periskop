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

A third source reconciles both of those against the wire. Flows are recorded,
scoped, joined against the other two sources and turned into findings, including
traffic that no call site and no runtime call accounts for. The kernel side is
written and runs on Linux, behind a program object built separately; a binary
built without it says so instead of reporting a quiet clean.

Finding the paths is half of the problem. The other half is the traffic you mean
to keep. A masking proxy stands between an application and a provider, replaces
the values that should not leave with aliases, and puts them back in the answer,
so a current model can be used without the data going with it.

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
- Kernel capture on Linux. `periskop sensor` loads an eBPF program, attaches its
  probes, gives up the capabilities that let it, and decodes what the kernel
  sends back. The program object is built from a separate crate with its own
  toolchain, and a binary built without one runs every check it can and then
  reports `loader_not_built` rather than an empty network.
- Detached Ed25519 signing, and verification that fails closed. The signature
  covers the bytes on disk rather than a reserialised value, so nothing a lenient
  parser would forgive can travel between what was signed and what a reader sees.
- A masking proxy for OpenAI and Anthropic chat, messages and embeddings. It
  detects the values that should not leave, replaces them with aliases before the
  request goes upstream, and restores them in the answer, including a streamed
  one, where an alias split across chunk boundaries is held rather than written
  out in halves.
- An encrypted alias vault. The key is derived with Argon2id from a passphrase
  read on standard input, records are sealed with XChaCha20-Poly1305, and
  `periskop proxy` keeps it in memory: a run writes nothing to a disk.
- An alias ladder that prefers aliases which can be shown not to be real: a
  published reserved range where one is cited, otherwise the type's shape with its
  validator deliberately failed, otherwise an opaque form. An IBAN alias is
  therefore an IBAN-shaped string that no mod 97 check accepts. A generator whose
  evidence runs out falls down the ladder and reports the rung it landed on; it
  never climbs.
- A command line interface and an MCP server, both thin clients over one engine.

Not implemented:

- Named entity recognition. Layer C of the masking policy does not exist, and
  `ner.enabled = false` is not a switch with something behind it. Person and
  organisation names are masked only when the operator's dictionary carries them;
  a name that is not in it reaches the provider, and every request declares
  `ner_disabled` rather than leaving that to be assumed.
- Date shifting. Dates are neither masked nor moved.
- Multi-tenant deployment. The proxy is single tenant and local: behind the vault
  passphrase there is no per-caller authorisation at all, which is why a bind
  address reachable from another host is refused unless the operator asks for it
  in so many words.
- Masking on the Responses and Assistants APIs. `/v1/responses`, `/v1/assistants`
  and `/v1/threads` reach the provider unmasked. They are declared rather than
  quietly passed, and image, audio and batch endpoints are refused outright, but
  an application on those surfaces gets no masking from this build.
- DNS answers and TLS server names on the wire. Those need a traffic control
  classifier, no build carries one, and a sensor plan that names either hook is
  refused whole rather than trimmed to what happens to work.

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
crates/     Rust workspace: engine, scanner, event collector, reconciliation,
            network sensor, eBPF loader and program object, masking proxy, CLI
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

Detector rules are built into the binary, so a scan works wherever the binary
is. `--rules <DIR>` reads a directory instead, which is how you run your own.

There is deliberately no search for a `rules` directory nearby. A directory
that happened to be next to the binary, or in whatever the working directory
was, could silently replace the shipped detectors with something older or
narrower, and the report would look exactly the same. Every run says on stderr
which set it used and, when it read from disk, from where.

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

This wants `CAP_BPF` and `CAP_PERFMON` on a Linux host with BTF, and a binary
built with the kernel program object. The capability pair is what is checked;
root is accepted as a fallback and recorded as such, because operators have it
and refusing it pushes them somewhere worse. Where any of that is missing it
writes an
empty record set, prints the reason from a fixed vocabulary
(`unsupported_platform`, `missing_capability`, `kernel_unsupported`,
`loader_not_built`) and exits non zero, because a run that never started must not
be read as a quiet machine.

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

### Masking what leaves

The commands above answer where data goes. The proxy is for the paths you mean to
keep: it stands in front of a provider, replaces what should not leave, and puts
it back in the answer, so the model sees an alias and the application sees the
value it sent.

```bash
periskop proxy --policy policy.toml < /run/secrets/vault-passphrase
```

The passphrase is read from standard input rather than from a flag or an
environment variable, both of which are readable by anything that can list
processes. There is no passwordless mode, so an unattended restart cannot open
the vault on its own.

There is no built-in policy and no fallback to one: a masking proxy running under
rules nobody wrote is the thing this component argues against, so a policy that
is missing or unloadable stops the command before the passphrase is even read.
`--policy` defaults to `policy.toml` in the working directory.

It listens on `127.0.0.1:8787` unless `--listen` says otherwise, and a bind
address reachable from another host is refused unless
`--allow-external-interface` is also given. Point the application's base URL at
it: OpenAI paths are served where they are, and Anthropic is mounted under
`/anthropic`. `--upstream openai=https://gateway.internal.example/v1` sends a
provider somewhere else and adds that host to the connect allow list, which the
run says out loud on start-up.

What that looks like on the wire. A `POST /v1/chat/completions` whose message
content is `hesabim TR33 0006 1005 1978 6457 8413 26` reaches the provider with an
IBAN-shaped string in place of the account number, one that fails its mod 97
check, and the answer comes back to the application with the original restored.
The response says what was done to it: how many entities were masked, the policy
in force, the alias scope the aliases belong to, and
`x-periskop-degraded: ner_disabled`, because names not in the operator's
dictionary were not looked for.

The vault is held in memory and nothing is written to a disk. Its key is derived
with Argon2id at 256 MiB, which is the cost that makes an offline guess at the
passphrase expensive. `--vault-profile ci` lowers that to 64 MiB for machines that
cannot spare it, and a run under it prints a line saying the vault is
correspondingly cheaper to attack.

### Signing a report

```bash
periskop key generate --secret-key signing.key --public-key signing.pub
periskop sign --report report.json --key signing.key
periskop verify --report report.json --public-key signing.pub
```

Both paths are required and there is no default location, because a key written
somewhere you did not name is a key you will not think to protect. `generate`
writes the private key readable by its owner alone, and `sign` refuses a key file
that anyone else can read: the rule is ssh's, and so is the reason. `verify` exits
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
