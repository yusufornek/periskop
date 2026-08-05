# Changelog

Notable changes, newest first. Versions follow semver, and the binary's MAJOR
version fixes the highest report `schema_version` it can produce, so a consumer
can tell from the version alone which report format it is reading.

## 0.1.0 (unreleased)

The first release. Nothing was released before it, so everything below is new,
and the sections that matter most are the ones about what is not measured.

### What it does

Answers where a codebase sends data to a model provider, from three sources that
are reconciled against each other rather than trusted one at a time.

- **Code.** Static scanning for Python, TypeScript/JavaScript, Go and Java.
  Detection is on the tree-sitter syntax tree, not on text, and every report
  states what could not be read so that a clean result is never a run that did
  not look.
- **Runtime.** Hooks for Python and Node record the shape of an outgoing call,
  never its content. They are fail-open: the application runs whether the hook
  does or not.
- **Wire.** `periskop sensor` loads an eBPF program on Linux, attaches its
  probes and decodes what the kernel sends back.

Reconciling those three derives findings no single source yields:
`dormant_egress_point`, `target_drift`, `unmatched_wire_traffic` and
`volume_anomaly`. Scan reports are deterministic over the same tree and rules,
and can be signed with a detached Ed25519 signature that covers the bytes on
disk.

Detector rules are compiled into the binary, so the downloaded executable is the
whole artefact and carries its detectors with it. `--rules <DIR>` replaces that
set for an operator running detectors they wrote themselves; nothing is searched
for on disk. Every `scan` prints which of the two it used, on stderr, and the
coverage statement carries it as `rule_set_source`, one of `embedded` or
`directory` and never a path. A reader told a tree is clean can therefore ask
what it was clean according to, months later, from the archived report. Embedding
cost 33 056 bytes, measured: 32.3 KiB on a release build, 0.325% of the binary.

Answers can also be kept from leaving in the first place. `periskop proxy` stands
between an application and OpenAI or Anthropic, masks what should not go
upstream, and restores it in the answer, including a streamed one. The alias
vault is encrypted with XChaCha20-Poly1305 under an Argon2id key and is held in
memory: a proxy run writes nothing to a disk.

What the masking recognises, and in what language. Layer A is pattern and
checksum work and does not care what language the prose around it is in: IBAN,
credit card, e-mail, phone (E.164 and the Turkish local forms), URL, API keys and
secrets, and the Turkish national and tax identifiers. Layer B is the operator's
dictionary, and its morphology is **Turkish only**: Turkish case folding and
Turkish inflectional suffixes are what let a dictionary entry match the forms it
takes in a sentence. There is no morphology for any other language, and no layer
C at all.

### Deferred, and not measured

These are the parts a reader should not assume. Every one of them is a decision
somebody made rather than an oversight.

The first two are open release gates, not caveats. Both have a runner written,
both refuse to publish a figure they did not take, and neither is closed by this
release. A build that ships with these open ships with them stated.

- **Masking quality is not measured here and cannot be.** The scored half of that
  benchmark needs the same prompt sent both masked and unmasked to a real
  provider, and periskop may not be a source of egress. The shipped artefact
  reports every score as `null` with `meets_minimum_sample: false` and the
  reason written out. The only party who can measure it is the operator, with
  their own funded provider key and synthetic data, behind the
  `PERISKOP_I_UNDERSTAND_SYNTHETIC_ONLY` gate, on a real run against a real
  provider. Moving that measurement into CI is forbidden and stays forbidden. An
  unmeasured score must not be read as a good one (KG-032).
- **The false positive rate is not measured, and this release does not close
  that gate.** The rate is defined over `unmatched_wire_traffic` findings, which
  come from observed flows rather than from source, so no amount of scanning
  repositories produces one: the denominator is structurally zero. The gate needs
  200 hand-labelled flows and today's artefact carries 8. The runner writes
  `meets_minimum_sample: false` with the count beside it and withholds the
  derived readings rather than publishing a rate over 8 cases; 100% accuracy over
  8 cases and over 200 cases are not the same sentence, and only the second one
  is about the tool. Nobody may quote a number from that file while the flag is
  false.
- **The detection benchmark shipped here runs on the bootstrap fixture corpus,**
  where every cell is below the minimum sample. Fixtures are written by the
  people who write the rules, so it measures whether the rules do what their
  authors intended, not whether that intent matches how the libraries are used.
- **The sensor is Linux only and asks for privilege.** It needs `CAP_BPF` and
  `CAP_PERFMON` on a host with BTF, and a binary built with the kernel program
  object, which is a separate crate with its own toolchain. Without any of those
  it writes an empty record set, prints `unsupported_platform`,
  `missing_capability`, `kernel_unsupported` or `loader_not_built`, and exits non
  zero rather than letting a run that never started read as a quiet machine.
- **`dropped_events` is a floor, not a count.** The kernel ring buffer does not
  always hand back a loss counter, and the coverage statement has no way to spell
  "nobody could count". The sensor status lists the field under `not_measured`
  and says so in words, so a `0` is not read as proof that nothing was dropped.
  Widening the contract itself is an open request against
  `coverage-statement.schema.json`.
- **Privilege reduction is half done.** After the programs are attached the
  sensor drops the capabilities that let it load them, but it does not drop the
  bounding set, which would need `CAP_SETPCAP` that it does not ask for, and it
  does not switch to an unprivileged user. The remaining exposure is a process
  that could regain the capability across an `execve`, and the sensor never
  execs.
- **DNS answers and TLS server names are not observed.** They need a traffic
  control classifier and no build carries one. A sensor plan naming either hook
  is refused whole rather than trimmed.
- **There is no passwordless proxy start.** The vault passphrase is read from
  standard input on every start, so an unattended restart leaves the vault
  sealed and, by the fail-closed rule, serves nothing (KG-020).

### Breaking behaviour

There is no earlier release to break, so this is for anyone who has been running
from the tree.

- **The implicit search for a rule directory is gone.** A run used to look for
  `rules` beside the executable and then under the working directory. Both
  directions were wrong. Run from a directory with no such tree, the scan refused
  to start at all, which is what made `periskop scan path/to/project` wrong for
  everyone who unpacked one file. Run from a directory that happened to have one,
  that tree silently replaced the shipped detectors, and a narrower rule set
  produces a cleaner report: fewer rules find fewer things, and the result reads
  as a clean tree rather than as a scan that was not looking. The same command
  answering differently in two directories also broke the determinism promise.
  Today the embedded set is the default and `--rules <DIR>` is the only override.
  A `--rules` path that is not a directory stops the run with exit code 2 rather
  than falling back to the embedded set: the operator asked for their own
  detectors, and answering with somebody else's while reporting success is the
  worst option available. Anyone who relied on a `rules` directory being picked
  up now has to name it.
- **A signing key file that anyone but its owner can read is now refused.**
  `periskop sign` checks the mode bits and exits non zero on a key at `0644`,
  with the path and the mode in the message. The rule is that no group or other
  bit may be set, so `0600` and `0400` pass and anything wider does not; it is
  ssh's rule, and so is the reason. `periskop key generate` has always
  written `0600` and narrows a replaced file to it, so a key this refuses was
  either not written by that command or was widened afterwards. On platforms
  where this build cannot read mode bits, it says the question was not asked
  rather than passing quietly. Fix: `chmod 600`, or generate a key that was never
  exposed.
- **The file vault refuses three things it used to accept.** Deleting `vault.psk`
  is now the same violation as restoring an older copy: a caller that knows the
  counter had reached a higher value gets `counter_rollback` and no vault is
  created, because deletion needs no valid header and was the easier of the two
  attacks. A vault path that is a symbolic link is refused rather than followed.
  A header claiming Argon2id parameters outside the hard bounds is refused before
  any key is derived, so a forged header cannot cost 64 GiB and minutes of CPU on
  the way to being rejected. All three answer with 503 and leave nothing behind.
  Only the `file` backend is affected; the `memory` default was never on a disk.

### Known limits

The catalogue of what this build cannot see, and why, is kept with the project
documentation in `docs/05-quality/known-gaps.md`, which travels with the source
tree rather than with the published repository. It is long on purpose. The
entries most likely to matter to somebody deciding whether to run this, with
their catalogue identifiers so they can be looked up there:

- Person and organisation names are masked only when the operator's dictionary
  carries them, and the dictionary misses Turkish names typed without their
  diacritics (`Yilmaz` for `Yılmaz`). Entering both spellings works today
  (KG-010, KG-029).
- Structured tool-call arguments are not masked, and the Responses, Assistants
  and Threads surfaces pass through unmasked. Both are declared in the response
  and in a finding rather than passed quietly, and a deployment that would rather
  break than pass unmasked data can set `tool_call_policy = "reject"` (KG-018).
- Inside fenced code blocks only the pattern layer runs, so a name in a comment
  is not masked. The alternative renames variables and hands the model code that
  does not compile. `code_block_policy = "full"` changes it (KG-028).
- Masking errs toward false positives in two known places: a ten digit number
  that happens to pass the tax identifier checksum is masked, and a truncated
  prefix of an invalid IBAN can pass mod 97 and be masked. Both cost a mangled
  prompt the operator can see, which was chosen over the other direction, where
  the cost is a real identifier reaching a provider (KG-024, KG-033).
- If the vault's pages cannot be locked into memory, the operating system may
  write resolved values to swap. The proxy says so in its status rather than
  stopping, because stopping would leave the machines that cannot lock memory
  with no proxy at all (KG-019).
