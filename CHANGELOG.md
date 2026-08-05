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

Detector rules are read from `rules/` beside the executable, or from `rules`
under the working directory when running from a checkout. An installation that
carries the binary alone scans nothing and says so; it does not report an empty
result.

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

- **Masking quality is not measured here and cannot be.** The scored half of that
  benchmark needs the same prompt sent both masked and unmasked to a real
  provider, and periskop may not be a source of egress. The shipped artefact
  reports every score as `null` with `meets_minimum_sample: false` and the
  reason written out. The only party who can measure it is the operator, with
  their own funded key and synthetic data, behind the
  `PERISKOP_I_UNDERSTAND_SYNTHETIC_ONLY` gate. An unmeasured score must not be
  read as a good one (KG-032).
- **The false positive rate is measured, and the number is deliberately not
  repeated here.** It is being taken over a real corpus rather than over the
  fixtures, and a rate is only readable next to the corpus it was measured on and
  the date it was measured. Read it in the measurement report rather than from a
  figure copied into a release note, where it would outlive the run that produced
  it.
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

- **A signing key file that anyone but its owner can read is now refused.**
  `periskop sign` checks the mode bits and exits non zero on a key at `0644`,
  with the path and the mode in the message. `periskop key generate` has always
  written `0600` and narrows a replaced file to it, so a key this refuses was
  either not written by that command or was widened afterwards. On platforms
  where this build cannot read mode bits, it says the question was not asked
  rather than passing quietly. Fix: `chmod 600`, or generate a key that was never
  exposed.

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
