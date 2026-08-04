# periskop python runtime hook

Records the calls a python process actually makes to LLM SDKs and HTTP clients.
Where the static scanner says the code *can* reach a provider, this says it
*did*.

Pure standard library, python 3.9 and later, no third party dependencies. The
application's source code is not modified (ADR-009).

## What it produces

One JSON object per line, each conforming to
[`schemas/egress-event.schema.json`](../../schemas/egress-event.schema.json):

```json
{"schema_version":"1.0","egress_event_id":"ee_3dfe316616cd47b4","process":{"language":"python","runtime":"cpython/3.12","entrypoint_hint":"billing-worker"},"library":{"module":"openai","mechanism":"sdk_wrapper"},"operation":"chat.completions.create","target":{"host_id":"api.openai.com","port":443,"path_template":"/v1/chat/completions","provider_ref":"openai"},"payload_shape":{"field_paths":["messages[].content","messages[].role","model"],"byte_size_estimate":346,"truncated_depth":0}}
```

The stream goes into the directory named by `PERISKOP_EVENT_DIR`, as one
`python-<pid>-<random>.jsonl` file per process. A directory rather than a file
path because multi process work then needs no coordination: two processes
appending to one file interleave their writes and corrupt lines, and a file
model would make the caller responsible for inventing a unique name for every
worker. The `.jsonl` extension is what `periskop-runtime-collector` selects on.

Next to the stream, a `<stream>.jsonl.status.json` sidecar declares what the run
was: `hook_status`, `reason`, `dropped_events_count`, `written_events_count` and
the failures that were swallowed. A file of zero events and a hook that never
ran are different facts, and the sidecar is what keeps them apart. It ends in
`.json` rather than `.jsonl` so the collector never reads a run's own accounting
back as an event.

### Identity

`egress_event_id` is derived, never counted, and the derivation is fixed by
`schemas/egress-event.schema.json`:

```
ee_ + blake3("ee/v1" | library.module | operation | target.host_id
             | target.path_template)[:8] as lowercase hex
```

with `0x1F` between the fields and an absent field written as the empty string.
Nothing else takes part: not the clock, not the pid, not the payload size, not
the call site. The same call recorded twice therefore carries one identity, in
this hook, in the node hook and in the collector. blake3 is written out in
`periskop_hook/blake3.py` because CPython ships no blake3 and a hook may not add
a third party dependency to somebody else's interpreter; it is held to the
official reference vectors in `tests/test_blake3.py`.

## Installation

### Primary path: the `.pth` file (ADR-009)

Copy the package and `periskop-hook.pth` into a site-packages directory:

```sh
SITE=$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
cp -r periskop_hook "$SITE"/
cp periskop-hook.pth "$SITE"/
```

`site.py` executes the import line of every `.pth` file before any application
code runs. Nothing else is needed: no `PYTHONPATH`, no wrapper script, no change
to the application.

### Fallback: chained `sitecustomize.py`

Only where a `.pth` cannot be dropped in, for example when the hook ships on
`PYTHONPATH` rather than in site-packages:

```sh
export PYTHONPATH=/opt/periskop/hooks/python:$PYTHONPATH
```

`sitecustomize` is a single name that debuggers, coverage tools and vendor
agents also use, and only one of them can win an import. This one therefore
**chains**: it imports the `sitecustomize` it shadows first, and installs the
hook second. The chaining code is inline rather than imported from
`periskop_hook`, so the other tool keeps working even when the periskop package
itself is broken. Overwriting an existing `sitecustomize.py` with this file is
the one installation mistake that would break another tool silently; use the
`.pth` path when in doubt.

## Environment variables

| Variable | Meaning | Default |
|---|---|---|
| `PERISKOP_EVENT_DIR` | **Directory** the event stream is written into, one `.jsonl` file per process. **Without it the hook stays off.** | unset, hook disabled |
| `PERISKOP_HOOK_OUTPUT` | Legacy: path of one exact event file. Kept so an existing deployment survives an upgrade; `PERISKOP_EVENT_DIR` wins when both are set. | unset |
| `PERISKOP_HOOK` | `0`, `false`, `off` or `no` disables the hook completely | unset, enabled |
| `PERISKOP_HOOK_BUFFER` | Ring buffer capacity in events | `1024` |
| `PERISKOP_HOOK_ENTRYPOINT` | `process.entrypoint_hint` in the event | basename of `sys.argv[0]` |
| `PERISKOP_HOOK_DEBUG` | Writes swallowed failures to stderr | unset, silent |
| `PERISKOP_HOOK_STATUS` | **Written by the hook**, not read: `active` or `disabled:<reason>` | set at startup |

There is no configuration file, and no default destination. Writing an event
stream somewhere the operator did not ask for is a side effect an observation
tool should not have. The directory is created on first write, not at startup,
so a process that records nothing leaves nothing behind.

## What is instrumented

| Module | Layer | Mechanism | Events |
|---|---|---|---|
| `openai` | SDK resource methods | `sdk_wrapper` | `chat.completions.create`, `responses.create`, `embeddings.create` |
| `anthropic` | SDK resource methods | `sdk_wrapper` | `messages.create`, `completions.create` |
| `httpx` | `Client.send`, `AsyncClient.send` | `http_client` | `http.<method>` |
| `requests` | `Session.send` | `http_client` | `http.<method>` |

A module that the application never imports is never wrapped: the hook watches
`sys.meta_path` and patches on import, then removes itself from `sys.meta_path`
once every watched library has been seen. Importing a library in order to
instrument it would add a dependency to a process that had chosen not to have
one.

The two layers are recorded separately in `library.mechanism`, because an
`sdk_wrapper` observation is stronger evidence than an `http_client` one: the
HTTP layer cannot tell a provider call from any other request without looking at
the target.

## Not instrumented, on purpose

Package installers and build tools (`pip`, `uv`, `poetry`, `setup.py` and
friends), and `python -c` one liners, exit before any of the machinery is
imported. The decision costs a handful of string comparisons on `sys.argv` and
the environment; everything else lives behind it.

## Fail-open guarantee

**A hook failure never reaches the application.** Any error the hook can produce
is caught at its own boundary and recorded for the status file: a broken or half
removed installation, a missing library method after a version upgrade, an
unwritable or misconfigured output path, a payload the traversal cannot walk.
The interpreter starts, the call runs, the return value and the exceptions are
the application's own.

The tension with full visibility is deliberately resolved towards reliability
(runtime-hooks spec section 5): a missed event can be declared in a coverage
statement and fixed on the next run, while a production process that periskop
crashed cannot be undone. An observation tool that breaks the thing it observes
has failed at its only job.

Practical consequences:

* The wrapper records **before** calling the original and discards its own
  result. A call that raises still left the process, and recording afterwards
  would drop exactly the failures worth seeing.
* Nothing is written on the call path. Events go into a bounded ring and a
  daemon thread does the I/O, so a slow disk cannot become backpressure inside
  somebody else's request handler. Measured overhead is tens of microseconds per
  call against the budget of under 1 ms.
* When the ring is full the oldest event is dropped **and counted**. Silent loss
  is forbidden; the count is in the status sidecar.
* `KeyboardInterrupt` and `SystemExit` are never swallowed. They belong to the
  application.

## What is never recorded

The hook records the **shape** of a payload and never its content. This is not a
default that can be switched: there is no content capture mode in this package.

* **No values.** No prompt, no message body, no header value, no argument value
  is read, copied, formatted or logged. From a string, only `len()` is taken.
* **No unrecognised field names.** `payload_shape.field_paths` carries field
  paths, and a key can carry data as readily as a value: a map keyed by customer
  email would otherwise copy those addresses into the record. Keys outside the
  known request vocabulary become `<dyn>` (runtime-hooks spec section 3.1), and
  a key that looks like content cannot be added to that vocabulary.
* **No body parsing.** For HTTP clients the body is already encoded by the time
  the hook sees it. It is not decoded back: the record carries no field paths
  plus `payload_traversal_truncated`, so a reader sees a request whose shape was
  not read rather than a request without fields.
* **No entity analysis.** No NER, no dictionary matching, no pattern scan over
  any body, no `entity_counts` field, in any mode, behind any flag (ADR-011
  section 7). Entity counting belongs to the proxy; if the proxy is not in the
  path, the count is absent and declared absent rather than estimated here.
* **No measurement of a streaming body.** Materialising it would change the
  behaviour of the program under observation, and consuming a generator would
  destroy the request. `byte_size_estimate` is an estimate, and
  `streaming_body_not_measured` says when it could not be taken at all.
* **No absolute paths.** `call_site_hint.path` is relative to the working
  directory; a frame outside the project tree is reported as unavailable rather
  than trimmed into something that only looks relative.
* **No network.** The hook writes to a local file and nowhere else. periskop
  does not phone home.

## Tests

```sh
cd hooks/python
python3 -m unittest discover -v
```

Standard library only, no pytest. The suite covers event schema conformance
against the repository's own schema and examples, fail-open under a broken
artefact, an unwritable stream and a mismatched library version, early exit in
non target processes, the off switch, lazy instrumentation, dynamic key masking,
and the one that matters most: that no raw value reaches `field_paths` or any
other part of a written event.
