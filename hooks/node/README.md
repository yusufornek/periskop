# periskop node hook

A Node.js runtime hook that records every call leaving a process, with the shape
of what was sent and never its content.

Where the static scanner says the code *can* reach a provider, this says it
*did*. It sits on the transport layer, so a call is recorded whether or not the
SDK making it is one periskop recognises, and whether or not the destination is
a known provider.

Mechanism and safety rules come from ADR-009 and
`docs/02-components/runtime-hooks/spec.md`. The event format is
`schemas/egress-event.schema.json`, which is binding: nothing here is allowed to
write a field that schema does not define.

## Requirements

Node 20 or newer. No third party dependencies, at build time or at run time, so
the hook adds no packages to the process it is loaded into. TypeScript and the
Node type definitions are the only development dependencies.

## Install

Build once:

```sh
npm install
npm run build
```

Then load it before the application starts. Either form works:

```sh
node --require /path/to/hooks/node/dist/preload.js app.js
```

```sh
NODE_OPTIONS="--require /path/to/hooks/node/dist/preload.js" node app.js
```

The application source is not modified. The second form is the one to put in a
container definition or a CI job, because it reaches a process whose command
line you do not control.

Note that `NODE_OPTIONS` is inherited by every child process. The hook expects
this and leaves package managers and build tools alone by itself; see the
process gate below.

## What it writes

One directory, two files per process:

| File | Contents |
|---|---|
| `node-<pid>.ndjson` | One egress event per line, each valid against `egress-event.schema.json` |
| `node-<pid>.status.json` | What the hook itself did: whether it was active, how many events it recorded, how many it dropped, how many internal failures it swallowed |

The status file is separate on purpose. The event schema is a closed set of
properties, so a status line written into the event stream would make that
stream fail its own contract. Keeping the two apart also preserves the
difference between "no calls were made" and "the hook never ran", which is a
difference a coverage report has to be able to state.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `PERISKOP_HOOK` | unset | Set to `0` to turn the hook off completely. Checked before anything else, so a disabled hook costs one lookup |
| `PERISKOP_HOOK_DIR` | `<tmpdir>/periskop-events` | Directory the event stream and status file are written to |
| `PERISKOP_HOOK_ENTRYPOINT` | basename of `argv[1]` | Name for this process in the event. Never a path; the schema rejects absolute paths in this field |
| `PERISKOP_HOOK_BODY_LIMIT` | `65536` | Bodies larger than this are not parsed for field paths. The event declares the omission rather than reporting an empty shape |
| `PERISKOP_HOOK_BUFFER` | `1024` | Events held in memory before the oldest are dropped. Drops are counted in the status file |
| `PERISKOP_HOOK_DEBUG` | unset | Set to `1` to print internal failures to stderr. Off by default, because a hook should not write to an application's output |
| `PERISKOP_HOOK_STATUS` | written by the hook | Set to `disabled:<reason>` when the hook takes itself out of the way, so that a process running unhooked says so |

## The process gate

A process is skipped, at no cost, when any of these is true:

- `PERISKOP_HOOK=0`
- the Node major version is below 20
- `argv[1]` names a package manager or build tool (`npm`, `npx`, `pnpm`, `yarn`,
  `corepack`, `tsc`, `node-gyp` and the like)

The check runs before the patches, the hash and the writer are loaded, so a
skipped process compares a few strings and then does nothing at all. The deny
list matches whole names, never prefixes: a script called `npm-metrics.js` is an
application and is instrumented.

That list is the one place where periskop's inverse-list principle is suspended,
so it is kept short. Every name on it is a class of egress the hook agrees not
to see.

## The fail-open guarantee

**A failure in the hook cannot affect the application.** This is not a quality
goal, it is a constraint, and there is no flag that relaxes it.

Concretely:

- The original function is called first, with the arguments and the receiver it
  was given, outside any `try` block of ours. Its return value is passed back
  untouched and its exceptions propagate exactly as they did before.
- Observation runs afterwards, inside a boundary that swallows everything. A
  broken patch, an unwritable event file, a body that cannot be parsed: none of
  it reaches the caller.
- Installation failures leave the process unhooked rather than stopped. A broken
  build artifact, a missing module, a directory that cannot be created, an
  incompatible Node version: the application starts and runs normally.
- The hook never keeps a process alive. Its flush timer is unreferenced, and its
  only synchronous write happens at exit, where there is no call path left to
  slow down.
- Failures are counted, not hidden. Every swallowed error increments a counter
  that lands in the status file.

The reasoning, from spec section 5: a call the hook missed shows up in the
coverage report as a gap somebody can close. A production service the hook took
down is an incident nobody can undo. An observation tool does not break the
thing it observes.

Each of these claims has a test. `preload.test.js` starts real child processes
with a broken artifact, a missing module and an unusable output path, and
asserts the application still finishes its work.

## What is not recorded

The hook produces a closed list of fields (ADR-011 section 7). It does not:

- copy or materialise a request body
- run entity recognition, dictionary matching or pattern scanning over a body,
  in any mode, under any flag
- produce entity type counts
- read a stream to measure it

`byte_size_estimate` is an estimate rather than a measurement for that last
reason. In Node a request body is usually a stream, and a stream is read once:
measuring it would take the bytes away from the socket and break the program
under observation. When the size could not be observed, the event says so
through `degraded_reasons`.

`payload_shape.field_paths` carries field *paths* and never values. Keys are
handled as carefully as values, because a key can carry data just as readily:
a map keyed by customer email would otherwise copy those addresses straight into
the record. So keys outside a closed allow list of provider schema words are
replaced with `<dyn>`, and a pattern filter runs over key strings first. Depth
is capped at six and long arrays are sampled; both are declared through
`truncated_depth` and `degraded_reasons` so that a shallow record is not
misread as a small payload.

The test named "no value from the payload reaches the field paths" builds a body
out of account numbers, API keys, medical text, a card number and an email
address used as an object key, then asserts that none of them, and none of their
fragments, appears anywhere in the output.

The hook also sends nothing anywhere. Events go to a local file. periskop is not
an egress source.

## Known limits

- Only the transport layer is patched (`node:http`, `node:https` and global
  `fetch`). SDK level detail such as a method name is not available, so
  `library.mechanism` is always `http_client` and `operation` is the HTTP
  method. The schema notes that this is the weaker of the two observation kinds.
- A client that bypasses these layers, for example one built directly on
  `node:tls` or a native module, is not seen. Detection for that case falls to
  the network sensor.
- `call_shape_hash` cannot be produced here: it is defined over a syntax tree,
  and a transport hook sees a socket. It is left empty in the identity input
  rather than invented.
- A body written in more than one piece is counted but not reassembled, so its
  field paths are unavailable. Putting the pieces back together is exactly the
  copy this hook exists to avoid.

## Development

```sh
npm run lint    # tsc --noEmit
npm run build   # tsc
npm test        # node --test dist/*.test.js
```

Test files mirror source files one for one. A module and its test sit at the
same path.
