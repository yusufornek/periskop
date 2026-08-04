# Detection corpus

Input for the benchmark that measures how much of the real egress in a codebase
the scanner finds.

## Why the corpus is nearly empty

Labeling has to be blind. Someone who has read the rules will label the cases
the rules already handle, and skip the ones they do not, without intending to.
The result is a benchmark that scores well and measures nothing.

So the entries here are limited to the fixture set, which is labeled by
construction, and adding real repositories is a task for someone who has not
worked on the rule set. That constraint is the point rather than an obstacle:
a number produced by grading your own work is worse than no number, because it
gets quoted.

## Adding a repository

1. Pick a repository and pin a commit. Never vendor the source.
2. Label it without reading `rules/`. For every call that sends data to a model
   provider, record the file, the line and the provider.
3. Add the entry to `corpus.toml` and the labels to `labels/<id>.jsonl`.

One entry should be a negative control: a project that uses no provider SDK.
Without one, a rule set that fires too eagerly is indistinguishable from one
that fires correctly.

## Label format

One JSON object per line:

```json
{"path": "src/summarize.py", "line": 42, "provider": "openai", "note": "chat completions"}
```

`note` is free text and is not used in scoring. It exists so a disagreement
between a label and a finding can be settled by reading rather than by guessing.
