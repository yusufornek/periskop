// Known gap: the call goes through an interface value.
//
// Which implementation runs is decided where the dependency is wired, usually in
// another file and often in another package. At this call site the tree holds a
// method on an interface and nothing that names a provider, so there is no
// evidence to report and none is invented. Go leans on this shape harder than
// most languages, because interfaces are the ordinary way to keep a provider
// swappable rather than a pattern reserved for tests.
//
// The runtime hooks cannot close it either: ADR-009 has no language native hook
// for a statically linked Go binary, so the second source here is the network
// sensor, which sees the destination and the volume but not the payload.
//
// Catalogued as KG-003 in the known gaps list.
package evasion

import "context"

type chatter interface {
	Send(ctx context.Context, prompt string) (string, error)
}

func summarize(ctx context.Context, llm chatter, record string) (string, error) {
	return llm.Send(ctx, record)
}
