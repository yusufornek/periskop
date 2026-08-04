// A CreateChatCompletion method on something unrelated to any provider SDK.
//
// The call shape is indistinguishable from the community OpenAI client, so the
// query matches and the binding is what drops it: the receiver was built by a
// local constructor, and an unqualified call names no package to resolve.
package negative

import "context"

type recordStore struct{}

func newRecordStore() *recordStore {
	return &recordStore{}
}

func (s *recordStore) CreateChatCompletion(ctx context.Context, req string) (string, error) {
	return req, nil
}

func save(ctx context.Context, record string) (string, error) {
	store := newRecordStore()
	return store.CreateChatCompletion(ctx, record)
}
