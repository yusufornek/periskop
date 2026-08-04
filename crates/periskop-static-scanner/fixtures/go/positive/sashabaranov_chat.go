// The community client, which is what most existing Go services are built on.
//
// The package name is derived from the repository name here, not written down:
// `go-openai` is imported as `openai`. The blank import next to it is deliberate,
// because a side effect import binds no name at all and a resolver that bound one
// would hand a rule a receiver that does not exist.
package positive

import (
	"context"

	_ "github.com/lib/pq"

	"github.com/sashabaranov/go-openai"
)

func classify(ctx context.Context, record string) (string, error) {
	client := openai.NewClient("token")
	resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: openai.GPT4,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: record},
		},
	})
	if err != nil {
		return "", err
	}
	return resp.Choices[0].Message.Content, nil
}
