// The official SDK behind an aliased import.
//
// The alias is what the call is written against, so a resolver that derived the
// package name from the path and stopped there would miss every call in this file.
package positive

import (
	"context"

	oai "github.com/openai/openai-go"
)

func summarize(ctx context.Context, record string) (string, error) {
	client := oai.NewClient()
	completion, err := client.Chat.Completions.New(ctx, oai.ChatCompletionNewParams{
		Model: "gpt-4o",
		Messages: []oai.ChatCompletionMessageParamUnion{
			oai.UserMessage(record),
		},
	})
	if err != nil {
		return "", err
	}
	return completion.Choices[0].Message.Content, nil
}
