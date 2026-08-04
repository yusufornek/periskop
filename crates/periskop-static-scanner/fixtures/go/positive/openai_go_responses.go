// The same SDK through the responses surface, one selector shallower than the
// chat completions chain.
package positive

import (
	"context"

	"github.com/openai/openai-go"
)

func draft(ctx context.Context, record string) (string, error) {
	client := openai.NewClient()
	response, err := client.Responses.New(ctx, openai.ResponseNewParams{
		Model: "gpt-4o",
		Input: openai.ResponseNewParamsInputUnion{OfString: openai.String(record)},
	})
	if err != nil {
		return "", err
	}
	return response.OutputText(), nil
}
