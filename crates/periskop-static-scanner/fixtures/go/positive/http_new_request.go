// Request construction, where the URL does not lead the argument list.
//
// Both forms are here because the URL sits in a different place in each, and a
// single pattern anchored at one position would silently cover only one of them.
package positive

import (
	"context"
	"net/http"
	"strings"
)

func askViaRequest(record string) (*http.Request, error) {
	return http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(record))
}

func askViaContext(ctx context.Context, record string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodPost, "https://api.openai.com/v1/responses", strings.NewReader(record))
}
