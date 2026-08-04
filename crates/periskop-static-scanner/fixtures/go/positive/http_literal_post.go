// Raw HTTP to a provider endpoint, no SDK in sight.
//
// Go code reaches for the standard library client far more often than other
// ecosystems do, so this shape is not an edge case worth a footnote: it is a
// large share of the real egress in a Go codebase.
package positive

import (
	"net/http"
	"strings"
)

func askViaPost(record string) (*http.Response, error) {
	body := strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"x"}]}`)
	return http.Post("https://api.openai.com/v1/chat/completions", "application/json", body)
}
