// Looks like an egress call and is not one.
//
// The destination is an internal service. A rule that fired here would report
// every HTTP call in a Go codebase, and a report full of those trains the reader
// to skim past the findings that matter.
package negative

import (
	"net/http"
	"strings"
)

func enrich(record string) (*http.Response, error) {
	body := strings.NewReader(record)
	return http.Post("https://billing.internal.example/v1/enrich", "application/json", body)
}
