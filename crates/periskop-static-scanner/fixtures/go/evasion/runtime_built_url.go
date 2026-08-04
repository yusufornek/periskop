// Known gap: the destination is assembled at runtime.
//
// The scanner sees an identifier where the URL should be. Reporting it as a
// provider call would be a claim the source does not support, and reporting every
// http.Post with a variable argument would drown the findings that are supported.
//
// The rule that would otherwise catch this file keys on a literal URL, so the
// gap is a property of the evidence rather than of the pattern: no tightening of
// the query recovers a string that is only built while the program runs.
//
// Catalogued as KG-002 in the known gaps list.
package evasion

import (
	"net/http"
	"os"
	"strings"
)

func summarize(record string) (*http.Response, error) {
	endpoint := strings.TrimSuffix(os.Getenv("MODEL_ENDPOINT"), "/") + "/v1/chat/completions"
	return http.Post(endpoint, "application/json", strings.NewReader(record))
}
