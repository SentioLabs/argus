package search

import (
	"regexp"
	"strings"
)

// Query represents a parsed search input.
type Query struct {
	SemanticText string            // bare words for EMBED()
	Filters      map[string]string // field:value pairs for WHERE clauses
	IsIDLookup   bool              // true if query looks like SNYK-*/GHSA-*/CVE-*
	RawID        string            // the raw ID for direct lookup
}

// knownFields maps recognized field prefixes to their canonical filter keys.
// A value of "" means the field name maps to itself.
var knownFields = map[string]string{
	"severity":   "severity",
	"package":    "package",
	"repo":       "repository",
	"repository": "repository",
	"provider":   "provider",
	"cve":        "cve",
	"id":         "id",
}

// vulnIDPattern matches standalone vulnerability IDs:
// SNYK-<anything>, GHSA-<anything>, CVE-YYYY-NNNNN
var vulnIDPattern = regexp.MustCompile(`^(?:SNYK-\S+|GHSA-\S+|CVE-\d{4}-\d+)$`)

// Parse splits a raw query string into a structured Query.
func Parse(raw string) Query {
	q := Query{
		Filters: make(map[string]string),
	}

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return q
	}

	tokens := strings.Fields(raw)

	// Single token: check for ID lookup first.
	if len(tokens) == 1 {
		if vulnIDPattern.MatchString(tokens[0]) {
			q.IsIDLookup = true
			q.RawID = tokens[0]
			return q
		}
	}

	// Multiple tokens (or single non-ID token): split into filters and bare words.
	var bareWords []string
	for _, tok := range tokens {
		colonIdx := strings.Index(tok, ":")
		if colonIdx > 0 {
			prefix := tok[:colonIdx]
			value := tok[colonIdx+1:]
			if canonical, ok := knownFields[prefix]; ok && value != "" {
				q.Filters[canonical] = value
				continue
			}
		}
		bareWords = append(bareWords, tok)
	}

	q.SemanticText = strings.Join(bareWords, " ")
	return q
}
