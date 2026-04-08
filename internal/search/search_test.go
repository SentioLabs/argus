package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse_BareWords(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantSemantic string
		wantFilters  map[string]string
		wantID       bool
	}{
		{
			name:         "empty input",
			input:        "",
			wantSemantic: "",
			wantFilters:  map[string]string{},
			wantID:       false,
		},
		{
			name:         "single bare word",
			input:        "lodash",
			wantSemantic: "lodash",
			wantFilters:  map[string]string{},
			wantID:       false,
		},
		{
			name:         "multiple bare words",
			input:        "remote code execution vulnerability",
			wantSemantic: "remote code execution vulnerability",
			wantFilters:  map[string]string{},
			wantID:       false,
		},
		{
			name:         "extra whitespace trimmed",
			input:        "  heap overflow  ",
			wantSemantic: "heap overflow",
			wantFilters:  map[string]string{},
			wantID:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.input)
			assert.Equal(t, tt.wantSemantic, got.SemanticText)
			assert.Equal(t, tt.wantFilters, got.Filters)
			assert.Equal(t, tt.wantID, got.IsIDLookup)
			assert.Empty(t, got.RawID)
		})
	}
}

func TestParse_FieldFilters(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantFilters map[string]string
		wantSemantic string
	}{
		{
			name:        "severity filter",
			input:       "severity:critical",
			wantFilters: map[string]string{"severity": "critical"},
			wantSemantic: "",
		},
		{
			name:        "package filter",
			input:       "package:lodash",
			wantFilters: map[string]string{"package": "lodash"},
			wantSemantic: "",
		},
		{
			name:        "repo alias maps to repository",
			input:       "repo:my-repo",
			wantFilters: map[string]string{"repository": "my-repo"},
			wantSemantic: "",
		},
		{
			name:        "repository long form",
			input:       "repository:my-org/my-repo",
			wantFilters: map[string]string{"repository": "my-org/my-repo"},
			wantSemantic: "",
		},
		{
			name:        "provider filter",
			input:       "provider:github",
			wantFilters: map[string]string{"provider": "github"},
			wantSemantic: "",
		},
		{
			name:        "cve filter",
			input:       "cve:CVE-2023-1234",
			wantFilters: map[string]string{"cve": "CVE-2023-1234"},
			wantSemantic: "",
		},
		{
			name:        "id filter",
			input:       "id:SNYK-JS-LODASH-1234",
			wantFilters: map[string]string{"id": "SNYK-JS-LODASH-1234"},
			wantSemantic: "",
		},
		{
			name:  "multiple filters",
			input: "severity:high provider:snyk",
			wantFilters: map[string]string{
				"severity": "high",
				"provider": "snyk",
			},
			wantSemantic: "",
		},
		{
			name:  "unrecognized prefix treated as bare word",
			input: "unknown:value",
			wantFilters: map[string]string{},
			wantSemantic: "unknown:value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.input)
			assert.Equal(t, tt.wantFilters, got.Filters)
			assert.Equal(t, tt.wantSemantic, got.SemanticText)
			assert.False(t, got.IsIDLookup)
		})
	}
}

func TestParse_Hybrid(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantSemantic string
		wantFilters  map[string]string
	}{
		{
			name:         "filter then bare words",
			input:        "severity:high remote code execution",
			wantSemantic: "remote code execution",
			wantFilters:  map[string]string{"severity": "high"},
		},
		{
			name:         "bare words then filter",
			input:        "heap overflow severity:critical",
			wantSemantic: "heap overflow",
			wantFilters:  map[string]string{"severity": "critical"},
		},
		{
			name:         "bare words between filters",
			input:        "severity:high sql injection provider:snyk",
			wantSemantic: "sql injection",
			wantFilters: map[string]string{
				"severity": "high",
				"provider": "snyk",
			},
		},
		{
			name:         "multiple filters with bare words",
			input:        "repo:my-repo buffer overflow severity:medium",
			wantSemantic: "buffer overflow",
			wantFilters: map[string]string{
				"repository": "my-repo",
				"severity":   "medium",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.input)
			assert.Equal(t, tt.wantSemantic, got.SemanticText)
			assert.Equal(t, tt.wantFilters, got.Filters)
			assert.False(t, got.IsIDLookup)
			assert.Empty(t, got.RawID)
		})
	}
}

func TestParse_IDLookup(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantID    bool
		wantRawID string
	}{
		{
			name:      "SNYK ID",
			input:     "SNYK-JS-LODASH-567522",
			wantID:    true,
			wantRawID: "SNYK-JS-LODASH-567522",
		},
		{
			name:      "GHSA ID",
			input:     "GHSA-jfh8-c2jp-hdlg",
			wantID:    true,
			wantRawID: "GHSA-jfh8-c2jp-hdlg",
		},
		{
			name:      "CVE ID",
			input:     "CVE-2023-44487",
			wantID:    true,
			wantRawID: "CVE-2023-44487",
		},
		{
			name:      "non-ID that starts with C is not an ID lookup",
			input:     "CRITICAL",
			wantID:    false,
			wantRawID: "",
		},
		{
			name:      "bare word that starts with SNYK but is not a valid ID",
			input:     "SNYK",
			wantID:    false,
			wantRawID: "",
		},
		{
			name:      "ID with extra tokens is not an ID lookup",
			input:     "CVE-2023-44487 extra",
			wantID:    false,
			wantRawID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.input)
			assert.Equal(t, tt.wantID, got.IsIDLookup)
			assert.Equal(t, tt.wantRawID, got.RawID)
		})
	}
}
