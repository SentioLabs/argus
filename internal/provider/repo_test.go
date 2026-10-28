package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRepoMatches(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		repo     string
		expected bool
	}{
		{"github exact", "bactrack/bacstack", "bactrack/bacstack", true},
		{"case insensitive", "Bactrack/BacStack", "bactrack/bacstack", true},
		{"snyk target file", "bactrack/bacstack", "bactrack/bacstack:package.json", true},
		{"snyk branch and nested target", "bactrack/bacstack", "bactrack/bacstack(main):services/api/go.mod", true},
		{"glob on repo part", "bactrack/bac*", "bactrack/bacstack(main):services/api/go.mod", true},
		{"org glob", "bactrack/*", "bactrack/bacstack:go.mod", true},
		{"full snyk name still matches", "bactrack/bacstack:go.mod", "bactrack/bacstack:go.mod", true},
		{"no prefix match", "bactrack/bacstack", "bactrack/bacstack-legacy:go.mod", false},
		{"different org", "bactrack/bacstack", "other/bacstack", false},
		{"bare repo name does not match", "bacstack", "bactrack/bacstack", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, RepoMatches(tt.pattern, tt.repo))
		})
	}
}

func TestApplyRepoScope(t *testing.T) {
	names := []string{"BACtrack/view-api:Dockerfile", "BACtrack/bacstack-api:go.mod", "BACtrack/bacstack-api"}
	identity := func(s string) string { return s }

	assert.Equal(t, names, applyRepoScope("", names, identity), "empty scope keeps everything")
	assert.Equal(t, []string{"BACtrack/bacstack-api:go.mod", "BACtrack/bacstack-api"},
		applyRepoScope("bactrack/bacstack-api", names, identity))
	assert.Empty(t, applyRepoScope("BACtrack/bacstack", names, identity))
}

func TestSnykFilterProjectsAppliesScopeAfterExcludes(t *testing.T) {
	p := &SnykProvider{
		projectExcludes: []string{"BACtrack/bacstack-api"},
		repoScope:       "BACtrack/bacstack-api*",
	}
	projects := []snykProject{
		{ID: "1", Name: "BACtrack/bacstack-api"},
		{ID: "2", Name: "BACtrack/bacstack-api:go.mod"},
		{ID: "3", Name: "BACtrack/view-api:Dockerfile"},
	}

	assert.Equal(t, []snykProject{{ID: "2", Name: "BACtrack/bacstack-api:go.mod"}}, p.filterProjects(projects))
}

func TestSuggestRepos(t *testing.T) {
	names := []string{
		"BACtrack/bacstack-api:go.mod",
		"BACtrack/bacstack-api",
		"BACtrack/view-api:Dockerfile",
		"BACtrack/bacstack-web(main):package.json",
	}

	tests := []struct {
		name     string
		pattern  string
		expected []string
	}{
		{"dedupes and strips suffixes", "BACtrack/bacstack", []string{"BACtrack/bacstack-api", "BACtrack/bacstack-web"}},
		{"mistyped org", "bactrak/bacstack", []string{"BACtrack/bacstack-api", "BACtrack/bacstack-web"}},
		{"glob characters ignored", "BACtrack/bacstack*", []string{"BACtrack/bacstack-api", "BACtrack/bacstack-web"}},
		{"nothing similar", "BACtrack/billing", nil},
		{"bare wildcard", "*", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, suggestRepos(tt.pattern, names))
		})
	}
}

func TestSuggestReposCapsResults(t *testing.T) {
	names := []string{"o/app-1", "o/app-2", "o/app-3", "o/app-4", "o/app-5", "o/app-6"}
	assert.Len(t, suggestRepos("o/app", names), maxRepoSuggestions)
}
