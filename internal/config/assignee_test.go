package config

import "testing"

func TestAssigneeResolver_Resolve(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{
			Jira: JiraConfig{
				Assignee: "global-default",
			},
		},
		Providers: map[string]ProviderConfig{
			"github": {
				Jira: &JiraConfig{
					Assignee: "github-lead",
				},
				RepoIncludes: []RepoInclude{
					{Name: "org/repo1", Assignee: "team-a-lead"},
					{Name: "org/repo2", Assignee: "team-b-lead"},
					{Name: "org/api-*", Assignee: "api-team-lead"}, // Pattern with assignee
				},
			},
			"snyk": {
				// No Jira override, no repo includes - should use global default
			},
			"provider-with-repos-only": {
				// Has repo includes but no provider-level assignee
				RepoIncludes: []RepoInclude{
					{Name: "org/special", Assignee: "special-owner"},
				},
			},
		},
	}

	resolver := NewAssigneeResolver(cfg)

	tests := []struct {
		name       string
		provider   string
		repository string
		want       string
	}{
		{
			name:       "repo-level override",
			provider:   "github",
			repository: "org/repo1",
			want:       "team-a-lead",
		},
		{
			name:       "different repo-level override",
			provider:   "github",
			repository: "org/repo2",
			want:       "team-b-lead",
		},
		{
			name:       "pattern match with assignee",
			provider:   "github",
			repository: "org/api-service",
			want:       "api-team-lead",
		},
		{
			name:       "provider-level fallback for unknown repo",
			provider:   "github",
			repository: "org/repo3",
			want:       "github-lead",
		},
		{
			name:       "global default for provider without overrides",
			provider:   "snyk",
			repository: "any-project",
			want:       "global-default",
		},
		{
			name:       "unknown provider uses global default",
			provider:   "unknown",
			repository: "any-repo",
			want:       "global-default",
		},
		{
			name:       "repo override without provider-level assignee",
			provider:   "provider-with-repos-only",
			repository: "org/special",
			want:       "special-owner",
		},
		{
			name:       "repo not in includes falls back to provider then global",
			provider:   "provider-with-repos-only",
			repository: "org/other",
			want:       "global-default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolver.Resolve(tt.provider, tt.repository)
			if got != tt.want {
				t.Errorf("Resolve(%q, %q) = %q, want %q",
					tt.provider, tt.repository, got, tt.want)
			}
		})
	}
}

func TestAssigneeResolver_EmptyAssignees(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{
			Jira: JiraConfig{
				// No assignee set
			},
		},
		Providers: map[string]ProviderConfig{
			"github": {
				// No overrides
			},
		},
	}

	resolver := NewAssigneeResolver(cfg)

	got := resolver.Resolve("github", "org/repo")
	if got != "" {
		t.Errorf("expected empty assignee when none configured, got %q", got)
	}
}

func TestAssigneeResolver_PatternWithoutAssignee(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{
			Jira: JiraConfig{
				Assignee: "global-default",
			},
		},
		Providers: map[string]ProviderConfig{
			"github": {
				Jira: &JiraConfig{
					Assignee: "github-lead",
				},
				RepoIncludes: []RepoInclude{
					{Name: "org/api-*"}, // Pattern without assignee - should fall back
				},
			},
		},
	}

	resolver := NewAssigneeResolver(cfg)

	// Pattern matches but has no assignee - should fall back to provider level
	got := resolver.Resolve("github", "org/api-service")
	if got != "github-lead" {
		t.Errorf("pattern without assignee should fall back to provider, got %q", got)
	}
}

func TestMatchRepoPattern(t *testing.T) {
	tests := []struct {
		pattern string
		repo    string
		want    bool
	}{
		{"org/repo", "org/repo", true},          // Exact match
		{"org/repo", "org/other", false},        // No match
		{"org/api-*", "org/api-service", true},  // Glob match
		{"org/api-*", "org/web-service", false}, // No glob match
		{"org/*-service", "org/api-service", true},
		{"org/[ab]bc", "org/abc", true}, // Character class
		{"org/[ab]bc", "org/bbc", true},
		{"org/[ab]bc", "org/cbc", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.repo, func(t *testing.T) {
			got := matchRepoPattern(tt.pattern, tt.repo)
			if got != tt.want {
				t.Errorf("matchRepoPattern(%q, %q) = %v, want %v",
					tt.pattern, tt.repo, got, tt.want)
			}
		})
	}
}

func TestAssigneeResolver_GetCandidates(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{
			Jira: JiraConfig{
				Assignee: "global@example.com",
			},
		},
		Providers: map[string]ProviderConfig{
			"github": {
				Jira: &JiraConfig{
					Assignee: "github@example.com",
				},
				RepoIncludes: []RepoInclude{
					{Name: "org/repo1", Assignee: "repo1@example.com"},
				},
			},
			"snyk": {
				// No Jira override - should only have global
			},
		},
	}

	resolver := NewAssigneeResolver(cfg)

	tests := []struct {
		name       string
		provider   string
		repository string
		want       []string
	}{
		{
			name:       "all three levels",
			provider:   "github",
			repository: "org/repo1",
			want:       []string{"repo1@example.com", "github@example.com", "global@example.com"},
		},
		{
			name:       "provider and global only",
			provider:   "github",
			repository: "org/other",
			want:       []string{"github@example.com", "global@example.com"},
		},
		{
			name:       "global only",
			provider:   "snyk",
			repository: "any-project",
			want:       []string{"global@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolver.GetCandidates(tt.provider, tt.repository)
			if len(got) != len(tt.want) {
				t.Errorf("GetCandidates() returned %d candidates, want %d: got %v, want %v",
					len(got), len(tt.want), got, tt.want)
				return
			}
			for i, candidate := range got {
				if candidate != tt.want[i] {
					t.Errorf("GetCandidates()[%d] = %q, want %q", i, candidate, tt.want[i])
				}
			}
		})
	}
}

func TestAssigneeResolver_GetCandidates_NoDuplicates(t *testing.T) {
	// When provider and global have the same assignee, should not duplicate
	cfg := &Config{
		Defaults: DefaultsConfig{
			Jira: JiraConfig{
				Assignee: "same@example.com",
			},
		},
		Providers: map[string]ProviderConfig{
			"github": {
				Jira: &JiraConfig{
					Assignee: "same@example.com", // Same as global
				},
			},
		},
	}

	resolver := NewAssigneeResolver(cfg)
	got := resolver.GetCandidates("github", "any-repo")

	// Should only have one entry, not duplicated
	if len(got) != 1 {
		t.Errorf("expected 1 candidate (no duplicates), got %d: %v", len(got), got)
	}
	if got[0] != "same@example.com" {
		t.Errorf("expected 'same@example.com', got %q", got[0])
	}
}
