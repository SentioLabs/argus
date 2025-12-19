package config

import "testing"

func TestConfig_GetJiraPriority(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{
			Jira: JiraConfig{
				PriorityMap: map[string]string{
					"critical": "Highest",
					"high":     "High",
					"medium":   "Medium",
					"low":      "Low",
				},
			},
		},
	}

	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "Highest"},
		{"CRITICAL", "Highest"}, // case insensitive
		{"high", "High"},
		{"medium", "Medium"},
		{"low", "Low"},
		{"unknown", "Medium"}, // default
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			if got := cfg.GetJiraPriority(tt.severity); got != tt.want {
				t.Errorf("GetJiraPriority(%q) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

func TestConfig_GetProviderJira(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{
			Jira: JiraConfig{
				Project:    "SEC",
				BoardName:  "Security Board",
				Assignee:   "default-user",
				Labels:     []string{"security"},
				Components: []string{"security"},
			},
		},
		Providers: map[string]ProviderConfig{
			"github": {
				Jira: &JiraConfig{
					Assignee: "github-lead",
					Labels:   []string{"github", "dependabot"},
				},
			},
			"snyk": {
				// No Jira override
			},
		},
	}

	t.Run("provider with overrides", func(t *testing.T) {
		jira := cfg.GetProviderJira("github")
		if jira.Project != "SEC" {
			t.Errorf("expected default project SEC, got %s", jira.Project)
		}
		if jira.Assignee != "github-lead" {
			t.Errorf("expected overridden assignee github-lead, got %s", jira.Assignee)
		}
		if len(jira.Labels) != 2 || jira.Labels[0] != "github" {
			t.Errorf("expected overridden labels, got %v", jira.Labels)
		}
	})

	t.Run("provider without overrides", func(t *testing.T) {
		jira := cfg.GetProviderJira("snyk")
		if jira.Assignee != "default-user" {
			t.Errorf("expected default assignee, got %s", jira.Assignee)
		}
	})

	t.Run("unknown provider", func(t *testing.T) {
		jira := cfg.GetProviderJira("unknown")
		if jira.Project != "SEC" {
			t.Errorf("expected default values for unknown provider, got %s", jira.Project)
		}
	})
}

func TestConfig_GetProviderFilters(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{
			Filters: FiltersConfig{
				SeverityThreshold: "medium",
				MaxAgeDays:        90,
				CVSSMin:           4.0,
			},
		},
		Providers: map[string]ProviderConfig{
			"snyk": {
				Filters: &FiltersConfig{
					SeverityThreshold: "high",
				},
			},
		},
	}

	t.Run("provider with filter override", func(t *testing.T) {
		filters := cfg.GetProviderFilters("snyk")
		if filters.SeverityThreshold != "high" {
			t.Errorf("expected overridden severity threshold high, got %s", filters.SeverityThreshold)
		}
		if filters.MaxAgeDays != 90 {
			t.Errorf("expected default max age days 90, got %d", filters.MaxAgeDays)
		}
	})

	t.Run("provider without filter override", func(t *testing.T) {
		filters := cfg.GetProviderFilters("github")
		if filters.SeverityThreshold != "medium" {
			t.Errorf("expected default severity threshold, got %s", filters.SeverityThreshold)
		}
	})
}

func TestSeverityOrder(t *testing.T) {
	if SeverityOrder["critical"] <= SeverityOrder["high"] {
		t.Error("critical should be higher than high")
	}
	if SeverityOrder["high"] <= SeverityOrder["medium"] {
		t.Error("high should be higher than medium")
	}
	if SeverityOrder["medium"] <= SeverityOrder["low"] {
		t.Error("medium should be higher than low")
	}
}

func TestConfig_GetRepoFilter(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{
			Filters: FiltersConfig{
				SeverityThreshold: "medium",
				MaxAgeDays:        90,
				CVSSMin:           4.0,
			},
		},
		Providers: map[string]ProviderConfig{
			"github": {
				Filters: &FiltersConfig{
					SeverityThreshold: "high",
				},
				RepoIncludes: []RepoInclude{
					{Name: "org/repo-a"},
					{
						Name: "org/repo-b",
						Filters: &FiltersConfig{
							SeverityThreshold: "critical",
						},
					},
					{
						Name: "org/api-*",
						Filters: &FiltersConfig{
							CVSSMin: 7.0,
						},
					},
				},
			},
			"snyk": {
				ProjectIncludes: []RepoInclude{
					{
						Name: "proj-critical",
						Filters: &FiltersConfig{
							SeverityThreshold: "critical",
						},
					},
				},
			},
		},
	}

	t.Run("defaults only (unknown provider)", func(t *testing.T) {
		filters := cfg.GetRepoFilter("unknown", "any-repo")
		if filters.SeverityThreshold != "medium" {
			t.Errorf("expected default severity threshold, got %s", filters.SeverityThreshold)
		}
		if filters.MaxAgeDays != 90 {
			t.Errorf("expected default max age days, got %d", filters.MaxAgeDays)
		}
	})

	t.Run("provider-level override", func(t *testing.T) {
		filters := cfg.GetRepoFilter("github", "org/other-repo")
		if filters.SeverityThreshold != "high" {
			t.Errorf("expected provider severity threshold high, got %s", filters.SeverityThreshold)
		}
		if filters.MaxAgeDays != 90 {
			t.Errorf("expected inherited max age days, got %d", filters.MaxAgeDays)
		}
	})

	t.Run("repo-level override", func(t *testing.T) {
		filters := cfg.GetRepoFilter("github", "org/repo-b")
		if filters.SeverityThreshold != "critical" {
			t.Errorf("expected repo severity threshold critical, got %s", filters.SeverityThreshold)
		}
		if filters.MaxAgeDays != 90 {
			t.Errorf("expected inherited max age days, got %d", filters.MaxAgeDays)
		}
	})

	t.Run("repo without filter override inherits provider", func(t *testing.T) {
		filters := cfg.GetRepoFilter("github", "org/repo-a")
		if filters.SeverityThreshold != "high" {
			t.Errorf("expected provider severity threshold, got %s", filters.SeverityThreshold)
		}
	})

	t.Run("pattern matching repo override", func(t *testing.T) {
		filters := cfg.GetRepoFilter("github", "org/api-service")
		if filters.CVSSMin != 7.0 {
			t.Errorf("expected pattern-matched CVSS min 7.0, got %f", filters.CVSSMin)
		}
		if filters.SeverityThreshold != "high" {
			t.Errorf("expected provider severity threshold (not overridden), got %s", filters.SeverityThreshold)
		}
	})

	t.Run("snyk project-level override", func(t *testing.T) {
		filters := cfg.GetRepoFilter("snyk", "proj-critical")
		if filters.SeverityThreshold != "critical" {
			t.Errorf("expected project severity threshold critical, got %s", filters.SeverityThreshold)
		}
	})
}
