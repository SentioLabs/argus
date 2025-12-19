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

func TestConfig_ShouldAddToSprint(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{
			Jira: JiraConfig{
				SprintThreshold: "high",
			},
		},
	}

	tests := []struct {
		severity string
		want     bool
	}{
		{"critical", true},
		{"high", true},
		{"CRITICAL", true}, // case insensitive
		{"medium", false},
		{"low", false},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			if got := cfg.ShouldAddToSprint(tt.severity); got != tt.want {
				t.Errorf("ShouldAddToSprint(%q) = %v, want %v", tt.severity, got, tt.want)
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
				MinSeverity: "medium",
				MaxAgeDays:  90,
				CVSSMin:     4.0,
			},
		},
		Providers: map[string]ProviderConfig{
			"snyk": {
				Filters: &FiltersConfig{
					MinSeverity: "high",
				},
			},
		},
	}

	t.Run("provider with filter override", func(t *testing.T) {
		filters := cfg.GetProviderFilters("snyk")
		if filters.MinSeverity != "high" {
			t.Errorf("expected overridden min severity high, got %s", filters.MinSeverity)
		}
		if filters.MaxAgeDays != 90 {
			t.Errorf("expected default max age days 90, got %d", filters.MaxAgeDays)
		}
	})

	t.Run("provider without filter override", func(t *testing.T) {
		filters := cfg.GetProviderFilters("github")
		if filters.MinSeverity != "medium" {
			t.Errorf("expected default min severity, got %s", filters.MinSeverity)
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
