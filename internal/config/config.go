// Package config handles the loading and management of Argus's configuration.
// It supports loading from a YAML configuration file and environment variables,
// with environment variables taking precedence.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// SeverityOrder defines Argus's canonical severity levels from lowest to highest.
// Provider-specific values (e.g., GitHub's "moderate") are normalized via SeverityMappings.
var SeverityOrder = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Config represents the full application configuration.
// It combines secrets loaded from environment variables and settings from the config file.
type Config struct {
	// Secrets (loaded from environment variables)
	GitHubToken  string `mapstructure:"github_token"`
	SnykToken    string `mapstructure:"snyk_token"`
	JiraURL      string `mapstructure:"jira_url"`
	JiraUsername string `mapstructure:"jira_username"`
	JiraToken    string `mapstructure:"jira_token"`

	// Config file settings
	Defaults  DefaultsConfig            `mapstructure:"defaults"`
	Providers map[string]ProviderConfig `mapstructure:"providers"`
}

// DefaultsConfig contains base configuration inherited by all providers
type DefaultsConfig struct {
	Jira             JiraConfig        `mapstructure:"jira"`
	Thresholds       ThresholdsConfig  `mapstructure:"thresholds"`
	Filters          FiltersConfig     `mapstructure:"filters"`
	SeverityMappings map[string]string `mapstructure:"severity_mappings"`
}

// JiraConfig contains Jira-specific settings
type JiraConfig struct {
	Project    string   `mapstructure:"project"`
	BoardID    int      `mapstructure:"board_id"`
	BoardName  string   `mapstructure:"board_name"`
	Assignee   string   `mapstructure:"assignee"`
	Labels     []string `mapstructure:"labels"`
	Components []string `mapstructure:"components"`
}

// ThresholdsConfig contains severity threshold mappings
type ThresholdsConfig struct {
	Priority          map[string]string `mapstructure:"priority"`
	SprintMinSeverity string            `mapstructure:"sprint_min_severity"`
}

// FiltersConfig contains filtering settings
type FiltersConfig struct {
	MinSeverity     string   `mapstructure:"min_severity"`
	MaxAgeDays      int      `mapstructure:"max_age_days"`
	CVSSMin         float64  `mapstructure:"cvss_min"`
	Packages        []string `mapstructure:"packages"`
	ExcludePackages []string `mapstructure:"exclude_packages"`
}

// ProviderConfig contains provider-specific configuration
type ProviderConfig struct {
	Enabled bool `mapstructure:"enabled"`

	// GitHub-specific
	Orgs         []string `mapstructure:"orgs"`
	Repos        []string `mapstructure:"repos"`
	RepoPatterns []string `mapstructure:"repo_patterns"`
	ExcludeRepos []string `mapstructure:"exclude_repos"`

	// Snyk-specific
	OrgID           string   `mapstructure:"org_id"`
	ProjectIDs      []string `mapstructure:"project_ids"`
	ProjectPatterns []string `mapstructure:"project_patterns"`
	ExcludeProjects []string `mapstructure:"exclude_projects"`
	APIVersion      string   `mapstructure:"api_version"` // Snyk REST API version (e.g., "2024-10-15")

	// Overrides for defaults
	Jira    *JiraConfig    `mapstructure:"jira"`
	Filters *FiltersConfig `mapstructure:"filters"`
}

// Load reads the configuration from the config file and environment variables.
// It applies default values for missing optional fields.
func Load() (*Config, error) {
	var cfg Config

	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set defaults if not specified
	setDefaults(&cfg)

	return &cfg, nil
}

// setDefaults ensures all required fields have sensible defaults
func setDefaults(cfg *Config) {
	if cfg.Defaults.Thresholds.Priority == nil {
		cfg.Defaults.Thresholds.Priority = map[string]string{
			"critical": "Highest",
			"high":     "High",
			"medium":   "Medium",
			"low":      "Low",
		}
	}

	if cfg.Defaults.Thresholds.SprintMinSeverity == "" {
		cfg.Defaults.Thresholds.SprintMinSeverity = "high"
	}

	if cfg.Defaults.Filters.MinSeverity == "" {
		cfg.Defaults.Filters.MinSeverity = "medium"
	}

	if cfg.Defaults.Filters.MaxAgeDays == 0 {
		cfg.Defaults.Filters.MaxAgeDays = 90
	}

	if cfg.Defaults.SeverityMappings == nil {
		cfg.Defaults.SeverityMappings = map[string]string{
			"moderate": "medium", // GitHub uses "moderate" instead of "medium"
		}
	}
}

// GetProviderJira returns the Jira configuration for a specific provider.
// It merges provider-specific overrides with the default Jira configuration.
func (c *Config) GetProviderJira(providerName string) JiraConfig {
	jira := c.Defaults.Jira

	provider, exists := c.Providers[providerName]
	if !exists || provider.Jira == nil {
		return jira
	}

	// Override with provider-specific values
	if provider.Jira.Project != "" {
		jira.Project = provider.Jira.Project
	}
	if provider.Jira.BoardID > 0 {
		jira.BoardID = provider.Jira.BoardID
	}
	if provider.Jira.BoardName != "" {
		jira.BoardName = provider.Jira.BoardName
	}
	if provider.Jira.Assignee != "" {
		jira.Assignee = provider.Jira.Assignee
	}
	if len(provider.Jira.Labels) > 0 {
		jira.Labels = provider.Jira.Labels
	}
	if len(provider.Jira.Components) > 0 {
		jira.Components = provider.Jira.Components
	}

	return jira
}

// GetProviderFilters returns the filter configuration for a specific provider.
// It merges provider-specific overrides with the default filter configuration.
func (c *Config) GetProviderFilters(providerName string) FiltersConfig {
	filters := c.Defaults.Filters

	provider, exists := c.Providers[providerName]
	if !exists || provider.Filters == nil {
		return filters
	}

	// Override with provider-specific values
	if provider.Filters.MinSeverity != "" {
		filters.MinSeverity = provider.Filters.MinSeverity
	}
	if provider.Filters.MaxAgeDays > 0 {
		filters.MaxAgeDays = provider.Filters.MaxAgeDays
	}
	if provider.Filters.CVSSMin > 0 {
		filters.CVSSMin = provider.Filters.CVSSMin
	}
	if len(provider.Filters.Packages) > 0 {
		filters.Packages = provider.Filters.Packages
	}
	if len(provider.Filters.ExcludePackages) > 0 {
		filters.ExcludePackages = provider.Filters.ExcludePackages
	}

	return filters
}

// GetJiraPriority maps a severity level to a Jira priority
func (c *Config) GetJiraPriority(severity string) string {
	severity = strings.ToLower(severity)
	if priority, exists := c.Defaults.Thresholds.Priority[severity]; exists {
		return priority
	}
	return "Medium" // default
}

// ShouldAddToSprint checks if a vulnerability should be added to the active sprint
func (c *Config) ShouldAddToSprint(severity string) bool {
	severity = strings.ToLower(severity)
	minSeverity := strings.ToLower(c.Defaults.Thresholds.SprintMinSeverity)

	severityLevel := SeverityOrder[severity]
	minLevel := SeverityOrder[minSeverity]

	return severityLevel >= minLevel
}

// NormalizeSeverity maps provider-specific severity values to Argus's canonical levels.
// For example, GitHub's "moderate" is mapped to "medium".
func (c *Config) NormalizeSeverity(severity string) string {
	severity = strings.ToLower(severity)
	if mapped, exists := c.Defaults.SeverityMappings[severity]; exists {
		return mapped
	}
	return severity
}
