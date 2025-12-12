package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sentiolabs/patrol/internal/config"
)

const (
	// HTTPTimeout is the timeout for HTTP requests to provider APIs
	HTTPTimeout = 30 * time.Second
	// APIPageSize is the number of items per page for API pagination
	APIPageSize = 100
)

// Vulnerability represents a security vulnerability from any provider
type Vulnerability struct {
	ID           string    `json:"id"`
	CVE          string    `json:"cve,omitempty"`
	Severity     string    `json:"severity"`
	CVSS         float64   `json:"cvss,omitempty"`
	Package      string    `json:"package"`
	Version      string    `json:"version,omitempty"`
	FixedVersion string    `json:"fixed_version,omitempty"`
	Repository   string    `json:"repository"`
	Description  string    `json:"description"`
	URL          string    `json:"url,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
	Provider     string    `json:"provider"`
}

// Getter methods to implement filter.Filterable interface
func (v Vulnerability) GetSeverity() string        { return v.Severity }
func (v Vulnerability) GetCVSS() float64           { return v.CVSS }
func (v Vulnerability) GetDiscoveredAt() time.Time { return v.DiscoveredAt }
func (v Vulnerability) GetPackage() string         { return v.Package }

// NormalizeSeverity applies severity mappings to convert provider-specific values
// (e.g., GitHub's "moderate") to Patrol's canonical levels (critical, high, medium, low).
func NormalizeSeverity(severity string, mappings map[string]string) string {
	severity = strings.ToLower(severity)
	if mapped, exists := mappings[severity]; exists {
		return mapped
	}
	return severity
}

// Provider defines the interface for security vulnerability providers
type Provider interface {
	// Name returns the provider name
	Name() string

	// FetchVulnerabilities retrieves all vulnerabilities from the provider
	FetchVulnerabilities(ctx context.Context) ([]Vulnerability, error)
}

// New creates a new provider instance based on name
func New(name string, cfg *config.Config, verbose bool) (Provider, error) {
	providerCfg, exists := cfg.Providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %q not found in config", name)
	}

	filters := cfg.GetProviderFilters(name)
	severityMappings := cfg.Defaults.SeverityMappings

	switch name {
	case "github":
		return NewGitHubProvider(cfg.GitHubToken, providerCfg, filters, severityMappings, verbose)
	case "snyk":
		return NewSnykProvider(cfg.SnykToken, providerCfg, filters, severityMappings, verbose)
	default:
		return nil, fmt.Errorf("unknown provider: %s", name)
	}
}
