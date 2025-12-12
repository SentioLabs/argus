package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/sentiolabs/patrol/internal/config"
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

	switch name {
	case "github":
		return NewGitHubProvider(cfg.GitHubToken, providerCfg, filters, verbose)
	case "snyk":
		return NewSnykProvider(cfg.SnykToken, providerCfg, filters, verbose)
	default:
		return nil, fmt.Errorf("unknown provider: %s", name)
	}
}
