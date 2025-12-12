package filter

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/sentiolabs/patrol/internal/config"
	"github.com/sentiolabs/patrol/internal/provider"
)

// Filter applies configured filters to vulnerabilities
type Filter struct {
	cfg config.FiltersConfig
}

// New creates a new Filter with the given configuration
func New(cfg config.FiltersConfig) *Filter {
	return &Filter{cfg: cfg}
}

// Apply filters a slice of vulnerabilities based on configured criteria
func (f *Filter) Apply(vulns []provider.Vulnerability) []provider.Vulnerability {
	var filtered []provider.Vulnerability
	for _, v := range vulns {
		if f.ShouldInclude(v) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// ShouldInclude checks if a single vulnerability passes all filters
func (f *Filter) ShouldInclude(v provider.Vulnerability) bool {
	if !f.checkSeverity(v) {
		return false
	}
	if !f.checkCVSS(v) {
		return false
	}
	if !f.checkAge(v) {
		return false
	}
	if !f.checkPackageInclude(v) {
		return false
	}
	if !f.checkPackageExclude(v) {
		return false
	}
	return true
}

// checkSeverity verifies the vulnerability meets minimum severity
func (f *Filter) checkSeverity(v provider.Vulnerability) bool {
	minSeverity := strings.ToLower(f.cfg.MinSeverity)
	if minSeverity == "" {
		return true
	}

	minLevel := config.SeverityOrder[minSeverity]
	vulnLevel := config.SeverityOrder[strings.ToLower(v.Severity)]
	return vulnLevel >= minLevel
}

// checkCVSS verifies the vulnerability meets minimum CVSS score
func (f *Filter) checkCVSS(v provider.Vulnerability) bool {
	if f.cfg.CVSSMin <= 0 {
		return true
	}
	return v.CVSS >= f.cfg.CVSSMin
}

// checkAge verifies the vulnerability is within the max age
func (f *Filter) checkAge(v provider.Vulnerability) bool {
	if f.cfg.MaxAgeDays <= 0 {
		return true
	}
	maxAge := time.Duration(f.cfg.MaxAgeDays) * 24 * time.Hour
	return time.Since(v.DiscoveredAt) <= maxAge
}

// checkPackageInclude verifies the vulnerability's package matches include patterns
func (f *Filter) checkPackageInclude(v provider.Vulnerability) bool {
	if len(f.cfg.Packages) == 0 {
		return true
	}
	for _, pkg := range f.cfg.Packages {
		if MatchPattern(pkg, v.Package) {
			return true
		}
	}
	return false
}

// checkPackageExclude verifies the vulnerability's package doesn't match exclude patterns
func (f *Filter) checkPackageExclude(v provider.Vulnerability) bool {
	for _, pkg := range f.cfg.ExcludePackages {
		if MatchPattern(pkg, v.Package) {
			return false
		}
	}
	return true
}

// MatchPattern checks if a string matches a glob-like pattern
func MatchPattern(pattern, s string) bool {
	// Handle case-insensitive matching
	matched, _ := filepath.Match(strings.ToLower(pattern), strings.ToLower(s))
	return matched
}

// MatchRepository checks if a repository matches any pattern in the list
func MatchRepository(patterns []string, repo string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if MatchPattern(pattern, repo) {
			return true
		}
	}
	return false
}

// IsExcluded checks if a value is in the exclusion list
func IsExcluded(exclusions []string, value string) bool {
	for _, excluded := range exclusions {
		if strings.EqualFold(excluded, value) {
			return true
		}
	}
	return false
}
