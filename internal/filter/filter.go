// Package filter implements the vulnerability filtering logic for Argus.
// It supports filtering by severity, CVSS score, age, and package patterns.
package filter

import (
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentiolabs/argus/internal/config"
)

// Filterable defines the interface that a vulnerability must implement to be filtered.
type Filterable interface {
	GetSeverity() string
	GetCVSS() float64
	GetDiscoveredAt() time.Time
	GetPackage() string
}

// Filter applies configured filters to vulnerabilities
type Filter struct {
	cfg config.FiltersConfig
}

// New creates a new Filter with the given configuration
func New(cfg config.FiltersConfig) *Filter {
	return &Filter{cfg: cfg}
}

// ShouldInclude checks if a single vulnerability passes all filters
func (f *Filter) ShouldInclude(v Filterable) bool {
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
func (f *Filter) checkSeverity(v Filterable) bool {
	minSeverity := strings.ToLower(f.cfg.MinSeverity)
	if minSeverity == "" {
		return true
	}

	minLevel := config.SeverityOrder[minSeverity]
	vulnLevel := config.SeverityOrder[strings.ToLower(v.GetSeverity())]
	return vulnLevel >= minLevel
}

// checkCVSS verifies the vulnerability meets minimum CVSS score
func (f *Filter) checkCVSS(v Filterable) bool {
	if f.cfg.CVSSMin <= 0 {
		return true
	}
	return v.GetCVSS() >= f.cfg.CVSSMin
}

// checkAge verifies the vulnerability is within the max age
func (f *Filter) checkAge(v Filterable) bool {
	if f.cfg.MaxAgeDays <= 0 {
		return true
	}
	maxAge := time.Duration(f.cfg.MaxAgeDays) * 24 * time.Hour
	return time.Since(v.GetDiscoveredAt()) <= maxAge
}

// checkPackageInclude verifies the vulnerability's package matches include patterns
func (f *Filter) checkPackageInclude(v Filterable) bool {
	if len(f.cfg.Packages) == 0 {
		return true
	}
	for _, pkg := range f.cfg.Packages {
		if MatchPattern(pkg, v.GetPackage()) {
			return true
		}
	}
	return false
}

// checkPackageExclude verifies the vulnerability's package doesn't match exclude patterns
func (f *Filter) checkPackageExclude(v Filterable) bool {
	for _, pkg := range f.cfg.ExcludePackages {
		if MatchPattern(pkg, v.GetPackage()) {
			return false
		}
	}
	return true
}

// MatchPattern checks if a string matches a glob-like pattern.
// It performs a case-insensitive match using filepath.Match.
func MatchPattern(pattern, s string) bool {
	// Handle case-insensitive matching
	matched, err := filepath.Match(strings.ToLower(pattern), strings.ToLower(s))
	if err != nil {
		slog.Warn("invalid glob pattern", "pattern", pattern, "error", err)
		return false
	}
	return matched
}

// MatchRepository checks if a repository name matches any of the provided patterns.
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

// IsExcluded checks if a value exists in the exclusion list (case-insensitive).
func IsExcluded(exclusions []string, value string) bool {
	for _, excluded := range exclusions {
		if strings.EqualFold(excluded, value) {
			return true
		}
	}
	return false
}
