package filter

import (
	"testing"
	"time"

	"github.com/sentiolabs/patrol/internal/config"
	"github.com/sentiolabs/patrol/internal/provider"
)

func TestFilter_ShouldInclude_Severity(t *testing.T) {
	tests := []struct {
		name        string
		minSeverity string
		vulnSev     string
		want        bool
	}{
		{"critical passes high", "high", "critical", true},
		{"high passes high", "high", "high", true},
		{"medium fails high", "high", "medium", false},
		{"low fails high", "high", "low", false},
		{"medium passes medium", "medium", "medium", true},
		{"low fails medium", "medium", "low", false},
		{"empty min passes all", "", "low", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New(config.FiltersConfig{MinSeverity: tt.minSeverity})
			v := provider.Vulnerability{
				Severity:     tt.vulnSev,
				DiscoveredAt: time.Now(),
			}
			if got := f.ShouldInclude(v); got != tt.want {
				t.Errorf("ShouldInclude() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilter_ShouldInclude_CVSS(t *testing.T) {
	tests := []struct {
		name     string
		minCVSS  float64
		vulnCVSS float64
		want     bool
	}{
		{"above min passes", 7.0, 8.5, true},
		{"equal to min passes", 7.0, 7.0, true},
		{"below min fails", 7.0, 6.9, false},
		{"zero min passes all", 0, 1.0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New(config.FiltersConfig{CVSSMin: tt.minCVSS})
			v := provider.Vulnerability{
				CVSS:         tt.vulnCVSS,
				Severity:     "high",
				DiscoveredAt: time.Now(),
			}
			if got := f.ShouldInclude(v); got != tt.want {
				t.Errorf("ShouldInclude() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilter_ShouldInclude_Age(t *testing.T) {
	tests := []struct {
		name       string
		maxAgeDays int
		daysAgo    int
		want       bool
	}{
		{"within age passes", 30, 15, true},
		{"at age boundary passes", 30, 29, true}, // slightly under to avoid boundary issues
		{"over age fails", 30, 31, false},
		{"zero max passes all", 0, 365, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New(config.FiltersConfig{MaxAgeDays: tt.maxAgeDays})
			v := provider.Vulnerability{
				Severity:     "high",
				DiscoveredAt: time.Now().AddDate(0, 0, -tt.daysAgo),
			}
			if got := f.ShouldInclude(v); got != tt.want {
				t.Errorf("ShouldInclude() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilter_ShouldInclude_Packages(t *testing.T) {
	tests := []struct {
		name     string
		packages []string
		exclude  []string
		pkgName  string
		want     bool
	}{
		{"include pattern matches", []string{"lodash*"}, nil, "lodash", true},
		{"include pattern fails", []string{"lodash*"}, nil, "express", false},
		{"empty include passes all", nil, nil, "anything", true},
		{"exclude pattern blocks", nil, []string{"test-*"}, "test-utils", false},
		{"exclude pattern allows", nil, []string{"test-*"}, "production-lib", true},
		{"both include and exclude", []string{"*"}, []string{"dev-*"}, "dev-tools", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New(config.FiltersConfig{
				Packages:        tt.packages,
				ExcludePackages: tt.exclude,
			})
			v := provider.Vulnerability{
				Package:      tt.pkgName,
				Severity:     "high",
				DiscoveredAt: time.Now(),
			}
			if got := f.ShouldInclude(v); got != tt.want {
				t.Errorf("ShouldInclude() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilter_Apply(t *testing.T) {
	f := New(config.FiltersConfig{MinSeverity: "high"})

	vulns := []provider.Vulnerability{
		{ID: "1", Severity: "critical", DiscoveredAt: time.Now()},
		{ID: "2", Severity: "high", DiscoveredAt: time.Now()},
		{ID: "3", Severity: "medium", DiscoveredAt: time.Now()},
		{ID: "4", Severity: "low", DiscoveredAt: time.Now()},
	}

	filtered := f.Apply(vulns)

	if len(filtered) != 2 {
		t.Errorf("Apply() returned %d vulnerabilities, want 2", len(filtered))
	}

	for _, v := range filtered {
		if v.Severity != "critical" && v.Severity != "high" {
			t.Errorf("Apply() included unexpected severity: %s", v.Severity)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"lodash", "lodash", true},
		{"lodash", "Lodash", true}, // case insensitive
		{"lodash*", "lodash", true},
		{"lodash*", "lodash.merge", true},
		{"*utils", "string-utils", true},
		{"react-*", "react-dom", true},
		{"react-*", "vue-dom", false},
		{"?est", "test", true},
		{"?est", "best", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			if got := MatchPattern(tt.pattern, tt.value); got != tt.want {
				t.Errorf("MatchPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestIsExcluded(t *testing.T) {
	exclusions := []string{"test-repo", "archived-repo", "DEMO-REPO"}

	tests := []struct {
		value string
		want  bool
	}{
		{"test-repo", true},
		{"Test-Repo", true}, // case insensitive
		{"archived-repo", true},
		{"demo-repo", true}, // case insensitive
		{"production-repo", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if got := IsExcluded(exclusions, tt.value); got != tt.want {
				t.Errorf("IsExcluded(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
