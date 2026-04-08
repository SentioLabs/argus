package output

import (
	"strings"
	"testing"
)

func TestFormatDetail_AllFields(t *testing.T) {
	d := VulnDetail{
		ID:           "SNYK-RUBY-RACKSESSION-15928857",
		CVE:          "CVE-2025-27610",
		Severity:     "high",
		CVSS:         7.5,
		Package:      "rack-session",
		Version:      "2.0.0",
		FixedVersion: "2.1.0",
		Repository:   "bactrack/my-rails-app",
		Provider:     "snyk",
		DiscoveredAt: "2026-03-15",
		URL:          "https://security.snyk.io/vuln/SNYK-RUBY-RACKSESSION-15928857",
		Description:  "Session fixation vulnerability",
		ProjectKey:   "-home-user-projects-my-app",
	}

	result := FormatDetail(d)

	checks := []string{
		"ID:",
		"SNYK-RUBY-RACKSESSION-15928857",
		"CVE:",
		"CVE-2025-27610",
		"Severity:",
		"high",
		"CVSS:",
		"7.5",
		"Package:",
		"rack-session",
		"2.0.0",
		"Fixed In:",
		"2.1.0",
		"Repository:",
		"bactrack/my-rails-app",
		"Provider:",
		"snyk",
		"Discovered:",
		"2026-03-15",
		"URL:",
		"https://security.snyk.io/vuln/SNYK-RUBY-RACKSESSION-15928857",
		"Project:",
		"-home-user-projects-my-app",
		"Description:",
		"Session fixation vulnerability",
	}

	for _, s := range checks {
		if !strings.Contains(result, s) {
			t.Errorf("FormatDetail output missing %q\nGot:\n%s", s, result)
		}
	}
}

func TestFormatDetail_MissingOptionalFields(t *testing.T) {
	d := VulnDetail{
		ID:         "SNYK-RUBY-RACKSESSION-15928857",
		Severity:   "high",
		CVSS:       7.5,
		Package:    "rack-session",
		Repository: "bactrack/my-rails-app",
		Provider:   "snyk",
	}

	result := FormatDetail(d)

	// Required fields must be present
	required := []string{
		"ID:",
		"SNYK-RUBY-RACKSESSION-15928857",
		"Severity:",
		"high",
		"CVSS:",
		"7.5",
		"Package:",
		"rack-session",
		"Repository:",
		"bactrack/my-rails-app",
		"Provider:",
		"snyk",
	}
	for _, s := range required {
		if !strings.Contains(result, s) {
			t.Errorf("FormatDetail output missing required field %q\nGot:\n%s", s, result)
		}
	}

	// Optional fields must be absent
	absent := []string{
		"CVE:",
		"Fixed In:",
		"Discovered:",
		"URL:",
		"Project:",
		"Description:",
	}
	for _, s := range absent {
		if strings.Contains(result, s) {
			t.Errorf("FormatDetail output unexpectedly contains %q\nGot:\n%s", s, result)
		}
	}
}
