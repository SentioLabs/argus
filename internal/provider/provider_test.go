package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// ProviderTestSuite tests provider package functionality
type ProviderTestSuite struct {
	suite.Suite
}

func TestProviderTestSuite(t *testing.T) {
	suite.Run(t, new(ProviderTestSuite))
}

func (s *ProviderTestSuite) TestNormalizeSeverity_WithMappings() {
	mappings := map[string]string{
		"moderate": "medium",
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"moderate maps to medium", "moderate", "medium"},
		{"MODERATE maps to medium (case insensitive)", "MODERATE", "medium"},
		{"Moderate maps to medium (mixed case)", "Moderate", "medium"},
		{"critical unchanged", "critical", "critical"},
		{"CRITICAL lowercase", "CRITICAL", "critical"},
		{"high unchanged", "high", "high"},
		{"medium unchanged", "medium", "medium"},
		{"low unchanged", "low", "low"},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := NormalizeSeverity(tt.input, mappings)
			assert.Equal(s.T(), tt.expected, result)
		})
	}
}

func (s *ProviderTestSuite) TestNormalizeSeverity_WithMultipleMappings() {
	mappings := map[string]string{
		"moderate":      "medium",
		"informational": "low",
		"severe":        "critical",
		"warning":       "medium",
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"moderate maps to medium", "moderate", "medium"},
		{"informational maps to low", "informational", "low"},
		{"severe maps to critical", "severe", "critical"},
		{"warning maps to medium", "warning", "medium"},
		{"unmapped high stays high", "high", "high"},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := NormalizeSeverity(tt.input, mappings)
			assert.Equal(s.T(), tt.expected, result)
		})
	}
}

func (s *ProviderTestSuite) TestNormalizeSeverity_WithNilMappings() {
	// Should return lowercase input when mappings is nil
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"moderate unchanged", "moderate", "moderate"},
		{"CRITICAL lowercase", "CRITICAL", "critical"},
		{"High lowercase", "High", "high"},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := NormalizeSeverity(tt.input, nil)
			assert.Equal(s.T(), tt.expected, result)
		})
	}
}

func (s *ProviderTestSuite) TestNormalizeSeverity_WithEmptyMappings() {
	mappings := map[string]string{}

	// Should return lowercase input when mappings is empty
	result := NormalizeSeverity("moderate", mappings)
	assert.Equal(s.T(), "moderate", result)

	result = NormalizeSeverity("CRITICAL", mappings)
	assert.Equal(s.T(), "critical", result)
}

func (s *ProviderTestSuite) TestNormalizeSeverity_EmptyInput() {
	mappings := map[string]string{
		"moderate": "medium",
	}

	result := NormalizeSeverity("", mappings)
	assert.Equal(s.T(), "", result)
}

func (s *ProviderTestSuite) TestNormalizeSeverity_AlwaysLowercase() {
	mappings := map[string]string{
		"moderate": "medium",
	}

	// Even unmapped values should be lowercased
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "critical"},
		{"Critical", "critical"},
		{"HIGH", "high"},
		{"Medium", "medium"},
		{"LOW", "low"},
	}

	for _, tt := range tests {
		s.Run(tt.input, func() {
			result := NormalizeSeverity(tt.input, mappings)
			assert.Equal(s.T(), tt.expected, result)
		})
	}
}

// VulnerabilityTestSuite tests Vulnerability struct functionality
type VulnerabilityTestSuite struct {
	suite.Suite
}

func TestVulnerabilityTestSuite(t *testing.T) {
	suite.Run(t, new(VulnerabilityTestSuite))
}

func (s *VulnerabilityTestSuite) TestVulnerability_GetterMethods() {
	v := Vulnerability{
		ID:       "CVE-2024-1234",
		Severity: "high",
		CVSS:     7.5,
		Package:  "lodash",
	}

	assert.Equal(s.T(), "high", v.GetSeverity())
	assert.Equal(s.T(), 7.5, v.GetCVSS())
	assert.Equal(s.T(), "lodash", v.GetPackage())
}
