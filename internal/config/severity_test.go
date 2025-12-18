package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// SeverityTestSuite tests severity normalization functionality
type SeverityTestSuite struct {
	suite.Suite
}

func TestSeverityTestSuite(t *testing.T) {
	suite.Run(t, new(SeverityTestSuite))
}

func (s *SeverityTestSuite) TestNormalizeSeverity_WithDefaultMappings() {
	cfg := &Config{
		Defaults: DefaultsConfig{
			SeverityMappings: map[string]string{
				"moderate": "medium",
			},
		},
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
		{"high unchanged", "high", "high"},
		{"medium unchanged", "medium", "medium"},
		{"low unchanged", "low", "low"},
		{"unknown unchanged", "unknown", "unknown"},
		{"empty unchanged", "", ""},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := cfg.NormalizeSeverity(tt.input)
			assert.Equal(s.T(), tt.expected, result)
		})
	}
}

func (s *SeverityTestSuite) TestNormalizeSeverity_WithCustomMappings() {
	cfg := &Config{
		Defaults: DefaultsConfig{
			SeverityMappings: map[string]string{
				"moderate":      "medium",
				"informational": "low",
				"severe":        "critical",
			},
		},
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"moderate maps to medium", "moderate", "medium"},
		{"informational maps to low", "informational", "low"},
		{"severe maps to critical", "severe", "critical"},
		{"critical unchanged", "critical", "critical"},
		{"unmapped value unchanged", "high", "high"},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := cfg.NormalizeSeverity(tt.input)
			assert.Equal(s.T(), tt.expected, result)
		})
	}
}

func (s *SeverityTestSuite) TestNormalizeSeverity_WithNilMappings() {
	cfg := &Config{
		Defaults: DefaultsConfig{
			SeverityMappings: nil,
		},
	}

	// Should return input unchanged when no mappings configured
	result := cfg.NormalizeSeverity("moderate")
	assert.Equal(s.T(), "moderate", result)

	result = cfg.NormalizeSeverity("critical")
	assert.Equal(s.T(), "critical", result)
}

func (s *SeverityTestSuite) TestNormalizeSeverity_WithEmptyMappings() {
	cfg := &Config{
		Defaults: DefaultsConfig{
			SeverityMappings: map[string]string{},
		},
	}

	// Should return input unchanged when mappings are empty
	result := cfg.NormalizeSeverity("moderate")
	assert.Equal(s.T(), "moderate", result)
}

func (s *SeverityTestSuite) TestSetDefaults_SeverityMappings() {
	cfg := &Config{}
	setDefaults(cfg)

	// Should set default mapping for moderate -> medium
	assert.NotNil(s.T(), cfg.Defaults.SeverityMappings)
	assert.Equal(s.T(), "medium", cfg.Defaults.SeverityMappings["moderate"])
}

func (s *SeverityTestSuite) TestSetDefaults_PreservesExistingMappings() {
	cfg := &Config{
		Defaults: DefaultsConfig{
			SeverityMappings: map[string]string{
				"custom": "high",
			},
		},
	}
	setDefaults(cfg)

	// Should preserve existing mappings
	assert.Equal(s.T(), "high", cfg.Defaults.SeverityMappings["custom"])
	// Should NOT override with defaults when already set
	_, hasModerate := cfg.Defaults.SeverityMappings["moderate"]
	assert.False(s.T(), hasModerate, "should not add moderate mapping when mappings already exist")
}

func (s *SeverityTestSuite) TestSeverityOrder_CanonicalLevels() {
	// Verify Argus's canonical severity levels are properly ordered
	assert.Equal(s.T(), 1, SeverityOrder["low"])
	assert.Equal(s.T(), 2, SeverityOrder["medium"])
	assert.Equal(s.T(), 3, SeverityOrder["high"])
	assert.Equal(s.T(), 4, SeverityOrder["critical"])

	// Verify moderate is NOT in SeverityOrder (normalization handles it)
	_, hasModerate := SeverityOrder["moderate"]
	assert.False(s.T(), hasModerate, "moderate should not be in SeverityOrder - use normalization instead")
}

func (s *SeverityTestSuite) TestSeverityOrder_Comparisons() {
	assert.Greater(s.T(), SeverityOrder["critical"], SeverityOrder["high"])
	assert.Greater(s.T(), SeverityOrder["high"], SeverityOrder["medium"])
	assert.Greater(s.T(), SeverityOrder["medium"], SeverityOrder["low"])
}
