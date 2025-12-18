package config

import "path/filepath"

// AssigneeResolver determines the Jira assignee for a vulnerability based on
// a three-tier hierarchy: repository > provider > defaults.
//
// This allows organizations to configure assignees at different levels:
//   - Global default for companies with a single security person
//   - Provider-level for different teams handling different sources
//   - Repository-level for team/code owner responsibility
type AssigneeResolver struct {
	cfg *Config
}

// NewAssigneeResolver creates a new AssigneeResolver with the given configuration.
func NewAssigneeResolver(cfg *Config) *AssigneeResolver {
	return &AssigneeResolver{cfg: cfg}
}

// Resolve returns the Jira assignee account ID for a given provider and repository.
// It checks the hierarchy in order of specificity:
//  1. Repository-level: matching entry in providers.{provider}.repo_includes with assignee
//  2. Provider-level: providers.{provider}.jira.assignee
//  3. Global default: defaults.jira.assignee
//
// For repo_includes, both exact matches and pattern matches (using glob syntax) are checked.
// The returned value is resolved through the users map if it's an alias.
// Returns an empty string if no assignee is configured at any level.
func (r *AssigneeResolver) Resolve(providerName, repository string) string {
	var assignee string

	if provider, exists := r.cfg.Providers[providerName]; exists {
		// Check repo_includes for GitHub
		for _, include := range provider.RepoIncludes {
			if matchRepoPattern(include.Name, repository) && include.Assignee != "" {
				assignee = include.Assignee
				return r.cfg.ResolveUserID(assignee)
			}
		}

		// Check project_includes for Snyk
		for _, include := range provider.ProjectIncludes {
			if matchRepoPattern(include.Name, repository) && include.Assignee != "" {
				assignee = include.Assignee
				return r.cfg.ResolveUserID(assignee)
			}
		}
	}

	// Fall back to provider-level override
	jiraCfg := r.cfg.GetProviderJira(providerName)
	if jiraCfg.Assignee != "" {
		assignee = jiraCfg.Assignee
		return r.cfg.ResolveUserID(assignee)
	}

	// Fall back to global default
	assignee = r.cfg.Defaults.Jira.Assignee
	return r.cfg.ResolveUserID(assignee)
}

// matchRepoPattern checks if a repository name matches a pattern.
// Supports exact matches and glob patterns (*, ?, []).
func matchRepoPattern(pattern, repo string) bool {
	// Try exact match first
	if pattern == repo {
		return true
	}

	// Try glob pattern match
	matched, err := filepath.Match(pattern, repo)
	if err != nil {
		// Invalid pattern, fall back to exact match only
		return false
	}
	return matched
}
