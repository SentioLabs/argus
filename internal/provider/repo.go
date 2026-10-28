package provider

import (
	"log/slog"
	"slices"
	"strings"

	"github.com/sentiolabs/argus/internal/filter"
)

// maxRepoSuggestions caps the "did you mean" list when a repo scope matches nothing.
const maxRepoSuggestions = 5

// RepoMatches reports whether a provider's repository or project name belongs
// to the repo pattern the user asked for. The pattern is a case-insensitive glob
// matched against both the full name and the bare "owner/repo" part, so
// "bactrack/bacstack" matches the Snyk project "bactrack/bacstack(main):go.mod".
func RepoMatches(pattern, name string) bool {
	return filter.MatchPattern(pattern, name) || filter.MatchPattern(pattern, repoFromProjectName(name))
}

// repoFromProjectName strips the "(branch)" and ":target/file" suffixes Snyk adds
// to projects imported from an SCM. GitHub repo names can't contain "(" or ":",
// so names without a suffix pass through unchanged.
func repoFromProjectName(name string) string {
	if i := strings.IndexAny(name, "(:"); i >= 0 {
		name = name[:i]
	}
	return strings.TrimSpace(name)
}

// applyRepoScope keeps the items whose name matches scope. An empty scope keeps
// everything. When nothing matches, it logs a warning with similar repo names so
// an empty result isn't mistaken for "no vulnerabilities".
func applyRepoScope[T any](scope string, items []T, name func(T) string) []T {
	if scope == "" {
		return items
	}

	names := make([]string, 0, len(items))
	matched := make([]T, 0, len(items))
	for _, item := range items {
		names = append(names, name(item))
		if RepoMatches(scope, name(item)) {
			matched = append(matched, item)
		}
	}

	if len(matched) == 0 {
		if suggestions := suggestRepos(scope, names); len(suggestions) > 0 {
			slog.Warn("no repositories matched --repo", "repo", scope, "did_you_mean", suggestions)
		} else {
			slog.Warn("no repositories matched --repo", "repo", scope, "searched", len(items))
		}
	}

	return matched
}

// suggestRepos returns up to maxRepoSuggestions distinct "owner/repo" names that
// contain the last path segment of pattern, ignoring case and glob characters.
// Matching on the repo segment alone still finds candidates when the org is mistyped.
func suggestRepos(pattern string, names []string) []string {
	needle := strings.ToLower(strings.Trim(pattern, "*?[]"))
	if i := strings.LastIndex(needle, "/"); i >= 0 {
		needle = needle[i+1:]
	}
	if needle == "" {
		return nil
	}

	seen := make(map[string]bool)
	var suggestions []string
	for _, name := range names {
		repo := repoFromProjectName(name)
		key := strings.ToLower(repo)
		if seen[key] || !strings.Contains(key, needle) {
			continue
		}
		seen[key] = true
		suggestions = append(suggestions, repo)
	}

	slices.Sort(suggestions)
	if len(suggestions) > maxRepoSuggestions {
		suggestions = suggestions[:maxRepoSuggestions]
	}
	return suggestions
}
