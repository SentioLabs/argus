# Patrol

A CLI tool that syncs security vulnerabilities from GitHub Dependabot and Snyk to Jira, automating your security ticket workflow.

## Features

- **Multi-provider support**: Fetch vulnerabilities from GitHub Dependabot and Snyk
- **Jira integration**: Automatically create and update Jira tickets
- **Cross-provider deduplication**: Merge vulnerabilities by CVE across providers into unified tickets
- **Duplicate detection**: Finds existing open tickets and adds informative comments instead of creating duplicates
- **Comment throttling**: Only adds comments once per 24 hours to avoid noise
- **Sprint management**: Automatically add high-severity issues to the active sprint
- **Flexible filtering**: Filter by severity, CVSS score, age, packages, and repositories
- **Pattern matching**: Include/exclude repos and projects using glob patterns
- **Priority mapping**: Map vulnerability severity to Jira priority levels
- **Severity normalization**: Normalize provider-specific severity values (e.g., GitHub's "moderate" → "medium")
- **Namespaced labels**: Auto-generate structured Jira labels (`patrol:dependabot`, `patrol:snyk`, `patrol:critical`)

## Installation

```bash
go install github.com/sentiolabs/patrol@latest
```

Or build from source:

```bash
git clone https://github.com/sentiolabs/patrol.git
cd patrol
go build .
```

### Docker

```bash
# Build the image
docker build -t patrol .

# Run with environment variables
docker run --rm \
  -e PATROL_GITHUB_TOKEN \
  -e PATROL_SNYK_TOKEN \
  -e PATROL_JIRA_URL \
  -e PATROL_JIRA_USERNAME \
  -e PATROL_JIRA_TOKEN \
  -v $(pwd)/.patrol.yaml:/app/.patrol.yaml:ro \
  patrol sync
```

### Kubernetes (Helm)

Patrol includes a Helm chart for running as a scheduled CronJob in Kubernetes.

```bash
# Install with inline values
helm install patrol ./charts/patrol \
  --namespace patrol --create-namespace \
  --set credentials.githubToken="ghp_xxx" \
  --set credentials.snykToken="xxx-xxx" \
  --set credentials.jiraUrl="https://your-domain.atlassian.net" \
  --set credentials.jiraUsername="your-email@example.com" \
  --set credentials.jiraToken="xxx" \
  --set config.providers.github.orgs[0]="your-org"
```

Or create a `values.yaml` file:

```yaml
schedule: "0 */6 * * *"  # Every 6 hours

credentials:
  githubToken: "ghp_xxx"
  snykToken: "xxx-xxx"
  jiraUrl: "https://your-domain.atlassian.net"
  jiraUsername: "your-email@example.com"
  jiraToken: "xxx"

config:
  defaults:
    jira:
      project: "SEC"
      board_name: "Security Board"
  providers:
    github:
      enabled: true
      orgs:
        - your-org
    snyk:
      enabled: true
      org_id: "your-snyk-org-id"
```

```bash
helm install patrol ./charts/patrol -f values.yaml -n patrol --create-namespace
```

Use an existing secret instead of storing credentials in values:

```bash
# Create secret manually
kubectl create secret generic patrol-credentials -n patrol \
  --from-literal=PATROL_GITHUB_TOKEN="ghp_xxx" \
  --from-literal=PATROL_SNYK_TOKEN="xxx" \
  --from-literal=PATROL_JIRA_URL="https://your-domain.atlassian.net" \
  --from-literal=PATROL_JIRA_USERNAME="email@example.com" \
  --from-literal=PATROL_JIRA_TOKEN="xxx"

# Install with existing secret
helm install patrol ./charts/patrol -n patrol \
  --set existingSecret=patrol-credentials
```

## Configuration

### Environment Variables

Set the following environment variables (or use a `.env` file):

```bash
# GitHub
PATROL_GITHUB_TOKEN=ghp_xxxxxxxxxxxx

# Snyk
PATROL_SNYK_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Jira
PATROL_JIRA_URL=https://your-domain.atlassian.net
PATROL_JIRA_USERNAME=your-email@example.com
PATROL_JIRA_TOKEN=xxxxxxxxxxxxxxxx
```

### Configuration File

Create a `.patrol.yaml` file in your working directory:

```yaml
defaults:
  jira:
    project: "SEC"
    board_name: "Security Team Board"
    labels:
      - security
      - vulnerability
  thresholds:
    priority:
      critical: "Highest"
      high: "High"
      medium: "Medium"
      low: "Low"
    sprint_min_severity: "high"
  filters:
    min_severity: "medium"
    max_age_days: 90
  # Severity mappings (optional - defaults shown)
  # severity_mappings:
  #   moderate: medium  # GitHub's "moderate" → Patrol's "medium"

providers:
  github:
    enabled: true
    orgs:
      - your-org
    exclude_repos:
      - archived-repo

  snyk:
    enabled: true
    org_id: "your-snyk-org-id"
    project_patterns:
      - "your-org/*"
```

See [config.example.yaml](config.example.yaml) for a complete example.

## Usage

### Sync vulnerabilities to Jira

```bash
# Fetch from all providers, dedupe, and sync to Jira
patrol sync

# Preview what would be synced (no Jira changes)
patrol sync --dry-run

# Verbose output
patrol sync -v

# JSON output
patrol sync --output json
```

### Verify provider configuration

Use `verify` to preview vulnerabilities from a specific provider without syncing to Jira:

```bash
# Preview GitHub Dependabot alerts
patrol verify --provider github

# Preview Snyk issues
patrol verify --provider snyk
```

This is useful for:
- Testing provider configuration
- Debugging API connectivity
- Previewing what will be synced

## How It Works

1. **Fetch**: Patrol queries all configured providers for open security vulnerabilities
2. **Filter**: Vulnerabilities are filtered by severity, age, CVSS score, and package patterns
3. **Merge**: Vulnerabilities are deduplicated by CVE across providers (e.g., same CVE from GitHub and Snyk becomes one entry)
4. **Check Jira**: For each merged vulnerability, Patrol searches Jira for existing open tickets
5. **Create or Update**:
   - If no ticket exists: Create a new Jira ticket with severity-based priority
   - If ticket exists and >24h since last comment: Add an informative comment
   - If ticket exists and <24h since last comment: Skip (throttled)
6. **Sprint Assignment**: High-severity issues are automatically added to the active sprint

## Severity Normalization

Different vulnerability providers use different severity terminology. Patrol normalizes these to a consistent set of canonical levels:

| Patrol Level | Provider Values |
|--------------|-----------------|
| `critical` | critical |
| `high` | high |
| `medium` | medium, moderate (GitHub) |
| `low` | low |

By default, GitHub's "moderate" is automatically mapped to "medium". You can customize these mappings in your config:

```yaml
defaults:
  severity_mappings:
    moderate: medium      # Default: GitHub's "moderate" → "medium"
    informational: low    # Custom: map "informational" → "low"
```

## Jira Labels

Patrol automatically adds structured labels to Jira tickets for easy filtering:

| Label | Description |
|-------|-------------|
| `patrol` | Base label for all Patrol-created tickets |
| `patrol:dependabot` | Detected by GitHub Dependabot |
| `patrol:snyk` | Detected by Snyk |
| `patrol:critical` | Critical severity |
| `patrol:high` | High severity |
| `patrol:medium` | Medium severity |
| `patrol:low` | Low severity |

These are in addition to any custom labels configured in `defaults.jira.labels`.

## Token Permissions

### GitHub

Required scopes:
- `repo` (for private repos) or `public_repo` (for public repos only)
- `security_events` - Read Dependabot alerts

### Snyk

- API token from Snyk account settings
- Requires access to the organization specified in config

### Jira

- API token from [Atlassian account settings](https://id.atlassian.com/manage-profile/security/api-tokens)
- User must have permission to create issues in the target project

## License

MIT License - see [LICENSE](LICENSE) for details.
