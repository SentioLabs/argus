# Argus

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
- **Namespaced labels**: Auto-generate structured Jira labels (`argus:dependabot`, `argus:snyk`, `argus:critical`)

## Installation

```bash
go install github.com/sentiolabs/argus@latest
```

Or build from source:

```bash
git clone https://github.com/sentiolabs/argus.git
cd argus
go build .
```

### Docker

```bash
# Build the image
docker build -t argus .

# Run with environment variables
docker run --rm \
  -e ARGUS_GITHUB_TOKEN \
  -e ARGUS_SNYK_TOKEN \
  -e ARGUS_JIRA_URL \
  -e ARGUS_JIRA_USERNAME \
  -e ARGUS_JIRA_TOKEN \
  -v $(pwd)/.argus.yaml:/app/.argus.yaml:ro \
  argus sync
```

### Kubernetes (Helm)

Argus includes a Helm chart for running as a scheduled CronJob in Kubernetes.

```bash
# Install with inline values
helm install argus ./charts/argus \
  --namespace argus --create-namespace \
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
helm install argus ./charts/argus -f values.yaml -n argus --create-namespace
```

Use an existing secret instead of storing credentials in values:

```bash
# Create secret manually
kubectl create secret generic argus-credentials -n argus \
  --from-literal=ARGUS_GITHUB_TOKEN="ghp_xxx" \
  --from-literal=ARGUS_SNYK_TOKEN="xxx" \
  --from-literal=ARGUS_JIRA_URL="https://your-domain.atlassian.net" \
  --from-literal=ARGUS_JIRA_USERNAME="email@example.com" \
  --from-literal=ARGUS_JIRA_TOKEN="xxx"

# Install with existing secret
helm install argus ./charts/argus -n argus \
  --set existingSecret=argus-credentials
```

## Configuration

### Environment Variables

Set the following environment variables (or use a `.env` file):

```bash
# GitHub
ARGUS_GITHUB_TOKEN=ghp_xxxxxxxxxxxx

# Snyk
ARGUS_SNYK_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Jira
ARGUS_JIRA_URL=https://your-domain.atlassian.net
ARGUS_JIRA_USERNAME=your-email@example.com
ARGUS_JIRA_TOKEN=xxxxxxxxxxxxxxxx
```

### Configuration File

Create a `.argus.yaml` file in your working directory:

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
  #   moderate: medium  # GitHub's "moderate" → Argus's "medium"

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
argus sync

# Preview what would be synced (no Jira changes)
argus sync --dry-run

# Verbose output
argus sync -v

# JSON output
argus sync --output json
```

### Verify provider configuration

Use `verify` to preview vulnerabilities from a specific provider without syncing to Jira:

```bash
# Preview GitHub Dependabot alerts
argus verify --provider github

# Preview Snyk issues
argus verify --provider snyk
```

This is useful for:
- Testing provider configuration
- Debugging API connectivity
- Previewing what will be synced

## How It Works

1. **Fetch**: Argus queries all configured providers for open security vulnerabilities
2. **Filter**: Vulnerabilities are filtered by severity, age, CVSS score, and package patterns
3. **Merge**: Vulnerabilities are deduplicated by CVE across providers (e.g., same CVE from GitHub and Snyk becomes one entry)
4. **Check Jira**: For each merged vulnerability, Argus searches Jira for existing open tickets
5. **Create or Update**:
   - If no ticket exists: Create a new Jira ticket with severity-based priority
   - If ticket exists and >24h since last comment: Add an informative comment
   - If ticket exists and <24h since last comment: Skip (throttled)
6. **Sprint Assignment**: High-severity issues are automatically added to the active sprint

## Severity Normalization

Different vulnerability providers use different severity terminology. Argus normalizes these to a consistent set of canonical levels:

| Argus Level | Provider Values |
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

Argus automatically adds structured labels to Jira tickets for easy filtering:

| Label | Description |
|-------|-------------|
| `argus` | Base label for all Argus-created tickets |
| `argus:dependabot` | Detected by GitHub Dependabot |
| `argus:snyk` | Detected by Snyk |
| `argus:critical` | Critical severity |
| `argus:high` | High severity |
| `argus:medium` | Medium severity |
| `argus:low` | Low severity |

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
