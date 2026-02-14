# CISA KEV TUI

![Go Version](https://img.shields.io/badge/go-1.26.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Go Report Card](https://goreportcard.com/badge/github.com/ethanolivertroy/kevs-tui)
![GitHub Release](https://img.shields.io/github/release/ethanolivertroy/kevs-tui.svg)
![Tests](https://github.com/ethanolivertroy/kevs-tui/workflows/Test/badge.svg)
![Lint](https://github.com/ethanolivertroy/kevs-tui/workflows/Lint/badge.svg)
![Coverage](https://codecov.io/gh/ethanolivertroy/kevs-tui/branch/main/graph/badge.svg)

Terminal UI for searching CISA Known Exploited Vulnerabilities (KEV) catalog with EPSS exploit probability scores and an integrated AI agent for security analysis.

![Demo](demo.gif)

## Install

### Go Install

```bash
go install github.com/ethanolivertroy/kevs-tui@latest
```

### Build from Source

```bash
git clone https://github.com/ethanolivertroy/kevs-tui.git
cd kevs-tui
go build -o kevs-tui .
```

## Quick Start

```bash
# Browse KEV catalog with KEVin AI sidebar
kevs-tui

# Chat with KEVin AI only
kevs-tui agent

# One-shot query
kevs-tui agent "show me critical Microsoft vulnerabilities"

# Start A2A server
kevs-tui serve
```

## Features

### KEV Browser
- **EPSS Scores** - Exploit Prediction Scoring System data showing probability of exploitation
- **Statistics Header** - Total KEVs, ransomware count, overdue count at a glance
- **Multiple Sort Options** - Sort by date added, due date, EPSS score, or vendor
- **Quick Filters** - Filter to show only ransomware or overdue vulnerabilities
- **Open in Browser** - Launch NVD page directly from the TUI
- **Copy to Clipboard** - Quick copy CVE IDs
- **Scrollable Detail View** - Navigate long descriptions with keyboard/mouse
- **Visual Indicators** - Color-coded EPSS bars, overdue badges, ransomware flags
- **Text Selection** - Click-and-drag text selection in chat and detail views

### KEVin AI Agent
Natural language interface for querying the KEV catalog with GRC control mapping and analytics.

### Command Palette
Press `Ctrl+P` or `Ctrl+K` for quick access to all commands with fuzzy search.

### Analytics & Charts
- Top vendors chart
- Monthly timeline
- CWE distribution
- Ransomware usage breakdown
- Risk distribution by EPSS

### Themes
Available themes: `default`, `dracula`, `catppuccin`, `nord`

### Export
Export filtered or full catalog to JSON, CSV, or Markdown formats.

## Usage

### TUI Mode (Default)

```bash
kevs-tui
```

Browse the KEV catalog with KEVin AI sidebar. Toggle the sidebar with `\`.

### Agent Mode

```bash
# Interactive chat
kevs-tui agent

# One-shot query
kevs-tui agent "Microsoft vulnerabilities with ransomware"
```

### A2A Server Mode

Run as an Agent-to-Agent protocol server for integration with other tools:

```bash
# Default port 8001
kevs-tui serve

# Custom port
kevs-tui serve --port 9000
```

## Configuration

### LLM Providers

KEVin supports multiple LLM providers. Set `LLM_PROVIDER` and the required API key:

| Provider | `LLM_PROVIDER` | Required Env Var | Default Model |
|----------|----------------|------------------|---------------|
| Google Gemini | `gemini` | `GEMINI_API_KEY` | `gemini-2.0-flash` |
| Vertex AI | `vertex` | `VERTEX_PROJECT`, `VERTEX_LOCATION` | `gemini-2.0-flash` |
| Ollama (local) | `ollama` | `OLLAMA_URL` (optional) | `llama3.2` |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | `anthropic/claude-sonnet-4` |

Override the model with `LLM_MODEL`:

```bash
export LLM_MODEL=gemini-1.5-pro
```

#### Examples

**Google Gemini (default):**
```bash
export GEMINI_API_KEY=your-api-key
kevs-tui agent
```

**OpenRouter (access Claude, GPT-4, Llama, etc.):**
```bash
export LLM_PROVIDER=openrouter
export OPENROUTER_API_KEY=sk-or-v1-xxxxx
kevs-tui agent
```

**Ollama (local, no API key needed):**
```bash
export LLM_PROVIDER=ollama
kevs-tui agent
```

## Keyboard Shortcuts

### Global

| Key | Action |
|-----|--------|
| `Ctrl+C` | Quit |
| `Ctrl+P` | Open command palette |
| `Ctrl+K` | Open/focus KEVin |
| `\` | Toggle KEVin panel |
| `Tab` | Switch focus between panels |
| `?` | Toggle help |

### KEV Browser

| Key | Action |
|-----|--------|
| `/` | Filter/search |
| `j/k` or arrows | Navigate |
| `Enter` | View details |
| `Esc` | Back/clear filter |
| `s` | Cycle sort mode |
| `r` | Toggle ransomware filter |
| `d` | Toggle overdue filter |
| `o` | Open NVD URL in browser |
| `c` | Copy CVE ID to clipboard |
| `t` | Cycle theme |
| `g` | Open charts menu |
| `x` | Open export menu |
| `q` | Quit |

## KEVin Capabilities

### KEV Tools
- **search_kevs** - Search by keyword, vendor, or product
- **get_cve_details** - Detailed CVE info with EPSS scores
- **list_ransomware_cves** - CVEs used in ransomware campaigns
- **list_overdue_cves** - Past remediation due date
- **get_stats** - Catalog statistics
- **export_report** - Export to JSON/CSV/Markdown

### GRC Compliance Tools
- **map_cve_to_controls** - Map CVE to NIST 800-53, FedRAMP, or CIS Controls v8
- **get_control_details** - Security control details (e.g., SI-2, RA-5)
- **list_controls** - List controls by family or implementation group

### Analytics Tools
- **find_related_cves** - Find CVEs related by CWE, vendor, or product
- **get_vendor_risk_profile** - Comprehensive vendor risk assessment
- **batch_analyze** - Analyze multiple CVEs with prioritization
- **analyze_cwe** - Deep dive on a CWE with affected vendors
- **check_exploit_availability** - Check for public exploits (GitHub PoCs, Nuclei)
- **check_patch_status** - Check for patches and advisories
- **analyze_trends** - Vulnerability trends over time

## Data Sources

- **KEV Catalog**: [CISA KEV Data](https://github.com/cisagov/kev-data) - Official GitHub mirror
- **EPSS Scores**: [FIRST EPSS API](https://www.first.org/epss/) - Exploit probability predictions
- **CVSS Metrics**: [NVD API](https://nvd.nist.gov/developers/vulnerabilities) - CVSS scores and assessments

## License

[MIT](LICENSE)
