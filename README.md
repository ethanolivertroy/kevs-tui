# CISA KEV TUI

![Go Version](https://img.shields.io/badge/go-1.25.5-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Go Report Card](https://goreportcard.com/badge/github.com/ethanolivertroy/kevs-tui)
![GitHub Release](https://img.shields.io/github/release/ethanolivertroy/kevs-tui.svg)
![Tests](https://github.com/ethanolivertroy/kevs-tui/workflows/Test/badge.svg)
![Lint](https://github.com/ethanolivertroy/kevs-tui/workflows/Lint/badge.svg)
![Coverage](https://codecov.io/gh/ethanolivertroy/kevs-tui/branch/main/graph/badge.svg)

Terminal UI for searching CISA Known Exploited Vulnerabilities (KEV) catalog with EPSS exploit probability scores.

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
go build -o kev .
```

## Usage

```bash
kev
```

## Features

- **EPSS Scores** - Exploit Prediction Scoring System data showing probability of exploitation
- **Statistics Header** - Total KEVs, ransomware count, overdue count at a glance
- **Multiple Sort Options** - Sort by date added, due date, EPSS score, or vendor
- **Quick Filters** - Filter to show only ransomware or overdue vulnerabilities
- **Open in Browser** - Launch NVD page directly from the TUI
- **Copy to Clipboard** - Quick copy CVE IDs
- **Scrollable Detail View** - Navigate long descriptions with keyboard/mouse
- **Visual Indicators** - Color-coded EPSS bars, overdue badges, ransomware flags
- **KEVin AI Agent** - Natural language queries with GRC control mapping

## KEVin AI Agent

KEVin is an AI-powered agent that lets you query the KEV catalog using natural language and map vulnerabilities to security controls (NIST 800-53, FedRAMP).

### Quick Start

```bash
# Interactive chat mode
kevs-tui agent

# One-shot query
kevs-tui agent "show me critical Microsoft vulnerabilities with ransomware"
```

### LLM Provider Configuration

KEVin supports multiple LLM providers. Set `LLM_PROVIDER` and the required API key:

| Provider | `LLM_PROVIDER` | Required Env Var | Default Model |
|----------|----------------|------------------|---------------|
| Google Gemini | `gemini` | `GEMINI_API_KEY` | `gemini-2.0-flash` |
| Vertex AI | `vertex` | `VERTEX_PROJECT`, `VERTEX_LOCATION` | `gemini-2.0-flash` |
| Ollama (local) | `ollama` | `OLLAMA_URL` (optional) | `llama3.2` |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | `anthropic/claude-sonnet-4` |

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
export LLM_MODEL=anthropic/claude-sonnet-4  # optional, this is the default
kevs-tui agent
```

**Ollama (local, no API key needed):**
```bash
export LLM_PROVIDER=ollama
export LLM_MODEL=llama3.2
kevs-tui agent
```

### Agent Capabilities

- **Search KEVs** - Find vulnerabilities by keyword, vendor, product
- **Get CVE Details** - Detailed info including EPSS scores
- **List Ransomware CVEs** - Filter to ransomware-associated vulnerabilities
- **List Overdue CVEs** - Find past-due remediation items
- **Get Statistics** - Catalog overview with top vendors and CWEs
- **Export Reports** - Generate JSON, CSV, or Markdown reports
- **Map to Controls** - Map CVEs to NIST 800-53 or FedRAMP controls

## Keys

| Key | Action |
|-----|--------|
| `/` | Filter/search |
| `j/k` or arrows | Navigate |
| `Enter` | View details |
| `Esc` | Back/clear filter |
| `?` | Toggle help |
| `s` | Cycle sort mode |
| `r` | Toggle ransomware filter |
| `d` | Toggle overdue filter |
| `o` | Open NVD URL in browser |
| `c` | Copy CVE ID to clipboard |
| `t` | Jump to top |
| `b` | Jump to bottom |
| `q` | Quit |

## Data Sources

- **KEV Catalog**: [CISA KEV Data](https://github.com/cisagov/kev-data) - Official GitHub mirror
- **EPSS Scores**: [FIRST EPSS API](https://www.first.org/epss/) - Exploit probability predictions

## License

[MIT](LICENSE)
