# CISA KEV TUI

Terminal UI for searching CISA Known Exploited Vulnerabilities (KEV) catalog with EPSS exploit probability scores.

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

MIT
