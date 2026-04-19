# kevs-tui archival note

`kevs-tui` is being archived and replaced by the Pi-native successor:

- **New home:** `/Users/ethantroy/Git/Github/kevin-pi`
- **New architecture:** Pi extension + Pi skill
- **Install:** `pi install /Users/ethantroy/Git/Github/kevin-pi`

## Why archive this repository?

The original Go/Bubble Tea app proved out the product idea well:

- fast CISA KEV browsing
- EPSS-aware prioritization
- agentic vulnerability assistance
- compliance and analytics workflows

But the long-term direction is to make KEVin a first-class Pi experience instead of maintaining a separate app runtime.

## What replaces it?

`kevin-pi` is the actively maintained successor and now contains the core KEVin experience as a native Pi package.

It includes:

- KEV search and CVE detail tools
- patch and exploit triage tools
- GRC mapping tools for NIST, FedRAMP, and CIS
- analytics tools for related CVEs, vendor risk, CWE analysis, batch analysis, and trends
- a Pi-native `/kev` browser UI
- a `kev-analyst` skill for remediation-focused workflows

## Migration

Install the new package:

```bash
pi install /Users/ethantroy/Git/Github/kevin-pi
```

Then use:

```bash
/kev
/cve CVE-2024-3400
/skill:kev-analyst
```

## Suggested GitHub archive blurb

> This repository is archived and no longer actively maintained.
> KEVin now lives as a Pi-native package in `kevin-pi`, where future development will continue.
> Install the successor with `pi install /Users/ethantroy/Git/Github/kevin-pi`.
