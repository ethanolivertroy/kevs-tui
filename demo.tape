Output demo.gif

Set FontSize 16
Set Width 1200
Set Height 800
Set Padding 20
Set FontFamily "JetBrains Mono"
Set Theme { "name": "KEV-TUI", "background": "#1E1F29", "foreground": "#FFFFFF", "black": "#282A36", "red": "#FF5F56", "green": "#04B575", "yellow": "#FFCC00", "blue": "#45B7D1", "magenta": "#7D56F4", "cyan": "#4ECDC4", "white": "#F8F8F2", "brightBlack": "#626262", "brightRed": "#FF6B6B", "brightGreen": "#58D68D", "brightYellow": "#F7DC6F", "brightBlue": "#85C1E9", "brightMagenta": "#BB8FCE", "brightCyan": "#98D8C8", "brightWhite": "#FFFFFF", "cursor": "#7D56F4", "selection": "#44475A" }
Set TypingSpeed 50ms

# Launch app (hidden)
Hide
Type "./kevs-tui"
Enter
Sleep 3s
Show

# ══════════════════════════════════════════════════════════════
# 1. MAIN VIEW - Browse KEVs with stats header & EPSS scores
# ══════════════════════════════════════════════════════════════
Sleep 2s

# Scroll through vulnerabilities showing EPSS bars
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 1.5s

# Show help overlay
Type "?"
Sleep 3s
Type "?"
Sleep 500ms

# ══════════════════════════════════════════════════════════════
# 2. SEARCH - Filter by vendor and CVE ID
# ══════════════════════════════════════════════════════════════
Sleep 500ms

# Search for a vendor
Type "/"
Type "microsoft"
Enter
Sleep 2s

# Clear and search for another vendor
Escape
Sleep 800ms
Type "/"
Type "cisco"
Enter
Sleep 2s

# Clear and search by CVE pattern
Escape
Sleep 800ms
Type "/"
Type "CVE-2024"
Enter
Sleep 2s

# Clear search
Escape
Sleep 1s

# ══════════════════════════════════════════════════════════════
# 3. SORT OPTIONS - All 4 modes
# ══════════════════════════════════════════════════════════════
# Sort by date added (default)
Type "s"
Sleep 1.2s
# Sort by due date
Type "s"
Sleep 1.2s
# Sort by EPSS score
Type "s"
Sleep 1.2s
# Sort by vendor
Type "s"
Sleep 1.5s

# ══════════════════════════════════════════════════════════════
# 4. QUICK FILTERS - Ransomware and Overdue
# ══════════════════════════════════════════════════════════════

# Toggle ransomware filter ON
Type "r"
Sleep 1.5s

# Toggle ransomware filter OFF
Type "r"
Sleep 1s

# Toggle overdue filter ON
Type "d"
Sleep 1.5s

# Toggle overdue filter OFF
Type "d"
Sleep 1s

# ══════════════════════════════════════════════════════════════
# 5. DETAIL VIEW - Full CVE details with scrolling
# ══════════════════════════════════════════════════════════════

# Go to top
Type "t"
Sleep 500ms

# Open first item detail view
Enter
Sleep 2s

# Scroll through details to show description, EPSS, CWEs
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 1.5s

# Copy CVE ID to clipboard
Type "c"
Sleep 1.5s

# Go back
Escape
Sleep 1s

# ══════════════════════════════════════════════════════════════
# 6. CHARTS & GRAPHS - Analytics dashboards
# ══════════════════════════════════════════════════════════════

# Open charts menu
Type "g"
Sleep 1.5s

# View top vendors chart
Enter
Sleep 2.5s

# Navigate vendor list
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 1.5s

# Go back to charts menu
Escape
Sleep 1s

# Navigate to timeline chart
Type "j"
Sleep 500ms
Enter
Sleep 2.5s

# Go back to charts menu
Escape
Sleep 1s

# Navigate to ransomware chart
Type "j"
Sleep 500ms
Enter
Sleep 2.5s

# Go back to charts menu
Escape
Sleep 1s

# Navigate to CWE chart
Type "j"
Sleep 500ms
Enter
Sleep 2.5s

# Go back to charts menu
Escape
Sleep 1s

# Navigate to risk chart (EPSS distribution)
Type "j"
Sleep 500ms
Enter
Sleep 2.5s

# Go back to main view
Escape
Sleep 500ms
Escape
Sleep 1s

# ══════════════════════════════════════════════════════════════
# 7. EXPORT MENU - Export data options
# ══════════════════════════════════════════════════════════════

# Open export menu
Type "x"
Sleep 2s

# Navigate through export options
Type "j"
Sleep 500ms
Type "j"
Sleep 500ms
Type "j"
Sleep 1s

# Cancel export
Escape
Sleep 1s

# ══════════════════════════════════════════════════════════════
# 8. NAVIGATION - Jump top/bottom
# ══════════════════════════════════════════════════════════════

# Jump to bottom
Type "b"
Sleep 1.5s

# Jump to top
Type "t"
Sleep 1s

# Quit
Type "q"
