package tui

import "testing"

func TestSetTheme(t *testing.T) {
	tests := []struct {
		name     string
		theme    ThemeName
		wantName ThemeName
	}{
		{"set default", ThemeDefault, ThemeDefault},
		{"set dracula", ThemeDracula, ThemeDracula},
		{"set catppuccin", ThemeCatppuccin, ThemeCatppuccin},
		{"set nord", ThemeNord, ThemeNord},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetTheme(tt.theme)
			if CurrentTheme.Name != tt.wantName {
				t.Errorf("SetTheme(%v) = %v, want %v", tt.theme, CurrentTheme.Name, tt.wantName)
			}
		})
	}

	// Reset to default
	SetTheme(ThemeDefault)
}

func TestSetThemeInvalid(t *testing.T) {
	// Save current theme
	original := CurrentTheme.Name

	// Try to set invalid theme - should not change
	SetTheme("invalid-theme")

	// Theme should remain unchanged (SetTheme only changes if theme exists)
	if CurrentTheme.Name != original {
		t.Errorf("SetTheme with invalid theme changed CurrentTheme")
	}

	// Reset
	SetTheme(ThemeDefault)
}

func TestCycleTheme(t *testing.T) {
	// Start from default
	SetTheme(ThemeDefault)

	// Cycle through all themes
	expected := []ThemeName{ThemeDracula, ThemeCatppuccin, ThemeNord, ThemeDefault}
	for _, want := range expected {
		got := CycleTheme()
		if got != want {
			t.Errorf("CycleTheme() = %v, want %v", got, want)
		}
	}

	// Reset
	SetTheme(ThemeDefault)
}

func TestThemeColorsNotEmpty(t *testing.T) {
	for name, theme := range Themes {
		t.Run(string(name), func(t *testing.T) {
			if theme.Primary == "" {
				t.Error("Primary color is empty")
			}
			if theme.Secondary == "" {
				t.Error("Secondary color is empty")
			}
			if theme.Subtle == "" {
				t.Error("Subtle color is empty")
			}
			if theme.Overdue == "" {
				t.Error("Overdue color is empty")
			}
			if theme.Foreground == "" {
				t.Error("Foreground color is empty")
			}
			if theme.Background == "" {
				t.Error("Background color is empty")
			}
		})
	}
}

func TestAllThemesExist(t *testing.T) {
	expectedThemes := []ThemeName{ThemeDefault, ThemeDracula, ThemeCatppuccin, ThemeNord}

	for _, name := range expectedThemes {
		if _, ok := Themes[name]; !ok {
			t.Errorf("Theme %v not found in Themes map", name)
		}
	}
}

func TestUpdateStylesChangesColors(t *testing.T) {
	// Set to dracula theme
	SetTheme(ThemeDracula)

	// Check that PrimaryColor was updated
	if PrimaryColor != Themes[ThemeDracula].Primary {
		t.Errorf("PrimaryColor not updated: got %v, want %v", PrimaryColor, Themes[ThemeDracula].Primary)
	}

	// Reset
	SetTheme(ThemeDefault)
}
