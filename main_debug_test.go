//go:build debug

package main

import (
	"os"
	"testing"
)

// TestStringExtraction shows what strings are being extracted (debugging test)
func TestStringExtraction(t *testing.T) {
	testFiles := []string{
		"testdata/sketchy_medium_pua_js.js",
		"testdata/sketchy_threshold_js.js",
	}

	for _, file := range testFiles {
		t.Run(file, func(t *testing.T) {
			content, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("Failed to read file: %v", err)
			}

			strings := extractStringsTreeSitter(file, content)
			t.Logf("\nExtracted %d strings from %s:", len(strings), file)
			for i, str := range strings {
				ratio := calculatePUARatio(str)
				runes := []rune(str)
				preview := str
				if len(runes) > 50 {
					preview = string(runes[:50]) + "..."
				}
				t.Logf("  %d. [%.2f%% PUA, %d chars] %q", i+1, ratio*100, len(runes), preview)
			}
		})
	}
}
