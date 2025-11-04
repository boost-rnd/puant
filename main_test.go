package main

import (
	"os"
	"testing"
)

// TestBenignFiles tests that benign files are correctly identified as clean
func TestBenignFiles(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
	}{
		{"Simple JavaScript", "testdata/benign_javascript.js"},
		{"Simple Python", "testdata/benign_python.py"},
		{"Simple Go", "testdata/benign_go.go"},
		{"JavaScript with some PUA", "testdata/benign_with_some_pua.js"},
		{"Complex JavaScript", "testdata/benign_complex_js.js"},
		{"Complex Python", "testdata/benign_complex_python.py"},
		{"Complex Go", "testdata/benign_complex_go.go"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := os.ReadFile(tt.filePath)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", tt.filePath, err)
			}

			isSketchy, _ := isFileSketchy(tt.filePath, content, PUA_THRESHOLD)
			if isSketchy {
				t.Errorf("File %s was incorrectly flagged as sketchy (false positive)", tt.filePath)
			}
		})
	}
}

// TestSketchyFiles tests that sketchy files with high PUA ratios are correctly detected
func TestSketchyFiles(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
	}{
		{"High PUA JavaScript", "testdata/sketchy_high_pua_js.js"},
		{"Medium PUA JavaScript", "testdata/sketchy_medium_pua_js.js"},
		{"Threshold PUA JavaScript", "testdata/sketchy_threshold_js.js"},
		{"Sketchy Python", "testdata/sketchy_python_pua.py"},
		{"Sketchy Go", "testdata/sketchy_go_pua.go"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := os.ReadFile(tt.filePath)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", tt.filePath, err)
			}

			isSketchy, _ := isFileSketchy(tt.filePath, content, PUA_THRESHOLD)
			if !isSketchy {
				t.Errorf("File %s was not detected as sketchy (false negative)", tt.filePath)
			}
		})
	}
}

// TestPUACharacterDetection tests the isPUACharacter function
func TestPUACharacterDetection(t *testing.T) {
	tests := []struct {
		name     string
		char     rune
		expected bool
	}{
		{"ASCII letter", 'a', false},
		{"ASCII number", '1', false},
		{"Basic Unicode", '世', false},
		{"Emoji", '🌍', false},
		{"BMP PUA", '\uE000', true},
		{"BMP PUA mid", '\uF000', true},
		{"BMP PUA end", '\uF8FF', true},
		{"Variation Selector start", '\U000E0100', true},
		{"Variation Selector mid", '\U000E0166', true},
		{"Variation Selector end", '\U000E01EF', true},
		{"Supplementary PUA-A start", '\U000F0000', true},
		{"Supplementary PUA-A end", '\U000FFFFD', true},
		{"Supplementary PUA-B start", '\U00100000', true},
		{"Supplementary PUA-B end", '\U0010FFFD', true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPUACharacter(tt.char)
			if result != tt.expected {
				t.Errorf("isPUACharacter(%U) = %v, expected %v", tt.char, result, tt.expected)
			}
		})
	}
}

// TestPUARatioCalculation tests the calculatePUARatio function
func TestPUARatioCalculation(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{"Empty string", "", 0.0},
		{"No PUA chars", "Hello World", 0.0},
		{"All PUA chars", "\uE000\uE001\uE002", 1.0},
		{"50% PUA chars", "ab\uE000\uE001", 0.5},
		{"80% PUA chars", "a\uE000\uE001\uE002\uE003", 0.8},
		{"Mixed Unicode no PUA", "Hello 世界", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculatePUARatio(tt.input)
			if result != tt.expected {
				t.Errorf("calculatePUARatio(%q) = %f, expected %f", tt.input, result, tt.expected)
			}
		})
	}
}

// TestLanguageDetection tests that the correct parser is selected for each file type
func TestLanguageDetection(t *testing.T) {
	tests := []struct {
		name      string
		filePath  string
		hasParser bool
	}{
		{"JavaScript .js", "test.js", true},
		{"JavaScript .jsx", "test.jsx", true},
		{"JavaScript .mjs", "test.mjs", true},
		{"JavaScript .cjs", "test.cjs", true},
		{"Python .py", "test.py", true},
		{"Python .pyw", "test.pyw", true},
		{"Go .go", "test.go", true},
		{"Java .java", "test.java", true},
		{"Unknown .txt", "test.txt", false},
		{"Unknown .c", "test.c", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := getLanguageParser(tt.filePath)
			hasParser := parser != nil
			if hasParser != tt.hasParser {
				t.Errorf("getLanguageParser(%s) returned parser=%v, expected parser=%v", tt.filePath, hasParser, tt.hasParser)
			}
		})
	}
}

// BenchmarkTreeSitterExtraction benchmarks the tree-sitter string extraction
func BenchmarkTreeSitterExtraction(b *testing.B) {
	content, err := os.ReadFile("testdata/sketchy_high_pua_js.js")
	if err != nil {
		b.Fatalf("Failed to read test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractStringsTreeSitter("testdata/sketchy_high_pua_js.js", content)
	}
}

// BenchmarkRegexExtraction benchmarks the fallback regex extraction
func BenchmarkRegexExtraction(b *testing.B) {
	content, err := os.ReadFile("testdata/sketchy_high_pua_js.js")
	if err != nil {
		b.Fatalf("Failed to read test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractStringsRegex(string(content))
	}
}

// BenchmarkPUADetection benchmarks the full detection process
func BenchmarkPUADetection(b *testing.B) {
	content, err := os.ReadFile("testdata/sketchy_high_pua_js.js")
	if err != nil {
		b.Fatalf("Failed to read test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isFileSketchy("testdata/sketchy_high_pua_js.js", content, PUA_THRESHOLD)
	}
}

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
