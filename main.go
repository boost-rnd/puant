package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
	tree_sitter_java "github.com/tree-sitter/tree-sitter-java/bindings/go"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

const PUA_THRESHOLD = 0.50 // 50% PUA characters threshold - anything above this is sketchy AF

// FileResult represents the scan result for a single file
type FileResult struct {
	Path     string  `json:"path"`
	Sketchy  bool    `json:"sketchy"`
	MaxRatio float64 `json:"max_ratio,omitempty"`
}

// ScanResult represents the overall scan results
type ScanResult struct {
	Threshold    float64      `json:"threshold"`
	TotalFiles   int          `json:"total_files"`
	SketchyFiles int          `json:"sketchy_files"`
	CleanFiles   int          `json:"clean_files"`
	Files        []FileResult `json:"files"`
}

func main() {
	// CLI flags
	threshold := flag.Float64("threshold", PUA_THRESHOLD, "PUA ratio threshold (0.0-1.0)")
	outputFormat := flag.String("format", "text", "Output format: text or json")
	scanGit := flag.Bool("scan-git", false, "Include .git directories in scan (default: false)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "puant: A tool to detect obfuscated malware in source code.")
		fmt.Fprintln(os.Stderr, "\nUsage: puant [options] <file|directory>")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	path := flag.Arg(0)
	results, err := scanPath(path, *threshold, *scanGit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	// Output results
	if *outputFormat == "json" {
		outputJSON(results)
	} else {
		outputText(results)
	}

	// Exit with error code if sketchy files found
	if results.SketchyFiles > 0 {
		os.Exit(1)
	}
}

// isPUACharacter checks if a rune is in the Private Use Area or related obfuscation ranges
func isPUACharacter(r rune) bool {
	// Unicode ranges commonly used for obfuscation:
	// U+E000 to U+F8FF (BMP Private Use Area)
	// U+E0000 to U+E0FFF (Tags, Variation Selectors Supplement - often used for obfuscation)
	// U+F0000 to U+FFFFD (Supplementary Private Use Area-A)
	// U+100000 to U+10FFFD (Supplementary Private Use Area-B)
	return (r >= 0xE000 && r <= 0xF8FF) ||
		(r >= 0xE0000 && r <= 0xE0FFF) ||
		(r >= 0xF0000 && r <= 0xFFFFD) ||
		(r >= 0x100000 && r <= 0x10FFFD)
}

// getLanguageParser returns the appropriate tree-sitter parser for a file
func getLanguageParser(filePath string) *sitter.Language {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs":
		return sitter.NewLanguage(tree_sitter_javascript.Language())
	case ".py", ".pyw":
		return sitter.NewLanguage(tree_sitter_python.Language())
	case ".go":
		return sitter.NewLanguage(tree_sitter_go.Language())
	case ".java":
		return sitter.NewLanguage(tree_sitter_java.Language())
	// TODO: Add C# support once package issues are resolved
	// case ".cs":
	//   return sitter.NewLanguage(tree_sitter_csharp.Language())
	default:
		return nil
	}
}

// extractStringsTreeSitter extracts string literals using tree-sitter
func extractStringsTreeSitter(filePath string, content []byte) []string {
	language := getLanguageParser(filePath)
	if language == nil {
		// Fallback to regex-based extraction for unsupported languages
		return extractStringsRegex(string(content))
	}

	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(language) //nolint:errcheck

	tree := parser.Parse(content, nil)
	defer tree.Close()

	var strings []string
	root := tree.RootNode()

	// Walk the AST and collect all string nodes
	var walk func(*sitter.Node)
	walk = func(node *sitter.Node) {
		if node == nil {
			return
		}

		nodeType := node.Kind()

		// String node types vary by language
		isString := nodeType == "string" ||
			nodeType == "string_literal" ||
			nodeType == "interpreted_string_literal" ||
			nodeType == "raw_string_literal" ||
			nodeType == "template_string" ||
			nodeType == "string_content"

		if isString {
			start := node.StartByte()
			end := node.EndByte()
			text := string(content[start:end])

			// Strip quote delimiters (", ', `) from the string
			text = stripQuotes(text)

			if len(text) > 0 {
				strings = append(strings, text)
			}
		}

		// Recursively walk children
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			walk(child)
		}
	}

	walk(root)
	return strings
}

// extractStringsRegex is a fallback for unsupported file types
func extractStringsRegex(content string) []string {
	var strings []string

	// Basic patterns for common string literals
	patterns := []string{
		`"(?:[^"\\]|\\.)*"`,
		`'(?:[^'\\]|\\.)*'`,
		"`[^`]+`",
	}

	for _, pattern := range patterns {
		matches := regexp.MustCompile(pattern).FindAllString(content, -1)
		strings = append(strings, matches...)
	}

	return strings
}

// stripQuotes removes surrounding quote characters from a string
func stripQuotes(s string) string {
	if len(s) < 2 {
		return s
	}

	// Check if surrounded by matching quotes
	if (s[0] == '"' && s[len(s)-1] == '"') ||
		(s[0] == '\'' && s[len(s)-1] == '\'') ||
		(s[0] == '`' && s[len(s)-1] == '`') {
		return s[1 : len(s)-1]
	}

	return s
}

// calculatePUARatio returns the ratio of PUA characters to total characters
func calculatePUARatio(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	runes := []rune(s)
	totalChars := len(runes)
	puaCount := 0

	for _, r := range runes {
		if isPUACharacter(r) {
			puaCount++
		}
	}

	return float64(puaCount) / float64(totalChars)
}

// exceedsThreshold checks if string has PUA ratio above threshold (short-circuits for efficiency)
func exceedsThreshold(s string, threshold float64) bool {
	if len(s) == 0 {
		return false
	}

	runes := []rune(s)
	totalChars := len(runes)
	puaCount := 0

	for i, r := range runes {
		if isPUACharacter(r) {
			puaCount++
			// Short circuit: if we've found enough PUA chars to exceed threshold, return early
			currentRatio := float64(puaCount) / float64(i+1)
			// Best case: even if remaining chars are all non-PUA, we'd still exceed threshold
			bestCaseRatio := float64(puaCount) / float64(totalChars)
			if bestCaseRatio >= threshold {
				return true
			}
			// Current ratio check for early exit
			if currentRatio >= threshold && float64(puaCount)/float64(totalChars) >= threshold {
				return true
			}
		}
	}

	finalRatio := float64(puaCount) / float64(totalChars)
	return finalRatio >= threshold
}

// isFileSketchy determines if a file contains suspicious PUA-obfuscated strings
// Returns (isSketchy, maxRatio) where maxRatio is the highest PUA ratio found
func isFileSketchy(filePath string, content []byte, threshold float64) (bool, float64) {
	strings := extractStringsTreeSitter(filePath, content)
	maxRatio := 0.0

	for _, str := range strings {
		ratio := calculatePUARatio(str)
		if ratio > maxRatio {
			maxRatio = ratio
		}
		// Use the short-circuiting threshold check
		if exceedsThreshold(str, threshold) {
			return true, maxRatio
		}
	}

	return false, maxRatio
}

// scanPath scans a file or directory recursively
func scanPath(path string, threshold float64, scanGit bool) (*ScanResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	result := &ScanResult{
		Threshold: threshold,
		Files:     []FileResult{},
	}

	if info.IsDir() {
		err = filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip .git directories unless scanGit flag is set
			if info.IsDir() && info.Name() == ".git" && !scanGit {
				return filepath.SkipDir
			}

			if !info.IsDir() && isSupportedFile(filePath) {
				scanFile(filePath, threshold, result)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		scanFile(path, threshold, result)
	}

	return result, nil
}

// isSupportedFile checks if a file has a supported extension
func isSupportedFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	supportedExts := []string{".js", ".jsx", ".mjs", ".cjs", ".py", ".pyw", ".go", ".java"}
	for _, supported := range supportedExts {
		if ext == supported {
			return true
		}
	}
	return false
}

// scanFile scans a single file and updates the result
func scanFile(filePath string, threshold float64, result *ScanResult) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		// Skip files we can't read
		return
	}

	isSketchy, maxRatio := isFileSketchy(filePath, content, threshold)

	fileResult := FileResult{
		Path:    filePath,
		Sketchy: isSketchy,
	}

	if isSketchy {
		fileResult.MaxRatio = maxRatio
		result.SketchyFiles++
	} else {
		result.CleanFiles++
	}

	result.TotalFiles++
	result.Files = append(result.Files, fileResult)
}

// outputJSON outputs results in JSON format
func outputJSON(result *ScanResult) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(result) //nolint:errcheck
}

// outputText outputs results in human-readable text format
func outputText(result *ScanResult) {
	fmt.Printf("Scan Results (threshold: %.2f%%)\n", result.Threshold*100)
	fmt.Printf("=====================================\n\n")

	if result.TotalFiles == 0 {
		fmt.Println("No supported files found.")
		return
	}

	// Print sketchy files first
	if result.SketchyFiles > 0 {
		fmt.Printf("SKETCHY FILES (%d):\n", result.SketchyFiles)
		for _, file := range result.Files {
			if file.Sketchy {
				fmt.Printf("  [!] %s (max ratio: %.2f%%)\n", file.Path, file.MaxRatio*100)
			}
		}
		fmt.Println()
	}

	// Print clean files
	if result.CleanFiles > 0 {
		fmt.Printf("CLEAN FILES (%d):\n", result.CleanFiles)
		for _, file := range result.Files {
			if !file.Sketchy {
				fmt.Printf("  [✓] %s\n", file.Path)
			}
		}
		fmt.Println()
	}

	// Summary
	fmt.Printf("Summary: %d total, %d sketchy, %d clean\n",
		result.TotalFiles, result.SketchyFiles, result.CleanFiles)
}
