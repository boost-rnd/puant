// Copyright 2025 BoostSecurity.io
//
// Licensed under the AGPLv3 License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.html

// puant is a command-line tool for detecting obfuscated malware in source code.
// It works by identifying strings with a high ratio of Unicode Private Use Area (PUA)
// characters, a technique sometimes used for malware obfuscation.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
	tree_sitter_java "github.com/tree-sitter/tree-sitter-java/bindings/go"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

const (
	// PUA_THRESHOLD is the default threshold for the ratio of PUA characters in a string.
	PUA_THRESHOLD = 0.50

	// Unicode Private Use Areas (PUA) ranges.
	puaBMPStart   = '\uE000'
	puaBMPEnd     = '\uF8FF'
	puaTagsStart  = '\U000E0000'
	puaTagsEnd    = '\U000E0FFF'
	puaSuppAStart = '\U000F0000'
	puaSuppAEnd   = '\U000FFFFD'
	puaSuppBStart = '\U00100000'
	puaSuppBEnd   = '\U0010FFFD'
)

// FileResult represents the scan result for a single file.
type FileResult struct {
	Path     string  `json:"path"`
	Sketchy  bool    `json:"sketchy"`
	MaxRatio float64 `json:"max_ratio,omitempty"`
}

// ScanResult represents the overall scan results for all processed files.
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
		fmt.Fprintf(os.Stderr, "Error scanning path %q: %v\n", path, err)
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

// isPUACharacter checks if a rune is in the Private Use Area or related obfuscation ranges.
func isPUACharacter(r rune) bool {
	return (r >= puaBMPStart && r <= puaBMPEnd) ||
		(r >= puaTagsStart && r <= puaTagsEnd) ||
		(r >= puaSuppAStart && r <= puaSuppAEnd) ||
		(r >= puaSuppBStart && r <= puaSuppBEnd)
}

// LanguageMap maps file extensions to their corresponding tree-sitter language.
var LanguageMap = map[string]*sitter.Language{
	".js":   sitter.NewLanguage(tree_sitter_javascript.Language()),
	".jsx":  sitter.NewLanguage(tree_sitter_javascript.Language()),
	".mjs":  sitter.NewLanguage(tree_sitter_javascript.Language()),
	".cjs":  sitter.NewLanguage(tree_sitter_javascript.Language()),
	".py":   sitter.NewLanguage(tree_sitter_python.Language()),
	".pyw":  sitter.NewLanguage(tree_sitter_python.Language()),
	".go":   sitter.NewLanguage(tree_sitter_go.Language()),
	".java": sitter.NewLanguage(tree_sitter_java.Language()),
}

// getLanguageParser returns the appropriate tree-sitter parser for a file.
func getLanguageParser(filePath string) *sitter.Language {
	ext := strings.ToLower(filepath.Ext(filePath))
	return LanguageMap[ext]
}

// isSupportedFile checks if a file has a supported extension.
func isSupportedFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	_, supported := LanguageMap[ext]
	return supported
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

// exceedsThreshold checks if a string's PUA ratio is likely to exceed a given threshold.
// It uses a short-circuiting algorithm for efficiency, stopping the scan as soon as
// the threshold is confirmed to be met.
func exceedsThreshold(s string, threshold float64) bool {
	if len(s) == 0 {
		return false
	}

	runes := []rune(s)
	totalChars := len(runes)
	puaCount := 0

	// The minimum number of PUA characters required to meet the threshold.
	minPUACount := int(float64(totalChars) * threshold)

	if minPUACount == 0 {
		// If threshold is 0, any PUA character will exceed it.
		// If string is non-empty and has no PUA, this will still be efficient.
		minPUACount = 1
	}

	for _, r := range runes {
		if isPUACharacter(r) {
			puaCount++
			// If we have found enough PUA characters to meet the threshold,
			// we can exit early.
			if puaCount >= minPUACount {
				return true
			}
		}
	}

	// Final check after iterating through the entire string.
	return puaCount >= minPUACount
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

// scanPath scans a file or directory recursively, using a worker pool for concurrency.
func scanPath(path string, threshold float64, scanGit bool) (*ScanResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
	}

	result := &ScanResult{
		Threshold: threshold,
		Files:     []FileResult{},
	}

	if !info.IsDir() {
		// If it's a single file, scan it directly without concurrency.
		scanFile(path, threshold, result)
		return result, nil
	}

	// --- Concurrent Scanning for Directories ---
	var wg sync.WaitGroup
	// Use a channel to distribute file paths to worker goroutines.
	filesChan := make(chan string, 100)
	// Use a channel to collect results from workers.
	resultsChan := make(chan FileResult, 100)

	// Start worker goroutines.
	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range filesChan {
				fileResult := scanSingleFile(filePath, threshold)
				if fileResult != nil {
					resultsChan <- *fileResult
				}
			}
		}()
	}

	// Walk the directory and send files to the workers.
	walkErr := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == ".git" && !scanGit {
			return filepath.SkipDir
		}
		if !info.IsDir() && isSupportedFile(filePath) {
			filesChan <- filePath
		}
		return nil
	})

	close(filesChan)

	// Wait for all workers to finish, then close the results channel.
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect and aggregate results.
	for fileResult := range resultsChan {
		result.TotalFiles++
		if fileResult.Sketchy {
			result.SketchyFiles++
		} else {
			result.CleanFiles++
		}
		result.Files = append(result.Files, fileResult)
	}

	if walkErr != nil {
		return nil, fmt.Errorf("failed to walk path %s: %w", path, walkErr)
	}

	return result, nil
}

// scanSingleFile scans a single file and returns a FileResult.
// This function is designed to be called from a worker goroutine.
func scanSingleFile(filePath string, threshold float64) *FileResult {
	content, err := os.ReadFile(filePath)
	if err != nil {
		// Skip files that cannot be read.
		return nil
	}

	isSketchy, maxRatio := isFileSketchy(filePath, content, threshold)

	fileResult := &FileResult{
		Path:    filePath,
		Sketchy: isSketchy,
	}

	if isSketchy {
		fileResult.MaxRatio = maxRatio
	}

	return fileResult
}

// scanFile scans a single file and updates the result (for non-concurrent scans).
func scanFile(filePath string, threshold float64, result *ScanResult) {
	fileResult := scanSingleFile(filePath, threshold)
	if fileResult != nil {
		result.TotalFiles++
		if fileResult.Sketchy {
			result.SketchyFiles++
		} else {
			result.CleanFiles++
		}
		result.Files = append(result.Files, *fileResult)
	}
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
