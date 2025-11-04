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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
	tree_sitter_java "github.com/tree-sitter/tree-sitter-java/bindings/go"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

const (
	// PUA_THRESHOLD is the default threshold for the ratio of PUA characters in a string.
	PUA_THRESHOLD = 0.50

	// MAX_FILE_SIZE is the default maximum file size to scan (10MB)
	MAX_FILE_SIZE = 10 * 1024 * 1024

	// FILE_TIMEOUT is the maximum time to spend scanning a single file
	FILE_TIMEOUT = 5 * time.Second

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

// Global configuration
var (
	verbose     bool
	maxFileSize int64
)

// FileResult represents the scan result for a single file.
type FileResult struct {
	Path     string  `json:"path"`
	Sketchy  bool    `json:"sketchy"`
	MaxRatio float64 `json:"max_ratio,omitempty"`
}

// SkippedFile represents a file that was skipped during scanning
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Size   int64  `json:"size,omitempty"`
}

// ScanResult represents the overall scan results for all processed files.
type ScanResult struct {
	Threshold    float64       `json:"threshold"`
	TotalFiles   int           `json:"total_files"`
	SketchyFiles int           `json:"sketchy_files"`
	CleanFiles   int           `json:"clean_files"`
	SkippedFiles int           `json:"skipped_files"`
	Files        []FileResult  `json:"files"`
	Skipped      []SkippedFile `json:"skipped,omitempty"`
}

func main() {
	threshold := flag.Float64("threshold", PUA_THRESHOLD, "PUA ratio threshold (0.0-1.0)")
	outputFormat := flag.String("format", "text", "Output format: text or json")
	scanGit := flag.Bool("scan-git", false, "Include .git directories in scan (default: false)")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose progress output")
	maxFileSizeFlag := flag.Int64("max-file-size", MAX_FILE_SIZE, "Maximum file size to scan in bytes (0 = unlimited)")
	flag.Parse()

	verbose = *verboseFlag
	maxFileSize = *maxFileSizeFlag

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "puant: A tool to detect obfuscated malware in source code.")
		fmt.Fprintln(os.Stderr, "\nUsage: puant [options] <file|directory>")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	path := flag.Arg(0)

	if verbose {
		fmt.Fprintf(os.Stderr, "Starting scan of: %s\n", path)
		fmt.Fprintf(os.Stderr, "Threshold: %.2f%%, Max file size: ", *threshold*100)
		if maxFileSize > 0 {
			fmt.Fprintf(os.Stderr, "%d bytes (%.2f MB)\n", maxFileSize, float64(maxFileSize)/(1024*1024))
		} else {
			fmt.Fprintf(os.Stderr, "unlimited\n")
		}
		fmt.Fprintf(os.Stderr, "Workers: %d\n\n", runtime.NumCPU())
	} else {
		fmt.Fprintf(os.Stderr, "Scanning %s...\n", path)
	}

	results, err := scanPath(path, *threshold, *scanGit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning path %q: %v\n", path, err)
		os.Exit(1)
	}

	if *outputFormat == "json" {
		outputJSON(results)
	} else {
		outputText(results)
	}

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
		return extractStringsRegex(string(content))
	}

	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(language) //nolint:errcheck

	tree := parser.Parse(content, nil)
	defer tree.Close()

	var strings []string
	root := tree.RootNode()

	var walk func(*sitter.Node)
	walk = func(node *sitter.Node) {
		if node == nil {
			return
		}

		nodeType := node.Kind()

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

			text = stripQuotes(text)

			if len(text) > 0 {
				strings = append(strings, text)
			}
		}

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

	// Pre-allocate with reasonable capacity to reduce reallocations
	result := &ScanResult{
		Threshold: threshold,
		Files:     make([]FileResult, 0, 100),  // Pre-allocate for potential sketchy files
		Skipped:   make([]SkippedFile, 0, 100), // Pre-allocate for potential skipped files
	}

	if !info.IsDir() {
		// If it's a single file, scan it directly without concurrency.
		scanFile(path, threshold, result)
		return result, nil
	}

	// --- Concurrent Scanning for Directories ---
	var wg sync.WaitGroup
	var processedFiles, skippedFiles atomic.Int64

	// Use a channel to distribute file paths to worker goroutines.
	type fileJob struct {
		path string
		size int64
	}
	filesChan := make(chan fileJob, 10000) // Larger buffer for better throughput
	// Use a channel to collect results from workers.
	type scanOutput struct {
		file    *FileResult
		skipped *SkippedFile
	}
	resultsChan := make(chan scanOutput, 50000) // Very large buffer to handle massive codebases

	// Start progress reporter (always on, verbose shows more detail)
	progressDone := make(chan bool)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				processed := processedFiles.Load()
				skipped := skippedFiles.Load()
				fmt.Fprintf(os.Stderr, "\rScanning... Processed: %d files, Skipped: %d files", processed, skipped)
			case <-progressDone:
				return
			}
		}
	}()

	// Start worker goroutines.
	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range filesChan {
				// Check file size limit
				if maxFileSize > 0 && job.size > maxFileSize {
					skippedFiles.Add(1)
					resultsChan <- scanOutput{
						skipped: &SkippedFile{
							Path:   job.path,
							Reason: "file too large",
							Size:   job.size,
						},
					}
					continue
				}

				// Scan file with timeout
				ctx, cancel := context.WithTimeout(context.Background(), FILE_TIMEOUT)
				fileResult := scanSingleFileWithTimeout(ctx, job.path, threshold)
				cancel()

				if fileResult == nil {
					// File timed out or had an error
					skippedFiles.Add(1)
					resultsChan <- scanOutput{
						skipped: &SkippedFile{
							Path:   job.path,
							Reason: "scan timeout or error",
							Size:   job.size,
						},
					}
					continue
				}

				processedFiles.Add(1)
				resultsChan <- scanOutput{file: fileResult}
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
		if !info.IsDir() {
			if !isSupportedFile(filePath) {
				return nil
			}
			filesChan <- fileJob{
				path: filePath,
				size: info.Size(),
			}
		}
		return nil
	})

	close(filesChan)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for output := range resultsChan {
		if output.file != nil {
			result.TotalFiles++
			if output.file.Sketchy {
				result.SketchyFiles++
				result.Files = append(result.Files, *output.file)
			} else {
				result.CleanFiles++
			}
		}
		if output.skipped != nil {
			result.SkippedFiles++
			result.Skipped = append(result.Skipped, *output.skipped)
		}
	}

	close(progressDone)
	fmt.Fprintf(os.Stderr, "\rScanning complete: %d files processed, %d files skipped\n\n", processedFiles.Load(), skippedFiles.Load())

	if walkErr != nil {
		return nil, fmt.Errorf("failed to walk path %s: %w", path, walkErr)
	}

	return result, nil
}

// scanSingleFileWithTimeout scans a single file with a timeout.
func scanSingleFileWithTimeout(ctx context.Context, filePath string, threshold float64) *FileResult {
	resultChan := make(chan *FileResult, 1)

	go func() {
		resultChan <- scanSingleFile(filePath, threshold)
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		// Timeout occurred
		if verbose {
			fmt.Fprintf(os.Stderr, "\nWarning: Timeout scanning file: %s\n", filePath)
		}
		return nil
	}
}

// scanSingleFile scans a single file and returns a FileResult.
func scanSingleFile(filePath string, threshold float64) *FileResult {
	if verbose {
		fmt.Fprintf(os.Stderr, "Scanning: %s\n", filePath)
	}

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

	if result.TotalFiles == 0 && result.SkippedFiles == 0 {
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

	// Don't print clean files - they're just noise

	// Print skipped files
	if result.SkippedFiles > 0 {
		fmt.Printf("SKIPPED FILES (%d):\n", result.SkippedFiles)
		for _, file := range result.Skipped {
			sizeStr := ""
			if file.Size > 0 {
				sizeStr = fmt.Sprintf(" (size: %.2f MB)", float64(file.Size)/(1024*1024))
			}
			fmt.Printf("  [-] %s - %s%s\n", file.Path, file.Reason, sizeStr)
		}
		fmt.Println()
	}

	// Summary
	fmt.Printf("Summary: %d scanned, %d sketchy, %d skipped\n",
		result.TotalFiles, result.SketchyFiles, result.SkippedFiles)
}
