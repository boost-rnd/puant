package main

import (
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("puant: A tool to detect obfuscated malware in source code.\n\nUsage: puant <file>")
		os.Exit(1)
	}

	filePath := os.Args[1]
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	if isFileSketchy(filePath, content) {
		fmt.Printf("SKETCHY: %s contains high ratio of PUA characters\n", filePath)
		os.Exit(0)
	} else {
		fmt.Printf("CLEAN: %s appears safe\n", filePath)
		os.Exit(0)
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

// isFileSketchy determines if a file contains suspicious PUA-obfuscated strings
func isFileSketchy(filePath string, content []byte) bool {
	strings := extractStringsTreeSitter(filePath, content)

	for _, str := range strings {
		ratio := calculatePUARatio(str)
		// Check if any string exceeds the threshold
		if ratio >= PUA_THRESHOLD {
			return true
		}
	}

	return false
}
