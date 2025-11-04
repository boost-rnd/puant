package main

import (
	"fmt"
)

// Complex benign Go with edge cases
func main() {
	// Various string types
	simple := "simple string"
	singleQuote := 'a' // rune, not string
	rawString := `Raw string
with newlines
and "quotes"`

	// Escaped characters
	escaped := "String with \"quotes\" and \\backslashes\\"

	// Unicode but NOT PUA
	unicode := "Hello 世界 мир 🌍"

	// Struct with strings
	type Config struct {
		Key1   string
		Key2   string
		Nested struct {
			Deep string
		}
	}

	config := Config{
		Key1: "value1",
		Key2: "value2",
	}
	config.Nested.Deep = "nested value"

	// Slice of strings
	items := []string{
		"first",
		"second",
		`third with "quotes"`,
		fmt.Sprintf("formatted %s", simple),
	}

	// Map with strings
	mapping := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	// Function with string return
	getMessage := func() string {
		return "function string"
	}

	// String concatenation
	concat := "part1" + "part2"

	// Multi-line strings
	multiline := "This is a very long string " +
		"that spans multiple lines " +
		"using explicit concatenation"

	// Comments with "strings" should be ignored
	// "this is a comment"
	/* "multiline
	   comment string" */

	fmt.Println(simple, escaped, unicode, config, items, mapping, getMessage(), concat, multiline)
}
