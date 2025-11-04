// Copyright 2025 BoostSecurity.io
//
// Licensed under the AGPLv3 License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.html

package main

import (
	"strings"
	"testing"
)

// varyLength creates varied string lengths based on average and index
func varyLength(avgLength int, index int) int {
	// Create variety: 50% average, 20% short, 20% long, 10% very short/long
	switch index % 10 {
	case 0, 1, 2, 3, 4: // 50% - around average
		return avgLength
	case 5, 6: // 20% - shorter (60-80%)
		return int(float64(avgLength) * (0.6 + float64(index%20)/100.0))
	case 7, 8: // 20% - longer (120-150%)
		return int(float64(avgLength) * (1.2 + float64(index%30)/100.0))
	case 9: // 10% - very varied (30-200%)
		if index%3 == 0 {
			return int(float64(avgLength) * 0.3)
		}
		return int(float64(avgLength) * 2.0)
	}
	return avgLength
}

// generatePUAString creates a string with a specific PUA ratio
func generatePUAString(length int, puaRatio float64) string {
	if length == 0 {
		return ""
	}

	puaCount := int(float64(length) * puaRatio)
	normalCount := length - puaCount

	runes := make([]rune, length)

	// Fill with normal ASCII characters (more variety than before)
	normalChars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-./:")
	for i := 0; i < normalCount; i++ {
		runes[i] = normalChars[i%len(normalChars)]
	}

	// Fill remaining with PUA characters from BMP PUA range (U+E000 to U+F8FF)
	for i := normalCount; i < length; i++ {
		runes[i] = rune(0xE000 + (i-normalCount)%0x8FF)
	}

	// Simple deterministic shuffle for consistent benchmarks
	for i := len(runes) - 1; i > 0; i-- {
		j := i % (i + 1)
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes)
}

// generateJavaScriptFile creates synthetic JavaScript code with many strings
func generateJavaScriptFile(stringCount int, avgStringLength int, puaRatio float64) string {
	var builder strings.Builder
	stringsAdded := 0

	builder.WriteString("// Auto-generated benchmark file\n")
	builder.WriteString("// Simulates real-world JavaScript with varied string usage\n\n")

	// Add some imports
	builder.WriteString("const crypto = require('crypto');\n")
	builder.WriteString("const path = require('path');\n\n")

	// Config object with single-line strings
	builder.WriteString("const config = {\n")
	configStrings := stringCount / 4
	for i := 0; i < configStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		builder.WriteString("  key_")
		builder.WriteString(intToString(i))
		builder.WriteString(": \"")
		builder.WriteString(str)
		builder.WriteString("\",\n")
		stringsAdded++
	}
	builder.WriteString("};\n\n")

	// Function with template literals (multiline)
	builder.WriteString("function processData(input) {\n")
	builder.WriteString("  const template = `\n")
	multilineStrings := stringCount / 6
	for i := 0; i < multilineStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		builder.WriteString("    ")
		builder.WriteString(str)
		builder.WriteString("\n")
		stringsAdded++
	}
	builder.WriteString("  `;\n")
	builder.WriteString("  return template.split('\\n').filter(x => x.length > 0);\n")
	builder.WriteString("}\n\n")

	// Class with methods and strings
	builder.WriteString("class DataHandler {\n")
	builder.WriteString("  constructor() {\n")
	builder.WriteString("    this.messages = [\n")
	arrayStrings := stringCount / 5
	for i := 0; i < arrayStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		builder.WriteString("      \"")
		builder.WriteString(str)
		builder.WriteString("\",\n")
		stringsAdded++
	}
	builder.WriteString("    ];\n")
	builder.WriteString("  }\n\n")

	builder.WriteString("  getMessage(index) {\n")
	builder.WriteString("    return this.messages[index] || \"default\";\n")
	builder.WriteString("  }\n\n")

	builder.WriteString("  setMessages(msgs) {\n")
	builder.WriteString("    const defaults = {\n")
	moreStrings := stringCount / 6
	for i := 0; i < moreStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		builder.WriteString("      msg")
		builder.WriteString(intToString(i))
		builder.WriteString(": \"")
		builder.WriteString(str)
		builder.WriteString("\",\n")
		stringsAdded++
	}
	builder.WriteString("    };\n")
	builder.WriteString("    this.messages = { ...defaults, ...msgs };\n")
	builder.WriteString("  }\n")
	builder.WriteString("}\n\n")

	// Object with nested structures
	builder.WriteString("const metadata = {\n")
	builder.WriteString("  version: \"1.0.0\",\n")
	builder.WriteString("  descriptions: {\n")
	nestedStrings := stringCount / 8
	for i := 0; i < nestedStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		builder.WriteString("    desc")
		builder.WriteString(intToString(i))
		builder.WriteString(": \"")
		builder.WriteString(str)
		builder.WriteString("\",\n")
		stringsAdded++
	}
	builder.WriteString("  },\n")
	builder.WriteString("  multiline: `\n")
	// Add remaining strings as multiline
	for stringsAdded < stringCount {
		length := varyLength(avgStringLength, stringsAdded)
		str := generatePUAString(length, puaRatio)
		builder.WriteString("    ")
		builder.WriteString(str)
		builder.WriteString("\n")
		stringsAdded++
	}
	builder.WriteString("  `,\n")
	builder.WriteString("};\n\n")

	builder.WriteString("module.exports = { config, DataHandler, processData, metadata };\n")
	return builder.String()
}

// generatePythonFile creates synthetic Python code with many strings
func generatePythonFile(stringCount int, avgStringLength int, puaRatio float64) string {
	var code string
	stringsAdded := 0

	code += "# Auto-generated benchmark file\n"
	code += "# Simulates real-world Python with varied string usage\n\n"
	code += "import os\n"
	code += "import json\n"
	code += "from typing import Dict, List\n\n"

	// Constants and config
	code += "CONFIG = {\n"
	configStrings := stringCount / 4
	for i := 0; i < configStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		code += "    \"key_" + intToString(i) + "\": \"" + str + "\",\n"
		stringsAdded++
	}
	code += "}\n\n"

	// Class with docstrings and methods
	code += "class DataProcessor:\n"
	code += "    \"\"\"Processes data with various string operations.\"\"\"\n\n"
	code += "    def __init__(self):\n"
	code += "        self.messages = [\n"
	arrayStrings := stringCount / 5
	for i := 0; i < arrayStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		code += "            \"" + str + "\",\n"
		stringsAdded++
	}
	code += "        ]\n\n"

	// Method with multiline strings (triple quotes)
	code += "    def get_template(self) -> str:\n"
	code += "        return \"\"\"\n"
	multilineStrings := stringCount / 6
	for i := 0; i < multilineStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		code += "        " + str + "\n"
		stringsAdded++
	}
	code += "        \"\"\"\n\n"

	// Method with f-strings
	code += "    def format_data(self, index: int) -> str:\n"
	code += "        templates = {\n"
	dictStrings := stringCount / 6
	for i := 0; i < dictStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		code += "            \"template_" + intToString(i) + "\": \"" + str + "\",\n"
		stringsAdded++
	}
	code += "        }\n"
	code += "        return templates.get(f\"template_{index}\", \"default\")\n\n"

	// Module-level dictionary with nested structures
	code += "METADATA = {\n"
	code += "    \"version\": \"1.0.0\",\n"
	code += "    \"descriptions\": {\n"
	nestedStrings := stringCount / 8
	for i := 0; i < nestedStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		code += "        \"desc_" + intToString(i) + "\": \"" + str + "\",\n"
		stringsAdded++
	}
	code += "    },\n"
	code += "    \"multiline\": \"\"\"\n"
	// Add remaining strings as multiline
	for stringsAdded < stringCount {
		length := varyLength(avgStringLength, stringsAdded)
		str := generatePUAString(length, puaRatio)
		code += "    " + str + "\n"
		stringsAdded++
	}
	code += "    \"\"\",\n"
	code += "}\n\n"

	code += "def main():\n"
	code += "    processor = DataProcessor()\n"
	code += "    print(processor.get_template())\n\n"
	code += "if __name__ == \"__main__\":\n"
	code += "    main()\n"

	return code
}

// generateGoFile creates synthetic Go code with many strings
func generateGoFile(stringCount int, avgStringLength int, puaRatio float64) string {
	var code string
	stringsAdded := 0

	code += "// Auto-generated benchmark file\n"
	code += "// Simulates real-world Go with varied string usage\n"
	code += "package test\n\n"
	code += "import (\n"
	code += "	\"fmt\"\n"
	code += "	\"strings\"\n"
	code += ")\n\n"

	// Package-level constants
	code += "var Config = map[string]string{\n"
	configStrings := stringCount / 4
	for i := 0; i < configStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		code += "	\"key_" + intToString(i) + "\": \"" + str + "\",\n"
		stringsAdded++
	}
	code += "}\n\n"

	// Struct with string fields
	code += "type DataHandler struct {\n"
	code += "	Messages []string\n"
	code += "	Templates map[string]string\n"
	code += "}\n\n"

	// Constructor with slice initialization
	code += "func NewDataHandler() *DataHandler {\n"
	code += "	return &DataHandler{\n"
	code += "		Messages: []string{\n"
	arrayStrings := stringCount / 5
	for i := 0; i < arrayStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		code += "			\"" + str + "\",\n"
		stringsAdded++
	}
	code += "		},\n"
	code += "		Templates: map[string]string{\n"
	mapStrings := stringCount / 6
	for i := 0; i < mapStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		code += "			\"tpl_" + intToString(i) + "\": \"" + str + "\",\n"
		stringsAdded++
	}
	code += "		},\n"
	code += "	}\n"
	code += "}\n\n"

	// Method with raw string literals (multiline)
	code += "func (h *DataHandler) GetMultilineTemplate() string {\n"
	code += "	return `\n"
	multilineStrings := stringCount / 6
	for i := 0; i < multilineStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		code += str + "\n"
		stringsAdded++
	}
	code += "`\n"
	code += "}\n\n"

	// Another method with map
	code += "func (h *DataHandler) GetDescriptions() map[string]string {\n"
	code += "	return map[string]string{\n"
	descStrings := stringCount / 8
	for i := 0; i < descStrings && stringsAdded < stringCount; i++ {
		length := varyLength(avgStringLength, i)
		str := generatePUAString(length, puaRatio)
		code += "		\"desc_" + intToString(i) + "\": \"" + str + "\",\n"
		stringsAdded++
	}
	code += "	}\n"
	code += "}\n\n"

	// Package-level variable with remaining strings
	code += "var Metadata = struct {\n"
	code += "	Version string\n"
	code += "	Data    []string\n"
	code += "}{\n"
	code += "	Version: \"1.0.0\",\n"
	code += "	Data: []string{\n"
	for stringsAdded < stringCount {
		length := varyLength(avgStringLength, stringsAdded)
		str := generatePUAString(length, puaRatio)
		code += "		\"" + str + "\",\n"
		stringsAdded++
	}
	code += "	},\n"
	code += "}\n\n"

	code += "func ProcessData() {\n"
	code += "	handler := NewDataHandler()\n"
	code += "	fmt.Println(handler.GetMultilineTemplate())\n"
	code += "}\n"

	return code
}

// BenchmarkScalability tests performance across different file sizes and PUA ratios
func BenchmarkScalability(b *testing.B) {
	scenarios := []struct {
		name      string
		stringCnt int
		avgStrLen int
		puaRatio  float64
		generator func(int, int, float64) string
		extension string
	}{
		// Small files (~5-15 KB)
		{"JS_Small_NoPUA", 50, 100, 0.0, generateJavaScriptFile, ".js"},
		{"JS_Small_LowPUA", 50, 100, 0.1, generateJavaScriptFile, ".js"},
		{"JS_Small_HighPUA", 50, 100, 0.8, generateJavaScriptFile, ".js"},

		// Medium files (~50-150 KB)
		{"JS_Medium_NoPUA", 500, 200, 0.0, generateJavaScriptFile, ".js"},
		{"JS_Medium_LowPUA", 500, 200, 0.1, generateJavaScriptFile, ".js"},
		{"JS_Medium_HighPUA", 500, 200, 0.8, generateJavaScriptFile, ".js"},

		// Large files (~500KB-1.5MB)
		{"JS_Large_NoPUA", 2000, 300, 0.0, generateJavaScriptFile, ".js"},
		{"JS_Large_LowPUA", 2000, 300, 0.1, generateJavaScriptFile, ".js"},
		{"JS_Large_HighPUA", 2000, 300, 0.8, generateJavaScriptFile, ".js"},

		// Very large files (~2-6MB) - stress test
		{"JS_XLarge_NoPUA", 5000, 500, 0.0, generateJavaScriptFile, ".js"},
		{"JS_XLarge_HighPUA", 5000, 500, 0.8, generateJavaScriptFile, ".js"},

		// Other languages
		{"Python_Medium_HighPUA", 500, 200, 0.8, generatePythonFile, ".py"},
		{"Go_Medium_HighPUA", 500, 200, 0.8, generateGoFile, ".go"},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			// Generate file content once
			content := []byte(sc.generator(sc.stringCnt, sc.avgStrLen, sc.puaRatio))
			filePath := "bench_test" + sc.extension

			// Report metrics
			b.ReportMetric(float64(len(content))/1024, "KB")
			b.ReportMetric(float64(sc.stringCnt), "strings")
			b.ReportMetric(sc.puaRatio*100, "PUA%")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				isFileSketchy(filePath, content, PUA_THRESHOLD)
			}
		})
	}
}

// BenchmarkStringLengthVariation tests how individual string length affects performance
func BenchmarkStringLengthVariation(b *testing.B) {
	stringLengths := []int{10, 50, 100, 500, 1000, 5000, 10000}

	for _, strLen := range stringLengths {
		b.Run(formatLength(strLen), func(b *testing.B) {
			content := []byte(generateJavaScriptFile(100, strLen, 0.7))

			b.ReportMetric(float64(strLen), "avg_chars")
			b.ReportMetric(float64(len(content))/1024, "KB")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				isFileSketchy("bench.js", content, PUA_THRESHOLD)
			}
		})
	}
}

// BenchmarkPUARatioSpectrum tests detection across the full PUA ratio range
func BenchmarkPUARatioSpectrum(b *testing.B) {
	ratios := []float64{0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}

	for _, ratio := range ratios {
		b.Run(formatRatio(ratio), func(b *testing.B) {
			content := []byte(generateJavaScriptFile(200, 250, ratio))

			b.ReportMetric(ratio*100, "PUA%")
			b.ReportMetric(float64(len(content))/1024, "KB")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				isFileSketchy("bench.js", content, PUA_THRESHOLD)
			}
		})
	}
}

// BenchmarkStringCountVariation tests how the number of strings affects performance
func BenchmarkStringCountVariation(b *testing.B) {
	stringCounts := []int{10, 50, 100, 500, 1000, 2000, 5000}

	for _, count := range stringCounts {
		b.Run(formatCount(count), func(b *testing.B) {
			content := []byte(generateJavaScriptFile(count, 200, 0.5))

			b.ReportMetric(float64(count), "strings")
			b.ReportMetric(float64(len(content))/1024, "KB")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				isFileSketchy("bench.js", content, PUA_THRESHOLD)
			}
		})
	}
}

// Helper function to format length for benchmark names
func formatLength(length int) string {
	if length < 1000 {
		return "Len_" + intToString(length)
	}
	return "Len_" + intToString(length/1000) + "k"
}

// Helper function to format ratio for benchmark names
func formatRatio(ratio float64) string {
	return "Ratio_" + intToString(int(ratio*100)) + "pct"
}

// Helper function to format count for benchmark names
func formatCount(count int) string {
	if count < 1000 {
		return "Cnt_" + intToString(count)
	}
	return "Cnt_" + intToString(count/1000) + "k"
}

// Helper to convert int to string without importing strconv
func intToString(n int) string {
	if n == 0 {
		return "0"
	}

	digits := []rune{}
	for n > 0 {
		digits = append([]rune{rune('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
