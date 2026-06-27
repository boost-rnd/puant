# puant 🦨

> *puant* (French) = stinky, smelly 💨



A fast, tree-sitter-powered detector for obfuscated malware hidden in source code.

`puant` scans source code files for strings with a high ratio of Unicode Private Use Area (PUA) characters. By parsing code into an Abstract Syntax Tree (AST), it accurately targets string literals while minimizing false positives.

## What are Private Use Areas?

[Private Use Areas (PUA)](https://en.wikipedia.org/wiki/Private_Use_Areas) are ranges of Unicode code points intentionally left undefined by the Unicode standard for custom character assignments. Three PUA ranges exist:

- **U+E000–U+F8FF** (Basic Multilingual Plane) - 6,400 characters
- **U+F0000–U+FFFFD** (Plane 15) - 65,534 characters
- **U+100000–U+10FFFD** (Plane 16) - 65,534 characters

PUA characters are invisible in most text editors and code review tools, making them useful for hiding malicious code in plain sight.

## Real-World Examples

- **[GlassWorm (2025)](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace)** - A self-propagating worm that infected 35,800+ VS Code extensions using invisible Unicode variation selectors. The payload appeared as blank lines in code editors.

- **[npm Calendar Invite Attack (2025)](https://www.aikido.dev/blog/youre-invited-delivering-malware-via-google-calendar-invites-and-puas)** - Five npm packages used PUA characters to hide base64-encoded payloads that fetched commands from Google Calendar invite titles.

- **[GitHub Repository Poisoning (2025)](https://www.aikido.dev/blog/the-return-of-the-invisible-threat-hidden-pua-unicode-hits-github-repositorties)** - PUA-obfuscated code in seemingly legitimate commits to JavaScript projects, using Solana blockchain as a C2 channel.

## Supported Languages

- Go
- Java
- JavaScript
- Python

A regex-based fallback is used for unsupported languages.

## Installation

```bash
git clone https://github.com/boost-rnd/puant.git
cd puant
go build
```

## Usage

### Basic Usage

Scan a single file or directory:

```bash
# Scan a single file
./puant path/to/suspicious.js

# Scan a directory (recursively)
./puant path/to/project/
```

### Command-Line Options

```bash
./puant [options] <file|directory>

Options:
  -threshold float
        PUA ratio threshold (0.0-1.0) (default 0.5)
  -format string
        Output format: text or json (default "text")
  -scan-git
        Include .git directories in scan (default: false)
  -min-string-length int
        Minimum string length to check for PUA (default 3)
  -max-file-size int
        Maximum file size to scan in bytes (default 10485760)
  -verbose
        Enable verbose progress output
```

### Examples

**Scan with custom threshold:**
```bash
./puant -threshold 0.8 suspicious.js
```

**Scan directory with JSON output:**
```bash
./puant -format json src/
```

**Include .git directories:**
```bash
./puant -scan-git .
```

**Adjust minimum string length to reduce false positives:**
```bash
./puant -min-string-length 5 src/
```

### Handling False Positives

PUA characters are legitimately used in:
- Icon fonts (Font Awesome, Material Icons)
- Mathematical typesetting (KaTeX, MathJax)
- Custom web fonts

The `-min-string-length` flag (default: 3) helps reduce false positives by skipping very short strings that are often single icon characters. Files with short PUA strings are reported separately as "FILES WITH SHORT PUA STRINGS" rather than flagged as sketchy.

To detect all PUA usage including single characters (useful for thorough audits):
```bash
./puant -min-string-length 1 src/
```

### Output Formats

#### Text Output (default)

```
Scan Results (threshold: 50.00%, min-length: 3)
=====================================

SKETCHY FILES (2):
  [!] suspicious.js (max ratio: 100.00%)
  [!] obfuscated.py (max ratio: 85.71%)

FILES WITH SHORT PUA STRINGS (1):
  [~] icons.js (17 short strings, max ratio: 100.00%)

Summary: 8 scanned, 2 sketchy, 0 skipped
```

#### JSON Output

```json
{
  "threshold": 0.5,
  "total_files": 3,
  "sketchy_files": 1,
  "clean_files": 2,
  "skipped_files": 0,
  "files": [
    {
      "path": "suspicious.js",
      "sketchy": true,
      "max_ratio": 1.0
    },
    {
      "path": "icons.js",
      "sketchy": false,
      "short_pua_strings": 17,
      "short_pua_max_ratio": 1.0
    },
    {
      "path": "safe.js",
      "sketchy": false
    }
  ]
}
```

### Exit Codes

- `0`: No sketchy files found (success)
- `1`: Sketchy files detected or error occurred

This makes `puant` easy to integrate into CI/CD pipelines.

## Benchmarking

`puant` includes comprehensive benchmarks that test detection performance across various scenarios using synthetically generated code. All test files are generated in-memory during benchmarking—no large test files are stored in the repository.

### Running Benchmarks

```bash
# Run all benchmarks
go test -bench=. -benchmem

# Run specific benchmark suites
go test -bench=BenchmarkScalability -benchmem
go test -bench=BenchmarkStringLengthVariation -benchmem
go test -bench=BenchmarkPUARatioSpectrum -benchmem
go test -bench=BenchmarkStringCountVariation -benchmem

# Quick benchmark run (shorter runtime)
go test -bench=. -benchmem -benchtime=200ms

# With CPU profiling
go test -bench=. -benchmem -cpuprofile=cpu.prof

# With memory profiling
go test -bench=. -benchmem -memprofile=mem.prof
```

### Benchmark Suites

**BenchmarkScalability** - Tests performance across different file sizes and PUA ratios:
- Small files (~10-15 KB)
- Medium files (~50-150 KB)
- Large files (~500 KB-1.5 MB)
- XLarge files (~2-6 MB)
- Tests JavaScript, Python, and Go files
- Varies PUA ratios: 0%, 10%, 80%

**BenchmarkStringLengthVariation** - Tests impact of individual string length:
- String lengths from 10 to 10,000 characters
- Fixed number of strings (100) with varying average length

**BenchmarkPUARatioSpectrum** - Tests detection across PUA ratio range:
- Tests ratios from 0% to 100% in 10% increments
- Helps understand detection accuracy at different obfuscation levels

**BenchmarkStringCountVariation** - Tests scalability with string count:
- Tests from 10 to 5,000 strings per file
- Fixed average string length (200 chars)

### Synthetic File Generation

The benchmarks generate realistic code with varied structures:

**JavaScript files include:**
- Import statements
- Config objects with nested properties
- Functions with template literals (multiline)
- Classes with constructors and methods
- Array and object literals

**Python files include:**
- Import statements with type hints
- Module-level constants and dictionaries
- Classes with docstrings
- Methods with triple-quoted multiline strings
- f-string templates

**Go files include:**
- Package imports
- Package-level variables and maps
- Struct definitions
- Constructor functions
- Methods with raw string literals (backticks)

### Example Results

Results on Apple M4 Pro (benchtime=100ms):

```
BenchmarkScalability/JS_Small_NoPUA-14         	     403	    282293 ns/op	   73688 B/op	    1107 allocs/op
BenchmarkScalability/JS_Medium_NoPUA-14        	      50	   2309903 ns/op	 1267837 B/op	    6920 allocs/op
BenchmarkScalability/JS_Large_NoPUA-14         	      10	  10852417 ns/op	 7220656 B/op	   26269 allocs/op
BenchmarkScalability/JS_XLarge_NoPUA-14        	       3	  36251750 ns/op	28560045 B/op	   64947 allocs/op

BenchmarkStringLengthVariation/Len_10-14       	     314	    375089 ns/op	   41784 B/op	    1605 allocs/op
BenchmarkStringLengthVariation/Len_1k-14       	     100	   1043429 ns/op	  539288 B/op	    1607 allocs/op
BenchmarkStringLengthVariation/Len_10k-14      	      16	   6887148 ns/op	 4927334 B/op	    1607 allocs/op

BenchmarkPUARatioSpectrum/Ratio_0pct-14        	     451	   1227401 ns/op	  604965 B/op	    4018 allocs/op
BenchmarkPUARatioSpectrum/Ratio_50pct-14       	     523	   1132388 ns/op	  288538 B/op	    3620 allocs/op
BenchmarkPUARatioSpectrum/Ratio_100pct-14      	     516	   1173062 ns/op	  391044 B/op	    3620 allocs/op
```

**Performance Summary:**
- Small files (~10 KB): ~280 μs
- Medium files (~150 KB): ~2.3 ms
- Large files (~1 MB): ~10 ms
- Extra large files (~6 MB): ~36 ms

These benchmarks demonstrate that `puant` scales linearly with file size and can efficiently process even large codebases.

## License

Licensed under the [AGPLv3](LICENSE).
