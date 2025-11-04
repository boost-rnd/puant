# puant 🦨

> *puant* (French) = stinky, smelly 💨

A fast, tree-sitter-powered detector for obfuscated malware hidden in source code.

`puant` sniffs out source code files containing strings with a high ratio of Unicode Private Use Area (PUA) characters. This is a technique that has been observed in the wild for malware obfuscation. By parsing code into an Abstract Syntax Tree (AST), `puant` accurately targets string literals, minimizing false positives.

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

### Output Formats

#### Text Output (default)

```
Scan Results (threshold: 50.00%)
=====================================

SKETCHY FILES (2):
  [!] suspicious.js (max ratio: 100.00%)
  [!] obfuscated.py (max ratio: 85.71%)

CLEAN FILES (5):
  [✓] main.go
  [✓] utils.js
  [✓] config.py
  [✓] handler.java
  [✓] app.js

Summary: 7 total, 2 sketchy, 5 clean
```

#### JSON Output

```json
{
  "threshold": 0.5,
  "total_files": 2,
  "sketchy_files": 1,
  "clean_files": 1,
  "files": [
    {
      "path": "suspicious.js",
      "sketchy": true,
      "max_ratio": 1.0
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

## License

Licensed under the [AGPLv3](LICENSE).