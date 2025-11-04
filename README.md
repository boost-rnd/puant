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

To scan a single file, run `puant` followed by the file path:

```bash
./puant path/to/suspicious.js
```

**Example Output:**

```
SKETCHY: path/to/suspicious.js contains high ratio of PUA characters
```
or
```
CLEAN: path/to/suspicious.js appears safe
```

## License

Licensed under the [AGPLv3](LICENSE).