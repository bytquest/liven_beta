# BytQuest's Internal beta Code Analysis Tool

Liven Beta is a fast, open-source codebase analysis tool for Rust, Python, and TypeScript projects. It generates call graphs, function/class summaries, and cross-file relationships, all from the terminal.

---

## Features

- **Multi-language Support:** Analyze Rust (`.rs`), Python (`.py`), and TypeScript/TSX (`.ts`, `.tsx`) codebases.
- **Call Graph Generation:** Discover function, method, and class relationships.
- **Cross-file Dependency Detection:** See how code interacts across files.
- **Multiple Output Formats:** Choose between summary, detailed, or JSON analysis.
- **CLI-first:** No server required—analyze directly from your terminal.
- **Verbose Mode:** See progress and detailed logs as you analyze.

---

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/your-username/your-repo.git
   cd your-repo
   ```

2. **Build the CLI:**
   ```sh
   cargo build --release --bin open_source
   ```

---

## Usage

### Analyze a Rust codebase

```sh
cargo run --bin open_source -- --path ./src --language rust --output detailed --verbose
```

### Analyze a Python codebase

```sh
cargo run --bin open_source -- --path ./your/python/project --language python --output detailed --verbose
```

### Analyze a TypeScript codebase

### Get JSON output for TypeScript analysis

```sh
cargo run --bin open_source -- --path ./src --language typescript --output json
```

#### CLI Options

- `--path <dir>`: Directory to analyze (required)
- `--language <rust|python|typescript>`: Language to analyze (`rust`, `python`, or `typescript`, default: `rust`)
- `--output <summary|detailed|json>`: Output format (default: `summary`)
- `--verbose`: Enable verbose logging
- `--limit <N>`: Limit the number of files to process

---

## Example Output

### Summary Output
```
🔍 Code Analysis Tool
Analyzing path: ./src
Found 8 TypeScript files to analyze

=== TypeScript Analysis Summary ===
Functions/classes discovered: 58
Relationships mapped: 3
Dependency graph nodes: 58
Dependency graph edges: 3
```

### Detailed Output
```
=== Discovered Entities ===
  generateConversationWithCustomConfigs (method) in C:/path/to/service/multiVoiceService.ts (bytes 8497-10912)
  SpeechConversationService (class) in C:/path/to/service/conversation.ts (bytes 1026-20529)
  ...and 56 more

=== Relationships ===
  C:/path/to/service/conversation.ts.SpeechConversationService -> C:/path/to/service/s3Service.ts.S3Service (instantiates)
  C:/path/to/service/multiVoiceService.ts.MultiVoiceSpeechService.constructor -> C:/path/to/service/s3Service.ts.S3Service (instantiates)
  ...and 1 more
```

### JSON Output
```json
{
  "summary": {
    "total_files": 8,
    "total_entities": 58,
    "total_relationships": 3,
    "total_imports": 45,
    "entities_by_type": {
      "method": 45,
      "class": 8,
      "function": 5
    },
    "relationships_by_type": {
      "instantiates": 3
    },
    "files_processed": [
      "C:/path/to/service/conversation.ts",
      "C:/path/to/service/s3Service.ts",
      "C:/path/to/service/multiVoiceService.ts"
    ],
    "relationships": [
      {
        "source": "C:/path/to/service/conversation.ts.SpeechConversationService",
        "target": "C:/path/to/service/s3Service.ts.S3Service",
        "type": "instantiates"
      }
    ]
  }
}
```

---

## TypeScript Analysis Features

The TypeScript analyzer provides:

- **Entity Detection:** Functions, methods, classes, and class properties
- **Relationship Types:** 
  - `calls`: Function/method calls
  - `inherits`: Class inheritance
  - `instantiates`: Constructor calls (`new` expressions)
  - `accesses`: Property access
- **Cross-file Resolution:** Import/export mapping for dependency tracking
- **Dependency Injection Support:** Handles `this.service.method()` patterns
- **Deduplication:** Prevents duplicate relationship entries

---

## Contributing

Contributions are welcome!  
Please open issues or pull requests for bug fixes, features, or improvements.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [tree-sitter](https://tree-sitter.github.io/tree-sitter/) for parsing
- [tree-sitter-typescript](https://github.com/tree-sitter/tree-sitter-typescript) for TypeScript parsing
- [petgraph](https://github.com/petgraph/petgraph) for graph analysis
- [clap](https://github.com/clap-rs/clap) for CLI parsing

---

*Happy hacking!*
