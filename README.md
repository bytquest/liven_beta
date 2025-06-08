# BytQuest Code Analysis Tool

BytQuest is a fast, open-source codebase analysis tool for Rust and Python projects. It generates call graphs, function/class summaries, and cross-file relationships, all from the terminal.

---

## Features

- **Rust & Python Support:** Analyze Rust (`.rs`) and Python (`.py`) codebases.
- **Call Graph Generation:** Discover function, method, and class relationships.
- **Cross-file Dependency Detection:** See how code interacts across files.
- **Detailed & Summary Output:** Choose between summary or detailed analysis.
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

#### CLI Options

- `--path <dir>`: Directory to analyze (required)
- `--language <rust|python>`: Language to analyze (`rust` or `python`, default: `rust`)
- `--output <summary|detailed|json>`: Output format (default: `summary`)
- `--verbose`: Enable verbose logging
- `--limit <N>`: Limit the number of files to process

---

## Example Output

```
🔍 Code Analysis Tool
Analyzing path: ./src
Found 6 Rust files to analyze
Processing all files together for comprehensive analysis...
Batch processing completed successfully!

=== Analysis Summary ===
Functions discovered: 29
Relationships mapped: 12

  ./src/main.rs::main (function) in ./src/main.rs
  ./src/foo.rs::foo (function) in ./src/foo.rs
  ...
  Edge: ./src/foo.rs::foo -> ./src/bar.rs::bar (calls)
```

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
- [petgraph](https://github.com/petgraph/petgraph) for graph analysis
- [clap](https://github.com/clap-rs/clap) for CLI parsing

---

*Happy hacking!*
