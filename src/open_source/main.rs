use clap::{arg, Parser};
use std::fs;
use std::sync::Arc;
use walkdir::WalkDir;
mod indexing;
mod python_indexing;
use indexing::{process_and_store_analysis, Indexer, collect_rust_files, process_files_individually, display_results};
use python_indexing::{process_python_files, process_python_file, Indexer as PyIndexer};
use tokio::runtime::Runtime;

#[derive(Parser)]
#[command(author, version, about = "BytQuest Tool", long_about = None)]
struct Cli {
    #[arg(short, long, help = "Directory path to analyze")]
    path: String,

    #[arg(short, long, default_value = "summary", help = "Output format: summary, json, detailed")]
    output: String,

    #[arg(short, long, help = "Enable verbose logging")]
    verbose: bool,

    #[arg(long, help = "Process each file individually (slower but more memory efficient)")]
    individual: bool,

    #[arg(long, help = "Limit the number of files to process")]
    limit: Option<usize>,

    #[arg(long, default_value = "rust", help = "Language to analyze: rust or python")]
    language: String,
}

fn main() {
    let cli = Cli::parse();
    let rt = match Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("Failed to create Tokio runtime: {}", e);
            std::process::exit(1);
        }
    };
    println!("🔍 Code Analysis Tool");
    println!("Analyzing path: {}", cli.path);
    if !std::path::Path::new(&cli.path).exists() {
        eprintln!("Error: Path '{}' does not exist", cli.path);
        std::process::exit(1);
    }

    match cli.language.as_str() {
        "rust" => {
            let indexer = Arc::new(Indexer::new());
            let files = match collect_rust_files(&cli.path, cli.limit, cli.verbose) {
                Ok(files) => files,
                Err(e) => {
                    eprintln!("Failed to collect files: {:?}", e);
                    std::process::exit(1);
                }
            };
            if files.is_empty() {
                println!("No Rust files found in the specified path.");
                return;
            }
            println!("Found {} Rust files to analyze", files.len());
            let session_id = if cli.individual {
                if let Err(e) = rt.block_on(process_files_individually(&files, indexer.clone(), cli.verbose)) {
                    eprintln!("Individual processing failed: {:?}", e);
                    std::process::exit(1);
                }
                uuid::Uuid::new_v4().to_string()
            } else {
                println!("Processing all files together for comprehensive analysis...");
                match rt.block_on(process_and_store_analysis(files, indexer.clone())) {
                    Ok(session_id) => {
                        println!("Batch processing completed successfully!");
                        session_id
                    }
                    Err(e) => {
                        eprintln!("Batch processing failed: {}", e);
                        std::process::exit(1);
                    }
                }
            };
            if let Err(e) = display_results(&session_id, &indexer, &cli.output, cli.verbose) {
                eprintln!("Failed to display results: {:?}", e);
                std::process::exit(1);
            }
        }
        "python" => {
            let indexer = Arc::new(PyIndexer::new());
            // Collect .py files
            let mut files = std::collections::HashMap::new();
            let mut processed_count = 0;
            for entry in WalkDir::new(&cli.path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "py"))
            {
                if let Some(max_files) = cli.limit {
                    if processed_count >= max_files {
                        break;
                    }
                }
                let file_path = entry.path().to_string_lossy().to_string();
                match fs::read_to_string(entry.path()) {
                    Ok(content) => {
                        files.insert(file_path.clone(), content);
                        processed_count += 1;
                        if cli.verbose {
                            println!("  [{}] Loaded: {}", processed_count, file_path);
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to read {}: {}", file_path, e);
                    }
                }
            }
            if files.is_empty() {
                println!("No Python files found in the specified path.");
                return;
            }
            println!("Found {} Python files to analyze", files.len());
            process_python_files(&files, &indexer, cli.verbose);
            // Print summary
            println!("\n=== Python Analysis Summary ===");
            println!("Functions/classes discovered: {}", indexer.entities.len());
            println!("\n\n Relationships mapped: {}\n\n", indexer.edges.len());
            if cli.output == "detailed" {
                for entity in indexer.entities.iter().take(20) {
                    println!(
                        "  {} ({}) in {} ",
                        entity.value().fq_name,
                        entity.value().entity_type,
                        entity.value().file,
                        
                    );
                }
                if indexer.entities.len() > 20 {
                    println!("  ...and {} more", indexer.entities.len() - 20);
                }
                let mut edge_vec = Vec::new();
                // Drain the SegQueue into a vector for display
                let mut temp_edges = Vec::new();
                while let Some(edge) = indexer.edges.pop() {
                    temp_edges.push(edge);
                }
                // If you want to preserve the queue, push them back
                for edge in &temp_edges {
                    indexer.edges.push(edge.clone());
                }
                edge_vec.extend(temp_edges.iter().cloned());
                for (i, edge) in edge_vec.iter().enumerate().take(20) {
                    println!(
                        "  Edge: {} -> {} ({})",
                        edge.0, edge.1, edge.2
                    );
                }
                if edge_vec.len() > 20 {
                    println!("  ...and {} more edges", edge_vec.len() - 20);
                }
            }
        }
        other => {
            eprintln!("Unsupported language: {}", other);
            std::process::exit(1);
        }
    }
}