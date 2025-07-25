use clap::{arg, Parser};
use std::fs;
use std::sync::Arc;
use walkdir::WalkDir;
mod indexing;
mod python_indexing;
mod typescript_indexing;
use indexing::{process_and_store_analysis, Indexer, collect_rust_files, process_files_individually, display_results};
use python_indexing::{process_python_files, process_python_file, Indexer as PyIndexer};
use typescript_indexing::{process_typescript_files, process_typescript_file, collect_typescript_files, Indexer as TsIndexer};
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

    #[arg(long, default_value = "rust", help = "Language to analyze: rust, python, or typescript")]
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
        "typescript" => {
            let indexer = Arc::new(TsIndexer::new());
            let files = match collect_typescript_files(&cli.path, cli.limit, cli.verbose) {
                Ok(files) => files,
                Err(e) => {
                    eprintln!("Failed to collect TypeScript files: {:?}", e);
                    std::process::exit(1);
                }
            };
            if files.is_empty() {
                println!("No TypeScript files found in the specified path.");
                return;
            }
            println!("Found {} TypeScript files to analyze", files.len());
            
            // Use the improved processing that handles cross-file dependencies
            process_typescript_files(&files, &indexer, cli.verbose, false);
            
            match cli.output.as_str() {
                "json" => {
                    let summary = typescript_indexing::generate_summary(&indexer);
                    println!("{}", serde_json::to_string_pretty(&summary).unwrap());
                },
                "detailed" => {
                    // First, collect relationships for display before building the graph
                    let mut relationships_for_display = Vec::new();
                    let mut edge_count = 0;
                    while let Some(edge) = indexer.edges.pop() {
                        relationships_for_display.push(edge.clone());
                        indexer.edges.push(edge); // Put it back for the graph
                        edge_count += 1;
                        if edge_count > 10000 { // Safety limit
                            break;
                        }
                    }
                    
                    // Now build the dependency graph
                    let graph = typescript_indexing::build_dependency_graph(&indexer);
                    
                    println!("\n=== TypeScript Analysis Summary ===");
                    println!("Functions/classes discovered: {}", indexer.entities.len());
                    println!("Relationships mapped: {}", relationships_for_display.len());
                    println!("Dependency graph nodes: {}", graph.node_count());
                    println!("Dependency graph edges: {}", graph.edge_count());
                    
                    println!("\n=== Discovered Entities ===");
                    for entity in indexer.entities.iter().take(20) {
                        println!(
                            "  {} ({}) in {} (bytes {}-{})",
                            entity.value().name,
                            entity.value().entity_type,
                            entity.value().file,
                            entity.value().start,
                            entity.value().end
                        );
                    }
                    if indexer.entities.len() > 20 {
                        println!("  ...and {} more", indexer.entities.len() - 20);
                    }
                    
                    println!("\n=== Relationships ===");
                    for (i, (source, target, edge_type)) in relationships_for_display.iter().enumerate().take(20) {
                        println!(
                            "  {} -> {} ({})",
                            source, target, edge_type
                        );
                    }
                    if relationships_for_display.len() > 20 {
                        println!("  ...and {} more edges", relationships_for_display.len() - 20);
                    }
                },
                _ => {
                    // Basic summary - collect relationships first
                    let mut relationship_count = 0;
                    while let Some(edge) = indexer.edges.pop() {
                        indexer.edges.push(edge); // Put it back
                        relationship_count += 1;
                        if relationship_count > 10000 { // Safety limit
                            break;
                        }
                    }
                    
                    // Build the dependency graph
                    let graph = typescript_indexing::build_dependency_graph(&indexer);
                    
                    println!("\n=== TypeScript Analysis Summary ===");
                    println!("Functions/classes discovered: {}", indexer.entities.len());
                    println!("Relationships mapped: {}", relationship_count);
                    println!("Dependency graph nodes: {}", graph.node_count());
                    println!("Dependency graph edges: {}", graph.edge_count());
                }
            }
        }
        other => {
            eprintln!("Unsupported language: {}", other);
            std::process::exit(1);
        }
    }
}