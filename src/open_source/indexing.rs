use std::{path::PathBuf, collections::HashMap, sync::Arc, net::SocketAddr};
use std::cell::RefCell;
use std::fs;
use petgraph::visit::EdgeRef;
use rayon::prelude::*;
use dashmap::DashMap;
use crossbeam_queue::SegQueue;
use tree_sitter::{Parser, Language, Node};
use petgraph::{Graph, Directed, graph::NodeIndex};
use serde_json::json;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Multipart, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response, Json},
    routing::{get, post},
};
use tokio::signal;
use sqlx::{sqlite::SqlitePool, migrate::MigrateDatabase, Sqlite, Row};
use serde::{Serialize, Deserialize};
use chrono::{Utc, DateTime};
use uuid::Uuid;

use tree_sitter_rust::language as rust_language;
use walkdir::WalkDir;

/// Represents a parsed function or method
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Function {
    /// Name of the function
    pub name: String,
    /// Fully qualified name (e.g. "crate::auth::login")
    pub fq_name: String,
    /// Module where the function is defined
    pub module: String,
    /// Path to the source file
    pub file: String,
    /// Start byte position in the file
    pub start: usize,
    /// End byte position in the file
    pub end: usize,
}

/// Represents an analysis session
#[derive(Debug)]
pub 
enum AnalysisError {
    IoError(std::io::Error),
    ProcessingError(String),
    RuntimeError(String),
}


/// Global in-memory state for code indexing
#[derive(Clone)]
pub struct AppState {
    // Use Arc to share between handlers
    indexer: Arc<Indexer>,
    // Database connection pool
    db_pool: SqlitePool,
}

pub struct Indexer {
    /// Map of fully-qualified name to Function
    pub funcs: DashMap<String, Function>,
    /// Call graph edges: (caller, callee)
    pub edges: SegQueue<(String, String)>,
}

impl Indexer {
    pub fn new() -> Self {
        Self {
            funcs: DashMap::new(),
            edges: SegQueue::new(),
        }
    }
}

pub async fn process_file(
    path: &str,
    source: &str,
    indexer: &Indexer,
) -> Result<(), Box<dyn std::error::Error>> {
    thread_local! {
        static PARSER: RefCell<Parser> = RefCell::new({
            let mut parser = Parser::new();
            parser.set_language(rust_language()).unwrap();
            parser
        });
    }



    PARSER.with(|parser| {
        let tree = match parser.borrow_mut().parse(source, None) {
            Some(tree) => tree,
            None => return,
        };
        let root = tree.root_node();
        extract_function_definitions(&root, source, path, path, &indexer);
    });

    // Phase 2: Extract function calls
    PARSER.with(|parser| {
        let tree = match parser.borrow_mut().parse(source, None) {
            Some(tree) => tree,
            None => return,
        };
        let root = tree.root_node();
        extract_function_calls(&root, source, path, &indexer);
    });

    Ok(())
}



pub fn collect_rust_files(
    path: &str, 
    limit: Option<usize>, 
    verbose: bool
) -> Result<HashMap<String, String>, AnalysisError> {
    let mut files = HashMap::new();
    let mut processed_count = 0;
    
    if verbose {
        println!("Scanning directory: {}", path);
    }
    
    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
    {
        // Check limit
        if let Some(max_files) = limit {
            if processed_count >= max_files {
                if verbose {
                    println!("Reached file limit of {}", max_files);
                }
                break;
            }
        }
        
        let file_path = entry.path().to_string_lossy().to_string();
        
        match fs::read_to_string(entry.path()) {
            Ok(content) => {
                files.insert(file_path.clone(), content);
                processed_count += 1;
                
                if verbose {
                    println!("  [{}] Loaded: {}", processed_count, file_path);
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to read {}: {}", file_path, e);
            }
        }
    }
    
    if verbose {
        println!("Successfully loaded {} Rust files", files.len());
    }
    
    Ok(files)
}

/// Process files individually (memory efficient for large codebases)
pub async fn process_files_individually(
    files: &HashMap<String, String>,
    indexer: Arc<Indexer>,
    verbose: bool,
) -> Result<(), AnalysisError> {
    let total_files = files.len();
    let mut processed = 0;
    
    println!("Processing {} files individually...", total_files);
    
    for (path, content) in files {
        match process_file(path, content, &indexer).await {
            Ok(_) => {
                processed += 1;
                if verbose || processed % 10 == 0 {
                    println!("  Progress: {}/{} files processed", processed, total_files);
                }
            }
            Err(e) => {
                eprintln!("Error processing {}: {}", path, e);
            }
        }
    }
    
    println!("Individual processing completed: {}/{} files", processed, total_files);
    Ok(())
}

/// Display analysis results based on output format
pub fn display_results(
    session_id: &str,
    indexer: &Arc<Indexer>,
    output_format: &str,
    verbose: bool,
) -> Result<(), AnalysisError> {
    let function_count = indexer.funcs.len();
    let mut edge_count = 0;
    
    // Count edges (non-destructive)
    let temp_edges: Vec<_> = std::iter::from_fn(|| indexer.edges.pop()).collect();
    edge_count = temp_edges.len();
    
    // Put edges back
    for edge in temp_edges {
        indexer.edges.push(edge);
    }
    
    match output_format {
        "json" => {
            let result = serde_json::json!({
                "session_id": session_id,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "statistics": {
                    "function_count": function_count,
                    "call_count": edge_count,
                    "call_ratio": if function_count > 0 { 
                        edge_count as f64 / function_count as f64 
                    } else { 0.0 }
                },
                "functions": indexer.funcs.iter()
                    .map(|entry| {
                        let func = entry.value();
                        serde_json::json!({
                            "name": func.name,
                            "fq_name": func.fq_name,
                            "module": func.module,
                            "file": func.file,
                            "start": func.start,
                            "end": func.end
                        })
                    })
                    .collect::<Vec<_>>(),
                "call_graph": {
                    "edges": std::iter::from_fn(|| indexer.edges.pop())
                        .map(|(caller, callee)| serde_json::json!({
                            "caller": caller,
                            "callee": callee
                        }))
                        .collect::<Vec<_>>()
                }
            });
            
            println!("{}", serde_json::to_string_pretty(&result)
                .map_err(|e| AnalysisError::ProcessingError(format!("JSON serialization error: {}", e)))?);
        }
        
        "detailed" => {
            println!("\n=== Detailed Analysis Results ===");
            println!("Session ID: {}", session_id);
            println!("Analysis Time: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
            println!("\n--- Statistics ---");
            println!("Functions found: {}", function_count);
            println!("Function calls: {}", edge_count);
            println!("Average calls per function: {:.2}", 
                if function_count > 0 { edge_count as f64 / function_count as f64 } else { 0.0 });
            
            println!("\n--- Functions ---");
            for entry in indexer.funcs.iter().take(20) { // Limit output
                let func = entry.value();
                println!("  {} ({}:{})", func.fq_name, func.file, func.start);
            }
            
            if function_count > 20 {
                println!("  ... and {} more functions", function_count - 20);
            }
            
            println!("\n--- Call Graph (sample) ---");
            let edges: Vec<_> = std::iter::from_fn(|| indexer.edges.pop()).take(20).collect();
            for (caller, callee) in &edges {
                println!("  {} -> {}", caller, callee);
            }
            
            if edge_count > 20 {
                println!("  ... and {} more call relationships", edge_count - 20);
            }
            
            // Put edges back
            for edge in edges {
                indexer.edges.push(edge);
            }
        }
        
        "summary" | _ => {
            println!("\n=== Analysis Summary ===");
            println!("Session ID: {}", session_id);
            println!("Functions discovered: {}", function_count);
            println!("Function calls mapped: {}", edge_count);
            println!("Call complexity ratio: {:.2}", 
                if function_count > 0 { edge_count as f64 / function_count as f64 } else { 0.0 });
            
            if verbose {
                println!("\nTop modules by function count:");
                let mut module_counts = HashMap::new();
                for entry in indexer.funcs.iter() {
                    let module = &entry.value().module;
                    *module_counts.entry(module.clone()).or_insert(0) += 1;
                }
                
                let mut sorted_modules: Vec<_> = module_counts.into_iter().collect();
                sorted_modules.sort_by(|a, b| b.1.cmp(&a.1));
                
                for (module, count) in sorted_modules.into_iter().take(10) {
                    println!("  {}: {} functions", module, count);
                }
            }
            
            println!("\nAnalysis completed successfully!");
        }
    }
    
    Ok(())
}

pub async fn process_and_store_analysis(
    files: HashMap<String, String>,
    indexer: Arc<Indexer>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Reset the indexer for this new analysis
    indexer.funcs.clear();
    while let Some(_) = indexer.edges.pop() {}

    thread_local! {
        static PARSER: RefCell<Parser> = RefCell::new({
            let mut parser = Parser::new();
            parser.set_language(rust_language()).unwrap();
            parser
        });
    }

    // Convert the files HashMap to a vector for parallel processing
    let files_vec: Vec<(String, String)> = files.into_iter().collect();

    // Phase 1: Extract function definitions from all files
    files_vec.par_iter().for_each(|(path, source)| {
        PARSER.with(|parser| {
            let tree = match parser.borrow_mut().parse(source, None) {
                Some(tree) => tree,
                None => return,
            };

            let root = tree.root_node();
            // Use file path directly as module path
            extract_function_definitions(&root, source, path, path, &indexer);
        });
    });

    // Phase 2: Extract function calls and resolve them
    files_vec.par_iter().for_each(|(path, source)| {
        PARSER.with(|parser| {
            let tree = match parser.borrow_mut().parse(source, None) {
                Some(tree) => tree,
                None => return,
            };

            let root = tree.root_node();
            // Use file path directly as module path
            extract_function_calls(&root, source, path, &indexer);
        });
    });

    // Build the call graph from collected data
    let mut graph = Graph::<Function, (), Directed>::new();
    let mut node_indices = HashMap::new();

    // Add all functions as nodes
    for entry in indexer.funcs.iter() {
        let function = entry.value().clone();
        let node_idx = graph.add_node(function.clone());
        node_indices.insert(function.fq_name.clone(), node_idx);
    }

    // Collect all edges
    let mut edges = Vec::new();
    while let Some(edge) = indexer.edges.pop() {
        edges.push(edge.clone());

        if let (Some(&caller_idx), Some(&callee_idx)) = (
            node_indices.get(&edge.0),
            node_indices.get(&edge.1)
        ) {
            graph.add_edge(caller_idx, callee_idx, ());
        }
    }
    
    for edge in &edges {
    indexer.edges.push(edge.clone());
}
    let session_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now();
    let function_count = graph.node_count() as i32;
    let call_count = graph.edge_count() as i32;

    // Store the session in database
    

    // Insert session metadata
    
    

    // Insert functions
    for entry in indexer.funcs.iter() {
        let func = entry.value();
        
    }

    for (caller, callee) in edges {
        println!("Storing edge: {} -> {}", caller, callee);
        println!("Caller: {}, Callee: {}\n", caller, callee);
    }


    Ok(session_id)
}






fn serialize_graph_to_json(
    graph: &Graph<Function, (), Directed>,
    node_indices: &HashMap<String, NodeIndex>
) -> serde_json::Value {
    let mut nodes = Vec::new();
    let mut links = Vec::new();
    
    // Add nodes
    for (fq_name, &idx) in node_indices {
        let func = &graph[idx];
        nodes.push(json!({
            "id": fq_name,
            "name": func.name,
            "module": func.module,
            "file": func.file
        }));
    }
    
    // Add edges
    for edge in graph.edge_references() {
        let source = &graph[edge.source()];
        let target = &graph[edge.target()];
        
        links.push(json!({
            "source": source.fq_name,
            "target": target.fq_name
        }));
    }
    
    json!({
        "nodes": nodes,
        "links": links
    })
}


fn extract_function_definitions(
    root: &Node,
    source: &str,
    module_path: &str,
    file_path: &str,
    indexer: &Indexer,
) {
    let mut cursor = root.walk();
    for function_node in root.children(&mut cursor).filter(|n| n.kind() == "function_item") {
        if let Some(name_node) = function_node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                // Create fully qualified name
                let fully_qualified_name = format!("{}::{}", module_path, name);
                
                // Store function information
                indexer.funcs.insert(fully_qualified_name.clone(), Function {
                    name: name.to_string(),
                    fq_name: fully_qualified_name.clone(),
                    module: module_path.to_string(),
                    file: file_path.to_string(),
                    start: function_node.start_byte(),
                    end: function_node.end_byte(),
                });
                
                println!("Found function: {}", fully_qualified_name);
            }
        }
    }
}

fn extract_function_calls(
    root: &Node,
    source: &str,
    module_path: &str,
    indexer: &Indexer,
) {
    // First collect all import statements to help resolve function calls
    let import_map = parse_import_statements(root, source);
    
    // Create a recursive function to visit all nodes
    fn visit_nodes_for_calls(
        node: &Node, 
        source: &str,
        module_path: &str,
        import_map: &HashMap<String, String>,
        indexer: &Indexer
    ) {
        // Check if current node is a call expression
        if node.kind() == "call_expression" {
            if let Some(callee_node) = node.child_by_field_name("function") {
                if let Ok(callee_name) = callee_node.utf8_text(source.as_bytes()) {
                    // Resolve the function name to its fully qualified form
                    let fully_qualified_callee = if callee_name.contains("::") {
                        // Already a fully qualified path
                        callee_name.to_string()
                    } else if let Some(full_path) = import_map.get(callee_name) {
                        // Resolve via import
                        full_path.clone()
                    } else {
                        // Assume it's in the current module
                        format!("{}::{}", module_path, callee_name)
                    };
                    
                    // Find the function containing this call
                    if let Some(caller_function) = find_enclosing_function(node, source, module_path) {
                        // Only record the edge if the callee exists in our index
                        if indexer.funcs.contains_key(&fully_qualified_callee) {
                            indexer.edges.push((caller_function.clone(), fully_qualified_callee.clone()));
                            println!("Found call: {} -> {}", caller_function, fully_qualified_callee);
                        }
                    }
                }
            }
        }
        
        // Visit all children recursively
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit_nodes_for_calls(&child, source, module_path, import_map, indexer);
        }
    }
    
    // Start the recursive traversal from the root
    visit_nodes_for_calls(root, source, module_path, &import_map, indexer);
}

/// Parse `use foo::bar as baz` and similar import statements 
fn parse_import_statements(root: &Node, source: &str) -> HashMap<String, String> {
    let mut imports = HashMap::new();
    
    // Create a recursive function to visit all nodes
    fn visit_nodes_for_imports(
        node: &Node,
        source: &str,
        imports: &mut HashMap<String, String>
    ) {
        // Check if this node is a use declaration
        if node.kind() == "use_declaration" {
            if let Some(path_node) = node.child_by_field_name("path") {
                if let Ok(path_text) = path_node.utf8_text(source.as_bytes()) {
                    // Extract the alias (last part after ::)
                    let alias = path_text.rsplit("::").next().unwrap_or(path_text);
                    imports.insert(alias.to_string(), path_text.to_string());
                }
            }
        }
        
        // Visit all children recursively
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit_nodes_for_imports(&child, source, imports);
        }
    }
    
    // Start the recursive traversal from the root
    visit_nodes_for_imports(root, source, &mut imports);
    
    imports
}

/// Walk up the tree to find the enclosing function and return its fully qualified name
fn find_enclosing_function(node: &Node, source: &str, module_path: &str) -> Option<String> {
    let mut current_opt = Some(*node);
    
    // Traverse up the tree
    while let Some(current) = current_opt {
        if current.kind() == "function_item" {
            if let Some(name_node) = current.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                    return Some(format!("{}::{}", module_path, name));
                }
            }
        }
        
        // Move to parent
        current_opt = current.parent();
    }
    
    None
}

