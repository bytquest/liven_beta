mod indexing;
mod python_indexing;
mod server;
mod embeddings;

// src/main.rs

use std::{path::PathBuf, collections::HashMap, sync::Arc, net::SocketAddr};
use std::cell::RefCell;
use python_indexing::{process_and_store_analysis, Indexer};
use rayon::prelude::*;
use dashmap::DashMap;
use crossbeam_queue::SegQueue;
use sqlx::{Row, SqlitePool};
use tree_sitter::{Parser, Language, Node};
use petgraph::{Graph, Directed, graph::NodeIndex};
use serde_json::json;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Multipart, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use tokio::runtime::Runtime;
use crate::server::build_server;


fn main(){
    // build_server();
    let rt = Runtime::new().unwrap();

    // Simulate Python files
    let mut files = HashMap::new();
    files.insert(
        "example.py".to_string(),
        r#"
class MyClass:
    def method1(self):
        print("Method1 called")
    
    def method2(self):
        self.method1()

def standalone_function():
    obj = MyClass()
    obj.method2()
"#
        .to_string(),
    );
  
    let indexer = Arc::new(Indexer::new());
    // if !sqlx::Sqlite::database_exists("sqlite:python_callgraph.db").await.unwrap_or(false) {
    //     sqlx::Sqlite::create_database("sqlite:python_callgraph.db").await?;
    // }
    let db_url = "sqlite::memory:"; // Use an in-memory SQLite database for testing
    let pool = rt.block_on(SqlitePool::connect("sqlite:python_callgraph.db")).unwrap();

    // Create necessary tables
    rt.block_on(crate::python_indexing::create_tables(&pool)).unwrap();

    // Run the analysis
    let description = "Test Analysis".to_string();
    let result = rt.block_on(process_and_store_analysis(files, indexer.clone(), &pool, description));
    match result {
        Ok(session_id) => {
            println!("Analysis completed successfully. Session ID: {}", session_id);

            // Query the database to verify the results
            let entities: Vec<(String, String)> = rt
                .block_on(sqlx::query("SELECT fq_name, entity_type FROM entities")
                .map(|row: sqlx::sqlite::SqliteRow| (row.get("fq_name"), row.get("entity_type")))
                .fetch_all(&pool))
                .unwrap();

            println!("Entities:");
            for (fq_name, entity_type) in entities {
                println!("  {} ({})", fq_name, entity_type);
            }

            let relations: Vec<(String, String, String)> = rt
                .block_on(sqlx::query("SELECT source, target, relation_type FROM relations")
                .map(|row: sqlx::sqlite::SqliteRow| (
                    row.get::<String, _>("source"), 
                    row.get::<String, _>("target"), 
                    row.get::<String, _>("relation_type")
                ))
                .fetch_all(&pool))
                .unwrap();

            println!("Relations:");
            for (source, target, relation_type) in relations {
                println!("  {} -> {} ({})", source, target, relation_type);
            }
        }
        Err(err) => {
            eprintln!("Analysis failed: {}", err);
        }
    }



}

// use tree_sitter_rust::language as rust_language;

// /// Represents a parsed function or method
// #[derive(Clone, Debug)]
// struct Function {
//     /// Name of the function
//     pub name: String,
//     /// Fully qualified name (e.g. "crate::auth::login")
//     pub fq_name: String,
//     /// Module where the function is defined
//     pub module: String,
//     /// Path to the source file
//     pub file: String,
//     /// Start byte position in the file
//     pub start: usize,
//     /// End byte position in the file
//     pub end: usize,
// }

// /// Global in-memory state for code indexing
// #[derive(Clone)]
// struct AppState {
//     // Use Arc to share between handlers
//     indexer: Arc<Indexer>,
// }

// struct Indexer {
//     /// Map of fully-qualified name to Function
//     pub funcs: DashMap<String, Function>,
//     /// Call graph edges: (caller, callee)
//     pub edges: SegQueue<(String, String)>,
// }

// impl Indexer {
//     pub fn new() -> Self {
//         Self {
//             funcs: DashMap::new(),
//             edges: SegQueue::new(),
//         }
//     }
// }

// #[tokio::main]
// async fn main() {
//     // Create application state
//     let state = AppState {
//         indexer: Arc::new(Indexer::new()),
//     };

//     // Build our application with routes
//     let app = Router::new()
//         .route("/", get(serve_upload_form))
//         .route("/upload", post(handle_upload))
//         .with_state(state);

//     // Run the server
//     let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
//     println!("Server running at http://{}", addr);
    
//     axum::Server::bind(&addr)
//         .serve(app.into_make_service())
//         .with_graceful_shutdown(shutdown_signal())
//         .await
//         .unwrap();
// }

// // Serve the HTML form for file upload
// async fn serve_upload_form() -> Html<&'static str> {
//     Html(include_str!("../assets/upload_form.html"))
// }

// // Handle uploaded files and build call graph
// async fn handle_upload(
//     State(state): State<AppState>, 
//     mut multipart: Multipart
// ) -> impl IntoResponse {
//     let mut in_memory_files: HashMap<String, String> = HashMap::new();
    
//     // Process each part of the multipart request
//     while let Ok(Some(field)) = multipart.next_field().await {
//         let filename = match field.file_name() {
//             Some(name) => name.to_string(),
//             None => continue, // Skip fields without filename
//         };
        
//         if !filename.ends_with(".rs") {
//             continue; // Skip non-Rust files
//         }
        
//         let data = match field.bytes().await {
//             Ok(bytes) => bytes,
//             Err(_) => continue,
//         };
        
//         // Convert bytes to string and add to our in-memory collection
//         if let Ok(content) = String::from_utf8(data.to_vec()) {
//             in_memory_files.insert(filename, content);
//         }
//     }
    
//     // Process the uploaded files and build the call graph
//     let result = process_in_memory_files(in_memory_files, state.indexer).await;
    
//     // Return JSON result
//     Response::builder()
//         .status(StatusCode::OK)
//         .header("Content-Type", "application/json")
//         .body(Body::from(result))
//         .unwrap()
// }

// // Process the in-memory files to build a call graph
// async fn process_in_memory_files(
//     files: HashMap<String, String>,
//     indexer: Arc<Indexer>
// ) -> String {
//     // Use thread_local for the parser since Tree-sitter isn't thread-safe
//     thread_local! {
//         static PARSER: RefCell<Parser> = RefCell::new({
//             let mut parser = Parser::new();
//             unsafe { parser.set_language(rust_language()).unwrap() };
//             parser
//         });
//     }

//     // Convert the files HashMap to a vector for parallel processing
//     let files_vec: Vec<(String, String)> = files.into_iter().collect();
    
//     // Phase 1: Extract function definitions from all files
//     files_vec.par_iter().for_each(|(path, source)| {
//         PARSER.with(|parser| {
//             let tree = match parser.borrow_mut().parse(source, None) {
//                 Some(tree) => tree,
//                 None => return,
//             };
            
//             let root = tree.root_node();
//             let mod_path = virtual_module_path_from_filename(path);
            
//             extract_function_definitions(&root, source, &mod_path, path, &indexer);
//         });
//     });

//     // Phase 2: Extract function calls and resolve them
//     files_vec.par_iter().for_each(|(path, source)| {
//         PARSER.with(|parser| {
//             let tree = match parser.borrow_mut().parse(source, None) {
//                 Some(tree) => tree,
//                 None => return,
//             };
            
//             let root = tree.root_node();
//             let mod_path = virtual_module_path_from_filename(path);
            
//             extract_function_calls(&root, source, &mod_path, &indexer);
//         });
//     });

//     // Build the call graph from collected data
//     let mut graph = Graph::<Function, (), Directed>::new();
//     let mut node_indices = HashMap::new();
    
//     // Add all functions as nodes
//     for entry in indexer.funcs.iter() {
//         let function = entry.value().clone();
//         let node_idx = graph.add_node(function.clone());
//         node_indices.insert(function.fq_name.clone(), node_idx);
//     }
    
//     // Add all edges between functions
//     while let Some((caller, callee)) = indexer.edges.pop() {
//         if let (Some(&caller_idx), Some(&callee_idx)) = (
//             node_indices.get(&caller), 
//             node_indices.get(&callee)
//         ) {
//             graph.add_edge(caller_idx, callee_idx, ());
//         }
//     }
    
//     // Convert the graph to a JSON representation
//     let graph_json = serialize_graph_to_json(&graph, &node_indices);
    
//     format!(
//         "{{ \"stats\": {{ \"functions\": {}, \"calls\": {} }}, \"graph\": {} }}",
//         graph.node_count(),
//         graph.edge_count(),
//         graph_json
//     )
// }

// // Generate a module path from a filename for in-memory files
// fn virtual_module_path_from_filename(filename: &str) -> String {
//     // Strip .rs extension
//     let without_ext = filename.trim_end_matches(".rs");
    
//     // Convert any path separators to Rust module separators
//     let mod_path = without_ext.replace('/', "::").replace('\\', "::");
    
//     // For lib.rs or mod.rs, use the parent directory name
//     if mod_path.ends_with("lib") || mod_path.ends_with("mod") {
//         let parts: Vec<&str> = mod_path.split("::").collect();
//         if parts.len() > 1 {
//             parts[..parts.len() - 1].join("::")
//         } else {
//             "crate".to_string()
//         }
//     } else {
//         if mod_path.is_empty() {
//             "crate".to_string()
//         } else {
//             mod_path
//         }
//     }
// }

// // Create a JSON representation of the graph for frontend visualization
// fn serialize_graph_to_json(
//     graph: &Graph<Function, (), Directed>,
//     node_indices: &HashMap<String, NodeIndex>
// ) -> String {
//     let mut nodes = Vec::new();
//     let mut links = Vec::new();
    
//     // Add nodes
//     for (fq_name, &idx) in node_indices {
//         let func = &graph[idx];
//         nodes.push(json!({
//             "id": fq_name,
//             "name": func.name,
//             "module": func.module,
//             "file": func.file
//         }));
//     }
    
//     // Add edges
//     for edge in graph.edge_references() {
//         let source = &graph[edge.source()];
//         let target = &graph[edge.target()];
        
//         links.push(json!({
//             "source": source.fq_name,
//             "target": target.fq_name
//         }));
//     }
    
//     json!({
//         "nodes": nodes,
//         "links": links
//     }).to_string()
// }

// /// Walks AST to find all function_item nodes and store them in the indexer
// fn extract_function_definitions(
//     root: &Node,
//     source: &str,
//     module_path: &str,
//     file_path: &str,
//     indexer: &Indexer,
// ) {
//     let mut cursor = root.walk();
//     for function_node in root.children(&mut cursor).filter(|n| n.kind() == "function_item") {
//         if let Some(name_node) = function_node.child_by_field_name("name") {
//             if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
//                 // Create fully qualified name
//                 let fully_qualified_name = format!("{}::{}", module_path, name);
                
//                 // Store function information
//                 indexer.funcs.insert(fully_qualified_name.clone(), Function {
//                     name: name.to_string(),
//                     fq_name: fully_qualified_name.clone(),
//                     module: module_path.to_string(),
//                     file: file_path.to_string(),
//                     start: function_node.start_byte(),
//                     end: function_node.end_byte(),
//                 });
                
//                 println!("Found function: {}", fully_qualified_name);
//             }
//         }
//     }
// }

// fn extract_function_calls(
//     root: &Node,
//     source: &str,
//     module_path: &str,
//     indexer: &Indexer,
// ) {
//     // First collect all import statements to help resolve function calls
//     let import_map = parse_import_statements(root, source);
    
//     // Create a recursive function to visit all nodes
//     fn visit_nodes_for_calls(
//         node: &Node, 
//         source: &str,
//         module_path: &str,
//         import_map: &HashMap<String, String>,
//         indexer: &Indexer
//     ) {
//         // Check if current node is a call expression
//         if node.kind() == "call_expression" {
//             if let Some(callee_node) = node.child_by_field_name("function") {
//                 if let Ok(callee_name) = callee_node.utf8_text(source.as_bytes()) {
//                     // Resolve the function name to its fully qualified form
//                     let fully_qualified_callee = if callee_name.contains("::") {
//                         // Already a fully qualified path
//                         callee_name.to_string()
//                     } else if let Some(full_path) = import_map.get(callee_name) {
//                         // Resolve via import
//                         full_path.clone()
//                     } else {
//                         // Assume it's in the current module
//                         format!("{}::{}", module_path, callee_name)
//                     };
                    
//                     // Find the function containing this call
//                     if let Some(caller_function) = find_enclosing_function(node, source, module_path) {
//                         // Only record the edge if the callee exists in our index
//                         if indexer.funcs.contains_key(&fully_qualified_callee) {
//                             indexer.edges.push((caller_function, fully_qualified_callee));
//                             println!("Found call: {} -> {}", caller_function, fully_qualified_callee);
//                         }
//                     }
//                 }
//             }
//         }
        
//         // Visit all children recursively
//         let mut cursor = node.walk();
//         for child in node.children(&mut cursor) {
//             visit_nodes_for_calls(&child, source, module_path, import_map, indexer);
//         }
//     }
    
//     // Start the recursive traversal from the root
//     visit_nodes_for_calls(root, source, module_path, &import_map, indexer);
// }

// /// Parse `use foo::bar as baz` and similar import statements 
// fn parse_import_statements(root: &Node, source: &str) -> HashMap<String, String> {
//     let mut imports = HashMap::new();
    
//     // Create a recursive function to visit all nodes
//     fn visit_nodes_for_imports(
//         node: &Node,
//         source: &str,
//         imports: &mut HashMap<String, String>
//     ) {
//         // Check if this node is a use declaration
//         if node.kind() == "use_declaration" {
//             if let Some(path_node) = node.child_by_field_name("path") {
//                 if let Ok(path_text) = path_node.utf8_text(source.as_bytes()) {
//                     // Extract the alias (last part after ::)
//                     let alias = path_text.rsplit("::").next().unwrap_or(path_text);
//                     imports.insert(alias.to_string(), path_text.to_string());
//                 }
//             }
//         }
        
//         // Visit all children recursively
//         let mut cursor = node.walk();
//         for child in node.children(&mut cursor) {
//             visit_nodes_for_imports(&child, source, imports);
//         }
//     }
    
//     // Start the recursive traversal from the root
//     visit_nodes_for_imports(root, source, &mut imports);
    
//     imports
// }

// /// Walk up the tree to find the enclosing function and return its fully qualified name
// fn find_enclosing_function(node: &Node, source: &str, module_path: &str) -> Option<String> {
//     let mut current_opt = Some(*node);
    
//     // Traverse up the tree
//     while let Some(current) = current_opt {
//         if current.kind() == "function_item" {
//             if let Some(name_node) = current.child_by_field_name("name") {
//                 if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
//                     return Some(format!("{}::{}", module_path, name));
//                 }
//             }
//         }
        
//         // Move to parent
//         current_opt = current.parent();
//     }
    
//     None
// }

// // Signal handler for graceful shutdown
// async fn shutdown_signal() {
//     let ctrl_c = async {
//         signal::ctrl_c()
//             .await
//             .expect("Failed to install Ctrl+C handler");
//     };

//     #[cfg(unix)]
//     let terminate = async {
//         signal::unix::signal(signal::unix::SignalKind::terminate())
//             .expect("Failed to install signal handler")
//             .recv()
//             .await;
//     };

//     #[cfg(not(unix))]
//     let terminate = std::future::pending::<()>();

//     tokio::select! {
//         _ = ctrl_c => {},
//         _ = terminate => {},
//     }

//     println!("Shutdown signal received, starting graceful shutdown");
// }