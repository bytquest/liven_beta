use std::{path::PathBuf, collections::HashMap, sync::Arc, net::SocketAddr};
use std::cell::RefCell;
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
#[derive(Clone, Debug, Serialize, Deserialize)]
struct AnalysisSession {
    /// Unique identifier for the session
    pub id: String,
    /// Number of functions found
    pub function_count: i32,
    /// Number of call relationships found
    pub call_count: i32,
    /// Description or name of the analysis
    pub description: String,
}

/// Global in-memory state for code indexing
#[derive(Clone)]
struct AppState {
    // Use Arc to share between handlers
    indexer: Arc<Indexer>,
    // Database connection pool
    db_pool: SqlitePool,
}

struct Indexer {
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup database
    let db_url = "sqlite:callgraph.db";
    
    // Create the database if it doesn't exist
    if !Sqlite::database_exists(db_url).await.unwrap_or(false) {
        Sqlite::create_database(db_url).await?;
    }
    
    // Connect to the database
    let pool = SqlitePool::connect(db_url).await?;
    
    // Create tables if they don't exist
    create_tables(&pool).await?;
    
    // Create application state
    let state = AppState {
        indexer: Arc::new(Indexer::new()),
        db_pool: pool,
    };

    // Build our application with routes
    let app = Router::new()
        .route("/upload", post(handle_upload))
        .route("/analyses", get(list_analyses))
        .route("/analysis/:id", get(get_analysis))
        .with_state(state);

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running at http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
        
    Ok(())
}

// Create necessary database tables
async fn create_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Create sessions table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            function_count INTEGER NOT NULL,
            call_count INTEGER NOT NULL,
            description TEXT NOT NULL
        )"
    )
    .execute(pool)
    .await?;
    
    // Create functions table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS functions (
            session_id TEXT NOT NULL,
            fq_name TEXT NOT NULL,
            name TEXT NOT NULL,
            module TEXT NOT NULL,
            file TEXT NOT NULL,
            start_byte INTEGER NOT NULL,
            end_byte INTEGER NOT NULL,
            PRIMARY KEY (session_id, fq_name),
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )"
    )
    .execute(pool)
    .await?;
    
    // Create calls table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS calls (
            session_id TEXT NOT NULL,
            caller TEXT NOT NULL,
            callee TEXT NOT NULL,
            PRIMARY KEY (session_id, caller, callee),
            FOREIGN KEY (session_id) REFERENCES sessions(id),
            FOREIGN KEY (session_id, caller) REFERENCES functions(session_id, fq_name),
            FOREIGN KEY (session_id, callee) REFERENCES functions(session_id, fq_name)
        )"
    )
    .execute(pool)
    .await?;
    
    Ok(())
}


// List all saved analyses
async fn list_analyses(
    State(state): State<AppState>
) -> Result<Json<Vec<AnalysisSession>>, StatusCode> {
    let sessions = sqlx::query("SELECT id,  function_count, call_count, description FROM sessions ORDER BY timestamp DESC")
        .map(|row: sqlx::sqlite::SqliteRow| {
            AnalysisSession {
                id: row.get("id"),
                function_count: row.get("function_count"),
                call_count: row.get("call_count"),
                description: row.get("description"),
            }
        })
        .fetch_all(&state.db_pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
    Ok(Json(sessions))
}

// Get a specific analysis by ID
async fn get_analysis(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Get session info
    let session = match sqlx::query("SELECT id, timestamp, function_count, call_count, description FROM sessions WHERE id = ?")
        .bind(&id)
        .map(|row: sqlx::sqlite::SqliteRow| {
            AnalysisSession {
                id: row.get("id"),
                function_count: row.get("function_count"),
                call_count: row.get("call_count"),
                description: row.get("description"),
            }
        })
        .fetch_optional(&state.db_pool)
        .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Get all functions for this session
    let functions: Vec<Function> = match sqlx::query(
        "SELECT fq_name, name, module, file, start_byte, end_byte 
         FROM functions 
         WHERE session_id = ?"
    )
    .bind(&id)
    .map(|row: sqlx::sqlite::SqliteRow| {
        Function {
            fq_name: row.get("fq_name"),
            name: row.get("name"),
            module: row.get("module"),
            file: row.get("file"),
            start: row.get::<i64, _>("start_byte") as usize,
            end: row.get::<i64, _>("end_byte") as usize,
        }
    })
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(funcs) => funcs,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    
    // Get all call relationships for this session
    let calls: Vec<(String, String)> = match sqlx::query(
        "SELECT caller, callee FROM calls WHERE session_id = ?"
    )
    .bind(&id)
    .map(|row: sqlx::sqlite::SqliteRow| {
        (row.get("caller"), row.get("callee"))
    })
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(calls) => calls,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    
    // Build a graph from the retrieved data
    let mut graph = Graph::<Function, (), Directed>::new();
    let mut node_indices = HashMap::new();
    
    // Add all functions as nodes
    for function in &functions {
        let node_idx = graph.add_node(function.clone());
        node_indices.insert(function.fq_name.clone(), node_idx);
    }
    
    // Add all edges
    for (caller, callee) in &calls {
        if let (Some(&caller_idx), Some(&callee_idx)) = (
            node_indices.get(caller), 
            node_indices.get(callee)
        ) {
            graph.add_edge(caller_idx, callee_idx, ());
        }
    }
    
    // Format the response
    let graph_json = serialize_graph_to_json(&graph, &node_indices);
    let response = json!({
        "session": session,
        "stats": {
            "functions": functions.len(),
            "calls": calls.len()
        },
        "graph": graph_json
    });
    
    Json(response).into_response()
}

// Handle uploaded files and build call graph
async fn handle_upload(
    State(state): State<AppState>, 
    mut multipart: Multipart
) -> impl IntoResponse {
    let mut in_memory_files: HashMap<String, String> = HashMap::new();
    let mut description = "Unnamed Analysis".to_string();
    
    // Process each part of the multipart request
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        
        // If this is the description field
        if name == "description" {
            if let Ok(desc) = field.text().await {
                if !desc.trim().is_empty() {
                    description = desc;
                }
            }
            continue;
        }
        
        let filename = match field.file_name() {
            Some(name) => name.to_string(),
            None => continue, // Skip fields without filename
        };
        
        if !filename.ends_with(".rs") {
            continue; // Skip non-Rust files
        }
        
        let data = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        
        // Convert bytes to string and add to our in-memory collection
        if let Ok(content) = String::from_utf8(data.to_vec()) {
            in_memory_files.insert(filename, content);
        }
    }
    
    // Process the uploaded files and build the call graph
    match process_and_store_analysis(in_memory_files, state.indexer.clone(), &state.db_pool, description).await {
        Ok(session_id) => {
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Body::from(format!(r#"{{"success":true,"session_id":"{}"}}"#, session_id)))
                .unwrap()
        },
        Err(_) => {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(r#"{"success":false,"error":"Failed to process files"}"#))
                .unwrap()
        }
    }
}

// Process the in-memory files to build a call graph and store in database
async fn process_and_store_analysis(
    files: HashMap<String, String>,
    indexer: Arc<Indexer>,
    db_pool: &SqlitePool,
    description: String,
) -> Result<String, Box<dyn std::error::Error>> {
    // Reset the indexer for this new analysis
    indexer.funcs.clear();
    while let Some(_) = indexer.edges.pop() {}
    
    // Use thread_local for the parser since Tree-sitter isn't thread-safe
    thread_local! {
        static PARSER: RefCell<Parser> = RefCell::new({
            let mut parser = Parser::new();
            unsafe { parser.set_language(rust_language()).unwrap() };
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
            let mod_path = virtual_module_path_from_filename(path);
            
            extract_function_definitions(&root, source, &mod_path, path, &indexer);
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
            let mod_path = virtual_module_path_from_filename(path);
            
            extract_function_calls(&root, source, &mod_path, &indexer);
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
    
    // Generate a unique ID for this analysis session
    let session_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now();
    let function_count = graph.node_count() as i32;
    let call_count = graph.edge_count() as i32;
    
    // Store the session in database
    let mut tx = db_pool.begin().await?;
    
    // Insert session record
    sqlx::query(
        "INSERT INTO sessions (id, timestamp, function_count, call_count, description) 
         VALUES (?, ?, ?, ?,?)"
    )
    .bind(&session_id)
    .bind(function_count)
    .bind(call_count)
    .bind(&description)
    .execute(&mut tx)
    .await?;
    
    // Insert all functions
    for node_idx in graph.node_indices() {
        let function = &graph[node_idx];
        
        sqlx::query(
            "INSERT INTO functions (session_id, fq_name, name, module, file, start_byte, end_byte)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&session_id)
        .bind(&function.fq_name)
        .bind(&function.name)
        .bind(&function.module)
        .bind(&function.file)
        .bind(function.start as i64)
        .bind(function.end as i64)
        .execute(&mut tx)
        .await?;
    }
    
    // Insert all call relationships
    for (caller, callee) in edges {
        sqlx::query(
            "INSERT INTO calls (session_id, caller, callee)
             VALUES (?, ?, ?)"
        )
        .bind(&session_id)
        .bind(&caller)
        .bind(&callee)
        .execute(&mut tx)
        .await?;
    }
    
    // Commit the transaction
    tx.commit().await?;
    
    Ok(session_id)
}

// Generate a module path from a filename for in-memory files
fn virtual_module_path_from_filename(filename: &str) -> String {
    // Strip .rs extension
    let without_ext = filename.trim_end_matches(".rs");
    
    // Convert any path separators to Rust module separators
    let mod_path = without_ext.replace('/', "::").replace('\\', "::");
    
    // For lib.rs or mod.rs, use the parent directory name
    if mod_path.ends_with("lib") || mod_path.ends_with("mod") {
        let parts: Vec<&str> = mod_path.split("::").collect();
        if parts.len() > 1 {
            parts[..parts.len() - 1].join("::")
        } else {
            "crate".to_string()
        }
    } else {
        if mod_path.is_empty() {
            "crate".to_string()
        } else {
            mod_path
        }
    }
}

// Create a JSON representation of the graph for frontend visualization
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

/// Walks AST to find all function_item nodes and store them in the indexer
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

// Signal handler for graceful shutdown
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("Shutdown signal received, starting graceful shutdown");
}