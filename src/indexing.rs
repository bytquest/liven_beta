// use std::{
//     collections::HashMap,
//     fs::File,
//     path::{Path, PathBuf},
//     sync::Arc,
//     time::{Duration, Instant, SystemTime},
// };

// use anyhow::{Context, Result};
// use axum::{
//     extract::{Json, State},
//     http::StatusCode,
//     response::{IntoResponse, Response},
//     routing::{get, post},
//     Router,
// };
// use tokio::net::{TcpListener, TcpStream};
// use std::net::SocketAddr;
// use axum::{
//     body::{Body, HttpBody}, extract::{self, Multipart,  Query}, handler::Handler,  response::{},  Error,
// };
// use dashmap::DashMap;
// use futures::stream::{self, StreamExt};
// use ignore::WalkBuilder;
// use log::{debug, error, info, warn};
// use memmap2::MmapOptions;
// use neo4rs::{query, Graph as NeoGraph};
// use petgraph::{
//     graph::{DiGraph, NodeIndex},
//     Direction,
// };
// use rayon::prelude::*;
// use serde::{Deserialize, Serialize};
// use tokio::sync::Semaphore;
// use tower_http::trace::TraceLayer;
// use tree_sitter::{Language, Node, Parser};

// extern "C" {
//     fn tree_sitter_rust() -> Language;
// }

// /// Rust Codebase Analyzer - Server configuration
// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct ServerConfig {
//     /// Neo4j connection URL
//     neo4j_url: String,
//     /// Neo4j username
//     neo4j_user: String,
//     /// Neo4j password
//     neo4j_pass: String,
//     /// Maximum number of concurrent Neo4j operations
//     neo4j_concurrency: usize,
//     /// Cache file to enable incremental processing
//     cache_file: Option<String>,
//     /// Server port to listen on
//     port: u16,
// }

// impl Default for ServerConfig {
//     fn default() -> Self {
//         Self {
//             neo4j_url: "localhost:7687".to_string(),
//             neo4j_user: "neo4j".to_string(),
//             neo4j_pass: "neo4j".to_string(),
//             neo4j_concurrency: 10,
//             cache_file: None,
//             port: 3000,
//         }
//     }
// }

// /// Request to analyze a repository
// #[derive(Debug, Deserialize)]
// struct AnalysisRequest {
//     /// Root directory of Rust codebase to analyze
//     repo_path: String,
//     /// Delete all existing nodes before processing
//     clean: bool,
//     /// Only parse files modified after this many days ago
//     days: Option<u64>,
// }

// /// Response with analysis statistics
// #[derive(Debug, Serialize)]
// struct AnalysisResponse {
//     functions_count: usize,
//     calls_count: usize,
//     processed_files: usize,
//     skipped_files: usize,
//     error_files: usize,
//     duration_seconds: f64,
// }

// /// Represents a function entity with fully-qualified name and metadata
// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct Function {
//     fq_name: String,
//     file: String,
//     start_byte: usize,
//     end_byte: usize,
//     modified: SystemTime,
//     #[serde(skip)]
//     call_count: usize,
//     #[serde(skip)]
//     called_by_count: usize,
// }

// /// Cached file information for incremental processing
// #[derive(Serialize, Deserialize)]
// struct FileCache {
//     path: String,
//     last_modified: SystemTime,
// }

// /// Holds processing and analysis results
// struct AnalysisResult {
//     functions: DashMap<String, Function>,
//     calls: DashMap<(String, String), bool>,
//     processed: std::sync::atomic::AtomicUsize,
//     skipped: std::sync::atomic::AtomicUsize,
//     errors: std::sync::atomic::AtomicUsize,
// }

// impl Default for AnalysisResult {
//     fn default() -> Self {
//         Self {
//             functions: DashMap::new(),
//             calls: DashMap::new(),
//             processed: std::sync::atomic::AtomicUsize::new(0),
//             skipped: std::sync::atomic::AtomicUsize::new(0),
//             errors: std::sync::atomic::AtomicUsize::new(0),
//         }
//     }
// }

// /// Application state shared across requests
// #[derive(Clone)]
// struct AppState {
//     config: ServerConfig,
//     neo_graph: Arc<NeoGraph>,
//     semaphore: Arc<Semaphore>,
// }

// /// Custom error type for API responses
// enum ApiError {
//     InternalError(anyhow::Error),
//     BadRequest(String),
// }

// impl From<anyhow::Error> for ApiError {
//     fn from(err: anyhow::Error) -> Self {
//         ApiError::InternalError(err)
//     }
// }

// impl IntoResponse for ApiError {
//     fn into_response(self) -> Response {
//         match self {
//             ApiError::InternalError(err) => {
//                 error!("Internal error: {}", err);
//                 (
//                     StatusCode::INTERNAL_SERVER_ERROR,
//                     Json(serde_json::json!({
//                         "error": format!("Internal server error: {}", err)
//                     })),
//                 )
//                     .into_response()
//             }
//             ApiError::BadRequest(msg) => {
//                 warn!("Bad request: {}", msg);
//                 (
//                     StatusCode::BAD_REQUEST,
//                     Json(serde_json::json!({
//                         "error": msg
//                     })),
//                 )
//                     .into_response()
//             }
//         }
//     }
// }

// type ApiResult<T> = std::result::Result<T, ApiError>;

// #[tokio::main]
// async fn build_server() -> Result<()> {
//     // Setup logging
//     env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
//     info!("Starting Rust code analyzer API server");

//     // Load server configuration
//     let config = load_config().unwrap_or_default();
    
//     // Create a Neo4j connection
//     let neo = Arc::new(
//         NeoGraph::new(&config.neo4j_url, &config.neo4j_user, &config.neo4j_pass)
//             .await
//             .context("Failed to connect to Neo4j")?,
//     );

//     // Create initial indexes
//     neo.run(query("CREATE INDEX function_id IF NOT EXISTS FOR (f:Function) ON (f.id)"))
//         .await?;

//     // Create app state
//     let state = AppState {
//         config: config.clone(),
//         neo_graph: neo,
//         semaphore: Arc::new(Semaphore::new(config.neo4j_concurrency)),
//     };

//     // Build the router
//     let app = Router::new()
//         .route("/health", get(health_check))
//         .route("/analyze", post(analyze_repo))
//         .route("/config", get(get_config))
//         .with_state(state);

//     // Start the server
//     let addr = format!("0.0.0.0:{}", config.port);
//     info!("Server listening on {}", addr);
//     let listener = tokio::net::TcpListener::bind(&addr).await?;
//     axum::serve(listener, app.into_make_service()).await?;

//     Ok(())
// }

// /// Load server configuration from environment or config file
// fn load_config() -> Result<ServerConfig> {
//     // TODO: Implement configuration loading from file or environment
//     // For now, just return default config
//     Ok(ServerConfig::default())
// }

// /// Health check endpoint
// async fn health_check() -> &'static str {
//     "OK"
// }

// /// Get server configuration
// async fn get_config(State(state): State<AppState>) -> Json<ServerConfig> {
//     Json(state.config.clone())
// }

// /// Analyze repository endpoint
// async fn analyze_repo(
//     State(state): State<AppState>,
//     Json(request): Json<AnalysisRequest>,
// ) -> ApiResult<Json<AnalysisResponse>> {
//     let start_time = Instant::now();
//     info!("Starting analysis of {}", request.repo_path);

//     // Validate repository path
//     let repo_path = Path::new(&request.repo_path);
//     if !repo_path.exists() || !repo_path.is_dir() {
//         return Err(ApiError::BadRequest(format!(
//             "Repository path does not exist or is not a directory: {}",
//             request.repo_path
//         )));
//     }

//     // Load file cache if available
//     let mut file_cache = HashMap::new();
//     if let Some(cache_path) = &state.config.cache_file {
//         let cache_path = PathBuf::from(cache_path);
//         if cache_path.exists() {
//             match std::fs::read_to_string(&cache_path) {
//                 Ok(cache_content) => {
//                     match serde_json::from_str::<Vec<FileCache>>(&cache_content) {
//                         Ok(cache_entries) => {
//                             for entry in cache_entries {
//                                 file_cache.insert(entry.path, entry.last_modified);
//                             }
//                             info!("Loaded cache with {} entries", file_cache.len());
//                         }
//                         Err(e) => warn!("Failed to parse cache file: {}", e),
//                     }
//                 }
//                 Err(e) => warn!("Failed to read cache file: {}", e),
//             }
//         }
//     }

//     // Find Rust files to process
//     info!("Scanning for Rust files in {}", request.repo_path);

//     let cutoff_time = if let Some(days) = request.days {
//         Some(
//             SystemTime::now()
//                 .checked_sub(Duration::from_secs(days * 24 * 60 * 60))
//                 .unwrap_or_else(SystemTime::now),
//         )
//     } else {
//         None
//     };

//     // Find all Rust files in the specified directory
//     let mut files_to_process = Vec::new();
//     let mut skipped_files = 0;
    
//     let walker = WalkBuilder::new(&request.repo_path)
//         .hidden(false)
//         .git_ignore(true)
//         .build();

//     for result in walker {
//         match result {
//             Ok(entry) => {
//                 let path = entry.path();
//                 if path.extension().and_then(|s| s.to_str()) == Some("rs") {
//                     // Check if file has been modified since last run
//                     let should_process = if let Some(cutoff) = cutoff_time {
//                         match path.metadata().and_then(|m| m.modified()) {
//                             Ok(modified) => modified > cutoff,
//                             Err(_) => true, // Process if we can't get modified time
//                         }
//                     } else if !file_cache.is_empty() {
//                         let path_str = path.to_string_lossy().to_string();
//                         match path.metadata().and_then(|m| m.modified()) {
//                             Ok(modified) => {
//                                 file_cache
//                                     .get(&path_str)
//                                     .map_or(true, |&cached| modified > cached)
//                             }
//                             Err(_) => true, // Process if we can't get modified time
//                         }
//                     } else {
//                         true
//                     };

//                     if should_process {
//                         files_to_process.push(path.to_path_buf());
//                     } else {
//                         skipped_files += 1;
//                     }
//                 }
//             }
//             Err(e) => warn!("Error walking directory: {}", e),
//         }
//     }

//     info!(
//         "Found {} Rust files to process ({} skipped due to cache/time filter)",
//         files_to_process.len(),
//         skipped_files
//     );

//     // Clean database if requested
//     if request.clean {
//         info!("Cleaning existing database");
//         state
//             .neo_graph
//             .run(query("MATCH (n) DETACH DELETE n"))
//             .await
//             .map_err(|e| ApiError::from(anyhow::Error::from(e)))?;
//     }

//     // Set up analysis result tracking
//     let result = Arc::new(AnalysisResult::default());

//     // Process files in parallel using Rayon's thread pool
//     info!("Processing {} files using Rayon thread pool", files_to_process.len());
    
//     // We need to use a specific closure format for Rayon's par_iter
//     files_to_process.par_iter().for_each(|path| {
//         // Thread-local parser setup
//         thread_local! {
//             static PARSER: std::cell::RefCell<Parser> = {
//                 let mut p = Parser::new();
//                 unsafe { p.set_language(tree_sitter_rust()).unwrap() };
//                 std::cell::RefCell::new(p)
//             };
//         }

//         PARSER.with(|parser_cell| {
//             let mut parser = parser_cell.borrow_mut();
//             match process_file(path, &mut parser, &result) {
//                 Ok(()) => {
//                     result.processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
//                 }
//                 Err(e) => {
//                     error!("Error processing {}: {}", path.display(), e);
//                     result.errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
//                 }
//             }
//         });
//     });

//     // Build a graph from the collected data
//     info!("Building call graph");
//     let mut graph = DiGraph::<String, (), u32>::new();
//     let mut idx_map = HashMap::new();

//     // Add nodes
//     for entry in result.functions.iter() {
//         let func_name = entry.key();
//         let idx = graph.add_node(func_name.clone());
//         idx_map.insert(func_name.clone(), idx);
//     }

//     // Add edges
//     for entry in result.calls.iter() {
//         let (src, dst) = entry.key();
//         if let (Some(&s_idx), Some(&d_idx)) = (idx_map.get(src), idx_map.get(dst)) {
//             graph.add_edge(s_idx, d_idx, ());
//         }
//     }

//     info!(
//         "Graph built with {} nodes and {} edges",
//         graph.node_count(),
//         graph.edge_count()
//     );

//     // Compute call metrics
//     for node_idx in graph.node_indices() {
//         let func_name = &graph[node_idx];
//         if let Some(mut func) = result.functions.get_mut(func_name) {
//             func.call_count = graph.neighbors_directed(node_idx, Direction::Outgoing).count();
//             func.called_by_count = graph.neighbors_directed(node_idx, Direction::Incoming).count();
//         }
//     }

//     // Persist to Neo4j with controlled concurrency
//     info!("Persisting {} functions to Neo4j", result.functions.len());
//     let functions: Vec<_> = result.functions.iter().map(|r| r.value().clone()).collect();
    
//     let chunks = functions.chunks(100);
//     let chunk_count = chunks.len();
    
//     stream::iter(functions.chunks(100).enumerate())
//         .map(|(i, chunk)| {
//             let neo = state.neo_graph.clone();
//             let semaphore = state.semaphore.clone();
            
//             async move {
//                 let _permit = semaphore.acquire().await.unwrap();
//                 debug!("Persisting function batch {}/{}", i + 1, chunk_count);
                
//                 let query_text = format!(
//                     "UNWIND $functions AS func 
//                      MERGE (f:Function {{id: func.fq_name}}) 
//                      SET f.file = func.file, 
//                          f.start = func.start_byte, 
//                          f.end = func.end_byte,
//                          f.callCount = func.call_count,
//                          f.calledByCount = func.called_by_count"
//                 );
                
//                 let functions_json: Vec<_> = chunk
//                     .iter()
//                     .map(|f| {
//                         serde_json::json!({
//                             "fq_name": f.fq_name,
//                             "file": f.file,
//                             "start_byte": f.start_byte,
//                             "end_byte": f.end_byte,
//                             "call_count": f.call_count,
//                             "called_by_count": f.called_by_count,
//                         })
//                     })
//                     .collect();
                
//                 let result = neo
//                     .run(query(&query_text).param("functions", functions_json.into_iter().map(neo4rs::types::Value::from).collect::<Vec<_>>()))
//                     .await;
                
//                 if let Err(e) = result {
//                     error!("Error persisting functions: {}", e);
//                 }
                
//                 Result::<_, anyhow::Error>::Ok(())
//             }
//         })
//         .buffer_unordered(state.config.neo4j_concurrency)
//         .collect::<Vec<_>>()
//         .await;

//     // Persist call relationships in batches
//     info!("Persisting {} call relationships to Neo4j", result.calls.len());
//     let calls: Vec<_> = result.calls.iter().map(|r| r.key().clone()).collect();
    
//     stream::iter(calls.chunks(500).enumerate())
//         .map(|(i, chunk)| {
//             let neo = state.neo_graph.clone();
//             let semaphore = state.semaphore.clone();
//             let chunk_count = (calls.len() + 499) / 500;
            
//             async move {
//                 let _permit = semaphore.acquire().await.unwrap();
//                 debug!("Persisting call batch {}/{}", i + 1, chunk_count);
                
//                 let query_text = format!(
//                     "UNWIND $calls AS call 
//                      MATCH (src:Function {{id: call.src}}), (dst:Function {{id: call.dst}}) 
//                      MERGE (src)-[:CALLS]->(dst)"
//                 );
                
//                 let calls_json: Vec<_> = chunk
//                     .iter()
//                     .map(|(src, dst)| {
//                         serde_json::json!({
//                             "src": src,
//                             "dst": dst
//                         })
//                     })
//                     .collect();
                
//                 let result = neo
//                     .run(query(&query_text).param("calls", calls_json))
//                     .await;
                
//                 if let Err(e) = result {
//                     error!("Error persisting calls: {}", e);
//                 }
                
//                 Result::<_, anyhow::Error>::Ok(())
//             }
//         })
//         .buffer_unordered(state.config.neo4j_concurrency)
//         .collect::<Vec<_>>()
//         .await;

//     // Update cache for incremental processing
//     if let Some(cache_path) = &state.config.cache_file {
//         info!("Updating cache file");
//         let cache_path = PathBuf::from(cache_path);
//         let mut new_cache = Vec::new();
        
//         for entry in result.functions.iter() {
//             let func = entry.value();
//             new_cache.push(FileCache {
//                 path: func.file.clone(),
//                 last_modified: func.modified,
//             });
//         }
        
//         // Update with files that were skipped but in cache
//         for (path, &modified) in &file_cache {
//             if !new_cache.iter().any(|c| c.path == *path) {
//                 new_cache.push(FileCache {
//                     path: path.clone(),
//                     last_modified: modified,
//                 });
//             }
//         }
        
//         match serde_json::to_string_pretty(&new_cache) {
//             Ok(json) => {
//                 if let Err(e) = std::fs::write(cache_path, json) {
//                     warn!("Failed to write cache file: {}", e);
//                 }
//             }
//             Err(e) => warn!("Failed to serialize cache: {}", e),
//         }
//     }

//     let duration = start_time.elapsed();
//     info!(
//         "Analysis complete in {:.2} seconds",
//         duration.as_secs_f64()
//     );

//     // Prepare the response
//     let response = AnalysisResponse {
//         functions_count: result.functions.len(),
//         calls_count: result.calls.len(),
//         processed_files: result.processed.load(std::sync::atomic::Ordering::Relaxed),
//         skipped_files,
//         error_files: result.errors.load(std::sync::atomic::Ordering::Relaxed),
//         duration_seconds: duration.as_secs_f64(),
//     };

//     Ok(Json(response))
// }

// /// Process a single Rust source file
// fn process_file(
//     path: &Path,
//     parser: &mut Parser,
//     result: &AnalysisResult,
// ) -> Result<()> {
//     // Get file modification time for cache
//     let modified = path
//         .metadata()
//         .context("Failed to get file metadata")?
//         .modified()
//         .context("Failed to get file modification time")?;

//     // Open and memory-map the file
//     let file = File::open(path).context("Failed to open file")?;
//     let mmap = unsafe { MmapOptions::new().map(&file).context("Failed to mmap file")? };
//     let source = std::str::from_utf8(&mmap).context("Failed to read file as utf8")?;

//     // Parse file with tree-sitter
//     let tree = parser
//         .parse(source, None)
//         .context("Failed to parse source code")?;
//     let root = tree.root_node();

//     // Determine module path
//     let file_path = path.to_string_lossy().into_owned();
//     let mod_path = module_path(path);

//     // Track module imports for better name resolution
//     let mut imports = HashMap::new();
//     let mut cursor = root.walk();
//     for import in root.children(&mut cursor).filter(|n| n.kind() == "use_declaration") {
//         if let Some(path_node) = import.child_by_field_name("path") {
//             if let Ok(path_text) = path_node.utf8_text(source.as_bytes()) {
//                 // Very basic import handling - just captures the last segment
//                 if let Some(last_segment) = path_text.split("::").last() {
//                     imports.insert(last_segment.to_string(), path_text.to_string());
//                 }
//             }
//         }
//     }

//     // Extract function definitions
//     let mut cursor = root.walk();
//     for fn_node in root.children(&mut cursor).filter(|n| n.kind() == "function_item") {
//         if let Some(name_node) = fn_node.child_by_field_name("name") {
//             if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
//                 let fq = format!("{}::{}", mod_path, name);
//                 result.functions.insert(
//                     fq.clone(),
//                     Function {
//                         fq_name: fq,
//                         file: file_path.clone(),
//                         start_byte: fn_node.start_byte(),
//                         end_byte: fn_node.end_byte(),
//                         modified,
//                         call_count: 0,
//                         called_by_count: 0,
//                     },
//                 );
//             }
//         }
//     }

//     // Extract call expressions
//     for call in root.descendants().filter(|n| n.kind() == "call_expression") {
//         if let Some(callee) = call.child_by_field_name("function") {
//             if let Ok(callee_name) = callee.utf8_text(source.as_bytes()) {
//                 // Try to resolve the callee using imports
//                 let resolved_callee = resolve_name(callee_name, &imports);
                
//                 if let Some(caller_fn) = find_enclosing_fn(&call, &mod_path, source) {
//                     // First try with module prefix
//                     let fq_call = format!("{}::{}", mod_path, resolved_callee);
//                     result.calls.insert((caller_fn.clone(), fq_call.clone()), true);
                    
//                     // Also try with the name as-is in case it's already fully qualified
//                     if resolved_callee.contains("::") {
//                         result.calls.insert((caller_fn, resolved_callee.to_string()), true);
//                     }
//                 }
//             }
//         }
//     }

//     Ok(())
// }

// /// Try to resolve a function name using import information
// fn resolve_name(name: &str, imports: &HashMap<String, String>) -> String {
//     if name.contains("::") {
//         // Already qualified
//         return name.to_string();
//     }
    
//     // Check if it's an imported name
//     if let Some(import_path) = imports.get(name) {
//         return import_path.clone();
//     }
    
//     // Default to the original name
//     name.to_string()
// }

// /// Derive a module path from file path, e.g., src/auth/mod.rs -> crate::auth
// fn module_path(path: &Path) -> String {
//     // Handle Cargo workspace structure
//     let components: Vec<_> = path
//         .components()
//         .filter_map(|c| c.as_os_str().to_str())
//         .collect();
        
//     let mut result = Vec::new();
//     let mut in_src = false;
//     let mut crate_name = String::from("crate");
    
//     // Try to determine crate name from path
//     for (i, comp) in components.iter().enumerate() {
//         if *comp == "src" {
//             in_src = true;
//             // Try to find crate name from Cargo.toml
//             if i > 0 {
//                 let potential_crate_dir = path.ancestors().nth(components.len() - i).unwrap_or(Path::new(""));
//                 let cargo_path = potential_crate_dir.join("Cargo.toml");
//                 if cargo_path.exists() {
//                     if let Ok(cargo_content) = std::fs::read_to_string(cargo_path) {
//                         for line in cargo_content.lines() {
//                             if line.trim().starts_with("name") {
//                                 if let Some(name) = line.split('=').nth(1) {
//                                     let cleaned = name.trim().trim_matches('"').trim_matches('\'');
//                                     if !cleaned.is_empty() {
//                                         crate_name = cleaned.to_string();
//                                     }
//                                 }
//                                 break;
//                             }
//                         }
//                     }
//                 }
//             }
//         } else if in_src {
//             result.push(*comp);
//         }
//     }
    
//     // Process the file name
//     if let Some(last) = result.last_mut() {
//         if *last == "mod.rs" {
//             result.pop();
//         } else if last.ends_with(".rs") {
//             *last = &last[0..last.len() - 3];
//         }
//     }
    
//     // Build the module path
//     let mut path_parts = vec![crate_name];
//     path_parts.extend(result.into_iter().map(|s| s.to_string()));
//     path_parts.join("::")
// }

// /// Find the fully-qualified name of the enclosing function
// fn find_enclosing_fn(node: &Node, mod_path: &str, source: &str) -> Option<String> {
//     let mut current = *node;
//     while !current.is_null() && !current.is_root() {
//         if current.kind() == "function_item" {
//             if let Some(name_node) = current.child_by_field_name("name") {
//                 if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
//                     return Some(format!("{}::{}", mod_path, name));
//                 }
//             }
//         }
//         current = match current.parent() {
//             Some(parent) => parent,
//             None => break,
//         };
//     }
//     None
// }