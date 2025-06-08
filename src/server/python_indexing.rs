use std::cell::RefCell;
use petgraph::visit::EdgeRef;
use rayon::prelude::*;
use tree_sitter::{Parser, Language, Node};
use petgraph::{Graph, Directed, graph::NodeIndex};
use serde_json::json;
use tree_sitter_python as python_lang;


use std::{path::PathBuf, collections::HashMap, sync::Arc, net::SocketAddr};
use dashmap::DashMap;
use crossbeam_queue::SegQueue;
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

// Use tree-sitter-python for parsing Python code instead of Rust

/// Represents a parsed function, method, or class
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CodeEntity {
    /// Name of the function, method, or class
    pub name: String,
    /// Fully qualified name (e.g. "package.module.MyClass.method")
    pub fq_name: String,
    /// Module where the entity is defined
    pub module: String,
    /// Path to the source file
    pub file: String,
    /// Type of entity: "function", "method", or "class"
    pub entity_type: String,
    /// Start byte position in the file
    pub start: usize,
    /// End byte position in the file
    pub end: usize,
}

/// Represents an analysis session
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisSession {
    /// Unique identifier for the session
    pub id: String,
    /// Number of entities found (functions, methods, classes)
    pub entity_count: i32,
    /// Number of call/usage relationships found
    pub relation_count: i32,
    /// Description or name of the analysis
    pub description: String,
}

/// Global in-memory state for code indexing
#[derive(Clone)]
pub struct AppState {
    // Use Arc to share between handlers
    pub indexer: Arc<Indexer>,
    // Database connection pool
    pub db_pool: SqlitePool,
}

pub struct Indexer {
    /// Map of fully-qualified name to CodeEntity
    pub entities: DashMap<String, CodeEntity>,
    /// Relation edges: (source, target, type)
    pub edges: SegQueue<(String, String, String)>,
}

impl Indexer {
    pub fn new() -> Self {
        Self {
            entities: DashMap::new(),
            edges: SegQueue::new(),
        }
    }
}






// Create necessary database tables
pub async fn create_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Create sessions table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            entity_count INTEGER NOT NULL,
            relation_count INTEGER NOT NULL,
            description TEXT NOT NULL
        )"
    )
    .execute(pool)
    .await?;
    
    // Create entities table (for functions, methods, and classes)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS entities (
            session_id TEXT NOT NULL,
            fq_name TEXT NOT NULL,
            name TEXT NOT NULL,
            module TEXT NOT NULL,
            file TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            start_byte INTEGER NOT NULL,
            end_byte INTEGER NOT NULL,
            PRIMARY KEY (session_id, fq_name),
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )"
    )
    .execute(pool)
    .await?;
    
    // Create relations table (for calls, instantiations, etc.)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS relations (
            session_id TEXT NOT NULL,
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            relation_type TEXT NOT NULL,
            PRIMARY KEY (session_id, source, target, relation_type),
            FOREIGN KEY (session_id) REFERENCES sessions(id),
            FOREIGN KEY (session_id, source) REFERENCES entities(session_id, fq_name),
            FOREIGN KEY (session_id, target) REFERENCES entities(session_id, fq_name)
        )"
    )
    .execute(pool)
    .await?;
    
    Ok(())
}

// List all saved analyses
pub async fn list_analyses(
    State(state): State<AppState>
) -> Result<Json<Vec<AnalysisSession>>, StatusCode> {
    let sessions = sqlx::query("SELECT id, entity_count, relation_count, description FROM sessions ORDER BY id DESC")
        .map(|row: sqlx::sqlite::SqliteRow| {
            AnalysisSession {
                id: row.get("id"),
                entity_count: row.get("entity_count"),
                relation_count: row.get("relation_count"),
                description: row.get("description")
            }
        })
        .fetch_all(&state.db_pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
    Ok(Json(sessions))
}

// Get a specific analysis by ID
pub async fn get_analysis(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Get session info
    let session = match sqlx::query("SELECT id, entity_count, relation_count, description FROM sessions WHERE id = ?")
        .bind(&id)
        .map(|row: sqlx::sqlite::SqliteRow| {
            AnalysisSession {
                id: row.get("id"),
                entity_count: row.get("entity_count"),
                relation_count: row.get("relation_count"),
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

    // Get all entities for this session
    let entities: Vec<CodeEntity> = match sqlx::query(
        "SELECT fq_name, name, module, file, entity_type, start_byte, end_byte 
         FROM entities 
         WHERE session_id = ?"
    )
    .bind(&id)
    .map(|row: sqlx::sqlite::SqliteRow| {
        CodeEntity {
            fq_name: row.get("fq_name"),
            name: row.get("name"),
            module: row.get("module"),
            file: row.get("file"),
            entity_type: row.get("entity_type"),
            start: row.get::<i64, _>("start_byte") as usize,
            end: row.get::<i64, _>("end_byte") as usize,
        }
    })
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(entities) => entities,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    
    // Get all relationships for this session
    let relations: Vec<(String, String, String)> = match sqlx::query(
        "SELECT source, target, relation_type FROM relations WHERE session_id = ?"
    )
    .bind(&id)
    .map(|row: sqlx::sqlite::SqliteRow| {
        (row.get("source"), row.get("target"), row.get("relation_type"))
    })
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(relations) => relations,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    
    // Build a graph from the retrieved data
    let mut graph = Graph::<CodeEntity, String, Directed>::new();
    let mut node_indices = HashMap::new();
    
    // Add all entities as nodes
    for entity in &entities {
        let node_idx = graph.add_node(entity.clone());
        node_indices.insert(entity.fq_name.clone(), node_idx);
    }
    
    // Add all edges
    for (source, target, relation_type) in &relations {
        if let (Some(&source_idx), Some(&target_idx)) = (
            node_indices.get(source), 
            node_indices.get(target)
        ) {
            graph.add_edge(source_idx, target_idx, relation_type.clone());
        }
    }
    
    // Format the response
    let graph_json = serialize_graph_to_json(&graph, &node_indices);
    let response = json!({
        "session": session,
        "stats": {
            "entities": entities.len(),
            "relations": relations.len()
        },
        "graph": graph_json
    });
    
    Json(response).into_response()
}

// Define a response type for entity search results
#[derive(Serialize)]
struct EntitySearchResult {
    entity: CodeEntity,
    callers: Vec<CodeEntity>,
    callees: Vec<CodeEntity>,
}

// Search for specific entities
pub async fn search_entities(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Get the search query parameter
    let query = match params.get("q") {
        Some(q) if !q.is_empty() => q.to_lowercase(),
        _ => String::new(), // Empty string will match all entities
    };

    // Get all entities for this session
    let entities: Vec<CodeEntity> = match sqlx::query(
        "SELECT fq_name, name, module, file, entity_type, start_byte, end_byte 
         FROM entities 
         WHERE session_id = ?"
    )
    .bind(&id)
    .map(|row: sqlx::sqlite::SqliteRow| {
        CodeEntity {
            fq_name: row.get("fq_name"),
            name: row.get("name"),
            module: row.get("module"),
            file: row.get("file"),
            entity_type: row.get("entity_type"),
            start: row.get::<i64, _>("start_byte") as usize,
            end: row.get::<i64, _>("end_byte") as usize,
        }
    })
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(entities) => entities,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    
    // Filter entities that match the search query
    let matching_entities: Vec<&CodeEntity> = entities.iter()
        .filter(|e| {
            query.is_empty() || 
            e.name.to_lowercase().contains(&query) || 
            e.fq_name.to_lowercase().contains(&query) ||
            e.module.to_lowercase().contains(&query) ||
            e.entity_type.to_lowercase().contains(&query)
        })
        .collect();
    
    if matching_entities.is_empty() {
        return (StatusCode::NOT_FOUND, "No matching entities found").into_response();
    }
    
    // Get all relationships for this session
    let relations: Vec<(String, String, String)> = match sqlx::query(
        "SELECT source, target, relation_type FROM relations WHERE session_id = ?"
    )
    .bind(&id)
    .map(|row: sqlx::sqlite::SqliteRow| {
        (row.get("source"), row.get("target"), row.get("relation_type"))
    })
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(relations) => relations,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    
    // Create a map from fq_name to CodeEntity for quick lookups
    let entity_map: HashMap<&String, &CodeEntity> = entities.iter()
        .map(|e| (&e.fq_name, e))
        .collect();
    
    // Build results for each matching entity
    let mut results = Vec::new();
    
    for entity in matching_entities {
        // Find all callers of this entity
        let callers: Vec<CodeEntity> = relations.iter()
            .filter(|(_, target, _)| target == &entity.fq_name)
            .filter_map(|(source, _, _)| entity_map.get(source).map(|&e| e.clone()))
            .collect();
        
        // Find all entities this entity calls/uses
        let callees: Vec<CodeEntity> = relations.iter()
            .filter(|(source, _, _)| source == &entity.fq_name)
            .filter_map(|(_, target, _)| entity_map.get(target).map(|&e| e.clone()))
            .collect();
        
        results.push(EntitySearchResult {
            entity: entity.clone(),
            callers,
            callees,
        });
    }
    
    Json(results).into_response()
}

// Handle uploaded files and build call graph
pub async fn handle_upload(
    State(state): State<AppState>, 
    mut multipart: Multipart
) -> impl IntoResponse {
    let mut in_memory_files: HashMap<String, String> = HashMap::new();
    let mut description = "Unnamed Python Analysis".to_string();
    
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
        
        if !filename.ends_with(".py") {
            continue; // Skip non-Python files
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
pub async fn process_and_store_analysis(
    files: HashMap<String, String>,
    indexer: Arc<Indexer>,
    db_pool: &SqlitePool,
    description: String,
) -> Result<String, Box<dyn std::error::Error>> {
    // Reset the indexer for this new analysis
    indexer.entities.clear();
    while let Some(_) = indexer.edges.pop() {}
    
    // Use thread_local for the parser since Tree-sitter isn't thread-safe
    thread_local! {
        static PARSER: RefCell<Parser> = RefCell::new({
            let mut parser = tree_sitter::Parser::new();
            unsafe { parser.set_language(python_lang::language()).expect("Error loading Python grammar");
        };
            parser
        });
    }

    // Convert the files HashMap to a vector for parallel processing
    let files_vec: Vec<(String, String)> = files.into_iter().collect();
    
    // Phase 1: Extract function, method, and class definitions from all files
    files_vec.par_iter().for_each(|(path, source)| {
        PARSER.with(|parser| {
            let tree = match parser.borrow_mut().parse(source, None) {
                Some(tree) => tree,
                None => return,
            };
            
            let root = tree.root_node();
            let module_path = get_python_module_path(path);
            
            extract_python_definitions(&root, source, &module_path, path, &indexer);
        });
    });

    // Phase 2: Extract function calls, method calls, and class instantiations
    files_vec.par_iter().for_each(|(path, source)| {
        PARSER.with(|parser| {
            let tree = match parser.borrow_mut().parse(source, None) {
                Some(tree) => tree,
                None => return,
            };
            
            let root = tree.root_node();
            let module_path = get_python_module_path(path);
            
            extract_python_relationships(&root, source, &module_path, &indexer);
        });
    });

    // Build the call graph from collected data
    let mut graph = Graph::<CodeEntity, String, Directed>::new();
    let mut node_indices = HashMap::new();
    
    // Add all entities as nodes
    for entry in indexer.entities.iter() {
        let entity = entry.value().clone();
        let node_idx = graph.add_node(entity.clone());
        node_indices.insert(entity.fq_name.clone(), node_idx);
    }
    
    // Collect all edges
    let mut edges = Vec::new();
    while let Some(edge) = indexer.edges.pop() {
        edges.push(edge.clone());
        
        if let (Some(&source_idx), Some(&target_idx)) = (
            node_indices.get(&edge.0), 
            node_indices.get(&edge.1)
        ) {
            graph.add_edge(source_idx, target_idx, edge.2.clone());
        }
    }
    
    // Generate a unique ID for this analysis session
    let session_id = Uuid::new_v4().to_string();
    let entity_count = graph.node_count() as i32;
    let relation_count = graph.edge_count() as i32;
    
    // Store the session in database
    let mut tx = db_pool.begin().await?;
    
    // Insert session record
    sqlx::query(
        "INSERT INTO sessions (id, entity_count, relation_count, description) 
     VALUES (?, ?, ?, ?)"
    )
    .bind(&session_id)
    .bind(entity_count)
    .bind(relation_count)
    .bind(&description)
    .execute(&mut tx)
    .await?;
    
    // Insert all entities
    for node_idx in graph.node_indices() {
        let entity = &graph[node_idx];
        
        sqlx::query(
            "INSERT INTO entities (session_id, fq_name, name, module, file, entity_type, start_byte, end_byte)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&session_id)
        .bind(&entity.fq_name)
        .bind(&entity.name)
        .bind(&entity.module)
        .bind(&entity.file)
        .bind(&entity.entity_type)
        .bind(entity.start as i64)
        .bind(entity.end as i64)
        .execute(&mut tx)
        .await?;
    }
    
    // Insert all relationships
    for (source, target, relation_type) in edges {
        sqlx::query(
            "INSERT INTO relations (session_id, source, target, relation_type)
             VALUES (?, ?, ?, ?)"
        )
        .bind(&session_id)
        .bind(&source)
        .bind(&target)
        .bind(&relation_type)
        .execute(&mut tx)
        .await?;
    }
    
    // Commit the transaction
    tx.commit().await?;
    
    Ok(session_id)
}

// Convert a filename to a Python module path
pub fn get_python_module_path(filename: &str) -> String {
    // Strip .py extension
    let without_ext = filename.trim_end_matches(".py");
    
    // Convert any path separators to Python module separators
    let mod_path = without_ext.replace('/', ".").replace('\\', ".");
    
    // For __init__.py, use the parent directory name
    if mod_path.ends_with("__init__") {
        let parts: Vec<&str> = mod_path.split('.').collect();
        if parts.len() > 1 {
            parts[..parts.len() - 1].join(".")
        } else {
            mod_path.clone()
        }
    } else {
        mod_path
    }
}


fn extract_python_definitions(
    root: &Node,
    source: &str,
    module_path: &str,
    file_path: &str,
    indexer: &Indexer,
) {
    fn recursive_extract(
        node: &Node,
        source: &str,
        module_path: &str,
        file_path: &str,
        class_context: Option<&str>,
        indexer: &Indexer,
    ) {
        match node.kind() {
            "function_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                        let (fq_name, entity_type) = if let Some(class_name) = class_context {
                            // It's a method inside a class
                            (format!("{}.{}.{}", module_path, class_name, name), "method")
                        } else {
                            // It's a standalone function
                            (format!("{}.{}", module_path, name), "function")
                        };
                        
                        indexer.entities.insert(fq_name.clone(), CodeEntity {
                            name: name.to_string(),
                            fq_name: fq_name.clone(),
                            module: module_path.to_string(),
                            file: file_path.to_string(),
                            entity_type: entity_type.to_string(),
                            start: node.start_byte(),
                            end: node.end_byte(),
                        });
                        
                        println!("Found {}: {}", entity_type, fq_name);
                    }
                }
            },
            "class_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(class_name) = name_node.utf8_text(source.as_bytes()) {
                        let fq_name = format!("{}.{}", module_path, class_name);
                        
                        indexer.entities.insert(fq_name.clone(), CodeEntity {
                            name: class_name.to_string(),
                            fq_name: fq_name.clone(),
                            module: module_path.to_string(),
                            file: file_path.to_string(),
                            entity_type: "class".to_string(),
                            start: node.start_byte(),
                            end: node.end_byte(),
                        });
                        
                        println!("Found class: {}", fq_name);
                        
                        // Process class body (methods)
                        if let Some(body_node) = node.child_by_field_name("body") {
                            let mut cursor = body_node.walk();
                            for child in body_node.children(&mut cursor) {
                                recursive_extract(&child, source, module_path, file_path, Some(class_name), indexer);
                            }
                        }
                        
                        return; // Don't process class body again in the loop below
                    }
                }
            },
            _ => {}
        }
        
        // Recursively process children (except for class body, which is handled above)
        if node.kind() != "class_definition" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                recursive_extract(&child, source, module_path, file_path, class_context, indexer);
            }
        }
    }
    
    recursive_extract(root, source, module_path, file_path, None, indexer);
}


// Create a JSON representation of the graph for frontend visualization
pub fn serialize_graph_to_json(
    graph: &Graph<CodeEntity, String, Directed>,
    node_indices: &HashMap<String, NodeIndex>
) -> serde_json::Value {
    let mut nodes = Vec::new();
    let mut links = Vec::new();
    
    // Add nodes
    for (fq_name, &idx) in node_indices {
        let entity = &graph[idx];
        nodes.push(json!({
            "id": fq_name,
            "name": entity.name,
            "module": entity.module,
            "file": entity.file,
            "type": entity.entity_type
        }));
    }
    
    // Add edges
    for edge in graph.edge_references() {
        let source = &graph[edge.source()];
        let target = &graph[edge.target()];
        let relation_type = edge.weight();
        
        links.push(json!({
            "source": source.fq_name,
            "target": target.fq_name,
            "type": relation_type
        }));
    }
    
    json!({
        "nodes": nodes,
        "links": links
    })
}


/// Extracts function calls, method calls, and class instantiations from the Python AST
pub fn extract_python_relationships(
    root: &Node,
    source: &str,
    module_path: &str,
    indexer: &Indexer,
) {
    // Import statements to resolve names
    let imports = collect_python_imports(root, source, module_path);
    
    // Find current enclosing entity (function, method, or class)
    fn find_enclosing_entity(
        node: &Node,
        source: &str,
        module_path: &str,
        class_context: Option<&str>,
    ) -> Option<String> {
        let mut current_opt = Some(*node);
        
        while let Some(current) = current_opt {
            match current.kind() {
                "function_definition" => {
                    if let Some(name_node) = current.child_by_field_name("name") {
                        if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                            return if let Some(class_name) = class_context {
                                Some(format!("{}.{}.{}", module_path, class_name, name))
                            } else {
                                Some(format!("{}.{}", module_path, name))
                            }
                        }
                    }
                },
                "class_definition" => {
                    if let Some(name_node) = current.child_by_field_name("name") {
                        if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                            return Some(format!("{}.{}", module_path, name));
                        }
                    }
                },
                _ => {}
            }
            
            current_opt = current.parent();
        }
        
        None
    }
    
    // Recursively process the AST
    fn analyze_relationships(
        node: &Node,
        source: &str,
        module_path: &str,
        imports: &HashMap<String, String>,
        indexer: &Indexer,
        class_context: Option<&str>,
    ) {
        // Process calls and instantiations
        match node.kind() {
            "call" => {
                if let Some(func_node) = node.child_by_field_name("function") {
                    // Handle function/method calls
                    match func_node.kind() {
                        "identifier" => {
                            // Direct function call: function_name()
                            if let Ok(func_name) = func_node.utf8_text(source.as_bytes()) {
                                // Resolve the function name
                                let resolved_name = if let Some(imported) = imports.get(func_name) {
                                    imported.clone()
                                } else {
                                    format!("{}.{}", module_path, func_name)
                                };
                                
                                // Find the enclosing entity that contains this call
                                if let Some(caller) = &find_enclosing_entity(node, source, module_path, class_context) {
                                    // Only record if both caller and callee exist
                                    if indexer.entities.contains_key(&resolved_name) && indexer.entities.contains_key(caller) {
                                        indexer.edges.push((caller.to_string(), resolved_name.clone(), "calls".to_string()));
                                        println!("Relationship: {} calls {}", caller, &resolved_name);
                                    }
                                }
                            }
                        },
                        "attribute" => {
                            // Method call: object.method()
                            if let Ok(attr_text) = func_node.utf8_text(source.as_bytes()) {
                                let parts: Vec<&str> = attr_text.split('.').collect();
                                if parts.len() >= 2 {
                                    let object_name = parts[0];
                                    let method_name = parts[parts.len() - 1];
                                    
                                    // Try to resolve the object type
                                    let resolved_type = if let Some(imported) = imports.get(object_name) {
                                        imported.clone()
                                    } else {
                                        format!("{}.{}", module_path, object_name)
                                    };
                                    
                                    // Construct method's fully qualified name
                                    let method_fq = format!("{}.{}", resolved_type, method_name);
                                    
                                    // Find the enclosing entity that contains this call
                                    if let Some(caller) = find_enclosing_entity(node, source, module_path, class_context) {
                                        // Check if method exists in our index
                                        if indexer.entities.contains_key(&method_fq) && indexer.entities.contains_key(&caller) {
                                            indexer.edges.push((caller.clone(), method_fq.clone(), "calls".to_string()));
                                            println!("Relationship: {} calls {}", &caller, &method_fq);
                                        } else if indexer.entities.contains_key(&resolved_type) && indexer.entities.contains_key(&caller) {
                                            // If method not found, at least record usage of the class/module
                                            indexer.edges.push((caller.clone(), resolved_type.clone(), "uses".to_string()));
                                            println!("Relationship: {} uses {}", caller, resolved_type);
                                        }
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                }
            },
            "class_definition" => {
                // Capture class inheritance relationships
                if let Some(bases_node) = node.child_by_field_name("base_class_names") {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        if let Ok(class_name) = name_node.utf8_text(source.as_bytes()) {
                            let class_fq = format!("{}.{}", module_path, class_name);
                            
                            // Process each base class
                            let mut cursor = bases_node.walk();
                            for base_node in bases_node.children(&mut cursor) {
                                if let Ok(base_name) = base_node.utf8_text(source.as_bytes()) {
                                    // Resolve base class name
                                    let resolved_base = if let Some(imported) = imports.get(base_name) {
                                        imported.clone()
                                    } else {
                                        format!("{}.{}", module_path, base_name)
                                    };
                                    
                                    if indexer.entities.contains_key(&class_fq) && indexer.entities.contains_key(&resolved_base) {
                                        indexer.edges.push((class_fq.clone(), resolved_base.clone(), "inherits".to_string()));
                                        println!("Relationship: {} inherits {}", class_fq, resolved_base);
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Process class body separately to maintain class context for methods
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(class_name) = name_node.utf8_text(source.as_bytes()) {
                        if let Some(body_node) = node.child_by_field_name("body") {
                            let mut cursor = body_node.walk();
                            for child in body_node.children(&mut cursor) {
                                analyze_relationships(&child, source, module_path, imports, indexer, Some(class_name));
                            }
                        }
                        
                        return; // Skip processing class body again in the recursive call below
                    }
                }
            },
            // Handle instantiation: var = ClassName()
            "assignment" => {
                if let Some(right) = node.child_by_field_name("right") {
                    if right.kind() == "call" {
                        if let Some(func_node) = right.child_by_field_name("function") {
                            if func_node.kind() == "identifier" {
                                if let Ok(class_name) = func_node.utf8_text(source.as_bytes()) {
                                    // Resolve class name
                                    let resolved_class = if let Some(imported) = imports.get(class_name) {
                                        imported.clone()
                                    } else {
                                        format!("{}.{}", module_path, class_name)
                                    };
                                    
                                    // Find the enclosing entity that contains this instantiation
                                    if let Some(caller) = find_enclosing_entity(node, source, module_path, class_context) {
                                        if indexer.entities.contains_key(&resolved_class) && indexer.entities.contains_key(&caller) {
                                            indexer.edges.push((caller.clone(), resolved_class.clone(), "instantiates".to_string()));
                                            println!("Relationship: {} instantiates {}", caller, resolved_class);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            _ => {}
        }
        
        // Recursively process all children (except for class body, which is handled separately)
        if node.kind() != "class_definition" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                analyze_relationships(&child, source, module_path, imports, indexer, class_context);
            }
        }
    }
    
    // Start analyzing relationships from the root
    analyze_relationships(root, source, module_path, &imports, indexer, None);
}

/// Collects Python import statements to help resolve names
pub fn collect_python_imports(
    root: &Node,
    source: &str,
    current_module: &str,
) -> HashMap<String, String> {
    let mut imports = HashMap::new();
    
    fn process_imports(
        node: &Node,
        source: &str,
        current_module: &str,
        imports: &mut HashMap<String, String>,
    ) {
        match node.kind() {
            "import_statement" => {
                // Handle simple imports: import module
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "dotted_name" {
                        if let Ok(module_name) = child.utf8_text(source.as_bytes()) {
                            imports.insert(module_name.to_string(), module_name.to_string());
                        }
                    }
                }
            },
            "import_from_statement" => {
                // Handle from ... import ... statements
                if let Some(module_node) = node.child_by_field_name("module_name") {
                    if let Ok(module_name) = module_node.utf8_text(source.as_bytes()) {
                        if let Some(names) = node.child_by_field_name("name") {
                            match names.kind() {
                                "dotted_name" => {
                                    // Single import: from module import name
                                    if let Ok(name) = names.utf8_text(source.as_bytes()) {
                                        imports.insert(name.to_string(), format!("{}.{}", module_name, name));
                                    }
                                },
                                "aliased_import" => {
                                    // Single import with alias: from module import name as alias
                                    if let Some(name_node) = names.child_by_field_name("name") {
                                        if let Some(alias_node) = names.child_by_field_name("alias") {
                                            if let (Ok(name), Ok(alias)) = (
                                                name_node.utf8_text(source.as_bytes()),
                                                alias_node.utf8_text(source.as_bytes()),
                                            ) {
                                                imports.insert(alias.to_string(), format!("{}.{}", module_name, name));
                                            }
                                        }
                                    }
                                },
                                "import_list" => {
                                    // Multiple imports: from module import name1, name2
                                    let mut cursor = names.walk();
                                    for name_node in names.children(&mut cursor) {
                                        if name_node.kind() == "dotted_name" {
                                            if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                                imports.insert(name.to_string(), format!("{}.{}", module_name, name));
                                            }
                                        } else if name_node.kind() == "aliased_import" {
                                            if let Some(orig_name) = name_node.child_by_field_name("name") {
                                                if let Some(alias) = name_node.child_by_field_name("alias") {
                                                    if let (Ok(name), Ok(alias_name)) = (
                                                        orig_name.utf8_text(source.as_bytes()),
                                                        alias.utf8_text(source.as_bytes()),
                                                    ) {
                                                        imports.insert(alias_name.to_string(), format!("{}.{}", module_name, name));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                _ => {}
                            }
                        }
                    }
                }
            },
            _ => {
                // Recursively process children
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    process_imports(&child, source, current_module, imports);
                }
            }
        }
    }
    
    process_imports(root, source, current_module, &mut imports);
    imports
}