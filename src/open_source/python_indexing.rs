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
pub struct CodeEntity {
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


// Define a response type for entity search results
#[derive(Serialize)]
struct EntitySearchResult {
    entity: CodeEntity,
    callers: Vec<CodeEntity>,
    callees: Vec<CodeEntity>,
}


pub fn process_python_files(
    files: &HashMap<String, String>,
    indexer: &Arc<Indexer>,
    verbose: bool,
) {
    let total_files = files.len();
    let mut processed = 0;
    for (path, content) in files {
        process_python_file(path, content, indexer, verbose);
        processed += 1;
        if verbose {
            println!("  [{}] Processed: {}", processed, path);
        }
    }
    if verbose {
        println!("Python processing completed: {}/{} files", processed, total_files);
    }
}


pub fn process_python_file(
    path: &str,
    source: &str,
    indexer: &Arc<Indexer>,
    verbose: bool,
) {
    let mut parser = Parser::new();
    parser.set_language(python_lang::language()).unwrap();
    let tree = match parser.parse(source, None) {
        Some(tree) => tree,
        None => {
            if verbose {
                eprintln!("Failed to parse: {}", path);
            }
            return;
        }
    };
    let root = tree.root_node();
    extract_python_definitions(&root, source, path, path, indexer);

    extract_python_relationships(&root, source, path, indexer);
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