use std::cell::RefCell;
use petgraph::visit::EdgeRef;
use rayon::prelude::*;
use tree_sitter::{Parser, Language, Node};
use petgraph::{Graph, Directed, graph::NodeIndex};
use serde_json::json;
use tree_sitter_typescript::{language_typescript, language_tsx};

use std::{collections::HashMap, sync::Arc, fs};
use dashmap::DashMap;
use crossbeam_queue::SegQueue;
use serde::{Serialize, Deserialize};
use walkdir::WalkDir;

/// Represents a parsed function, method, or class in TypeScript/TSX
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeEntity {
    /// Name of the function, method, or class
    pub name: String,
    /// Fully qualified name (e.g. "src/module.ts:MyClass.method")
    pub fq_name: String,
    /// Module or file where the entity is defined
    pub module: String,
    /// Path to the source file
    pub file: String,
    /// Type of entity: "function", "method", "class"
    pub entity_type: String,
    /// Start byte position in the file
    pub start: usize,
    /// End byte position in the file
    pub end: usize,
}

/// Indexer for TypeScript/TSX codebases
pub struct Indexer {
    /// Map of fully-qualified name to CodeEntity
    pub entities: DashMap<String, CodeEntity>,
    /// Relation edges: (source, target, type)
    pub edges: SegQueue<(String, String, String)>,
    /// Map of imported name to fully qualified name (for cross-file resolution)
    pub import_map: DashMap<String, String>,
    /// Map of file path to its exported entities
    pub exports_map: DashMap<String, Vec<String>>,
    /// Set to track processed relationships to avoid duplicates
    pub processed_relationships: DashMap<String, bool>,
}

impl Indexer {
    pub fn new() -> Self {
        Self {
            entities: DashMap::new(),
            edges: SegQueue::new(),
            import_map: DashMap::new(),
            exports_map: DashMap::new(),
            processed_relationships: DashMap::new(),
        }
    }
}

/// Normalize file paths to ensure consistency
fn normalize_path(path: &str) -> String {
    path.replace("\\", "/")
}

/// Collect import/export statements from all files and build a global import map
pub fn collect_imports_exports(
    files: &HashMap<String, String>,
    indexer: &Arc<Indexer>,
) {
    // First pass: collect all exports from each file
    for (file_path, content) in files {
        let normalized_path = normalize_path(file_path);
        let mut parser = Parser::new();
        parser.set_language(language_typescript()).unwrap();
        if let Some(tree) = parser.parse(content, None) {
            let root = tree.root_node();
            collect_exports_from_ast(&root, content, &normalized_path, indexer);
        }
    }
    
    // Second pass: collect imports and map them to the collected exports
    for (file_path, content) in files {
        let normalized_path = normalize_path(file_path);
        let mut parser = Parser::new();
        parser.set_language(language_typescript()).unwrap();
        if let Some(tree) = parser.parse(content, None) {
            let root = tree.root_node();
            collect_imports_from_ast(&root, content, &normalized_path, indexer);
        }
    }
}

/// Helper to collect exports from a single AST
fn collect_exports_from_ast(
    root: &Node,
    source: &str,
    file_path: &str,
    indexer: &Indexer,
) {
    let mut exports = Vec::new();
    let mut cursor = root.walk();
    
    for child in root.children(&mut cursor) {
        match child.kind() {
            "export_statement" => {
                // Handle export statements
                if let Some(export_clause) = child.child_by_field_name("declaration") {
                    match export_clause.kind() {
                        "function_declaration" => {
                            if let Some(name_node) = export_clause.child_by_field_name("name") {
                                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                    let fq_name = format!("{}.{}", file_path, name);
                                    exports.push(name.to_string());
                                    indexer.import_map.insert(name.to_string(), fq_name.clone());
                                }
                            }
                        },
                        "class_declaration" => {
                            if let Some(name_node) = export_clause.child_by_field_name("name") {
                                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                    let fq_name = format!("{}.{}", file_path, name);
                                    exports.push(name.to_string());
                                    indexer.import_map.insert(name.to_string(), fq_name.clone());
                                }
                            }
                        },
                        "variable_declaration" => {
                            let mut var_cursor = export_clause.walk();
                            for var_child in export_clause.children(&mut var_cursor) {
                                if var_child.kind() == "variable_declarator" {
                                    if let Some(name_node) = var_child.child_by_field_name("name") {
                                        if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                            let fq_name = format!("{}.{}", file_path, name);
                                            exports.push(name.to_string());
                                            indexer.import_map.insert(name.to_string(), fq_name.clone());
                                        }
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                }
                
                // Handle named exports like: export { func1, func2 };
                if let Some(source_node) = child.child_by_field_name("source") {
                    // Re-export from another module
                    if let Ok(source_text) = source_node.utf8_text(source.as_bytes()) {
                        let import_path = source_text.trim_matches('"').trim_matches('\'');
                        let resolved_path = resolve_import_path(import_path, file_path);
                        
                        if let Some(named_exports) = child.child_by_field_name("named_exports") {
                            let mut export_cursor = named_exports.walk();
                            for export_item in named_exports.children(&mut export_cursor) {
                                if export_item.kind() == "export_specifier" {
                                    if let Some(name_node) = export_item.child_by_field_name("name") {
                                        if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                            // This is a re-export, map to the original
                                            let original_fq = format!("{}.{}", resolved_path, name);
                                            exports.push(name.to_string());
                                            indexer.import_map.insert(name.to_string(), original_fq.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if let Some(named_exports) = child.child_by_field_name("named_exports") {
                    // Regular named exports
                    let mut export_cursor = named_exports.walk();
                    for export_item in named_exports.children(&mut export_cursor) {
                        if export_item.kind() == "export_specifier" {
                            if let Some(name_node) = export_item.child_by_field_name("name") {
                                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                    let fq_name = format!("{}.{}", file_path, name);
                                    exports.push(name.to_string());
                                    indexer.import_map.insert(name.to_string(), fq_name.clone());
                                }
                            }
                        }
                    }
                }
            },
            "export_declaration" => {
                // Handle export declarations (export function, export class, etc.)
                if let Some(declaration) = child.child_by_field_name("declaration") {
                    match declaration.kind() {
                        "function_declaration" => {
                            if let Some(name_node) = declaration.child_by_field_name("name") {
                                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                    let fq_name = format!("{}.{}", file_path, name);
                                    exports.push(name.to_string());
                                    indexer.import_map.insert(name.to_string(), fq_name.clone());
                                }
                            }
                        },
                        "class_declaration" => {
                            if let Some(name_node) = declaration.child_by_field_name("name") {
                                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                    let fq_name = format!("{}.{}", file_path, name);
                                    exports.push(name.to_string());
                                    indexer.import_map.insert(name.to_string(), fq_name.clone());
                                }
                            }
                        },
                        _ => {}
                    }
                }
            },
            _ => {}
        }
    }
    
    if !exports.is_empty() {
        indexer.exports_map.insert(file_path.to_string(), exports);
    }
}

/// Helper to collect imports from a single AST
fn collect_imports_from_ast(
    root: &Node,
    source: &str,
    file_path: &str,
    indexer: &Indexer,
) {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "import_statement" {
            // Get the import source (module path)
            let mut import_source: Option<String> = None;
            if let Some(source_node) = child.child_by_field_name("source") {
                if let Ok(source_text) = source_node.utf8_text(source.as_bytes()) {
                    import_source = Some(source_text.trim_matches('"').trim_matches('\'').to_string());
                }
            }
            
            if let Some(import_path) = import_source {
                let resolved_path = resolve_import_path(&import_path, file_path);
                
                // Handle default imports
                if let Some(name_node) = child.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                        // For default imports, we need to handle them specially
                        // For now, assume default export has same name as import
                        let target_fq = format!("{}.{}", resolved_path, name);
                        indexer.import_map.insert(format!("{}:{}", file_path, name), target_fq.clone());
                    }
                }
                
                // Handle named imports - check import_clause for the structure
                if let Some(import_clause) = child.child_by_field_name("import_clause") {
                    process_import_clause(&import_clause, source, file_path, &resolved_path, indexer);
                }
            }
        }
    }
}

/// Process import clause to extract named imports
fn process_import_clause(
    import_clause: &Node,
    source: &str,
    file_path: &str,
    resolved_path: &str,
    indexer: &Indexer,
) {
    let mut cursor = import_clause.walk();
    for child in import_clause.children(&mut cursor) {
        match child.kind() {
            "named_imports" => {
                let mut named_cursor = child.walk();
                for named_child in child.children(&mut named_cursor) {
                    if named_child.kind() == "import_specifier" {
                        if let Some(name_node) = named_child.child_by_field_name("name") {
                            if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                // Create a mapping from the local name to the fully qualified name
                                let target_fq = format!("{}.{}", resolved_path, name);
                                let local_key = format!("{}:{}", file_path, name);
                                
                                // Check if the target exists in our exports
                                if indexer.import_map.contains_key(name) {
                                    if let Some(actual_fq) = indexer.import_map.get(name) {
                                        indexer.import_map.insert(local_key.clone(), actual_fq.value().clone());
                                    }
                                } else {
                                    // Fallback to constructed path
                                    indexer.import_map.insert(local_key.clone(), target_fq.clone());
                                }
                            }
                        }
                    }
                }
            },
            "namespace_import" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    if let Ok(namespace) = name_node.utf8_text(source.as_bytes()) {
                        // Handle namespace imports like: import * as utils from './utils'
                        let namespace_key = format!("{}:{}", file_path, namespace);
                        indexer.import_map.insert(namespace_key.clone(), format!("{}:*", resolved_path));
                    }
                }
            },
            _ => {}
        }
    }
}

/// Helper to resolve relative import paths to absolute file paths
fn resolve_import_path(import_path: &str, current_file: &str) -> String {
    let normalized_current = normalize_path(current_file);
    
    if import_path.starts_with("./") || import_path.starts_with("../") {
        let current_dir = std::path::Path::new(&normalized_current)
            .parent()
            .unwrap_or_else(|| std::path::Path::new(""));
        let resolved = current_dir.join(import_path);
        
        // Normalize and add .ts extension if needed
        let resolved_str = normalize_path(&resolved.to_string_lossy());
        if resolved_str.ends_with(".ts") || resolved_str.ends_with(".tsx") {
            resolved_str
        } else {
            format!("{}.ts", resolved_str)
        }
    } else {
        // Absolute path or module name
        if import_path.ends_with(".ts") || import_path.ends_with(".tsx") {
            normalize_path(import_path)
        } else {
            format!("{}.ts", import_path)
        }
    }
}

/// Process a set of TypeScript/TSX files and populate the indexer
pub fn process_typescript_files(
    files: &HashMap<String, String>,
    indexer: &Arc<Indexer>,
    verbose: bool,
    use_tsx: bool,
) {
    let total_files = files.len();
    let mut processed = 0;
    
    // First pass: collect all definitions
    for (path, content) in files {
        let normalized_path = normalize_path(path);
        process_typescript_file(&normalized_path, content, indexer, verbose, use_tsx);
        processed += 1;
        if verbose {
            println!("  [{}] Processed definitions: {}", processed, normalized_path);
        }
    }
    
    // Second pass: collect imports/exports for cross-file resolution
    collect_imports_exports(files, indexer);
    
    // Third pass: extract relationships (both local and cross-file)
    for (path, content) in files {
        let normalized_path = normalize_path(path);
        let mut parser = Parser::new();
        if use_tsx {
            parser.set_language(language_tsx()).unwrap();
        } else {
            parser.set_language(language_typescript()).unwrap();
        }
        if let Some(tree) = parser.parse(content, None) {
            let root = tree.root_node();
            extract_all_relationships(&root, content, &normalized_path, indexer);
        }
        if verbose {
            println!("  [{}] Processed relationships: {}", processed, normalized_path);
        }
    }
    
    if verbose {
        println!("TypeScript processing completed: {}/{} files", processed, total_files);
        println!("Total entities: {}", indexer.entities.len());
        println!("Total relationships: {}", indexer.edges.len());
    }
}

/// Process a single TypeScript or TSX file
pub fn process_typescript_file(
    path: &str,
    source: &str,
    indexer: &Arc<Indexer>,
    verbose: bool,
    use_tsx: bool,
) {
    let mut parser = Parser::new();
    if use_tsx {
        parser.set_language(language_tsx()).unwrap();
    } else {
        parser.set_language(language_typescript()).unwrap();
    }
    
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
    extract_typescript_definitions(&root, source, path, path, indexer);
}

/// Extracts function, method, and class definitions from the TypeScript AST
fn extract_typescript_definitions(
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
            "function_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                        let (fq_name, entity_type) = if let Some(class_name) = class_context {
                            (format!("{}.{}.{}", module_path, class_name, name), "method")
                        } else {
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
                    }
                }
            },
            "method_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                        if let Some(class_name) = class_context {
                            let fq_name = format!("{}.{}.{}", module_path, class_name, name);
                            indexer.entities.insert(fq_name.clone(), CodeEntity {
                                name: name.to_string(),
                                fq_name: fq_name.clone(),
                                module: module_path.to_string(),
                                file: file_path.to_string(),
                                entity_type: "method".to_string(),
                                start: node.start_byte(),
                                end: node.end_byte(),
                            });
                        }
                    }
                }
            },
            "class_declaration" => {
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
                        
                                                   // Process class body (methods and properties)
                           if let Some(body_node) = node.child_by_field_name("body") {
                               let mut cursor = body_node.walk();
                               for child in body_node.children(&mut cursor) {
                                   // Extract class properties
                                   if child.kind() == "public_field_definition" || child.kind() == "property_declaration" {
                                       if let Some(name_node) = child.child_by_field_name("name") {
                                           if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                               let prop_fq_name = format!("{}.{}.{}", module_path, class_name, name);
                                               indexer.entities.insert(prop_fq_name.clone(), CodeEntity {
                                                   name: name.to_string(),
                                                   fq_name: prop_fq_name.clone(),
                                                   module: module_path.to_string(),
                                                   file: file_path.to_string(),
                                                   entity_type: "property".to_string(),
                                                   start: child.start_byte(),
                                                   end: child.end_byte(),
                                               });
                                           }
                                       }
                                   }
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
        if node.kind() != "class_declaration" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                recursive_extract(&child, source, module_path, file_path, class_context, indexer);
            }
        }
    }
    
    recursive_extract(root, source, module_path, file_path, None, indexer);
}

/// Extract both local and cross-file relationships
fn extract_all_relationships(
    root: &Node,
    source: &str,
    module_path: &str,
    indexer: &Indexer,
) {
    // Helper to find the enclosing function or class for a node
    fn find_enclosing_entity(
        node: &Node,
        source: &str,
        module_path: &str,
    ) -> Option<String> {
        let mut current_opt = node.parent();
        while let Some(current) = current_opt {
            match current.kind() {
                "function_declaration" => {
                    if let Some(name_node) = current.child_by_field_name("name") {
                        if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                            return Some(format!("{}.{}", module_path, name));
                        }
                    }
                },
                "method_definition" => {
                    if let Some(name_node) = current.child_by_field_name("name") {
                        if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                            // Find the enclosing class
                            let mut class_opt = current.parent();
                            while let Some(class_node) = class_opt {
                                if class_node.kind() == "class_declaration" {
                                    if let Some(class_name_node) = class_node.child_by_field_name("name") {
                                        if let Ok(class_name) = class_name_node.utf8_text(source.as_bytes()) {
                                            return Some(format!("{}.{}.{}", module_path, class_name, name));
                                        }
                                    }
                                }
                                class_opt = class_node.parent();
                            }
                        }
                    }
                },
                "class_declaration" => {
                    if let Some(name_node) = current.child_by_field_name("name") {
                        if let Ok(class_name) = name_node.utf8_text(source.as_bytes()) {
                            return Some(format!("{}.{}", module_path, class_name));
                        }
                    }
                },
                "arrow_function" => {
                    // For arrow functions, we need to find the enclosing context
                    // This could be a variable declaration, method, etc.
                    let mut parent_opt = current.parent();
                    while let Some(parent) = parent_opt {
                        match parent.kind() {
                            "variable_declarator" => {
                                if let Some(name_node) = parent.child_by_field_name("name") {
                                    if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                        return Some(format!("{}.{}", module_path, name));
                                    }
                                }
                            },
                            "method_definition" => {
                                if let Some(name_node) = parent.child_by_field_name("name") {
                                    if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                                        // Find the enclosing class
                                        let mut class_opt = parent.parent();
                                        while let Some(class_node) = class_opt {
                                            if class_node.kind() == "class_declaration" {
                                                if let Some(class_name_node) = class_node.child_by_field_name("name") {
                                                    if let Ok(class_name) = class_name_node.utf8_text(source.as_bytes()) {
                                                        return Some(format!("{}.{}.{}", module_path, class_name, name));
                                                    }
                                                }
                                            }
                                            class_opt = class_node.parent();
                                        }
                                    }
                                }
                            },
                            _ => {}
                        }
                        parent_opt = parent.parent();
                    }
                },
                _ => {}
            }
            current_opt = current.parent();
        }
        None
    }

    // Helper to resolve an entity name to its fully qualified name
    fn resolve_entity_name(
        entity_name: &str,
        current_file: &str,
        indexer: &Indexer,
    ) -> Option<String> {
        // Handle this-based references (e.g., "this.s3Service", "this.s3Service.getAudioUrl")
        if entity_name.starts_with("this.") {
            let parts: Vec<&str> = entity_name.split('.').collect();
            if parts.len() >= 2 {
                let prop_name = parts[1]; // e.g., "s3Service"
                let method_name = if parts.len() > 2 { parts[2] } else { "" }; // e.g., "getAudioUrl"

                // Find the enclosing class in the current file
                for entity in indexer.entities.iter() {
                    if entity.value().file == current_file && entity.value().entity_type == "class" {
                        let class_name = &entity.value().name;
                        let class_fq = format!("{}.{}", current_file, class_name);

                        // Try to resolve as a property or method
                        let target_fq = if !method_name.is_empty() {
                            format!("{}.{}.{}", current_file, class_name, method_name)
                        } else {
                            format!("{}.{}.{}", current_file, class_name, prop_name)
                        };

                        if indexer.entities.contains_key(&target_fq) {
                            return Some(target_fq);
                        } else if !method_name.is_empty() {
                            // Try resolving as a service method (e.g., "s3Service.getAudioUrl")
                            let service_method = format!("{}.{}", prop_name, method_name);
                            if let Some(resolved_fq) = indexer.import_map.get(&service_method) {
                                return Some(resolved_fq.value().clone());
                            }
                            
                            // Try resolving the service class and its method
                            if let Some(service_fq) = indexer.import_map.get(prop_name) {
                                let service_method_fq = format!("{}.{}", service_fq.value(), method_name);
                                if indexer.entities.contains_key(&service_method_fq) {
                                    return Some(service_method_fq);
                                }
                            }
                        }
                    }
                }
            }
        }

        // First, try to find it as a local import in this file
        let local_key = format!("{}:{}", current_file, entity_name);
        if let Some(fq_name) = indexer.import_map.get(&local_key) {
            return Some(fq_name.value().clone());
        }
        
        // Then try global import map (for exported entities)
        if let Some(fq_name) = indexer.import_map.get(entity_name) {
            return Some(fq_name.value().clone());
        }
        
        // Finally, try as local entity in current file
        let local_fq = format!("{}.{}", current_file, entity_name);
        if indexer.entities.contains_key(&local_fq) {
            return Some(local_fq);
        }
        
        None
    }

    // Helper to add relationships with deduplication
    fn add_relationship(
        source: &str,
        target: &str,
        edge_type: &str,
        indexer: &Indexer,
    ) {
        let relationship_key = format!("{}->{}->{}", source, target, edge_type);
        if !indexer.processed_relationships.contains_key(&relationship_key) {
            indexer.processed_relationships.insert(relationship_key.clone(), true);
            indexer.edges.push((source.to_string(), target.to_string(), edge_type.to_string()));
        }
    }

    // Recursively process the AST
    fn analyze_relationships(
        node: &Node,
        source: &str,
        module_path: &str,
        indexer: &Indexer,
    ) {
        match node.kind() {
            "call_expression" => {
                if let Some(func_node) = node.child_by_field_name("function") {
                    if let Ok(func_name) = func_node.utf8_text(source.as_bytes()) {
                        // Handle method calls (e.g., obj.method(), this.service.method())
                        let parts: Vec<&str> = func_name.split('.').collect();
                        let callee_fq = if parts.len() >= 2 {
                            // Handle method chaining like "this.s3Service.getAudioUrl"
                            if parts[0] == "this" {
                                // Use the enhanced resolve_entity_name function for this-based calls
                                resolve_entity_name(func_name, module_path, indexer).unwrap_or_else(|| {
                                    // Fallback: try to resolve as a service method
                                    let service_name = parts[1]; // e.g., "s3Service"
                                    let method_name = parts[parts.len() - 1]; // e.g., "getAudioUrl"
                                    let service_method = format!("{}.{}", service_name, method_name);
                                    
                                    // Try to find the service class and its method
                                    for entity in indexer.entities.iter() {
                                        if entity.value().entity_type == "class" && 
                                           entity.value().name.to_lowercase().contains(&service_name.to_lowercase()) {
                                            let service_method_fq = format!("{}.{}", entity.value().fq_name, method_name);
                                            if indexer.entities.contains_key(&service_method_fq) {
                                                return service_method_fq;
                                            }
                                        }
                                    }
                                    
                                    format!("{}.{}", module_path, service_method)
                                })
                            } else {
                                // Regular method call like "obj.method"
                                let base_name = parts[0];
                                let method_name = parts[parts.len() - 1];
                                
                                if let Some(base_fq) = resolve_entity_name(base_name, module_path, indexer) {
                                    format!("{}.{}", base_fq, method_name)
                                } else {
                                    // Try to resolve the whole method name
                                    resolve_entity_name(func_name, module_path, indexer).unwrap_or_else(|| {
                                        format!("{}.{}", module_path, func_name)
                                    })
                                }
                            }
                        } else {
                            // Simple function call
                            resolve_entity_name(func_name, module_path, indexer).unwrap_or_else(|| {
                                format!("{}.{}", module_path, func_name)
                            })
                        };
                        
                        // Find the caller
                        if let Some(caller) = find_enclosing_entity(node, source, module_path) {
                            let caller_exists = indexer.entities.contains_key(&caller);
                            let callee_exists = indexer.entities.contains_key(&callee_fq);
                            
                            if caller_exists && callee_exists {
                                add_relationship(&caller, &callee_fq, "calls", indexer);
                            }
                        }
                    }
                }
            },
            "class_declaration" => {
                // Handle class inheritance
                if let Some(heritage_node) = node.child_by_field_name("heritage") {
                    let mut cursor = heritage_node.walk();
                    for child in heritage_node.children(&mut cursor) {
                        if child.kind() == "extends_clause" {
                            if let Some(base_node) = child.child_by_field_name("value") {
                                if let Ok(base_name) = base_node.utf8_text(source.as_bytes()) {
                                    if let Some(name_node) = node.child_by_field_name("name") {
                                        if let Ok(class_name) = name_node.utf8_text(source.as_bytes()) {
                                            let class_fq = format!("{}.{}", module_path, class_name);
                                            
                                            // Try to resolve the base class
                                            let base_fq = resolve_entity_name(base_name, module_path, indexer)
                                                .unwrap_or_else(|| format!("{}.{}", module_path, base_name));
                                            
                                            let class_exists = indexer.entities.contains_key(&class_fq);
                                            let base_exists = indexer.entities.contains_key(&base_fq);
                                            
                                            if class_exists && base_exists {
                                                add_relationship(&class_fq, &base_fq, "inherits", indexer);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Process class body for method relationships
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(class_name) = name_node.utf8_text(source.as_bytes()) {
                        if let Some(body_node) = node.child_by_field_name("body") {
                            let mut cursor = body_node.walk();
                            for child in body_node.children(&mut cursor) {
                                analyze_relationships(&child, source, module_path, indexer);
                            }
                        }
                        return; // Skip processing class body again
                    }
                }
            },
            "new_expression" => {
                // Handle constructor calls (new ClassName())
                if let Some(constructor_node) = node.child_by_field_name("constructor") {
                    if let Ok(class_name) = constructor_node.utf8_text(source.as_bytes()) {
                        let class_fq = resolve_entity_name(class_name, module_path, indexer)
                            .unwrap_or_else(|| format!("{}.{}", module_path, class_name));
                        
                        if let Some(caller) = find_enclosing_entity(node, source, module_path) {
                            let caller_exists = indexer.entities.contains_key(&caller);
                            let class_exists = indexer.entities.contains_key(&class_fq);
                            
                            if caller_exists && class_exists {
                                add_relationship(&caller, &class_fq, "instantiates", indexer);
                            }
                        }
                    }
                }
            },
            "member_expression" => {
                // Handle property access and method calls on objects
                if let Some(object_node) = node.child_by_field_name("object") {
                    if let Some(property_node) = node.child_by_field_name("property") {
                        if let Ok(object_name) = object_node.utf8_text(source.as_bytes()) {
                            if let Ok(property_name) = property_node.utf8_text(source.as_bytes()) {
                                // Try to resolve the object to see if it's a class instance
                                if let Some(object_fq) = resolve_entity_name(object_name, module_path, indexer) {
                                    let property_fq = format!("{}.{}", object_fq, property_name);
                                    
                                    if let Some(caller) = find_enclosing_entity(node, source, module_path) {
                                        let caller_exists = indexer.entities.contains_key(&caller);
                                        let property_exists = indexer.entities.contains_key(&property_fq);
                                        
                                        if caller_exists && property_exists {
                                            add_relationship(&caller, &property_fq, "accesses", indexer);
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
        
        // Recursively process children (except for class body, which is handled separately)
        if node.kind() != "class_declaration" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                analyze_relationships(&child, source, module_path, indexer);
            }
        }
    }
    
    analyze_relationships(root, source, module_path, indexer);
}

/// Build a dependency graph from the collected entities and relationships
pub fn build_dependency_graph(indexer: &Indexer) -> Graph<String, String, Directed> {
    let mut graph = Graph::new();
    let mut node_indices = HashMap::new();
    
    // Add all entities as nodes
    for entity in indexer.entities.iter() {
        let node_idx = graph.add_node(entity.fq_name.clone());
        node_indices.insert(entity.fq_name.clone(), node_idx);
    }
    
    // Add all relationships as edges
    let mut edge_count = 0;
    while let Some((source, target, edge_type)) = indexer.edges.pop() {
        if let (Some(&source_idx), Some(&target_idx)) = (
            node_indices.get(&source),
            node_indices.get(&target)
        ) {
            graph.add_edge(source_idx, target_idx, edge_type);
            edge_count += 1;
        }
    }
    
    println!("Built dependency graph with {} nodes and {} edges", 
             graph.node_count(), edge_count);
    
    graph
}

/// Generate a summary of the indexing results
pub fn generate_summary(indexer: &Indexer) -> serde_json::Value {
    let mut entity_counts = HashMap::new();
    let mut relationship_counts = HashMap::new();
    let mut files = std::collections::HashSet::new();
    
    // Count entities by type and collect files
    for entity in indexer.entities.iter() {
        *entity_counts.entry(entity.entity_type.clone()).or_insert(0) += 1;
        files.insert(entity.file.clone());
    }
    
    // Count relationships and build JSON directly from the queue
    let mut relationships = Vec::new();
    let mut edge_count = 0;
    
    while let Some((source, target, edge_type)) = indexer.edges.pop() {
        *relationship_counts.entry(edge_type.clone()).or_insert(0) += 1;
        relationships.push(json!({
            "source": source,
            "target": target,
            "type": edge_type
        }));
        edge_count += 1;
        if edge_count > 10000 { // Safety limit
            break;
        }
    }
    
    json!({
        "summary": {
            "total_files": files.len(),
            "total_entities": indexer.entities.len(),
            "total_relationships": relationships.len(),
            "total_imports": indexer.import_map.len(),
            "entities_by_type": entity_counts,
            "relationships_by_type": relationship_counts,
            "files_processed": files.into_iter().collect::<Vec<_>>(),
            "relationships": relationships
        }
    })
}

/// Collect TypeScript and TSX files from a directory
pub fn collect_typescript_files(
    path: &str,
    limit: Option<usize>,
    verbose: bool,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut files = HashMap::new();
    let mut processed_count = 0;
    
    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            if let Some(ext) = e.path().extension() {
                ext == "ts" || ext == "tsx"
            } else {
                false
            }
        })
    {
        if let Some(max_files) = limit {
            if processed_count >= max_files {
                break;
            }
        }
        
        let file_path = normalize_path(&entry.path().to_string_lossy());
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
        println!("Collected {} TypeScript files", files.len());
    }
    
    Ok(files)
}
