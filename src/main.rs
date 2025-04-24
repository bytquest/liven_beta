mod indexing;


// src/main.rs

use std::{path::PathBuf, fs, collections::HashMap};
use walkdir::WalkDir;
use rayon::prelude::*;
use dashmap::DashMap;
use crossbeam_queue::SegQueue;
use tree_sitter::{Parser, Language, Node};
use petgraph::{Graph, Directed};

use tree_sitter_rust::language as rust_language;


/// Represents a parsed function or method
#[derive(Clone, Debug)]
struct Function {
    /// Fully qualified name (e.g. "crate::auth::login")
    pub fq_name: String,
    /// Path to the source file
    pub file: String,
    /// Start byte position in the file
    pub start: usize,
    /// End byte position in the file
    pub end: usize,
}

/// Global in-memory state for code indexing
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

fn main() {
    // 1. Discover all .rs files in the current directory tree
    let files: Vec<PathBuf> = WalkDir::new(r"C:\Users\pranav\Desktop\Bytquest\liven\src")
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
        .map(|e| e.into_path())
        .collect();

    let indexer = Indexer::new();
    
    // Use thread_local for the parser since Tree-sitter isn't thread-safe
    thread_local! {
        static PARSER: std::cell::RefCell<Parser> = std::cell::RefCell::new({
            let mut parser = Parser::new();
            unsafe { parser.set_language(rust_language()).unwrap() };
            parser
        });
    }

    // 2. Phase 1: Extract function definitions from all files
    files.par_iter().for_each(|path| {
        let source = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(_) => return,
        };
        
        PARSER.with(|parser| {
            let tree = match parser.borrow_mut().parse(&source, None) {
                Some(tree) => tree,
                None => return,
            };
            
            let root = tree.root_node();
            let mod_path = module_path_from_file(path);
            
            extract_function_definitions(&root, &source, &mod_path, path, &indexer);
        });
    });

    // 3. Phase 2: Extract function calls and resolve them
    files.par_iter().for_each(|path| {
        let source = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(_) => return,
        };
        
        PARSER.with(|parser| {
            let tree = match parser.borrow_mut().parse(&source, None) {
                Some(tree) => tree,
                None => return,
            };
            
            let root = tree.root_node();
            let mod_path = module_path_from_file(path);
            
            extract_function_calls(&root, &source, &mod_path, &indexer);
        });
    });

    // 4. Build the call graph from collected data
    let mut graph = Graph::<Function, (), Directed>::new();
    let mut node_indices = HashMap::new();
    
    // Add all functions as nodes
    for entry in indexer.funcs.iter() {
        let function = entry.value().clone();
        let node_idx = graph.add_node(function.clone());
        node_indices.insert(function.fq_name.clone(), node_idx);
    }
    
    // Add all edges between functions
    while let Some((caller, callee)) = indexer.edges.pop() {
        if let (Some(&caller_idx), Some(&callee_idx)) = (node_indices.get(&caller), node_indices.get(&callee)) {
            graph.add_edge(caller_idx, callee_idx, ());
        }
    }

    println!("Analysis complete! Indexed {} functions with {} call relationships",
             graph.node_count(), graph.edge_count());
}

/// Walks AST to find all function_item nodes and store them in the indexer
fn extract_function_definitions(
    root: &Node,
    source: &str,
    module_path: &str,
    file_path: &PathBuf,
    indexer: &Indexer,
) {
    let mut cursor = root.walk();
    for function_node in root.children(&mut cursor).filter(|n| n.kind() == "function_item") {
        if let Some(name_node) = function_node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                // Create fully qualified name
                let fully_qualified_name = format!("{}::{}", module_path, name);
                println!("Found function: {}", fully_qualified_name);
                
                // Store function information
                indexer.funcs.insert(fully_qualified_name.clone(), Function {
                    fq_name: fully_qualified_name,
                    file: file_path.display().to_string(),
                    start: function_node.start_byte(),
                    end: function_node.end_byte(),
                });
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
    
    println!("Extracting function calls...");

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
                    println!("Found function call: {}", callee_name);
                    
                    // Resolve the function name to its fully qualified form
                    let fully_qualified_callee = if callee_name.contains("::") {
                        // Already a fully qualified path
                        callee_name.to_string()
                    } else if let Some(full_path) = import_map.get(callee_name) {
                        // Resolve via import
                        println!("Resolving via import: {} -> {}", callee_name, full_path);
                        full_path.clone()
                    } else {
                        // Assume it's in the current module
                        format!("{}::{}", module_path, callee_name)
                    };
                    
                    // Find the function containing this call
                    if let Some(caller_function) = find_enclosing_function(node, source, module_path) {
                        println!("Found call: {} -> {}", caller_function, fully_qualified_callee);
                        
                        // Only record the edge if the callee exists in our index
                        if indexer.funcs.contains_key(&fully_qualified_callee) {
                            indexer.edges.push((caller_function, fully_qualified_callee));
                        } else {
                            println!("  (Skipping: function not defined in this codebase)");
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
                    println!("Found import: {}", path_text);
                    
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
                    println!("Found enclosing function: {}", name);
                    return Some(format!("{}::{}", module_path, name));
                }
            }
        }
        
        // Move to parent
        current_opt = current.parent();
    }
    
    None
}

/// Convert a file path to a module path: `src/auth.rs` → `crate::auth`
fn module_path_from_file(path: &PathBuf) -> String {
    let mut components: Vec<_> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    
    // Remove the .rs extension from the filename
    if let Some(file) = components.last_mut() {
        if file.ends_with(".rs") {
            *file = &file[..file.len() - 3];
        }
    }
    
    // Build the module path starting with "crate"
    let mut module_path = vec!["crate"];
    module_path.extend(components);
    module_path.join("::")
}