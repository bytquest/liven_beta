use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::error::Error;
use serde::{Deserialize, Serialize};
use mongodb::{Client, options::ClientOptions};
use mongodb::bson::{doc, Document};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, AUTHORIZATION};
use walkdir::WalkDir;
use tree_sitter::{Parser, Language, Node};
use dotenv::dotenv;
use tree_sitter_python::language as python_language;




#[derive(Debug, Serialize, Deserialize)]
struct EmbeddingRequest {
    model: String,
    content: Content,
}

#[derive(Debug, Serialize, Deserialize)]
struct Content {
    parts: Vec<Part>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Part {
    text: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EmbeddingResponse {
    embedding: Embedding,
}

#[derive(Debug, Serialize, Deserialize)]
struct Embedding {
    values: Vec<f32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SummaryRequest {
    contents: Vec<Content>,
    model: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SummaryResponse {
    candidates: Vec<Candidate>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Candidate {
    content: Content,
}

struct Config {
    gemini_api_key: String,
    mongodb_uri: String,
    db_name: String,
    collection_name: String,
}

// Extract Python definitions using tree-sitter
fn extract_python_definitions(
    root: &Node,
    source: &str,
    module_path: &str,
    file_path: &str,
) -> Vec<(String, String, String)> {
    let mut results = Vec::new();
    
    fn recursive_extract(
        node: &Node,
        source: &str,
        module_path: &str,
        file_path: &str,
        class_context: Option<&str>,
        results: &mut Vec<(String, String, String)>,
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
                        
                        // Extract the actual code text
                        let start = node.start_byte();
                        let end = node.end_byte();
                        let code = source[start..end].to_string();
                        
                        results.push((fq_name.clone(), entity_type.to_string(), code));
                        println!("Found {}: {}", entity_type, fq_name);
                    }
                }
            },
            "class_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(class_name) = name_node.utf8_text(source.as_bytes()) {
                        let fq_name = format!("{}.{}", module_path, class_name);
                        
                        // Extract the actual code text
                        let start = node.start_byte();
                        let end = node.end_byte();
                        let code = source[start..end].to_string();
                        
                        results.push((fq_name.clone(), "class".to_string(), code));
                        println!("Found class: {}", fq_name);
                        
                        // Process class body (methods)
                        if let Some(body_node) = node.child_by_field_name("body") {
                            let mut cursor = body_node.walk();
                            for child in body_node.children(&mut cursor) {
                                recursive_extract(&child, source, module_path, file_path, Some(class_name), results);
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
                recursive_extract(&child, source, module_path, file_path, class_context, results);
            }
        }
    }
    
    recursive_extract(root, source, module_path, file_path, None, &mut results);
    results
}

// Function to summarize code using Gemini API
async fn summarize_code(api_key: &str, code: &str) -> Result<String, Box<dyn Error>> {
    let client = reqwest::Client::new();
    
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", api_key))?);
    
    let request = SummaryRequest {
        contents: vec![Content {
            parts: vec![Part {
                text: format!("Summarize the following Python code in a clear and concise paragraph:\n\n{}", code),
            }],
        }],
        model: "models/gemini-1.0-pro".to_string(),
    };
    
    let response = client.post("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.0-pro:generateContent")
        .headers(headers)
        .json(&request)
        .send()
        .await?
        .json::<SummaryResponse>()
        .await?;
    
    if response.candidates.is_empty() {
        return Err("No summary generated".into());
    }
    
    let summary = &response.candidates[0].content.parts[0].text;
    Ok(summary.clone())
}

// Function to generate embeddings using Gemini API
async fn generate_embedding(api_key: &str, text: &str) -> Result<Vec<f32>, Box<dyn Error>> {
    let client = reqwest::Client::new();
    
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", api_key))?);
    
    let request = EmbeddingRequest {
        model: "models/text-embedding-004".to_string(),
        content: Content {
            parts: vec![Part {
                text: text.to_string(),
            }],
        },
    };
    
    let response = client.post("https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent")
        .headers(headers)
        .json(&request)
        .send()
        .await?
        .json::<EmbeddingResponse>()
        .await?;
    
    Ok(response.embedding.values)
}

// Function to store data in MongoDB
async fn store_in_mongodb(config: &Config, filepath: &str, block_name: &str, code: &str, summary: &str, embedding: Vec<f32>) -> Result<(), Box<dyn Error>> {
    let client_options = ClientOptions::parse(&config.mongodb_uri).await?;
    let client = Client::with_options(client_options)?;
    
    let db = client.database(&config.db_name);
    let collection = db.collection::<Document>(&config.collection_name);
    
    let doc = doc! {
        "filepath": filepath,
        "block_name": block_name,
        "code": code,
        "summary": summary,
        "embedding": embedding,
    };
    
    collection.insert_one(doc).await?;
    
    Ok(())
}

// Process a single Python file
async fn process_file(
    config: &Config,
    filepath: &str,
    source: &str,
) -> Result<(), Box<dyn Error>> {
    dotenv().ok();
    println!("Processing file: {}", filepath);
    let gemini_api_key = std::env::var("GEMINI_API_KEY").unwrap();
    
    // Initialize tree-sitter parser
    let mut parser = tree_sitter::Parser::new();
    unsafe { 
        parser.set_language(python_language()).expect("Error loading Python grammar");
    };
    
    // Parse the file
    let tree = parser.parse(source, None).expect("Failed to parse Python file");
    let root_node = tree.root_node();
    
    // Determine module path from file path
    let file_path = Path::new(filepath);
    let stem = file_path.file_stem().unwrap().to_str().unwrap();
    let module_path = if stem == "__init__" {
        file_path.parent().unwrap().to_str().unwrap().replace("/", ".")
    } else {
        let mut path = file_path.parent().unwrap().to_str().unwrap().replace("/", ".");
        if !path.is_empty() {
            format!("{}.{}", path, stem)
        } else {
            stem.to_string()
        }
    };
    
    // Extract code blocks
    let blocks = extract_python_definitions(&root_node, source, &module_path, filepath);
    
    for (block_name, entity_type, code) in blocks {
        // Skip if code is too small
        if code.len() < 10 {
            continue;
        }
        
        println!("Processing {}: {}", entity_type, block_name);
        
        // Summarize the code
        let summary = match summarize_code(&config.gemini_api_key, &code).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error summarizing code: {}", e);
                continue;
            }
        };
        
        // Generate embeddings for the summary
        let embedding = match generate_embedding(&config.gemini_api_key, &summary).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Error generating embedding: {}", e);
                continue;
            }
        };
        
        // Store in MongoDB
        if let Err(e) = store_in_mongodb(config, filepath, &block_name, &code, &summary, embedding).await {
            eprintln!("Error storing in MongoDB: {}", e);
        } else {
            println!("Successfully stored {} in MongoDB", block_name);
        }
    }
    
    Ok(())
}

async fn process_files(
    config: &Config,
    files: HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    println!("Processing {} files", files.len());
    
    // Convert the files HashMap to a vector
    let files_vec: Vec<(String, String)> = files.into_iter().collect();
    
    // Process each file sequentially
    for (filepath, source) in files_vec {
        if let Err(e) = process_file(config, &filepath, &source).await {
            eprintln!("Error processing file {}: {}", filepath, e);
        }
    }
    
    Ok(())
}


// Process a directory recursively
// #[async_recursion]
// async fn process_directory(config: &Config, dir_path: &str) -> Result<(), Box<dyn Error>> {
//     println!("Processing directory: {}", dir_path);
    
//     for entry in WalkDir::new(dir_path) {
//         let entry = entry?;
//         let path = entry.path();
        
//         if path.is_file() && path.extension().map_or(false, |ext| ext == "py") {
//             if let Err(e) = process_file(config, path.to_str().unwrap()).await {
//                 eprintln!("Error processing file {}: {}", path.display(), e);
//             }
//         }
//     }
    
//     Ok(())
// }

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn Error>> {
//     // Load configuration from environment variables or a config file
//     let config = Config {
//         gemini_api_key: std::env::var("GEMINI_API_KEY").expect("GEMINI_API_KEY not set"),
//         mongodb_uri: std::env::var("MONGODB_URI")
//             .unwrap_or_else(|_| "mongodb+srv://bytquest:MDUYatGA4MAoQcLP@cluster0.pgzae.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0".to_string()),
//         db_name: std::env::var("DB_NAME").unwrap_or_else(|_| "sample_db".to_string()),
//         collection_name: std::env::var("COLLECTION_NAME").unwrap_or_else(|_| "file_snippets".to_string()),
//     };
    
//     // Process directory specified as command line argument or use default
//     let dir_path = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());
    
//     process_directory(&config, &dir_path).await?;
    
//     println!("Processing completed successfully.");
    
//     Ok(())
// }