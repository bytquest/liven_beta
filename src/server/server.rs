use std::{collections::HashMap, net::SocketAddr, sync::Arc};

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

use crate::python_indexing::{create_tables, get_analysis, handle_upload, list_analyses, search_entities, Indexer, AppState};



#[tokio::main]
pub async fn build_server() -> Result<(), Box<dyn std::error::Error>> {
    // Setup databases with language-specific URLs
    let db_configs = [
        ("python", "sqlite:python_callgraph.db"),
        ("generic", "sqlite:callgraph.db"),
        // Add more languages as needed
        // ("java", "sqlite:java_callgraph.db"),
        // ("rust", "sqlite:rust_callgraph.db"),
    ];
    
    // Create a HashMap to store language-specific database pools
    let mut db_pools = HashMap::new();
    
    // Initialize all databases
    for (lang, db_url) in &db_configs {
        // Create the database if it doesn't exist
        if !sqlx::Sqlite::database_exists(db_url).await.unwrap_or(false) {
            sqlx::Sqlite::create_database(db_url).await?;
        }
        
        // Connect to the database
        let pool = sqlx::sqlite::SqlitePool::connect(db_url).await?;
        
        // Create tables if they don't exist
        create_tables(&pool).await?;
        
        // Store the pool in the HashMap
        db_pools.insert(lang.to_string(), pool);
        
        println!("Initialized database for {} language: {}", lang, db_url);
    }
    
    // Get the default database pool (using "generic" as default)
    let default_pool = db_pools.get("python")
        .expect("Default database pool must exist")
        .clone();
    
    // Create application state with all language-specific database pools
    let state = AppState {
        indexer: Arc::new(Indexer::new()),
        db_pool: default_pool, // Use "generic" as the default pool
    };
    
    // Build our application with routes
    let app = Router::new()
        // Common routes
        .route("/analyses", get(list_analyses))
        .route("/analysis/:id", get(get_analysis))
        .route("/analysis/:id/search", get(search_entities))
        .route("/upload", post(handle_upload))
        
        .with_state(state);
    
    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running at http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
    
    Ok(())
}
// Removed duplicate AppState definition to avoid conflict with python_indexing::AppState