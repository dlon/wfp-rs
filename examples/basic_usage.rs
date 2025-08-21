//! Basic usage example for the WFP library.
//!
//! This example demonstrates how to:
//! - Create a filter engine with dynamic session
//! - Add a custom sublayer for organizing filters
//! - Create and add a blocking filter for IPv4 outbound connections
//! - Use transactions to ensure atomic operations

use std::io;
use wfp::{ActionType, FilterBuilder, FilterEngineBuilder, Layer, SubLayerBuilder, Transaction};

fn main() -> io::Result<()> {
    println!("Creating WFP filter engine...");

    let mut engine = FilterEngineBuilder::default().dynamic().open()?;

    std::thread::spawn(move || {
        println!("Starting transaction...");
        let transaction = Transaction::new(&mut engine)?;

        // Create a custom sublayer for organizing our filters
        println!("Adding custom sublayer...");
        SubLayerBuilder::default()
            .name("Example SubLayer")
            .description("Custom sublayer for example filters")
            .weight(100)
            .add(&transaction)?;

        // Create a blocking filter for IPv4 outbound connections
        println!("Adding blocking filter...");
        FilterBuilder::default()
            .name("Example Block Filter")
            .description("Blocks all outbound IPv4 connections")
            .action(ActionType::Block)
            .layer(Layer::ConnectV4)
            .add(&transaction)?;

        println!("Committing transaction...");
        transaction.commit()?;

        println!("Filter successfully added!");
        Ok::<(), io::Error>(())
    })
    .join()
    .unwrap()?;

    println!("Example completed successfully!");
    Ok(())
}
