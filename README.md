# WFP - Windows Filtering Platform Rust library

⚠️ **This project is experimental and a work in progress.**

A safe Rust library for the Windows Filtering Platform (WFP) API, providing an ergonomic interface for creating and managing network filters on Windows systems.

## Adding wfp-rs to your project

Add this to your `Cargo.toml`:

```toml
[dependencies]
wfp = "0.1.0"
log = "0.4"  # Optional, for logging
```

## Quick start

Here is a simple example adding a sublayer and a blocking rule:

```rust
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
            .description("Blocks all outbound IPv4 connections on port 80")
            .action(ActionType::Block)
            .layer(Layer::ConnectV4)
            .condition(
                PortConditionBuilder::remote()
                    .equal(80)
                    .build(),
            )
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
```

See [examples](examples) for more examples.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
