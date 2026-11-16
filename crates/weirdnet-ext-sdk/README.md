# weirdnet-ext-sdk

Write [Weirdnet](https://github.com/WeirdBrains/weirdnet-ext) extensions in Rust.

A host (such as Morph) starts your binary in its sandbox with a private socket and a one-time
token. `Extension::connect` uses them to reach the host and do the handshake; after that you
call the app's services, log, report health, and handle events.

```rust,no_run
use weirdnet_ext_sdk::{Event, Extension, Level};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ext = Extension::connect(env!("CARGO_PKG_VERSION")).await?;
    ext.log(Level::Info, "started", &[]).await?;
    let e = ext.clone();
    ext.run(move |ev| {
        let e = e.clone();
        async move {
            if let Event::App { kind, payload } = ev {
                let _ = e.call("morph.ext.v1.Notes", "Append", payload).await;
                let _ = kind;
            }
        }
    })
    .await?;
    Ok(())
}
```

The sandbox leaves you no network, no files outside your package and data directory, and no
`socket()` call: everything goes through the host, which checks each call against what the
user granted. BSD-3-Clause.
