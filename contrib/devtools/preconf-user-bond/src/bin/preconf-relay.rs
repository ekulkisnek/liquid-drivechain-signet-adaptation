use elementsplus_preconf::relay::{serve, Profile, ServerConfig, Store};
use std::{io::Read, path::Path};

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 || args.iter().any(|arg| arg == "--help") {
        println!("Experimental signed-receipt monitor, NOT a payment admission service.\n\
            Usage: preconf-relay PROFILE.json JOURNAL.jsonl 127.0.0.1:PORT [--peer wss://HOST/PATH] [--origin https://WALLET]\n\
            Pins a fixed profile; peers must have the same profile. No private keys or node RPC credentials required.");
        return if args == ["--help"] {
            Ok(())
        } else {
            Err("missing arguments".into())
        };
    }
    let mut config = ServerConfig::default();
    for pair in args[3..].chunks(2) {
        if pair.len() != 2 {
            return Err("option needs a value".into());
        }
        match pair[0].as_str() {
            "--peer" => config.peers.push(pair[1].clone()),
            "--origin" => config.allowed_origins.push(pair[1].clone()),
            _ => return Err("unknown option".into()),
        }
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&args[0])?
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 256 * 1024 {
        return Err("profile too large".into());
    }
    let profile = serde_json::from_slice::<Profile>(&bytes)?.validate()?;
    let store = Store::open(Path::new(&args[1]), profile.clone())?;
    let listener = tokio::net::TcpListener::bind(&args[2]).await?;
    println!(
        "Profile {}\nListening on {} (signature observations only)",
        profile.id,
        listener.local_addr()?
    );
    serve(listener, store, config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
