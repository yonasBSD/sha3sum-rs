use std::{
    io::{self, BufRead, Read},
    process,
};

use clap::Parser;
use sha3::{Digest, Sha3_256, Sha3_512};

/// Simple program to hash strings using SHA-3
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Hash algorithm
    #[arg(short, long, default_value_t = 512)]
    algo: u32,

    /// Input
    #[arg(required = false, default_value = "")]
    input: String,
}

fn copy_wide<R, H>(mut reader: R, hasher: &mut H) -> io::Result<u64>
where
    R: Read,
    H: Digest,
{
    let mut buffer = [0; 65536];
    let mut total = 0;

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                hasher.update(&buffer[..n]);
                total += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn get_hash() -> io::Result<String> {
    let args = Args::parse();
    let mut password = args.input;

    if password.is_empty() {
        let stdin = io::stdin();
        stdin.lock().read_line(&mut password)?;
    }

    let output: String = match args.algo {
        256 => {
            let mut hasher = Sha3_256::new();
            let _ = copy_wide(io::stdin().lock(), &mut hasher);
            hex::encode(hasher.finalize())
        }
        512 => {
            let mut hasher = Sha3_512::new();
            let _ = copy_wide(io::stdin().lock(), &mut hasher);
            hex::encode(hasher.finalize())
        }
        _ => {
            eprintln!("Unknown hash algorithm");
            process::exit(1);
        }
    };

    Ok(output)
}

fn main() -> io::Result<()> {
    println!("{}", get_hash()?);
    Ok(())
}
