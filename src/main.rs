use std::io;
use sha3::{Sha3_256, Sha3_512, Digest};

use clap::Parser;

/// Simple program to hash strings using SHA-3
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Hash algorithm
    #[arg(short, long, default_value_t = 512)]
    algo: u32,

    /// Input
    #[arg(required = false, default_value = "")]
    input: String,
}

pub fn copy_wide_256(
  mut reader: impl io::Read,
  hasher: &mut Sha3_256,
) -> io::Result<u64> {
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

pub fn copy_wide_512(
  mut reader: impl io::Read,
  hasher: &mut Sha3_512,
) -> io::Result<u64> {
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

pub fn get_hash() -> io::Result<String> {
  let args = Args::parse();
  let mut password = args.input;

  if password.len() == 0 {
    use std::io::{self, BufRead};

    let stdin = io::stdin();
    stdin.lock().read_line(&mut password).unwrap();
  }

  let output:String;

  match args.algo {
    256 => {
        let mut hasher = Sha3_256::new();
        let _ = copy_wide_256(io::stdin().lock(), &mut hasher);
        let hash = hasher.finalize();
        output = hex::encode(&hash);
    },
    512 => {
        let mut hasher = Sha3_512::new();
        let _ = copy_wide_512(io::stdin().lock(), &mut hasher);
        let hash = hasher.finalize();
        output = hex::encode(&hash);
    },
    _ => {
        eprintln!("Unknown hash algorithm");
        std::process::exit(1);
    }
  };

  Ok(output)
}

fn main() -> io::Result<()> {
  let output = get_hash()?;
  println!("{}", output);

  Ok(())
}
