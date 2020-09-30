use zkinterface::{Reader, Result};
use zkinterface_bellman::zkif_backend::{setup, prove, verify, validate};
use std::io;
use std::io::Read;
use std::env;
use bls12_381::Scalar as Bls12Scalar;


const USAGE: &str = "Bellman prover.

Validate that the witness satisfies the constraints:

    zkif_bellman validate

Print the circuit in a text-form:

    zkif_bellman print

Generate public parameters:

    zkif_bellman setup <workspace>

Generate a proof using the public parameters:

    zkif_bellman prove <workspace>

The circuit and witness are read from stdin in zkInterface format.
The filenames of keys and proofs are derived from the workspace argument; defaults to the current directory.

";

pub fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let args: Vec<&str> = args.iter().map(|a| &a[..]).collect();
    if args.len() <= 1 {
        eprintln!("{}", USAGE);
        return Err("Missing command.".into());
    }

    let mut reader = Reader::new();
    let mut buffer = vec![];
    io::stdin().read_to_end(&mut buffer)?;
    reader.push_message(buffer)?;

    let command = args[1];
    let workspace = env::current_dir()?;

    match &command[..] {
        "validate" => validate::<Bls12Scalar>(&reader, false),
        "print" => validate::<Bls12Scalar>(&reader, true),
        "setup" => setup(&reader, &workspace),
        "prove" => prove(&reader, &workspace),
        "verify" => verify(&reader, &workspace),
        _ => {
            eprintln!("{}", USAGE);
            Err(format!("Unknown command {}", command).into())
        }
    }
}
