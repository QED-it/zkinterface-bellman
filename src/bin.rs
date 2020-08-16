use zkinterface_bellman::zkif_backend::{Messages, zkif_backend};
use std::io;
use std::io::Read;
use std::env;
use std::error::Error;


pub fn main() -> Result<(), Box<dyn Error>> {
    let mut messages = Messages::new();

    let mut buffer = vec![];
    io::stdin().read_to_end(&mut buffer)?;
    messages.push_message(buffer)?;

    zkif_backend(&messages, &env::current_dir()?)?;

    Ok(())
}
