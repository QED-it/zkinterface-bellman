use zkinterface_bellman::zkif_backend::{Messages, zkif_backend};
use std::io;
use std::io::Read;
use std::env;


pub fn main() -> Result<(), Box<std::error::Error>> {
    let mut messages = Messages::new(1);

    let mut buffer = vec![];
    io::stdin().read_to_end(&mut buffer)?;
    messages.push_message(buffer)?;

    zkif_backend(&messages, &env::current_dir()?)?;

    Ok(())
}
