# zkInterface Bellman adapter

More on zkInterface: https://github.com/QED-it/zkinterface

More on Bellman: https://github.com/zcash/librustzcash

## Usage

Bellman prover.

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

## Example:

Create a proving key:

    cat src/demo_import_from_zokrates/messages/*.zkif | cargo run --release setup

Create a proof:

    cat src/demo_import_from_zokrates/messages/*.zkif | cargo run --release prove
