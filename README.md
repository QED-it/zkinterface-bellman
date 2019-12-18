# zkInterface Bellman adapter

See https://github.com/QED-it/zkinterface

## Example:

Create a proving key:

    cat src/test/messages/circuit_r1cs.zkif src/test/messages/r1cs.zkif       | cargo run --release

Create a proof:

    cat src/test/messages/circuit_witness.zkif src/test/messages/witness.zkif | cargo run --release

