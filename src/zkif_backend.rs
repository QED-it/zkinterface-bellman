use bellman::{
    Circuit,
    ConstraintSystem,
    groth16::{
        generate_random_parameters,
        create_random_proof,
        prepare_verifying_key,
        verify_proof,
        Parameters,
        Proof,
    },
    SynthesisError,
    Variable,
    gadgets::num::AllocatedNum,
};
use bls12_381::{Bls12, Scalar};
use rand;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use super::import::{enforce, decode_scalar};
pub use zkinterface::reading::Messages;
use std::error::Error;
use bellman::gadgets::test::TestConstraintSystem;

/// A circuit instance built from zkif messages.
#[derive(Clone, Debug)]
pub struct ZKIFCircuit<'a> {
    pub messages: &'a Messages,
}

impl<'a> Circuit<Scalar> for ZKIFCircuit<'a> {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        // Check that we are working on the right field.
        match self.messages.first_circuit().unwrap().field_maximum() {
            None => {
                eprintln!("Warning: no field_maximum specified in messages, the field may be incompatible.");
            }
            Some(field_maximum) => {
                let requested = decode_scalar(field_maximum);
                let supported = Scalar::one().neg();
                if requested != supported {
                    eprintln!("Error: This proving system does not support the field specified for this circuit.");
                    eprintln!("Requested field: {:?}", requested);
                    eprintln!("Supported field: {:?}", supported);
                    panic!();
                }
            }
        }

        // Track variables by id. Used to convert constraints.
        let mut id_to_var = HashMap::<u64, Variable>::new();

        id_to_var.insert(0, CS::one());

        // Allocate public inputs, with optional values.
        let public_vars = self.messages.connection_variables().unwrap();

        for var in public_vars {
            let mut cs = cs.namespace(|| format!("public_{}", var.id));
            let num = AllocatedNum::alloc(&mut cs, || {
                Ok(decode_scalar(var.value))
            })?;

            num.inputize(&mut cs)?;

            // Track input variable.
            id_to_var.insert(var.id, num.get_variable());
        }

        // Allocate private variables, with optional values.
        let private_vars = self.messages.private_variables().unwrap();

        for var in private_vars {
            let num = AllocatedNum::alloc(
                cs.namespace(|| format!("private_{}", var.id)), || {
                    Ok(decode_scalar(var.value))
                })?;

            // Track private variable.
            id_to_var.insert(var.id, num.get_variable());
        };

        for (i, constraint) in self.messages.iter_constraints().enumerate() {
            enforce(&mut cs.namespace(|| format!("constraint_{}", i)), &id_to_var, &constraint);
        }

        Ok(())
    }
}


pub fn validate(messages: &Messages, print: bool) -> Result<(), Box<dyn Error>> {
    let circuit = ZKIFCircuit { messages };
    let mut cs = TestConstraintSystem::<Scalar>::new();
    circuit.synthesize(&mut cs)?;

    if print {
        eprintln!("{}", cs.pretty_print());
    }

    match cs.which_is_unsatisfied() {
        None => {
            eprintln!("Satisfied: YES");
            Ok(())
        }
        Some(constraint) => {
            eprintln!("Satisfied: NO");
            eprintln!("This constraint is not satisfied: {}", constraint);
            Err("The witness does not satisfy the constraints.".into())
        }
    }
}


pub fn setup(
    messages: &Messages,
    workspace: &Path,
) -> Result<(), Box<dyn Error>>
{
    let key_path = workspace.join("bellman-pk");

    let circuit = ZKIFCircuit { messages };

    let mut rng = rand::thread_rng();
    let params = generate_random_parameters::<Bls12, _, _>(
        circuit.clone(),
        &mut rng,
    )?;

    // Store params.
    let file = File::create(&key_path)?;
    params.write(file)?;

    Ok(())
}

pub fn prove(
    messages: &Messages,
    workspace: &Path,
) -> Result<(), Box<dyn Error>>
{
    let key_path = workspace.join("bellman-pk");
    let proof_path = workspace.join("bellman-proof");

    let circuit = ZKIFCircuit { messages };

    // Load params.
    let params = {
        let mut file = File::open(&key_path)?;
        Parameters::<Bls12>::read(&mut file, false)?
    };

    let mut rng = rand::thread_rng();
    let proof = create_random_proof(
        circuit,
        &params,
        &mut rng,
    )?;

    // Store proof.
    let file = File::create(proof_path)?;
    proof.write(file)?;

    Ok(())
}

pub fn verify(
    messages: &Messages,
    workspace: &Path,
) -> Result<(), Box<dyn Error>> {
    let key_path = workspace.join("bellman-pk");
    let proof_path = workspace.join("bellman-proof");

    let pvk = {
        let mut file = File::open(&key_path)?;
        let params = Parameters::<Bls12>::read(&mut file, false)?;
        prepare_verifying_key::<Bls12>(&params.vk)
    };

    let public_inputs: Vec<Scalar> = {
        match messages.connection_variables() {
            None => Vec::new(),
            Some(connections) => {
                connections.iter().map(|var|
                    decode_scalar(var.value)
                ).collect()
            }
        }
    };

    let proof = {
        let mut file = File::open(&proof_path)?;
        Proof::read(&mut file).unwrap()
    };
    let res = verify_proof(&pvk, &proof, &public_inputs);

    match res {
        Ok(()) => eprintln!("The proof is valid."),
        Err(_) => eprintln!("The proof is NOT valid."),
    };
    res?;
    Ok(())
}


#[test]
fn test_zkif_backend() {

    // Load test messages.
    let test_dir = Path::new("src/tests/example.zkif");
    let out_dir = Path::new("local");

    let mut messages = Messages::new();
    messages.read_file(test_dir).unwrap();

    setup(&messages, out_dir).unwrap();

    prove(&messages, out_dir).unwrap();

    verify(&messages, out_dir).unwrap();
}
