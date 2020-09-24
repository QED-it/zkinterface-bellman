use bellman::{
    ConstraintSystem,
    LinearCombination,
    SynthesisError,
    Variable,
    gadgets::num::AllocatedNum,
};
use bls12_381::Scalar;
use std::collections::HashMap;
use zkinterface::{
    Messages, CircuitOwned, VariablesOwned, Result,
    reading::{Constraint, Term},
};
use crate::export::encode_scalar;


/// Convert zkInterface little-endian bytes to bellman Fr.
pub fn decode_scalar(bytes_le: &[u8]) -> Scalar {
    if bytes_le.len() == 0 {
        return Scalar::zero();
    }
    assert!(bytes_le.len() <= 32, "Element is too big ({} > 32 bytes)", bytes_le.len());

    let mut repr = [0 as u8; 32];
    for i in 0..bytes_le.len() {
        repr[i] = bytes_le[i];
    }
    Scalar::from_bytes(&repr).unwrap()
}

/// Convert zkInterface terms to bellman LinearCombination.
pub fn terms_to_lc(vars: &HashMap<u64, Variable>, terms: &[Term]) -> LinearCombination<Scalar> {
    let mut lc = LinearCombination::zero();
    for term in terms {
        let coeff = decode_scalar(term.value);
        let var = vars.get(&term.id).unwrap().clone();
        lc = lc + (coeff, var);
    }
    lc
}

/// Enforce a zkInterface constraint in bellman CS.
pub fn enforce<CS>(cs: &mut CS, vars: &HashMap<u64, Variable>, constraint: &Constraint)
    where CS: ConstraintSystem<Scalar>
{
    cs.enforce(|| "",
               |_| terms_to_lc(vars, &constraint.a),
               |_| terms_to_lc(vars, &constraint.b),
               |_| terms_to_lc(vars, &constraint.c),
    );
}

/// Call a foreign gadget through zkInterface.
pub fn call_gadget<CS>(
    cs: &mut CS,
    inputs: &[AllocatedNum<Scalar>],
    exec_fn: &dyn Fn(&[u8]) -> Result<Messages>,
) -> Result<Vec<AllocatedNum<Scalar>>>
    where CS: ConstraintSystem<Scalar>
{
    let witness_generation = inputs.len() > 0 && inputs[0].get_value().is_some();

    // Serialize input values.
    let values = if witness_generation {
        let mut values = Vec::<u8>::new();
        for i in inputs {
            let val = i.get_value().unwrap();
            encode_scalar(&val, &mut values);
        }
        Some(values)
    } else {
        None
    };

    // Describe the input connections.
    let first_input_id = 1;
    let free_variable_id = first_input_id + inputs.len() as u64;

    let call = CircuitOwned {
        connections: VariablesOwned {
            variable_ids: (first_input_id..free_variable_id).collect(),
            values,
        },
        free_variable_id,
        field_maximum: None,
        configuration: None,
    };

    // Prepare the call.
    let mut call_buf = vec![];
    call.write_into(&mut call_buf)?;

    // Call.
    let messages = exec_fn(&call_buf).or(Err(SynthesisError::Unsatisfiable))?;

    // Track variables by id. Used to convert constraints.
    let mut id_to_var = HashMap::<u64, Variable>::new();

    id_to_var.insert(0, CS::one());

    for i in 0..inputs.len() {
        id_to_var.insert(call.connections.variable_ids[i], inputs[i].get_variable());
    }

    // Collect output variables and values to return.
    let mut outputs = Vec::new();

    // Allocate outputs, with optional values.
    if let Some(output_vars) = messages.connection_variables() {
        for var in output_vars {
            let num = AllocatedNum::alloc(
                cs.namespace(|| format!("output_{}", var.id)), || {
                    Ok(decode_scalar(var.value))
                })?;

            // Track output variable.
            id_to_var.insert(var.id, num.get_variable());
            outputs.push(num);
        }
    }

    // Allocate private variables, with optional values.
    let private_vars = messages.private_variables().unwrap();

    for var in private_vars {
        let num = AllocatedNum::alloc(
            cs.namespace(|| format!("local_{}", var.id)), || {
                Ok(decode_scalar(var.value))
            })?;

        // Track private variable.
        id_to_var.insert(var.id, num.get_variable());
    };

    // Add gadget constraints.
    for (i, constraint) in messages.iter_constraints().enumerate() {
        enforce(&mut cs.namespace(|| format!("constraint_{}", i)), &id_to_var, &constraint);
    }

    Ok(outputs)
}
