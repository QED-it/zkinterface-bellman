use std::path::Path;
use std::marker::PhantomData;

use zkinterface::{
    ConstraintSystemOwned, WitnessOwned, VariablesOwned, CircuitOwned, KeyValueOwned,
    statement::{StatementBuilder, FileStore, GadgetCallbacks, Store},
};
use bellman::{ConstraintSystem, Variable, Index, LinearCombination, SynthesisError};
use ff::PrimeField;
use super::export::{encode_scalar, to_zkif_constraint};


pub struct ZkifCS<Scalar: PrimeField> {
    stmt: StatementBuilder<FileStore>,
    constraints: ConstraintSystemOwned,
    proving: bool,
    witness: Vec<u8>,
    phantom: PhantomData<Scalar>,
}

impl<Scalar: PrimeField> ZkifCS<Scalar> {
    /// Must call finish() to finalize the files in the workspace.
    pub fn new(workspace: impl AsRef<Path>, proving: bool) -> Self {
        let store = FileStore::new(workspace, true, true, false).unwrap();
        let stmt = StatementBuilder::new(store);

        ZkifCS {
            stmt,
            constraints: ConstraintSystemOwned { constraints: vec![] },
            proving,
            witness: vec![],
            phantom: PhantomData,
        }
    }

    pub fn finish(mut self, name: &str) {
        let mut msg = Vec::<u8>::new();
        self.constraints.write_into(&mut msg).unwrap();
        self.stmt.receive_constraints(&msg).unwrap();

        if self.proving {
            let variable_ids = (1..self.stmt.vars.free_variable_id).collect();
            let wit = WitnessOwned {
                assigned_variables: VariablesOwned {
                    variable_ids,
                    values: Some(self.witness.clone()),
                }
            };
            let mut msg = Vec::<u8>::new();
            wit.write_into(&mut msg).unwrap();
            self.stmt.receive_witness(&msg).unwrap();
        }

        let negative_one = Scalar::one().neg();
        let mut field_maximum = Vec::<u8>::new();
        encode_scalar(&negative_one, &mut field_maximum);

        let statement = CircuitOwned {
            connections: VariablesOwned {
                variable_ids: vec![],
                values: Some(vec![]),
            },
            free_variable_id: self.stmt.vars.free_variable_id,
            field_maximum: Some(field_maximum),
            configuration: Some(vec![
                KeyValueOwned {
                    key: "name".to_string(),
                    text: Some(name.to_string()),
                    data: None,
                    number: 0,
                }]),
        };
        self.stmt.store.push_main(&statement).unwrap();
    }
}

impl<Scalar: PrimeField> ConstraintSystem<Scalar> for ZkifCS<Scalar> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _annotation: A, f: F) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<Scalar, SynthesisError>,
              A: FnOnce() -> AR, AR: Into<String>
    {
        let zkid = self.stmt.vars.allocate();
        if self.proving {
            let fr = f()?;
            encode_scalar(&fr, &mut self.witness);
        }
        Ok(Variable::new_unchecked(Index::Aux(zkid as usize)))
    }

    fn alloc_input<F, A, AR>(&mut self, annotation: A, f: F) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<Scalar, SynthesisError>,
              A: FnOnce() -> AR, AR: Into<String>
    {
        ConstraintSystem::<Scalar>::alloc(self, annotation, f)
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _annotation: A, a: LA, b: LB, c: LC)
        where A: FnOnce() -> AR, AR: Into<String>,
              LA: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
              LB: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
              LC: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>
    {
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());

        let co = to_zkif_constraint(a, b, c);
        self.constraints.constraints.push(co);
    }

    fn push_namespace<NR, N>(&mut self, _name_fn: N) where NR: Into<String>, N: FnOnce() -> NR {}

    fn pop_namespace(&mut self) {}

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}
