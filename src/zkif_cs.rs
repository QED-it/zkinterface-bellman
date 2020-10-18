use std::path::Path;
use std::marker::PhantomData;

use zkinterface::{ConstraintSystem, Witness, Variables, KeyValue, producers::builder::{StatementBuilder, Sink, FileSink}, BilinearConstraint};
use bellman as bl;
use bellman::{Variable, Index, LinearCombination, SynthesisError};
use ff::PrimeField;
use super::export::{write_scalar, to_zkif_constraint};
use std::mem;


pub struct ZkifCS<Scalar: PrimeField> {
    pub constraints_per_message: usize,

    statement: StatementBuilder<FileSink>,
    constraints: ConstraintSystem,
    proving: bool,
    witness: Vec<u8>,
    phantom: PhantomData<Scalar>,
}

impl<Scalar: PrimeField> ZkifCS<Scalar> {
    /// Must call finish() to finalize the files in the workspace.
    pub fn new(workspace: impl AsRef<Path>, proving: bool) -> Self {
        let sink = FileSink::new(workspace).unwrap();
        let statement = StatementBuilder::new(sink);

        ZkifCS {
            constraints_per_message: 100000,
            statement,
            constraints: ConstraintSystem::default(),
            proving,
            witness: vec![],
            phantom: PhantomData,
        }
    }

    pub fn finish(mut self, name: &str) -> zkinterface::Result<()> {
        if self.constraints.constraints.len() > 0 {
            self.statement.push_constraints(self.constraints)?;
        }

        if self.proving {
            let variable_ids = (1..self.statement.header.free_variable_id).collect();
            let wit = Witness {
                assigned_variables: Variables {
                    variable_ids,
                    values: Some(self.witness.clone()),
                }
            };
            self.statement.push_witness(wit)?;
        }

        let negative_one = Scalar::one().neg();
        let mut field_maximum = Vec::<u8>::new();
        write_scalar(&negative_one, &mut field_maximum);

        self.statement.header.field_maximum = Some(field_maximum);
        self.statement.header.configuration = Some(vec![
            KeyValue {
                key: "name".to_string(),
                text: Some(name.to_string()),
                data: None,
                number: 0,
            }]);
        self.statement.finish_header()
    }

    fn push_constraint(&mut self, co: BilinearConstraint) -> zkinterface::Result<()> {
        self.constraints.constraints.push(co);

        if self.constraints.constraints.len() >= self.constraints_per_message {
            let cs = mem::replace(&mut self.constraints, ConstraintSystem::default());
            self.statement.push_constraints(cs)?;
        }
        Ok(())
    }
}

impl<Scalar: PrimeField> bl::ConstraintSystem<Scalar> for ZkifCS<Scalar> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _annotation: A, f: F) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<Scalar, SynthesisError>,
              A: FnOnce() -> AR, AR: Into<String>
    {
        let zkid = self.statement.allocate_var();
        if self.proving {
            let fr = f()?;
            write_scalar(&fr, &mut self.witness);
        }
        Ok(Variable::new_unchecked(Index::Aux(zkid as usize)))
    }

    fn alloc_input<F, A, AR>(&mut self, _annotation: A, f: F) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<Scalar, SynthesisError>,
              A: FnOnce() -> AR, AR: Into<String>
    {
        let value = f()?;
        let mut encoded = vec![];
        write_scalar(&value, &mut encoded);

        let zkid = self.statement.allocate_instance_var(&encoded);
        Ok(Variable::new_unchecked(Index::Input(zkid as usize)))
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
        self.push_constraint(co).unwrap();
    }

    fn push_namespace<NR, N>(&mut self, _name_fn: N) where NR: Into<String>, N: FnOnce() -> NR {}

    fn pop_namespace(&mut self) {}

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}
