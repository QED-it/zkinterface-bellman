use std::io::Write;
use zkinterface::owned::variables::VariablesOwned;
use zkinterface::owned::constraints::BilinearConstraintOwned;
use bellman::{LinearCombination, Index};
use ff::{PrimeField, PrimeFieldRepr, ScalarEngine};


pub fn to_zkif_constraint<E: ScalarEngine>(
    a: LinearCombination<E>, b: LinearCombination<E>, c: LinearCombination<E>,
) -> BilinearConstraintOwned
{
    BilinearConstraintOwned {
        linear_combination_a: to_zkif_lc(a),
        linear_combination_b: to_zkif_lc(b),
        linear_combination_c: to_zkif_lc(c),
    }
}

pub fn to_zkif_lc<E: ScalarEngine>(lc: LinearCombination<E>) -> VariablesOwned {
    let mut variable_ids = Vec::<u64>::new();
    let mut coeffs = Vec::<u8>::new();

    for (var, coeff) in lc.as_ref() {
        let zkid = match var.get_unchecked() {
            Index::Input(zkid) => zkid,
            Index::Aux(zkid) => zkid,
        };
        variable_ids.push(zkid as u64);

        fr_to_le(coeff, &mut coeffs);
    }

    VariablesOwned { variable_ids, values: Some(coeffs) }
}

/// Convert bellman Fr to zkInterface little-endian bytes.
pub fn fr_to_le(fr: &impl PrimeField, writer: &mut impl Write) {
    let repr = fr.into_repr();
    repr.write_le(writer).unwrap();
}
