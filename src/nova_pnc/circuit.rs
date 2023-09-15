use bellpepper::gadgets::boolean::AllocatedBit;
use bellpepper_core::{
    num::AllocatedNum, ConstraintSystem, Namespace, SynthesisError,
};
use neptune::Arity;
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::traits::circuit::StepCircuit;
use merkle_trees::index_tree;
use merkle_trees::index_tree::tree::IndexTree;
use crate::nova_por::utils::{DST_HEIGHT, get_empty_dst};

#[derive(Clone, Debug)]
pub struct PNCIteration<F, A2, A3>
where
    F: PrimeField + PrimeFieldBits,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    dct: IndexTree<F, DST_HEIGHT, A3, A2>,
    ex_dst: IndexTree<F, DST_HEIGHT, A3, A2>,
    other_ex_val: F,
}

impl<F, A2, A3> Default for PNCIteration<F, A2, A3>
where
    F: PrimeField + PrimeFieldBits + PartialOrd,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    fn default() -> Self {
        Self {
            dct: IndexTree::new(index_tree::tree::Leaf::default()),
            ex_dst: IndexTree::new(index_tree::tree::Leaf::default()),
            other_ex_val: F::ZERO,
        }
    }
}

impl<F, A2, A3> PNCIteration<F, A2, A3>
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits<ReprBits = [u64; 4]> + PartialOrd,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    pub fn get_w0() -> PNCIteration<F, A2, A3> {
        let mut rng = rand::thread_rng();
        let dct = get_empty_dst::<F, A2, A3, A2>();
        let ex_dst = get_empty_dst::<F, A2, A3, A2>();
        let other_ex_val = F::random(&mut rng);


        PNCIteration {
            dct: dct,
            ex_dst: ex_dst,
            other_ex_val: other_ex_val,
        }
    }

    pub fn get_next_witness(&self) -> PNCIteration<F, A2, A3> {
        let mut rng = rand::thread_rng();
        let mut new_dct = self.dct.clone();
        new_dct.insert_vanilla(self.other_ex_val); 

        PNCIteration {
            dct: new_dct,
            ex_dst: self.ex_dst.clone(),
            other_ex_val: F::random(&mut rng),
        }
    }

    pub fn get_z0(&self) -> Vec<F> {
        let z0 = vec![self.dct.root, self.ex_dst.root];
        assert_eq!(z0.len(), 2);
        z0
    }
}

impl<F, A2, A3> StepCircuit<F> for PNCIteration<F, A2, A3>
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits + PartialOrd,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    fn arity(&self) -> usize {
        2
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        
        // Check DCT root
        let alloc_dct_root =
            AllocatedNum::alloc(&mut cs.namespace(|| "alloc DCT root"), || Ok(self.dct.root))?;
        cs.enforce(
            || "Check DCT root",
            |lc| lc,
            |lc| lc,
            |lc| lc + z[0].get_variable() - alloc_dct_root.get_variable(),
        );
        
        // Check Exchnage DST root
        let alloc_dst_root =
            AllocatedNum::alloc(&mut cs.namespace(|| "alloc DST root"), || Ok(self.ex_dst.root))?;
        cs.enforce(
            || "Check DST root",
            |lc| lc,
            |lc| lc,
            |lc| lc + z[1].get_variable() - alloc_dst_root.get_variable(),
        );

        // Check non-membership of other_ex_val in DCT
        let alloc_val = AllocatedNum::alloc(&mut cs.namespace(|| "alloc other exchnage val"), || Ok(self.other_ex_val))?;
        let val_is_non_member_dct = index_tree::circuit::is_non_member::<
            F,
            A3,
            A2,
            DST_HEIGHT,
            Namespace<'_, F, CS::Root>,
        >(
            cs.namespace(|| "val is non-member in dct"),
            alloc_dct_root.clone(),
            self.dct.clone(),
            alloc_val.clone(),
        )?;
        let val_bit_dct =
            AllocatedBit::alloc(cs.namespace(|| "alloc val_bit_dct"), val_is_non_member_dct.get_value())?;
        cs.enforce(
            || "enforce val_bit_dct equal to one",
            |lc| lc,
            |lc| lc,
            |lc| lc + CS::one() - val_bit_dct.get_variable(),
        );

        // Check non-membership of other_ex_val in Exchnage's DST
        let val_is_non_member_dst = index_tree::circuit::is_non_member::<
            F,
            A3,
            A2,
            DST_HEIGHT,
            Namespace<'_, F, CS::Root>,
        >(
            cs.namespace(|| "val is non-member in dst"),
            alloc_dst_root.clone(),
            self.ex_dst.clone(),
            alloc_val.clone(),
        )?;
        let val_bit_dst =
            AllocatedBit::alloc(cs.namespace(|| "alloc val_bit_dst"), val_is_non_member_dst.get_value())?;
        cs.enforce(
            || "enforce val_bit_dst equal to one",
            |lc| lc,
            |lc| lc,
            |lc| lc + CS::one() - val_bit_dst.get_variable(),
        );

        // Insert other_ex_val in DCT
        let mut next_dct = self.dct.clone();
        index_tree::circuit::insert::<F, A3, A2, DST_HEIGHT, Namespace<'_, F, CS::Root>>(
            cs.namespace(|| "Insert other_ex_val"),
            &mut next_dct,
            alloc_dct_root,
            alloc_val,
        )?;
        let next_dct_root_alloc =
            AllocatedNum::alloc(cs.namespace(|| "dct root var output"), || Ok(next_dct.root))?;

        // Output
        let mut out_vec = vec![];
        out_vec.push(next_dct_root_alloc);
        out_vec.push(z[1].clone());
        assert_eq!(out_vec.len(), 2);

        Ok(out_vec)
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use generic_array::typenum::{U2, U3};
    use pasta_curves::Fp;

    #[test]
    fn test_step_pnc() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let iter: PNCIteration<Fp, U2, U3> = PNCIteration::get_w0();

        let z_0: Vec<Fp> = iter.get_z0();
        
        let alloc_z_in: Vec<AllocatedNum<Fp>> = z_0
            .iter()
            .enumerate()
            .map(|(j, v)| {
                AllocatedNum::alloc(cs.namespace(|| format!("alloc input {j}")), || {
                    Ok(*v)
                })
                .unwrap()
            })
            .collect();

        let z_1 = iter
            .synthesize(
                &mut cs.namespace(|| format!("synthesize step 1")),
                &alloc_z_in,
            )
            .unwrap();

        let next_iter = iter.get_next_witness();

        let z_2 = next_iter.synthesize(&mut cs.namespace(|| format!("synthesize step 2")), &z_1).unwrap();

        assert_eq!(z_2.len(), iter.arity());
        assert!(cs.is_satisfied());
        println!("Num constraints = {:?}", cs.num_constraints());
        println!("Num inputs = {:?}", cs.num_inputs());
    }
}
