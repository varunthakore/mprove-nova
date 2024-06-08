use bellpepper::gadgets::boolean::AllocatedBit;
use bellpepper_core::{
    num::AllocatedNum, ConstraintSystem, Namespace, SynthesisError,
};
use neptune::Arity;
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::traits::circuit::StepCircuit;
use merkle_trees::index_tree;
use merkle_trees::index_tree::tree::IndexTree;
use crate::nova_rcg::utils::DST_HEIGHT;
use super::utils::get_full_dst;

#[derive(Clone, Debug)]
pub struct NCIteration<F, A2, A3>
where
    F: PrimeField + PrimeFieldBits,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    pub oit: IndexTree<F, DST_HEIGHT, A3, A2>,
    pub ex1_dst: IndexTree<F, DST_HEIGHT, A3, A2>,
    pub ex2_val: F,
    pub ex2_dst: IndexTree<F, DST_HEIGHT, A3, A2>,

    // low leaf of ex2_val in OIT
    ex2_val_low_leaf_oit: index_tree::tree::Leaf<F, A3>,
    ex2_val_low_leaf_idx_int_oit: u64,

    // low leaf of ex2_val in Exchnage1 DST
    ex2_val_low_leaf_dst1: index_tree::tree::Leaf<F, A3>,
    ex2_val_low_leaf_idx_int_dst1: u64,
}

impl<F, A2, A3> Default for NCIteration<F, A2, A3>
where
    F: PrimeField + PrimeFieldBits + PartialOrd,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    fn default() -> Self {
        Self {
            oit: IndexTree::new(index_tree::tree::Leaf::default()),
            ex1_dst: IndexTree::new(index_tree::tree::Leaf::default()),
            ex2_val: F::ZERO,
            ex2_dst: IndexTree::new(index_tree::tree::Leaf::default()),

            // low leaf of ex2_val in OIT
            ex2_val_low_leaf_oit: index_tree::tree::Leaf::default(),
            ex2_val_low_leaf_idx_int_oit: 0u64,

            // low leaf of ex2_val in Exchnage1 DST
            ex2_val_low_leaf_dst1: index_tree::tree::Leaf::default(),
            ex2_val_low_leaf_idx_int_dst1: 0u64,
        }
    }
}

impl<F, A2, A3> NCIteration<F, A2, A3>
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits<ReprBits = [u64; 4]> + PartialOrd,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    pub fn get_w0(m: usize) -> NCIteration<F, A2, A3> {
        let oit = IndexTree::new(index_tree::tree::Leaf::default());
        let ex1_dst = IndexTree::new(index_tree::tree::Leaf::default());
        let ex2_dst = get_full_dst(m+1);
        let ex2_val = ex2_dst.inserted_leaves[1].value;

        // Get low leaf of ex2_val in OIT
        let (ex2_val_low_leaf_oit, ex2_val_low_leaf_idx_int_oit) = oit.get_low_leaf(ex2_val);

        // Get low leaf of ex2_val in Exchnage1 DST
        let (ex2_val_low_leaf_dst1, ex2_val_low_leaf_idx_int_dst1) = ex1_dst.get_low_leaf(ex2_val);


        NCIteration {
            oit: oit,
            ex1_dst: ex1_dst,
            ex2_val: ex2_val.unwrap(),
            ex2_dst: ex2_dst,

            // low leaf of ex2_val in OIT
            ex2_val_low_leaf_oit: ex2_val_low_leaf_oit,
            ex2_val_low_leaf_idx_int_oit: ex2_val_low_leaf_idx_int_oit,

            // low leaf of ex2_val in Exchnage1 DST
            ex2_val_low_leaf_dst1: ex2_val_low_leaf_dst1,
            ex2_val_low_leaf_idx_int_dst1: ex2_val_low_leaf_idx_int_dst1,

        }
    }

    pub fn get_next_witness(&self, i: usize) -> NCIteration<F, A2, A3> {
        let mut new_oit = self.oit.clone();
        new_oit.insert_vanilla(self.ex2_val); 

        let ex1_dst = self.ex1_dst.clone();
        let ex2_val = self.ex2_dst.inserted_leaves[i+1].value;
        let ex2_dst = self.ex2_dst.clone();

        // Get low leaf of ex2_val in OIT
        let (ex2_val_low_leaf_oit, ex2_val_low_leaf_idx_int_oit) = new_oit.get_low_leaf(ex2_val);

        // Get low leaf of ex2_val in Exchnage1 DST
        let (ex2_val_low_leaf_dst1, ex2_val_low_leaf_idx_int_dst1) = ex1_dst.get_low_leaf(ex2_val);


        NCIteration {
            oit: new_oit,
            ex1_dst: ex1_dst,
            ex2_val: ex2_val.unwrap(),
            ex2_dst: ex2_dst,

            // low leaf of ex2_val in OIT
            ex2_val_low_leaf_oit: ex2_val_low_leaf_oit,
            ex2_val_low_leaf_idx_int_oit: ex2_val_low_leaf_idx_int_oit,

            // low leaf of ex2_val in Exchnage1 DST
            ex2_val_low_leaf_dst1: ex2_val_low_leaf_dst1,
            ex2_val_low_leaf_idx_int_dst1: ex2_val_low_leaf_idx_int_dst1,
        }
    }

    pub fn get_z0(&self) -> Vec<F> {
        let z0 = vec![self.oit.root, self.ex1_dst.root];
        assert_eq!(z0.len(), 2);
        z0
    }
}

impl<F, A2, A3> StepCircuit<F> for NCIteration<F, A2, A3>
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits + PartialOrd,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    fn arity(&self) -> usize {
        2
    }

    fn get_counter_type(&self) -> nova_snark::StepCounterType {
        nova_snark::StepCounterType::External
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        
        // Check OIT root
        let alloc_oit_root =
            AllocatedNum::alloc(&mut cs.namespace(|| "alloc OIT root"), || Ok(self.oit.root))?;
        cs.enforce(
            || "Check OIT root",
            |lc| lc,
            |lc| lc,
            |lc| lc + z[0].get_variable() - alloc_oit_root.get_variable(),
        );
        
        // Check Exchnage1 DST root
        let alloc_ex1_dst_root =
            AllocatedNum::alloc(&mut cs.namespace(|| "alloc Exchnage1 DST root"), || Ok(self.ex1_dst.root))?;
        cs.enforce(
            || "Check Exchnage1 DST root",
            |lc| lc,
            |lc| lc,
            |lc| lc + z[1].get_variable() - alloc_ex1_dst_root.get_variable(),
        );


        let alloc_val = AllocatedNum::alloc(&mut cs.namespace(|| "alloc Exchnage2 val"), || Ok(self.ex2_val))?;

        // Check non-membership of ex2_val in OIT
        let val_is_non_member_oit = index_tree::circuit::is_non_member::<
            F,
            A3,
            A2,
            DST_HEIGHT,
            Namespace<'_, F, CS::Root>,
        >(
            cs.namespace(|| "val is non-member in OIT"),
            alloc_oit_root.clone(),
            self.oit.clone(),
            alloc_val.clone(),
            self.ex2_val_low_leaf_oit.clone(),
            self.ex2_val_low_leaf_idx_int_oit,
        )?;
        let val_bit_oit =
            AllocatedBit::alloc(cs.namespace(|| "alloc val_bit_oit"), val_is_non_member_oit.get_value())?;
        cs.enforce(
            || "enforce val_bit_oit equal to one",
            |lc| lc,
            |lc| lc,
            |lc| lc + CS::one() - val_bit_oit.get_variable(),
        );

        // Check non-membership of ex2_val in Exchange1 DST
        let val_is_non_member_dst1 = index_tree::circuit::is_non_member::<
            F,
            A3,
            A2,
            DST_HEIGHT,
            Namespace<'_, F, CS::Root>,
        >(
            cs.namespace(|| "val is non-member in Exchnage1 dst"),
            alloc_ex1_dst_root.clone(),
            self.ex1_dst.clone(),
            alloc_val.clone(),
            self.ex2_val_low_leaf_dst1.clone(),
            self.ex2_val_low_leaf_idx_int_dst1
        )?;
        let val_bit_dst1 =
            AllocatedBit::alloc(cs.namespace(|| "alloc val_bit_dst1"), val_is_non_member_dst1.get_value())?;
        cs.enforce(
            || "enforce val_bit_dst1 equal to one",
            |lc| lc,
            |lc| lc,
            |lc| lc + CS::one() - val_bit_dst1.get_variable(),
        );

        // Insert ex2_val in OIT
        let mut next_oit = self.oit.clone();
        index_tree::circuit::insert::<F, A3, A2, DST_HEIGHT, Namespace<'_, F, CS::Root>>(
            cs.namespace(|| "Insert ex2_val"),
            &mut next_oit,
            alloc_oit_root,
            alloc_val,
            self.ex2_val_low_leaf_oit.clone(),
            self.ex2_val_low_leaf_idx_int_oit
        )?;
        let next_oit_root_alloc =
            AllocatedNum::alloc(cs.namespace(|| "oit root var output"), || Ok(next_oit.root))?;

        // Output
        let mut out_vec = vec![];
        out_vec.push(next_oit_root_alloc);
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
    fn test_step_nc() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let iter: NCIteration<Fp, U2, U3> = NCIteration::get_w0(2);

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

        let next_iter = iter.get_next_witness(1);

        let z_2 = next_iter.synthesize(&mut cs.namespace(|| format!("synthesize step 2")), &z_1).unwrap();

        assert_eq!(z_2.len(), iter.arity());
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 91934);
        assert_eq!(cs.num_inputs(), 1);
    }
}
