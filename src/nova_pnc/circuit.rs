use bellpepper::gadgets::boolean::AllocatedBit;
use bellpepper_core::{
    num::AllocatedNum, ConstraintSystem, Namespace, SynthesisError,
};
use neptune::Arity;
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::traits::circuit::StepCircuit;
use merkle_trees::index_tree;
use merkle_trees::index_tree::tree::{IndexTree, idx_to_bits};
use crate::nova_por::utils::DST_HEIGHT;
use super::utils::get_full_dst;

#[derive(Clone, Debug)]
pub struct PNCIteration<F, A2, A3>
where
    F: PrimeField + PrimeFieldBits,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    pub oit: IndexTree<F, DST_HEIGHT, A3, A2>,
    pub ex1_val: F,
    pub ex1_dst: IndexTree<F, DST_HEIGHT, A3, A2>,
    pub ex2_dst: IndexTree<F, DST_HEIGHT, A3, A2>,
}

impl<F, A2, A3> Default for PNCIteration<F, A2, A3>
where
    F: PrimeField + PrimeFieldBits + PartialOrd,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    fn default() -> Self {
        Self {
            oit: IndexTree::new(index_tree::tree::Leaf::default()),
            ex1_val: F::ZERO,
            ex1_dst: IndexTree::new(index_tree::tree::Leaf::default()),
            ex2_dst: IndexTree::new(index_tree::tree::Leaf::default()),
        }
    }
}

impl<F, A2, A3> PNCIteration<F, A2, A3>
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits<ReprBits = [u64; 4]> + PartialOrd,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
{
    pub fn get_w0(m: usize) -> PNCIteration<F, A2, A3> {
        let oit = IndexTree::new(index_tree::tree::Leaf::default());
        let ex1_dst = get_full_dst(m+1);
        let ex2_dst = IndexTree::new(index_tree::tree::Leaf::default());


        PNCIteration {
            oit: oit,
            ex1_val: ex1_dst.inserted_leaves[1].value.unwrap(),
            ex1_dst: ex1_dst,
            ex2_dst: ex2_dst,
        }
    }

    pub fn get_next_witness(&self, i: usize) -> PNCIteration<F, A2, A3> {
        let mut new_oit = self.oit.clone();
        new_oit.insert_vanilla(self.ex1_val); 

        PNCIteration {
            oit: new_oit,
            ex1_val: self.ex1_dst.inserted_leaves[i+1].value.unwrap(),
            ex1_dst: self.ex1_dst.clone(),
            ex2_dst: self.ex2_dst.clone(),
        }
    }

    pub fn get_z0(&self) -> Vec<F> {
        let z0 = vec![self.oit.root, self.ex1_dst.root, self.ex2_dst.root];
        assert_eq!(z0.len(), 3);
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
        3
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

        // Check Exchnage2 DST root
        let alloc_ex2_dst_root =
            AllocatedNum::alloc(&mut cs.namespace(|| "alloc Exchnage2 DST root"), || Ok(self.ex2_dst.root))?;
        cs.enforce(
            || "Check Exchnage2 DST root",
            |lc| lc,
            |lc| lc,
            |lc| lc + z[2].get_variable() - alloc_ex2_dst_root.get_variable(),
        );

        // Check membership of ex1_val in Exchnage1 DST
        let alloc_val = AllocatedNum::alloc(&mut cs.namespace(|| "alloc Exchnage1 val"), || Ok(self.ex1_val))?;
        let (leaf, leaf_idx_int) = self.ex1_dst.get_leaf(Some(self.ex1_val));
        let leaf_idx = idx_to_bits(DST_HEIGHT, F::from(leaf_idx_int));
        let leaf_siblings = self.ex1_dst.get_siblings_path(leaf_idx.clone()).siblings;
        let alloc_leaf = index_tree::circuit::AllocatedLeaf::alloc_leaf(
            &mut cs.namespace(|| "alloc leaf"), 
            leaf
        );
        let leaf_siblings_var: Vec<AllocatedNum<F>> = leaf_siblings
            .into_iter()
            .enumerate()
            .map(|(i, s)| AllocatedNum::alloc(cs.namespace(|| format!("sibling {}", i)), || Ok(s)))
            .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;

        let leaf_idx_var: Vec<AllocatedBit> = leaf_idx
            .into_iter()
            .enumerate()
            .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("idx {}", i)), Some(b)))
            .collect::<Result<Vec<AllocatedBit>, SynthesisError>>()?;
        let val_is_member_dst1 = index_tree::circuit::is_member::<
            F,
            A3,
            A2,
            DST_HEIGHT,
            Namespace<'_, F, CS::Root>,
        >(
            &mut cs.namespace(|| "val is member in Ex1 dst"),
            alloc_ex1_dst_root.clone(),
            alloc_leaf.clone(),
            leaf_idx_var,
            leaf_siblings_var.clone(),
        )?;
        let val_bit_dst =
            AllocatedBit::alloc(cs.namespace(|| "alloc val_bit_dst"), val_is_member_dst1.get_value())?;
        cs.enforce(
            || "enforce val_bit_dst equal to one",
            |lc| lc,
            |lc| lc,
            |lc| lc + CS::one() - val_bit_dst.get_variable(),
        );

        // Check non-membership of ex1_val in OIT
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
        )?;
        let val_bit_oit =
            AllocatedBit::alloc(cs.namespace(|| "alloc val_bit_oit"), val_is_non_member_oit.get_value())?;
        cs.enforce(
            || "enforce val_bit_oit equal to one",
            |lc| lc,
            |lc| lc,
            |lc| lc + CS::one() - val_bit_oit.get_variable(),
        );

        // Check non-membership of ex1_val in Exchnage2 DST
        let val_is_non_member_dst2 = index_tree::circuit::is_non_member::<
            F,
            A3,
            A2,
            DST_HEIGHT,
            Namespace<'_, F, CS::Root>,
        >(
            cs.namespace(|| "val is non-member in Exchnage2 dst"),
            alloc_ex2_dst_root.clone(),
            self.ex2_dst.clone(),
            alloc_val.clone(),
        )?;
        let val_bit_dst2 =
            AllocatedBit::alloc(cs.namespace(|| "alloc val_bit_dst2"), val_is_non_member_dst2.get_value())?;
        cs.enforce(
            || "enforce val_bit_dst2 equal to one",
            |lc| lc,
            |lc| lc,
            |lc| lc + CS::one() - val_bit_dst2.get_variable(),
        );

        // Insert ex1_val in OIT
        let mut next_oit = self.oit.clone();
        index_tree::circuit::insert::<F, A3, A2, DST_HEIGHT, Namespace<'_, F, CS::Root>>(
            cs.namespace(|| "Insert ex1_val"),
            &mut next_oit,
            alloc_oit_root,
            alloc_val,
        )?;
        let next_oit_root_alloc =
            AllocatedNum::alloc(cs.namespace(|| "oit root var output"), || Ok(next_oit.root))?;

        // Output
        let mut out_vec = vec![];
        out_vec.push(next_oit_root_alloc);
        out_vec.push(z[1].clone());
        out_vec.push(z[2].clone());
        assert_eq!(out_vec.len(), 3);

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
        let iter: PNCIteration<Fp, U2, U3> = PNCIteration::get_w0(2);

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
        println!("Num constraints = {:?}", cs.num_constraints());
        println!("Num inputs = {:?}", cs.num_inputs());
    }
}
