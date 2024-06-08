use neptune::Arity;
use ff::{PrimeField, PrimeFieldBits};
use merkle_trees::index_tree;
use merkle_trees::index_tree::tree::IndexTree;
use crate::nova_rcg::utils::DST_HEIGHT;


pub fn get_full_dst<F, AL, AN>(
    m: usize
) -> IndexTree<F, DST_HEIGHT, AL, AN>
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits<ReprBits = [u64; 4]> + PartialOrd,
    AL: Arity<F>,

    AN: Arity<F>,
{
    let mut rng = rand::thread_rng();
    let mut dst = IndexTree::new(index_tree::tree::Leaf::default());
    for _i in 0..m-1 {
        let val = F::random(&mut rng);
        dst.insert_vanilla(val);
    }
    assert_eq!(dst.inserted_leaves.len(), m);
    dst.clone()
}