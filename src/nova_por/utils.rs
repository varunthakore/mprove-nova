use merkle_trees::index_tree;
use merkle_trees::index_tree::tree::IndexTree;
use neptune::{Strength, Arity};
use neptune::sponge::vanilla::{SpongeTrait, Sponge};
use ff::{PrimeField, PrimeFieldBits};
use bp_ed25519::curve::AffinePoint;
use bp_ed25519::field::Fe25519;
use crypto_bigint::{U256, CheckedAdd, CheckedMul};

use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;

use itertools::izip;

use std::cmp::PartialOrd;

use merkle_trees::vanilla_tree;
use merkle_trees::vanilla_tree::tree::MerkleTree;
use merkle_trees::hash::vanilla::hash;

pub const KIT_HEIGHT: usize = 32;
pub const DST_HEIGHT: usize = 32;
pub const UTXO_HEIGHT: usize = 32;
pub const BLOCK_HEIGHT: u128 = 1001; // Insert Block Height for POR

// Convert AffinePoint to Vec<F>. Representing x as two feild elements. Similarly for y.
pub fn point_to_vec<F: PrimeField + PrimeFieldBits>(point: AffinePoint) -> Vec<F> {
    let x_bytes: [u8; 32] = point.get_x().to_repr().try_into().unwrap();
    let x: Vec<u128> = x_bytes
        .clone()
        .chunks(16)
        .map(|a| u128::from_le_bytes(<&[u8] as TryInto<[u8; 16]>>::try_into(a).unwrap()))
        .collect();
    assert_eq!(x.len(), 2);
    assert_eq!(
        U256::from(x[0])
            .checked_add(
                &(&U256::from(1u64) << 128)
                    .checked_mul(&U256::from(x[1]))
                    .unwrap()
            )
            .unwrap(),
        point.get_x().get_value()
    );

    let y_bytes: [u8; 32] = point.get_y().to_repr().try_into().unwrap();
    let y: Vec<u128> = y_bytes
        .clone()
        .chunks(16)
        .map(|a| u128::from_le_bytes(<&[u8] as TryInto<[u8; 16]>>::try_into(a).unwrap()))
        .collect();
    assert_eq!(y.len(), 2);
    assert_eq!(
        U256::from(y[0])
            .checked_add(
                &(&U256::from(1u64) << 128)
                    .checked_mul(&U256::from(y[1]))
                    .unwrap()
            )
            .unwrap(),
        point.get_y().get_value()
    );

    let mut out_vec: Vec<F> = vec![];
    out_vec.push(F::from_u128(x[0]));
    out_vec.push(F::from_u128(x[1]));
    out_vec.push(F::from_u128(y[0]));
    out_vec.push(F::from_u128(y[1]));
    assert_eq!(out_vec.len(), 4);
    out_vec
}

pub fn vec_to_point<F: PrimeField<Repr = [u8; 32]>>(vec: Vec<F>) -> AffinePoint {
    assert_eq!(vec.len(), 4);
    let x0 = vec[0].to_repr();
    let x1 = vec[1].to_repr();
    let (x_bytes_0, _) = x0.split_at(16);
    let (x_bytes_1, _) = x1.split_at(16);

    let y0 = vec[2].to_repr();
    let y1 = vec[3].to_repr();
    let (y_bytes_0, _) = y0.split_at(16);
    let (y_bytes_1, _) = y1.split_at(16);

    let mut x_bytes: [u8; 32] = [0; 32];
    let mut y_bytes: [u8; 32] = [0; 32];

    for i in 0..16 {
        x_bytes[i] = x_bytes_0[i];
        x_bytes[i+16] = x_bytes_1[i];
        y_bytes[i] = y_bytes_0[i];
        y_bytes[i+16] = y_bytes_1[i];
    }

    let x_fe = Fe25519::from_repr(x_bytes).unwrap();
    let y_fe = Fe25519::from_repr(y_bytes).unwrap();

    let point = AffinePoint::coord_to_point(x_fe, y_fe);
    point
}

pub fn read_keys<F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits<ReprBits = [u64; 4]>>() -> Vec<F> {
    let mut keys: Vec<F> = vec![];
    let mut x_file = File::open("./src/gen_values/x.txt").unwrap();
    let mut x_buffer = vec![0; 32];
    loop {
        let bytes_read = x_file.read(&mut x_buffer).unwrap();
        if bytes_read == 0 {
            break;
        }
        let d: [u8; 32] = x_buffer[..bytes_read].try_into().unwrap();
        let x = F::from_repr(d);
        assert_eq!(x.is_some().unwrap_u8(), 1);
        keys.push(x.unwrap());
    }
    keys
}

pub fn read_comm() -> Vec<AffinePoint> {
    let mut c_vec: Vec<AffinePoint> = vec![];
    let mut c_file = File::open("src/gen_values/c.txt").unwrap();
    let mut c_buffer = vec![0; 64];
    loop {
        let cbytes = c_file.read(&mut c_buffer).unwrap();
        if cbytes == 0 {
            break;
        }
        let ctemp: [u8; 64] = c_buffer[..cbytes].try_into().unwrap();
        let cx: [u8; 32] = ctemp[..32].try_into().unwrap();
        let cy: [u8; 32] = ctemp[32..64].try_into().unwrap();
        let c = AffinePoint::coord_to_point(
            Fe25519::from_repr(cx).unwrap(),
            Fe25519::from_repr(cy).unwrap(),
        );
        assert!(c.is_on_curve());
        c_vec.push(c);
    }
    c_vec
}

pub fn read_addr() -> Vec<AffinePoint> {
    let mut p_vec: Vec<AffinePoint> = vec![];
    let mut p_file = File::open("src/gen_values/p.txt").unwrap();
    let mut p_buffer = vec![0; 64];
    loop {
        let pbytes = p_file.read(&mut p_buffer).unwrap();
        if pbytes == 0 {
            break;
        }
        let ptemp: [u8; 64] = p_buffer[..pbytes].try_into().unwrap();
        let px: [u8; 32] = ptemp[..32].try_into().unwrap();
        let py: [u8; 32] = ptemp[32..64].try_into().unwrap();
        let p = AffinePoint::coord_to_point(
            Fe25519::from_repr(px).unwrap(),
            Fe25519::from_repr(py).unwrap(),
        );
        assert!(p.is_on_curve());
        p_vec.push(p);
    }
    p_vec
}

pub fn read_hash_addr() -> Vec<AffinePoint> {
    let mut hp_vec: Vec<AffinePoint> = vec![];
    let mut hp_file = File::open("src/gen_values/hp.txt").unwrap();
    let mut hp_buffer = vec![0; 64];
    loop {
        let hpbytes = hp_file.read(&mut hp_buffer).unwrap();
        if hpbytes == 0 {
            break;
        }
        let hptemp: [u8; 64] = hp_buffer[..hpbytes].try_into().unwrap();
        let hpx: [u8; 32] = hptemp[..32].try_into().unwrap();
        let hpy: [u8; 32] = hptemp[32..64].try_into().unwrap();
        let hp = AffinePoint::coord_to_point(
            Fe25519::from_repr(hpx).unwrap(),
            Fe25519::from_repr(hpy).unwrap(),
        );
        assert!(hp.is_on_curve());
        hp_vec.push(hp);
    }
    hp_vec
}
pub fn read_kit<F: PrimeField + PrimeFieldBits + PartialOrd, AL:Arity<F>, AN:Arity<F>>() -> IndexTree<F, KIT_HEIGHT, AL, AN> {
    IndexTree::new(index_tree::tree::Leaf::default())
}

pub fn read_dst<F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits<ReprBits = [u64; 4]> + PartialOrd, AX: Arity<F>, AL:Arity<F>, AN:Arity<F>>() -> (Vec<IndexTree<F, DST_HEIGHT, AL, AN>>, Vec<F>, Vec<F>) {
    let mut rng = rand::thread_rng();
    let x_hash_params = Sponge::<F, AX>::api_constants(Strength::Standard);
    let root_hash_params = Sponge::<F, AN>::api_constants(Strength::Standard);
    let mut hash_output_roots: Vec<F> = vec![];
    let mut salts: Vec<F> = vec![];
    let keys: Vec<F> = read_keys();
    let mut trees = vec![];
    let mut empty_tree = IndexTree::new(index_tree::tree::Leaf::default());
    trees.push(empty_tree.clone());

    for x in keys.iter().rev().skip(1).rev() {
        let hash_x = hash(vec![*x, F::from_u128(BLOCK_HEIGHT)], &x_hash_params);
        empty_tree.insert_vanilla(hash_x);
        trees.push(empty_tree.clone());

        // hash output dst
        let r = F::random(&mut rng);
        salts.push(r);
        let hash_root = hash(vec![r, empty_tree.root.clone()], &root_hash_params);
        hash_output_roots.push(hash_root);
    }

    // last insertion into index tree
    let hash_x = hash(
        vec![keys[keys.len() - 1], F::from_u128(BLOCK_HEIGHT)],
            &x_hash_params,
    );
    empty_tree.insert_vanilla(hash_x);

    // last hash root
    let r = F::random(&mut rng);
    salts.push(r);
    let hash_root = hash(vec![r, empty_tree.root.clone()], &root_hash_params);
    hash_output_roots.push(hash_root);

    assert_eq!(keys.len(), trees.len());
    assert_eq!(keys.len(), hash_output_roots.len());
    assert_eq!(keys.len(), salts.len());

    (trees, salts, hash_output_roots)
}

pub fn read_utxot<F: PrimeField + PrimeFieldBits,  AL:Arity<F>, AN:Arity<F>>() -> MerkleTree<F, UTXO_HEIGHT, AL, AN> {
    let empty_leaf_val = vanilla_tree::tree::Leaf::default();
    let mut tree = MerkleTree::new(empty_leaf_val);

    // Read Leaves to Insert
    let c_vec = read_comm();
    let p_vec = read_addr();
    let hp_vec = read_hash_addr();
    assert_eq!(c_vec.len(), p_vec.len());
    assert_eq!(c_vec.len(), hp_vec.len());
    let mut leaf_vec = vec![];
    for (c, p, hp) in izip!(c_vec.clone(), p_vec.clone(), hp_vec.clone()) {
        let leaf = get_utxo_leaf(c, p, hp);
        leaf_vec.push(leaf);
    }
    assert_eq!(c_vec.len(), leaf_vec.len());

    for (i, leaf) in leaf_vec.iter().enumerate() {
        let idx = F::from(i as u64);
        let idx_in_bits = vanilla_tree::tree::idx_to_bits(UTXO_HEIGHT, idx);
        let val = leaf;
        tree.insert(idx_in_bits.clone(), &val);

        let path = tree.get_siblings_path(idx_in_bits.clone());

        assert!(path.verify(idx_in_bits.clone(), &val, tree.root));
    }

    tree
}

pub fn get_utxo_leaf<F: PrimeField + PrimeFieldBits, A: Arity<F>>(
    c: AffinePoint,
    p: AffinePoint,
    hp: AffinePoint,
) -> vanilla_tree::tree::Leaf<F, A> {
    let mut val = vec![];
    let c_vec: Vec<F> = point_to_vec(c);
    let p_vec: Vec<F> = point_to_vec(p);
    let hp_vec: Vec<F> = point_to_vec(hp);
    val.extend(c_vec);
    val.extend(p_vec);
    val.extend(hp_vec);
    let leaf = vanilla_tree::tree::Leaf {
        val: val,
        _arity: PhantomData,
    };
    leaf
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pasta_curves::Fp;
    use crypto_bigint::Encoding;

    fn random_point() -> AffinePoint {
        let mut rng = rand::thread_rng();
        let d = U256::to_le_bytes(&U256::from_be_hex("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"));
        let d_fe = Fe25519::from_repr(d).unwrap();
        let point;
        loop {
            let y = Fe25519::random(&mut rng);
            let y_sq = y.square();
            let x_sq = (y_sq - Fe25519::ONE) * (d_fe*y_sq + Fe25519::ONE).invert().unwrap();

            let x = x_sq.sqrt();
            if bool::from(x.is_some()) {
                point = AffinePoint::coord_to_point(x.unwrap(), y);
                break;
            }
        }
        point
    }

    #[test]
    fn test_point_roundtrip() {
        let point = random_point();
        let vec: Vec<Fp> = point_to_vec(point);
        let point_rt = vec_to_point(vec);
        assert_eq!(point, point_rt);
    }
}