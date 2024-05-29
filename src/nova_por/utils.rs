use bellpepper_ed25519::curve::AffinePoint;
use bellpepper_ed25519::field::Fe25519;
use ff::{PrimeField, PrimeFieldBits};
use merkle_trees::index_tree;
use merkle_trees::index_tree::tree::IndexTree;
use neptune::sponge::vanilla::{Sponge, SpongeTrait};
use neptune::{Arity, Strength};

use std::fs::File;
use std::io::{self, BufRead};
use std::marker::PhantomData;
use std::path::Path;

use itertools::izip;

use std::cmp::PartialOrd;

use merkle_trees::hash::vanilla::hash;
use merkle_trees::vanilla_tree;
use merkle_trees::vanilla_tree::tree::MerkleTree;

pub const KIT_HEIGHT: usize = 32;
pub const DST_HEIGHT: usize = 32;
pub const UTXO_HEIGHT: usize = 32;
pub const BLOCK_HEIGHT: u128 = 1001; // Insert Block Height for POR

// Code from https://doc.rust-lang.org/rust-by-example/std_misc/file/read_lines.html
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn read_line_at<P>(filename: P, line_number: usize) -> io::Result<Option<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    
    let mut current_line_number = 0;
    
    for line in reader.lines() {
        current_line_number += 1;
        if current_line_number == line_number {
            return Ok(Some(line?));
        }
    }
    
    Ok(None)
}


// Convert AffinePoint to F slice. Representing x as two field elements. Similarly for y.
pub fn point_to_slice<F: PrimeField>(point: &AffinePoint) -> [F; 4] {
    let x_bytes: [u8; 32] = point.x.to_bytes_le();
    let x_lo = u128::from_le_bytes(x_bytes[..16].try_into().unwrap());
    let x_hi = u128::from_le_bytes(x_bytes[16..].try_into().unwrap());

    let y_bytes: [u8; 32] = point.y.to_bytes_le();
    let y_lo = u128::from_le_bytes(y_bytes[..16].try_into().unwrap());
    let y_hi = u128::from_le_bytes(y_bytes[16..].try_into().unwrap());

    vec![x_lo, x_hi, y_lo, y_hi]
        .into_iter()
        .map(|a| F::from_u128(a))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn slice_to_point<F: PrimeField<Repr = [u8; 32]>>(a: [F; 4]) -> AffinePoint {
    let x_lo: [u8; 16] = a[0].to_repr()[..16].try_into().unwrap();
    let x_hi: [u8; 16] = a[1].to_repr()[..16].try_into().unwrap();

    let y_lo: [u8; 16] = a[2].to_repr()[..16].try_into().unwrap();
    let y_hi: [u8; 16] = a[3].to_repr()[..16].try_into().unwrap();

    let x_bytes: [u8; 32] = [x_lo, x_hi].concat().try_into().unwrap();
    let y_bytes: [u8; 32] = [y_lo, y_hi].concat().try_into().unwrap();

    let x = Fe25519::from_bytes_le(&x_bytes);
    let y = Fe25519::from_bytes_le(&y_bytes);

    AffinePoint { x, y }
}

pub fn read_scalar_at_line<F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits<ReprBits = [u64; 4]>>(
    filename: String,
    line_number: usize,
) -> Option<F> {
    assert!(F::CAPACITY > 252);
    
    if let Ok(Some(line)) = read_line_at(filename, line_number) {
        let scalar_bytes = hex::decode(line).unwrap();
        let x = F::from_repr(scalar_bytes.try_into().unwrap()).unwrap();
        Some(x)
    }
    else {
        None
    }

}

pub fn read_point_at_line(filename: String, line_number: usize) -> Option<AffinePoint> {

    if let Ok(Some(line)) = read_line_at(filename, line_number) {
        let coordinates: Vec<&str> = line.trim().split(' ').collect();
        assert_eq!(coordinates.len(), 2);

        let cx: [u8; 32] = hex::decode(String::from(coordinates[0]))
            .expect("Error")
            .as_slice()
            .try_into()
            .unwrap();
        let cy: [u8; 32] = hex::decode(String::from(coordinates[1]))
            .expect("Error")
            .as_slice()
            .try_into()
            .unwrap();

        let p = AffinePoint {
            x: Fe25519::from_bytes_le(&cx),
            y: Fe25519::from_bytes_le(&cy),
        };

        assert!(p.is_on_curve());
        Some(p)
    }
    else {
        None
    }
}

pub fn read_points(filename: String) -> Vec<AffinePoint> {
    let mut points: Vec<AffinePoint> = vec![];

    // read point coordinates from file
    if let Ok(lines) = read_lines(filename) {
        for line in lines {
            if let Ok(coordinates_string) = line {
                let coordinates: Vec<&str> = coordinates_string.trim().split(' ').collect();
                assert_eq!(coordinates.len(), 2);

                let cx: [u8; 32] = hex::decode(String::from(coordinates[0]))
                    .expect("Error")
                    .as_slice()
                    .try_into()
                    .unwrap();
                let cy: [u8; 32] = hex::decode(String::from(coordinates[1]))
                    .expect("Error")
                    .as_slice()
                    .try_into()
                    .unwrap();

                let p = AffinePoint {
                    x: Fe25519::from_bytes_le(&cx),
                    y: Fe25519::from_bytes_le(&cy),
                };

                assert!(p.is_on_curve());
                points.push(p);
            }
        }
    }
    points
}

pub fn read_kit<F: PrimeField + PrimeFieldBits + PartialOrd, AL: Arity<F>, AN: Arity<F>>(
) -> IndexTree<F, KIT_HEIGHT, AL, AN> {
    IndexTree::new(index_tree::tree::Leaf::default())
}

pub fn get_new_dst<F, AX, AL, AN>(
    old_dst: &mut IndexTree<F, DST_HEIGHT, AL, AN>,
    x: &F,
) -> IndexTree<F, DST_HEIGHT, AL, AN>
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits<ReprBits = [u64; 4]> + PartialOrd,
    AX: Arity<F>,
    AL: Arity<F>,
    AN: Arity<F>,
{
    let x_hash_params = Sponge::<F, AX>::api_constants(Strength::Standard);
    let hash_x = hash(vec![*x, F::from_u128(BLOCK_HEIGHT)], &x_hash_params);
    old_dst.insert_vanilla(hash_x);
    old_dst.clone()
}

pub fn get_empty_dst<F, AX, AL, AN>() -> IndexTree<F, DST_HEIGHT, AL, AN>
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits<ReprBits = [u64; 4]> + PartialOrd,
    AX: Arity<F>,
    AL: Arity<F>,
    AN: Arity<F>,
{
    IndexTree::new(index_tree::tree::Leaf::default())
}

pub fn read_utxot<F: PrimeField + PrimeFieldBits, AL: Arity<F>, AN: Arity<F>>(
    commitment_file_name: String,
    public_key_file_name: String,
    public_key_hash_file_name: String,
) -> MerkleTree<F, UTXO_HEIGHT, AL, AN> {
    let empty_leaf_val = vanilla_tree::tree::Leaf::default();
    let mut tree = MerkleTree::new(empty_leaf_val);

    // Read Leaves to Insert
    let c_vec = read_points(commitment_file_name);
    let p_vec = read_points(public_key_file_name);
    let hp_vec = read_points(public_key_hash_file_name);
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
    let c_slice: [F; 4] = point_to_slice(&c);
    let p_slice: [F; 4] = point_to_slice(&p);
    let hp_slice: [F; 4] = point_to_slice(&hp);
    val.extend(c_slice);
    val.extend(p_slice);
    val.extend(hp_slice);
    let leaf = vanilla_tree::tree::Leaf {
        val,
        _arity: PhantomData,
    };
    leaf
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::Fp;
    use ff::Field;
    use generic_array::typenum::{U12, U2, U3};
    use vanilla_tree::tree::Leaf;
    use std::time::{Instant, Duration};

    fn random_point() -> AffinePoint {
        let mut rng = rand::thread_rng();
        let d = hex::decode("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
        assert!(d.is_ok());
        let d_bytes = d.unwrap();
        let d_fe = &Fe25519::from_bytes_le(&d_bytes);
        let point;
        loop {
            let y = Fe25519::random(&mut rng);
            let y_sq = &y.square();
            let x_sq = (y_sq - &Fe25519::one()) * (d_fe * y_sq + Fe25519::one()).invert().unwrap();

            let x = x_sq.sqrt();
            if bool::from(x.is_some()) {
                point = AffinePoint { x: x.unwrap(), y };
                break;
            }
        }
        point
    }

    #[test]
    fn test_point_roundtrip() {
        let point = random_point();
        let slice: [Fp; 4] = point_to_slice(&point);
        let point_rt = slice_to_point(slice);
        assert_eq!(point, point_rt);
    }

    #[test]
    fn test_create_kit() {
        let mut rng = rand::thread_rng();
        let mut tree: IndexTree<Fp, KIT_HEIGHT, U3, U2> = IndexTree::new(index_tree::tree::Leaf::default());

        let num_values = 1000;
        let values: Vec<Fp> = (0..num_values).map(|_| Fp::random(&mut rng)).collect();

        let step_start = Instant::now();
        for new_value in values {
            // Insert new value at next_insertion_index
            tree.insert_vanilla(new_value);
        }
        let end_step = step_start.elapsed();

        println!(
            "Total time to construct KIT with {:?} leaves: {:?}",
            num_values,
            end_step
        );
    }

    #[test]
    fn test_create_utxo_tree() {

        let empty_leaf_val: Leaf<Fp, U12> = vanilla_tree::tree::Leaf::default();
        let mut tree: MerkleTree<Fp, UTXO_HEIGHT, U12, U2> = MerkleTree::new(empty_leaf_val);

        let num_leaf: usize = 1000;

        let mut recursive_snark_prove_time = Duration::ZERO;
        
        for i in 0..num_leaf {
            let c = random_point();
            let p = random_point();
            let hp = random_point();
            
            let step_start = Instant::now();

            let leaf: Leaf<Fp, U12> = get_utxo_leaf(c, p, hp);
            let idx = Fp::from(i as u64);
            let idx_in_bits = vanilla_tree::tree::idx_to_bits(UTXO_HEIGHT, idx);
            let val = leaf;
            tree.insert(idx_in_bits.clone(), &val);

            let end_step = step_start.elapsed();
            recursive_snark_prove_time += end_step;
        }

        println!(
            "Total time to construct UTXO Tree with {:?} leaves: {:?}",
            num_leaf,
            recursive_snark_prove_time
        ); 
    }
}
