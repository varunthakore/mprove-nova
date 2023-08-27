use std::marker::PhantomData;
use std::path::Path;
use std::process::exit;

use bellperson::gadgets::boolean::AllocatedBit;
use bellperson::{
    gadgets::boolean::Boolean, gadgets::num::AllocatedNum, ConstraintSystem, LinearCombination,
    Namespace, SynthesisError,
};
use neptune::sponge::vanilla::{Sponge, SpongeTrait};
use neptune::{Arity, Strength};

use ff::{PrimeField, PrimeFieldBits};
use nova_snark::traits::circuit::StepCircuit;

use crate::nova_por::utils::read_points;

use super::utils::{point_to_slice, slice_to_point};
use bellperson_ed25519::circuit::AllocatedAffinePoint;
use bellperson_ed25519::curve::{AffinePoint, Ed25519Curve};
use merkle_trees::hash::circuit::hash_circuit;
use merkle_trees::index_tree;
use merkle_trees::index_tree::tree::{idx_to_bits, IndexTree};
use merkle_trees::vanilla_tree;
use merkle_trees::vanilla_tree::tree::MerkleTree;

use super::utils::{
    get_utxo_leaf, read_dst, read_keys, read_kit, read_utxot, BLOCK_HEIGHT, DST_HEIGHT, KIT_HEIGHT,
    UTXO_HEIGHT,
};

#[derive(Clone, Debug)]
pub struct PORIteration<F, A1, A2, A3, A4, A12>
where
    F: PrimeField + PrimeFieldBits,
    A1: Arity<F> + Send + Sync,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
    A4: Arity<F> + Send + Sync,
    A12: Arity<F> + Send + Sync,
{
    priv_key: F,
    c: AffinePoint,
    hp: AffinePoint,
    dst: IndexTree<F, DST_HEIGHT, A3, A2>,
    r: F,
    hash_dst_root: F, // H(r, output_dst_root)
    kit: IndexTree<F, KIT_HEIGHT, A3, A2>,
    utxot: MerkleTree<F, UTXO_HEIGHT, A12, A2>,
    utxo_idx: F,
    _phantom1: PhantomData<A1>,
    _phantom2: PhantomData<A4>,
}

impl<F, A1, A2, A3, A4, A12> Default for PORIteration<F, A1, A2, A3, A4, A12>
where
    F: PrimeField + PrimeFieldBits + PartialOrd,
    A1: Arity<F> + Send + Sync,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
    A4: Arity<F> + Send + Sync,
    A12: Arity<F> + Send + Sync,
{
    fn default() -> Self {
        Self {
            priv_key: F::ZERO,
            c: Ed25519Curve::basepoint(),
            hp: Ed25519Curve::basepoint(),
            dst: IndexTree::new(index_tree::tree::Leaf::default()),
            r: F::ZERO,
            hash_dst_root: F::ZERO,
            kit: IndexTree::new(index_tree::tree::Leaf::default()),
            utxot: MerkleTree::new(vanilla_tree::tree::Leaf::default()),
            utxo_idx: F::ZERO,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        }
    }
}

impl<F, A1, A2, A3, A4, A12> PORIteration<F, A1, A2, A3, A4, A12>
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits<ReprBits = [u64; 4]> + PartialOrd,
    A1: Arity<F> + Send + Sync,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
    A4: Arity<F> + Send + Sync,
    A12: Arity<F> + Send + Sync,
{
    pub fn get_iters(num_iters: usize) -> Vec<PORIteration<F, A1, A2, A3, A4, A12>> {
        let private_key_file_name = format!("tmp/x_{num_iters}.txt");
        let commitment_file_name = format!("tmp/c_{num_iters}.txt");
        let public_key_file_name = format!("tmp/p_{num_iters}.txt");
        let public_key_hash_file_name = format!("tmp/hp_{num_iters}.txt");

        let required_files = vec![
            &private_key_file_name,
            &commitment_file_name,
            &public_key_file_name,
            &public_key_hash_file_name,
        ];

        if required_files
            .iter()
            .map(|path| Path::new(path).is_file())
            .any(|x| x == false)
        {
            println!("Values files missing. Please run gen_values before running this example");
            exit(1);
        }

        let keys: Vec<F> = read_keys::<F>(private_key_file_name.clone());
        let comms = read_points(commitment_file_name.clone());
        let hash_ps = read_points(public_key_hash_file_name.clone());
        let (dsts, salts, hash_dst_roots) = read_dst::<F, A2, A3, A2>(private_key_file_name);
        let utxot = read_utxot(
            commitment_file_name,
            public_key_file_name,
            public_key_hash_file_name,
        );
        let kit = read_kit();

        assert_eq!(keys.len(), comms.len());
        assert_eq!(keys.len(), hash_ps.len());
        assert_eq!(keys.len(), dsts.len());

        let mut iters = vec![];

        for i in 0..keys.len() {
            iters.push(PORIteration {
                priv_key: keys[i].clone(),
                c: comms[i].clone(),
                hp: hash_ps[i].clone(),
                dst: dsts[i].clone(),
                r: salts[i],
                hash_dst_root: hash_dst_roots[i].clone(),
                kit: kit.clone(),
                utxot: utxot.clone(),
                utxo_idx: F::from(i as u64),
                _phantom1: PhantomData,
                _phantom2: PhantomData,
            });
        }
        iters
    }

    pub fn get_z0(&self) -> Vec<F> {
        let mut z0 = vec![self.kit.root, self.utxot.root, F::ZERO];
        let zero_comm = Ed25519Curve::basepoint();
        let zero_comm_slice: [F; 4] = point_to_slice(&zero_comm);
        z0.extend(zero_comm_slice);
        assert_eq!(z0.len(), 7);
        z0
    }
}

impl<F, A1, A2, A3, A4, A12> StepCircuit<F> for PORIteration<F, A1, A2, A3, A4, A12>
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits + PartialOrd,
    A1: Arity<F> + Send + Sync,
    A2: Arity<F> + Send + Sync,
    A3: Arity<F> + Send + Sync,
    A4: Arity<F> + Send + Sync,
    A12: Arity<F> + Send + Sync,
{
    fn arity(&self) -> usize {
        7
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let b = Ed25519Curve::basepoint();
        let b_alloc: AllocatedAffinePoint<F> = AllocatedAffinePoint::alloc_affine_point(
            &mut cs.namespace(|| "allocate base point"),
            &b,
        )?;

        // Alloc priv_key
        let x_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "alloc private key"), || {
            Ok(self.priv_key)
        })?;
        let x_bits: Vec<AllocatedBit> = self
            .priv_key
            .to_le_bits()
            .iter()
            .enumerate()
            .map(|(i, b)| {
                AllocatedBit::alloc(
                    &mut cs.namespace(|| format!("alloc bit {} of priv_key", i)),
                    Some(*b),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(x_bits.len(), 256);
        assert_eq!(x_bits[255].get_value().unwrap(), false);
        assert_eq!(x_bits[254].get_value().unwrap(), false);
        assert_eq!(x_bits[253].get_value().unwrap(), false);
        let x_bits: Vec<AllocatedBit> = x_bits[..253].try_into().unwrap(); //the largest curve25519 scalar fits in 253 bits
        let mut lc = LinearCombination::zero();
        let mut coeff = F::ONE;
        for bit in x_bits.iter() {
            lc = lc + (coeff, bit.get_variable());

            coeff = coeff.double();
        }
        lc = lc - x_alloc.get_variable();
        cs.enforce(|| "unpacking constraint", |lc| lc, |lc| lc, |_| lc);
        let x_vec: Vec<Boolean> = x_bits.into_iter().map(Boolean::from).collect();
        let x_vec: Vec<Boolean> = x_vec[..253].try_into().unwrap();
        assert_eq!(x_vec.len(), 253);

        // x is absent in DST
        let alloc_block_height =
            AllocatedNum::alloc(&mut cs.namespace(|| "alloc block height"), || {
                Ok(F::from_u128(BLOCK_HEIGHT))
            })?;
        let x_hash_params = Sponge::<F, A2>::api_constants(Strength::Standard);
        let hash_x = hash_circuit(
            &mut cs.namespace(|| "hash addr"),
            vec![x_alloc, alloc_block_height.clone()],
            &x_hash_params,
        )?;
        let dst_root_var: AllocatedNum<F> =
            AllocatedNum::alloc(cs.namespace(|| "dst root var"), || Ok(self.dst.root))?;
        let x_is_non_member = index_tree::circuit::is_non_member::<
            F,
            A3,
            A2,
            DST_HEIGHT,
            Namespace<'_, F, CS::Root>,
        >(
            cs.namespace(|| "P is non-member"),
            dst_root_var.clone(),
            self.dst.clone(),
            hash_x.clone(),
        )?;
        let x_bit =
            AllocatedBit::alloc(cs.namespace(|| "alloc p bit"), x_is_non_member.get_value())?;
        cs.enforce(
            || "enforce x_bit equal to one",
            |lc| lc,
            |lc| lc,
            |lc| lc + CS::one() - x_bit.get_variable(),
        );

        // Calculate one-time address P = xG
        let p: AllocatedAffinePoint<F> = b_alloc
            .clone()
            .ed25519_scalar_multiplication(&mut cs.namespace(|| "calculate p"), x_vec.clone())?;

        // Check UTXO Tree root is same
        let alloc_utxot_root =
            AllocatedNum::alloc(&mut cs.namespace(|| "alloc UTXOT root"), || {
                Ok(self.utxot.root)
            })?;
        cs.enforce(
            || "UTXO Tree root is same",
            |lc| lc,
            |lc| lc,
            |lc| lc + z[1].get_variable() - alloc_utxot_root.get_variable(),
        );

        // C, P, H(P) is present in Utxo Tree
        let utxo_idx = self.utxo_idx;
        let utxo_idx_in_bits = idx_to_bits(UTXO_HEIGHT, utxo_idx);
        let utxo_path = self.utxot.get_siblings_path(utxo_idx_in_bits.clone());

        let utxo_root_var: AllocatedNum<F> =
            AllocatedNum::alloc(cs.namespace(|| "root"), || Ok(self.utxot.root))?;
        let utxo_leaf: Vec<F> =
            get_utxo_leaf::<F, A12>(self.c.clone(), p.get_point(), self.hp.clone()).val;
        let utxo_leaf_var: Vec<AllocatedNum<F>> = utxo_leaf
            .into_iter()
            .enumerate()
            .map(|(i, s)| AllocatedNum::alloc(cs.namespace(|| format!("leaf vec {}", i)), || Ok(s)))
            .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;
        let utxo_siblings_var: Vec<AllocatedNum<F>> = utxo_path
            .siblings
            .into_iter()
            .enumerate()
            .map(|(i, s)| AllocatedNum::alloc(cs.namespace(|| format!("sibling {}", i)), || Ok(s)))
            .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;

        let utxo_idx_var: Vec<AllocatedBit> = utxo_idx_in_bits
            .into_iter()
            .enumerate()
            .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("idx {}", i)), Some(b)))
            .collect::<Result<Vec<AllocatedBit>, SynthesisError>>()?;

        let utxo_is_valid = Boolean::from(vanilla_tree::circuit::path_verify_circuit::<
            F,
            A12,
            A2,
            UTXO_HEIGHT,
            CS,
        >(
            cs,
            utxo_root_var,
            utxo_leaf_var,
            utxo_idx_var,
            utxo_siblings_var,
        )?);
        Boolean::enforce_equal(
            cs.namespace(|| "utxo is present"),
            &utxo_is_valid,
            &Boolean::constant(true),
        )?;

        // Calculate I = x * H(P)
        let hp_alloc = AllocatedAffinePoint::alloc_affine_point(
            &mut cs.namespace(|| "allocate H(P)"),
            &self.hp,
        )?;
        let key_img: AllocatedAffinePoint<F> = hp_alloc
            .clone()
            .ed25519_scalar_multiplication(&mut cs.namespace(|| "calculate key image"), x_vec)?;

        // Check KIT Root is same
        let alloc_kit_root =
            AllocatedNum::alloc(&mut cs.namespace(|| "alloc KIT root"), || Ok(self.kit.root))?;
        cs.enforce(
            || "KIT root is same",
            |lc| lc,
            |lc| lc,
            |lc| lc + z[0].get_variable() - alloc_kit_root.get_variable(),
        );

        // Check I is absent in KIT
        let key_img_slice: [F; 4] = point_to_slice(&key_img.get_point());
        let key_img_alloc: Vec<AllocatedNum<F>> = key_img_slice
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                AllocatedNum::alloc(cs.namespace(|| format!("key img vec {}", i)), || Ok(s))
            })
            .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;
        let key_img_hash_params = Sponge::<F, A4>::api_constants(Strength::Standard);
        let hash_key_img = hash_circuit(
            &mut cs.namespace(|| "hash key image"),
            key_img_alloc,
            &key_img_hash_params,
        )?;
        let kit_root_var: AllocatedNum<F> =
            AllocatedNum::alloc(cs.namespace(|| "kit root var"), || Ok(self.kit.root))?;
        let key_img_is_non_member = index_tree::circuit::is_non_member::<
            F,
            A3,
            A2,
            KIT_HEIGHT,
            Namespace<'_, F, CS::Root>,
        >(
            cs.namespace(|| "I is non-member"),
            kit_root_var.clone(),
            self.kit.clone(),
            hash_key_img.clone(),
        )?;
        let k_bit = AllocatedBit::alloc(
            cs.namespace(|| "alloc k bit"),
            key_img_is_non_member.get_value(),
        )?;
        cs.enforce(
            || "enforce k_bit equal to one",
            |lc| lc,
            |lc| lc,
            |lc| lc + CS::one() - k_bit.get_variable(),
        );

        // Insert x in DST
        let mut next_dst = self.dst.clone();
        index_tree::circuit::insert::<F, A3, A2, DST_HEIGHT, Namespace<'_, F, CS::Root>>(
            cs.namespace(|| "Insert P"),
            &mut next_dst,
            dst_root_var,
            hash_x.clone(),
        )?;

        // Sum commitments to amount
        let basepoint_slice: [F; 4] = point_to_slice(&Ed25519Curve::basepoint());
        let mut v = vec![];
        v.push(z[3].get_value().unwrap_or(basepoint_slice[0]));
        v.push(z[4].get_value().unwrap_or(basepoint_slice[1]));
        v.push(z[5].get_value().unwrap_or(basepoint_slice[2]));
        v.push(z[6].get_value().unwrap_or(basepoint_slice[3]));
        let c_total = slice_to_point(v.as_slice().try_into().unwrap());
        let alloc_c_total = AllocatedAffinePoint::alloc_affine_point(
            &mut cs.namespace(|| "Alloc c_total"),
            &c_total,
        )?;
        let alloc_c =
            AllocatedAffinePoint::alloc_affine_point(&mut cs.namespace(|| "alloc c"), &self.c)?;
        let c_new_total = AllocatedAffinePoint::ed25519_point_addition(
            &mut cs.namespace(|| "Add commitments"),
            &alloc_c,
            &alloc_c_total,
        )?;
        let c_new_total_vec: Vec<AllocatedNum<F>> = point_to_slice(&c_new_total.get_point())
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                AllocatedNum::alloc(cs.namespace(|| format!("c_new_total_vec {}", i)), || Ok(s))
            })
            .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;

        // Output
        let mut out_vec = vec![];
        let r_alloc = AllocatedNum::alloc(cs.namespace(|| "salt"), || Ok(self.r))?;
        let dst_root_alloc =
            AllocatedNum::alloc(cs.namespace(|| "dst root var output"), || Ok(next_dst.root))?;
        let dst_root_hash_params = Sponge::<F, A2>::api_constants(Strength::Standard);
        let hash_dst_root = hash_circuit(
            &mut cs.namespace(|| "hash dst root"),
            vec![r_alloc.clone(), dst_root_alloc],
            &dst_root_hash_params,
        )?;
        out_vec.push(alloc_kit_root);
        out_vec.push(alloc_utxot_root);
        out_vec.push(hash_dst_root);
        out_vec.extend(c_new_total_vec);

        Ok(out_vec)
    }

    fn output(&self, z: &[F]) -> Vec<F> {
        assert_eq!(z.len(), 7);
        assert_eq!(z[0], self.kit.root);
        assert_eq!(z[1], self.utxot.root);

        let mut out = vec![self.kit.root, self.utxot.root, self.hash_dst_root];
        let c_total = slice_to_point(z[3..7].try_into().unwrap());
        let c_total_new = c_total + self.c.clone();
        let c_total_new_slice: [F; 4] = point_to_slice(&c_total_new);
        out.extend(c_total_new_slice);
        out
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };

    use crate::{gen_utxo_witness, ristretto_to_affine_bytes, utxo_from_witness};

    use super::*;
    use bellperson::gadgets::test::TestConstraintSystem;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint};
    use generic_array::typenum::{U1, U12, U2, U3, U4};
    use pasta_curves::Fp;
    use sha2::Sha512;

    #[test]
    fn test_step() {
        let mut cs = TestConstraintSystem::<Fp>::new();

        let num_iters = 1;
        let file_err_msg = "Unable to create or write to file";
        // let amount_file_name = format!("tmp/a_{num_iters}.txt");
        let private_key_file_name = format!("tmp/x_{num_iters}.txt");
        let commitment_file_name = format!("tmp/c_{num_iters}.txt");
        let public_key_file_name = format!("tmp/p_{num_iters}.txt");
        let public_key_hash_file_name = format!("tmp/hp_{num_iters}.txt");
        let keyimage_file_name = format!("tmp/i_{num_iters}.txt");

        // let amount_file = File::create(amount_file_name).expect(file_err_msg);
        // let mut amount_buf = BufWriter::new(amount_file);
        let private_key_file = File::create(private_key_file_name).expect(file_err_msg);
        let mut private_key_buf = BufWriter::new(private_key_file);
        let commitment_file = File::create(commitment_file_name).expect(file_err_msg);
        let mut commitment_buf = BufWriter::new(commitment_file);
        let public_key_file = File::create(public_key_file_name).expect(file_err_msg);
        let mut public_key_buf = BufWriter::new(public_key_file);
        let public_key_hash_file = File::create(public_key_hash_file_name).expect(file_err_msg);
        let mut public_key_hash_buf = BufWriter::new(public_key_hash_file);
        let keyimage_file = File::create(keyimage_file_name).expect(file_err_msg);
        let mut keyimage_buf = BufWriter::new(keyimage_file);

        let g = RISTRETTO_BASEPOINT_POINT;
        // Placeholder for the point H which is used to generate Pedersen commitments of the amount
        let h = RistrettoPoint::hash_from_bytes::<Sha512>(g.compress().as_bytes());

        let mut rng = rand_07::thread_rng();

        for _i in 0..num_iters {
            let wit = gen_utxo_witness(&mut rng);
            let utxo_info = utxo_from_witness(&wit, &h);

            let x_bytes = wit.private_key.as_bytes();
            writeln!(private_key_buf, "{}", hex::encode(x_bytes)).expect(file_err_msg);

            // Write commitments
            let (cx, cy) = ristretto_to_affine_bytes(utxo_info.amount_commitment);
            writeln!(commitment_buf, "{} {}", hex::encode(cx), hex::encode(cy))
                .expect(file_err_msg);

            // Write P
            let (px, py) = ristretto_to_affine_bytes(utxo_info.public_key);
            writeln!(public_key_buf, "{} {}", hex::encode(px), hex::encode(py))
                .expect(file_err_msg);

            // Write H_P
            let (hpx, hpy) = ristretto_to_affine_bytes(utxo_info.public_key_hash);
            writeln!(
                public_key_hash_buf,
                "{} {}",
                hex::encode(hpx),
                hex::encode(hpy)
            )
            .expect(file_err_msg);

            // Write Key Images
            let (ix, iy) = ristretto_to_affine_bytes(utxo_info.key_image);
            writeln!(keyimage_buf, "{} {}", hex::encode(ix), hex::encode(iy)).expect(file_err_msg);
        }
        let _ = private_key_buf.flush();
        let _ = commitment_buf.flush();
        let _ = public_key_buf.flush();
        let _ = public_key_hash_buf.flush();
        let _ = keyimage_buf.flush();

        let iters: Vec<PORIteration<Fp, U1, U2, U3, U4, U12>> = PORIteration::get_iters(num_iters);

        for i in 0..num_iters {
            let mut z_in: Vec<Fp> = vec![
                iters[i].kit.root.clone(),
                iters[i].utxot.root.clone(),
                iters[i].hash_dst_root,
            ];
            let basept: [Fp; 4] = point_to_slice(&Ed25519Curve::basepoint());
            z_in.extend(basept);
            let alloc_z_in: Vec<AllocatedNum<Fp>> = z_in
                .iter()
                .enumerate()
                .map(|(j, v)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("{i} : alloc input {j}")), || {
                        Ok(*v)
                    })
                    .unwrap()
                })
                .collect();

            let z_out = iters[i]
                .synthesize(
                    &mut cs.namespace(|| format!("synthesize step {}", i)),
                    &alloc_z_in,
                )
                .unwrap();

            let z_out_exp = iters[i].output(&z_in);
            assert_eq!(z_out.len(), z_out_exp.len());
            for i in 0..z_out.len() {
                assert_eq!(z_out[i].get_value().unwrap(), z_out_exp[i]);
            }
            println!("iteration {} done", i);
        }

        assert!(cs.is_satisfied());
        println!("Num constraints = {:?}", cs.num_constraints());
        println!("Num inputs = {:?}", cs.num_inputs());
    }
}
