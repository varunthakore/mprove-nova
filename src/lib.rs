pub mod nova_por;
pub mod nova_pnc;

use bellpepper_ed25519::{curve::AffinePoint, field::Fe25519};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_07::{CryptoRng, Rng, RngCore};
use sha3::Keccak512;

#[derive(Debug)]
pub struct MoneroUtxoWitness {
    pub amount: Scalar,
    pub amount_blinding_factor: Scalar,
    pub private_key: Scalar,
}

#[derive(Debug)]
pub struct MoneroUtxoInfo {
    pub amount_commitment: RistrettoPoint,
    pub public_key: RistrettoPoint,
    pub public_key_hash: RistrettoPoint,
    pub key_image: RistrettoPoint,
}

pub fn gen_utxo_witness<R>(rng: &mut R) -> MoneroUtxoWitness
where
    R: RngCore + CryptoRng,
{
    let amount = Scalar::from(rng.gen::<u64>());
    let amount_blinding_factor = Scalar::random(rng);
    let pk_bytes: [u8; 32] = rng.gen();
    let private_key: Scalar = Scalar::from_bytes_mod_order(pk_bytes);

    MoneroUtxoWitness {
        amount,
        amount_blinding_factor,
        private_key,
    }
}

pub fn utxo_from_witness(w: &MoneroUtxoWitness, h: &RistrettoPoint) -> MoneroUtxoInfo {
    let g = RISTRETTO_BASEPOINT_POINT;
    let amount_commitment = g * w.amount_blinding_factor + h * w.amount;
    let public_key = g * w.private_key;
    let public_key_hash =
        RistrettoPoint::hash_from_bytes::<Keccak512>(public_key.compress().as_bytes());
    let key_image = public_key_hash * w.private_key;

    MoneroUtxoInfo {
        amount_commitment,
        public_key,
        public_key_hash,
        key_image,
    }
}

pub fn ristretto_to_affine_bytes(point: RistrettoPoint) -> ([u8; 32], [u8; 32]) {
    let (x, y, z) = point.get_value();
    let x_fe = Fe25519::from_bytes_le(&x);
    let y_fe = Fe25519::from_bytes_le(&y);
    let z_fe = Fe25519::from_bytes_le(&z);

    let z_fe_inv = z_fe.invert();
    assert!(bool::from(z_fe_inv.is_some()));
    let z_fe_inv = z_fe_inv.unwrap();

    let x_affine = x_fe * z_fe_inv.clone();
    let y_affine = y_fe * z_fe_inv;

    let pfe = AffinePoint {
        x: x_affine.clone(),
        y: y_affine.clone(),
    };
    assert!(pfe.is_on_curve());

    (x_affine.to_bytes_le(), y_affine.to_bytes_le())
}
