// Usage: cargo r -r gen_vales [number_of_values]

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use sha2::Sha512;
use sha3::Keccak512;

use bp_ed25519::field::Fe25519;
use bp_ed25519::curve::AffinePoint;
use rand_07::{self, Rng};

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use ff::{Field, PrimeField};

pub fn scalar_to_bytes(s: Scalar) -> [u8; 32] {
    Scalar::to_bytes(&s)
}

fn ristretto_to_affine(point: RistrettoPoint) -> ([u8; 32], [u8; 32]) {
    let (x, y, z) = point.get_value();
    let x_fe = Fe25519::from_repr(x);
    let y_fe = Fe25519::from_repr(y);
    let z_fe = Fe25519::from_repr(z);

    assert!(bool::from(x_fe.is_some()));
    assert!(bool::from(y_fe.is_some()));
    assert!(bool::from(z_fe.is_some()));

    let x_fe = x_fe.unwrap();
    let y_fe = y_fe.unwrap();
    let z_fe = z_fe.unwrap();

    let z_fe_inv = z_fe.invert();
    assert!(bool::from(z_fe_inv.is_some()));
    let z_fe_inv = z_fe_inv.unwrap();

    let x_affine = x_fe * z_fe_inv ;
    let y_affine = y_fe * z_fe_inv;

    let pfe = AffinePoint::coord_to_point(x_affine, y_affine);
    assert!(pfe.is_on_curve());

    (x_affine.to_repr(), y_affine.to_repr())

}

fn main() {
    let mut rng = rand_07::thread_rng();
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 3);
    let num_gen: usize = match args[2].parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Invalid integer argument provided.");
            return;
        }
    };

    // Remove old files if they exists
    std::fs::remove_file("./src/gen_values/a.txt").ok();
    std::fs::remove_file("./src/gen_values/x.txt").ok();
    std::fs::remove_file("./src/gen_values/c.txt").ok();
    std::fs::remove_file("./src/gen_values/p.txt").ok();
    std::fs::remove_file("./src/gen_values/hp.txt").ok();
    std::fs::remove_file("./src/gen_values/i.txt").ok();

    for i in 0..num_gen {
        // Copied from https://github.com/suyash67/MProve-Ristretto/tree/master/src/proofs
        // generate random ammounts from 2^64 -1
        let a: Scalar = Scalar::from(rng.gen::<u64>());
        // generate blinding factors
        let r: Scalar = Scalar::random(&mut rng);
        // generate secret keys
        let random_bytes: [u8; 32] = rng.gen();
        let x: Scalar = Scalar::from_bytes_mod_order(random_bytes);
        // G, H - curve points for generating outputs and key-images
        let g = constants::RISTRETTO_BASEPOINT_POINT;
        let h = RistrettoPoint::hash_from_bytes::<Sha512>(g.compress().as_bytes());

        let c = g * r + h * a;
        let p = g * x;
        let hp = RistrettoPoint::hash_from_bytes::<Keccak512>(p.compress().as_bytes());
        let key_img = hp * x;

        // Write Ammounts
        let a_bytes = scalar_to_bytes(a);
        let mut afile = OpenOptions::new()
            .create(true)
            .append(true)
            .open("./src/gen_values/a.txt")
            .unwrap();
        afile.write_all(&a_bytes).unwrap();

        // Write keys
        let x_bytes = scalar_to_bytes(x);
        let mut xfile = OpenOptions::new()
            .create(true)
            .append(true)
            .open("./src/gen_values/x.txt")
            .unwrap();
        xfile.write_all(&x_bytes).unwrap();

        // Write C
        let (cx, cy) = ristretto_to_affine(c);
        let mut cfile = OpenOptions::new()
            .create(true)
            .append(true)
            .open("./src/gen_values/c.txt")
            .unwrap();
        cfile.write_all(&cx).unwrap();
        cfile.write_all(&cy).unwrap();

        // Write P
        let (px, py) = ristretto_to_affine(p);
        let mut pfile = OpenOptions::new()
            .create(true)
            .append(true)
            .open("./src/gen_values/p.txt")
            .unwrap();
        pfile.write_all(&px).unwrap();
        pfile.write_all(&py).unwrap();

        // Write H_P
        let (hpx, hpy) = ristretto_to_affine(hp);
        let mut hpfile = OpenOptions::new()
            .create(true)
            .append(true)
            .open("./src/gen_values/hp.txt")
            .unwrap();
        hpfile.write_all(&hpx).unwrap();
        hpfile.write_all(&hpy).unwrap();

        // Write Key Images
        let (ix, iy) = ristretto_to_affine(key_img);
        let mut ifile = OpenOptions::new()
            .create(true)
            .append(true)
            .open("./src/gen_values/i.txt")
            .unwrap();
        ifile.write_all(&ix).unwrap();
        ifile.write_all(&iy).unwrap();

        if i % 500 == 0 {
            println!("{}th value generated", i);
        }
    }
    println!("generation complete !");
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use bp_ed25519::curve::Ed25519Curve;
    use crypto_bigint::{U256, Encoding};
    use rand_07::thread_rng;

    #[test]
    fn test_amt_to_bytes() {
        let mut rng = thread_rng();
        let a: Scalar = Scalar::from(rng.gen::<u64>());
        let a_bytes = scalar_to_bytes(a); // a_bytes is little-endian

        // Remove old file if it exists
        std::fs::remove_file("./src/gen_values/a_test.txt").ok();

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("./src/gen_values/a_test.txt")
            .unwrap();
        file.write_all(&a_bytes).unwrap();

        // read ammount from a file
        let mut file = File::open("./src/gen_values/a_test.txt").unwrap();
        let mut buffer = vec![0; 32];
        loop {
            let bytes_read = file.read(&mut buffer).unwrap();
            if bytes_read == 0 {
                break;
            }
            let d: [u8; 32] = buffer[..bytes_read].try_into().unwrap();
            // a can be represented as a single feild element
            // assert_eq!(Fp::from_repr(a_bytes).unwrap(), Fp::from_repr(d).unwrap());
            assert_eq!(a_bytes, d);
            println!("Scalar is {:?}", a);
            println!("Fp is {:?}", d);
        }
    }

    #[test]
    fn test_key_to_bytes() {
        let mut rng = thread_rng();
        let random_bytes: [u8; 32] = rng.gen();
        let x: Scalar = Scalar::from_bytes_mod_order(random_bytes);
        let x_bytes = scalar_to_bytes(x); // x_bytes is little-endian

        // Remove old file if it exists
        std::fs::remove_file("./src/gen_values/x_test.txt").ok();

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("./src/gen_values/x_test.txt")
            .unwrap();
        file.write_all(&x_bytes).unwrap();

        // read key from a file
        let mut file = File::open("./src/gen_values/x_test.txt").unwrap();
        let mut buffer = vec![0; 32];
        loop {
            let bytes_read = file.read(&mut buffer).unwrap();
            if bytes_read == 0 {
                break;
            }
            let d: [u8; 32] = buffer[..bytes_read].try_into().unwrap();

            // Curve Order is 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
            // p is 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
            // x can be represented as a single feild element
            // assert_eq!(Fp::from_repr(x_bytes).unwrap(), Fp::from_repr(d).unwrap());
            assert_eq!(x_bytes, d);
            println!("Scalar is {:?}", x);
            println!("Fp is {:?}", d);
        }
    }

    #[test]
    fn test_read_values() {
        // Read Commitment
        let mut c_vec: Vec<AffinePoint> = vec![];
        let mut c_file = File::open("./src/gen_values/c.txt").unwrap();
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
        println!("len is {}", c_vec.len());
    }

    #[test]
    fn test_ristretto_to_affine() {
        let mut rng = thread_rng();
        let b = Ed25519Curve::basepoint();
        let x = U256::from(rng.gen::<u64>());
        let point = Ed25519Curve::scalar_multiplication(&b, &x);
        let (px, py) = (
            point.get_x().get_value().to_le_bytes(),
            point.get_y().get_value().to_le_bytes(),
        );

        let x_ris: Scalar = Scalar::from_bytes_mod_order(x.to_le_bytes());
        let b_ris = constants::RISTRETTO_BASEPOINT_POINT;
        let point = b_ris * x_ris;
        let (rx, ry) = ristretto_to_affine(point);

        assert_eq!(rx, px);
        assert_eq!(ry, py);
    }
}