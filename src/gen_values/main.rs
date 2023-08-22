// Usage: cargo run -r --bin gen_values [number_of_values]

use clap::{Command, Arg};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use sha2::Sha512;
use sha3::Keccak512;

use bp_ed25519::field::Fe25519;
use bp_ed25519::curve::AffinePoint;
use rand_07::{self, Rng};


use std::{fs::File, io::{Write, BufWriter}};
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
    let cmd = Command::new("Test values generator for MProve-Nova")
        .bin_name("gen_values")
        .arg(
            Arg::new("num_values")
                .value_name("Number of outputs")
                .value_parser(clap::value_parser!(u32))
                .required(true)
                .long_help("Number of outputs that will be generated in the test data")

        )
        .after_help("The gen_Values command generates the test data that will be used\
         to benchmark the performance of MProve-Nova");

    let m = cmd.get_matches();
    let num_values = m.get_one::<u32>("num_values").unwrap();
    let mut rng = rand_07::thread_rng();

    let file_err_msg = "Unable to create or write to file";
    let amount_file_name = format!("a_{num_values}.txt");
    let private_key_file_name = format!("x_{num_values}.txt");
    let commitment_file_name = format!("c_{num_values}.txt");
    let public_key_file_name = format!("p_{num_values}.txt");
    let public_key_hash_file_name = format!("hp_{num_values}.txt");
    let keyimage_file_name = format!("i_{num_values}.txt");


    let amount_file = File::create(amount_file_name).expect(file_err_msg);
    let mut amount_buf = BufWriter::new(amount_file);
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

    // G, H - curve points for generating outputs and key-images
    let g = constants::RISTRETTO_BASEPOINT_POINT;
    // Placeholder for the point H which is used to generate Pedersen commitments of the amount
    let h = RistrettoPoint::hash_from_bytes::<Sha512>(g.compress().as_bytes());

    for i in 0..(*num_values as usize) {
        // generate random amounts from 2^64 -1
        let a: Scalar = Scalar::from(rng.gen::<u64>());
        // generate blinding factors
        let r: Scalar = Scalar::random(&mut rng);
        // generate secret keys
        let random_bytes: [u8; 32] = rng.gen();
        let x: Scalar = Scalar::from_bytes_mod_order(random_bytes);

        let c = g * r + h * a;
        let p = g * x;
        let hp = RistrettoPoint::hash_from_bytes::<Keccak512>(p.compress().as_bytes());
        let key_img = hp * x;

        // Write amounts
        let amount_bytes = scalar_to_bytes(a);
        writeln!(amount_buf, "{}", hex::encode(amount_bytes)).expect(file_err_msg);

        // Write keys
        let x_bytes = scalar_to_bytes(x);
        writeln!(private_key_buf, "{}", hex::encode(x_bytes)).expect(file_err_msg);

        // Write commitments
        let (cx, cy) = ristretto_to_affine(c);
        writeln!(commitment_buf, "{} {}", hex::encode(cx), hex::encode(cy)).expect(file_err_msg);

        // Write P
        let (px, py) = ristretto_to_affine(p);
        writeln!(public_key_buf, "{} {}", hex::encode(px), hex::encode(py)).expect(file_err_msg);

        // Write H_P
        let (hpx, hpy) = ristretto_to_affine(hp);
        writeln!(public_key_hash_buf, "{} {}", hex::encode(hpx), hex::encode(hpy)).expect(file_err_msg);

        // Write Key Images
        let (ix, iy) = ristretto_to_affine(key_img);
        writeln!(keyimage_buf, "{} {}", hex::encode(ix), hex::encode(iy)).expect(file_err_msg);

        if i % 500 == 0 {
            println!("Value with index {i} generated");
        }
    }
    println!("Values generation complete!");
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{fs::File, io};
    use std::io::BufRead;
    use std::path::Path;
    use bp_ed25519::curve::Ed25519Curve;
    use crypto_bigint::{U256, Encoding};
    use rand_07::thread_rng;

    // Code from https://doc.rust-lang.org/rust-by-example/std_misc/file/read_lines.html
    fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }

    #[test]
    fn test_amt_to_bytes() {
        let mut rng = thread_rng();
        let a: Scalar = Scalar::from(rng.gen::<u64>());
        let a_bytes = scalar_to_bytes(a).to_vec(); // a_bytes is little-endian

        let file_err_msg = "Unable to create or write to file";
        let amount_file_name = "a_test.txt";
        let amount_file = File::create(amount_file_name).expect(file_err_msg);

        let mut amount_buf = BufWriter::new(amount_file);
        let amount_hex_string = hex::encode(a_bytes);
        writeln!(amount_buf, "{amount_hex_string}").expect(file_err_msg);
        let _ = amount_buf.flush();

        // read amount from file
        if let Ok(lines) = read_lines(amount_file_name) {
            for line in lines {
                if let Ok(amount_string_read) = line {
                    assert_eq!(amount_string_read, amount_hex_string);
                }
            }
        } else {
            assert!(false)
        }
    }

    #[test]
    fn test_key_to_bytes() {
        let mut rng = thread_rng();
        let random_bytes: [u8; 32] = rng.gen();
        let x: Scalar = Scalar::from_bytes_mod_order(random_bytes);
        let x_bytes = scalar_to_bytes(x); // x_bytes is little-endian

        let file_err_msg = "Unable to create or write to file";
        let private_key_file_name = "x_test.txt";
        let private_key_file = File::create(private_key_file_name).expect(file_err_msg);

        let mut private_key_buf = BufWriter::new(private_key_file);
        let private_key_hex_string = hex::encode(x_bytes);
        writeln!(private_key_buf, "{private_key_hex_string}").expect(file_err_msg);
        let _ = private_key_buf.flush();

        // read key from file
        if let Ok(lines) = read_lines(private_key_file_name) {
            for line in lines {
                if let Ok(private_key_string_read) = line {
                    assert_eq!(private_key_string_read, private_key_hex_string);
                }
            }
        } else {
            assert!(false)
        }
    }

    #[test]
    fn test_public_key_to_bytes() {
        let mut rng = thread_rng();
        let random_bytes: [u8; 32] = rng.gen();
        let x: Scalar = Scalar::from_bytes_mod_order(random_bytes);
        let g = constants::RISTRETTO_BASEPOINT_POINT;
        let p = g * x;
        let (px, py) = ristretto_to_affine(p);

        let file_err_msg = "Unable to create or write to file";
        let public_key_file_name = "p_test.txt";
        let public_key_file = File::create(public_key_file_name).expect(file_err_msg);

        let mut public_key_buf = BufWriter::new(public_key_file);
        let pk_x_string = hex::encode(px);
        let pk_y_string = hex::encode(py);
        writeln!(public_key_buf, "{pk_x_string} {pk_y_string}").expect(file_err_msg);
        let _ = public_key_buf.flush();

        // read key from file
        if let Ok(lines) = read_lines(public_key_file_name) {
            for line in lines {
                if let Ok(key_coordinates) = line {
                    let coordinates: Vec<&str> = key_coordinates.trim().split(' ').collect();
                    assert_eq!(coordinates.len(), 2);
                    assert_eq!(String::from(coordinates[0]), pk_x_string);
                    assert_eq!(String::from(coordinates[1]), pk_y_string);

                    let cx_dec: [u8; 32] = hex::decode(String::from(coordinates[0])).expect("Error").as_slice().try_into().unwrap();
                    let cy_dec: [u8; 32] = hex::decode(String::from(coordinates[1])).expect("Error").as_slice().try_into().unwrap();

                    let p_dec = AffinePoint::coord_to_point(
                        Fe25519::from_repr(cx_dec).unwrap(),
                        Fe25519::from_repr(cy_dec).unwrap(),
                    );

                    assert!(p_dec.is_on_curve());
                }
            }
        } else {
            assert!(false)
        }
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