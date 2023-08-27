type G1 = pasta_curves::pallas::Point;
type G2 = pasta_curves::vesta::Point;
use clap::{Arg, Command};
use flate2::{write::ZlibEncoder, Compression};
use generic_array::typenum::{U1, U12, U2, U3, U4};
use mprove_nova::nova_por::circuit::PORIteration;
use nova_snark::{
    traits::{circuit::TrivialTestCircuit, Group},
    CompressedSNARK, PublicParams, RecursiveSNARK,
};
use std::time::Instant;

fn main() {
    let cmd = Command::new("MProve-Nova proof generation and verification")
        .bin_name("por")
        .arg(
            Arg::new("num_of_iters")
                .value_name("Number of POR Iterations")
                .default_value("1")
                .value_parser(clap::value_parser!(usize)),
        );
    let m = cmd.get_matches();
    let m = *m.get_one::<usize>("num_of_iters").unwrap();

    println!("MProve-Nova iterations");
    println!("=========================================================");

    type C1 = PORIteration<<G1 as Group>::Scalar, U1, U2, U3, U4, U12>;
    type C2 = TrivialTestCircuit<<G2 as Group>::Scalar>;
    let circuit_primary: C1 = PORIteration::default();
    let circuit_secondary: C2 = TrivialTestCircuit::default();

    let param_gen_timer = Instant::now();
    println!("Producing public parameters...");
    let pp = PublicParams::<G1, G2, C1, C2>::setup(circuit_primary, circuit_secondary.clone());

    let param_gen_time = param_gen_timer.elapsed();
    println!("PublicParams::setup, took {:?} ", param_gen_time);

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );
    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    let primary_circuit_sequence = C1::get_iters(m); // select m iterations

    let z0_primary = C1::get_z0(&primary_circuit_sequence[0]);
    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    let proof_gen_timer = Instant::now();
    // produce a recursive SNARK
    println!("Generating a RecursiveSNARK...");
    let mut recursive_snark: RecursiveSNARK<G1, G2, C1, C2> = RecursiveSNARK::<G1, G2, C1, C2>::new(
        &pp,
        &primary_circuit_sequence[0],
        &circuit_secondary,
        z0_primary.clone(),
        z0_secondary.clone(),
    );
    let start = Instant::now();
    for (i, circuit_primary) in primary_circuit_sequence.iter().enumerate() {
        let step_start = Instant::now();
        let res = recursive_snark.prove_step(
            &pp,
            circuit_primary,
            &circuit_secondary,
            z0_primary.clone(),
            z0_secondary.clone(),
        );
        assert!(res.is_ok());
        println!(
            "RecursiveSNARK::prove_step {}: {:?}, took {:?} ",
            i,
            res.is_ok(),
            step_start.elapsed()
        );
    }
    println!(
        "Total time taken by RecursiveSNARK::prove_steps: {:?}",
        start.elapsed()
    );

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let num_steps = primary_circuit_sequence.len();
    let res = recursive_snark.verify(&pp, num_steps, &z0_primary, &z0_secondary);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());

    // produce a compressed SNARK
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();

    let start = Instant::now();
    type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<G1>;
    type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<G2>;
    type S1 = nova_snark::spartan::RelaxedR1CSSNARK<G1, EE1>;
    type S2 = nova_snark::spartan::RelaxedR1CSSNARK<G2, EE2>;

    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    let proving_time = proof_gen_timer.elapsed();
    println!("Total proving time is {:?}", proving_time);

    let compressed_snark = res.unwrap();

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &compressed_snark).unwrap();
    let compressed_snark_encoded = encoder.finish().unwrap();
    println!(
        "CompressedSNARK::len {:?} bytes",
        compressed_snark_encoded.len()
    );

    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(&vk, num_steps, z0_primary, z0_secondary);
    let verification_time = start.elapsed();
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        verification_time,
    );
    assert!(res.is_ok());
    println!("=========================================================");
    println!("Public parameters generation time: {:?} ", param_gen_time);
    println!(
        "Total proving time (excl pp generation): {:?}",
        proving_time
    );
    println!("Total verification time: {:?}", verification_time);
}
