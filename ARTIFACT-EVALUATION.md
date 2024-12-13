# Artifact Appendix

Paper title: **MProve-Nova: A Privacy-Preserving Proof of Reserves Protocol for Monero**

Artifacts HotCRP Id: **#3**

Requested Badge: **Available**, **Functional** and **Reproduced**

## Description
This artifact contains the source code for implementing MProve-Nova, which includes the Reserves Commitment Generator (RCG) protocol and the Non-Collusion (NC) protocol. It provides detailed instructions to reproduce the performance comparisons between MProve-Nova RCG, MProve+, and MProve, as well as the performance results of the NC protocol, as presented in Table 1 and Table 2 of the paper.

### Security/Privacy Issues and Ethical Concerns (All badges)
Artifact does **not** hold any risk to the security or privacy of the reviewer's machine.

## Basic Requirements (Only for Functional and Reproduced badges)
The hardware and software requirements for the artifact, along with the estimated compute time and storage needed to run it, are detailed below.

### Hardware Requirements
Reproducing the exact results requires evaluating the artifact on a **64-core 2.30GHz Intel Xeon Gold 6314U CPU with 125GiB RAM**.

### Software Requirements
The artifact is compatible with any operating system that has Rust installed. Details on accessing the artifact and setting up the environment are provided in the following sections.

### Estimated Time and Storage Consumption
Evaluating the artifact requires approximately 50 hours of computation time and 1 GB of disk space.

## Environment 
The artifact includes the source code for MProve-Nova. The following sections provide details on accessing the source code, setting up the environment, and testing it to run the benchmarks.

### Accessibility (All badges)
The source code is hosted in a public GitHub repository. To clone the repository, use the following command:
```bash
git clone https://github.com/varunthakore/mprove-nova.git
```

### Set up the environment (Only for Functional and Reproduced badges)
First, install Rust on macOS, Linux, or another Unix-like OS, using the following command:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install `build-essential` package for Ubuntu using the following command:
```bash
sudo apt update
sudo apt install build-essential
```

Next, clone the repository and build the project:
```bash
git clone https://github.com/varunthakore/mprove-nova.git
cd mprove-nova/ && rustup show
cargo build --release --examples --bins
```

Ensure that the library is built successfully without any errors.

### Testing the Environment (Only for Functional and Reproduced badges)
The source code includes several tests. To run all tests, use the following command:
```bash
cargo test --release
```

Ensure that all tests pass successfully without any errors.

The `mprove-nova` library also includes examples for the RCG and NC protocols.

To run an example for the RCG protocol, use the following commands, passing the number of addresses as an argument:
```bash
cargo run --release --bin gen_values [num_of_addrs]
cargo run --release --example rcg [num_of_addrs]
```
Here, `num_of_addrs` specifies the number of addresses owned by the exchange for which it wants to compute the total reserves commitment. The `gen_values` binary generates `num_of_addrs` dummy one-time addresses, commitments, and key images, which are subsequently used in the reserves commitment generator protocol when the `rcg` example is executed.

For instance, to calculate the reserves commitment for 1,000 owned addresses:
```bash
cargo run --release --bin gen_values 1000
cargo run --release --example rcg 1000
```

To run an example for the NC protocol, use the following command, passing the number of addresses as an argument:
```bash
cargo run --release --example nc [num_of_addrs]
```
In the non-collusion protocol, exchange Ex2 shares its double-spend tree leaves with exchange Ex1, and Ex1 runs the non-collusion protocol. Here, `num_of_addrs` represents the number of double-spend tree leaves sent by Ex2 to Ex1, which corresponds to the number of addresses owned by Ex2.

For instance, if Ex2 owns 1,000 addresses and Ex1 wants to prove non-collusion with respect to those 1,000 addresses owned by Ex2:
```bash
cargo run --release --example nc 1000
```

Ensure that running the above examples produces no errors.

## Artifact Evaluation (Only for Functional and Reproduced badges)
The main results, claims of the paper, and the experiments supporting these claims are as follows:

### Main Results and Claims
MProve-Nova consists of two Nova-based subprotocols, a reserves commitment generator (RCG) protocol used to compute a commitment to the total reserves owned by an exchange and a non-collusion (NC) protocol used to prove non-collusion between two exchanges. In the following sections, we present the performance results of both protocols, as described in Section 9 of the paper.

#### Main Result 1: RCG Protocol Performance Results
As described in Section 9 of the paper, the RCG protocol has constant proof size and verification time of 28 KB and 4.3 seconds, respectively. The proving time is linear in the number of exchange-owned outputs, taking about 7 hours per 10,000 outputs. The steps to reproduce these results are outlined in the **Experiments** section.

#### Main Result 2: NC Protocol Performance Results
As described in Section 9 of the paper, the NC protocol has constant proof size and verification time of 24 KB and 0.2 seconds, respectively. The proving time is linear in the number of exchange-owned outputs, taking about 47 minutes per 10,000 outputs. The steps to reproduce these results are outlined in the **Experiments** section.

#### Main Result 3: Performance Comparison between MProve-Nova RCG, MProve+ and MProve
Section 9 of the paper presents a performance comparison among MProve-Nova RCG, MProve+, and MProve, as shown in **Table 1**. The steps to reproduce **Table 1** are detailed in the Experiments section.

### Experiments 
First, follow the steps to set up and test the environment as described in the **Environment** section. To generate the performance results of MProve-Nova, run the following command:
```bash
rustup show
cargo build --release --examples --bins
./genlog_all.sh
```
This will generate the benchmark outputs in the `logs` directory, which contains two sub-directories: `rcg` for RCG protocol output log and `nc` for NC protocol output log.

#### Experiment 1: RCG Protocol Benchmarks
The command to check the RCG protocol proving time from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep "Total proving time is" $(ls logs/rcg/output_* | sort -V)
logs/rcg/output_500.txt:Total proving time is 1236.964131298s
logs/rcg/output_1000.txt:Total proving time is 2451.683974152s
logs/rcg/output_3000.txt:Total proving time is 7303.713045962s
logs/rcg/output_5000.txt:Total proving time is 12254.04523336s
logs/rcg/output_7000.txt:Total proving time is 17204.209811385s
logs/rcg/output_10000.txt:Total proving time is 24989.116031124s
logs/rcg/output_15000.txt:Total proving time is 37831.119494451s
logs/rcg/output_20000.txt:Total proving time is 50389.009951745s
```

From the above output, we can observe that the proving time is linear with respect to the number of exchange-owned outputs. For 10,000 outputs, the proving time is 24,989 seconds, which is approximately 7 hours.

The command to check the RCG protocol verification time from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep "Total verification time" $(ls logs/rcg/output_* | sort -V)
logs/rcg/output_500.txt:Total verification time: 4.398468933s
logs/rcg/output_1000.txt:Total verification time: 4.387817808s
logs/rcg/output_3000.txt:Total verification time: 4.391256186s
logs/rcg/output_5000.txt:Total verification time: 4.392875195s
logs/rcg/output_7000.txt:Total verification time: 4.382738747s
logs/rcg/output_10000.txt:Total verification time: 4.389350362s
logs/rcg/output_15000.txt:Total verification time: 4.344367114s
logs/rcg/output_20000.txt:Total verification time: 4.36039312s
```

From the above output, we can observe that the verification time is constant at approximately 4.3 seconds and is independent of the number of exchange-owned outputs. 

The command to check the RCG protocol proof size from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep "CompressedSNARK::len" $(ls logs/rcg/output_* | sort -V) 
logs/rcg/output_500.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_1000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_3000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_5000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_7000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_10000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_15000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_20000.txt:CompressedSNARK::len 28024 bytes
```

From the above output, we can observe that the proof size is constant at approximately 28 KB and is independent of the number of exchange-owned outputs. This experiment also reproduces MProve-Nova RCG section of the performance comparison in **Table 1**.

Running the benchmarks and generating the outputs takes approximately 45 hours of computation time and 1 GB of disk space.

#### Experiment 2: NC Protocol Benchmarks 
The command to check the NC protocol proving time from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep "Total proving time is" $(ls logs/nc/output_* | sort -V)
logs/nc/output_500.txt:Total proving time is 143.324505882s
logs/nc/output_1000.txt:Total proving time is 285.208374511s
logs/nc/output_3000.txt:Total proving time is 848.153001505s
logs/nc/output_5000.txt:Total proving time is 1410.219713391s
logs/nc/output_7000.txt:Total proving time is 1984.67171172s
logs/nc/output_10000.txt:Total proving time is 2826.393281175s
logs/nc/output_15000.txt:Total proving time is 4236.945553835s
logs/nc/output_20000.txt:Total proving time is 5632.551304325s
```

From the above output, we can observe that the proving time is linear with respect to the number of exchange-owned outputs. For 10,000 outputs, the proving time is 2,826 seconds, which is approximately 47 minutes.

The command to check the NC protocol verification time from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep "Total verification time" $(ls logs/nc/output_* | sort -V) 
logs/nc/output_500.txt:Total verification time: 218.79353ms
logs/nc/output_1000.txt:Total verification time: 221.96927ms
logs/nc/output_3000.txt:Total verification time: 229.690116ms
logs/nc/output_5000.txt:Total verification time: 249.285577ms
logs/nc/output_7000.txt:Total verification time: 212.644103ms
logs/nc/output_10000.txt:Total verification time: 210.938363ms
logs/nc/output_15000.txt:Total verification time: 219.091602ms
logs/nc/output_20000.txt:Total verification time: 214.905847ms
```

From the above output, we can observe that the verification time is constant at approximately 0.2 seconds and is independent of the number of exchange-owned outputs. 

The command to check the NC protocol proof size from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep "CompressedSNARK::len" $(ls logs/nc/output_* | sort -V)
logs/nc/output_500.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_1000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_3000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_5000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_7000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_10000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_15000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_20000.txt:CompressedSNARK::len 23704 bytes
```

From the above output, we can observe that the proof size is constant at approximately 24 KB and is independent of the number of exchange-owned outputs. This experiment also reproduces the performance of NC protocol as shown in **Table 2**.

Running the benchmarks and generating the outputs takes approximately 5 hours of computation time and 1 GB of disk space.

#### Experiment 3: Performance Comparison between MProve-Nova RCG, MProve+ and MProve
This experiment involves reproducing the performance results of MProve+ and MProve, as shown in **Table 1**. The process for reproducing the MProve-Nova RCG performance results in **Table 1** has already been described in **Experiment 1**.

**MProve+ Benchmarks**

Clone a fork of MProve+ implementation and run benchmarks:
```bash
git clone https://github.com/varunthakore/MProvePlus-Ristretto.git
cd MProvePlus-Ristretto/ && rustup show
./gen_log_omnires.sh
```

This will generate the benchmark outputs in the `logs` directory. Note that for anonymity sets of size 20,000 and beyond, the simulation ran out of memory; therefore, only estimated values derived using linear interpolation are provided in **Table 1**.

The command to check the MProve+ proving time from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep -e "Average proof generation time" -e "Options" $(ls logs/out_omni_1* | sort -V)
logs/out_omni_10.txt:Options = Opt { anon_list_size: 10000, own_list_size: 500, num_iter: 1 }
logs/out_omni_10.txt:Average proof generation time = 1057.435
logs/out_omni_15.txt:Options = Opt { anon_list_size: 15000, own_list_size: 1000, num_iter: 1 }
logs/out_omni_15.txt:Average proof generation time = 2243.881
```

The command to check the MProve+ verification time from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep -e "Average proof verification time" -e "Options" $(ls logs/out_omni_1* | sort -V)
logs/out_omni_10.txt:Options = Opt { anon_list_size: 10000, own_list_size: 500, num_iter: 1 }
logs/out_omni_10.txt:Average proof verification time = 112.128
logs/out_omni_15.txt:Options = Opt { anon_list_size: 15000, own_list_size: 1000, num_iter: 1 }
logs/out_omni_15.txt:Average proof verification time = 236.94
```

The command to check the MProve+ proof size from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep -e "Proof size" -e "Options" $(ls logs/out_omni_1* | sort -V)
logs/out_omni_10.txt:Options = Opt { anon_list_size: 10000, own_list_size: 500, num_iter: 1 }
logs/out_omni_10.txt:Proof size : 82432.0 bytes
logs/out_omni_15.txt:Options = Opt { anon_list_size: 15000, own_list_size: 1000, num_iter: 1 }
logs/out_omni_15.txt:Proof size : 162496.0 bytes
```

**MProve Benchmarks**

Clone a fork of MProve implementation and run benchmarks:
```bash
git clone https://github.com/varunthakore/MProve-Ristretto.git
cd MProve-Ristretto/ && rustup show
./gen_log.sh
```

This will generate the benchmark outputs in the `logs` directory.

The command to check the MProve proving time from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep -e "Average proof generation time" -e "Options" $(ls logs/out_* | sort -V)
logs/out_10.txt:Options = Opt { anon_list_size: 10000, own_list_size: 500, num_iter: 1 }
logs/out_10.txt:Average proof generation time = 7.345138256s
logs/out_15.txt:Options = Opt { anon_list_size: 15000, own_list_size: 1000, num_iter: 1 }
logs/out_15.txt:Average proof generation time = 11.698061679s
logs/out_20.txt:Options = Opt { anon_list_size: 20000, own_list_size: 3000, num_iter: 1 }
logs/out_20.txt:Average proof generation time = 16.890208193s
logs/out_25.txt:Options = Opt { anon_list_size: 25000, own_list_size: 5000, num_iter: 1 }
logs/out_25.txt:Average proof generation time = 23.197197886s
logs/out_30.txt:Options = Opt { anon_list_size: 30000, own_list_size: 7000, num_iter: 1 }
logs/out_30.txt:Average proof generation time = 30.456396606s
logs/out_35.txt:Options = Opt { anon_list_size: 35000, own_list_size: 10000, num_iter: 1 }
logs/out_35.txt:Average proof generation time = 38.729862158s
logs/out_40.txt:Options = Opt { anon_list_size: 40000, own_list_size: 15000, num_iter: 1 }
logs/out_40.txt:Average proof generation time = 47.359424184s
logs/out_45.txt:Options = Opt { anon_list_size: 45000, own_list_size: 20000, num_iter: 1 }
logs/out_45.txt:Average proof generation time = 57.453281486s
```

The command to check the MProve verification time from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep -e "Average proof verification time" -e "Options" $(ls logs/out_* | sort -V)
logs/out_10.txt:Options = Opt { anon_list_size: 10000, own_list_size: 500, num_iter: 1 }
logs/out_10.txt:Average proof verification time = 3.798095387s
logs/out_15.txt:Options = Opt { anon_list_size: 15000, own_list_size: 1000, num_iter: 1 }
logs/out_15.txt:Average proof verification time = 5.701835846s
logs/out_20.txt:Options = Opt { anon_list_size: 20000, own_list_size: 3000, num_iter: 1 }
logs/out_20.txt:Average proof verification time = 7.605099082s
logs/out_25.txt:Options = Opt { anon_list_size: 25000, own_list_size: 5000, num_iter: 1 }
logs/out_25.txt:Average proof verification time = 9.50861897s
logs/out_30.txt:Options = Opt { anon_list_size: 30000, own_list_size: 7000, num_iter: 1 }
logs/out_30.txt:Average proof verification time = 11.409164644s
logs/out_35.txt:Options = Opt { anon_list_size: 35000, own_list_size: 10000, num_iter: 1 }
logs/out_35.txt:Average proof verification time = 13.31377302s
logs/out_40.txt:Options = Opt { anon_list_size: 40000, own_list_size: 15000, num_iter: 1 }
logs/out_40.txt:Average proof verification time = 15.216348827s
logs/out_45.txt:Options = Opt { anon_list_size: 45000, own_list_size: 20000, num_iter: 1 }
logs/out_45.txt:Average proof verification time = 17.113787606s
```

The command to check the MProve proof size from the generated benchmarks, along with the expected command output, is as follows:
```bash
$ grep -e "Proof size" -e "Options" $(ls logs/out_* | sort -V)
logs/out_10.txt:Options = Opt { anon_list_size: 10000, own_list_size: 500, num_iter: 1 }
logs/out_10.txt:Proof size = 8320320 bytes
logs/out_15.txt:Options = Opt { anon_list_size: 15000, own_list_size: 1000, num_iter: 1 }
logs/out_15.txt:Proof size = 12480320 bytes
logs/out_20.txt:Options = Opt { anon_list_size: 20000, own_list_size: 3000, num_iter: 1 }
logs/out_20.txt:Proof size = 16640320 bytes
logs/out_25.txt:Options = Opt { anon_list_size: 25000, own_list_size: 5000, num_iter: 1 }
logs/out_25.txt:Proof size = 20800320 bytes
logs/out_30.txt:Options = Opt { anon_list_size: 30000, own_list_size: 7000, num_iter: 1 }
logs/out_30.txt:Proof size = 24960320 bytes
logs/out_35.txt:Options = Opt { anon_list_size: 35000, own_list_size: 10000, num_iter: 1 }
logs/out_35.txt:Proof size = 29120320 bytes
logs/out_40.txt:Options = Opt { anon_list_size: 40000, own_list_size: 15000, num_iter: 1 }
logs/out_40.txt:Proof size = 33280320 bytes
logs/out_45.txt:Options = Opt { anon_list_size: 45000, own_list_size: 20000, num_iter: 1 }
logs/out_45.txt:Proof size = 37440320 bytes
```

Running the benchmarks and generating the outputs takes approximately 1 hours of computation time and 1 GB of disk space.

The above benchmarks for MProve and MProve+ along with the MProve-RCG benchmarks from **Experiment 3** reproduce the complete performance comparison results of **Table 1**.

## Limitations (Only for Functional and Reproduced badges)
The performance of the MProve-Nova RCG and NC protocols, as shown in **Table 1** and **Table 2** respectively, is reproducible using the provided artifact, provided the benchmarking machine meets the hardware requirement of a **64-core 2.30GHz Intel Xeon Gold 6314U CPU with 125GiB RAM**. Otherwise, the performance numbers may differ. For instance, the VM spawned from HotCRP for review purposes, with the IP address 141.39.220.156, has only a 16-core CPU and 64GB RAM, which is insufficient to reproduce the reported performance results.

## Notes on Reusability (Only for Functional and Reproduced badges)
The MProve-Nova source code is hosted in a public GitHub repository and is licensed under the MIT/Apache license, allowing anyone to use it. Users can clone the GitHub repository and follow the steps in the README to test the code and generate the benchmarks.

