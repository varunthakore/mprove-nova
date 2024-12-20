#!/bin/bash
iters=(500 1000 3000 5000 7000 10000 15000 20000)
for i in "${iters[@]}"
do
    echo "Generating values for $i iteration"
    command ./target/release/gen_values $i > /dev/null
    echo "Values generation complete!"
    echo "Sleeping for 1 mins to give the CPU a break"
    sleep 60
    echo "Generating output logs for $i iteration"
    command ./target/release/examples/rcg $i > ./logs/rcg/output_$i.txt
    echo "Sleeping for 1 mins to give the CPU a break"
    sleep 60
    command ./target/release/examples/nc $i > ./logs/nc/output_$i.txt
    echo "Sleeping for 1 mins to give the CPU a break"
    sleep 60
done
echo "See logs directory for output files"
