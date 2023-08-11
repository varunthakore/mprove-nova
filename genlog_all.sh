#!/bin/bash
iters=(10 50 100 500 1000 5000)
for i in "${iters[@]}"
do
    echo "Generating output logs for $i iteration"
    command ./target/release/examples/por $i > ./logs/output_$i.txt
    echo "Sleeping for 2 mins to give the CPU a break"
    sleep 120
done
echo "See logs directory for output files"