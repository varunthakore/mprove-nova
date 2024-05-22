#!/bin/bash
if [ $# -eq 0 ]; then
    >&2 echo "No arguments provided !"
    exit 1
fi

echo "Generating values for $1 iteration"
command ./target/release/gen_values $1 > /dev/null
echo "Values generation complete!"
echo "Sleeping for 1 mins to give the CPU a break"
sleep 60
echo "Generating output logs for $1 iteration"
command ./target/release/examples/por $1 > ./logs/por/output_$1.txt
echo "Sleeping for 1 mins to give the CPU a break"
sleep 60
command ./target/release/examples/pnc $1 > ./logs/pnc/output_$1.txt
echo "See logs directory for output files"
