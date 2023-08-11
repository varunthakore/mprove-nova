#!/bin/bash
if [ $# -eq 0 ]; then
    >&2 echo "No arguments provided !"
    exit 1
fi

echo "Generating output logs for $1 iteration"
command ./target/release/examples/por $1 > ./logs/output_$1.txt
echo "See logs directory for output files"