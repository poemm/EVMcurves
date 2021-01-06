#! /usr/bin/bash

# glob all test cases corresponding to each test type (1 pairing, 2 pairing, etc...)
# run them through each engine

shopt -s nullglob
for f in "tests/"*."json"; do echo $f; done
