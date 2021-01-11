#! /usr/bin/env bash

# maybe support json tests in the future, but I don't want to rely on users having jq (json query) installed

# first line is input
INPUT=$(cat $2 | sed -n '1p;2q')

# second line is expected
EXPECTED=$(cat $2 | sed -n '2p;3q')

# evmone-bench doesn't support input data in the evm384-v7 branch
# ./evmone/build/bin/evmone-bench --benchmark_format=json --benchmark_color=false --benchmark_min_time=5 $INPUT 00 "$EXPECTED" $2

./go-ethereum-purego/build/bin/evm --statdump --codefile $1 --input $INPUT run
