WORK IN PROGRESS


## Dependencies


### Huff

Get huff and patch huff in the parent directory. Note: relative paths are hard-coded in `compile.js`.


### EVM384 Engine

Currently we generate EVM384v7 bytecode, so we use a branch of evmone which supports EVM384v7.

Warning: when building evmone, it will download a bunch of stuff, including to hidden directory `.hunter` in your home directory and maybe other places. I don't know of any way around this.

```
git clone --recursive https://github.com/jwasinger/evmone
cd evmone
git checkout evm384-v7
git checkout 60092fc9aaf592b6f1ad4081795c067bbd90d2d1   # maybe more recent versions work too
mkdir build
cd build
cmake .. -DEVMONE_TESTING=ON
cmake --build . -- -j
cd ../..
```


### BLS Implementation

We compare our outputs against third-party implementations.

For BLS12-381 operations, we use Supranational's blst. We use a branch of blst with our custom inputs/outptus.

```
git clone https://github.com/jwasinger/blst
cd blst
git checkout evm384-v7
cd paul
make
cd ../..
```

Edit the file we compile with `make` to run on specific inputs.


## Generate Test Bytecode

Generate the EVM bytecode for tests.

```
python3 genhufftests.py > bls12_381.huff
node compile.js MILLER_LOOP_TEST_HARD_CODED > miller_loop_test_hard_coded.hex
node compile.js MILLER_LOOP_CONTRACT > miller_loop.hex
node compile.js FINAL_EXPONENTIATION_TEST_HARD_CODED > final_exponentiation_test_hard_coded.hex
node compile.js FINAL_EXPONENTIATION_CONTRACT > final_exponentiation.hex
```

## Execute Test

Execute EVM384 bytecode. (This also runs a benchmark.)
```
./evmone/build/bin/evmone-bench --benchmark_format=json --benchmark_color=false --benchmark_min_time=1 miller_loop_test_hard_coded.hex 00 ""
./evmone/build/bin/evmone-bench --benchmark_format=json --benchmark_color=false --benchmark_min_time=1 final_exponentiation_test_hard_coded.hex 00 ""

```

