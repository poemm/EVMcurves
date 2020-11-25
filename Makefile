all: build_pairing_eq2_test

build_pairing_eq2_test:
	python3 genhuff.py > bls12_381.huff
	node compile.js PAIRING_EQ2_TEST > pairing_eq2_test.hex 

benchmark:
	./run_evmone_bench.sh pairing_eq2_test.hex
