# inversemod384_bls12381

We use an addition chain generated with this tool:
```
git clone https://github.com/kwantam/addchain
cd addchain
go build
./addchain 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559785
```

The case Bos-Coster (win=4) has the fewest operations: 461 mulmodmont384s. But this case is less convenient for codesize, so we choose the case Bos-Coster (win=3).

Note: To print that case (and all cases), edit `main.go` at bottom in loop `// find the best result`, add: `print_sequence(wx.seq)`.

Copy the output from `addchain` to file `addchain_boscosterwin3.txt` as below.

Next we convert `addchain_boscosterwin3.txt` to huff using a custom script.

```
python3 addchain2huff.py > inversemod384.huff
```

Note that we hard-code some parameters in `addchain2huff.py` like input memory offset, output memory offset, temporary value offsets, and the memory offset to the modulus. Also, we only have nine temporary value offsets, which may not be enough for other addition chains.

