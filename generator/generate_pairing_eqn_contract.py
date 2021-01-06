from pairing import gen_pairing_eqn_huff
import sys

if __name__=="__main__":
  if len(sys.argv) > 1:
    if sys.argv[1] == "1":
      gen_pairing_eqn_huff(1)
    elif sys.argv[1] == "2":
      gen_pairing_eqn_huff(2)
    else:
      print("invalid input.  expects 1 or 2")
  else:
    print("expected input (either 1 or 2)")
