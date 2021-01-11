
import sys
sys.path.append('..')

from genhuff import *



# hard-coded miller loop inputs
# these inputs can be hard-coded anywhere before the miller loop starts
def gen_miller_loop_test_input():
  case = 3
  if case==0:
    # test from https://tools.ietf.org/id/draft-yonezawa-pairing-friendly-curves-02.html#rfc.appendix.B
    # Input x,y values:
    inE1  = bytearray.fromhex("120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16")[::-1]
    inE1  += bytearray.fromhex("0e44d2ede97744303cff1b76964b531712caf35ba344c12a89d7738d9fa9d05592899ce4383b0270ff526c2af318883a")[::-1]
    gen_memstore(buffer_inputs,inE1)
    # Input x’0,x'1 value:
    inE2 = bytearray.fromhex("058191924350bcd76f67b7631863366b9894999d1a3caee9a1a893b53e2ae580b3f5fb2687b4961af5f28fa202940a10")[::-1]
    inE2 += bytearray.fromhex("11922a097360edf3c2b6ed0ef21585471b1ab6cc8541b3673bb17e18e2867806aaa0c59dbccd60c3a5a9c0759e23f606")[::-1]
    # Input y’0,y'1 value:
    inE2 += bytearray.fromhex("197d145bbaff0bb54347fe40525c8734a887959b8577c95f7f4a4d344ca692c9c52f05df531d63a56d8bf5079fb65e61")[::-1]
    inE2 += bytearray.fromhex("0ed54f48d5a1caa764044f659f0ee1e9eb2def362a476f84e0832636bacc0a840601d8f4863f9e230c3e036d209afa4e")[::-1]
    gen_memstore(buffer_inputs+96,inE2)
  elif case==2:
    print()
    # these are the identity elements, copied from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2539.md#specification
    # G1:
    inE1  = bytearray.fromhex("008848defe740a67c8fc6225bf87ff5485951e2caa9d41bb188282c8bd37cb5cd5481512ffcd394eeab9b16eb21be9ef")[::-1]
    inE1  += bytearray.fromhex("01914a69c5102eff1f674f5d30afeec4bd7fb348ca3e52d96d182ad44fb82305c2fe3d3634a9591afd82de55559c8ea6")[::-1]
    gen_memstore(buffer_inputs,inE1)
    # G2:
    inE2 = bytearray.fromhex("018480be71c785fec89630a2a3841d01c565f071203e50317ea501f557db6b9b71889f52bb53540274e3e48f7c005196")[::-1]
    inE2 += bytearray.fromhex("00ea6040e700403170dc5a51b1b140d5532777ee6651cecbe7223ece0799c9de5cf89984bff76fe6b26bfefa6ea16afe")[::-1]
    inE2 += bytearray.fromhex("00690d665d446f7bd960736bcbb2efb4de03ed7274b49a58e458c282f832d204f2cf88886d8c7c2ef094094409fd4ddf")[::-1]
    inE2 += bytearray.fromhex("00f8169fd28355189e549da3151a70aa61ef11ac3d591bf12463b01acee304c24279b83f5e52270bd9a1cdd185eb8f93")[::-1]
    gen_memstore(buffer_inputs+96,inE2)
  elif case==3:
    print()
    # these are from wasmsnark
    # cd wasmsnark && ~/repos/node/node-v12.18.4-linux-x64/bin/npx mocha test/bls12381.js
    # G1:
    inE1  = bytearray.fromhex("0f81da25ecf1c84b577fefbedd61077a81dc43b00304015b2b596ab67f00e41c86bb00ebd0f90d4b125eb0539891aeed")[::-1]
    inE1  += bytearray.fromhex("11af629591ec86916d6ce37877b743fe209a3af61147996c1df7fd1c47b03181cd806fd31c3071b739e4deb234bd9e19")[::-1]
    gen_memstore(buffer_inputs,inE1)
    # G2:
    inE2 = bytearray.fromhex("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")[::-1]
    inE2 += bytearray.fromhex("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")[::-1]
    inE2 += bytearray.fromhex("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801")[::-1]
    inE2 += bytearray.fromhex("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")[::-1]
    gen_memstore(buffer_inputs+96,inE2)
  elif case==4:
    # from https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/?include_text=1 appendix B
    inE1  = bytearray.fromhex("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")[::-1]
    inE1  += bytearray.fromhex("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1")[::-1]
    gen_memstore(buffer_inputs,inE1)
    inE2  = bytearray.fromhex("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")[::-1]
    inE2  += bytearray.fromhex("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")[::-1]
    inE2  += bytearray.fromhex("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801")[::-1]
    inE2  += bytearray.fromhex("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")[::-1]
    gen_memstore(buffer_inputs+96,inE2)
  elif case==5:
    # from casey
    inE1  = bytearray.fromhex("0b83dfefb120fab7665a607d749ef1765fbb3cc0ba5827a20a135402c09d987c701ddb5b60f0f5495026817e8ab6ea2e")[::-1]
    inE1  += bytearray.fromhex("15c82e5362493d173e96edb436e396a30b9d3ae5d1a2633c375cfbbf3aed34bbc30448ec6b8102ab2f8da4486d23a717")[::-1]
    gen_memstore(buffer_inputs,inE1)
    inE2  = bytearray.fromhex("16fc2f7ff7eb01f34e97a5d5274390ee168f32ff5803597da434b40fa7778793eaac8cc3e8f0d75f3bf55889258ebea7")[::-1]
    inE2  += bytearray.fromhex("183aa5f5b84721a4efdfc5a759ec88792e3080b8f9207d02eca66082d6076569b84b95e05b3a4b95697909f1dda69d8d")[::-1]
    inE2  += bytearray.fromhex("002e5c809b03e98d5406ae13e3aa6e477b4aa0a0cedef70dafdd5f0b0c2c64152f52837f92870d0c57b21dd62e9ead91")[::-1]
    inE2  += bytearray.fromhex("039dc3bb023f737d7c60f62b4e669843817fe1ed0751a7b750d02c9df5ee87758e7fe7d6fd614b5fe013f35e6fd9ae4d")[::-1]
    gen_memstore(buffer_inputs+96,inE2)


def gen_final_exp_test_input():
  # this is to generate test values, which are then hard-coded into the main.huff
  case = 3
  if case==1:
    pass
  elif case==2:
    pass
  elif case==3:
    # from test 3
    a  = bytearray.fromhex("3cf8fe6aba6061de70638196991c6c245ccc8d011108841a2d19eecc877c3fbcb1cc9a694c0aac2903c8c41520526a00")
    a += bytearray.fromhex("16a3242ef581eb5bc185108cbde497bc21150576fd77b2c9166fb392a444e0503c54caed9cba054d3851c6fd58821917")
    a += bytearray.fromhex("1d364d5982bdece58c3d9ff500fd25ae4589ca4d3c2d81391ce1a3afbc4c5ffaab909e5e2f03b4e690a4b7677dd39102")
    a += bytearray.fromhex("a5a6a20f4e3d0702b4dc8f8dab2dbd3e5b769c5116bc3889502ced4f6efd1f5e344b1f6299bb1e7c9508f465a64da515")
    a += bytearray.fromhex("e9f8ce46f6dd5883b4342c56af2ffcf89088ccd992bb4b707824d3ad74d569b07f9ce69c0c7c38907ff41b57c0ce190c")
    a += bytearray.fromhex("925dd857f1ef631f083592773a02acb2c93e1dd2940cf0d29bed0d3710c2128811267eba6d19202807de48bb42699108")
    a += bytearray.fromhex("2d0bc7f84f68520c8cd47622db80eb306e1dc84ba817c63539ac4455c4284efcb18301782b2100096e01840ae3dfe302")
    a += bytearray.fromhex("7f67af26013c4bbf335e878f66312c5c645fb5418ba855c6bac3324fbda16158c4c87246767192c372029e9e9b0c3b0c")
    a += bytearray.fromhex("2c57f559fdd03dc9a9443633bf4a1f0b5306341fbf67d47ef5bef488a82f5adb75e860182004899f9ad9ad48a5c36d08")
    a += bytearray.fromhex("b2e7a310546da097a4f53d663c875fea9cf99e7e6a1c607d23004c368f1f4955c00c2352f10484e582115d83cb5cd019")
    a += bytearray.fromhex("f6aed3544c28c8b9efda117c0b8241adc55ed0ee88c6bce0a06f41a11a1ddb939ddba145345d9e78854c554554357414")
    a += bytearray.fromhex("15a66fbe62fa646a72f15b3ffdccdae69abfc78c290cebb24fbb96b781375f87fbdb4168ccc04f245f02531b38e1400a")
    gen_memstore(buffer_miller_output,a)


def gen_tests():

  print("#include \"../inversemod_bls12381.huff\"")

  # init memory with consts like the modulus
  print("#define macro INIT_MEM = takes(0) returns(0) {")
  gen_consts(1)
  print("} // INIT_MEM")

  # these are just some hard-coded inputs which may be useful for testing
  print("#define macro MILLER_LOOP_TEST_VALUES = takes(0) returns(0) {")
  gen_miller_loop_test_input()  # hard-code values for testing
  print("} // MILLER_LOOP_TEST_VALUES")
  print("#define macro FINAL_EXPONENTIATION_TEST_VALUES = takes(0) returns(0) {")
  gen_final_exp_test_input()    # hard-code values for testing
  print("} // FINAL_EXPONENTIATION_TEST_VALUES")

  # miller loop macro
  print("#define macro MILLER_LOOP = takes(0) returns(0) {")
  #gen_consts(1)                        # consts like the modulus, this is required
  gen_miller_loop(buffer_miller_output,buffer_inputs,buffer_inputs+96,mod)
  print("} // MILLER_LOOP")

  # final exponentiation macro
  print("#define macro FINAL_EXPONENTIATION = takes(0) returns(0) {")
  gen_final_exponentiation_with_function_calls_optimized_mem_locations(buffer_finalexp_output,buffer_miller_output,mod)
  print("} // FINAL_EXPONENTIATION")


if __name__=="__main__":
  gen_tests()
