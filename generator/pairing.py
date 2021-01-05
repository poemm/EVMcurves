from util import *
from fields import *
from curve import *

# test e(p, q * 2) * e(p, -q * 2) == 1
def gen_pairing_eq2_test_input_2():
    # G1 generator (montgomery):
    input_val = bytearray.fromhex("120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16")[::-1]
    input_val += bytearray.fromhex("0bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271")[::-1]
    gen_memstore(p_g1_1,input_val)

    # G2_gen * 2 
    input_val =  bytearray.fromhex("05710794c255c06441d7c12786354493cfdb31c9b0b64f4c3db3b820376bed2754f1199346b97f36e9d9e2da9620f98b")[::-1]
    input_val += bytearray.fromhex("08d7ea71ea91ef8148cc8433925ef70e8ade5d736f8c97e04f5352d43479221dda0cbd905595489fd6c1d3ca6ea0d06e")[::-1]
    input_val += bytearray.fromhex("21dcf93f255e8dd8b6dc812aeecf46a6123bae4fc8b848dd652f4c780d086d64b7e9e01e15ba26eb4b0d186f08d7ea71")[::-1]
    input_val += bytearray.fromhex("25cb89cf3556b155066a210541c777878931e3da6856301fc89f086ed417b114cccff748f9b4a1a895984db4164142af")[::-1]
    gen_memstore(p_g2_1,input_val)

    # G1 generator 
    input_val =  bytearray.fromhex("120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16")[::-1]
    input_val += bytearray.fromhex("0bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271")[::-1]
    gen_memstore(p_g1_2,input_val)

    # -G2_gen * 2 
    input_val =  bytearray.fromhex("05710794c255c06441d7c12786354493cfdb31c9b0b64f4c3db3b820376bed2754f1199346b97f36e9d9e2da9620f98b")[::-1]
    input_val += bytearray.fromhex("08d7ea71ea91ef8148cc8433925ef70e8ade5d736f8c97e04f5352d43479221dda0cbd905595489fd6c1d3ca6ea0d06e")[::-1]
    input_val += bytearray.fromhex("17a2ed5b25bd19dd8c6f2bac75a804dee149646f9e7889c39181a9ac11a39299f96a1fe1a444d914b4f2923c08d7ea71")[::-1]
    input_val += bytearray.fromhex("13b45ccb15c4f6613ce18bd222afd3fd6a532ee4fedaa2812e11edb54a944ee9e48408b6c04a5e576a675cf703bfcf3b")[::-1]
    gen_memstore(p_g2_2,input_val)

# "naive" pairingEq2 test: e(p, q) * e(-p, q) == 1
def gen_pairing_eq2_test_input():
    # G1 generator (montgomery):
    input_val = bytearray.fromhex("120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16")[::-1]
    input_val += bytearray.fromhex("0bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271")[::-1]

    gen_memstore(p_g1_1,input_val)

    # G2 generator (montgomery):
    input_val = bytearray.fromhex("058191924350bcd76f67b7631863366b9894999d1a3caee9a1a893b53e2ae580b3f5fb2687b4961af5f28fa202940a10")[::-1] 
    input_val += bytearray.fromhex("11922a097360edf3c2b6ed0ef21585471b1ab6cc8541b3673bb17e18e2867806aaa0c59dbccd60c3a5a9c0759e23f606")[::-1] 
    input_val += bytearray.fromhex("0083fd8e7e80dae507d3a975f0ef25a2bbefb5e96e0d495fe7e6856caa0a635a597cfa1f5e369c5a4c730af860494c4a")[::-1] 
    input_val += bytearray.fromhex("0b2bc2a163de1bf2e7175850a43ccaed79495c4ec93da33a86adac6a3be4eba018aa270a2b1461dcadc0fc92df64b05d")[::-1] 
    gen_memstore(p_g2_1,input_val)

    # -G1 (montgomery):
    input_val = bytearray.fromhex("120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16")[::-1]
    input_val += bytearray.fromhex("0e44d2ede97744303cff1b76964b531712caf35ba344c12a89d7738d9fa9d05592899ce4383b0270ff526c2af318883a")[::-1]
    gen_memstore(p_g1_2,input_val)

    # G2 generator (montgomery):
    input_val = bytearray.fromhex("058191924350bcd76f67b7631863366b9894999d1a3caee9a1a893b53e2ae580b3f5fb2687b4961af5f28fa202940a10")[::-1] 
    input_val += bytearray.fromhex("11922a097360edf3c2b6ed0ef21585471b1ab6cc8541b3673bb17e18e2867806aaa0c59dbccd60c3a5a9c0759e23f606")[::-1] 
    input_val += bytearray.fromhex("0083fd8e7e80dae507d3a975f0ef25a2bbefb5e96e0d495fe7e6856caa0a635a597cfa1f5e369c5a4c730af860494c4a")[::-1] 
    input_val += bytearray.fromhex("0b2bc2a163de1bf2e7175850a43ccaed79495c4ec93da33a86adac6a3be4eba018aa270a2b1461dcadc0fc92df64b05d")[::-1] 
    gen_memstore(p_g2_2,input_val)


##############
# Miller Loop

# hard-coded miller loop inputs, optional
# these inputs can be hard-coded anywhere before the miller loop starts, we copy/paste the output of this function into main.huff
def gen_miller_loop_test_input():
  case = 2
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
    # generators (in montgomery)
    # G1:
    inE1  = bytearray.fromhex("120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16")[::-1]
    inE1 += bytearray.fromhex("0bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271")[::-1]
    gen_memstore(buffer_inputs,inE1)
    # G2:
    inE2  = bytearray.fromhex("058191924350bcd76f67b7631863366b9894999d1a3caee9a1a893b53e2ae580b3f5fb2687b4961af5f28fa202940a10")[::-1] 
    inE2 += bytearray.fromhex("11922a097360edf3c2b6ed0ef21585471b1ab6cc8541b3673bb17e18e2867806aaa0c59dbccd60c3a5a9c0759e23f606")[::-1] 
    inE2 += bytearray.fromhex("0083fd8e7e80dae507d3a975f0ef25a2bbefb5e96e0d495fe7e6856caa0a635a597cfa1f5e369c5a4c730af860494c4a")[::-1] 
    inE2 += bytearray.fromhex("0b2bc2a163de1bf2e7175850a43ccaed79495c4ec93da33a86adac6a3be4eba018aa270a2b1461dcadc0fc92df64b05d")[::-1] 
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

def gen_line_add(line,T,R,Q,mod):
  # line is 3 f2s, T on E2, R on E2, Q on E2 affine
  TZ = T+192
  QX = Q
  QY = QX+96
  line0 = line
  line1 = line0+96
  line2 = line1+96
  # ecadd
  I,J,r = gen_Eadd__madd_2007_bl("f2",T,R,Q,line1,mod)
  # line eval
  gen_f2mul(I,r,QX,mod)
  gen_f2mul(J,QY,TZ,mod)
  gen_f2sub(I,I,J,mod)
  gen_f2add(line0,I,I,mod)
  #gen_memcopy(line1,r,96)	# already done in the 
  gen_memcopy(line2,TZ,96)	
  
def gen_line_dbl(line,T,Q,mod):
  # line is 3 f2s, T is E2 point, Q E2 point	(note: our pairing algorithm, T=Q)
  line0 = line
  line1 = line0+96
  line2 = line1+96
  QX = Q
  TZ = T+192
  # double
  A,B,E,F,ZZ,X1 = gen_Edouble__dbl_2009_alnr("f2",T,Q,line0,mod)
  # eval line
  # note: line0=E+QX is already done in alnr function
  gen_f2sqr(line0,line0,mod)
  gen_f2sub(line0,line0,A,mod)
  gen_f2sub(line0,line0,F,mod)
  gen_f2add(B,B,B,mod)
  gen_f2add(B,B,B,mod)
  gen_f2sub(line0,line0,B,mod)
  gen_f2mul(line1,E,ZZ,mod)
  gen_f2mul(line2,TZ,ZZ,mod)
 
def gen_line_by_Px2(line,Px2,mod):
  # line is 3 f2s, Px2 is E1 point affine
  Px2X = Px2
  Px2Y = Px2X+48
  line00 = line
  line01 = line00+48
  line10 = line01+48
  line11 = line10+48
  line20 = line11+48
  line21 = line20+48
  gen_f1mul(line10,line10,Px2X,mod)
  gen_f1mul(line11,line11,Px2X,mod)
  gen_f1mul(line20,line20,Px2Y,mod)
  gen_f1mul(line21,line21,Px2Y,mod)

def gen_start_dbl(out,T,Px2,mod):
  # out is f12 point (ie 2 f6 pts), T is E2 point, Px2 is E1 point (affine)
  out00 = out
  out11 = out+288+96	# ??
  line = buffer_line	# 3 f2 points
  line0 = line
  line2 = line0+192
  gen_line_dbl(line,T,T,mod)
  gen_line_by_Px2(line,Px2,mod)
  gen_memcopy(out,zero,576)
  gen_memcopy(out00,line0,192)
  gen_memcopy(out11,line2,96)

count_pairing_eq2_test = 0
def gen_add_dbl_loop(out,T,Q,Px2,mod):
  global count_pairing_eq2_test
  count_pairing_eq2_test+=1
  line = buffer_line	# 3 f2 points
  print("63")           # loop iterator will be decremented on stack
  print("miller_loop"+str(count_pairing_eq2_test)+":")
  print("0x1 swap1 sub")        # decrement loop iterator and leave it a top of stack
  print("0xd201000000010000 dup2 shr")   # get the next bit by shifting by loop iterator
  print("0x1 and")              # get next bit by shifting by loop iterator
  print("0x1 xor end_if"+str(count_pairing_eq2_test)+" jumpi")         # skip if next bit was 1 (ie skip if flipped bit is 1)
  print("begin_if"+str(count_pairing_eq2_test)+":")    # if 1 bit, then add
  gen_line_add(line,T,T,Q,mod)
  gen_line_by_Px2(line,Px2,mod)
  gen_mul_by_xy00z0_fp12(out,out,line,mod)
  print("end_if"+str(count_pairing_eq2_test)+":")
  gen_f12sqr(out,out,mod)
  gen_line_dbl(line,T,T,mod)
  gen_line_by_Px2(line,Px2,mod)
  gen_mul_by_xy00z0_fp12(out,out,line,mod)
  print("dup1 1 lt")          # check if 1 < loop iterator	note: don't iterate on least significant bit
  print("miller_loop"+str(count_pairing_eq2_test)+" jumpi")    # if loop iterator > 0, then jump to next iter
  print("pop")			# pop loop iterator to leave stack how we found it
  """
  this loop is over 0xd201000000010000 which in binary is:
1
10
100
100000000
10000000000000000000000000000000
10000000000000000
  """

def gen_miller_loop(out,P,Q,mod):
  # P is E1 point (affine), Q is E2 point (affine)
  PX = P
  PY = PX+48
  QX = Q
  # temp offsets
  T = buffer_miller_loop	# E2 point
  TX = T
  TY = TX+96
  TZ = TY+96
  Px2 = T+288			# E1 point (affine)
  Px2X = Px2
  Px2Y = Px2+48

  # prepare some stuff
  gen_f1add(Px2X,PX,PX,mod)
  gen_f1neg(Px2X,Px2X,mod)
  gen_f1add(Px2Y,PY,PY,mod)
  gen_memcopy(TX,QX,192)
  gen_memcopy(TZ,f12one,96)

  # execute
  gen_start_dbl(out,T,Px2,mod)
  gen_add_dbl_loop(out,T,Q,Px2,mod)
  gen_f12conjugate(out,mod)

# Miller Loop
##############



#######################
# final exponentiaiton

"""
This version of final exponentiaiton wraps f12mul and f12sqrcyclotomic in function calls.
This is needed to keep the bytecode size small.
An explanation of function calls:
Final exponentiation has very large bytecode size when fully unrolled. To try to minimize bytecode size, we made f12raise_to_z_div_by_2 into a bit-iterator loop, but the bytecode was still too large.
The two biggest pieces of bytecode are f12mul and f12sqrcyclotomic. So we have one instance of each of these in the bytecode and we jump to/from them. We call this jumping to/from as function calls.
Function calls operate on hard-coded memory offsets, so there may be memcopy input/output overhead. We try to minimize this memcopying by conveniently having values already there when possible.
"""

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

def gen_f12raise_to_z_with_function_calls(out,x,mod):
  if x!=buffer_f12_function2:
    gen_memcopy(buffer_f12_function2,x,48*12)
  gen_f12raise_to_z_div_by_2_with_function_calls(buffer_f12_function,buffer_f12_function2,mod)
  gen_f12sqrcyclotomic_loop_with_function_call(buffer_f12_function,buffer_f12_function,mod,1)
  if out!=buffer_f12_function:
    gen_memcopy(out,buffer_f12_function,48*12)

def gen_f12raise_to_z_div_by_2_with_function_calls(out,x,mod):
  if x not in [buffer_f12_function,buffer_f12_function2]:
    gen_mergedmemcopy([buffer_f12_function,buffer_f12_function2],x,48*12)
  elif x!=buffer_f12_function:
    gen_memcopy(buffer_f12_function,x,48*12)
  elif x!=buffer_f12_function2:
    gen_memcopy(buffer_f12_function2,x,48*12)
  gen_f12sqrcyclotomic_loop_with_function_call(buffer_f12_function,buffer_f12_function,mod,1)
  gen_f12mul_n_sqr_with_function_calls(buffer_f12_function,buffer_f12_function,buffer_f12_function2,mod,2)
  gen_f12mul_n_sqr_with_function_calls(buffer_f12_function,buffer_f12_function,buffer_f12_function2,mod,3)
  gen_f12mul_n_sqr_with_function_calls(buffer_f12_function,buffer_f12_function,buffer_f12_function2,mod,9)
  gen_f12mul_n_sqr_with_function_calls(buffer_f12_function,buffer_f12_function,buffer_f12_function2,mod,32)
  gen_f12mul_n_sqr_with_function_calls(buffer_f12_function,buffer_f12_function,buffer_f12_function2,mod,16-1)
  gen_f12conjugate(buffer_f12_function,mod)
  if out!=buffer_f12_function:
    gen_memcopy(out,buffer_f12_function,48*12)

def gen_f12mul_n_sqr_with_function_calls(out,x,y,mod,numiters):
  if x!=buffer_f12_function:
    gen_memcopy(buffer_f12_function,x,48*12)
  if y!=buffer_f12_function2:
    gen_memcopy(buffer_f12_function2,y,48*12)
  gen_f12mul_with_function_call(buffer_f12_function,buffer_f12_function,buffer_f12_function2,mod)
  gen_f12sqrcyclotomic_loop_with_function_call(buffer_f12_function,buffer_f12_function,mod,numiters)
  if out!=buffer_f12_function:
    gen_memcopy(out,buffer_f12_function,48*12)

count_f12mul_function_call_num = 0
def gen_f12mul_with_function_call(out,x,y,mod):
  global count_f12mul_function_call_num
  count_f12mul_function_call_num+=1
  if x!=buffer_f12_function:
    gen_memcopy(buffer_f12_function,x,48*12)
  if y!=buffer_f12_function2:
    gen_memcopy(buffer_f12_function2,y,48*12)
  print("f12mul_return_location"+str(count_f12mul_function_call_num))	# push return location
  print("f12mul_function_call jump")	# jump to f12mul
  print("f12mul_return_location"+str(count_f12mul_function_call_num)+":")	# return location
  if out!=buffer_f12_function:
    gen_memcopy(out,buffer_f12_function,48*12)

def gen_f12mul_function(out,x,mod):
  # stack should be: returndest
  print("f12mul_function_call:")
  gen_f12mul(out,out,x,mod)
  print("jump")	# jump to returndest

count_f12sqrcyclotomic_loop_with_function_call_num = 0
def gen_f12sqrcyclotomic_loop_with_function_call(out,x,mod,numiters):
  global count_f12sqrcyclotomic_loop_with_function_call_num
  count_f12sqrcyclotomic_loop_with_function_call_num+=1
  if x!=buffer_f12_function:
    gen_memcopy(buffer_f12_function,x,48*12)
  # set up stack: return_jumpdest, numiters
  print("f12sqrcyclotomic_loop_return_location"+str(count_f12sqrcyclotomic_loop_with_function_call_num))	# push jumpdest to return to
  print(numiters)	# push number of iterations
  print("f12sqrcyclotomic_loop_function_call jump")
  print("f12sqrcyclotomic_loop_return_location"+str(count_f12sqrcyclotomic_loop_with_function_call_num)+":")
  if out!=buffer_f12_function:
    gen_memcopy(out,buffer_f12_function,48*12)

def gen_f12sqrcyclotomic_loop_function(out,x,mod):
  # stack should be: returndest, numiters
  print("f12sqrcyclotomic_loop_function_call:")
  gen_f12sqrcyclotomic(out,x,mod)
  print("0x1 swap1 sub")      # decrement loop iterator and leave it a top of stack
  print("dup1 0 lt")          # check if 0 < loop iterator
  print("f12sqrcyclotomic_loop_function_call jumpi")    # if loop iterator > 0, then jump to next iter
  print("pop") 	# pop numiters
  print("jump")	# jump to returndest
 
def gen_final_exponentiation_with_function_calls(out,in_,mod):
  y0 = buffer_finalexp
  y1 = y0+12*48
  y2 = y1+12*48
  y3 = y2+12*48

  gen_frobenius_coeffs()

  if 0:	# if don't want to clobber input
    gen_memcopy(y1,in_,48*12)
  else:
    y1 = in_
  gen_f12conjugate(y1,mod)
  gen_f12inverse(y2,in_,mod)
  gen_f12mul_with_function_call(out,y1,y2,mod)
  gen_f12frobeniusmap(y2,out,2,mod)
  gen_f12mul_with_function_call(out,out,y2,mod)

  gen_f12sqrcyclotomic_loop_with_function_call(y0,out,mod,1)
  gen_f12raise_to_z_with_function_calls(y1,y0,mod)
  gen_f12raise_to_z_div_by_2_with_function_calls(y2,y1,mod)
  gen_memcopy(y3,out,48*12)
  gen_f12conjugate(y3,mod)
  gen_f12mul_with_function_call(y1,y1,y3,mod)
  gen_f12conjugate(y1,mod)
  gen_f12mul_with_function_call(y1,y1,y2,mod)
  gen_f12raise_to_z_with_function_calls(y2,y1,mod)
  gen_f12raise_to_z_with_function_calls(y3,y2,mod)
  gen_f12conjugate(y1,mod)
  gen_f12mul_with_function_call(y3,y3,y1,mod)
  gen_f12conjugate(y1,mod)
  gen_f12frobeniusmap(y1,y1,3,mod)
  gen_f12frobeniusmap(y2,y2,2,mod)
  gen_f12mul_with_function_call(y1,y1,y2,mod)
  gen_f12raise_to_z_with_function_calls(y2,y3,mod)
  gen_f12mul_with_function_call(y2,y2,y0,mod)
  gen_f12mul_with_function_call(y2,y2,out,mod)
  gen_f12mul_with_function_call(y1,y1,y2,mod)
  gen_f12frobeniusmap(y2,y3,1,mod)
  gen_f12mul_with_function_call(out,y1,y2,mod)

  # generate the actual functions which we "call"
  gen_f12mul_function(buffer_f12_function,buffer_f12_function2,mod)
  gen_f12sqrcyclotomic_loop_function(buffer_f12_function,buffer_f12_function,mod)

# input and output are hardcoded to be expected at buffer_f12_functionc
def gen_final_exponentiation_with_function_calls_optimized_mem_locations(mod):
  y0 = buffer_finalexp
  y1 = y0+12*48
  y2 = y1+12*48
  y3 = y2+12*48
  y4 = y3+12*48

  gen_frobenius_coeffs()

  # buffers for function calls
  b1=buffer_f12_function
  b2=buffer_f12_function2

  gen_f12inverse(b2,b1,mod)
  gen_f12conjugate(b1,mod)
  gen_f12mul_with_function_call(b1,b1,b2,mod)
  gen_f12frobeniusmap(b2,b1,2,mod)
  gen_f12mul_with_function_call(b1,b1,b2,mod)
  
  #gen_memcopy(y0,b1,48*12)
  #gen_memcopy(y1,b1,48*12)
  gen_mergedmemcopy([y0,y1],b1,48*12)	# this is the above two memcopys but merged, to save bytecode size

  gen_f12sqrcyclotomic_loop_with_function_call(b1,b1,mod,1)

  gen_memcopy(y2,b1,48*12)
  gen_f12raise_to_z_with_function_calls(b1,b1,mod)
  gen_memcopy(y3,b1,48*12)
  gen_f12raise_to_z_div_by_2_with_function_calls(b1,b1,mod)
  gen_memcopy(y4,b1,48*12)
  gen_f12conjugate(y0,mod)
  gen_f12mul_with_function_call(b1,y3,y0,mod)
  gen_f12conjugate(b1,mod)
  gen_f12mul_with_function_call(b1,b1,y4,mod)
  gen_memcopy(y0,b1,48*12)
  gen_f12raise_to_z_with_function_calls(b1,b1,mod)
  gen_memcopy(y3,b1,48*12)
  gen_f12raise_to_z_with_function_calls(b1,b1,mod)
  gen_f12conjugate(y0,mod)
  gen_f12mul_with_function_call(b1,b1,y0,mod)
  gen_memcopy(y4,b1,48*12)
  gen_f12conjugate(y0,mod)
  gen_f12frobeniusmap(y0,y0,3,mod)
  gen_f12frobeniusmap(y3,y3,2,mod)
  gen_f12mul_with_function_call(b1,y0,y3,mod)
  gen_memcopy(y0,b1,48*12)
  gen_f12raise_to_z_with_function_calls(b1,y4,mod)
  gen_f12mul_with_function_call(b1,b1,y2,mod)
  gen_f12mul_with_function_call(b1,b1,y1,mod)
  gen_f12mul_with_function_call(b1,b1,y0,mod)
  gen_f12frobeniusmap(y1,y4,1,mod)
  gen_f12mul_with_function_call(b1,b1,y1,mod)

  print("final_exp_done jump")

  # generate the actual functions which for "function calls"
  gen_f12mul_function(b1,b2,mod)
  gen_f12sqrcyclotomic_loop_function(b1,b1,mod)

  print("final_exp_done:")

# final exponentiaiton
#######################



######################
# the main generators

# this is the place to build your cyptosystem with building-blocks defined above

# consts for BLS12-381
def gen_consts(miller_loop_flag):
  if miller_loop_flag:
    # one in mont form
    one = "15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd"
    gen_memstore(f12one,bytearray.fromhex(one)[::-1])
  # prime and montgomery parameter 89f3fffcfffcfffd
  p = "89f3fffcfffcfffd1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
  gen_memstore(mod,bytes.fromhex(p)[::-1])

def gen_pairing():
  print("#include \"inversemod_bls12381.huff\"")

  # init memory with consts like the modulus
  print("#define macro INIT_MEM = takes(0) returns(0) {")
  gen_consts(1)	
  print("} // INIT_MEM")

  # these are just some hard-coded inputs which may be useful for testing
  print("#define macro MILLER_LOOP_TEST_VALUES = takes(0) returns(0) {")
  gen_miller_loop_test_input()	# hard-code values for testing
  print("} // MILLER_LOOP_TEST_VALUES")
  print("#define macro PAIRING_EQ2_TEST_VALUES = takes(0) returns(0) {")
  gen_pairing_eq2_test_input()	# hard-code values for testing
  print("} // MILLER_LOOP_TEST_VALUES")
  print("#define macro FINAL_EXPONENTIATION_TEST_VALUES = takes(0) returns(0) {")
  gen_final_exp_test_input()	# hard-code values for testing
  print("} // FINAL_EXPONENTIATION_TEST_VALUES")

  # miller loop macro
  print("#define macro MILLER_LOOP = takes(0) returns(0) {")
  #gen_consts(1)			# consts like the modulus, this is required
  gen_miller_loop(buffer_miller_output,buffer_inputs,buffer_inputs+96,mod)
  print("} // MILLER_LOOP")

  # final exponentiation macro
  print("#define macro FINAL_EXPONENTIATION = takes(0) returns(0) {")
  gen_final_exponentiation_with_function_calls_optimized_mem_locations(mod)
  print("} // FINAL_EXPONENTIATION")

  # pairing equation with two pairings, using the multi-pairing trick so only one final exponentiation
  # this is untested, but it has two miller loops, a f2mul, a final exponentiation, and an equality check
  print("#define macro PAIRING_EQ2 = takes(0) returns(0) {")

  # first miller loop
  gen_miller_loop(buffer_miller_output,p_g1_1,p_g2_1,mod)
  gen_memcopy(buffer_f12_function2,buffer_miller_output,48*12)

  # second miller loop
  gen_miller_loop(buffer_miller_output,p_g1_2,p_g2_2,mod)
  gen_memcopy(buffer_f12_function,buffer_miller_output,48*12)

  # multiply the two miller loop outputs
  gen_f12mul_with_function_call(buffer_f12_function,buffer_f12_function,buffer_f12_function2,mod)

  # final exp
  gen_final_exponentiation_with_function_calls_optimized_mem_locations(mod)
  gen_memcopy(buffer_finalexp_output, buffer_f12_function, 12 * 48)

  gen_equals(buffer_finalexp_output, f12one,buffer_finalexp_output,12*48)
  gen_return(buffer_finalexp_output, 32)

  print("} // PAIRING_EQ2")

# the main generators
######################



##################################################
# unrolled pairing, for troubleshooting/debugging

def gen_add_dbl_unrolled(out,T,Q,Px2,k,mod):
  line = buffer_line    # 3 f2 points
  gen_line_add(line,T,T,Q,mod)
  gen_line_by_Px2(line,Px2,mod)
  gen_mul_by_xy00z0_fp12(out,out,line,mod)
  for i in range(k):
    gen_f12sqr(out,out,mod)
    gen_line_dbl(line,T,T,mod)
    gen_line_by_Px2(line,Px2,mod)
    gen_mul_by_xy00z0_fp12(out,out,line,mod)

def gen_miller_loop_unrolled(out,P,Q,mod):
  # P is E1 point (affine), Q is E2 point (affine)
  PX = P
  PY = PX+48
  QX = Q
  # temp offsets
  T = buffer_miller_loop	# E2 point
  TX = T
  TY = TX+96
  TZ = TY+96
  Px2 = T+288			# E1 point (affine)
  Px2X = Px2
  Px2Y = Px2+48
  # prepare some stuff
  gen_f1add(Px2X,PX,PX,mod)
  gen_f1neg(Px2X,Px2X,mod)
  gen_f1add(Px2Y,PY,PY,mod)
  gen_memcopy(TX,QX,192)
  gen_memcopy(TZ,f12one,96)
  # execute
  gen_start_dbl(out,T,Px2,mod)
  gen_add_dbl_unrolled(out,T,Q,Px2,2,mod)
  gen_add_dbl_unrolled(out,T,Q,Px2,3,mod)
  gen_add_dbl_unrolled(out,T,Q,Px2,9,mod)
  gen_add_dbl_unrolled(out,T,Q,Px2,32,mod)
  gen_add_dbl_unrolled(out,T,Q,Px2,16,mod)
  gen_f12conjugate(out,mod)

def gen_mul_n_sqr_unrolled(out,x,n,mod):
  gen_f12mul(out,out,x,mod)
  for i in range(n):
    gen_f12sqrcyclotomic(out,out,mod)

def gen_f12raise_to_z_div_by_2_unrolled(out,x,mod):
  gen_f12sqrcyclotomic(out,x,mod)
  gen_mul_n_sqr_unrolled(out,x,2,mod)
  gen_mul_n_sqr_unrolled(out,x,3,mod)
  gen_mul_n_sqr_unrolled(out,x,9,mod)
  gen_mul_n_sqr_unrolled(out,x,32,mod)
  gen_mul_n_sqr_unrolled(out,x,16-1,mod)
  gen_f12conjugate(out,mod)

def gen_f12raise_to_z_unrolled(out,x,mod):
  gen_f12raise_to_z_div_by_2_unrolled(out,x,mod)
  gen_f12sqrcyclotomic(out,out,mod)

def gen_final_exponentiation_unrolled(out,in_,mod):
  y0 = buffer_finalexp
  y1 = y0+12*48
  y2 = y1+12*48
  y3 = y2+12*48

  gen_frobenius_coeffs()

  gen_memcopy(y1,in_,48*12)
  gen_f12conjugate(y1,mod)
  gen_f12inverse(y2,in_,mod)
  gen_f12mul(out,y1,y2,mod)
  gen_f12frobeniusmap(y2,out,2,mod)
  gen_f12mul(out,out,y2,mod)

  gen_f12sqrcyclotomic(y0,out,mod)
  gen_f12raise_to_z_unrolled(y1,y0,mod)
  gen_f12raise_to_z_div_by_2_unrolled(y2,y1,mod)
  gen_memcopy(y3,out,48*12)
  gen_f12conjugate(y3,mod)
  gen_f12mul(y1,y1,y3,mod)
  gen_f12conjugate(y1,mod)
  gen_f12mul(y1,y1,y2,mod)
  gen_f12raise_to_z_unrolled(y2,y1,mod)
  gen_f12raise_to_z_unrolled(y3,y2,mod)
  gen_f12conjugate(y1,mod)
  gen_f12mul(y3,y3,y1,mod)
  gen_f12conjugate(y1,mod)
  gen_f12frobeniusmap(y1,y1,3,mod)
  gen_f12frobeniusmap(y2,y2,2,mod)
  gen_f12mul(y1,y1,y2,mod)
  gen_f12raise_to_z_unrolled(y2,y3,mod)
  gen_f12mul(y2,y2,y0,mod)
  gen_f12mul(y2,y2,out,mod)
  gen_f12mul(y1,y1,y2,mod)
  gen_f12frobeniusmap(y2,y3,1,mod)
  gen_f12mul(out,y1,y2,mod)
