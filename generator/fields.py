from util import *

# general ops when field can change, eg used for curve add and dbl
def gen_fadd(f,out,x,y,mod):
  if f=="f12":
    gen_f12add(out,x,y,mod)
  if f=="f6":
    gen_f6add(out,x,y,mod)
  if f=="f2":
    gen_f2add(out,x,y,mod)
  if f=="f1":
    gen_f1add(out,x,y,mod)

def gen_fsub(f,out,x,y,mod):
  if f=="f12":
    gen_f12sub(out,x,y,mod)
  if f=="f6":
    gen_f6sub(out,x,y,mod)
  if f=="f2":
    gen_f2sub(out,x,y,mod)
  if f=="f1":
    gen_f1sub(out,x,y,mod)

def gen_fmul(f,out,x,y,mod):
  if f=="f12":
    gen_f12mul(out,x,y,mod)
  if f=="f6":
    gen_f6mul(out,x,y,mod)
  if f=="f2":
    gen_f2mul(out,x,y,mod)
  if f=="f1":
    gen_f1mul(out,x,y,mod)

def gen_fsqr(f,out,x,mod):
  if f=="f12":
    gen_f12sqr(out,x,mod)
  if f=="f6":
    gen_f6sqr(out,x,mod)
  if f=="f2":
    gen_f2sqr(out,x,mod)
  if f=="f1":
    gen_f1sqr(out,x,mod)


# f1

def gen_f1add(out,x,y,mod):
  global addmod384_count
  gen_evm384_offsets(out,x,y,mod); print("addmod384"); addmod384_count+=1

def gen_f1sub(out,x,y,mod):
  global submod384_count
  gen_evm384_offsets(out,x,y,mod); print("submod384"); submod384_count+=1

def gen_f1mul(out,x,y,mod):
  global mulmodmont384_count
  gen_evm384_offsets(out,x,y,mod); print("mulmodmont384"); mulmodmont384_count+=1
  
def gen_f1neg(out,x,mod):
  global submod384_count
  gen_evm384_offsets(out,f1zero,x,mod); print("submod384"); submod384_count+=1

def gen_f1inverse(out,x,mod):
  print("INVERSEMOD_BLS12381()")	# this is in a separate huff file
  #print("INVERSEMOD_BLS12381_NAIVE()")	# this is in a separate huff file
  pass


# f2

def gen_f2add(out,x,y,mod):
  global f2add_count
  f2add_count+=1
  print("// f2 add")
  x0 = x
  x1 = x+48
  y0 = y
  y1 = y+48
  out0 = out
  out1 = out+48
  gen_f1add(out0,x0,y0,mod)
  gen_f1add(out1,x1,y1,mod)

def gen_f2sub(out,x,y,mod):
  global f2sub_count
  f2sub_count+=1
  print("// f2 sub")
  x0 = x
  x1 = x+48
  y0 = y
  y1 = y+48
  out0 = out
  out1 = out+48
  gen_f1sub(out0,x0,y0,mod)
  gen_f1sub(out1,x1,y1,mod)

def gen_f2mul(out,x,y,mod):
  global f2mul_count
  f2mul_count+=1
  print("// f2 mul")
  # get offsets
  x0 = x
  x1 = x+48
  y0 = y
  y1 = y+48
  out0 = out
  out1 = out+48
  # temporary values
  tmp1 = buffer_f2mul
  tmp2 = tmp1+48
  tmp3 = tmp2+48
  case=3  # choose a case to experiment with different f2muls
  if case==0:
    pass # deleted, similar to case 3
  elif case==1:
    pass # deleted, similar to case 3
  elif case==2:
    pass # deleted, similar to case 3
  elif case==3:	# use this to match blst values
    aa=tmp1
    bb=tmp2
    cc=tmp3
    gen_f1add(aa,x0,x1,mod)
    gen_f1add(bb,y0,y1,mod)
    gen_f1mul(bb,bb,aa,mod)
    gen_f1mul(aa,x0,y0,mod)
    gen_f1mul(cc,x1,y1,mod)
    gen_f1sub(out0,aa,cc,mod)
    gen_f1sub(out1,bb,aa,mod)
    gen_f1sub(out1,out1,cc,mod)
  elif case==4:  # this is naive f2mul with four f1mul's, but may be better for EVM since uses two less opcodes
    gen_f1mul(tmp1,x0,y0,mod)
    gen_f1mul(tmp2,x1,y1,mod)
    gen_f1sub(out0,tmp1,tmp2,mod)
    gen_f1mul(tmp1,x0,y1,mod)
    gen_f1mul(tmp2,x1,y0,mod)
    gen_f1add(out1,tmp1,tmp2,mod)

def gen_f2sqr(out,x,mod):
  global f2mul_count
  f2mul_count+=1
  print("// f2sqr")
  # get offsets
  x0 = x
  x1 = x+48
  out0 = out
  out1 = out+48
  tmp0 = buffer_f2mul
  tmp1 = tmp0+48
  gen_f1add(tmp0,x0,x1,mod)
  gen_f1sub(tmp1,x0,x1,mod)
  gen_f1mul(out1,x0,x1,mod)
  gen_f1add(out1,out1,out1,mod)
  gen_f1mul(out0,tmp0,tmp1,mod)
 
def gen_f2neg(out,in_,mod):
  #gen_f2sub(out,zero,in_,mod)
  gen_f1sub(out,mod,in_,mod)
  gen_f1sub(out+48,mod,in_+48,mod)

def gen_mul_by_u_plus_1_fp2(out,x,mod):
  t = buffer_f2mul	# to prevent clobbering, took a while to find this bug
  gen_f1add(t, x, x+48, mod)
  gen_f1sub(out, x, x+48, mod)
  gen_memcopy(out+48,t,48)

def gen_f2inverse(out,x,mod):
  # get offsets
  x0 = x
  x1 = x+48
  out0 = out
  out1 = out+48
  # temporary values
  t0 = buffer_f2mul
  t1 = t0+48
  # algorithm
  gen_f1mul(t0,x0,x0,mod)
  gen_f1mul(t1,x1,x1,mod)
  gen_f1add(t0,t0,t1,mod)

  gen_f1inverse(t1,t0,mod)

  gen_f1mul(out0,x0,t1,mod)
  gen_f1mul(out1,x1,t1,mod)
  gen_f1neg(out1,out1,mod)


# f6

def gen_f6add(out,x,y,mod):
  global f6add_count
  f6add_count+=1
  print("// f6 add")
  x0 = x
  x1 = x0+96
  x2 = x1+96
  y0 = y
  y1 = y0+96
  y2 = y1+96
  out0 = out
  out1 = out0+96
  out2 = out1+96
  gen_f2add(out0,x0,y0,mod)
  gen_f2add(out1,x1,y1,mod)
  gen_f2add(out2,x2,y2,mod)

def gen_f6sub(out,x,y,mod):
  global f6sub_count
  f6sub_count+=1
  print("// f6 sub")
  x0 = x
  x1 = x0+96
  x2 = x1+96
  y0 = y
  y1 = y0+96
  y2 = y1+96
  out0 = out
  out1 = out0+96
  out2 = out1+96
  gen_f2sub(out0,x0,y0,mod)
  gen_f2sub(out1,x1,y1,mod)
  gen_f2sub(out2,x2,y2,mod)

def gen_f6neg(out,x,mod):
  x0=x
  x1=x0+96
  x2=x1+96
  out0=out
  out1=out0+96
  out2=out1+96
  gen_f2neg(out0,x0,mod)
  gen_f2neg(out1,x1,mod)
  gen_f2neg(out2,x2,mod)

def gen_f6mul(out,x,y,mod):
  global f6mul_count
  f6mul_count+=1
  print("// f6mul begin")
  x0 = x
  x1 = x0+96
  x2 = x1+96
  y0 = y
  y1 = y0+96
  y2 = y1+96
  out0 = out
  out1 = out0+96
  out2 = out1+96
  # temporary variables
  t0 = buffer_f6mul
  t1 = t0+96
  t2 = t1+96
  t3 = t2+96
  t4 = t3+96
  t5 = t4+96
  # algorithm
  gen_f2mul(t0,x0,y0,mod)
  gen_f2mul(t1,x1,y1,mod)
  gen_f2mul(t2,x2,y2,mod)
  # out0
  gen_f2add(t4,x1,x2,mod)
  gen_f2add(t5,y1,y2,mod)
  gen_f2mul(t3,t4,t5,mod)
  gen_f2sub(t3,t3,t1,mod)
  gen_f2sub(t3,t3,t2,mod)
  gen_mul_by_u_plus_1_fp2(t3,t3,mod)
  #gen_f2add(out0,t3,t0,mod)	# below
  # out1
  gen_f2add(t4,x0,x1,mod)
  gen_f2add(t5,y0,y1,mod)
  gen_f2mul(out1,t4,t5,mod)
  gen_f2sub(out1,out1,t0,mod)
  gen_f2sub(out1,out1,t1,mod)
  gen_mul_by_u_plus_1_fp2(t4,t2,mod)
  gen_f2add(out1,out1,t4,mod)
  # out2
  gen_f2add(t4,x0,x2,mod)
  gen_f2add(t5,y0,y2,mod)
  gen_f2mul(out2,t4,t5,mod)
  gen_f2sub(out2,out2,t0,mod)
  gen_f2sub(out2,out2,t2,mod)
  gen_f2add(out2,out2,t1,mod)

  gen_f2add(out0,t3,t0,mod)
  print("// f6mul end")

def gen_f6sqr(out,x,mod):
  print("// f6sqr begin")
  #gen_f6mul(out,x,x,mod)	# TODO: optimize
  x0 = x
  x1 = x0+96
  x2 = x1+96
  out0 = out
  out1 = out0+96
  out2 = out1+96
  # temporary variables
  s0 = buffer_f6mul
  m01 = s0+96
  m12 = m01+96
  s2 = m12+96
  # algorithm
  gen_f2sqr(s0,x0,mod)
  gen_f2mul(m01,x0,x1,mod)
  gen_f2add(m01,m01,m01,mod)
  gen_f2mul(m12,x1,x2,mod)
  gen_f2add(m12,m12,m12,mod)
  gen_f2sqr(s2,x2,mod)

  gen_f2add(out2,x2,x1,mod)
  gen_f2add(out2,out2,x0,mod)
  gen_f2sqr(out2,out2,mod)
  gen_f2sub(out2,out2,s0,mod)
  gen_f2sub(out2,out2,s2,mod)
  gen_f2sub(out2,out2,m01,mod)
  gen_f2sub(out2,out2,m12,mod)
  
  gen_mul_by_u_plus_1_fp2(out0,m12,mod)
  gen_f2add(out0,out0,s0,mod)
  
  gen_mul_by_u_plus_1_fp2(out1,s2,mod)
  gen_f2add(out1,out1,m01,mod)
  print("// f6sqr end")

def gen_f6inverse(out,x,mod):
  print("// f6inverse begin")
  x0 = x
  x1 = x0+96
  x2 = x1+96
  out0 = out
  out1 = out0+96
  out2 = out1+96
  # temporary variables
  t0 = buffer_f6mul
  t1 = t0+96
  c0 = t1+96
  c1 = c0+96
  c2 = c1+96
  # algorithm
  gen_f2sqr(c0,x0,mod)
  gen_f2mul(t0,x1,x2,mod)
  gen_mul_by_u_plus_1_fp2(t0,t0,mod)
  gen_f2sub(c0,c0,t0,mod)

  gen_f2sqr(c1,x2,mod)
  gen_mul_by_u_plus_1_fp2(c1,c1,mod)
  gen_f2mul(t0,x0,x1,mod)
  gen_f2sub(c1,c1,t0,mod)

  gen_f2sqr(c2,x1,mod)
  gen_f2mul(t0,x0,x2,mod)
  gen_f2sub(c2,c2,t0,mod)

  gen_f2mul(t0,c1,x2,mod)
  gen_f2mul(t1,c2,x1,mod)
  gen_f2add(t0,t0,t1,mod)
  gen_mul_by_u_plus_1_fp2(t0,t0,mod)
  gen_f2mul(t1,c0,x0,mod)
  gen_f2add(t0,t0,t1,mod)

  gen_f2inverse(t1,t0,mod)

  gen_f2mul(out0,c0,t1,mod)
  gen_f2mul(out1,c1,t1,mod)
  gen_f2mul(out2,c2,t1,mod)
  print("// f6inverse end")


# f12

def gen_f12add(out,x,y,mod):
  print("// f12add begin")
  global f12add_count
  f12add_count+=1
  print("// f6 add")
  x0 = x
  x1 = x0+288
  y0 = y
  y1 = y0+288
  out0 = out
  out1 = out0+288
  gen_f6add(out0,x0,y0,mod)
  gen_f6add(out1,x1,y1,mod)
  print("// f12add end")
  
def gen_f12sub(out,x,y,mod):
  print("// f12sub begin")
  global f12sub_count
  f12sub_count+=1
  print("// f6 add")
  x0 = x
  x1 = x0+288
  y0 = y
  y1 = y0+288
  out0 = out
  out1 = out0+288
  gen_f6sub(out0,x0,y0,mod)
  gen_f6sub(out1,x1,y1,mod)
  print("// f12sub end")

def gen_f12mul(out,x,y,mod):
  print("// f12mul begin")
  global f12mul_count
  f12mul_count+=1
  print("// f12 mul")
  x0 = x
  x1 = x0+288
  y0 = y
  y1 = y0+288
  out0 = out
  out00 = out0
  out01 = out00+96
  out02 = out01+96
  out1 = out0+288
  # temporary variables
  t0 = buffer_f12mul
  t00 = t0
  t01 = t00+96
  t02 = t01+96
  t1 = t0+288
  t10 = t1
  t11 = t10+96
  t12 = t11+96
  t2 = t1+288
  gen_f6mul(t0,x0,y0,mod)
  gen_f6mul(t1,x1,y1,mod)
  # out1
  gen_f6add(t2,x0,x1,mod)
  gen_f6add(out1,y0,y1,mod)
  gen_f6mul(out1,out1,t2,mod)
  gen_f6sub(out1,out1,t0,mod)
  gen_f6sub(out1,out1,t1,mod)
  # out0
  gen_mul_by_u_plus_1_fp2(t12,t12,mod)
  gen_f2add(out00,t00,t12,mod)
  gen_f2add(out01,t01,t10,mod)
  gen_f2add(out02,t02,t11,mod)
  print("// f12mul end")

def gen_f12sqr(out,x,mod):
  print("// f12sqr begin")
  x0 = x
  x00 = x0
  x01 = x00+96
  x02 = x01+96
  x1 = x0+288
  x10 = x1
  x11 = x10+96
  x12 = x11+96
  out0 = out
  out00 = out0
  out01 = out00+96
  out02 = out01+96
  out1 = out0+288
  # temporary variables
  t0 = buffer_f12mul
  t00 = t0
  t01 = t00+96
  t02 = t01+96
  t1 = t0+288
  t10 = t1
  t11 = t10+96
  t12 = t11+96

  gen_f6add(t0,x0,x1,mod)

  gen_mul_by_u_plus_1_fp2(t12,x12,mod)
  gen_f2add(t10,x00,t12,mod)
  gen_f2add(t11,x01,x10,mod)
  gen_f2add(t12,x02,x11,mod)
  
  gen_f6mul(t0,t0,t1,mod)
  gen_f6mul(t1,x0,x1,mod)

  gen_f6add(out1,t1,t1,mod)

  gen_f6sub(out0,t0,t1,mod)
 
  gen_mul_by_u_plus_1_fp2(t12,t12,mod)
  gen_f2sub(out00,out00,t12,mod)
  gen_f2sub(out01,out01,t10,mod)
  gen_f2sub(out02,out02,t11,mod)
  print("// f12sqr end")

def gen_f12conjugate(x,mod):
  print("// f12conjugate begin")
  x1 = x+288
  gen_f6neg(x1,x1,mod)
  print("// f12conjugate end")

def gen_f12inverse(out,x,mod):
  print("// f12inverse begin")
  # input/output
  x0 = x
  x1 = x0+288
  out0 = out
  out00 = out0
  out01 = out00+96
  out02 = out01+96
  out1 = out0+288
  # temporary
  t0 = buffer_f12mul
  t00 = t0
  t01 = t00+96
  t02 = t01+96
  t1 = t0+288
  t10 = t1
  t11 = t10+96
  t12 = t11+96

  gen_f6sqr(t0,x0,mod)
  gen_f6sqr(t1,x1,mod)
  gen_mul_by_u_plus_1_fp2(t12,t12,mod)
  gen_f2sub(t00,t00,t12,mod)
  gen_f2sub(t01,t01,t10,mod)
  gen_f2sub(t02,t02,t11,mod)
  gen_f6inverse(t1,t0,mod)
  gen_f6mul(out0,x0,t1,mod)
  gen_f6mul(out1,x1,t1,mod)
  gen_f6neg(out1,out1,mod)
  print("// f12inverse end")
 

# f6 and f12 optimizations for special cases

def gen_mul_by_0y0_fp6(out,x,y,mod):
  # out is f6, x is f6, y is f2
  x0 = x
  x1 = x0+96
  x2 = x1+96
  y0 = y
  y1 = y0+48
  out0 = out
  out1 = out0+96
  out2 = out1+96
  t = buffer_f6mul
  gen_f2mul(t,x2,y,mod)
  gen_f2mul(out2,x1,y,mod)
  gen_f2mul(out1,x0,y,mod)
  gen_mul_by_u_plus_1_fp2(out0,t,mod)
  
def gen_mul_by_xy0_fp6(out,x,y,mod):
  # out if f6, x is f6, y is f6
  x0 = x
  x1 = x0+96
  x2 = x1+96
  y0 = y
  y1 = y0+96
  y2 = y1+96
  out0 = out
  out1 = out0+96
  out2 = out1+96
  t0 = buffer_f6mul
  t1 = t0+96
  t2 = t1+96	# unused
  t3 = t2+96
  t4 = t3+96
  t5 = t4+96
  gen_f2mul(t0,x0,y0,mod)
  gen_f2mul(t1,x1,y1,mod)

  gen_f2mul(t3,x2,y1,mod)
  gen_mul_by_u_plus_1_fp2(t3,t3,mod)
  
  gen_f2add(t4,x0,x1,mod)
  gen_f2add(t5,y0,y1,mod)
  gen_f2mul(out1,t4,t5,mod)
  gen_f2sub(out1,out1,t0,mod)
  gen_f2sub(out1,out1,t1,mod)
  
  gen_f2mul(out2,x2,y0,mod)
  gen_f2add(out2,out2,t1,mod)

  gen_f2add(out0,t3,t0,mod)

def gen_mul_by_xy00z0_fp12(out,x,y,mod):
  # out is f12, x is f12, y is f6
  x0 = x
  x1 = x0+288
  y0 = y
  y1 = y0+96
  y2 = y1+96
  out0 = out
  out00 = out0
  out01 = out00+96
  out02 = out01+96
  out1 = out+288
  t0 = buffer_f12mul
  t00 = t0
  t01 = t00+96
  t02 = t01+96
  t1 = t0+288
  t10 = t1
  t11 = t10+96
  t12 = t11+96
  t2 = t1+288
  t20 = t2
  t21 = t2+96
  gen_mul_by_xy0_fp6(t0,x0,y,mod)
  gen_mul_by_0y0_fp6(t1,x1,y2,mod)
  gen_memcopy(t20,y0,96)
  gen_f2add(t21,y1,y2,mod)
  gen_f6add(out1,x0,x1,mod)
  gen_mul_by_xy0_fp6(out1,out1,t2,mod)
  gen_f6sub(out1,out1,t0,mod)
  gen_f6sub(out1,out1,t1,mod)
  gen_mul_by_u_plus_1_fp2(t12,t12,mod)
  gen_f2add(out00,t00,t12,mod)
  gen_f2add(out01,t01,t10,mod)
  gen_f2add(out02,t02,t11,mod)

#################
# Frobenius maps

def gen_frobenius_coeffs():
  if 0: # the naive way which needlessly stores zeros, useful for debugging
    f12coefs = bytearray.fromhex("08f2220fb0fb66eb1ce393ea5daace4da35baecab2dc29ee97e83cccd117228fc6695f92b50a831307089552b319d465")[::-1] \
             + bytearray.fromhex("110eefda88847faf2e3813cbe5a0de89c11b9cba40a8e8d0cf4895d42599d3945842a06bfc497cecb2f66aad4ce5d646")[::-1] \
             + bytearray.fromhex("0110f184e51c5f5947222a47bf7b5c04d5c13cc6f1ca47210ec08ff1232bda8ec100ddb891865a2cecfb361b798dba3a")[::-1] \
             + bytearray.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")[::-1] \
             + bytearray.fromhex("0bd592fc7d825ec81d794e4fac7cf0b992ad2afd19103e18382844c88b6237324294213d86c181833e2f585da55c9ad1")[::-1] \
             + bytearray.fromhex("0e2b7eedbbfd87d22da2596696cebc1dd1ca2087da74d4a72f088dd86b4ebef1dc17dec12a927e7c7bcfa7a25aa30fda")[::-1]
    gen_memstore(buffer_f12frobeniuscoefs,f12coefs)
    f6coefs = bytearray.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")[::-1] \
            + bytearray.fromhex("18f020655463874103f97d6e83d050d28eb60ebe01bacb9e587042afd3851b955dab22461fcda5d2cd03c9e48671f071")[::-1] \
            + bytearray.fromhex("051ba4ab241b61603636b76660701c6ec26a2ff874fd029b16a8ca3ac61577f7f3b8ddab7ece5a2a30f1361b798a64e8")[::-1] \
            + bytearray.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")[::-1] \
            + bytearray.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")[::-1] \
            + bytearray.fromhex("15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd")[::-1] \
            + bytearray.fromhex("14e56d3f1564853a14e4f04fe2db9068a20d1b8c7e88102450880866309b7e2c2af322533285a5d5890dc9e4867545c3")[::-1] \
            + bytearray.fromhex("18f020655463874103f97d6e83d050d28eb60ebe01bacb9e587042afd3851b955dab22461fcda5d2cd03c9e48671f071")[::-1] \
            + bytearray.fromhex("040ab3263eff0206ef148d1ea0f4c069eca8f3318332bb7a07e83a49a2e99d6932b7fff2ed47fffd43f5fffffffcaaae")[::-1]
    gen_memstore(buffer_f6frobeniuscoefs,f6coefs)
  else: # optimized for gas and bytecode size
    f12coefs = bytearray.fromhex("08f2220fb0fb66eb1ce393ea5daace4da35baecab2dc29ee97e83cccd117228fc6695f92b50a831307089552b319d465")[::-1] \
             + bytearray.fromhex("110eefda88847faf2e3813cbe5a0de89c11b9cba40a8e8d0cf4895d42599d3945842a06bfc497cecb2f66aad4ce5d646")[::-1] \
             + bytearray.fromhex("0110f184e51c5f5947222a47bf7b5c04d5c13cc6f1ca47210ec08ff1232bda8ec100ddb891865a2cecfb361b798dba3a")[::-1]
    gen_memstore(buffer_f12frobeniuscoefs,f12coefs)
    f12coefs = bytearray.fromhex("0bd592fc7d825ec81d794e4fac7cf0b992ad2afd19103e18382844c88b6237324294213d86c181833e2f585da55c9ad1")[::-1] \
             + bytearray.fromhex("0e2b7eedbbfd87d22da2596696cebc1dd1ca2087da74d4a72f088dd86b4ebef1dc17dec12a927e7c7bcfa7a25aa30fda")[::-1]
    gen_memstore(buffer_f12frobeniuscoefs+4*48,f12coefs)
    f6coefs = bytearray.fromhex("18f020655463874103f97d6e83d050d28eb60ebe01bacb9e587042afd3851b955dab22461fcda5d2cd03c9e48671f071")[::-1] \
            + bytearray.fromhex("051ba4ab241b61603636b76660701c6ec26a2ff874fd029b16a8ca3ac61577f7f3b8ddab7ece5a2a30f1361b798a64e8")[::-1]
    gen_memstore(buffer_f6frobeniuscoefs+48,f6coefs)
    f6coefs = bytearray.fromhex("15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd")[::-1] \
            + bytearray.fromhex("14e56d3f1564853a14e4f04fe2db9068a20d1b8c7e88102450880866309b7e2c2af322533285a5d5890dc9e4867545c3")[::-1] \
            + bytearray.fromhex("18f020655463874103f97d6e83d050d28eb60ebe01bacb9e587042afd3851b955dab22461fcda5d2cd03c9e48671f071")[::-1] \
            + bytearray.fromhex("040ab3263eff0206ef148d1ea0f4c069eca8f3318332bb7a07e83a49a2e99d6932b7fff2ed47fffd43f5fffffffcaaae")[::-1]
    gen_memstore(buffer_f6frobeniuscoefs+48*5,f6coefs)

def gen_f2frobeniusmap(out,x,n,mod):
  out0 = out
  out1 = out0+48
  x0 = x
  x1 = x0+48
  gen_memcopy(out0,x0,48)
  if n&1:			# TODO, check cneg() with input 0 or 1, I think that input 0 means do nothing
    gen_f1neg(out1,x1,mod)	# TODO: check if cneg() corresponds to f1neg()
  else:
    gen_memcopy(out1,x1,48)

def gen_f6frobeniusmap(out,x,n,mod):
  x0 = x
  x1 = x0+96
  x2 = x1+96
  out0 = out
  out1 = out0+96
  out2 = out1+96
  out20 = out2
  out21 = out20+48
  gen_f2frobeniusmap(out0,x0,n,mod)
  gen_f2frobeniusmap(out1,x1,n,mod)
  gen_f2frobeniusmap(out2,x2,n,mod)
  n-=1
  buffer_coefs1 = buffer_f6frobeniuscoefs+n*96		# TODO: check this, since index 0 should be one, and the overall offsets
  buffer_coefs2 = buffer_f6frobeniuscoefs+3*96+n*48			# TODO: check this
  gen_f2mul(out1,out1,buffer_coefs1,mod)
  gen_f1mul(out20,out20,buffer_coefs2,mod)
  gen_f1mul(out21,out21,buffer_coefs2,mod)

def gen_f12frobeniusmap(out,x,n,mod):
  print("// f12frobeniusmap begin")
  x0 = x
  x1 = x0+288
  out0 = out
  out1 = out+288
  out10 = out1
  out11 = out10+96
  out12 = out11+96

  gen_f6frobeniusmap(out0,x0,n,mod)
  gen_f6frobeniusmap(out1,x1,n,mod)
  n-=1
  buffer_coefs = buffer_f12frobeniuscoefs+n*96	# TODO: check this, since index 0 should be one and idx 1 only has one val
  gen_f2mul(out10,out10,buffer_coefs,mod)
  gen_f2mul(out11,out11,buffer_coefs,mod)
  gen_f2mul(out12,out12,buffer_coefs,mod)
  print("// f12frobeniusmap end")

# Frobenius maps
#################



####################
# Cyclotomic square

def gen_f4sqr(out,x0,x1,mod):
  # input is two f2s, output is a f4 (?)
  t0 = buffer_f6mul
  t1 = t0+96
  out0 = out
  out1 = out0+96
  #
  gen_f2sqr(t0,x0,mod)
  gen_f2sqr(t1,x1,mod)
  gen_f2add(out1,x0,x1,mod)
  gen_mul_by_u_plus_1_fp2(out0,t1,mod)
  gen_f2add(out0,out0,t0,mod)
  gen_f2sqr(out1,out1,mod)
  gen_f2sub(out1,out1,t0,mod)
  gen_f2sub(out1,out1,t1,mod)

def gen_f12sqrcyclotomic(out,x,mod):
  print("// f12sqrcyclotomic begin")
  # in
  x0 = x
  x00 = x0
  x01 = x00+96
  x02 = x01+96
  x1 = x0+288
  x10 = x1
  x11 = x10+96
  x12 = x11+96
  # out
  out0 = out
  out00 = out0
  out01 = out00+96
  out02 = out01+96
  out1 = out+288
  out10 = out1
  out11 = out10+96
  out12 = out11+96
  # temp f4s, which are two f2s each
  t0 = buffer_f12mul
  t00 = t0
  t01 = t00+96
  t1 = t0+192
  t10 = t1
  t11 = t10+96
  t2 = t1+192
  t20 = t2
  t21 = t20+96

  gen_f4sqr(t0,x00,x11,mod)
  gen_f4sqr(t1,x10,x02,mod)
  gen_f4sqr(t2,x01,x12,mod)
  
  gen_f2sub(out00,t00,x00,mod)
  gen_f2add(out00,out00,out00,mod)
  gen_f2add(out00,out00,t00,mod)
  
  gen_f2sub(out01,t10,x01,mod)
  gen_f2add(out01,out01,out01,mod)
  gen_f2add(out01,out01,t10,mod)

  gen_f2sub(out02,t20,x02,mod)
  gen_f2add(out02,out02,out02,mod)
  gen_f2add(out02,out02,t20,mod)

  gen_mul_by_u_plus_1_fp2(t21,t21,mod)
  gen_f2add(out10,t21,x10,mod)
  gen_f2add(out10,out10,out10,mod)
  gen_f2add(out10,out10,t21,mod)

  gen_f2add(out11,t01,x11,mod)
  gen_f2add(out11,out11,out11,mod)
  gen_f2add(out11,out11,t01,mod)

  gen_f2add(out12,t11,x12,mod)
  gen_f2add(out12,out12,out12,mod)
  gen_f2add(out12,out12,t11,mod)
  print("// f12sqrcyclotomic end")

# Cyclotomic square
####################
