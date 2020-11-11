""" GPLv3
    EVMcurves - Implmentation of some crypto in EVM and its proposed EVM384 extension.
    Copyright (C) 2020  Paul Dworzanski
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""




####################
# memcopy and mstore

def gen_memstore(dst_offset,bytes_):
  idx = 0
  if len(bytes_)<32:
    print("ERROR gen_copy() fewer than 32 bytes needs special handling, len_ is only ",len_)
    return
  while idx<len(bytes_)-32:
    print("0x"+bytes_[idx:idx+32].hex(),end=' ')
    print(hex(dst_offset),end=' ')
    print("mstore")
    dst_offset+=32
    idx+=32
  print("0x"+bytes_[-32:].hex(),end=' ')
  print(hex(dst_offset+len(bytes_[idx:])-32),end=' ')
  print("mstore")

def gen_memcopy(dst_offset,src_offset,len_):
  if len_<32:
    print("ERROR gen_memcopy() len_ is ",len_)
    return
  while len_>32:
    len_-=32
    print(hex(src_offset))
    print("mload")
    print(hex(dst_offset))
    print("mstore")
    src_offset+=32
    dst_offset+=32
  print(hex(src_offset-(32-len_)))
  print("mload")
  print(hex(dst_offset-(32-len_)))
  print("mstore")



#########
# Buffers

# memory offsets for local buffers used for temporary values, the first 576-bytes are zeros
buffer_offset = 0
zero = buffer_offset
f1zero = buffer_offset	# 48 bytes
f2zero = buffer_offset	# 96 bytes
f6zero = buffer_offset	# 288 bytes
f12zero = buffer_offset	# 576 bytes
buffer_offset += 576
f12one = buffer_offset	# 576 bytes
buffer_offset += 576
mod = buffer_offset	# 56 bytes, mod||inv
buffer_offset += 56
buffer_miller_loop = buffer_offset	# 1 E2 point, 1 E1 point affine
buffer_offset += 288+96
buffer_line = buffer_offset		# 3 f2 points
buffer_offset += 288
buffer_f2mul = buffer_offset	# 3 f1 points
buffer_offset += 144
buffer_f6mul = buffer_offset	# 6 f2 points
buffer_offset += 576
buffer_f12mul = buffer_offset	# 3 f6 points
buffer_offset += 864
buffer_Eadd = buffer_offset	# 14 or 9 values
buffer_offset += 14*3*96
buffer_Edouble = buffer_offset	# 7 or 6 values
buffer_offset += 7*3*96
buffer_inputs = buffer_offset
buffer_offset += 2*48+2*96
buffer_miller_output = buffer_offset
buffer_offset += 12*48
buffer_finalexp = buffer_offset
buffer_offset += 12*48*4
buffer_finalexp_output = buffer_offset
buffer_offset += 12*48
buffer_f12frobeniuscoefs = buffer_offset
buffer_offset += 6*48
buffer_f6frobeniuscoefs = buffer_offset
buffer_offset += 9*48








##################
# Argument packing

# Each EVM384v7 opcode is preceeded with a PUSH16 with packed memory offsets

# pack offsets into stack item
def gen_evm384_offsets(a,b,c,d):
  print("0x"+hex(a)[2:].zfill(8)+hex(b)[2:].zfill(8)+hex(c)[2:].zfill(8)+hex(d)[2:].zfill(8), end=' ')




#################################
## Field operations add, sub, mul

# for counting number of operations
addmod384_count=0
submod384_count=0
mulmodmont384_count=0
f2add_count=0
f2sub_count=0
f2mul_count=0
f6add_count=0
f6sub_count=0
f6mul_count=0
f12add_count=0
f12sub_count=0
f12mul_count=0

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


####
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
  # TODO: needed for pairing
  # options:
  # - extended euclidean algorithm
  # - montgomery inversion
  # - modexp precompile
  pass


####
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
  # we experiment with different implementations of f2mul, should enable only one
  if 0:
    # this is naive f2mul with four f1mul's
    gen_f1mul(tmp1,x0,y0,mod)
    gen_f1mul(tmp2,x1,y1,mod)
    gen_f1sub(out0,tmp1,tmp2,mod)
    gen_f1mul(tmp1,x0,y1,mod)
    gen_f1mul(tmp2,x1,y0,mod)
    gen_f1add(out1,tmp1,tmp2,mod)
  elif 1:
    gen_f1mul(tmp1,x0,y0,mod)			# tmp1 = x0*y0
    gen_f1mul(tmp2,x1,y1,mod)			# tmp2 = x1*y1
    #gen_f1sub(tmp3,zero,tmp2,mod)		# tmp3 = zero-tmp2
    #gen_f1add(out0,tmp1,tmp3,mod)		# out0 = tmp1+tmp3
    gen_f1sub(out0,tmp1,tmp2,mod)		# above sub,add give same result as just this sub
    gen_f1add(tmp1,tmp1,tmp2,mod)		# tmp1 = tmp1+tmp2
    gen_f1add(tmp2,x0,x1,mod)			# tmp2 = x0+x1
    gen_f1add(tmp3,y0,y1,mod)			# tmp3 = y0+y1
    gen_f1mul(tmp2,tmp2,tmp3,mod)		# tmp2 = tmp2*tmp3
    gen_f1sub(out1,tmp2,tmp1,mod)		# out1 = tmp2-tmp1
  elif 0:
    gen_f1mul(tmp1,x0,y0,mod)			# t1 = x0*y0
    gen_f1sub(tmp2,zero,x1,mod)			# t2 = -x1
    gen_f1mul(tmp2,tmp2,y1,mod)			# t2 = -x1*y1
    gen_f1add(out0,tmp1,tmp2,mod)		# out0 = t1+t2
    gen_f1add(tmp3,x0,x1,mod)			# t3 = x0+y0
    gen_f1add(out1,y0,y1,mod)			# out1 = x1+y1
    gen_f1mul(out1,out1,tmp3,mod)		# out1 = out1*t3
    gen_f1sub(out1,out1,tmp1,mod)		# out1 = out1-t1
    gen_f1add(out1,out1,tmp2,mod)		# out1 = out1+t2
  elif 0:
    gen_f1mul(tmp1,x0,y0,mod)                   # t1 = x0*y0
    gen_f1mul(tmp2,x1,y1,mod)                   # t2 = x1*y1
    gen_f1sub(out0,tmp1,tmp2,mod)               # out0 = t1-t2
    gen_f1add(tmp3,x0,x1,mod)                   # t3 = x0+y0
    gen_f1add(out1,y0,y1,mod)                   # out1 = x1+y1
    gen_f1mul(out1,out1,tmp3,mod)               # out1 = out1*t3
    gen_f1sub(out1,out1,tmp1,mod)               # out1 = out1-t1
    gen_f1sub(out1,out1,tmp2,mod)               # out1 = out1-t2
  elif 0:
    gen_f1add(tmp1,x0,y0,mod)
    gen_f1add(tmp2,x1,y1,mod)
    gen_f1mul(tmp2,tmp2,tmp1,mod)
    gen_f1mul(tmp1,x0,y0,mod)
    gen_f1mul(tmp3,x1,y1,mod)
    gen_f1sub(out0,tmp1,tmp3,mod)
    gen_f1sub(out1,tmp2,tmp1,mod)
    gen_f1sub(out1,out1,tmp3,mod)

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


####
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
  #gen_f6sub(out,f6zero,x,mod)
  #gen_f6sub(out,mod,x,mod)
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
  print("// f6 mul")
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

def gen_f6sqr(out,x,mod):
  #gen_f6mul(out,x,x,mod)	# TODO: optimize
  print("// f6 sqr")
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

def gen_f6inverse(out,x,mod):
  print("// f6 mul")
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

  gen_f2sqr(c2,x2,mod)
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


#####
# f12

def gen_f12add(out,x,y,mod):
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
  
def gen_f12sub(out,x,y,mod):
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

def gen_f12mul(out,x,y,mod):
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

def gen_f12sqr(out,x,mod):
  print("// f12 sqr")
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

def gen_f12conjugate(x,mod):
  x1 = x+288
  gen_f6neg(x1,x1,mod)

def gen_f12inverse(out,x,mod):
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
  gen_f2sub(t02,t01,t11,mod)
  gen_f6inverse(t1,t0,mod)
  gen_f6mul(out0,x0,t1,mod)
  gen_f6mul(out1,x1,t1,mod)
  gen_f6neg(out1,out1,mod)
  

############
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




####################
# Curve operations #
####################


######################
# add two curve points

def gen_Eadd__madd_2001_b(f,XYZout,XYZ1,XYZ2,mod):
  print("/////////")
  print("// Eadd https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2001-b")
  # inputs/ouput
  X1=XYZ1
  Y1=X1+int(f[1])*48
  Z1=Y1+int(f[1])*48
  X2=XYZ2
  Y2=X2+int(f[1])*48
  Z2=Y2+int(f[1])*48
  X3=XYZout
  Y3=X3+int(f[1])*48
  Z3=Y3+int(f[1])*48
  """
  ZZ1 = Z1^2
  ZZZ1 = Z1*ZZ1
  ZZ2 = Z2^2
  ZZZ2 = Z2*ZZ2
  A = X1*ZZ2
  B = X2*ZZ1-A
  c = Y1*ZZZ2
  d = Y2*ZZZ1-c
  e = B^2
  f = B*e
  g = A*e
  h = Z1*Z2
  f2g = 2*g+f
  X3 = d^2-f2g
  Z3 = B*h
  gx = g-X3
  Y3 = d*gx-c*f
  """
  # temp vars
  ZZ1 = buffer_Eadd
  ZZZ1 = ZZ1+int(f[1])*48
  ZZ2 = ZZZ1+int(f[1])*48
  ZZZ2 = ZZ2+int(f[1])*48
  A = ZZZ2+int(f[1])*48
  B = A+int(f[1])*48
  c = B+int(f[1])*48
  d = c+int(f[1])*48
  e = d+int(f[1])*48
  f_ = e+int(f[1])*48
  g = f_+int(f[1])*48
  h = g+int(f[1])*48
  f2g = h+int(f[1])*48
  gx = f2g+int(f[1])*48

  print("ZZ1 = Z1^2")
  gen_fmul(f,ZZ1,Z1,Z1,mod)
  print("ZZZ1 = Z1*ZZ1")
  gen_fmul(f,ZZZ1,Z1,ZZ1,mod)
  print("ZZ2 = Z2^2")
  gen_fmul(f,ZZ2,Z2,Z2,mod)
  print("ZZZ2 = Z2*ZZ2")
  gen_fmul(f,ZZZ2,Z2,ZZ2,mod)
  print("A = X1*ZZ2")
  gen_fmul(f,A,X1,ZZ2,mod)
  print("B = X2*ZZ1-A")
  gen_fmul(f,B,X2,ZZ1,mod)
  gen_fsub(f,B,B,A,mod)
  print("c = Y1*ZZZ2")
  gen_fmul(f,c,Y1,ZZZ2,mod)
  print("d = Y2*ZZZ1-c")
  gen_fmul(f,d,Y2,ZZZ1,mod)
  gen_fsub(f,d,d,c,mod)
  print("e = B^2")
  gen_fmul(f,e,B,B,mod)
  print("f = B*e")
  gen_fmul(f,f_,B,e,mod)
  print("g = A*e")
  gen_fmul(f,g,A,e,mod)
  print("h = Z1*Z2")
  gen_fmul(f,h,Z1,Z2,mod)
  print("f2g = 2*g+f")
  gen_fadd(f,f2g,g,g,mod)
  gen_fadd(f,f2g,f2g,f_,mod)
  print("X3 = d^2-f2g")
  gen_fmul(f,X3,d,d,mod)
  gen_fsub(f,X3,X3,f2g,mod)
  print("Z3 = B*h")
  gen_fmul(f,Z3,B,h,mod)
  print("gx = g-X3")
  gen_fsub(f,gx,g,X3,mod)
  print("Y3 = d*gx-c*f")
  gen_fmul(f,Y3,d,g,mod)
  gen_fmul(f,c,c,f_,mod)	# clobber c
  gen_fsub(f,Y3,Y3,c,mod)

  print("// E add")
  print("/////////")

def gen_Eadd__madd_2007_bl(f,XYZout,XYZ1,XYZ2,line1,mod):
  print("/////////")
  print("// Eadd https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl")
  # for pairing:
  #   line0 is useful for pairings which reuse that intermediate value in this calculation
  #   XYZout and XYZ are both T, and E2 point, and XYZ2 is Q which is affine E2 point

  # inputs/ouput
  X1=XYZ1
  Y1=X1+int(f[1])*48
  Z1=Y1+int(f[1])*48
  X2=XYZ2
  Y2=X2+int(f[1])*48
  Z2=Y2+int(f[1])*48
  X3=XYZout
  Y3=X3+int(f[1])*48
  Z3=Y3+int(f[1])*48

  # temp vars
  Z1Z1 = buffer_Eadd
  U2 = Z1Z1+int(f[1])*48
  S2 = U2+int(f[1])*48
  H = S2+int(f[1])*48
  HH = H+int(f[1])*48
  I = HH+int(f[1])*48
  J = I+int(f[1])*48
  V = J+int(f[1])*48
  r = line1 if line1 else V+int(f[1])*48

  # Z1Z1 = Z1^2
  print("// Z1Z1 = Z1^2")
  gen_fsqr(f,Z1Z1,Z1,mod)
  # U2 = X2*Z1Z1
  print("// U2 = X2*Z1Z1")
  gen_fmul(f,U2,X2,Z1Z1,mod)
  # S2 = Y2*Z1*Z1Z1
  print("// S2 = Y2*Z1*Z1Z1")
  gen_fmul(f,S2,Y2,Z1,mod)
  gen_fmul(f,S2,S2,Z1Z1,mod)
  # H = U2-X1
  print("// H = U2-X1")
  gen_fsub(f,H,U2,X1,mod)
  # HH = H^2
  print("// HH = H^2")
  gen_fsqr(f,HH,H,mod)
  # I = 4*HH
  print("// I = 4*HH")
  gen_fadd(f,I,HH,HH,mod)
  gen_fadd(f,I,I,I,mod)
  # J = H*I
  print("// J = H*I")
  gen_fmul(f,J,H,I,mod)
  # line0 = 2*(S2-Y1)
  print("// r = 2*(S2-Y1)")
  gen_fsub(f,r,S2,Y1,mod)
  gen_fadd(f,r,r,r,mod)
  # V = X1*I
  print("// V = X1*I")
  gen_fmul(f,V,X1,I,mod)
  # X3 = r^2-J-2*V
  print("// X3 = r^2-J-2*V")
  gen_fsqr(f,X3,r,mod)
  gen_fsub(f,X3,X3,J,mod)
  gen_fsub(f,X3,X3,V,mod)
  gen_fsub(f,X3,X3,V,mod)
  # Y3 = r*(V-X3)-2*Y1*J
  print("// Y3 = r*(V-X3)-2*Y1*J")
  gen_fmul(f,J,J,Y1,mod)
  gen_fsub(f,Y3,V,X3,mod)
  gen_fmul(f,Y3,Y3,r,mod)
  gen_fsub(f,Y3,Y3,J,mod)
  gen_fsub(f,Y3,Y3,J,mod)
  """
  gen_fsub(f,Y3,V,X3,mod)
  gen_fmul(f,Y3,r,Y3,mod)
  gen_fmul(f,V,Y1,J,mod)	# overwriting V
  gen_fsub(f,Y3,Y3,V,mod)
  gen_fsub(f,Y3,Y3,V,mod)
  """
  # Z3 = (Z1+H)^2-Z1Z1-HH
  print("// Z3 = (Z1+H)^2-Z1Z1-HH")
  gen_fadd(f,Z3,Z1,H,mod)
  gen_fsqr(f,Z3,Z3,mod)
  gen_fsub(f,Z3,Z3,Z1Z1,mod)
  gen_fsub(f,Z3,Z3,HH,mod)
  
  print("// E add")
  print("/////////")

  return I,J,r		# these are useful for pairing



######################
# double a curve point

def gen_Edouble__dbl_2009_alnr(f,XYZout,XYZ,line0,mod):
  # XYZout is E2 point, XYZ is E2 point		(note: for our pairing algorithm, T=XYZout=XYZ)
  # line is an extra f2 point, not part of dbl operation, but useful for pairing's line evaluation
  print("///////////")
  print("// Edouble https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-alnr")

  # inputs/ouput
  X1=XYZ
  Y1=X1+int(f[1])*48
  Z1=Y1+int(f[1])*48
  X3=XYZout
  Y3=X3+int(f[1])*48
  Z3=Y3+int(f[1])*48
  #print("gen_Edouble__dbl_2009_alnr(",X1,Y1,Z1,X3,Y3,Z3,")")

  """
  A = X1^2
  B = Y1^2
  ZZ = Z1^2
  C = B^2
  D = 2*((X1+B)^2-A-C)
  E = 3*A
  F = E^2
  X3 = F-2*D
  Y3 = E*(D-X3)-8*C
  Z3 = (Y1+Z1)^2-B-ZZ
  """
  A = buffer_Edouble
  B = A+int(f[1])*48
  ZZ = B+int(f[1])*48 
  C = ZZ+int(f[1])*48
  D = C+int(f[1])*48
  E = D+int(f[1])*48
  F = E+int(f[1])*48

  print("// A = X1^2")
  gen_fsqr(f,A,X1,mod)
  print("// B = Y1^2")
  gen_fsqr(f,B,Y1,mod)
  print("// ZZ = Z1^2")
  gen_fsqr(f,ZZ,Z1,mod)
  print("// C = B^2")
  gen_fsqr(f,C,B,mod)
  print("// D = 2*((X1+B)^2-A-C)")
  gen_fadd(f,D,X1,B,mod)
  gen_fsqr(f,D,D,mod)
  gen_fsub(f,D,D,A,mod)
  gen_fsub(f,D,D,C,mod)
  gen_fadd(f,D,D,D,mod)
  print("// E = 3*A")
  gen_fadd(f,E,A,A,mod)
  gen_fadd(f,E,E,A,mod)
  print("// F = E^2")
  gen_fsqr(f,F,E,mod)
  # note: the following is not part of the dbl, but is useful for line evaluation
  if line0:
    print("// line0 = E+X1, this is useful for pairing")
    gen_fadd(f,line0,E,X1,mod)
  print("// X3 = F-2*D")
  gen_fsub(f,X3,F,D,mod)
  gen_fsub(f,X3,X3,D,mod)
  print("// Z3 = (Y1+Z1)^2-B-ZZ")
  gen_fadd(f,Z3,Y1,Z1,mod)
  gen_fsqr(f,Z3,Z3,mod)
  gen_fsub(f,Z3,Z3,B,mod)
  gen_fsub(f,Z3,Z3,ZZ,mod)
  print("// Y3 = E*(D-X3)-8*C")
  gen_fsub(f,Y3,D,X3,mod)
  gen_fmul(f,Y3,E,Y3,mod)
  gen_fadd(f,C,C,C,mod)		# overwriting C
  gen_fadd(f,C,C,C,mod)
  gen_fadd(f,C,C,C,mod)
  gen_fsub(f,Y3,Y3,C,mod)
  print("// E double")
  print("////////////")
  return A,B,E,F,ZZ,X1

def gen_Edouble__dbl_2009_l(f,XYZout,XYZ,mod):
  print("///////////")
  print("// Edouble https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l")

  # inputs/ouput
  X1=XYZ
  Y1=X1+int(f[1])*48
  Z1=Y1+int(f[1])*48
  X3=XYZout
  Y3=X3+int(f[1])*48
  Z3=Y3+int(f[1])*48

  """
  A = X1^2
  B = Y1^2
  C = B^2
  D = 2*((X1+B)^2-A-C)
  E = 3*A
  F = E^2
  X3 = F-2*D
  Y3 = E*(D-X3)-8*C
  Z3 = 2*Y1*Z1
  """
  A = buffer_Edouble
  B = A+int(f[1])*48
  C = B+int(f[1])*48
  D = C+int(f[1])*48
  E = D+int(f[1])*48
  F = E+int(f[1])*48

  print("// A = X1^2")
  gen_fmul(f,A,X1,X1,mod)
  print("// B = Y1^2")
  gen_fmul(f,B,Y1,Y1,mod)
  print("// C = B^2")
  gen_fmul(f,C,B,B,mod)
  print("// D = 2*((X1+B)^2-A-C)")
  gen_fadd(f,D,X1,B,mod)
  gen_fmul(f,D,D,D,mod)
  gen_fsub(f,D,D,A,mod)
  gen_fsub(f,D,D,C,mod)
  gen_fadd(f,D,D,D,mod)
  print("// E = 3*A")
  gen_fadd(f,F,A,A,mod)
  gen_fadd(f,F,F,A,mod)
  print("// F = E^2")
  gen_fmul(f,F,E,E,mod)
  print("// X3 = F-2*D")
  gen_fadd(f,X3,D,D,mod)
  gen_fsub(f,X3,F,D,mod)
  print("// Y3 = E*(D-X3)-8*C")
  gen_fsub(f,Y3,D,X3,mod)
  gen_fmul(f,Y3,E,Y3,mod)
  gen_fadd(f,C,C,C,mod)		# clobber C
  gen_fadd(f,C,C,C,mod)
  gen_fadd(f,C,C,C,mod)
  gen_fsub(f,Y3,Y3,C,mod)
  print("// Z3 = 2*Y1*Z1")
  gen_fmul(f,Z3,Y1,Z1,mod)
  gen_fadd(f,Z3,Z3,Z3,mod)
  print("// E double")
  print("////////////")




###########
# Pairing #
###########


#############
# Miller Loop

# hard-coded miller loop inputs, optional
# these inputs can be hard-coded anywhere before the miller loop starts, we copy/paste the output of this function into main.huff
def gen_miller_loop_test_input():
  if 0:
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
  if 0:
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
  if 0:
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
  if 0:
    # from https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/?include_text=1 appendix B
    inE1  = bytearray.fromhex("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")[::-1]
    inE1  += bytearray.fromhex("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1")[::-1]
    gen_memstore(buffer_inputs,inE1)
    inE2  = bytearray.fromhex("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")[::-1]
    inE2  += bytearray.fromhex("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")[::-1]
    inE2  += bytearray.fromhex("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801")[::-1]
    inE2  += bytearray.fromhex("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")[::-1]
    gen_memstore(buffer_inputs+96,inE2)
  if 1:
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

def gen_add_dbl_loop(out,T,Q,Px2,mod):
  line = buffer_line	# 3 f2 points
  print("63")           # loop iterator will be decremented on stack
  print("miller_loop:")
  print("0x1 swap1 sub")        # decrement loop iterator and leave it a top of stack
  print("0xd201000000010000 dup2 shr")   # get the next bit by shifting by loop iterator
  print("0x1 and")              # get next bit by shifting by loop iterator
  print("0x1 xor end_if jumpi")         # skip if next bit was 1 (ie skip if flipped bit is 1)
  print("begin_if:")    # if 1 bit, then add
  gen_line_add(line,T,T,Q,mod)
  gen_line_by_Px2(line,Px2,mod)
  gen_mul_by_xy00z0_fp12(out,out,line,mod)
  print("end_if:")
  gen_f12sqr(out,out,mod)
  gen_line_dbl(line,T,T,mod)
  gen_line_by_Px2(line,Px2,mod)
  gen_mul_by_xy00z0_fp12(out,out,line,mod)
  print("dup1 1 lt")          # check if 1 < loop iterator	note: don't iterate on least significant bit
  print("miller_loop jumpi")    # if loop iterator > 0, then jump to next iter
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



######################
# final exponentiation

def gen_final_exp_test_input():
  # this is to generate test values, which are then hard-coded into the main.huff
  if 1:
    # from test 3
    a  = bytearray.fromhex("786d3d21c54900e339dbe16585cb97e9f13ee46ac9aabcc131fd629b4f0a14f362317cd5d58bf78309bd747194efa709")
    a += bytearray.fromhex("fa72990a456a3d13ee283c82e3e9bafcd0313edaba3651487bf305bf804a60b274948f08f3b1b8ec8de7674c1e139408")
    a += bytearray.fromhex("8f792ac1809f0774fdeff769a1d369eaa1d8e41c162587bec04a2a87b3a34662a839fcf7bf984ea547ea824f7f8be006")
    a += bytearray.fromhex("e70e8ac4be663bad3497b5e76e48828706e383a710ae7e2ac687b0cba496c3c92d5ba6fc0ea6bd30b8426f57db016813")
    a += bytearray.fromhex("aed2dada2310c16e2359be60850e985d5903cda75b6deb8556b3d18e69c14dbba176079c733f9453d5d3dcd49799a10e")
    a += bytearray.fromhex("69b164bd3ca2879c468aef06fafdddb35cdec4e1d21d28b3310f8d6a65a4cc3897ba3c1f8653003274da96c21aa92404")
    a += bytearray.fromhex("7cfc59066b62e31c44756e13c4e7f8ce67053348e83ea4922671cdfc346611e41b2addbdb1e7c170fd5c4820f45f3e16")
    a += bytearray.fromhex("85d83efaaf4da2010b34279cfa614cec624bcb137b1c87f9979e48733a283020bd29ab4cf999ec0c0cd675882152e406")
    a += bytearray.fromhex("6e9334b190df79095260698573eb490d2f637309165b8a3fb760668811c28ae0795f2b9b5fd5ce9e0b257ebbd93b7d09")
    a += bytearray.fromhex("d066481d5847783875603d93871654d8a7ccb1ea1ce1528ea7a71963accf70d96db38ffacdebf29e0ec62f1f47784c16")
    a += bytearray.fromhex("28c06e8012b4a52ec27edfe6898b9e6aea3f2b6b5d145976c232c44029cd71845e3b5943dc096d49d8d1c63860c15b10")
    a += bytearray.fromhex("70add590f5a782b332d4bd6e15c9612f90c59f6b3478b4d9b87bd984d287fa031ae35e8494b828a43b29fd8ff3fa5f10")
    gen_memstore(buffer_miller_output,a)

def gen_final_exp_dummy_inv(buffer_):
  # this overwrites the output of f12inverse(), used for testing/debugging
  if 1:
    # from test 3
    a  = bytearray.fromhex("6d9ac0bf64e149c7a548ecbae2a1fcf1ea3b967b262ac0187695b241416c8b84236f0bcef1eac962f6d77c599b8ab308")
    a += bytearray.fromhex("644a76672180d9a6407688d7fd970f702d6402e7dd7019867062643ace62c30f005437473b88f38cf41834b339eb0e0a")
    a += bytearray.fromhex("2eda1ab8749c14ac43cd3f6623b45f49699879a9348a835582fc0518bc30e22185fc77f4139dfe05dfc9990290b3c605")
    a += bytearray.fromhex("89a1097d08cb0109085b1df5dff5231d221afff4f74338308f200414e5a72fc2c640a0919e946d060de86fbdfc20c416")
    a += bytearray.fromhex("b90d5506e27d983e6ad37c11d1f8279fa85be785d853ddbc5e54328f39893a1d031817b8f07fc37092c279ad51591e13")
    a += bytearray.fromhex("60407d1f7b655eb87ce7041c1c638c008ebc1b9119e653b19cc9fd366d0bf73ac47e8bb034b6cc5a7a1c570242383c06")
    a += bytearray.fromhex("0e59a601bd4f9270078e79e0bf65d5352e56a04838496ce3278036c3c0cad8b1ccaf0a4c34c1f46268ec72abde97fa01")
    a += bytearray.fromhex("fa0e2cac50b81e35c0d96fbac0fe3069656003aa15e4fb02252660be1198845afd0802d43e7a2e0eb0ab3dc6032edb03")
    a += bytearray.fromhex("79ece6417c41005480cc33e3b6bd654deb41156fa6ee86b9ec4d78ce158fbef065f53746212071f095cc551c602a0005")
    a += bytearray.fromhex("6ad774f67366f630f4d88e794f15beed63cb622efafa9bf4c04394ea215eba7293e3b0b159a69d78860448236264180d")
    a += bytearray.fromhex("b25c994d8054d2775aec7d99f9d296ecbb3209ee7a909b991f0b79c54253f86bcb3ccd8fba8fa5e3b0a07ed9dd770b09")
    a += bytearray.fromhex("aa0d81a7f4d5109e85cbf65157a982cee279e253040807c08b4ec5c586b5345c09f5724d65865f295f7c97a5c631c209")
    gen_memstore(buffer_,a)

counter_raise_loop = 0	# this variable is to make unique jumpdests each time this generator is called
def gen_f12raise_to_z_div_by_2(out,x,mod):
  global counter_raise_loop
  counter_raise_loop += 1
  #if counter_raise_loop==1:
  gen_f12sqrcyclotomic(out,x,mod)
  print("63")           # loop iterator will be decremented on stack
  print("raise_loop"+str(counter_raise_loop)+":")
  print("0x1 swap1 sub")        # decrement loop iterator and leave it a top of stack
  print("0xd201000000010000 dup2 shr")   # get the next bit by shifting by loop iterator
  print("0x1 and")              # get next bit by shifting by loop iterator
  print("0x1 xor end_if_raise_loop"+str(counter_raise_loop)+" jumpi")         # skip if next bit was 1 (ie skip if flipped bit is 1)
  print("begin_if_raise_loop"+str(counter_raise_loop)+":")    # if 1 bit, then
  gen_f12mul(out,out,x,mod)
  print("end_if_raise_loop"+str(counter_raise_loop)+":")
  gen_f12sqrcyclotomic(out,out,mod)
  print("dup1 2 lt")          # check if 1 < loop iterator	note: don't iterate on least significant bit
  print("raise_loop"+str(counter_raise_loop)+" jumpi")    # if loop iterator > 0, then jump to next iter
  print("pop")			# pop loop iterator to leave stack how we found it
  gen_f12conjugate(out,mod)

def gen_f12raise_to_z(out,x,mod):
  gen_f12raise_to_z_div_by_2(out,x,mod)
  gen_f12sqrcyclotomic(out,out,mod)

def gen_final_exponentiation(out,in_,mod):
  y0 = buffer_finalexp
  y1 = y0+12*48
  y2 = y1+12*48
  y3 = y2+12*48

  gen_frobenius_coeffs()

  gen_memcopy(y1,in_,48*12)
  gen_f12conjugate(y1,mod)
  gen_f12inverse(y2,in_,mod)
  gen_final_exp_dummy_inv(y2)
  gen_f12mul(out,y1,y2,mod)
  gen_f12frobeniusmap(y2,out,2,mod)
  gen_f12mul(out,out,y2,mod)

  gen_f12sqrcyclotomic(y0,out,mod)
  gen_f12raise_to_z(y1,y0,mod)
  gen_f12raise_to_z_div_by_2(y2,y1,mod)
  gen_memcopy(y3,out,48*12)
  gen_f12conjugate(y3,mod)
  gen_f12mul(y1,y1,y3,mod)
  gen_f12conjugate(y1,mod)
  gen_f12mul(y1,y1,y2,mod)
  gen_f12raise_to_z(y2,y1,mod)
  gen_f12raise_to_z(y3,y2,mod)
  gen_f12conjugate(y1,mod)
  gen_f12mul(y3,y3,y1,mod)
  gen_f12conjugate(y1,mod)
  gen_f12frobeniusmap(y1,y1,3,mod)
  gen_f12frobeniusmap(y2,y2,2,mod)
  gen_f12mul(y1,y1,y2,mod)
  gen_f12raise_to_z(y2,y3,mod)
  gen_f12mul(y2,y2,y0,mod)
  gen_f12mul(y2,y2,out,mod)
  gen_f12mul(y1,y1,y2,mod)
  gen_f12frobeniusmap(y2,y3,1,mod)
  gen_f12mul(out,y1,y2,mod)



######################
# finally, the main pairing interface to call above generators for miller loop and final exp

# consts for BLS12-381
def gen_consts():
  # f12 one in mont form
  one = "15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd"
  gen_memstore(f12one,bytearray.fromhex(one)[::-1])
  # prime
  p = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
  gen_memstore(mod,bytes.fromhex(p)[::-1])
  # inv
  inv="fdfffcfffcfff389000000000000000000000000000000000000000000000000"
  gen_memstore(mod+48,bytes.fromhex(inv))


def gen_pairing():

  # generate huff macro to initialize memory
  print("#define macro INIT_MEM = takes(0) returns(0) {")
  gen_consts()			# consts like the modulus, this is required
  print("} // INIT_MEM")

  # these are just some hard-coded inputs which may be useful for testing
  print("#define macro FINAL_EXPONENTIATION_TEST_VALUES = takes(0) returns(0) {")
  gen_final_exp_test_input()	# hard-code values for testing
  print("} // FINAL_EXPONENTIATION_TEST_VALUES")
  print("#define macro MILLER_LOOP_TEST_VALUES = takes(0) returns(0) {")
  gen_miller_loop_test_input()	# hard-code values for testing
  print("} // MILLER_LOOP_TEST_VALUES")

  # miller loop macro
  print("#define macro MILLER_LOOP = takes(0) returns(0) {")
  gen_miller_loop_test_input()	# hard-code values in memory
  gen_miller_loop(buffer_miller_output,buffer_inputs,buffer_inputs+96,mod)
  print("} // MILLER_LOOP")

  # final exponentiation macro
  print("#define macro FINAL_EXPONENTIATION = takes(0) returns(0) {")
  gen_final_exponentiation(buffer_finalexp_output,buffer_miller_output,mod)
  print("} // FINAL_EXPONENTIATION")



#############################
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
  gen_final_exp_dummy_inv(y2)
  gen_f12mul(out,y1,y2,mod)
  gen_f12frobeniusmap(y2,out,2,mod)
  gen_f12mul(out,out,y2,mod)

  gen_f12sqrcyclotomic(y0,out,mod)
  gen_f12raise_to_z(y1,y0,mod)
  gen_f12raise_to_z_div_by_2(y2,y1,mod)
  gen_memcopy(y3,out,48*12)
  gen_f12conjugate(y3,mod)
  gen_f12mul(y1,y1,y3,mod)
  gen_f12conjugate(y1,mod)
  gen_f12mul(y1,y1,y2,mod)
  gen_f12raise_to_z(y2,y1,mod)
  gen_f12raise_to_z(y3,y2,mod)
  gen_f12conjugate(y1,mod)
  gen_f12mul(y3,y3,y1,mod)
  gen_f12conjugate(y1,mod)
  gen_f12frobeniusmap(y1,y1,3,mod)
  gen_f12frobeniusmap(y2,y2,2,mod)
  gen_f12mul(y1,y1,y2,mod)
  gen_f12raise_to_z(y2,y3,mod)
  gen_f12mul(y2,y2,y0,mod)
  gen_f12mul(y2,y2,out,mod)
  gen_f12mul(y1,y1,y2,mod)
  gen_f12frobeniusmap(y2,y3,1,mod)
  gen_f12mul(out,y1,y2,mod)

def gen_pairing_unrolled():
  print("#define macro MILLER_LOOP = takes(0) returns(0) {")
  gen_consts()	# TODO: put this somewhere else
  gen_miller_loop_unrolled(buffer_miller_output,buffer_inputs,buffer_inputs+96,mod)
  print("} // MILLER_LOOP")

  print()

  print("#define macro FINAL_EXPONENTIATION = takes(0) returns(0) {")
  #gen_final_exp_test_values()	# hard-coded input values for testing/debugging
  gen_final_exponentiation_unrolled(buffer_finalexp_output,buffer_miller_output,mod)
  print("} // FINAL_EXPONENTIATION")



####################################################


if __name__=="__main__":
  gen_pairing()
  #gen_pairing_unrolled()
  if 0:
    print("addmod384_count ",addmod384_count)
    print("submod384_count ",submod384_count)
    print("mulmodmont384_count ",mulmodmont384_count)

