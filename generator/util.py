# size of the underlying prime field
SIZE_F1 = 48

# Size of a curve point for elements in G1
SIZE_E1 = SIZE_F1 * 2

# Size of a curve point for elements in G2
SIZE_E2 = SIZE_E1 * 2

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

def gen_return(offset, length):
  print("{} {} return".format(length, offset))

def gen_logf(offset, field_size, num_elems):
  print("{} {} {} logf".format(offset, field_size, num_elems))

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
  print("// begin memcopy length",len_)
  while len_>32:
    len_-=32
    print(hex(src_offset),end=" ")
    print("mload",end=" ")
    print(hex(dst_offset),end=" ")
    print("mstore",end=" ")
    src_offset+=32
    dst_offset+=32
  # final chunk, may have some overlap with previous chunk
  print(hex(src_offset-(32-len_)),end=" ")
  print("mload",end=" ")
  print(hex(dst_offset-(32-len_)),end=" ")
  print("mstore")

def gen_mergedmemcopy(dst_offsets,src_offset,len_):
  if len_<32:
    print("ERROR gen_memcopy() len_ is ",len_)
    return
  print("// begin memcopy length",len_)
  while len_>32:
    len_-=32
    print(hex(src_offset),end=" ")
    print("mload",end=" ")
    for i,dst_offset in enumerate(dst_offsets):
      if i!=len(dst_offsets)-1:
        print("dup1",end=" ")
      print(hex(dst_offset),end=" ")
      print("mstore",end=" ")
      dst_offsets[i]+=32
    src_offset+=32
  # final chunk, may have some overlap with previous chunk
  print(hex(src_offset-(32-len_)),end=" ")
  print("mload",end=" ")
  for i,dst_offset in enumerate(dst_offsets):
    if i!=len(dst_offsets)-1:
      print("dup1",end=" ")
    print(hex(dst_offset-(32-len_)),end=" ")
    print("mstore")

def gen_equals(output, lhs,rhs,len_):
  if len_<32:
    print("ERROR gen_equals() len_ is ",len_)
    return

  print("{} {} sha3".format(len_, lhs))
  print("{} {} sha3".format(len_, rhs))
  print("eq")
  print(output)
  print("mstore")

# memory offsets for local buffers used for temporary values, the first 576-bytes are zeros
buffer_offset = 0
buffer_f12_function = buffer_offset
buffer_offset += 12*48
buffer_f12_function2 = buffer_offset
buffer_offset += 12*48
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
buffer_miller_output = buffer_offset
buffer_offset += 12*48
buffer_finalexp = buffer_offset
buffer_offset += 12*48*5
buffer_finalexp_output = buffer_offset
buffer_offset += 12*48
buffer_f12frobeniuscoefs = buffer_offset
buffer_offset += 6*48
buffer_f6frobeniuscoefs = buffer_offset
buffer_offset += 9*48
buffer_inputs = buffer_offset
buffer_offset += 2*48+2*96

mem_offsets = {
"buffer_f12_function": buffer_f12_function,	# 12*48
"buffer_f12_function2": buffer_f12_function2,	# 12*48
"zero": zero,					# 12*48
"f12one": f12one,				# 12*48
"mod": mod,					# 48+8
"buffer_miller_loop": buffer_miller_loop,	# 1 E2 point, 1 E1 point affine
"buffer_line": buffer_line,			# 3 f2 points
"buffer_f2mul": buffer_f2mul,			# 3 f1 points
"buffer_f6mul": buffer_f6mul,			# 6 f2 points
"buffer_f12mul": buffer_f12mul,			# 3 f6 points
"buffer_Eadd": buffer_Eadd,			# 14 or 9 values
"buffer_Edouble": buffer_Edouble,		# 7 or 6 values
"buffer_miller_output": buffer_miller_output,
"buffer_finalexp": buffer_finalexp,
"buffer_finalexp_output": buffer_finalexp_output,
"buffer_f12frobeniuscoefs": buffer_f12frobeniuscoefs,
"buffer_f6frobeniuscoefs": buffer_f6frobeniuscoefs,
"buffer_inputs": buffer_inputs,
}

p_g1_1 = buffer_inputs
p_g2_1 = p_g1_1 + SIZE_E1
p_g1_2 = p_g2_1 + SIZE_E2 
p_g2_2 = p_g1_2 + SIZE_E1

# pack offsets into stack item
def gen_evm384_offsets(a,b,c,d):
  # Each EVM384v7 opcode is preceeded with a PUSH16 with packed memory offsets
  print("0x"+hex(a)[2:].zfill(8)+hex(b)[2:].zfill(8)+hex(c)[2:].zfill(8)+hex(d)[2:].zfill(8), end=' ')
