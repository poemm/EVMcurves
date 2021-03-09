

# prints MULMODMONT PUSH9... for each one
def gen_huff_chain(formulas,mod_offset,t_offsets):
  count_bytes = 0
  stack=[]
  for idx in range(len(formulas)):
    f=formulas[idx]
    t,f=f.split("=")
    t=int(t[1:])
    if f[:3]=="sqr":
      v1 = int(f[:-1][5:])
      numlimbs = (6).to_bytes(1, byteorder='little').hex()
      out = t_offsets[t].to_bytes(2, byteorder='little').hex()
      x = t_offsets[v1].to_bytes(2, byteorder='little').hex()
      mod = mod_offset.to_bytes(2, byteorder='little').hex()
      immediate=out+x+x
      #immediate=hex(6)[2:].zfill(2)+hex(t_offsets[t])[2:].zfill(4)+hex(t_offsets[v1])[2:].zfill(4)+hex(t_offsets[v1])[2:].zfill(4)+hex(mod_offset)[2:].zfill(4)
    else:
      v1,v2=f.split("*")
      v1=int(v1[1:])
      v2=int(v2[1:])
      numlimbs = (6).to_bytes(1, byteorder='little').hex()
      out = t_offsets[t].to_bytes(2, byteorder='little').hex()
      x = t_offsets[v1].to_bytes(2, byteorder='little').hex()
      y = t_offsets[v2].to_bytes(2, byteorder='little').hex()
      mod = mod_offset.to_bytes(2, byteorder='little').hex()
      immediate=out+x+y
      #immediate=hex(6)[2:].zfill(2)+hex(t_offsets[t])[2:].zfill(4)+hex(t_offsets[v1])[2:].zfill(4)+hex(t_offsets[v2])[2:].zfill(4)+hex(mod_offset)[2:].zfill(4)
    print("mulmodmont 0x"+immediate,"       // ",f, )
    count_bytes += 11

  print("// count_bytes",count_bytes)


if __name__=="__main__":

  filename = "addchain_boscosterwin3.txt"
  mod_offset=2304
  buffer_f12mul = 3752
  buffer_f6mul = 3176
  buffer_f2mul = 3032
  # input, output
  t8 = buffer_f2mul	# input
  t0 = t8+48		# output
  # need 7 other 384-bit offsets as temporary values -- by inspection, unused are the 3rd temp of buffer_f12mul and the 6th temp of buffer_f6mul
  t1 = buffer_f12mul + 576
  t2 = t1+48
  t3 = t2+48
  t4 = t3+48
  t5 = t4+48
  t6 = t5+48
  t7 = buffer_f6mul+(5*96)
  t_offsets = [t0,t1,t2,t3,t4,t5,t6,t7,t8]

  with open(filename) as f:
    in_ = f.readlines()

  formulas = []

  for s in in_:
    if s[0]=="#":
      continue
    if s=='':
      continue
    formulas += [s.split("#")[0].strip().replace(" ", "")]

  # handle input
  t,f=formulas[0].split("=")
  t=int(t[1:])
  # print("memcopy input to t"+str(t))
  formulas=formulas[1:]

  print("#define macro INVERSEMOD_BLS12381 = takes(0) returns(0) {")
  gen_huff_chain(formulas,mod_offset,t_offsets)
  print("} // INVERSEMOD_BLS12381")

