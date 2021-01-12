

# this is the naive way, always prints PUSH16... MULMODMONT384, results in large bytecode
def naive_all_push16(formulas,mod_offset,t_offsets):
  count_bytes = 0
  stack=[]
  for idx in range(len(formulas)):
    f=formulas[idx]
    t,f=f.split("=")
    t=int(t[1:])
    if f[:3]=="sqr":
      v1 = int(f[:-1][5:])
      push16=hex(t_offsets[t])[2:].zfill(8)+hex(t_offsets[v1])[2:].zfill(8)+hex(t_offsets[v1])[2:].zfill(8)+hex(mod_offset)[2:].zfill(8)
    else:
      v1,v2=f.split("*")
      v1=int(v1[1:])
      v2=int(v2[1:])
      push16=hex(t_offsets[t])[2:].zfill(8)+hex(t_offsets[v1])[2:].zfill(8)+hex(t_offsets[v2])[2:].zfill(8)+hex(mod_offset)[2:].zfill(8)
    print("0x"+push16,"mulmodmont384	// ",f, )
    count_bytes += 18

  print("// count_bytes",count_bytes)


#################

# this is an optimization to the naive way, DUP's whenever possible, PUSH16s when not already on stack, then MULMODMONT384, results in smaller bytecode
def dup_or_push_and_dup(formulas,mod_offset,t_offsets):
  count_bytes = 0
  stack=[]
  for idx in range(len(formulas)):
    f=formulas[idx]
    t,f=f.split("=")
    t=int(t[1:])
    if f[:3]=="sqr":
      v1 = int(f[:-1][5:])
      push16=hex(t_offsets[t])[2:].zfill(8)+hex(t_offsets[v1])[2:].zfill(8)+hex(t_offsets[v1])[2:].zfill(8)+hex(mod_offset)[2:].zfill(8)
    else:
      v1,v2=f.split("*")
      v1=int(v1[1:])
      v2=int(v2[1:])
      push16=hex(t_offsets[t])[2:].zfill(8)+hex(t_offsets[v1])[2:].zfill(8)+hex(t_offsets[v2])[2:].zfill(8)+hex(mod_offset)[2:].zfill(8)
    if push16 not in stack[-16:]:
      stack+=[push16]
      print("0x"+push16,end=' ')
      count_bytes += 17
    for i,e in enumerate(stack[-1:-17:-1]):
      if e==push16:
        print("dup"+str(i+1),end=' ')	# might be off by one
        count_bytes += 1
        break
    print("mulmodmont384	// ",f)
    count_bytes += 1

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
  dup_or_push_and_dup(formulas,mod_offset,t_offsets)
  print("} // INVERSEMOD_BLS12381")

  print("#define macro INVERSEMOD_BLS12381_NAIVE = takes(0) returns(0) {")
  naive_all_push16(formulas,mod_offset,t_offsets)
  print("} // INVERSEMOD_BLS12381_NAIVE")




