from util import *
from fields import *

####################
# Curve operations #
####################


#######################
# add two curve points

def gen_Eadd__madd_2001_b(f,XYZout,XYZ1,XYZ2,mod):
  # this is untested
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

# add two curve points
#######################



#######################
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
  """
  """
  print("// E double")
  print("////////////")
  return A,B,E,F,ZZ,X1

def gen_Edouble__dbl_2009_l(f,XYZout,XYZ,mod):
  # this is untested
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

# double a curve point
#######################


