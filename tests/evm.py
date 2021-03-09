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


import sys
import math

import sha3     # pip install pysha3


verbose = 0
debug = 0






##############################
# 2. The Blockchain Paradigm #
##############################


##################
# 3. Conventions #
##################

def keccak256(bytes_):
  return sha3.keccak_256(bytes_).digest()

# keccak-256
def KEC(bytes_):
  return keccak256(bytes_)



######################
# 5. Gas and Payment #
######################



############################
# 6. Transaction Execution #
############################

# 6.1 Substate

# transaction execution accrues info which is acted upon immediately following the tx

# accrued transaction substate
# A denotes an instance
class AccruedSubstate:
  def __init__(self,self_destruct_set,log_series,touched_accounts,refund_balance):
    self.s = self_destruct_set  # accounts which will be discarded following tx's completion
    self.l = log_series         # series of indexed checkpoints in VM code execution
    self.t = touched_accounts   # set of touched accts, empty ones will be deleted, not in frontier
    self.r = refund_balance     # from SSTORE to set from nonzero to zero, partially offsets the execution cost

# empty accrued substate
def A0():
  return AccruedSubstate(set(),[],set(),0)



######################
# 9. Execution Model #
######################


###########################
# 9.3 Execution Environment

# I denotes an instance of ExecutionEnvironment
class ExecutionEnvironment:
  def __init__(self, a, o, p, d, s, v, b, H, e, w, recentblocks):
    self.a = a  # code owner address
    self.o = o  # original sender address
    self.p = p  # gas price of original tx
    self.d = d  # input data
    self.s = s  # address which caused this execution
    self.v = v  # wei
    self.b = b  # bytecode being executed
    self.H = H  # block header, or at least what is needed for opcodes BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT
    self.e = e  # depth of calls and creations before can execute the present
    self.w = w  # permission to modify state, not in frontier
    # the following are not in the spec, but we need it
    self.recentblocks = recentblocks    # dictionary with 256 recent blocks, used only by BLOCKHASH with 256 recent block headers, dictionary is indexed by blockhash

# note: after frontier, Xi should also have arg t and return z. In frontier, it returns s,l,r but we just return A for now
# def Xi(sigma, g, I):
#   return sigmaprime, gprime, A, o



########################
# 9.4 Execution Overview

# sigma (i.e. greek letter 𝝈) denotes system state
# mu (i.e. greek letter 𝛍) denotes machine state

# this section defines Xi() (i.e. greek letter Ξ)
# yellowpaper defines Xi() recursively
#   with function X()
#   and iterator function O() which defines a single cycle of the state machine
#   and function Z() which determines exceptional halting
#   and function H() which specifies the output data iff normal halting states
# yellowpaper suggests that a fast implementations of Xi() may be an iterative progression of sigma and mu

# notation: empty sequence () is different from emptyset. H outputs emptyset when execution is to continue and a sequence, possibly (), when execution halts

# Ξ in the yellowpaper, Xi is how this Greek letter is written in ASCII
def Xi(sigma, 
       g,       # available gas
       I,       # execution environment
       T):      # tuple (sender address, contract address), not in frontier
  if verbose: print("Xi()")
  #print("Xi()")
  #print("code", I.b.hex())
  mu = MachineState(g,0,bytearray([]),0,[],[0,0,0],bytearray([]))   # note: MachineState is defined in 9.4.1
  sigmaprime,muprime,A,I,o = X_loop(sigma,mu,A0(),I)
  return sigmaprime, muprime.g, A, o


debug_X = 0
def X(sigma,mu,A,I):
  if debug_X: print("X()")
  # this function recurses until exception, REVERT, or there is an output
  o = H(mu,I)   # check whether we reached a non-exception halting opcode
  w_ = w(mu,I)  # get next opcode
  if debug_X: print("w_",w_,I.b.hex())
  if Z(sigma,mu,I): # exception
    if debug_X: print("X() exception Z()")
    sigmaprime,muprime,A,I,o = {},mu,A0(),I,b''
    #elif w_==0xfd:    # REVERT     REVERT is not in frontier
    #muprime = mu
    #muprime.g = mu.g-C(sigma,mu,I)
    #sigmaprime,muprime,A,I,o = None,muprime,A0(),I,o
  elif o!=None:     # halt after this opcode
    if debug_X: print("X() halt after this opcode")
    sigmaprime,muprime,A,I = O(sigma,mu,A,I) # execution cycle
    o = mu.o # this is awkward, call it again after O() now that mu.o is updated
  else:             # recurse 
    if debug_X: print("X() recurse")
    sigmaprime,muprime,A,I,o = X(*O(sigma,mu,A,I))
  return sigmaprime, muprime, A, I, o


# the book suggests doing X() in a loop, so implement that too, since recursion with long-running programs may exceed system limits, I think that python has limit recursion depth 500
def X_loop(sigma,mu,A,I):
  if debug_X: print("X_loop()")
  while 1:
    if debug_X: print("X_loop() iter",mu.g)
    o = H(mu,I)   # check whether we reached a non-exception halting opcode
    w_ = w(mu,I)  # get next opcode
    if Z(sigma,mu,I): # excepton
      sigma,mu,A,I,o = {},mu,A0(),I,b''
      break
    #elif w_==0xfd:    # REVERT     # not in frontier
    #  muprime = mu
    #  muprime.g = mu.g-C(sigma,mu,I)
    #  sigmaprime,muprime,A,I,o = None,muprime,A0(),I,o
    #  break
    elif o!=None:     # halt after this halting opcode
      sigma,mu,A,I = O(sigma,mu,A,I) # execution cycle
      o = mu.o     # this is awkward, call it again after O() so that mu.o is updated
      break
    else:
      sigma,mu,A,I = O(sigma,mu,A,I)
  return sigma, mu, A, I, o



# 9.4.1 Machine State.

# mu denotes an instance of MachineState
class MachineState:
  def __init__(self,g,pc,m,i,s,mc,o):
    self.g =    g   # gas available
    self.pc =   pc  # program counter
    self.m =    m   # memory contents up to zero padding until size 2^256
    self.i =    i   # number of active words in memory, counting continuously from position 0
    self.s =    s   # stack contents
    self.mc =    mc  # modulus context for *MODMONT
    # the rest are not officially in machine state, but the spec treats them as if they are
    self.o =    o   # return data, should be empty bytearray by default

# w is current instruction to be executed
def w(mu,I):
  if mu.pc<len(I.b):
    return I.b[mu.pc]
  else:
    return 0x00     # STOP


# 9.4.2 Exceptional Halting

# the exceptional halting function
debug_Z = 0
def Z(sigma, mu, I):
  if debug_Z: print("Z()")
  w_ = w(mu,I)
  if((w_ not in EVM_opcodes) or   # instruction is invalid (in spec, they check if delta_w is undefined)
     len(mu.s)<EVM_opcodes[w_]["delta"] or  # insufficient stack items 
     mu.g<C(sigma,mu,I) or      # insufficient gas, typo in yp, this goes after checking for insufficient stack items which C() depends on
     ( w_==0x56 and             # opcode is "JUMP", need JUMPDEST
       mu.s[-1] not in D_loop(I.b) ) or  # D(), defined below, is the set of valid jump destinations
     ( w_==0x57 and             # similar for JUMPI
       mu.s[-2] != 0 and 
       mu.s[-1] not in D_loop(I.b) ) or
     len(mu.s) - EVM_opcodes[w_]["delta"] + EVM_opcodes[w_]["alpha"] > 1024):    #or  # stack size > 1024
    # the following are not in frontier
    #( w_==0x3e and             # RETURNDATACOPY
    #  mu.s[-2] + mu.s[-3] > len(mu.o) ) or 
    #( ( not I.w ) and W(w_,mu) ) ):   # state modification attempted during static call
    return True
  else:
    if debug_Z: print("Z() returning False")
    return False

# W() is not in frontier
# check if this opcode does state modification
def W(w_,mu):
  if(w_ in {0xf0,0x55,0xff} or    # CREATE, SSTORE, SELFDESTRUCT
     ( 0xa0 <= w_ and w_ <= 0xa4 ) or  # LOG0 to LOG4; note: typo in yellowpaper gives ambiguous precedence of and
     ( w_ in {0xf1,0xf2} and mu.s[-3]!=0 ) ):   # CALL or CALLCODE with nonzero value transferred
    return True
  else:
    return False

# claim: if Z() returns False, then execution of instruction can't cause an exceptional halt
# I.e. there are no undefined exceptional halts. This needs proof.


# 9.4.3 Jump Destination Validity

# valid jump destinations are positions of JUMPDEST instruction
#   must not be in immediates of PUSH
#   must be in "explicitly" defined portion of code, not "implicitly" defined STOP operations that trail it

# TODO: do this at contract creation, store it with code

# return set of valid jump destinations
def D(c):
  return D_J(c,0)

# recursive helper of D
def D_J(c,i):
  if i >= len(c):
    return set()
  elif c[i] == 0x5b:    # JUMPDEST
    return set([i]).union(D_J(c,N(i,c[i])))
  else:
    return D_J(c,N(i,c[i]))

# get the next valid instruction position, skipping PUSH* immediates
def N(i,w_):
  #print("N()",i,hex(w_))
  if 0x60<=w_ and w_<=0x7f:   # PUSH1,PUSH2,...,PUSH32
    return i+w_-0x60+2
  elif 0xc0<=w_ and w_<=0xc2:   # *MODMONT
    return i+8
  else:
    return i+1

# Note: above D() is recursive, and python exceeds recursion here at depth 1000, so do it in a loop. Both versions seem to work, but D_loop() can handle >1000 jumpdests.
def D_loop(c):
  jumpdests = set()
  pc = 0
  while pc < len(c):
    if c[pc] == 0x5b:    # JUMPDEST
      jumpdests.add(pc)
    pc = N(pc,c[pc])
  return jumpdests



# 9.4.4 Normal Halting

# the normal halting function
def H(mu,I):
  w_ = w(mu,I)
  if w_ in {0xf3}: #,0xfd}:      # RETURN, since 0xfd REVERT is not in frontier
    return mu.o              # H_RETURN(mu) is defined in appx H, opcode RETURN. We hard-code mu.o here which may be empty string since H() is called before RETURN opcode
  elif w_ in {0x00,0xff}:    # STOP,SELFDESTRUCT
    return bytearray([])
  else:
    return None



#########################
# 9.5 The Execution Cycle

# iterator function, defines single cycle of the state machine
debug_O = 0
counter = 0
def O(sigma, mu, A, I):
  global counter
  if debug_O:
    print("O() counter",counter)
    print("O() gas available",mu.g)
  counter+=1


  # 1. get opcode
  w_ = w(mu,I)

  # count opcodes executed
  if debug_O:
    if "count" in EVM_opcodes[w_]:
      EVM_opcodes[w_]["count"]+=1
    else:
      EVM_opcodes[w_]["count"]=1
    all_counts = {}
    all_counts["other"] = 0
    for op in EVM_opcodes:
      threshold = 0     # set threshold here
      if threshold:
        if "count" in EVM_opcodes[op] and EVM_opcodes[op]["count"]>threshold:
          all_counts[EVM_opcodes[op]["mnemonic"]] = EVM_opcodes[op]["count"]
        elif "count" in EVM_opcodes[op]:
          all_counts["other"] += EVM_opcodes[op]["count"]
      elif "count" in EVM_opcodes[op]: # no threshold
        all_counts[EVM_opcodes[op]["mnemonic"]] = EVM_opcodes[op]["count"]
    #print(all_counts)
    if 1:
      non_mont_count=0
      for op in all_counts:
        if op not in {'ADDMODMONT', 'SUBMODMONT', 'MULMODMONT'}:
         non_mont_count+=all_counts[op]
      print("non_mont_count",non_mont_count)
    print("memory length",len(mu.m))
    print(dict(sorted(all_counts.items(), key=lambda item: item[1], reverse=True)))

  if debug_O:
    print(hex(w_)[2:],EVM_opcodes[w_]["mnemonic"],"\tstack,gas:",[mu.s[-1*i] for i in range(EVM_opcodes[w_]["delta"],0,-1)],"\t",mu.g,"\t->",end="")

  # 2. check stack, making sure that stack pops/pushes items with low index first then shifts indices
  # there is several stack assertions, which we omit because EVM does precisely what these assertions check
  # note: we must reduce gas, execute opcode, then adjust pc, in the following order, otherwise opcodes GAS and PC will break

  # 3. reduce gas; note: some opcodes reduce it further
  mu.g = mu.g - C(sigma, mu, I) # note: this is repeated in 9.4
  if mu.g<0:
    return {}, mu, A, I     # out-of-gas error

  # 4. execute opcode
  # execute opcode
  sigmaprime,muprime,Aprime,I = EVM_opcodes[w_]["description"](sigma,mu,A,I)
  if debug_O:
    print("\t",[mu.s[-1*i] for i in range(EVM_opcodes[w_]["alpha"],0,-1)],mu.g)

  # note: if sigmaprime=={}, then there was an exception

  # 5. adjust program counter
  if w_ not in {0x56,0x57}: # if not JUMP or JUMPI
    muprime.pc = N(mu.pc,w_)
  else: 
    # JUMP and JUMPI already adjusted it
    pass

  return sigmaprime, muprime, Aprime, I


###################
# 10. Blockchaian # 
###################

# get parent block from this block header
# we give it an extra arg Blocks which is a dictionary
def P(H,            # a block header
      blocks):      # this is not in the yellowpaper, but we need a dictionary of blocks indexed by hash
  parent = blocks[H.p]
  return parent




##########################
# 11. Block Finalization #
##########################






#######################################
# Appendix B. Recursive Length Prefix #
#######################################



###################################
# Appendix C. Hex Prefix Encoding #
###################################



###########################################
# Appendix D. Modified Merkle Patricia Tree



############
# Appendix F






##########################
# Appendix G. Fee Schedule

# G denotes fixed gas costs
G = {
  "zero":         0,        # nothing paid for ops of the set W["zero"]
  "base":         2,        # gas for ops in set W["base"]
  "verylow":      3,        #                    W["verylow"]
  "low":          5,        #                    W["low"]
  "lowmid":       6,        #                    W["lowmid"]  for MULMODMONT
  "mid":          8,        #                    W["mid"]
  "high":         10,       #                    W["high"]
  "ext":          20,       #                    W["ext"]
  #"balance":      400,      #         BALANCE
  "sload":        50,       #         SLOAD
  "jumpdest":     1,        #         JUMPDEST
  "sset":         20000,    #         SSTORE when change from zero to nonzero
  "sreset":       5000,     #         SSTORE when set to or remains zero
  "selfdestruct": 5000,     #         SELFDESTRUCT
  "create":       32000,    #         CREATE
  "codedeposit":  200,      #         CREATE per byte to put code in state
  "call":         40,       #         CALL
  "callvalue":    9000,     #         CALL for non-zero value transfer
  "callstipend":  2300,     # stipend for called contract subtracted from G["callvalue"] for nonzero value transfer
  "newaccount":   25000,    # gas for CALL or SELFDESTRUCT op which creates an account
  "exp":          10,       # partial payment for EXP
  "expbyte":      10,       #                     EXP when multiplied by ceil(log_256(exponent)) [?]
  "memory":       3,        # every additional word when expanding mem
  #"txcreate":     32000,
  "txdatazero":   4,
  "txdatanonzero":68,
  "transaction":  21000,
  "log":          375,
  "logdata":      8,
  "logtopic":     375,
  "sha3":         30,
  "sha3word":     6,
  "copy":         3,
  #"blockhash":    20,
  #"quaddivisor":  20 
}

# R denotes gas refund amonuts
R = {
  "sclear":       15000,    # added to refund counter when storage is set from nonzero to zero
  "selfdestruct": 24000,    # added to refund counter when SELFDESTRUCT account
}


###########################################
# Appendix H. Virtual Machine Specification

# H.1 Gas Cost

# returns gas used by an opcode
# note: we deviate from the yellowpaper, we compute C_memory, C_SELFDESTRUCT, C_SSTORE inside the opcodes, where they can be readily computed.
def C(sigma, mu, I):
  # get opcode
  w_ = w(mu,I)
  # prepare return
  ret = 0 # C_memory(mu.iprime) - C_memory(mu.i)  # note: mu.iprime is available in the opcodes, so compute C_memory there
  if w_==0x55:   # SSTORE
    pass # this is done inside SSTORE
  elif w_==0x0a and mu.s[-2]==0:    # EXP
    ret += G["exp"]
  elif w_==0x0a and mu.s[-2]>0:     # EXP
    ret += G["exp"] + G["expbyte"] * (1 + math.floor(math.log(mu.s[-2],256)))
  elif w_ in {0x37,0x39}:   # CALLDATACOPY, CODECOPY    #0x3c RETURNDATACOPY
    ret += G["verylow"] + G["copy"]*-1*((-1*mu.s[-3])//32)
  elif w_ == 0x3c:   # EXTCODECOPY
    ret += G["ext"] + G["copy"]*-1*((-1*mu.s[-4])//32)
  elif w_ == 0xa0:   # LOG0
    ret += G["log"] + G["logdata"]*mu.s[-2]
  elif w_ == 0xa1:   # LOG1
    ret += G["log"] + G["logdata"]*mu.s[-2] + G["logtopic"]
  elif w_ == 0xa2:   # LOG2
    ret += G["log"] + G["logdata"]*mu.s[-2] + 2*G["logtopic"]
  elif w_ == 0xa3:   # LOG3
    ret += G["log"] + G["logdata"]*mu.s[-2] + 3*G["logtopic"]
  elif w_ == 0xa4:   # LOG4
    ret += G["log"] + G["logdata"]*mu.s[-2] + 4*G["logtopic"]
  elif w_ in {0xf1,0xf2}:  # CALL, CALLCODE:
    ret += 0 # C_CALL(sigma,mu)  # note: C_CALL() is in appx H, compute it there
  #elif w_ == "SELFDESTRUCT":    # not in frontier
  #  ret += 0 # C_SELFDESTRUCT(sigma,mu)  # note: C_SELFDESTRUCT() is in appx H, compute it there
  elif w_ in {0xf1,0xf2}:  # CALL or CALLCODE
    # do this in the actual opcodes
    pass
  elif w_ == 0xf0:  # CREATE
    ret += G["create"]
  elif w_ == 0x20:  # SHA3
    ret += G["sha3"] + G["sha3word"]*(-1*(-1*mu.s[-2])//32)      # typo: s should be mu.s
  elif w_ == 0x5b:   # JUMPDEST
    ret += G["jumpdest"]
  elif w_ == 0x54:   # SLOAD
    ret += G["sload"]
  elif w_ in W["zero"]:
    ret += G["zero"]
  elif w_ in W["base"]:
    ret += G["base"]
  elif w_ in W["verylow"]:
    ret += G["verylow"]
  elif w_ in W["low"]:
    ret += G["low"]
  elif w_ in W["lowmid"]:
    ret += G["lowmid"]
  elif w_ in W["mid"]:
    ret += G["mid"]
  elif w_ in W["high"]:
    ret += G["high"]
  elif w_ in W["ext"]:
    ret += G["ext"]
  #elif w_ == "BALANCE":
  #  ret += G["balance"]
  #elif w_ == "BLOCKHASH":
  #  ret += G["blockhash"]
  return ret

def C_memory(a):
  return G["memory"]*a + (a**2)//512

W = {
  "zero":{0xfd,0xff,0xf3}, # STOP, SELFDESTRUCT, RETURN
  "base":{0x30,0x32,0x33,0x34,0x36,0x38,0x3a,0x41,0x42,0x43,0x44,0x45,0x50,0x58,0x59,0x5a}, # ADDRESS, ORIGIN, CALLER, CALLVALUE, CALLDATASIZE, CODESIZE, GASPRICE, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, POP, PC, MSIZE, GAS
  "verylow":{0x01,0x03,0x19,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x1a,0x35,0x51,0x52,0x53,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f}, # ADD, SUB, NOT, LT, GT, SLT, SGT, EQ, ISZERO, AND, OR, XOR, BYTE, CALLDATALOAD, MLOAD, MSTORE, MSTORE8, PUSH*, DUP*, SWAP*},
  "low":{0x02,0x04,0x05,0x06,0x07,0x0b}, # MUL, DIV, SDIV, MOD, SMOD, SIGNEXTEND
  "mid":{0x08,0x09,0x56},  # ADDMOD, MULMOD, JUMP
  "high":{0x57}, # JUMPI
  "ext":{0x31,0x3b,0x40}  # BALANCE, EXTCODESIZE, BLOCKHASH
}

# experimental
W["base"].update([0xc0,0xc1])      # ADDMODMONT/SUBMODMONT
W["lowmid"] = {0xc2}               # MULMODMONT
W["verylow"].add(0x5c)             # MCOPY
 
# memory expansion range function ("memory expansion function")
# note: name collision with chapter 4.3.1 involving logs, so call this one M_
def M_(s,f,l):
  # args are current numwords, proposed start byte, proposed length
  if l==0:
    return s
  else:
    return max(s,-1*((-1*(f+l))//32))

# not in frontier
# all but one 64th function
def L(n):
  return n-n//64


# H.2 Instruction Set

def STOP(sigma,mu,A,I):
  return sigma,mu,A,I

def ADD(sigma,mu,A,I):
  mu.s.append((mu.s.pop()+mu.s.pop())%2**256)
  return sigma,mu,A,I

def MUL(sigma,mu,A,I):
  mu.s.append((mu.s.pop()*mu.s.pop())%2**256)
  return sigma,mu,A,I

def SUB(sigma,mu,A,I):
  mu.s.append((mu.s.pop()-mu.s.pop())%2**256)
  return sigma,mu,A,I

def DIV(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  if mus1==0:
    mu.s.append(0)
  else:
    mu.s.append(mus0//mus1)
  return sigma,mu,A,I

def SDIV(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  # note: convert negative values to 2**256-value
  mus0_signed = mus0 if mus0<2**255 else mus0-2**256
  mus1_signed = mus1 if mus1<2**255 else mus1-2**256
  if mus1==0:
    mu.s.append(0)
  elif mus0_signed==-1*2**255 and mus1_signed==-1:
    mu.s.append(mus0)
  else:
    sgn = -1 if mus0_signed*mus1_signed<0 else 1
    ret = sgn*(abs(mus0_signed)//abs(mus1_signed))
    if ret<0:
      ret = 2**256+ret
    mu.s.append(ret)
  return sigma,mu,A,I

def MOD(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  if mus1==0:
    mu.s.append(0)
  else:
    mu.s.append(mus0%mus1)
  return sigma,mu,A,I

def SMOD(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  mus0_signed = mus0 if mus0<2**255 else mus0-2**256
  mus1_signed = mus1 if mus1<2**255 else mus1-2**256
  if mus1==0:
    mu.s.append(0)
  else:
    sgn = 1 if mus0_signed>=0 else -1
    ret = sgn*(abs(mus0_signed)%abs(mus1_signed))
    if ret<0:
      ret = 2**256+ret
    mu.s.append(ret)
  return sigma,mu,A,I

def ADDMOD(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  mus2 = mu.s.pop()
  if mus2==0:
    mu.s.append(0)
  else:
    mu.s.append((mus0+mus1)%mus2)
  return sigma,mu,A,I

def MULMOD(sigma,mu,A,I):
  mus0 = mu.s.pop()     # a
  mus1 = mu.s.pop()     # b
  mus2 = mu.s.pop()     # modulus
  if mus2==0:
    mu.s.append(0)
  else:
    mu.s.append((mus0*mus1)%mus2)
  return sigma,mu,A,I

def EXP(sigma,mu,A,I):
  mus0 = mu.s.pop()     # base
  mus1 = mu.s.pop()     # exponent
  #mu.s.append((mus0**mus1)%2**256)  # this is very slow for big mus1, so use the popular right-to-left binary method below
  base = mus0
  exponent = mus1
  base = base % 2**256
  result = 1
  while exponent > 0:
    if (exponent % 2 == 1):
      result = (result * base) % 2**256
    exponent = exponent >> 1
    base = (base * base) % 2**256
  mu.s.append(result)
  return sigma,mu,A,I

def SIGNEXTEND(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  # I think that mus0 is assumed unsigned, otherwise t can be >256 and we overflow
  # and mus1 is arbitrary, since two's complement
  mus1_bytes = mus1.to_bytes(256,"big")
  ret = 0
  t = 256-8*(mus0+1)    # takes value 0, 8, 16, ..., 248
  for i in range(256):
    if i<=t:
      ret += (mus1 & (1<<(255-t))) << (t-i)
    else:
      ret += (mus1 & (1<<(255-i)))
  mu.s.append(ret)
  return sigma,mu,A,I

def LT(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  if mus0<mus1:
    mu.s.append(1)
  else:
    mu.s.append(0)
  return sigma,mu,A,I

def GT(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  if mus0>mus1:
    mu.s.append(1)
  else:
    mu.s.append(0)
  return sigma,mu,A,I

def SLT(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  mus0_signed = mus0 if mus0<2**255 else mus0-2**256
  mus1_signed = mus1 if mus1<2**255 else mus1-2**256
  if mus0_signed<mus1_signed:
    mu.s.append(1)
  else:
    mu.s.append(0)
  return sigma,mu,A,I

def SGT(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  mus0_signed = mus0 if mus0<2**255 else mus0-2**256
  mus1_signed = mus1 if mus1<2**255 else mus1-2**256
  if mus0_signed>mus1_signed:
    mu.s.append(1)
  else:
    mu.s.append(0)
  return sigma,mu,A,I

def EQ(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  if mus0==mus1:
    mu.s.append(1)
  else:
    mu.s.append(0)
  return sigma,mu,A,I

def ISZERO(sigma,mu,A,I):
  mus0 = mu.s.pop()
  if mus0==0:
    mu.s.append(1)
  else:
    mu.s.append(0)
  return sigma,mu,A,I

def AND(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  mu.s.append(mus0 & mus1)
  return sigma,mu,A,I

def OR(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  mu.s.append(mus0 | mus1)
  return sigma,mu,A,I

def XOR(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  mu.s.append(mus0 ^ mus1)
  return sigma,mu,A,I

def NOT(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mu.s.append(2**256-1 - mus0)
  return sigma,mu,A,I

def BYTE(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  ret = 0
  for i in range(256):
    if i<8 and mus0<32:
      ret += (mus1 & 1<<(i+8*(31-mus0)))
  #ret >>= 8*(31-mus0)
  mu.s.append(ret)
  return sigma,mu,A,I

def SHR(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  ret = mus1//(2**mus0)
  mu.s.append(ret)
  return sigma,mu,A,I

def SHA3(sigma,mu,A,I):
  mus0 = mu.s.pop()     # start offset
  mus1 = mu.s.pop()     # length
  mu_iprev = mu.i
  mu.i = M_(mu.i,mus0,mus1)
  print("SHA3",mu.i,mu_iprev)
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  ret = KEC(mu.m[mus0:mus0+mus1])
  mu.s.append(int.from_bytes(ret,"big"))
  #mu.s.append(1)
  return sigma,mu,A,I

def ADDRESS(sigma,mu,A,I):
  mu.s.append(int.from_bytes(I.a,"big"))
  return sigma,mu,A,I

def BALANCE(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus0bytes20 = mus0.to_bytes(160,"big")  # note: maybe should be "little"
  if mus0bytes20 in sigma:
    mu.s.append(sigma[mus0bytes20].b)
  else:
    mu.s.append(0)
  return sigma,mu,A,I

def ORIGIN(sigma,mu,A,I):
  mu.s.append(int.from_bytes(I.o,"big"))
  return sigma,mu,A,I

def CALLER(sigma,mu,A,I):
  print(int.from_bytes(I.s,'big'))
  mu.s.append(int.from_bytes(I.s,'big'))
  return sigma,mu,A,I

def CALLVALUE(sigma,mu,A,I):
  mu.s.append(I.v)
  return sigma,mu,A,I

def CALLDATALOAD(sigma,mu,A,I):
  mus0 = mu.s.pop()
  if mus0>=len(I.d):
    mu.s.append(0)
  else:
    calldata = I.d[mus0:mus0+32]
    calldata += bytes(32-len(calldata))
    mu.s.append(int.from_bytes(calldata,"big"))
  return sigma,mu,A,I

def CALLDATASIZE(sigma,mu,A,I):
  mu.s.append(len(I.d))
  return sigma,mu,A,I

def CALLDATACOPY(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  mus2 = mu.s.pop()
  # extend memory if necessary
  mu_iprev = mu.i
  mu.i = M_(mu.i,mus0,mus2)
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  for i in range(mus2):
    if mus1+i<len(I.d):
      mu.m[mus0+i] = I.d[mus1+i]
    else:
      mu.m[mus0+i] = 0
  return sigma,mu,A,I

def CODESIZE(sigma,mu,A,I):
  mu.s.append(len(I.b))
  return sigma,mu,A,I

def CODECOPY(sigma,mu,A,I):
  mus0 = mu.s.pop()     # memory location
  mus1 = mu.s.pop()     # code location
  mus2 = mu.s.pop()     # length
  # extend memory if necessary
  mu_iprev = mu.i
  mu.i = M_(mu.i,mus0,mus2)
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  for i in range(mus2):
    if mus1+i<len(I.b):
      mu.m[mus0+i] = I.b[mus1+i]
    else:
      mu.m[mus0+i] = 0
  return sigma,mu,A,I

def GASPRICE(sigma,mu,A,I):
  mu.s.append(I.p)
  return sigma,mu,A,I

def EXTCODESIZE(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus0bytes20 = mus0.to_bytes(160,"big")  # note: maybe should be "little"
  if mus0bytes20 in sigma:
    mu.s.append(len(sigma[mus0bytes20].b))
  else:
    mu.s.append(0)
  return sigma,mu,A,I

def EXTCODECOPY(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  mus2 = mu.s.pop()
  mus3 = mu.s.pop()
  # extend memory if necessary
  mu_iprev = mu.i
  mu.i = M_(mu.i,mus1,mus3)
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  # get code
  mus0bytes20 = mus0.to_bytes(160,"big")  # note: maybe should be "little"
  if mus0bytes20 in sigma:
    c = sigma[mus0bytes20].c
  else:
    c = bytes([])
  # copy code to mem
  for i in range(mus3):
    if mus2+i<len(c):
      mu.m[mus1+i] = c[mus2+i]
    else:
      assert 1==0     # STOP, note: find a nicer way to do this
  return sigma,mu,A,I
      
def RETURNDATASIZE(sigma,mu,A,I):
  mu.s.append(len(mu.o))
  return sigma,mu,A,I

def RETURNDATACOPY(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  mus2 = mu.s.pop()
  # extend memory if necessary
  mu_iprev = mu.i
  mu.i = M_(mu.i,mus0,mus2)
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  # copy code to mem
  for i in range(mus2):
    if mus1+i<len(mu.o):
      mu.m[mus0+i] = mu.o[mus1+i]
    else:
      mu.m[mus0+i] = 0
  return sigma,mu,A,I

def BLOCKHASH(sigma,mu,A,I):
  # func P_ steps back over headers until it reaches the correct block number
  # note: name collision with func P() in section 10
  def P_(h,n,a):
    H = I.recentblocks[h].H         # get block header from block hash h
    if n>H.i or a==256 or h==0:     # recall: H.i is blocknumber
      return 0
    elif n==H.i:
      return h
    else:
      return P_(H.p,n,a+1)
  blockhash = P_(I.H.p,mus0,0)
  ret = int.from_bytes(blockhash,'big')
  mu.s.append(ret)
  return sigma,mu,A,I

def COINBASE(sigma,mu,A,I):
  mu.s.append(int.from_bytes(I.H.c,"big"))
  return sigma,mu,A,I

def TIMESTAMP(sigma,mu,A,I):
  mu.s.append(I.H.s)
  return sigma,mu,A,I

def NUMBER(sigma,mu,A,I):
  mu.s.append(I.H.i)
  return sigma,mu,A,I

def DIFFICULTY(sigma,mu,A,I):
  print("DIFFICULTY",I.H.d)
  mu.s.append(I.H.d)
  return sigma,mu,A,I

def GASLIMIT(sigma,mu,A,I):
  mu.s.append(I.H.l)
  return sigma,mu,A,I

def POP(sigma,mu,A,I):
  mu.s.pop()
  return sigma,mu,A,I

def MLOAD(sigma,mu,A,I):
  mus0 = mu.s.pop()
  # extend memory if necessary
  mu_iprev = mu.i
  mu.i = max(mu.i,-1*((-1*(mus0+32))//32))
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  ret = int.from_bytes(mu.m[mus0:mus0+32],'big')
  mu.s.append(ret)
  return sigma,mu,A,I

def MSTORE(sigma,mu,A,I):
  mus0 = mu.s.pop()     # mem offset
  mus1 = mu.s.pop()     # word to store
  # extend memory if necessary
  mu_iprev = mu.i
  mu.i = max(mu.i,-1*((-1*(mus0+32))//32))
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  mus1bytes = mus1.to_bytes(32,'big')
  mu.m[mus0:mus0+32] = mus1bytes
  return sigma,mu,A,I

def MSTORE8(sigma,mu,A,I):
  mus0 = mu.s.pop()
  mus1 = mu.s.pop()
  # extend memory if necessary
  mu_iprev = mu.i
  mu.i = max(mu.i,-1*((-1*(mus0+1))//32))
  print("MSTORE8",mu.i,mu_iprev)
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  mu.m[mus0] = mus1%256
  return sigma,mu,A,I

def SLOAD(sigma,mu,A,I):
  return sigma,mu,A,I
  
def SSTORE(sigma,mu,A,I):
  return sigma,mu,A,I
  
def JUMP(sigma,mu,A,I):
  def J_JUMP(mu):
    mus0 = mu.s.pop()
    mu.pc = mus0
  J_JUMP(mu)
  # note: JUMPDEST check done in Z()
  return sigma,mu,A,I

def JUMPI(sigma,mu,A,I):
  def J_JUMPI(mu):
    mus0 = mu.s.pop()
    mus1 = mu.s.pop()
    if mus1!=0:
      mu.pc = mus0
    else:
      mu.pc = mu.pc+1
  J_JUMPI(mu)
  # note: JUMPDEST check done in Z()
  return sigma,mu,A,I

def PC(sigma,mu,A,I):
  mu.s.append(mu.pc)
  return sigma,mu,A,I

def MSIZE(sigma,mu,A,I):
  mu.s.append(32*mu.i)
  return sigma,mu,A,I

def GAS(sigma,mu,A,I):
  mu.s.append(mu.g)
  return sigma,mu,A,I

def JUMPDEST(sigma,mu,A,I):
  # do nothing during execution
  return sigma,mu,A,I

def MCOPY(sigma,mu,A,I):
  mus0 = mu.s.pop()     # length
  mus1 = mu.s.pop()     # dst offset
  mus2 = mu.s.pop()     # src offset
  # extend memory if necessary
  mu_iprev = mu.i
  mu.i = max(mu.i,-1*((-1*(max(mus1,mus2)+mus0))//32))
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  mu.g = mu.g - 3*(mus0//32)     # MCOPY costs 1 gas per 256-bit word, excluding first one
  mu.m[mus1:mus1+mus0] = mu.m[mus2:mus2+mus0]
  return sigma,mu,A,I

def PUSHn(sigma,mu,A,I):
  # c() returns the immediates, or 0 if overflow code
  def c(x):
    if x<len(I.b):
      return I.b[x]
    else:
      return 0
  n = I.b[mu.pc]-0x60+1
  immediate = int.from_bytes(bytes([c(mu.pc+i+1) for i in range(n)]),'big')
  mu.s.append(immediate)
  # note: PC incremented by N()
  return sigma,mu,A,I

def DUPn(sigma,mu,A,I):
  n = I.b[mu.pc]-0x7f
  val = mu.s[-1*n]          # note: check for underflow done in Z() in section 9.4.2
  mu.s.append(val)
  return sigma,mu,A,I

def SWAPn(sigma,mu,A,I):
  n = I.b[mu.pc]-0x8e
  tmp = mu.s[-1]            # note: check for underflow done in Z() in section 9.4.2
  mu.s[-1] = mu.s[-1*n]     # note: check for underflow done in Z() in section 9.4.2
  mu.s[-1*n] = tmp
  return sigma,mu,A,I

def LOGn(sigma,mu,A,I):
  pass

addmodmontcount = 0
submodmontcount = 0
mulmodmontcount = 0
def MODMONT_common(mu, A, I):

  #print("I.b[mu.pc:mu.pc+11]",I.b[mu.pc:mu.pc+11].hex())
  if I.b[mu.pc+1] != 0x65:
    print("ERROR in MODMONT_common")
    return [None]*3     # halting exception
  immediate = I.b[mu.pc+2:mu.pc+8]
  n = mu.mc[0]

  out_offset = int.from_bytes(immediate[0:2],'little')
  x_offset = int.from_bytes(immediate[2:4],'little')
  y_offset = int.from_bytes(immediate[4:6],'little')

  # extend memory if necessary
  mu_iprev = mu.i
  max_word_current = -1*((-1*(max(out_offset,x_offset,y_offset)+n))//32)
  mu.i = max(mu.i,max_word_current)
  if mu_iprev<mu.i:
    print("*MODMONT memory expansion gas used",C_memory(mu.i)-C_memory(mu_iprev))
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))

  x = int.from_bytes(mu.m[x_offset:x_offset+n],'little')
  y = int.from_bytes(mu.m[y_offset:y_offset+n],'little')
  return out_offset,x,y


def ADDMODMONT(sigma,mu,A,I):
  global addmodmontcount
  addmodmontcount+=1

  bytelength = mu.mc[0]
  mod = mu.mc[1]
  inv = mu.mc[2]

  out_offset,x,y = MODMONT_common(mu, A, I)
  if out_offset==None:
    return {}, mu, A, I     # halting exception
  out = x + y
  if out > mod:
    out -= mod

  #print("ADDMODMONT",out_offset,hex(out),hex(x),hex(y),hex(mod))
  mu.m[out_offset:out_offset+bytelength] = out.to_bytes(bytelength, 'little')
  return sigma,mu,A,I


def SUBMODMONT(sigma,mu,A,I):
  global submodmontcount
  submodmontcount+=1

  bytelength = mu.mc[0]
  mod = mu.mc[1]

  out_offset,x,y = MODMONT_common(mu, A, I)
  if out_offset==None:
    return {}, mu, A, I     # halting exception
  out = x - y
  if out < 0:
    out += mod

  #print("SUBMODMONT",out_offset,hex(out),hex(x),hex(y),hex(mod))
  mu.m[out_offset:out_offset+bytelength] = out.to_bytes(bytelength, 'little')
  return sigma,mu,A,I


def MULMODMONT(sigma,mu,A,I):
  global mulmodmontcount
  mulmodmontcount+=1

  bytelength = mu.mc[0]
  mod = mu.mc[1]
  Nprime = mu.mc[2]
  R = 2**(bytelength*8)

  out_offset,x,y = MODMONT_common(mu, A, I)
  if out_offset==None:
    return {}, mu, A, I     # halting exception

  T = x*y
  m = ((T%R)*Nprime)%R
  t = (T + m*mod) // R
  if t>=mod:
    t-=mod

  out = t

  #print("MULMODMONT",out_offset,hex(out),hex(x),hex(y),hex(mod),hex(Nprime))
  mu.m[out_offset:out_offset+bytelength] = out.to_bytes(bytelength, 'little')
  return sigma,mu,A,I

def SETMOD(sigma,mu,A,I):
  mus0 = mu.s.pop()     # memory offset
  mus1 = mu.s.pop()     # length
  # update memory if overflow
  mu_iprev = mu.i
  mu.i = M_(mu.i,mus0,mus1)
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  # for now, setmod costs 139 gas for 384-bits, based on benchmarks
  mu.g = mu.g - 139
  mod = int.from_bytes(mu.m[mus0:mus0+mus1],'little')
  base = 2**(mus1*8)
  x=1
  x_prev=0
  while x != x_prev:
    # n iters for base 2^n, eg 5 iters for 32-bit, 8 iters for 256-bit
    x_prev=x
    x = (x*(2+x*mod))%base
  # set the modulus context in the machine state
  mu.mc[0]=mus1
  mu.mc[1]=mod
  mu.mc[2]=x
  return sigma,mu,A,I

def CREATE(sigma,mu,A,I):
  pass

def CALL(sigma,mu,A,I):
  pass

def CALLCODE(sigma,mu,A,I,opcode):
  pass

def RETURN(sigma,mu,A,I):
  mus0 = mu.s.pop()     # memory offset
  mus1 = mu.s.pop()     # length
  # update memory if overflow
  mu_iprev = mu.i
  mu.i = M_(mu.i,mus0,mus1)
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  def H_RETURN(mu):
    return mu.m[mus0:mus0+mus1]
  mu.o = H_RETURN(mu)   # set mu.o here, since H() is called before RETURN opcode is executed
  return sigma,mu,A,I

# not in frontier
def REVERT(sigma,mu,A,I):
  mus0 = mu.s.pop()     # memory offset
  mus1 = mu.s.pop()     # length
  # update memory if overflow
  mu_iprev = mu.i
  mu.i = M_(mu.i,mus0,mus1)
  if mu_iprev<mu.i:
    mu.g = mu.g - (C_memory(mu.i)-C_memory(mu_iprev))
    if mu.g<0:
      return {}, mu, A, I     # halting exception
    mu.m.extend(bytes((mu.i-mu_iprev)*32))
  mu.o = mu.m[mus0:mus0+mus1]   # H_RETURN(mu) in yellowpaper
  return sigma,mu,A,I

# not in frontier
def INVALID(sigma,mu,A,I):
  return sigma,mu,A,I


def SELFDESTRUCT(sigma,mu,A,I):
  mus0 = mu.s.pop()     # address that gets remaining balance
  r = (mus0%2**160).to_bytes(20,'big')

  if I.a not in A.s:
    A.r += R["selfdestruct"]   # in a later fork, this is done in function Upsilon

  A.s = A.s.union(I.a)

  if r in sigma:
    sigma[r] = Account(sigma[r].n, sigma[r].b+sigma[I.a].b, sigma[r].s, sigma[r].c, b'', StateTree(), r)
  else:
    sigma[r] = Account(0, sigma[I.a].b, TRIE({}), KEC(b''), b'', StateTree(), r)

  print("SELFDESTRUCT", I.a.hex())
  del sigma[I.a]
  #sigma[I.a].b = 0

  return sigma,mu,A,I
  


EVM_opcodes = {
  0x00:{"mnemonic":'STOP',           'delta':0, 'alpha':0, 'description':STOP},
  0x01:{"mnemonic":'ADD',            'delta':2, 'alpha':1, 'description':ADD},
  0x02:{"mnemonic":'MUL',            'delta':2, 'alpha':1, 'description':MUL},
  0x03:{"mnemonic":'SUB',            'delta':2, 'alpha':1, 'description':SUB},
  0x04:{"mnemonic":'DIV',            'delta':2, 'alpha':1, 'description':DIV},
  0x05:{"mnemonic":'SDIV',           'delta':2, 'alpha':1, 'description':SDIV},
  0x06:{"mnemonic":'MOD',            'delta':2, 'alpha':1, 'description':MOD},
  0x07:{"mnemonic":'SMOD',           'delta':2, 'alpha':1, 'description':SMOD},
  0x08:{"mnemonic":'ADDMOD',         'delta':3, 'alpha':1, 'description':ADDMOD},
  0x09:{"mnemonic":'MULMOD',         'delta':3, 'alpha':1, 'description':MULMOD},
  0x0a:{"mnemonic":'EXP',            'delta':2, 'alpha':1, 'description':EXP},
  0x0b:{"mnemonic":'SIGNEXTEND',     'delta':2, 'alpha':1, 'description':SIGNEXTEND},
  0x10:{"mnemonic":'LT',             'delta':2, 'alpha':1, 'description':LT},
  0x11:{"mnemonic":'GT',             'delta':2, 'alpha':1, 'description':GT},
  0x12:{"mnemonic":'SLT',            'delta':2, 'alpha':1, 'description':SLT},
  0x13:{"mnemonic":'SGT',            'delta':2, 'alpha':1, 'description':SGT},
  0x14:{"mnemonic":'EQ',             'delta':2, 'alpha':1, 'description':EQ},
  0x15:{"mnemonic":'ISZERO',         'delta':1, 'alpha':1, 'description':ISZERO},
  0x16:{"mnemonic":'AND',            'delta':2, 'alpha':1, 'description':AND},
  0x17:{"mnemonic":'OR',             'delta':2, 'alpha':1, 'description':OR},
  0x18:{"mnemonic":'XOR',            'delta':2, 'alpha':1, 'description':XOR},
  0x19:{"mnemonic":'NOT',            'delta':1, 'alpha':1, 'description':NOT},
  0x1a:{"mnemonic":'BYTE',           'delta':2, 'alpha':1, 'description':BYTE},
  0x1c:{"mnemonic":'SHR',            'delta':2, 'alpha':1, 'description':SHR},		# note: this isn't in homestead
  0x20:{"mnemonic":'SHA3',           'delta':2, 'alpha':1, 'description':SHA3},
  0x30:{"mnemonic":'ADDRESS',        'delta':0, 'alpha':1, 'description':ADDRESS},
  0x31:{"mnemonic":'BALANCE',        'delta':1, 'alpha':1, 'description':BALANCE},
  0x32:{"mnemonic":'ORIGIN',         'delta':0, 'alpha':1, 'description':ORIGIN},
  0x33:{"mnemonic":'CALLER',         'delta':0, 'alpha':1, 'description':CALLER},
  0x34:{"mnemonic":'CALLVALUE',      'delta':0, 'alpha':1, 'description':CALLVALUE},
  0x35:{"mnemonic":'CALLDATALOAD',   'delta':1, 'alpha':1, 'description':CALLDATALOAD},
  0x36:{"mnemonic":'CALLDATASIZE',   'delta':0, 'alpha':1, 'description':CALLDATASIZE},
  0x37:{"mnemonic":'CALLDATACOPY',   'delta':3, 'alpha':0, 'description':CALLDATACOPY},
  0x38:{"mnemonic":'CODESIZE',       'delta':0, 'alpha':1, 'description':CODESIZE},
  0x39:{"mnemonic":'CODECOPY',       'delta':3, 'alpha':0, 'description':CODECOPY},
  0x3a:{"mnemonic":'GASPRICE',       'delta':0, 'alpha':1, 'description':GASPRICE},
  0x3b:{"mnemonic":'EXTCODESIZE',    'delta':1, 'alpha':1, 'description':EXTCODESIZE},
  0x3c:{"mnemonic":'EXTCODECOPY',    'delta':4, 'alpha':0, 'description':EXTCODECOPY},
  0x3d:{"mnemonic":'RETURNDATASIZE', 'delta':0, 'alpha':1, 'description':RETURNDATASIZE},
  0x3e:{"mnemonic":'RETURNDATACOPY', 'delta':3, 'alpha':0, 'description':RETURNDATACOPY},
  0x40:{"mnemonic":'BLOCKHASH',      'delta':1, 'alpha':1, 'description':BLOCKHASH},
  0x41:{"mnemonic":'COINBASE',       'delta':0, 'alpha':1, 'description':COINBASE},
  0x42:{"mnemonic":'TIMESTAMP',      'delta':0, 'alpha':1, 'description':TIMESTAMP},
  0x43:{"mnemonic":'NUMBER',         'delta':0, 'alpha':1, 'description':NUMBER},
  0x44:{"mnemonic":'DIFFICULTY',     'delta':0, 'alpha':1, 'description':DIFFICULTY},
  0x45:{"mnemonic":'GASLIMIT',       'delta':0, 'alpha':1, 'description':GASLIMIT},
  0x50:{"mnemonic":'POP',            'delta':1, 'alpha':0, 'description':POP},
  0x51:{"mnemonic":'MLOAD',          'delta':1, 'alpha':1, 'description':MLOAD},
  0x52:{"mnemonic":'MSTORE',         'delta':2, 'alpha':0, 'description':MSTORE},
  0x53:{"mnemonic":'MSTORE8',        'delta':2, 'alpha':0, 'description':MSTORE8},
  0x54:{"mnemonic":'SLOAD',          'delta':1, 'alpha':1, 'description':SLOAD},
  0x55:{"mnemonic":'SSTORE',         'delta':2, 'alpha':0, 'description':SSTORE},
  0x56:{"mnemonic":'JUMP',           'delta':1, 'alpha':0, 'description':JUMP},
  0x57:{"mnemonic":'JUMPI',          'delta':2, 'alpha':0, 'description':JUMPI},
  0x58:{"mnemonic":'PC',             'delta':0, 'alpha':1, 'description':PC},
  0x59:{"mnemonic":'MSIZE',          'delta':0, 'alpha':1, 'description':MSIZE},
  0x5a:{"mnemonic":'GAS',            'delta':0, 'alpha':1, 'description':GAS},
  0x5b:{"mnemonic":'JUMPDEST',       'delta':0, 'alpha':0, 'description':JUMPDEST},
  0x5c:{"mnemonic":'MCOPY',          'delta':3, 'alpha':0, 'description':MCOPY},
  0x60:{"mnemonic":'PUSH1',          'delta':0, 'alpha':1, 'description':PUSHn},
  0x61:{"mnemonic":'PUSH2',          'delta':0, 'alpha':1, 'description':PUSHn},
  0x62:{"mnemonic":'PUSH3',          'delta':0, 'alpha':1, 'description':PUSHn},
  0x63:{"mnemonic":'PUSH4',          'delta':0, 'alpha':1, 'description':PUSHn},
  0x64:{"mnemonic":'PUSH5',          'delta':0, 'alpha':1, 'description':PUSHn},
  0x65:{"mnemonic":'PUSH6',          'delta':0, 'alpha':1, 'description':PUSHn},
  0x66:{"mnemonic":'PUSH7',          'delta':0, 'alpha':1, 'description':PUSHn},
  0x67:{"mnemonic":'PUSH8',          'delta':0, 'alpha':1, 'description':PUSHn},
  0x68:{"mnemonic":'PUSH9',          'delta':0, 'alpha':1, 'description':PUSHn},
  0x69:{"mnemonic":'PUSH10',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x6a:{"mnemonic":'PUSH11',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x6b:{"mnemonic":'PUSH12',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x6c:{"mnemonic":'PUSH13',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x6d:{"mnemonic":'PUSH14',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x6e:{"mnemonic":'PUSH15',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x6f:{"mnemonic":'PUSH16',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x70:{"mnemonic":'PUSH17',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x71:{"mnemonic":'PUSH18',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x72:{"mnemonic":'PUSH19',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x73:{"mnemonic":'PUSH20',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x74:{"mnemonic":'PUSH21',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x75:{"mnemonic":'PUSH22',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x76:{"mnemonic":'PUSH23',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x77:{"mnemonic":'PUSH24',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x78:{"mnemonic":'PUSH25',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x79:{"mnemonic":'PUSH26',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x7a:{"mnemonic":'PUSH27',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x7b:{"mnemonic":'PUSH28',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x7c:{"mnemonic":'PUSH29',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x7d:{"mnemonic":'PUSH30',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x7e:{"mnemonic":'PUSH31',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x7f:{"mnemonic":'PUSH32',         'delta':0, 'alpha':1, 'description':PUSHn},
  0x80:{"mnemonic":'DUP1',           'delta':1, 'alpha':2, 'description':DUPn},
  0x81:{"mnemonic":'DUP2',           'delta':2, 'alpha':3, 'description':DUPn},
  0x82:{"mnemonic":'DUP3',           'delta':3, 'alpha':4, 'description':DUPn},
  0x83:{"mnemonic":'DUP4',           'delta':4, 'alpha':5, 'description':DUPn},
  0x84:{"mnemonic":'DUP5',           'delta':5, 'alpha':6, 'description':DUPn},
  0x85:{"mnemonic":'DUP6',           'delta':6, 'alpha':7, 'description':DUPn},
  0x86:{"mnemonic":'DUP7',           'delta':7, 'alpha':8, 'description':DUPn},
  0x87:{"mnemonic":'DUP8',           'delta':8, 'alpha':9, 'description':DUPn},
  0x88:{"mnemonic":'DUP9',           'delta':9, 'alpha':10, 'description':DUPn},
  0x89:{"mnemonic":'DUP10',          'delta':10, 'alpha':11, 'description':DUPn},
  0x8a:{"mnemonic":'DUP11',          'delta':11, 'alpha':12, 'description':DUPn},
  0x8b:{"mnemonic":'DUP12',          'delta':12, 'alpha':13, 'description':DUPn},
  0x8c:{"mnemonic":'DUP13',          'delta':13, 'alpha':14, 'description':DUPn},
  0x8d:{"mnemonic":'DUP14',          'delta':14, 'alpha':15, 'description':DUPn},
  0x8e:{"mnemonic":'DUP15',          'delta':15, 'alpha':16, 'description':DUPn},
  0x8f:{"mnemonic":'DUP16',          'delta':16, 'alpha':17, 'description':DUPn},
  0x90:{"mnemonic":'SWAP1',          'delta':2, 'alpha':2, 'description':SWAPn},
  0x91:{"mnemonic":'SWAP2',          'delta':3, 'alpha':3, 'description':SWAPn},
  0x92:{"mnemonic":'SWAP3',          'delta':4, 'alpha':4, 'description':SWAPn},
  0x93:{"mnemonic":'SWAP4',          'delta':5, 'alpha':5, 'description':SWAPn},
  0x94:{"mnemonic":'SWAP5',          'delta':6, 'alpha':6, 'description':SWAPn},
  0x95:{"mnemonic":'SWAP6',          'delta':7, 'alpha':7, 'description':SWAPn},
  0x96:{"mnemonic":'SWAP7',          'delta':8, 'alpha':8, 'description':SWAPn},
  0x97:{"mnemonic":'SWAP8',          'delta':9, 'alpha':9, 'description':SWAPn},
  0x98:{"mnemonic":'SWAP9',          'delta':10, 'alpha':10, 'description':SWAPn},
  0x99:{"mnemonic":'SWAP10',         'delta':11, 'alpha':11, 'description':SWAPn},
  0x9a:{"mnemonic":'SWAP11',         'delta':12, 'alpha':12, 'description':SWAPn},
  0x9b:{"mnemonic":'SWAP12',         'delta':13, 'alpha':13, 'description':SWAPn},
  0x9c:{"mnemonic":'SWAP13',         'delta':14, 'alpha':14, 'description':SWAPn},
  0x9d:{"mnemonic":'SWAP14',         'delta':15, 'alpha':15, 'description':SWAPn},
  0x9e:{"mnemonic":'SWAP15',         'delta':16, 'alpha':16, 'description':SWAPn},
  0x9f:{"mnemonic":'SWAP16',         'delta':17, 'alpha':17, 'description':SWAPn},
  0xa0:{"mnemonic":'LOG0',           'delta':2, 'alpha':0, 'description':LOGn},
  0xa1:{"mnemonic":'LOG1',           'delta':3, 'alpha':0, 'description':LOGn},
  0xa2:{"mnemonic":'LOG2',           'delta':4, 'alpha':0, 'description':LOGn},
  0xa3:{"mnemonic":'LOG3',           'delta':5, 'alpha':0, 'description':LOGn},
  0xa4:{"mnemonic":'LOG4',           'delta':6, 'alpha':0, 'description':LOGn},
  0xc0:{"mnemonic":'ADDMODMONT',     'delta':0, 'alpha':0, 'description':ADDMODMONT},
  0xc1:{"mnemonic":'SUBMODMONT',     'delta':0, 'alpha':0, 'description':SUBMODMONT},
  0xc2:{"mnemonic":'MULMODMONT',     'delta':0, 'alpha':0, 'description':MULMODMONT},
  0xc3:{"mnemonic":'SETMOD',         'delta':2, 'alpha':0, 'description':SETMOD},
  0xf0:{"mnemonic":'CREATE',         'delta':3, 'alpha':1, 'description':CREATE},
  0xf1:{"mnemonic":'CALL',           'delta':7, 'alpha':1, 'description':CALL},
  0xf2:{"mnemonic":'CALLCODE',       'delta':7, 'alpha':1, 'description':CALLCODE},
  0xf3:{"mnemonic":'RETURN',         'delta':2, 'alpha':0, 'description':RETURN},
  #0xfd:{"mnemonic":'REVERT',         'delta':2, 'alpha':0, 'description':REVERT},
  #0xfe:{"mnemonic":'INVALID',        'delta':0, 'alpha':0, 'description':INVALID},
  0xff:{"mnemonic":'SELFDESTRUCT',   'delta':1, 'alpha':0, 'description':SELFDESTRUCT},
}







def exec_evm(bytecode,calldata):

  # transaction info
  caller = bytes.fromhex("00"*20)
  origin = bytes.fromhex("00"*20)
  to = bytes.fromhex("00"*20)
  gasPrice = 1
  gasLimit = 10000000
  value = 0
  header = None

  I = ExecutionEnvironment(to,          # code owner's address
                           origin,      # original sender address
                           gasPrice,    # gas price of orig tx
                           calldata,    # input data
                           caller,      # address which caused this execution
                           value,       # wei
                           bytecode,    # bytecode being executed
                           header,      # block header, or at least what is needed for opcodes BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT
                           0,           # depth of calls and creations
                           True,        # permission to modify state, not in Frontier
                           {})          # dictionary of recent 256 blocks for BLOCKHASH

  prestate = {}
  t = (caller,to) # this is not in frontier, also not in each call to Xi* below
  state, g, A, o_ = Xi(prestate,gasLimit,I,t)
  return o_, gasLimit-g




if __name__ == "__main__":

  f = open(sys.argv[1],'r')
  bytecode = bytes.fromhex(f.read().strip().strip('0x'))
  f.close()
  calldata = bytes.fromhex(sys.argv[2].strip('0x'))
  returndata_expected = bytes.fromhex(sys.argv[3].strip('0x'))
  returndata,gasUsed = exec_evm(bytecode,calldata)
  if returndata!=returndata_expected:
    print("RETURN DATA DOES NOT MATCH")
  else:
    print("CORRECT")
  if 1:
    #print("return data:",returndata.hex())
    print("addmodmontcount",addmodmontcount)
    print("submodmontcount",submodmontcount)
    print("mulmodmontcount",mulmodmontcount)
    print("gas used:",gasUsed)


