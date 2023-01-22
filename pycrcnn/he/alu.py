import nufhe
import numpy as np

def encrypted_add(vm: nufhe.api_high_level.VirtualMachine, op1: nufhe.LweSampleArray, op2: nufhe.LweSampleArray, n_bits: int, check_overflow = True) -> nufhe.LweSampleArray:
  """
  Homomorphic addition between 2 ciphertexts.
  If overflow occurs, it returns the max value.

  It builds the adder circuit with the TFHE logical gates:
  * sum_res_i = op1_i XOR op2_i XOR carry(i-1)
  * carry = (op1_i AND op2_i) XOR (carry(i-1) AND (op1_i XOR op2_i))
  
  :param VirtualMachine vm: The virtual machine capable of executing gates on ciphertexts given by the nuFHE object.
  :param LweSampleArray op1: The first operand of the addition.
  :param LweSampleArray op2: The second operand of the addition.
  :param int n_bits: The number of bits of the result.
  :param bool check_overflow (default = True): If the overflow check is active.

  :return: The encrypted addition result.
  """

  sum_res = vm.empty_ciphertext((n_bits, 1))
  carry = vm.gate_constant([0])
  max_pos = 2**(n_bits-1)-1
  min_neg = -2**(n_bits-1)

  for i in range(n_bits):
    # sum_res_i = op1_i XOR op2_i XOR carry(i-1)
    xor_res1 = vm.gate_xor(op1[n_bits-1-i], op2[n_bits-1-i])
    sum_res[n_bits-1-i] = vm.gate_xor(xor_res1, carry)

    # carry = (op1_i AND op2_i) XOR (carry(i-1) AND (op1_i XOR op2_i))
    and_res1 = vm.gate_and(op1[n_bits-1-i], op2[n_bits-1-i])
    and_res2 = vm.gate_and(carry, xor_res1)
    carry = vm.gate_xor(and_res1, and_res2)

    if i == n_bits-2:
      last_carry_in = carry
  
  if check_overflow:
    sum_res = vm.gate_mux(vm.gate_xor(carry, last_carry_in), 
                        vm.gate_mux(op1[0], vm.gate_constant([[int(x)] for x in np.binary_repr(min_neg, n_bits)]), vm.gate_constant([[int(x)] for x in np.binary_repr(max_pos, n_bits)])), 
                        sum_res)
  return sum_res

def encrypted_sub(vm: nufhe.api_high_level.VirtualMachine, op1: nufhe.LweSampleArray, op2: nufhe.LweSampleArray, n_bits: int, check_overflow: bool = True) -> nufhe.LweSampleArray:
  """
  Homomorphic subtraction between 2 ciphertexts.
  If overflow occurs, it returns the min/max value.

  It builds the subtractor circuit with the TFHE logical gates:
  * sub_res_i = op1_i XOR op2_i XOR borrow(i-1)
  * borrow = (NOT op1_i AND op2_i) OR (NOT op1_i AND borrow(i-1)) OR (op2_i AND borrow(i-1))
  
  :param VirtualMachine vm: The virtual machine capable of executing gates on ciphertexts given by the nuFHE object.
  :param LweSampleArray op1: The first operand of the subtraction.
  :param LweSampleArray op2: The second operand of the subtraction.
  :param int n_bits: The number of bits of the result.
  :param bool check_overflow (default = True): If the overflow check is active.

  :return: The encrypted subtraction result.
  """
  sub_res =  vm.empty_ciphertext((n_bits, 1))
  borrows = vm.empty_ciphertext((n_bits, 1))
  temp = vm.empty_ciphertext((2, 1))
  max_pos = 2**(n_bits-1)-1
  min_neg = -2**(n_bits-1)

  borrows[n_bits-1] = vm.gate_constant([0])

  for i in range(n_bits-1, -1, -1):
    temp[0] = vm.gate_xor(op1[i], op2[i])
    sub_res[i] = vm.gate_xor(temp[0], borrows[i])
    temp[1] = vm.gate_andny(op1[i], op2[i])
    temp[0] = vm.gate_andny(temp[0], borrows[i])
    borrows[i-1] = vm.gate_or(temp[1], temp[0])
      
  if check_overflow:
    sub_res = vm.gate_mux(vm.gate_xor(borrows[0], borrows[n_bits-1]), 
                        vm.gate_mux(op1[0], vm.gate_constant([[int(x)] for x in np.binary_repr(min_neg, n_bits)]), vm.gate_constant([[int(x)] for x in np.binary_repr(max_pos, n_bits)])), 
                        sub_res)
  return sub_res

def encrypted_mul(vm: nufhe.api_high_level.VirtualMachine, op1: nufhe.LweSampleArray, op2: nufhe.LweSampleArray, n_bits: int) -> nufhe.LweSampleArray:
  """
  Homomorphic multiplication between 2 ciphertexts.
  *Assumption*: The value of op1 must be of lenght <= n_bits/2

  It builds the multiplier circuit implementing the shift and add algorithm with the TFHE logical gates.
  
  :param VirtualMachine vm: The virtual machine capable of executing gates on ciphertexts given by the nuFHE object.
  :param LweSampleArray op1: The first operand of the multiplication.
  :param LweSampleArray op2: The second operand of the multiplication.
  :param int n_bits: The number of bits of the result.

  :returns: The encrypted multiplication result.
  """

  zeros = vm.gate_constant([[0] for i in range(n_bits)])
  mul_res = zeros
  abs_op1 = vm.gate_mux(op1[0], twos_complement(vm, op1, n_bits), op1)

  for i in range(n_bits//2, n_bits):
    mul_res = vm.gate_mux(abs_op1[i], encrypted_add(vm, mul_res, left_shift(vm, op2, n_bits-1-i, n_bits), n_bits, check_overflow=False), mul_res)

  mul_res = vm.gate_mux(op1[0], twos_complement(vm, mul_res, n_bits), mul_res)

  return mul_res

def encrypted_po2_div(vm: nufhe.api_high_level.VirtualMachine, op1: nufhe.LweSampleArray, op2: nufhe.LweSampleArray, n_bits: int) -> nufhe.LweSampleArray:
  """
  Homomorphic division between 2 ciphertexts.
  *Assumption*: Divider must be a power-of-2.

  It builds the power-of-2 divider circuit using the right shifts.
  
  :param VirtualMachine vm: The virtual machine capable of executing gates on ciphertexts given by the nuFHE object.
  :param LweSampleArray op1: The dividend.
  :param LweSampleArray op2: The p-o-2 divisor.
  :param int n_bits: The number of bits of the result.

  :returns: The encrypted division result.
  """

  div_res = op1
  abs_op2 = vm.gate_mux(op2[0], twos_complement(vm, op2, n_bits), op2)

  # From 1 because div by 1 will not cause any shift
  for i in range(1, n_bits//2):
    div_res = vm.gate_mux(abs_op2[n_bits-1-i], right_shift(vm, op1, i, n_bits), div_res)

  div_res = vm.gate_mux(op2[0], twos_complement(vm, div_res, n_bits), div_res)

  return div_res

def encrypted_po2_mod(vm: nufhe.api_high_level.VirtualMachine, op1: nufhe.LweSampleArray, op2: nufhe.LweSampleArray, n_bits: int) -> nufhe.LweSampleArray:
  """
  Homomorphic modulo between 2 ciphertexts.
  *Assumption*: Divider must be a power-of-2.

  It builds the power-of-2 modulo circuit using the AND gate.
  
  :param VirtualMachine vm: The virtual machine capable of executing gates on ciphertexts given by the nuFHE object.
  :param LweSampleArray op1: The dividend.
  :param LweSampleArray op2: The p-o-2 divisor.
  :param int n_bits: The number of bits of the result.

  :returns: The encrypted modulo result.
  """

  sub = encrypted_sub(vm, op2, vm.gate_constant([[int(x)] for x in np.binary_repr(1, n_bits)]), n_bits)
  mod_res = vm.gate_and(op1, sub)

  return mod_res

def twos_complement(vm: nufhe.api_high_level.VirtualMachine, op: nufhe.LweSampleArray, n_bits: int):
  b = vm.empty_ciphertext((n_bits, 1))
  res = vm.empty_ciphertext((n_bits, 1))

  b[n_bits-1] = vm.gate_constant([1])

  for i in range(n_bits-1, -1, -1):
    temp = vm.gate_not(op[i])
    res[i] = vm.gate_xor(temp, b[i])
    b[i-1] = vm.gate_and(temp, b[i])

  return res

def right_shift(vm, op, shift_amount, n_bits):
  assert(shift_amount<n_bits)

  shifted = vm.gate_copy(op)
  shifted.roll(shift_amount, axis=0)
  for i in range(shift_amount):
    shifted[i] = vm.gate_copy(op[0])
  
  return shifted

def left_shift(vm, op, shift_amount, n_bits):
  assert(shift_amount<n_bits)

  shifted = vm.gate_copy(op)
  shift_amount = -shift_amount
  shifted.roll(shift_amount, axis=0)
  for i in range(n_bits+shift_amount, n_bits):
    shifted[i] = vm.gate_constant([0])
  
  return shifted

def encrypted_eq(vm: nufhe.api_high_level.VirtualMachine, op1: nufhe.LweSampleArray, op2: nufhe.LweSampleArray, n_bits: int) -> nufhe.LweSampleArray:
  res = vm.gate_constant([0])
  temp = vm.gate_xor(op1, op2)

  for i in range(n_bits-1, -1, -1):
    res = vm.gate_or(res, temp[i])

  return vm.gate_not(res)

def encrypted_lt(vm: nufhe.api_high_level.VirtualMachine, op1: nufhe.LweSampleArray, op2: nufhe.LweSampleArray, n_bits: int) -> nufhe.LweSampleArray:
  res = vm.gate_constant([0])
  temp = vm.gate_xnor(op1, op2)

  for i in range(n_bits-1, -1, -1):
    res = vm.gate_mux(temp[i], res, op2[i])

  res = vm.gate_mux(vm.gate_not(temp[0]), vm.gate_not(res), res)

  return res

def encrypted_gt(vm: nufhe.api_high_level.VirtualMachine, op1: nufhe.LweSampleArray, op2: nufhe.LweSampleArray, n_bits: int) -> nufhe.LweSampleArray:
  res = vm.gate_constant([0])
  temp = vm.gate_xnor(op1, op2)

  for i in range(n_bits-1, -1, -1):
    res = vm.gate_mux(temp[i], res, op1[i])

  res = vm.gate_mux(vm.gate_not(temp[0]), vm.gate_not(res), res)

  return res

def encrypted_max(array):
  max = array[0].copy()
  vm = array[0].vm

  for i in range(1, len(array)):
    max.value = vm.gate_mux(max < array[i], array[i].value, max.value)

  return max

def encrypted_argmax(array):
  vm, n_bits = array[0].vm, array[0].n_bits
  argmax, max = array[0].copy(), array[0].copy()
  argmax.value = vm.gate_constant([[int(x)] for x in np.binary_repr(0, n_bits)])

  for i in range(1, len(array)):
    argmax.value = vm.gate_mux(max < array[i], vm.gate_constant([[int(x)] for x in np.binary_repr(i, n_bits)]), argmax.value)
    max.value = vm.gate_mux(max < array[i], array[i].value, max.value)

  return argmax

def encrypted_mux(condition, op1, op2):
  res, vm = op1.copy(), op1.vm
  res.value = vm.gate_mux(condition, op1.value, op2.value)
  return res
    
def encrypted_mux_matrix(condition, matrix1, matrix2):
  try:
      return np.array(list(map(lambda x,y: encrypted_mux(condition,x,y), matrix1, matrix2)))
  except (TypeError, AttributeError):
      return np.array([encrypted_mux_matrix(condition, matrix1[i], matrix2[i]) for i in range(len(matrix1))])

def encrypted_round(w_len, div, res):
  vm, n_bits = div.vm, div.n_bits

  div.value = vm.gate_mux(div > 0, 
      vm.gate_mux(res > w_len//2, 
        encrypted_add(vm, div.value, vm.gate_constant([[int(x)] for x in np.binary_repr(1, n_bits)]), n_bits, check_overflow=True),
        div.value), 
      vm.gate_mux(
        vm.gate_and(res <= w_len//2, res > 0),
        encrypted_add(vm, div.value, vm.gate_constant([[int(x)] for x in np.binary_repr(1, n_bits)]), n_bits, check_overflow=True),
        div.value)
    )
  return div

def encrypted_round_matrix(w_len, div, res):
  try:
    return np.array(list(map(lambda x,y: encrypted_round(w_len, x, y), div, res)))
  except (TypeError, AttributeError):
    return np.array([encrypted_round_matrix(w_len, div[i], res[i]) for i in range(len(div))])

def encrypted_mean_matrix(array):
  w_len = len(array)
  div = np.sum(array, axis=0)/w_len
  res = np.sum(array, axis=0)%w_len

  return encrypted_round_matrix(w_len, div, res)

