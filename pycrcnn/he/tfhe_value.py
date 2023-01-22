from __future__ import annotations
import nufhe
import math
from pycrcnn.he.alu import *

class TFHEValue:
    """
    A class used to represent an encoded/encrypted TFHE value.
    
    :param LweSampleArray value: The encrypted/encoded value represented by the class.
    :param VirtualMachine vm: The virtual machine capable of executing gates on ciphertexts given by the nuFHE object.
    :param int n_bits: The number of bits used during the encrypted computations.
    """

    def __init__(self, value: nufhe.LweSampleArray, vm: nufhe.api_high_level.VirtualMachine, n_bits: int):
      self.value = value
      self.vm = vm
      self.n_bits = n_bits
    
    def __add__(self, tfhe_value2):
      if type(tfhe_value2) is not TFHEValue:
        if tfhe_value2 == 0:
          return TFHEValue(self.value, self.vm, self.n_bits)
        else:
          return TFHEValue(encrypted_add(self.vm, self.value, self.vm.gate_constant([[int(x)] for x in np.binary_repr(tfhe_value2, self.n_bits)]), self.n_bits), self.vm, self.n_bits)
      else:
        return TFHEValue(encrypted_add(self.vm, self.value, tfhe_value2.value, self.n_bits), self.vm, self.n_bits) 

    def __sub__(self, tfhe_value: TFHEValue):
      return TFHEValue(encrypted_sub(self.vm, self.value, tfhe_value.value, self.n_bits), self.vm, self.n_bits)
    
    def __mul__(self, encrypted_value2):
      if type(encrypted_value2) is TFHEValue:
        return TFHEValue(encrypted_mul(self.vm, self.value, encrypted_value2.value, self.n_bits), self.vm, self.n_bits)

      assert (abs(encrypted_value2) & (abs(encrypted_value2)-1) == 0)

      if encrypted_value2 == 0:
        return TFHEValue(self.vm.gate_constant([[0] for i in range(self.n_bits)]), self.vm, self.n_bits)
      elif encrypted_value2 > 0:
        if encrypted_value2 == 1:
          return TFHEValue(self.value, self.vm, self.n_bits)
        else:
          shift_amount = int(math.log2(encrypted_value2))
          return TFHEValue(left_shift(self.vm, self.value, shift_amount, self.n_bits), self.vm, self.n_bits)
      else:
        if encrypted_value2 == -1:
          return TFHEValue(twos_complement(self.vm, self.value, self.n_bits), self.vm, self.n_bits)
        else:
          shift_amount = int(math.log2(abs(encrypted_value2)))
          return TFHEValue(left_shift(self.vm, twos_complement(self.vm, self.value, self.n_bits), shift_amount, self.n_bits), self.vm, self.n_bits)

    def __truediv__(self, tfhe_value2):
      if type(tfhe_value2) is TFHEValue:
        return TFHEValue(encrypted_po2_div(self.vm, self.value, tfhe_value2.value, self.n_bits), self.vm, self.n_bits)

      assert (tfhe_value2 != 0 and abs(tfhe_value2) & (abs(tfhe_value2)-1) == 0) # power of 2 and not 0

      if tfhe_value2 > 0:
        if tfhe_value2 == 1:
          return TFHEValue(self.value, self.vm, self.n_bits)
        else:
          shift_amount = int(math.log2(tfhe_value2))
          return TFHEValue(right_shift(self.vm, self.value, shift_amount, self.n_bits), self.vm, self.n_bits)
      else:
        if tfhe_value2 == -1:
          return TFHEValue(twos_complement(self.vm, self.value, self.n_bits), self.vm, self.n_bits)
        else:
          shift_amount = int(math.log2(abs(tfhe_value2)))
          return TFHEValue(right_shift(self.vm, twos_complement(self.vm, self.value, self.n_bits), shift_amount, self.n_bits), self.vm, self.n_bits)
    
    def __mod__(self, tfhe_value2):
      if type(tfhe_value2) is not TFHEValue:
        assert (tfhe_value2 != 0 and abs(tfhe_value2) & (abs(tfhe_value2)-1) == 0) # power of 2 and not 0
        return TFHEValue(encrypted_po2_mod(self.vm, self.value, self.vm.gate_constant([[int(x)] for x in np.binary_repr(tfhe_value2, self.n_bits)]), self.n_bits), self.vm, self.n_bits)
      return TFHEValue(encrypted_po2_mod(self.vm, self.value, tfhe_value2.value, self.n_bits), self.vm, self.n_bits)

    def __lt__(self, tfhe_value2):
      if type(tfhe_value2) is not TFHEValue:
        return encrypted_lt(self.vm, self.value, self.vm.gate_constant([[int(x)] for x in np.binary_repr(tfhe_value2, self.n_bits)]), self.n_bits)
      return encrypted_lt(self.vm, self.value, tfhe_value2.value, self.n_bits)

    def __le__(self, tfhe_value2):
      if type(tfhe_value2) is not TFHEValue:
        return self.vm.gate_not(encrypted_gt(self.vm, self.value, self.vm.gate_constant([[int(x)] for x in np.binary_repr(tfhe_value2, self.n_bits)]), self.n_bits))
      return self.vm.gate_not(encrypted_gt(self.vm, self.value, tfhe_value2.value, self.n_bits))

    def __gt__(self, tfhe_value2):
      if type(tfhe_value2) is not TFHEValue:
        return encrypted_gt(self.vm, self.value, self.vm.gate_constant([[int(x)] for x in np.binary_repr(tfhe_value2, self.n_bits)]), self.n_bits)
      return encrypted_gt(self.vm, self.value, tfhe_value2.value, self.n_bits)

    def __ge__(self, tfhe_value2):
      if type(tfhe_value2) is not TFHEValue:
        return self.vm.gate_not(encrypted_lt(self.vm, self.value, self.vm.gate_constant([[int(x)] for x in np.binary_repr(tfhe_value2, self.n_bits)]), self.n_bits))
      return self.vm.gate_not(encrypted_lt(self.vm, self.value, tfhe_value2.value, self.n_bits))

    def __eq__(self, tfhe_value2):
      if type(tfhe_value2) is not TFHEValue:
        return encrypted_eq(self.vm, self.value, self.vm.gate_constant([[int(x)] for x in np.binary_repr(tfhe_value2, self.n_bits)]), self.n_bits)
      return encrypted_eq(self.vm, self.value, tfhe_value2.value, self.n_bits)
    
    def copy(self):
      return TFHEValue(self.value, self.vm, self.n_bits)