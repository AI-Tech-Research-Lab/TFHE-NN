import numpy as np
# from Pyfhel import Pyfhel
import torch
from pycrcnn.he.tfhe_value import TFHEValue
import nufhe

import tempfile

tmp_dir = tempfile.TemporaryDirectory()


class HE:
    def generate_keys(self):
        pass

    def generate_relin_keys(self):
        pass

    def get_public_key(self):
        pass

    def get_relin_key(self):
        pass

    def load_public_key(self, key):
        pass

    def load_relin_key(self, key):
        pass

    def get_zero(self, x):
        pass

    def encode_matrix(self, matrix):
        """Encode a matrix in a plaintext HE nD-matrix.

        Parameters
        ----------
        matrix : nD-np.array( dtype=float )
            matrix to be encoded

        Returns
        -------
        matrix
            nD-np.array with encoded values
        """
        pass

    def decode_matrix(self, matrix):
        pass

    def encrypt_matrix(self, matrix):
        pass

    def decrypt_matrix(self, matrix):
        pass

    def encode_number(self, number):
        pass

    def power(self, number, exp):
        pass

    def noise_budget(self, ciphertext):
        pass


# class BFVPyfhel(HE):
#     def __init__(self, m, p, sec=128, int_digits=64, frac_digits=32):
#         self.he = Pyfhel()
#         self.he.contextGen(p, m=m, sec=sec, fracDigits=frac_digits,
#                            intDigits=int_digits)

#     def generate_keys(self):
#         self.he.keyGen()

#     def generate_relin_keys(self, bitCount=60, size=3):
#         self.he.relinKeyGen(bitCount, size)

#     def get_public_key(self):
#         self.he.savepublicKey(tmp_dir.name + "/pub.key")
#         with open(tmp_dir.name + "/pub.key", 'rb') as f:
#             return f.read()

#     def get_relin_key(self):
#         self.he.saverelinKey(tmp_dir.name + "/relin.key")
#         with open(tmp_dir.name + "/relin.key", 'rb') as f:
#             return f.read()

#     def load_public_key(self, key):
#         with open(tmp_dir.name + "/pub.key", 'wb') as f:
#             f.write(key)
#         self.he.restorepublicKey(tmp_dir.name + "/pub.key")

#     def load_relin_key(self, key):
#         with open(tmp_dir.name + "/relin.key", 'wb') as f:
#             f.write(key)
#         self.he.restorerelinKey(tmp_dir.name + "/relin.key")

#     def get_zero(self, x):
#         return x - x

#     def encode_matrix(self, matrix):
#         """Encode a float nD-matrix in a PyPtxt nD-matrix.

#         Parameters
#         ----------
#         matrix : nD-np.array( dtype=float )
#             matrix to be encoded

#         Returns
#         -------
#         matrix
#             nD-np.array( dtype=PyPtxt ) with encoded values
#         """

#         try:
#             return np.array(list(map(self.he.encodeFrac, matrix)))
#         except TypeError:
#             return np.array([self.encode_matrix(m) for m in matrix])

#     def decode_matrix(self, matrix):
#         """Decode a PyPtxt nD-matrix in a float nD-matrix.

#         Parameters
#         ----------
#         matrix : nD-np.array( dtype=PyPtxt )
#             matrix to be decoded

#         Returns
#         -------
#         matrix
#             nD-np.array( dtype=float ) with float values
#         """
#         try:
#             return np.array(list(map(self.he.decodeFrac, matrix)))
#         except TypeError:
#             return np.array([self.decode_matrix(m) for m in matrix])

#     def encrypt_matrix(self, matrix):
#         """Encrypt a float nD-matrix in a PyCtxt nD-matrix.

#         Parameters
#         ----------
#         matrix : nD-np.array( dtype=float )
#             matrix to be encrypted

#         Returns
#         -------
#         matrix
#             nD-np.array( dtype=PyCtxt ) with encrypted values
#         """
#         try:
#             return np.array(list(map(self.he.encryptFrac, matrix)))
#         except TypeError:
#             return np.array([self.encrypt_matrix(m) for m in matrix])

#     def decrypt_matrix(self, matrix):
#         """Decrypt a PyCtxt nD matrix in a float nD matrix.

#         Parameters
#         ----------
#         matrix : nD-np.array( dtype=PyCtxt )
#             matrix to be decrypted

#         Returns
#         -------
#         matrix
#             nD-np.array( dtype=float ) with plain values
#         """
#         try:
#             return np.array(list(map(self.he.decryptFrac, matrix)))
#         except TypeError:
#             return np.array([self.decrypt_matrix(m) for m in matrix])

#     def encode_number(self, number):
#         return self.he.encode(number)

#     def power(self, number, exp):
#         return self.he.power(number, exp)

#     def noise_budget(self, ciphertext):
#         try:
#             return self.he.noiseLevel(ciphertext)
#         except SystemError:
#             return "Can't get NB without secret key."


class TFHEnuFHE:
    """
    Object that manages the TFHE cryptography scheme.

    :param int n_bits: The number of bits used during the encrypted computations.
    """

    def __init__(self, n_bits: int):
        self.ctx = nufhe.Context()
        self.n_bits = n_bits

    def generate_keys(self):
        """
        Generates the secret and cloud keys of the TFHE cryptography scheme.
        """
        fft = nufhe.NuFHEParameters(transform_type='FFT')
        self.secret_key, self.cloud_key = self.ctx.make_key_pair()

    def generate_vm(self, cloud_key: nufhe.NuFHECloudKey):
        """
        Generates the virtual machine capable of executing gates on ciphertexts.

        :param NuFHECloudKey cloud_key: The cloud_key generated by the client.
        """
        fft = nufhe.NuFHEParameters(transform_type='FFT')
        # param = nufhe.PerformanceParameters(fft)  # 1. Ottimizzazioni disattivate (solo fft)

        # param = nufhe.PerformanceParameters(fft, ntt_base_method='cuda_asm', ntt_mul_method='cuda_asm', ntt_lsh_method='cuda_asm', 
        #                                     use_constant_memory_multi_iter=True,
        #                                     use_constant_memory_single_iter=True,
        #                                     transforms_per_block=4)

        # Ottimizzazioni di Luca
        param = nufhe.PerformanceParameters(fft, ntt_base_method='cuda_asm', ntt_mul_method='cuda_asm', ntt_lsh_method='cuda_asm', 
                                            use_constant_memory_multi_iter=True,
                                            use_constant_memory_single_iter=True,
                                            transforms_per_block=8, 
                                            single_kernel_bootstrap=True)

        self.vm = self.ctx.make_virtual_machine(cloud_key, perf_params=param)

    def get_zero(self, x):
        return self.encode(0)

    def compute_uint(self, binary: list):
        """
        Compute the unsigned integer value from the binary list.

        :returns: The unsigned integer value.
        """

        uint = 0
        for i in range(len(binary)-1, -1, -1):
            if binary[i][0]:
                uint += 2**(len(binary)-1 - i)
        
        return uint
    
    def compute_int(self, binary: list):
        """
        Compute the integer value from the 2's complement representation.

        :returns: The signed integer value.
        """
        uint = self.compute_uint(binary)
        if (uint & (1 << (len(binary) - 1))) != 0:
            uint = uint - (1 << len(binary))

        return uint
    
    def encode(self, number: int):
        """
        Encode an integer number in a TFHEValue using the 2's complement representation.

        :returns: TFHEValue containing the encoded number.
        """

        bin_num = [[int(x)] for x in np.binary_repr(number, self.n_bits)]
        return TFHEValue(self.vm.gate_constant(bin_num), self.vm, self.n_bits)
    
    def encrypt(self, number: int) -> TFHEValue:
        """
        Encrypt an integer number in a TFHEValue using the 2's complement representation.

        :returns: TFHEValue containing the LweSampleArray that represents the encrypted number.
        """

        bin_num = [[int(x)] for x in np.binary_repr(number, self.n_bits)]
        return TFHEValue(self.ctx.encrypt(self.secret_key, bin_num), self.vm, self.n_bits)
    
    def decrypt(self, TFHE_value: TFHEValue) -> int:
        """
        Decrypt a TFHEValue containing the LweSampleArray in an integer value.

        :returns: The decrypted integer value.
        """

        return self.compute_int(self.ctx.decrypt(self.secret_key, TFHE_value.value))

    def encode_matrix(self, matrix) -> TFHEValue:
        """
        Encode an int nD-matrix in a TFHEValue nD-matrix.

        Parameters
        ----------
        matrix : nD-np.array( dtype=int )
            matrix to be encoded

        Returns
        -------
        matrix
            nD-np.array( dtype=TFHEValue ) with encoded values
        """

        try:
            return np.array(list(map(self.encode, matrix)))
        except TypeError:
            return np.array([self.encode_matrix(m) for m in matrix])

    def encrypt_matrix(self, matrix) -> TFHEValue:
        """
        Encrypt an int nD-matrix in a TFHEValue nD-matrix.

        Parameters
        ----------
        matrix : nD-np.array( dtype=int )
            matrix to be encrypted

        Returns
        -------
        matrix
            nD-np.array( dtype=TFHEValue ) with encrypted values
        """
        try:
            return np.array(list(map(self.encrypt, matrix)))
        except TypeError:
            return np.array([self.encrypt_matrix(m) for m in matrix])

    def decrypt_matrix(self, matrix):
        """
        Decrypt a TFHEValue nD matrix in an int nD matrix.

        Parameters
        ----------
        matrix : nD-np.array( dtype=TFHEValue )
            matrix to be decrypted

        Returns
        -------
        matrix
            nD-np.array( dtype=int ) with plain values
        """
        try:
            return np.array(list(map(self.decrypt, matrix)))
        except (TypeError, AttributeError):
            return np.array([self.decrypt_matrix(m) for m in matrix])

    def serialize(self, TFHE_value: TFHEValue):
        """
        Serialize the LweSampleArray wrapped inside the TFHEValue into a bytestring.

        :returns: The serialized TFHEValue.
        """
        return TFHE_value.value.dumps()
    
    def serialize_matrix(self, matrix):
        """
        Serialize the LweSampleArray-s wrapped inside the TFHEValue-s of the matrix.

        :returns: The serialized matrix.
        """

        try:
            return np.array(list(map(self.serialize, matrix)))
        except (TypeError, AttributeError):
            return np.array([self.serialize_matrix(m) for m in matrix])
    
    def deserialize(self, bytestring):
        """
        Deserialize the LweSampleArray into a TFHEValue from the provided bytestring.

        :returns: The deserialized TFHEValue.
        """
        if not isinstance(bytestring, bytes):
          raise AttributeError()
        return TFHEValue(self.vm.load_ciphertext(bytestring), self.vm, self.n_bits)
    
    def deserialize_matrix(self, matrix):
        """
        Deserialize the LweSampleArray-s into the TFHEValue-s of the matrix.

        :returns: The deserialized matrix.
        """

        try:
            return np.array(list(map(self.deserialize, matrix)))
        except:
            return np.array([self.deserialize_matrix(m) for m in matrix])