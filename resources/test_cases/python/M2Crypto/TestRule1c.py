from M2Crypto.EVP import Cipher


class TestRule1c:
    def __init__(self):
        self.g_encrypt = 1
        self.g_decrypt = 0
        self.g_algorithm = "aes_256_ecb"
        self.g_iv = b"0000000000000000"

    def p_example1_hard_coded(self, key, data):
        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example2_local_variable(self, key, data):
        algorithm = "aes_256_ecb"
        cipher = Cipher(algorithm, key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example3_nested_local_variable(self, key, data):
        algorithm1 = "aes_256_ecb"
        algorithm2 = algorithm1
        algorithm3 = algorithm2

        cipher = Cipher(algorithm3, key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example_method_call(self, key, data, algorithm):
        cipher = Cipher(algorithm, key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example_nested_method_call(self, key, data, algorithm):
        return self.p_example_method_call(key, data, algorithm)

    def p_example4_direct_method_call(self, key, data):
        algorithm = "aes_256_ecb"
        return self.p_example_method_call(key, data, algorithm)

    def p_example5_nested_method_call(self, key, data):
        algorithm = "aes_256_ecb"
        return self.p_example_nested_method_call(key, data, algorithm)

    def p_example6_direct_g_variable_access(self, key, data):
        cipher = Cipher(self.g_algorithm, key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example7_indirect_g_variable_access(self, key, data):
        algorithm = self.g_algorithm
        cipher = Cipher(algorithm, key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example8_warning_parameter_not_resolvable(self, key, data, algorithm):
        cipher = Cipher(algorithm, key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def n_example1_cbc(self, key, iv, data):
        cipher = Cipher("aes_256_cbc", key, iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text
