from M2Crypto.EVP import Cipher
from M2Crypto.Rand import rand_bytes


class TestRule3c:
    def __init__(self):
        self.g_encrypt = 1
        self.g_decrypt = 0
        self.g_key1 = b"12345678123456781234567812345678"
        self.g_key2 = bytes("12345678123456781234567812345678", "utf8")
        self.g_iv = b"0000000000000000"

    def p_example1_hard_coded1(self, data):
        cipher = Cipher("aes_256_ecb", b"12345678123456781234567812345678", self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example2_hard_coded2(self, data):
        cipher = Cipher("aes_256_ecb", bytes("12345678123456781234567812345678", "utf8"),
                        self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example3_local_variable1(self, data):
        key = b"12345678123456781234567812345678"
        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example4_local_variable2(self, data):
        key = bytes("12345678123456781234567812345678", "utf8")
        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example5_nested_local_variable1(self, data):
        key1 = b"12345678123456781234567812345678"
        key2 = key1
        key3 = key2

        cipher = Cipher("aes_256_ecb", key3, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example6_nested_local_variable2(self, data):
        key1 = bytes("12345678123456781234567812345678", "utf8")
        key2 = key1
        key3 = key2

        cipher = Cipher("aes_256_ecb", key3, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example_method_call(self, key, data):
        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example_nested_method_call(self, key, data):
        return self.p_example_method_call(key, data)

    def p_example7_direct_method_call1(self, data):
        key = b"12345678123456781234567812345678"
        return self.p_example_method_call(key, data)

    def p_example8_direct_method_call2(self, data):
        key = bytes("12345678123456781234567812345678", "utf8")
        return self.p_example_method_call(key, data)

    def p_example9_nested_method_call1(self, data):
        key = b"12345678123456781234567812345678"
        return self.p_example_nested_method_call(key, data)

    def p_example10_nested_method_call2(self, data):
        key = bytes("12345678123456781234567812345678", "utf8")
        return self.p_example_nested_method_call(key, data)

    def p_example11_direct_g_variable_access1(self, data):
        cipher = Cipher("aes_256_ecb", self.g_key1, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example12_direct_g_variable_access2(self, data):
        cipher = Cipher("aes_256_ecb", self.g_key2, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example13_indirect_g_variable_access1(self, data):
        key = self.g_key1
        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example14_indirect_g_variable_access2(self, data):
        key = self.g_key2
        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example15_warning_parameter_not_resolvable(self, key, data):
        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def n_example1_random_key(self, data):
        key = rand_bytes(32)
        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text
