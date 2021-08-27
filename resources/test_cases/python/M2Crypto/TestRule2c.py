from M2Crypto.EVP import Cipher
from M2Crypto.Rand import rand_bytes


class TestRule2c:
    def __init__(self):
        self.g_encrypt = 1
        self.g_decrypt = 0
        self.g_iv1 = b"1234567812345678"
        self.g_iv2 = bytes("1234567812345678", "utf8")

    def p_example1_hard_coded1(self, key, data):
        cipher = Cipher("aes_256_cbc", key, b"1234567812345678", self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example2_hard_coded2(self, key, data):
        cipher = Cipher("aes_256_cbc", key, bytes("1234567812345678", "utf8"), self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example3_local_variable1(self, key, data):
        iv = b"1234567812345678"
        cipher = Cipher("aes_256_cbc", key, iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example4_local_variable2(self, key, data):
        iv = bytes("1234567812345678", "utf8")
        cipher = Cipher("aes_256_cbc", key, iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example5_nested_local_variable1(self, key, data):
        iv1 = b"1234567812345678"
        iv2 = iv1
        iv3 = iv2

        cipher = Cipher("aes_256_cbc", key, iv3, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example6_nested_local_variable2(self, key, data):
        iv1 = bytes("1234567812345678", "utf8")
        iv2 = iv1
        iv3 = iv2

        cipher = Cipher("aes_256_cbc", key, iv3, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example_method_call(self, key, iv, data):
        cipher = Cipher("aes_256_cbc", key, iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example_nested_method_call(self, key, iv, data):
        return self.p_example_method_call(key, iv, data)

    def p_example7_direct_method_call1(self, key, data):
        iv = b"1234567812345678"
        return self.p_example_method_call(key, iv, data)

    def p_example8_direct_method_call2(self, key, data):
        iv = bytes("1234567812345678", "utf8")
        return self.p_example_method_call(key, iv, data)

    def p_example9_nested_method_call1(self, key, data):
        iv = b"1234567812345678"
        return self.p_example_nested_method_call(key, iv, data)

    def p_example10_nested_method_call2(self, key, data):
        iv = bytes("1234567812345678", "utf8")
        return self.p_example_nested_method_call(key, iv, data)

    def p_example11_direct_g_variable_access1(self, key, data):
        cipher = Cipher("aes_256_cbc", key, self.g_iv1, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example12_direct_g_variable_access2(self, key, data):
        cipher = Cipher("aes_256_cbc", key, self.g_iv2, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example13_indirect_g_variable_access1(self, key, data):
        iv = self.g_iv1
        cipher = Cipher("aes_256_cbc", key, iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example14_indirect_g_variable_access2(self, key, data):
        iv = self.g_iv2
        cipher = Cipher("aes_256_cbc", key, iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example15_warning_parameter_not_resolvable(self, key, iv, data):
        cipher = Cipher("aes_256_cbc", key, iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def n_example1_secrets_system_random(self, key, data):
        iv = rand_bytes(16)
        cipher = Cipher("aes_256_cbc", key, iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text
