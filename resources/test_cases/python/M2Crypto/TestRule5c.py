from M2Crypto.EVP import Cipher
from M2Crypto.EVP import pbkdf2
from M2Crypto.Rand import rand_bytes


class TestRule5c:
    def __init__(self):
        self.g_encrypt = 1
        self.g_decrypt = 0
        self.g_iter = 999
        self.g_iv = b"1234567812345678"

    def p_example1_hard_coded(self, password, data):
        key = pbkdf2(password, b"12345678", 999, 32)

        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example2_local_variable(self, password, data):
        iter = 999
        key = pbkdf2(password, b"12345678", iter, 32)

        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example3_nested_local_variable(self, password, data):
        iter1 = 999
        iter2 = iter1
        iter3 = iter2

        key = pbkdf2(password, b"12345678", iter3, 32)

        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example_method_call(self, password, iter, data):
        key = pbkdf2(password, b"12345678", iter, 32)

        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example_nested_method_call(self, password, iter, data):
        return self.p_example_method_call(password, iter, data)

    def p_example4_direct_method_call(self, password, data):
        iter = 999
        return self.p_example_method_call(password, iter, data)

    def p_example5_nested_method_call(self, password, data):
        iter = 999
        return self.p_example_nested_method_call(password, iter, data)

    def p_example6_direct_g_variable_access(self, password, data):
        key = pbkdf2(password, b"12345678", self.g_iter, 32)

        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example7_indirect_g_variable_access(self, password, data):
        iter = self.g_iter
        key = pbkdf2(password, b"12345678", iter, 32)

        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def p_example8_warning_parameter_not_resolvable(self, password, iter, data):
        key = pbkdf2(password, b"12345678", iter, 32)

        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text

    def n_example1_iterations_eq_1000(self, password, data):
        salt = rand_bytes(8)
        key = pbkdf2(password, salt, 1000, 32)

        cipher = Cipher("aes_256_ecb", key, self.g_iv, self.g_encrypt)
        cipher_text = cipher.update(data) + cipher.final()
        return cipher_text
