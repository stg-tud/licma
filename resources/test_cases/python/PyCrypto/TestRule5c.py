from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import random


class TestRule5c:
    def __init__(self):
        self.g_count = 999

    def p_example1_hard_coded(self, password, data):
        key = PBKDF2(password, b"12345678", 16, count=999)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example2_local_variable(self, password, data):
        count = 999
        key = PBKDF2(password, b"12345678", 16, count=count)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example3_nested_local_variable(self, password, data):
        count1 = 999
        count2 = count1
        count3 = count2

        key = PBKDF2(password, b"12345678", 16, count=count3)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example_method_call(self, password, count, data):
        key = PBKDF2(password, b"12345678", 16, count=count)
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example_nested_method_call(self, password, count, data):
        return self.p_example_method_call(password, count, data)

    def p_example4_direct_method_call(self, password, data):
        count = 999
        return self.p_example_method_call(password, count, data)

    def p_example5_nested_method_call(self, password, data):
        count = 999
        return self.p_example_nested_method_call(password, count, data)

    def p_example6_direct_g_variable_access(self, password, data):
        key = PBKDF2(password, b"12345678", 16, count=self.g_count)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example7_indirect_g_variable_access(self, password, data):
        count = self.g_count
        key = PBKDF2(password, b"12345678", 16, count=count)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example8_warning_parameter_not_resolvable(self, password, count, data):
        key = PBKDF2(password, b"12345678", 16, count=count)
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def n_example1_iterations_eq_1000(self, password, data):
        salt = random.getrandbits(16).to_bytes(16, 'big')
        key = PBKDF2(password, salt, 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text
