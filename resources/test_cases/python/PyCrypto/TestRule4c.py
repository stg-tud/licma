from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import random


class TestRule4c:
    def __init__(self):
        self.g_salt1 = b"12345678"
        self.g_salt2 = bytes("12345678", "utf8")

    def p_example1_hard_coded1(self, password, data):
        key = PBKDF2(password, b"12345678", 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example2_hard_coded2(self, password, data):
        key = PBKDF2(password, bytes("12345678", "utf8"), 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example3_local_variable1(self, password, data):
        salt = b"12345678"
        key = PBKDF2(password, salt, 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example4_local_variable2(self, password, data):
        salt = bytes("12345678", "utf8")
        key = PBKDF2(password, salt, 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example5_nested_local_variable1(self, password, data):
        salt1 = b"12345678"
        salt2 = salt1
        salt3 = salt2

        key = PBKDF2(password, salt3, 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example6_nested_local_variable2(self, password, data):
        salt1 = bytes("12345678", "utf8")
        salt2 = salt1
        salt3 = salt2

        key = PBKDF2(password, salt3, 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example_method_call(self, password, salt, data):
        key = PBKDF2(password, salt, 16, count=1000)
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example_nested_method_call(self, password, salt, data):
        return self.p_example_method_call(password, salt, data)

    def p_example7_direct_method_call1(self, password, data):
        salt = b"12345678"
        return self.p_example_method_call(password, salt, data)

    def p_example8_direct_method_call2(self, password, data):
        salt = bytes("12345678", "utf8")
        return self.p_example_method_call(password, salt, data)

    def p_example9_nested_method_call1(self, password, data):
        salt = b"12345678"
        return self.p_example_nested_method_call(password, salt, data)

    def p_example10_nested_method_call2(self, password, data):
        salt = bytes("12345678", "utf8")
        return self.p_example_nested_method_call(password, salt, data)

    def p_example11_direct_g_variable_access1(self, password, data):
        key = PBKDF2(password, self.g_salt1, 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example12_direct_g_variable_access2(self, password, data):
        key = PBKDF2(password, self.g_salt2, 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example13_indirect_g_variable_access1(self, password, data):
        salt = self.g_salt1
        key = PBKDF2(password, salt, 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example14_indirect_g_variable_access2(self, password, data):
        salt = self.g_salt2
        key = PBKDF2(password, salt, 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example15_warning_parameter_not_resolvable(self, password, salt, data):
        key = PBKDF2(password, salt, 16, count=1000)
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def n_example1_random_salt(self, password, data):
        salt = random.getrandbits(16).to_bytes(16, 'big')
        key = PBKDF2(password, salt, 16, count=1000)

        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text
