from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class TestRule3c:
    def __init__(self):
        self.g_key1 = b"1234567812345678"
        self.g_key2 = bytes("1234567812345678", "utf8")

    def p_example1_hard_coded1(self, data):
        cipher = AES.new(b"1234567812345678", AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example2_hard_coded2(self, data):
        cipher = AES.new(bytes("1234567812345678", "utf8"), AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example3_local_variable1(self, data):
        key = b"1234567812345678"
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example4_local_variable2(self, data):
        key = bytes("1234567812345678", "utf8")
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example5_nested_local_variable1(self, data):
        key1 = b"1234567812345678"
        key2 = key1
        key3 = key2

        cipher = AES.new(key3, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example6_nested_local_variable2(self, data):
        key1 = bytes("1234567812345678", "utf8")
        key2 = key1
        key3 = key2

        cipher = AES.new(key3, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example_method_call(self, key, data):
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example_nested_method_call(self, key, data):
        return self.p_example_method_call(key, data)

    def p_example7_direct_method_call1(self, data):
        key = b"1234567812345678"
        return self.p_example_method_call(key, data)

    def p_example8_direct_method_call2(self, data):
        key = bytes("1234567812345678", "utf8")
        return self.p_example_method_call(key, data)

    def p_example9_nested_method_call1(self, data):
        key = b"1234567812345678"
        return self.p_example_nested_method_call(key, data)

    def p_example10_nested_method_call2(self, data):
        key = bytes("1234567812345678", "utf8")
        return self.p_example_nested_method_call(key, data)


    def p_example11_direct_g_variable_access1(self, data):
        cipher = AES.new(self.g_key1, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example12_direct_g_variable_access2(self, data):
        cipher = AES.new(self.g_key2, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example13_indirect_g_variable_access1(self, data):
        key = self.g_key1
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example14_indirect_g_variable_access2(self, data):
        key = self.g_key2
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example15_warning_parameter_not_resolvable(self, key, data):
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def n_example1_random_key(self, data):
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text
