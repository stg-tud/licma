from nacl.utils import random
from nacl.secret import SecretBox


class TestRule3c:
    def __init__(self):
        self.g_key1 = b"12345678123456781234567812345678"
        self.g_key2 = bytes("12345678123456781234567812345678", "utf8")
        self.nonce = b"123456781234567812345678"  # 24 byte

    def p_example1_hard_coded1(self, data):
        secret_box = SecretBox(b"12345678123456781234567812345678")
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def p_example2_hard_coded2(self, data):
        secret_box = SecretBox(bytes("12345678123456781234567812345678", "utf8"))
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def p_example3_local_variable1(self, data):
        key = b"12345678123456781234567812345678"
        secret_box = SecretBox(key)
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def p_example4_local_variable2(self, data):
        key = bytes("12345678123456781234567812345678", "utf8")
        secret_box = SecretBox(key)
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def p_example5_nested_local_variable1(self, data):
        key1 = b"12345678123456781234567812345678"
        key2 = key1
        key3 = key2

        secret_box = SecretBox(key3)
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def p_example6_nested_local_variable2(self, data):
        key1 = bytes("12345678123456781234567812345678", "utf8")
        key2 = key1
        key3 = key2

        secret_box = SecretBox(key3)
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def p_example_method_call(self, key, data):
        secret_box = SecretBox(key)
        cipher_text = secret_box.encrypt(data, self.nonce)
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
        secret_box = SecretBox(self.g_key1)
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def p_example12_direct_g_variable_access2(self, data):
        secret_box = SecretBox(self.g_key2)
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def p_example13_indirect_g_variable_access1(self, data):
        key = self.g_key1
        secret_box = SecretBox(key)
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def p_example14_indirect_g_variable_access2(self, data):
        key = self.g_key2
        secret_box = SecretBox(key)
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def p_example15_warning_parameter_not_resolvable(self, key, data):
        secret_box = SecretBox(key)
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text

    def n_example1_random_key(self, data):
        key = random(32)
        secret_box = SecretBox(key)
        cipher_text = secret_box.encrypt(data, self.nonce)
        return cipher_text
