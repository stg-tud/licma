# https://hwwong168.wordpress.com/2019/09/25/esp32-micropython-implementation-of-cryptographic/
from ucryptolib import aes, MODE_ECB, MODE_CBC


class TestRule1c:
    def __init__(self):
        self.g_mode1 = MODE_ECB
        self.g_mode2 = 1

    def p_example1_hard_coded1(self, key, data):
        cipher = aes(key, MODE_ECB)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example2_hard_coded2(self, key, data):
        cipher = aes(key, 1)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example3_local_variable1(self, key, data):
        mode = MODE_ECB
        cipher = aes(key, mode)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example4_local_variable2(self, key, data):
        mode = 1
        cipher = aes(key, mode)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example5_nested_local_variable1(self, key, data):
        mode1 = MODE_ECB
        mode2 = mode1
        mode3 = mode2

        cipher = aes(key, mode3)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example6_nested_local_variable2(self, key, data):
        mode1 = 1
        mode2 = mode1
        mode3 = mode2

        cipher = aes(key, mode3)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example_method_call(self, key, data, mode):
        cipher = aes(key, mode)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example_nested_method_call(self, key, data, mode):
        return self.p_example_method_call(key, data, mode)

    def p_example7_direct_method_call1(self, key, data):
        mode = MODE_ECB
        return self.p_example_method_call(key, data, mode)

    def p_example8_direct_method_call2(self, key, data):
        mode = 1
        return self.p_example_method_call(key, data, mode)

    def p_example9_nested_method_call1(self, key, data):
        mode = MODE_ECB
        return self.p_example_nested_method_call(key, data, mode)

    def p_example10_nested_method_call2(self, key, data):
        mode = 1
        return self.p_example_nested_method_call(key, data, mode)

    def p_example11_direct_g_variable_access1(self, key, data):
        cipher = aes(key, self.g_mode1)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example12_direct_g_variable_access2(self, key, data):
        cipher = aes(key, self.g_mode2)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example13_indirect_g_variable_access1(self, key, data):
        mode = self.g_mode1
        cipher = aes(key, mode)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example14_indirect_g_variable_access2(self, key, data):
        mode = self.g_mode2
        cipher = aes(key, mode)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def p_example15_warning_parameter_not_resolvable(self, key, data, mode):
        cipher = aes(key, mode)
        cipher_text = cipher.encrypt(data)
        return cipher_text

    def n_example1_cbc(self, key, iv, data):
        cipher = aes(key, MODE_CBC, iv)
        cipher_text = cipher.encrypt(data)
        return cipher_text
