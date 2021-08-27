from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class TestRule1c:
    def __init__(self):
        self.g_backend = default_backend()
        self.g_mode = modes.ECB()

    def p_example1_hard_coded(self, key, data):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example2_local_variable(self, key, data):
        mode = modes.ECB()
        cipher = Cipher(algorithms.AES(key), mode, backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example3_nested_local_variable(self, key, data):
        mode1 = modes.ECB()
        mode2 = mode1
        mode3 = mode2

        cipher = Cipher(algorithms.AES(key), mode3, backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example_method_call(self, key, data, mode):
        cipher = Cipher(algorithms.AES(key), mode, backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example_nested_method_call(self, key, data, mode):
        return self.p_example_method_call(key, data, mode)

    def p_example4_direct_method_call(self, key, data):
        mode = modes.ECB()
        return self.p_example_method_call(key, data, mode)

    def p_example5_nested_method_call(self, key, data):
        mode = modes.ECB()
        return self.p_example_nested_method_call(key, data, mode)

    def p_example6_direct_g_variable_access(self, key, data):
        cipher = Cipher(algorithms.AES(key), self.g_mode, backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example7_indirect_g_variable_access(self, key, data):
        mode = self.g_mode
        cipher = Cipher(algorithms.AES(key), mode, backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example8_warning_parameter_not_resolvable(self, key, data, mode):
        cipher = Cipher(algorithms.AES(key), mode, backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def n_example1_cbc(self, key, data):
        iv = b"1234567812345678"
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text
