import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class TestRule4c:
    def __init__(self):
        self.g_backend = default_backend()
        self.g_salt1 = b"12345678"
        self.g_salt2 = bytes("12345678", "utf8")

    def p_example1_hard_coded1(self, password, data):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=b"12345678", iterations=1000,
                         backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example2_hard_coded2(self, password, data):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=bytes("12345678", "utf8"), iterations=1000,
                         backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example3_local_variable1(self, password, data):
        salt = b"12345678"
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=1000, backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example4_local_variable2(self, password, data):
        salt = bytes("12345678", "utf8")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=1000, backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example5_nested_local_variable1(self, password, data):
        salt1 = b"12345678"
        salt2 = salt1
        salt3 = salt2

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt3, iterations=1000, backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example6_nested_local_variable2(self, password, data):
        salt1 = bytes("12345678", "utf8")
        salt2 = salt1
        salt3 = salt2

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt3, iterations=1000, backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example_method_call(self, password, salt, data):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=1000, backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
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
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=self.g_salt1, iterations=1000,
                         backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example12_direct_g_variable_access2(self, password, data):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=self.g_salt2, iterations=1000,
                         backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example13_indirect_g_variable_access1(self, password, data):
        salt = self.g_salt1
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=1000, backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example14_indirect_g_variable_access2(self, password, data):
        salt = self.g_salt2
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=1000, backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def p_example15_warning_parameter_not_resolvable(self, password, salt, data):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=1000, backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text

    def n_example1_random_salt(self, password, data):
        salt = os.urandom(8)  # Recommended by the cryptography developers
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=1000, backend=self.g_backend)
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.g_backend)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        return cipher_text
