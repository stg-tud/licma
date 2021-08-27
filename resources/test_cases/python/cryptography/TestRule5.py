from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

g_backend = default_backend()
g_count = 999


def p_example1_hard_coded(password, data):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=b"12345678", iterations=999, backend=g_backend)
    key = kdf.derive(password)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example2_local_variable(password, data):
    count = 999
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=b"12345678", iterations=count, backend=g_backend)
    key = kdf.derive(password)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example3_nested_local_variable(password, data):
    count1 = 999
    count2 = count1
    count3 = count2

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=b"12345678", iterations=count3, backend=g_backend)
    key = kdf.derive(password)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example_method_call(password, count, data):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=b"12345678", iterations=count, backend=g_backend)
    key = kdf.derive(password)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example_nested_method_call(password, count, data):
    return p_example_method_call(password, count, data)


def p_example4_direct_method_call(password, data):
    count = 999
    return p_example_method_call(password, count, data)


def p_example5_nested_method_call(password, data):
    count = 999
    return p_example_nested_method_call(password, count, data)


def p_example6_direct_g_variable_access(password, data):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=b"12345678", iterations=g_count, backend=g_backend)
    key = kdf.derive(password)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example7_indirect_g_variable_access(password, data):
    count = g_count
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=b"12345678", iterations=count, backend=g_backend)
    key = kdf.derive(password)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example8_warning_parameter_not_resolvable(password, count, data):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=b"12345678", iterations=count, backend=g_backend)
    key = kdf.derive(password)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def n_example1_iterations_eq_1000(password, data):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=b"12345678", iterations=1000, backend=g_backend)
    key = kdf.derive(password)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text
