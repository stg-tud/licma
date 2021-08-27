from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Random import random

g_backend = default_backend()
g_iv1 = b"1234567812345678"
g_iv2 = bytes("1234567812345678", "utf8")


def p_example1_hard_coded1(key, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(b"1234567812345678"), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example2_hard_coded2(key, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes("1234567812345678", "utf8")), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example3_local_variable1(key, data):
    iv = b"1234567812345678"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example4_local_variable2(key, data):
    iv = bytes("1234567812345678", "utf8")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example5_nested_local_variable1(key, data):
    iv1 = b"1234567812345678"
    iv2 = iv1
    iv3 = iv2

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv3), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example6_nested_local_variable2(key, data):
    iv1 = bytes("1234567812345678", "utf8")
    iv2 = iv1
    iv3 = iv2

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv3), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example_method_call(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example_nested_method_call(key, iv, data):
    return p_example_method_call(key, iv, data)


def p_example7_direct_method_call1(key, data):
    iv = b"1234567812345678"
    return p_example_method_call(key, iv, data)


def p_example8_direct_method_call2(key, data):
    iv = bytes("1234567812345678", "utf8")
    return p_example_method_call(key, iv, data)


def p_example9_nested_method_call1(key, data):
    iv = b"1234567812345678"
    return p_example_nested_method_call(key, iv, data)


def p_example10_nested_method_call2(key, data):
    iv = bytes("1234567812345678", "utf8")
    return p_example_nested_method_call(key, iv, data)


def p_example11_direct_g_variable_access1(key, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(g_iv1), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example12_direct_g_variable_access2(key, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(g_iv2), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example13_indirect_g_variable_access1(key, data):
    iv = g_iv1
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example14_indirect_g_variable_access2(key, data):
    iv = g_iv2
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example15_warning_parameter_not_resolvable(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def n_example1_cbc(key, data):
    iv = random.getrandbits(16).to_bytes(16, 'big')
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text
