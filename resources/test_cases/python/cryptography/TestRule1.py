from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

g_backend = default_backend()
g_mode = modes.ECB()


def p_example1_hard_coded(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example2_local_variable(key, data):
    mode = modes.ECB()
    cipher = Cipher(algorithms.AES(key), mode, backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example3_nested_local_variable(key, data):
    mode1 = modes.ECB()
    mode2 = mode1
    mode3 = mode2

    cipher = Cipher(algorithms.AES(key), mode3, backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example_method_call(key, data, mode):
    cipher = Cipher(algorithms.AES(key), mode, backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example_nested_method_call(key, data, mode):
    return p_example_method_call(key, data, mode)


def p_example4_direct_method_call(key, data):
    mode = modes.ECB()
    return p_example_method_call(key, data, mode)


def p_example5_nested_method_call(key, data):
    mode = modes.ECB()
    return p_example_nested_method_call(key, data, mode)


def p_example6_direct_g_variable_access(key, data):
    cipher = Cipher(algorithms.AES(key), g_mode, backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example7_indirect_g_variable_access(key, data):
    mode = g_mode
    cipher = Cipher(algorithms.AES(key), mode, backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example8_warning_parameter_not_resolvable(key, data, mode):
    cipher = Cipher(algorithms.AES(key), mode, backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def n_example1_cbc(key, data):
    iv = b"1234567812345678"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text
