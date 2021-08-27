from M2Crypto.EVP import Cipher
from M2Crypto.EVP import pbkdf2
from M2Crypto.Rand import rand_bytes

g_encrypt = 1
g_decrypt = 0
g_iter = 999
g_iv = b"1234567812345678"


def p_example1_hard_coded(password, data):
    key = pbkdf2(password, b"12345678", 999, 32)

    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example2_local_variable(password, data):
    iter = 999
    key = pbkdf2(password, b"12345678", iter, 32)

    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example3_nested_local_variable(password, data):
    iter1 = 999
    iter2 = iter1
    iter3 = iter2

    key = pbkdf2(password, b"12345678", iter3, 32)

    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example_method_call(password, iter, data):
    key = pbkdf2(password, b"12345678", iter, 32)

    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example_nested_method_call(password, iter, data):
    return p_example_method_call(password, iter, data)


def p_example4_direct_method_call(password, data):
    iter = 999
    return p_example_method_call(password, iter, data)


def p_example5_nested_method_call(password, data):
    iter = 999
    return p_example_nested_method_call(password, iter, data)


def p_example6_direct_g_variable_access(password, data):
    key = pbkdf2(password, b"12345678", g_iter, 32)

    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example7_indirect_g_variable_access(password, data):
    iter = g_iter
    key = pbkdf2(password, b"12345678", iter, 32)

    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example8_warning_parameter_not_resolvable(password, iter, data):
    key = pbkdf2(password, b"12345678", iter, 32)

    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def n_example1_iterations_eq_1000(password, data):
    salt = rand_bytes(8)
    key = pbkdf2(password, salt, 1000, 32)

    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text
