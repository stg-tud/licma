from M2Crypto.EVP import Cipher
from M2Crypto.Rand import rand_bytes

g_encrypt = 1
g_decrypt = 0
g_key1 = b"12345678123456781234567812345678"
g_key2 = bytes("12345678123456781234567812345678", "utf8")
g_iv = b"0000000000000000"


def p_example1_hard_coded1(data):
    cipher = Cipher("aes_256_ecb", b"12345678123456781234567812345678", g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example2_hard_coded2(data):
    cipher = Cipher("aes_256_ecb", bytes("12345678123456781234567812345678", "utf8"),
                    g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example3_local_variable1(data):
    key = b"12345678123456781234567812345678"
    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example4_local_variable2(data):
    key = bytes("12345678123456781234567812345678", "utf8")
    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example5_nested_local_variable1(data):
    key1 = b"12345678123456781234567812345678"
    key2 = key1
    key3 = key2

    cipher = Cipher("aes_256_ecb", key3, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example6_nested_local_variable2(data):
    key1 = bytes("12345678123456781234567812345678", "utf8")
    key2 = key1
    key3 = key2

    cipher = Cipher("aes_256_ecb", key3, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example_method_call(key, data):
    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example_nested_method_call(key, data):
    return p_example_method_call(key, data)


def p_example7_direct_method_call1(data):
    key = b"12345678123456781234567812345678"
    return p_example_method_call(key, data)


def p_example8_direct_method_call2(data):
    key = bytes("12345678123456781234567812345678", "utf8")
    return p_example_method_call(key, data)


def p_example9_nested_method_call1(data):
    key = b"12345678123456781234567812345678"
    return p_example_nested_method_call(key, data)


def p_example10_nested_method_call2(data):
    key = bytes("12345678123456781234567812345678", "utf8")
    return p_example_nested_method_call(key, data)


def p_example11_direct_g_variable_access1(data):
    cipher = Cipher("aes_256_ecb", g_key1, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example12_direct_g_variable_access2(data):
    cipher = Cipher("aes_256_ecb", g_key2, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example13_indirect_g_variable_access1(data):
    key = g_key1
    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example14_indirect_g_variable_access2(data):
    key = g_key2
    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example15_warning_parameter_not_resolvable(key, data):
    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def n_example1_random_key(data):
    key = rand_bytes(32)
    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text
