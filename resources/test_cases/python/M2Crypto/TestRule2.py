from M2Crypto.EVP import Cipher
from M2Crypto.Rand import rand_bytes

g_encrypt = 1
g_decrypt = 0
g_iv1 = b"1234567812345678"
g_iv2 = bytes("1234567812345678", "utf8")


def p_example1_hard_coded1(key, data):
    cipher = Cipher("aes_256_cbc", key, b"1234567812345678", g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example2_hard_coded2(key, data):
    cipher = Cipher("aes_256_cbc", key, bytes("1234567812345678", "utf8"), g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example3_local_variable1(key, data):
    iv = b"1234567812345678"
    cipher = Cipher("aes_256_cbc", key, iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example4_local_variable2(key, data):
    iv = bytes("1234567812345678", "utf8")
    cipher = Cipher("aes_256_cbc", key, iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example5_nested_local_variable1(key, data):
    iv1 = b"1234567812345678"
    iv2 = iv1
    iv3 = iv2

    cipher = Cipher("aes_256_cbc", key, iv3, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example6_nested_local_variable2(key, data):
    iv1 = bytes("1234567812345678", "utf8")
    iv2 = iv1
    iv3 = iv2

    cipher = Cipher("aes_256_cbc", key, iv3, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example_method_call(key, iv, data):
    cipher = Cipher("aes_256_cbc", key, iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
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
    cipher = Cipher("aes_256_cbc", key, g_iv1, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example12_direct_g_variable_access2(key, data):
    cipher = Cipher("aes_256_cbc", key, g_iv2, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example13_indirect_g_variable_access1(key, data):
    iv = g_iv1
    cipher = Cipher("aes_256_cbc", key, iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example14_indirect_g_variable_access2(key, data):
    iv = g_iv2
    cipher = Cipher("aes_256_cbc", key, iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example15_warning_parameter_not_resolvable(key, iv, data):
    cipher = Cipher("aes_256_cbc", key, iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def n_example1_secrets_system_random(key, data):
    iv = rand_bytes(16)
    cipher = Cipher("aes_256_cbc", key, iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text
