from M2Crypto.EVP import Cipher

g_encrypt = 1
g_decrypt = 0
g_algorithm = "aes_256_ecb"
g_iv = b"0000000000000000"


def p_example1_hard_coded(key, data):
    cipher = Cipher("aes_256_ecb", key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example2_local_variable(key, data):
    algorithm = "aes_256_ecb"
    cipher = Cipher(algorithm, key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example3_nested_local_variable(key, data):
    algorithm1 = "aes_256_ecb"
    algorithm2 = algorithm1
    algorithm3 = algorithm2

    cipher = Cipher(algorithm3, key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example_method_call(key, data, algorithm):
    cipher = Cipher(algorithm, key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example_nested_method_call(key, data, algorithm):
    return p_example_method_call(key, data, algorithm)


def p_example4_direct_method_call(key, data):
    algorithm = "aes_256_ecb"
    return p_example_method_call(key, data, algorithm)


def p_example5_nested_method_call(key, data):
    algorithm = "aes_256_ecb"
    return p_example_nested_method_call(key, data, algorithm)


def p_example6_direct_g_variable_access(key, data):
    cipher = Cipher(g_algorithm, key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example7_indirect_g_variable_access(key, data):
    algorithm = g_algorithm
    cipher = Cipher(algorithm, key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def p_example8_warning_parameter_not_resolvable(key, data, algorithm):
    cipher = Cipher(algorithm, key, g_iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def n_example1_cbc(key, iv, data):
    cipher = Cipher("aes_256_cbc", key, iv, g_encrypt)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text
