from Crypto.Cipher import AES

g_mode1 = AES.MODE_ECB
g_mode2 = 1


def p_example1_hard_coded1(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example2_hard_coded2(key, data):
    cipher = AES.new(key, 1)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example3_local_variable1(key, data):
    mode = AES.MODE_ECB
    cipher = AES.new(key, mode)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example4_local_variable2(key, data):
    mode = 1
    cipher = AES.new(key, mode)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example5_nested_local_variable1(key, data):
    mode1 = AES.MODE_ECB
    mode2 = mode1
    mode3 = mode2

    cipher = AES.new(key, mode3)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example6_nested_local_variable2(key, data):
    mode1 = 1
    mode2 = mode1
    mode3 = mode2

    cipher = AES.new(key, mode3)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example_method_call(key, data, mode):
    cipher = AES.new(key, mode)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example_nested_method_call(key, data, mode):
    return p_example_method_call(key, data, mode)


def p_example7_direct_method_call1(key, data):
    mode = AES.MODE_ECB
    return p_example_method_call(key, data, mode)


def p_example8_direct_method_call2(key, data):
    mode = 1
    return p_example_method_call(key, data, mode)


def p_example9_nested_method_call1(key, data):
    mode = AES.MODE_ECB
    return p_example_nested_method_call(key, data, mode)


def p_example10_nested_method_call2(key, data):
    mode = 1
    return p_example_nested_method_call(key, data, mode)


def p_example11_direct_g_variable_access1(key, data):
    cipher = AES.new(key, g_mode1)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example12_direct_g_variable_access2(key, data):
    cipher = AES.new(key, g_mode2)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example13_indirect_g_variable_access1(key, data):
    mode = g_mode1
    cipher = AES.new(key, mode)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example14_indirect_g_variable_access2(key, data):
    mode = g_mode2
    cipher = AES.new(key, mode)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example15_warning_parameter_not_resolvable(key, data, mode):
    cipher = AES.new(key, mode)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def n_example1_cbc(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(data)
    return cipher_text
