from nacl.utils import random
from nacl.secret import SecretBox

g_key1 = b"12345678123456781234567812345678"
g_key2 = bytes("12345678123456781234567812345678", "utf8")
nonce = b"123456781234567812345678"  # 24 byte


def p_example1_hard_coded1(data):
    secret_box = SecretBox(b"12345678123456781234567812345678")
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example2_hard_coded2(data):
    secret_box = SecretBox(bytes("12345678123456781234567812345678", "utf8"))
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example3_local_variable1(data):
    key = b"12345678123456781234567812345678"
    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example4_local_variable2(data):
    key = bytes("12345678123456781234567812345678", "utf8")
    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example5_nested_local_variable1(data):
    key1 = b"12345678123456781234567812345678"
    key2 = key1
    key3 = key2

    secret_box = SecretBox(key3)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example6_nested_local_variable2(data):
    key1 = bytes("12345678123456781234567812345678", "utf8")
    key2 = key1
    key3 = key2

    secret_box = SecretBox(key3)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example_method_call(key, data):
    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
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
    secret_box = SecretBox(g_key1)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example12_direct_g_variable_access2(data):
    secret_box = SecretBox(g_key2)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example13_indirect_g_variable_access1(data):
    key = g_key1
    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example14_indirect_g_variable_access2(data):
    key = g_key2
    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example15_warning_parameter_not_resolvable(key, data):
    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def n_example1_random_key(data):
    key = random(32)
    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text
