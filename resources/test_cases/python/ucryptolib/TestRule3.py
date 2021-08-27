# https://hwwong168.wordpress.com/2019/09/25/esp32-micropython-implementation-of-cryptographic/
import uos
from ucryptolib import aes, MODE_ECB, MODE_CBC

g_key1 = b"1234567812345678"
g_key2 = bytes("1234567812345678", "utf8")


def p_example1_hard_coded1(data):
    cipher = aes(b"1234567812345678", MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example2_hard_coded2(data):
    cipher = aes(bytes("1234567812345678", "utf8"), MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example3_local_variable1(data):
    key = b"1234567812345678"
    cipher = aes(key, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example4_local_variable2(data):
    key = bytes("1234567812345678", "utf8")
    cipher = aes(key, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example5_nested_local_variable1(data):
    key1 = b"1234567812345678"
    key2 = key1
    key3 = key2

    cipher = aes(key3, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example6_nested_local_variable2(data):
    key1 = bytes("1234567812345678", "utf8")
    key2 = key1
    key3 = key2

    cipher = aes(key3, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example_method_call(key, data):
    cipher = aes(key, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example_nested_method_call(key, data):
    return p_example_method_call(key, data)


def p_example7_direct_method_call1(data):
    key = b"1234567812345678"
    return p_example_method_call(key, data)


def p_example8_direct_method_call2(data):
    key = bytes("1234567812345678", "utf8")
    return p_example_method_call(key, data)


def p_example9_nested_method_call1(data):
    key = b"1234567812345678"
    return p_example_nested_method_call(key, data)


def p_example10_nested_method_call2(data):
    key = bytes("1234567812345678", "utf8")
    return p_example_nested_method_call(key, data)


def p_example11_direct_g_variable_access1(data):
    cipher = aes(g_key1, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example12_direct_g_variable_access2(data):
    cipher = aes(g_key2, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example13_indirect_g_variable_access1(data):
    key = g_key1
    cipher = aes(key, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example14_indirect_g_variable_access2(data):
    key = g_key2
    cipher = aes(key, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def p_example15_warning_parameter_not_resolvable(key, data):
    cipher = aes(key, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text


def n_example1_random_key(data):
    key = uos.urandom(16)
    cipher = aes(key, MODE_ECB)
    cipher_text = cipher.encrypt(data)
    return cipher_text
