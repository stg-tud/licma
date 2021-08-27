from nacl.utils import random
from nacl.secret import SecretBox
from nacl.pwhash.argon2i import kdf

g_salt1 = b"1234567812345678"
g_salt2 = bytes("1234567812345678", "utf8")
nonce = b"123456781234567812345678"  # 24 byte


def p_example1_hard_coded1(password, data):
    key = kdf(32, password, b"1234567812345678")

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example2_hard_coded2(password, data):
    key = kdf(32, password, bytes("1234567812345678", "utf8"))

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example3_local_variable1(password, data):
    salt = b"1234567812345678"
    key = kdf(32, password, salt)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example4_local_variable2(password, data):
    salt = bytes("1234567812345678", "utf8")
    key = kdf(32, password, salt)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example5_nested_local_variable1(password, data):
    salt1 = b"1234567812345678"
    salt2 = salt1
    salt3 = salt2

    key = kdf(32, password, salt3)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example6_nested_local_variable2(password, data):
    salt1 = bytes("1234567812345678", "utf8")
    salt2 = salt1
    salt3 = salt2

    key = kdf(32, password, salt3)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example_method_call(password, salt, data):
    key = kdf(32, password, salt)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example_nested_method_call(password, salt, data):
    return p_example_method_call(password, salt, data)


def p_example7_direct_method_call1(password, data):
    salt = b"1234567812345678"
    return p_example_method_call(password, salt, data)


def p_example8_direct_method_call2(password, data):
    salt = bytes("1234567812345678", "utf8")
    return p_example_method_call(password, salt, data)


def p_example9_nested_method_call1(password, data):
    salt = b"1234567812345678"
    return p_example_nested_method_call(password, salt, data)


def p_example10_nested_method_call2(password, data):
    salt = bytes("1234567812345678", "utf8")
    return p_example_nested_method_call(password, salt, data)


def p_example11_direct_g_variable_access1(password, data):
    key = kdf(32, password, g_salt1)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example12_direct_g_variable_access2(password, data):
    key = kdf(32, password, g_salt2)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example13_indirect_g_variable_access1(password, data):
    salt = g_salt1
    key = kdf(32, password, salt)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example14_indirect_g_variable_access2(password, data):
    salt = g_salt2
    key = kdf(32, password, salt)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def p_example15_warning_parameter_not_resolvable(password, salt, data):
    key = kdf(32, password, salt)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text


def n_example1_random_salt(password, data):
    salt = random(16)
    key = kdf(32, password, salt)

    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(data, nonce)
    return cipher_text
