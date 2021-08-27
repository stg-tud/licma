import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

g_backend = default_backend()
g_key1 = b"1234567812345678"
g_key2 = bytes("1234567812345678", "utf8")
g_key_fernet1 = base64.urlsafe_b64encode(b"12345678123456781234567812345678")
g_key_fernet2 = base64.urlsafe_b64encode(bytes("12345678123456781234567812345678", "utf8"))


def p_example1_hard_coded1(data):
    cipher = Cipher(algorithms.AES(b"1234567812345678"), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example2_hard_coded2(data):
    cipher = Cipher(algorithms.AES(bytes("1234567812345678", "utf8")), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example3_hard_coded3(data):
    fernet = Fernet(base64.urlsafe_b64encode(b"12345678123456781234567812345678"), backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example4_hard_coded4(data):
    fernet = Fernet(base64.urlsafe_b64encode(bytes("12345678123456781234567812345678", "utf8")), backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example5_local_variable1(data):
    key = b"1234567812345678"
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example6_local_variable2(data):
    key = bytes("1234567812345678", "utf8")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example7_local_variable3(data):
    key = base64.urlsafe_b64encode(b"12345678123456781234567812345678")
    fernet = Fernet(key, backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example8_local_variable4(data):
    key = base64.urlsafe_b64encode(bytes("12345678123456781234567812345678", "utf8"))
    fernet = Fernet(key, backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example9_nested_local_variable1(data):
    key1 = b"1234567812345678"
    key2 = key1
    key3 = key2

    cipher = Cipher(algorithms.AES(key3), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example10_nested_local_variable2(data):
    key1 = bytes("1234567812345678", "utf8")
    key2 = key1
    key3 = key2

    cipher = Cipher(algorithms.AES(key3), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example11_nested_local_variable3(data):
    key1 = base64.urlsafe_b64encode(b"12345678123456781234567812345678")
    key2 = key1
    key3 = key2

    fernet = Fernet(key3)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example12_nested_local_variable4(data):
    key1 = base64.urlsafe_b64encode(bytes("12345678123456781234567812345678", "utf8"))
    key2 = key1
    key3 = key2

    fernet = Fernet(key3, backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example_method_call1(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example_method_call2(key, data):
    fernet = Fernet(key, backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example_nested_method_call1(key, data):
    return p_example_method_call1(key, data)


def p_example_nested_method_call2(key, data):
    return p_example_method_call2(key, data)


def p_example13_direct_method_call1(data):
    key = b"1234567812345678"
    return p_example_method_call1(key, data)


def p_example14_direct_method_call2(data):
    key = bytes("1234567812345678", "utf8")
    return p_example_method_call1(key, data)


def p_example15_direct_method_call3(data):
    key = base64.urlsafe_b64encode(b"12345678123456781234567812345678")
    return p_example_method_call2(key, data)


def p_example16_direct_method_call4(data):
    key = base64.urlsafe_b64encode(bytes("12345678123456781234567812345678", "utf8"))
    return p_example_method_call2(key, data)


def p_example17_nested_method_call1(data):
    key = b"1234567812345678"
    return p_example_nested_method_call1(key, data)


def p_example18_nested_method_call2(data):
    key = bytes("1234567812345678", "utf8")
    return p_example_nested_method_call1(key, data)


def p_example19_nested_method_call3(data):
    key = base64.urlsafe_b64encode(b"12345678123456781234567812345678")
    return p_example_nested_method_call2(key, data)


def p_example20_nested_method_call4(data):
    key = base64.urlsafe_b64encode(bytes("12345678123456781234567812345678", "utf8"))
    return p_example_nested_method_call2(key, data)


def p_example21_direct_g_variable_access1(data):
    cipher = Cipher(algorithms.AES(g_key1), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example22_direct_g_variable_access2(data):
    cipher = Cipher(algorithms.AES(g_key2), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example23_direct_g_variable_access3(data):
    fernet = Fernet(g_key_fernet1, backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example24_direct_g_variable_access4(data):
    fernet = Fernet(g_key_fernet2, backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example25_indirect_g_variable_access1(data):
    key = g_key1
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example26_indirect_g_variable_access2(data):
    key = g_key2
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example27_indirect_g_variable_access3(data):
    key = g_key_fernet1
    fernet = Fernet(key, backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example28_indirect_g_variable_access4(data):
    key = g_key_fernet2
    fernet = Fernet(key, backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def p_example29_warning_parameter_not_resolvable1(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def p_example30_warning_parameter_not_resolvable2(key, data):
    fernet = Fernet(key, backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text


def n_example1_random_key1(data):
    key = os.urandom(16)  # Recommended by the cryptography developers
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    return cipher_text


def n_example2_random_key2(data):
    key = base64.urlsafe_b64encode(os.urandom(32))  # Recommended by the cryptography developers
    fernet = Fernet(key, backend=g_backend)
    cipher_text = fernet.encrypt(data)
    return cipher_text
