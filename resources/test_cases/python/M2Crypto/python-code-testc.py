from M2Crypto.EVP import Cipher
from M2Crypto.EVP import pbkdf2
from TestRule1c import TestRule1c
from TestRule2c import TestRule2c
from TestRule3c import TestRule3c
from TestRule4c import TestRule4c
from TestRule5c import TestRule5c

encryption_mode = 1
decryption_mode = 0
key = b"12345678123456781234567812345678"
iv_ecb = b"0000000000000000"
iv_cbc = b"1234567812345678"
password = b"12345678"
salt = b"12345678"
iter_eq_1000 = 1000
iter_eq_999 = 999
algorithm = "aes_256_ecb"
plaintext = b"abcdefghijklmnop"


def decrypt_aes_ecb(key, data):
    cipher = Cipher("aes_256_ecb", key, iv_ecb, decryption_mode)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def decrypt_aes_cbc(key, iv, data):
    cipher = Cipher("aes_256_cbc", key, iv, decryption_mode)
    cipher_text = cipher.update(data) + cipher.final()
    return cipher_text


def get_pbk(salt, iter):
    key = pbkdf2(password, salt, iter, 32)
    return key


if __name__ == '__main__':
    # TestRule1c code
    testRule1c = TestRule1c()
    print("M2Crypto -> rule1 -> p_example1_hard_coded1:", decrypt_aes_ecb(key, testRule1c.p_example1_hard_coded(key, plaintext)) == plaintext)
    print("M2Crypto -> rule1 -> p_example2_local_variable1:", decrypt_aes_ecb(key, testRule1c.p_example2_local_variable(key, plaintext)) == plaintext)
    print("M2Crypto -> rule1 -> p_example3_nested_local_variable1:", decrypt_aes_ecb(key, testRule1c.p_example3_nested_local_variable(key, plaintext)) == plaintext)
    print("M2Crypto -> rule1 -> p_example4_direct_method_call1:", decrypt_aes_ecb(key, testRule1c.p_example4_direct_method_call(key, plaintext)) == plaintext)
    print("M2Crypto -> rule1 -> p_example5_nested_method_call1:", decrypt_aes_ecb(key, testRule1c.p_example5_nested_method_call(key, plaintext)) == plaintext)
    print("M2Crypto -> rule1 -> p_example6_direct_g_variable_access1:", decrypt_aes_ecb(key, testRule1c.p_example6_direct_g_variable_access(key, plaintext)) == plaintext)
    print("M2Crypto -> rule1 -> p_example7_indirect_g_variable_access1:", decrypt_aes_ecb(key, testRule1c.p_example7_indirect_g_variable_access(key, plaintext)) == plaintext)
    print("M2Crypto -> rule1 -> p_example8_warning_parameter_not_resolvable:", decrypt_aes_ecb(key, testRule1c.p_example8_warning_parameter_not_resolvable(key, plaintext, algorithm)) == plaintext)
    print("M2Crypto -> rule1 -> n_example1_cbc:", testRule1c.n_example1_cbc(key, iv_cbc, plaintext))

    # TestRule2c code
    testRule2c = TestRule2c()
    print("M2Crypto -> rule2 -> p_example1_hard_coded1:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example1_hard_coded1(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example2_hard_coded2:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example2_hard_coded2(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example3_local_variable1:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example3_local_variable1(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example4_local_variable2:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example4_local_variable2(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example5_nested_local_variable1:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example5_nested_local_variable1(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example6_nested_local_variable2:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example6_nested_local_variable2(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example7_direct_method_call1:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example7_direct_method_call1(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example8_direct_method_call2:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example8_direct_method_call2(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example9_nested_method_call1:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example9_nested_method_call1(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example10_nested_method_call2:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example10_nested_method_call2(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example11_direct_g_variable_access1:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example11_direct_g_variable_access1(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example12_direct_g_variable_access2:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example12_direct_g_variable_access2(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example13_indirect_g_variable_access1:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example13_indirect_g_variable_access1(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example14_indirect_g_variable_access2:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example14_indirect_g_variable_access2(key, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> p_example15_warning_parameter_not_resolvable:", decrypt_aes_cbc(key, iv_cbc, testRule2c.p_example15_warning_parameter_not_resolvable(key, iv_cbc, plaintext)) == plaintext)
    print("M2Crypto -> rule2 -> n_example1_secrets_system_random:", testRule2c.n_example1_secrets_system_random(key, plaintext))

    # TestRule3c code
    testRule3c = TestRule3c()
    print("M2Crypto -> rule3 -> p_example1_hard_coded1:", decrypt_aes_ecb(key, testRule3c.p_example1_hard_coded1(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example2_hard_coded2:", decrypt_aes_ecb(key, testRule3c.p_example2_hard_coded2(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example3_local_variable1:", decrypt_aes_ecb(key, testRule3c.p_example3_local_variable1(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example4_local_variable2:", decrypt_aes_ecb(key, testRule3c.p_example4_local_variable2(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example5_nested_local_variable1:", decrypt_aes_ecb(key, testRule3c.p_example5_nested_local_variable1(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example6_nested_local_variable2:", decrypt_aes_ecb(key, testRule3c.p_example6_nested_local_variable2(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example7_direct_method_call1:", decrypt_aes_ecb(key, testRule3c.p_example7_direct_method_call1(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example8_direct_method_call2:", decrypt_aes_ecb(key, testRule3c.p_example8_direct_method_call2(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example9_nested_method_call1:", decrypt_aes_ecb(key, testRule3c.p_example9_nested_method_call1(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example10_nested_method_call2:", decrypt_aes_ecb(key, testRule3c.p_example10_nested_method_call2(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example11_direct_g_variable_access1:", decrypt_aes_ecb(key, testRule3c.p_example11_direct_g_variable_access1(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example12_direct_g_variable_access2:", decrypt_aes_ecb(key, testRule3c.p_example12_direct_g_variable_access2(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example13_indirect_g_variable_access1:", decrypt_aes_ecb(key, testRule3c.p_example13_indirect_g_variable_access1(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example14_indirect_g_variable_access2:", decrypt_aes_ecb(key, testRule3c.p_example14_indirect_g_variable_access2(plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> p_example15_warning_parameter_not_resolvable:", decrypt_aes_ecb(key, testRule3c.p_example15_warning_parameter_not_resolvable(key, plaintext)) == plaintext)
    print("M2Crypto -> rule3 -> n_example1_random_key:", testRule3c.n_example1_random_key(plaintext))

    # TestRule4c code
    testRule4c = TestRule4c()
    print("M2Crypto -> rule4 -> p_example1_hard_coded1:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example1_hard_coded1(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example2_hard_coded2:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example2_hard_coded2(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example3_local_variable1:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example3_local_variable1(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example4_local_variable2:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example4_local_variable2(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example5_nested_local_variable1:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example5_nested_local_variable1(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example6_nested_local_variable2:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example6_nested_local_variable2(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example7_direct_method_call1:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example7_direct_method_call1(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example8_direct_method_call2:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example8_direct_method_call2(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example9_nested_method_call1:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example9_nested_method_call1(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example10_nested_method_call2:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example10_nested_method_call2(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example11_direct_g_variable_access1:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example11_direct_g_variable_access1(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example12_direct_g_variable_access2:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example12_direct_g_variable_access2(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example13_indirect_g_variable_access1:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example13_indirect_g_variable_access1(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example14_indirect_g_variable_access2:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example14_indirect_g_variable_access2(password, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> p_example15_warning_parameter_not_resolvable:", decrypt_aes_ecb(get_pbk(salt, iter_eq_1000), testRule4c.p_example15_warning_parameter_not_resolvable(password, salt, plaintext)) == plaintext)
    print("M2Crypto -> rule4 -> n_example1_random_salt:", testRule4c.n_example1_random_salt(password, plaintext))

    # TestRule5c code
    testRule5c = TestRule5c()
    print("M2Crypto -> rule5 -> p_example1_hard_coded1:", decrypt_aes_ecb(get_pbk(salt, iter_eq_999), testRule5c.p_example1_hard_coded(password, plaintext)) == plaintext)
    print("M2Crypto -> rule5 -> p_example2_local_variable:", decrypt_aes_ecb(get_pbk(salt, iter_eq_999), testRule5c.p_example2_local_variable(password, plaintext)) == plaintext)
    print("M2Crypto -> rule5 -> p_example3_nested_local_variable:", decrypt_aes_ecb(get_pbk(salt, iter_eq_999), testRule5c.p_example3_nested_local_variable(password, plaintext)) == plaintext)
    print("M2Crypto -> rule5 -> p_example4_direct_method_call:", decrypt_aes_ecb(get_pbk(salt, iter_eq_999), testRule5c.p_example4_direct_method_call(password, plaintext)) == plaintext)
    print("M2Crypto -> rule5 -> p_example5_nested_method_call:", decrypt_aes_ecb(get_pbk(salt, iter_eq_999), testRule5c.p_example5_nested_method_call(password, plaintext)) == plaintext)
    print("M2Crypto -> rule5 -> p_example6_direct_g_variable_access:", decrypt_aes_ecb(get_pbk(salt, iter_eq_999), testRule5c.p_example6_direct_g_variable_access(password, plaintext)) == plaintext)
    print("M2Crypto -> rule5 -> p_example7_indirect_g_variable_access:", decrypt_aes_ecb(get_pbk(salt, iter_eq_999), testRule5c.p_example7_indirect_g_variable_access(password, plaintext)) == plaintext)
    print("M2Crypto -> rule5 -> p_example8_warning_parameter_not_resolvable:", decrypt_aes_ecb(get_pbk(salt, 1000), testRule5c.p_example8_warning_parameter_not_resolvable(password, iter_eq_1000, plaintext)) == plaintext)
    print("M2Crypto -> rule5 -> n_example1_iterations_eq_1000:", testRule5c.n_example1_iterations_eq_1000(password, plaintext))
