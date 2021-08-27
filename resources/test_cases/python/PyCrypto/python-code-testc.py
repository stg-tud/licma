from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from TestRule1c import TestRule1c
from TestRule2c import TestRule2c
from TestRule3c import TestRule3c
from TestRule4c import TestRule4c
from TestRule5c import TestRule5c

g_key = b"1234567812345678"
g_iv = b"1234567812345678"
g_password = "12345678"
g_salt = b"12345678"
g_count_lower_1000 = 999
g_count_equal_1000 = 1000
g_plaintext = b"abcdefghijklmnop"
g_mode = AES.MODE_ECB


def decrypt_aes_ecb(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_text = cipher.decrypt(data)
    return cipher_text


def decrypt_aes_cbc(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.decrypt(data)
    return cipher_text


def get_pbk(salt, count):
    return PBKDF2(g_password, salt, 16, count=count)


if __name__ == '__main__':
    # TestRule1c code
    testRule1c = TestRule1c()
    print("PyCrypto -> rule1 -> p_example1_hard_coded1:",
          decrypt_aes_ecb(g_key, testRule1c.p_example1_hard_coded1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example2_hard_coded2:",
          decrypt_aes_ecb(g_key, testRule1c.p_example2_hard_coded2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example3_local_variable1:",
          decrypt_aes_ecb(g_key, testRule1c.p_example3_local_variable1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example4_local_variable2:",
          decrypt_aes_ecb(g_key, testRule1c.p_example4_local_variable2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example5_nested_local_variable1:",
          decrypt_aes_ecb(g_key, testRule1c.p_example5_nested_local_variable1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example6_nested_local_variable2:",
          decrypt_aes_ecb(g_key, testRule1c.p_example6_nested_local_variable2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example7_direct_method_call1:",
          decrypt_aes_ecb(g_key, testRule1c.p_example7_direct_method_call1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example8_direct_method_call2:",
          decrypt_aes_ecb(g_key, testRule1c.p_example8_direct_method_call2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example9_nested_method_call1:",
          decrypt_aes_ecb(g_key, testRule1c.p_example9_nested_method_call1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example10_nested_method_call2:",
          decrypt_aes_ecb(g_key, testRule1c.p_example10_nested_method_call2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example11_direct_g_variable_access1:",
          decrypt_aes_ecb(g_key, testRule1c.p_example11_direct_g_variable_access1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example12_direct_g_variable_access2:",
          decrypt_aes_ecb(g_key, testRule1c.p_example12_direct_g_variable_access2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example13_indirect_g_variable_access1:",
          decrypt_aes_ecb(g_key, testRule1c.p_example13_indirect_g_variable_access1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example14_indirect_g_variable_access2:",
          decrypt_aes_ecb(g_key, testRule1c.p_example14_indirect_g_variable_access2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example15_warning_parameter_not_resolvable:", decrypt_aes_ecb(g_key,
                                                                                                testRule1c.p_example15_warning_parameter_not_resolvable(
                                                                                                    g_key, g_plaintext,
                                                                                                    g_mode)) == g_plaintext)
    print("PyCrypto -> rule1 -> n_example1_cbc:", testRule1c.n_example1_cbc(g_key, g_iv, g_plaintext))

    # TestRule2c code
    testRule2c = TestRule2c()
    print("PyCrypto -> rule2 -> p_example1_hard_coded1:",
          decrypt_aes_cbc(g_key, g_iv, testRule2c.p_example1_hard_coded1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example2_hard_coded2:",
          decrypt_aes_cbc(g_key, g_iv, testRule2c.p_example2_hard_coded2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example3_local_variable1:",
          decrypt_aes_cbc(g_key, g_iv, testRule2c.p_example3_local_variable1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example4_local_variable2:",
          decrypt_aes_cbc(g_key, g_iv, testRule2c.p_example4_local_variable2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example5_nested_local_variable1:",
          decrypt_aes_cbc(g_key, g_iv, testRule2c.p_example5_nested_local_variable1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example6_nested_local_variable2:",
          decrypt_aes_cbc(g_key, g_iv, testRule2c.p_example6_nested_local_variable2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example7_direct_method_call1:",
          decrypt_aes_cbc(g_key, g_iv, testRule2c.p_example7_direct_method_call1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example8_direct_method_call2:",
          decrypt_aes_cbc(g_key, g_iv, testRule2c.p_example8_direct_method_call2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example9_nested_method_call1:",
          decrypt_aes_cbc(g_key, g_iv, testRule2c.p_example9_nested_method_call1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example10_nested_method_call2:",
          decrypt_aes_cbc(g_key, g_iv, testRule2c.p_example10_nested_method_call2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example11_direct_g_variable_access1:", decrypt_aes_cbc(g_key, g_iv,
                                                                                         testRule2c.p_example11_direct_g_variable_access1(
                                                                                             g_key,
                                                                                             g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example12_direct_g_variable_access2:", decrypt_aes_cbc(g_key, g_iv,
                                                                                         testRule2c.p_example12_direct_g_variable_access2(
                                                                                             g_key,
                                                                                             g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example13_indirect_g_variable_access1:", decrypt_aes_cbc(g_key, g_iv,
                                                                                           testRule2c.p_example13_indirect_g_variable_access1(
                                                                                               g_key,
                                                                                               g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example14_indirect_g_variable_access2:", decrypt_aes_cbc(g_key, g_iv,
                                                                                           testRule2c.p_example14_indirect_g_variable_access2(
                                                                                               g_key,
                                                                                               g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example15_warning_parameter_not_resolvable:", decrypt_aes_cbc(g_key, g_iv,
                                                                                                testRule2c.p_example15_warning_parameter_not_resolvable(
                                                                                                    g_key, g_iv,
                                                                                                    g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> n_example1_secrets_system_random:",
          testRule2c.n_example1_secrets_system_random(g_key, g_plaintext))

    # TestRule3c code
    testRule3c = TestRule3c()
    print("PyCrypto -> rule3 -> p_example1_hard_coded1:",
          decrypt_aes_ecb(g_key, testRule3c.p_example1_hard_coded1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example2_hard_coded2:",
          decrypt_aes_ecb(g_key, testRule3c.p_example2_hard_coded2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example3_local_variable1:",
          decrypt_aes_ecb(g_key, testRule3c.p_example3_local_variable1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example4_local_variable2:",
          decrypt_aes_ecb(g_key, testRule3c.p_example4_local_variable2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example5_nested_local_variable1:",
          decrypt_aes_ecb(g_key, testRule3c.p_example5_nested_local_variable1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example6_nested_local_variable2:",
          decrypt_aes_ecb(g_key, testRule3c.p_example6_nested_local_variable2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example7_direct_method_call1:",
          decrypt_aes_ecb(g_key, testRule3c.p_example7_direct_method_call1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example8_direct_method_call2:",
          decrypt_aes_ecb(g_key, testRule3c.p_example8_direct_method_call2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example9_nested_method_call1:",
          decrypt_aes_ecb(g_key, testRule3c.p_example9_nested_method_call1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example10_nested_method_call2:",
          decrypt_aes_ecb(g_key, testRule3c.p_example10_nested_method_call2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example11_direct_g_variable_access1:",
          decrypt_aes_ecb(g_key, testRule3c.p_example11_direct_g_variable_access1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example12_direct_g_variable_access2:",
          decrypt_aes_ecb(g_key, testRule3c.p_example12_direct_g_variable_access2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example13_indirect_g_variable_access1:",
          decrypt_aes_ecb(g_key, testRule3c.p_example13_indirect_g_variable_access1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example14_indirect_g_variable_access2:",
          decrypt_aes_ecb(g_key, testRule3c.p_example14_indirect_g_variable_access2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example15_warning_parameter_not_resolvable:", decrypt_aes_ecb(g_key,
                                                                                                testRule3c.p_example15_warning_parameter_not_resolvable(
                                                                                                    g_key,
                                                                                                    g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> n_example1_random_key:", testRule3c.n_example1_random_key(g_plaintext))

    # TestRule4c code
    testRule4c = TestRule4c()
    print("PyCrypto -> rule4 -> p_example1_hard_coded1:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                          testRule4c.p_example1_hard_coded1(g_password,
                                                                                                            g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example2_hard_coded2:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                          testRule4c.p_example2_hard_coded2(g_password,
                                                                                                            g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example3_local_variable1:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                              testRule4c.p_example3_local_variable1(
                                                                                  g_password,
                                                                                  g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example4_local_variable2:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                              testRule4c.p_example4_local_variable2(
                                                                                  g_password,
                                                                                  g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example5_nested_local_variable1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          testRule4c.p_example5_nested_local_variable1(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example6_nested_local_variable2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          testRule4c.p_example6_nested_local_variable2(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example7_direct_method_call1:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                                  testRule4c.p_example7_direct_method_call1(
                                                                                      g_password,
                                                                                      g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example8_direct_method_call2:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                                  testRule4c.p_example8_direct_method_call2(
                                                                                      g_password,
                                                                                      g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example9_nested_method_call1:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                                  testRule4c.p_example9_nested_method_call1(
                                                                                      g_password,
                                                                                      g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example10_nested_method_call2:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                                   testRule4c.p_example10_nested_method_call2(
                                                                                       g_password,
                                                                                       g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example11_direct_g_variable_access1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          testRule4c.p_example11_direct_g_variable_access1(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example12_direct_g_variable_access2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          testRule4c.p_example12_direct_g_variable_access2(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example13_indirect_g_variable_access1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          testRule4c.p_example13_indirect_g_variable_access1(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example14_indirect_g_variable_access2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          testRule4c.p_example14_indirect_g_variable_access2(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example15_warning_parameter_not_resolvable:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          testRule4c.p_example15_warning_parameter_not_resolvable(g_password, g_salt,
                                                                                  g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> n_example1_random_salt:", testRule4c.n_example1_random_salt(g_password, g_plaintext))

    # TestRule5c code
    testRule5c = TestRule5c()
    print("PyCrypto -> rule5 -> p_example1_hard_coded1:", decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                                                                          testRule5c.p_example1_hard_coded(g_password,
                                                                                                           g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example2_local_variable:", decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                                                                             testRule5c.p_example2_local_variable(
                                                                                 g_password,
                                                                                 g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example3_nested_local_variable:", decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                                                                                    testRule5c.p_example3_nested_local_variable(
                                                                                        g_password,
                                                                                        g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example4_direct_method_call:", decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                                                                                 testRule5c.p_example4_direct_method_call(
                                                                                     g_password,
                                                                                     g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example5_nested_method_call:", decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                                                                                 testRule5c.p_example5_nested_method_call(
                                                                                     g_password,
                                                                                     g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example6_direct_g_variable_access:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                          testRule5c.p_example6_direct_g_variable_access(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example7_indirect_g_variable_access:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                          testRule5c.p_example7_indirect_g_variable_access(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example8_warning_parameter_not_resolvable:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                          testRule5c.p_example8_warning_parameter_not_resolvable(g_password, g_count_lower_1000,
                                                                                 g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> n_example1_random_salt:",
          testRule5c.n_example1_iterations_eq_1000(g_password, g_plaintext))
