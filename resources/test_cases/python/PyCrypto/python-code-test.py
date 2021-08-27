from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import TestRule1
import TestRule2
import TestRule3
import TestRule4
import TestRule5

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
    # TestRule1 code
    print("PyCrypto -> rule1 -> p_example1_hard_coded1:",
          decrypt_aes_ecb(g_key, TestRule1.p_example1_hard_coded1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example2_hard_coded2:",
          decrypt_aes_ecb(g_key, TestRule1.p_example2_hard_coded2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example3_local_variable1:",
          decrypt_aes_ecb(g_key, TestRule1.p_example3_local_variable1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example4_local_variable2:",
          decrypt_aes_ecb(g_key, TestRule1.p_example4_local_variable2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example5_nested_local_variable1:",
          decrypt_aes_ecb(g_key, TestRule1.p_example5_nested_local_variable1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example6_nested_local_variable2:",
          decrypt_aes_ecb(g_key, TestRule1.p_example6_nested_local_variable2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example7_direct_method_call1:",
          decrypt_aes_ecb(g_key, TestRule1.p_example7_direct_method_call1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example8_direct_method_call2:",
          decrypt_aes_ecb(g_key, TestRule1.p_example8_direct_method_call2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example9_nested_method_call1:",
          decrypt_aes_ecb(g_key, TestRule1.p_example9_nested_method_call1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example10_nested_method_call2:",
          decrypt_aes_ecb(g_key, TestRule1.p_example10_nested_method_call2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example11_direct_g_variable_access1:",
          decrypt_aes_ecb(g_key, TestRule1.p_example11_direct_g_variable_access1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example12_direct_g_variable_access2:",
          decrypt_aes_ecb(g_key, TestRule1.p_example12_direct_g_variable_access2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example13_indirect_g_variable_access1:",
          decrypt_aes_ecb(g_key, TestRule1.p_example13_indirect_g_variable_access1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example14_indirect_g_variable_access2:",
          decrypt_aes_ecb(g_key, TestRule1.p_example14_indirect_g_variable_access2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule1 -> p_example15_warning_parameter_not_resolvable:", decrypt_aes_ecb(g_key,
                                                                                                TestRule1.p_example15_warning_parameter_not_resolvable(
                                                                                                    g_key, g_plaintext,
                                                                                                    g_mode)) == g_plaintext)
    print("PyCrypto -> rule1 -> n_example1_cbc:", TestRule1.n_example1_cbc(g_key, g_iv, g_plaintext))

    # TestRule2 code
    print("PyCrypto -> rule2 -> p_example1_hard_coded1:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example1_hard_coded1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example2_hard_coded2:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example2_hard_coded2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example3_local_variable1:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example3_local_variable1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example4_local_variable2:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example4_local_variable2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example5_nested_local_variable1:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example5_nested_local_variable1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example6_nested_local_variable2:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example6_nested_local_variable2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example7_direct_method_call1:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example7_direct_method_call1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example8_direct_method_call2:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example8_direct_method_call2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example9_nested_method_call1:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example9_nested_method_call1(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example10_nested_method_call2:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example10_nested_method_call2(g_key, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example11_direct_g_variable_access1:", decrypt_aes_cbc(g_key, g_iv,
                                                                                         TestRule2.p_example11_direct_g_variable_access1(
                                                                                             g_key,
                                                                                             g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example12_direct_g_variable_access2:", decrypt_aes_cbc(g_key, g_iv,
                                                                                         TestRule2.p_example12_direct_g_variable_access2(
                                                                                             g_key,
                                                                                             g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example13_indirect_g_variable_access1:", decrypt_aes_cbc(g_key, g_iv,
                                                                                           TestRule2.p_example13_indirect_g_variable_access1(
                                                                                               g_key,
                                                                                               g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example14_indirect_g_variable_access2:", decrypt_aes_cbc(g_key, g_iv,
                                                                                           TestRule2.p_example14_indirect_g_variable_access2(
                                                                                               g_key,
                                                                                               g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> p_example15_warning_parameter_not_resolvable:", decrypt_aes_cbc(g_key, g_iv,
                                                                                                TestRule2.p_example15_warning_parameter_not_resolvable(
                                                                                                    g_key, g_iv,
                                                                                                    g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule2 -> n_example1_secrets_system_random:",
          TestRule2.n_example1_secrets_system_random(g_key, g_plaintext))

    # TestRule3 code
    print("PyCrypto -> rule3 -> p_example1_hard_coded1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example1_hard_coded1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example2_hard_coded2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example2_hard_coded2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example3_local_variable1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example3_local_variable1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example4_local_variable2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example4_local_variable2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example5_nested_local_variable1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example5_nested_local_variable1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example6_nested_local_variable2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example6_nested_local_variable2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example7_direct_method_call1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example7_direct_method_call1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example8_direct_method_call2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example8_direct_method_call2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example9_nested_method_call1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example9_nested_method_call1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example10_nested_method_call2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example10_nested_method_call2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example11_direct_g_variable_access1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example11_direct_g_variable_access1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example12_direct_g_variable_access2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example12_direct_g_variable_access2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example13_indirect_g_variable_access1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example13_indirect_g_variable_access1(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example14_indirect_g_variable_access2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example14_indirect_g_variable_access2(g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> p_example15_warning_parameter_not_resolvable:", decrypt_aes_ecb(g_key,
                                                                                                TestRule3.p_example15_warning_parameter_not_resolvable(
                                                                                                    g_key,
                                                                                                    g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule3 -> n_example1_random_key:", TestRule3.n_example1_random_key(g_plaintext))

    # TestRule4 code
    print("PyCrypto -> rule4 -> p_example1_hard_coded1:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                          TestRule4.p_example1_hard_coded1(g_password,
                                                                                                           g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example2_hard_coded2:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                          TestRule4.p_example2_hard_coded2(g_password,
                                                                                                           g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example3_local_variable1:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                              TestRule4.p_example3_local_variable1(
                                                                                  g_password,
                                                                                  g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example4_local_variable2:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                              TestRule4.p_example4_local_variable2(
                                                                                  g_password,
                                                                                  g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example5_nested_local_variable1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          TestRule4.p_example5_nested_local_variable1(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example6_nested_local_variable2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          TestRule4.p_example6_nested_local_variable2(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example7_direct_method_call1:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                                  TestRule4.p_example7_direct_method_call1(
                                                                                      g_password,
                                                                                      g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example8_direct_method_call2:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                                  TestRule4.p_example8_direct_method_call2(
                                                                                      g_password,
                                                                                      g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example9_nested_method_call1:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                                  TestRule4.p_example9_nested_method_call1(
                                                                                      g_password,
                                                                                      g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example10_nested_method_call2:", decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                                                                                   TestRule4.p_example10_nested_method_call2(
                                                                                       g_password,
                                                                                       g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example11_direct_g_variable_access1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          TestRule4.p_example11_direct_g_variable_access1(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example12_direct_g_variable_access2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          TestRule4.p_example12_direct_g_variable_access2(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example13_indirect_g_variable_access1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          TestRule4.p_example13_indirect_g_variable_access1(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example14_indirect_g_variable_access2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          TestRule4.p_example14_indirect_g_variable_access2(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> p_example15_warning_parameter_not_resolvable:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_equal_1000),
                          TestRule4.p_example15_warning_parameter_not_resolvable(g_password, g_salt,
                                                                                 g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule4 -> n_example1_random_salt:", TestRule4.n_example1_random_salt(g_password, g_plaintext))

    # TestRule5 code
    print("PyCrypto -> rule5 -> p_example1_hard_coded1:", decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                                                                          TestRule5.p_example1_hard_coded(g_password,
                                                                                                          g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example2_local_variable:", decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                                                                             TestRule5.p_example2_local_variable(
                                                                                 g_password,
                                                                                 g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example3_nested_local_variable:", decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                                                                                    TestRule5.p_example3_nested_local_variable(
                                                                                        g_password,
                                                                                        g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example4_direct_method_call:", decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                                                                                 TestRule5.p_example4_direct_method_call(
                                                                                     g_password,
                                                                                     g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example5_nested_method_call:", decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                                                                                 TestRule5.p_example5_nested_method_call(
                                                                                     g_password,
                                                                                     g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example6_direct_g_variable_access:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                          TestRule5.p_example6_direct_g_variable_access(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example7_indirect_g_variable_access:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                          TestRule5.p_example7_indirect_g_variable_access(g_password, g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> p_example8_warning_parameter_not_resolvable:",
          decrypt_aes_ecb(get_pbk(g_salt, g_count_lower_1000),
                          TestRule5.p_example8_warning_parameter_not_resolvable(g_password, g_count_lower_1000,
                                                                                g_plaintext)) == g_plaintext)
    print("PyCrypto -> rule5 -> n_example1_random_salt:",
          TestRule5.n_example1_iterations_eq_1000(g_password, g_plaintext))
