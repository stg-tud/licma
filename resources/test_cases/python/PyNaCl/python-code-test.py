from nacl.secret import SecretBox
from nacl.pwhash.argon2i import kdf
import TestRule3
import TestRule4

g_key = b"12345678123456781234567812345678"
g_nonce = b"123456781234567812345678"  # 24 byte
g_password = b"12345678123456781234567812345678"
g_salt = b"1234567812345678"
g_plaintext = b"abcdefghijklmnop"


def decrypt(key, data):
    secret_box = SecretBox(key)
    cipher_text = secret_box.decrypt(data, g_nonce)
    return cipher_text


def get_pbk(salt):
    return kdf(32, g_password, salt)


if __name__ == '__main__':
    # TestRule3 code
    print("PyNaCl -> rule3 -> p_example1_hard_coded1:",
          decrypt(g_key, TestRule3.p_example1_hard_coded1(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example2_hard_coded2:",
          decrypt(g_key, TestRule3.p_example2_hard_coded2(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example3_local_variable1:",
          decrypt(g_key, TestRule3.p_example3_local_variable1(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example4_local_variable2:",
          decrypt(g_key, TestRule3.p_example4_local_variable2(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example5_nested_local_variable1:",
          decrypt(g_key, TestRule3.p_example5_nested_local_variable1(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example6_nested_local_variable2:",
          decrypt(g_key, TestRule3.p_example6_nested_local_variable2(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example7_direct_method_call1:",
          decrypt(g_key, TestRule3.p_example7_direct_method_call1(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example8_direct_method_call2:",
          decrypt(g_key, TestRule3.p_example8_direct_method_call2(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example9_nested_method_call1:",
          decrypt(g_key, TestRule3.p_example9_nested_method_call1(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example10_nested_method_call2:",
          decrypt(g_key, TestRule3.p_example10_nested_method_call2(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example11_direct_g_variable_access1:",
          decrypt(g_key, TestRule3.p_example11_direct_g_variable_access1(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example12_direct_g_variable_access2:",
          decrypt(g_key, TestRule3.p_example12_direct_g_variable_access2(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example13_indirect_g_variable_access1:",
          decrypt(g_key, TestRule3.p_example13_indirect_g_variable_access1(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example14_indirect_g_variable_access2:",
          decrypt(g_key, TestRule3.p_example14_indirect_g_variable_access2(g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> p_example15_warning_parameter_not_resolvable:", decrypt(g_key,
                                                                                      TestRule3.p_example15_warning_parameter_not_resolvable(
                                                                                          g_key, g_plaintext)[
                                                                                      24:]) == g_plaintext)
    print("PyNaCl -> rule3 -> n_example1_random_key:", TestRule3.n_example1_random_key(g_plaintext))

    # TestRule4 code
    print("PyNaCl -> rule4 -> p_example1_hard_coded1:",
          decrypt(get_pbk(g_salt), TestRule4.p_example1_hard_coded1(g_password, g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example2_hard_coded2:",
          decrypt(get_pbk(g_salt), TestRule4.p_example2_hard_coded2(g_password, g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example3_local_variable1:",
          decrypt(get_pbk(g_salt), TestRule4.p_example3_local_variable1(g_password, g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example4_local_variable2:",
          decrypt(get_pbk(g_salt), TestRule4.p_example4_local_variable2(g_password, g_plaintext)[24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example5_nested_local_variable1:", decrypt(get_pbk(g_salt),
                                                                           TestRule4.p_example5_nested_local_variable1(
                                                                               g_password, g_plaintext)[
                                                                           24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example6_nested_local_variable2:", decrypt(get_pbk(g_salt),
                                                                           TestRule4.p_example6_nested_local_variable2(
                                                                               g_password, g_plaintext)[
                                                                           24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example7_direct_method_call1:", decrypt(get_pbk(g_salt),
                                                                        TestRule4.p_example7_direct_method_call1(
                                                                            g_password, g_plaintext)[
                                                                        24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example8_direct_method_call2:", decrypt(get_pbk(g_salt),
                                                                        TestRule4.p_example8_direct_method_call2(
                                                                            g_password, g_plaintext)[
                                                                        24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example9_nested_method_call1:", decrypt(get_pbk(g_salt),
                                                                        TestRule4.p_example9_nested_method_call1(
                                                                            g_password, g_plaintext)[
                                                                        24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example10_nested_method_call2:", decrypt(get_pbk(g_salt),
                                                                         TestRule4.p_example10_nested_method_call2(
                                                                             g_password, g_plaintext)[
                                                                         24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example11_direct_g_variable_access1:", decrypt(get_pbk(g_salt),
                                                                               TestRule4.p_example11_direct_g_variable_access1(
                                                                                   g_password, g_plaintext)[
                                                                               24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example12_direct_g_variable_access2:", decrypt(get_pbk(g_salt),
                                                                               TestRule4.p_example12_direct_g_variable_access2(
                                                                                   g_password, g_plaintext)[
                                                                               24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example13_indirect_g_variable_access1:", decrypt(get_pbk(g_salt),
                                                                                 TestRule4.p_example13_indirect_g_variable_access1(
                                                                                     g_password, g_plaintext)[
                                                                                 24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example14_indirect_g_variable_access2:", decrypt(get_pbk(g_salt),
                                                                                 TestRule4.p_example14_indirect_g_variable_access2(
                                                                                     g_password, g_plaintext)[
                                                                                 24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> p_example15_warning_parameter_not_resolvable:", decrypt(get_pbk(g_salt),
                                                                                      TestRule4.p_example15_warning_parameter_not_resolvable(
                                                                                          g_password, g_salt,
                                                                                          g_plaintext)[
                                                                                      24:]) == g_plaintext)
    print("PyNaCl -> rule4 -> n_example1_random_salt:", TestRule4.n_example1_random_salt(g_password, g_plaintext))
