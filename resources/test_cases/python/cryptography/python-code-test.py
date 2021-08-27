import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import TestRule1
import TestRule2
import TestRule3
import TestRule4
import TestRule5

g_backend = default_backend()
g_key = b"1234567812345678"
g_key_fernet = base64.urlsafe_b64encode(b"12345678123456781234567812345678")
g_iv = b"1234567812345678"
g_password = b"12345678"
g_salt = b"12345678"
g_iterations_lower_1000 = 999
g_iterations_equal = 1000
g_plaintext = b"abcdefghijklmnop"
g_mode = modes.ECB()


def decrypt_aes_ecb(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=g_backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(data) + decryptor.finalize()
    return plaintext


def decrypt_aes_cbc(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=g_backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(data) + decryptor.finalize()
    return plaintext


def decrypt_fernet(key, data):
    fernet = Fernet(key)
    plaintext = fernet.decrypt(data)
    return plaintext


def get_pbk(salt, iterations):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=iterations, backend=g_backend)
    key = kdf.derive(g_password)
    return key


if __name__ == '__main__':
    # TestRule1 code
    print("cryptography -> rule1 -> p_example1_hard_coded:",
          decrypt_aes_ecb(g_key, TestRule1.p_example1_hard_coded(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule1 -> p_example2_local_variable:",
          decrypt_aes_ecb(g_key, TestRule1.p_example2_local_variable(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule1 -> p_example3_nested_local_variable:",
          decrypt_aes_ecb(g_key, TestRule1.p_example3_nested_local_variable(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule1 -> p_example4_direct_method_call:",
          decrypt_aes_ecb(g_key, TestRule1.p_example4_direct_method_call(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule1 -> p_example5_nested_method_call:",
          decrypt_aes_ecb(g_key, TestRule1.p_example5_nested_method_call(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule1 -> p_example6_direct_g_variable_access:",
          decrypt_aes_ecb(g_key, TestRule1.p_example6_direct_g_variable_access(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule1 -> p_example7_indirect_g_variable_access:",
          decrypt_aes_ecb(g_key, TestRule1.p_example7_indirect_g_variable_access(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule1 -> p_example8_warning_parameter_not_resolvable:",
          decrypt_aes_ecb(g_key, TestRule1.p_example8_warning_parameter_not_resolvable(g_key, g_plaintext,
                                                                                       g_mode)) == g_plaintext)
    print("cryptography -> rule1 -> n_example1_cbc:", TestRule1.n_example1_cbc(g_key, g_plaintext))

    # TestRule2 code
    print("cryptography -> rule2 -> p_example1_hard_coded1:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example1_hard_coded1(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example2_hard_coded2:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example2_hard_coded2(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example3_local_variable1:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example3_local_variable1(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example4_local_variable2:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example4_local_variable2(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example5_nested_local_variable1:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example5_nested_local_variable1(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example6_nested_local_variable2:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example6_nested_local_variable2(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example7_direct_method_call1:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example7_direct_method_call1(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example8_direct_method_call2:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example8_direct_method_call2(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example9_nested_method_call1:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example9_nested_method_call1(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example10_nested_method_call2:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example10_nested_method_call2(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example11_direct_g_variable_access1:",
          decrypt_aes_cbc(g_key, g_iv,
                          TestRule2.p_example11_direct_g_variable_access1(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example12_direct_g_variable_access2:",
          decrypt_aes_cbc(g_key, g_iv,
                          TestRule2.p_example12_direct_g_variable_access2(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example13_indirect_g_variable_access1:",
          decrypt_aes_cbc(g_key, g_iv,
                          TestRule2.p_example13_indirect_g_variable_access1(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example14_indirect_g_variable_access2:",
          decrypt_aes_cbc(g_key, g_iv,
                          TestRule2.p_example14_indirect_g_variable_access2(g_key, g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> p_example15_warning_parameter_not_resolvable:",
          decrypt_aes_cbc(g_key, g_iv, TestRule2.p_example15_warning_parameter_not_resolvable(g_key, g_iv,
                                                                                              g_plaintext)) == g_plaintext)
    print("cryptography -> rule2 -> n_example1_cbc:",
          TestRule2.n_example1_cbc(g_key, g_plaintext))

    # TestRule3 code
    print("cryptography -> rule3 -> p_example1_hard_coded1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example1_hard_coded1(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example2_hard_coded2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example2_hard_coded2(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example3_hard_coded3:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example3_hard_coded3(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example4_hard_coded4:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example4_hard_coded4(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example5_local_variable1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example5_local_variable1(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example6_local_variable2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example6_local_variable2(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example7_local_variable3:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example7_local_variable3(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example8_local_variable4:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example8_local_variable4(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example9_nested_local_variable1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example9_nested_local_variable1(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example10_nested_local_variable2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example10_nested_local_variable2(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example11_nested_local_variable3:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example11_nested_local_variable3(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example12_nested_local_variable4:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example12_nested_local_variable4(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example13_direct_method_call1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example13_direct_method_call1(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example14_direct_method_call2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example14_direct_method_call2(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example15_direct_method_call3:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example15_direct_method_call3(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example16_direct_method_call4:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example16_direct_method_call4(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example17_nested_method_call1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example17_nested_method_call1(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example18_nested_method_call2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example18_nested_method_call2(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example19_nested_method_call3:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example19_nested_method_call3(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example20_nested_method_call4:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example20_nested_method_call4(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example21_direct_g_variable_access1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example21_direct_g_variable_access1(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example22_direct_g_variable_access2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example22_direct_g_variable_access2(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example23_direct_g_variable_access3:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example23_direct_g_variable_access3(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example24_direct_g_variable_access4:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example24_direct_g_variable_access4(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example25_indirect_g_variable_access1:",
          decrypt_aes_ecb(g_key, TestRule3.p_example25_indirect_g_variable_access1(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example26_indirect_g_variable_access2:",
          decrypt_aes_ecb(g_key, TestRule3.p_example26_indirect_g_variable_access2(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example27_indirect_g_variable_access3:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example27_indirect_g_variable_access3(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example28_indirect_g_variable_access4:",
          decrypt_fernet(g_key_fernet, TestRule3.p_example28_indirect_g_variable_access4(g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example29_warning_parameter_not_resolvable1:", decrypt_aes_ecb(g_key,
                                                                                                     TestRule3.p_example29_warning_parameter_not_resolvable1(
                                                                                                         g_key,
                                                                                                         g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> p_example30_warning_parameter_not_resolvable2:", decrypt_fernet(g_key_fernet,
                                                                                                    TestRule3.p_example30_warning_parameter_not_resolvable2(
                                                                                                        g_key_fernet,
                                                                                                        g_plaintext)) == g_plaintext)
    print("cryptography -> rule3 -> n_example1_random_key1:", TestRule3.n_example1_random_key1(g_plaintext))
    print("cryptography -> rule3 -> n_example2_random_key2:", TestRule3.n_example2_random_key2(g_plaintext))

    # TestRule4 code
    print("cryptography -> rule4 -> p_example1_hard_coded1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example1_hard_coded1(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example2_hard_coded2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example2_hard_coded2(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example3_local_variable1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example3_local_variable1(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example4_local_variable2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example4_local_variable2(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example5_nested_local_variable1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example5_nested_local_variable1(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example6_nested_local_variable2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example6_nested_local_variable2(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example7_direct_method_call1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example7_direct_method_call1(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example8_direct_method_call2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example8_direct_method_call2(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example9_nested_method_call1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example9_nested_method_call1(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example10_nested_method_call2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example10_nested_method_call2(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example11_direct_g_variable_access1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example11_direct_g_variable_access1(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example12_direct_g_variable_access2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example12_direct_g_variable_access2(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example13_indirect_g_variable_access1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example13_indirect_g_variable_access1(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example14_indirect_g_variable_access2:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example14_indirect_g_variable_access2(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> p_example15_warning_parameter_not_resolvable:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_equal),
                          TestRule4.p_example15_warning_parameter_not_resolvable(g_password, g_salt,
                                                                                 g_plaintext)) == g_plaintext)
    print("cryptography -> rule4 -> n_example1_random_salt:", TestRule4.n_example1_random_salt(g_password, g_plaintext))

    # TestRule5 code
    print("cryptography -> rule5 -> p_example1_hard_coded1:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_lower_1000),
                          TestRule5.p_example1_hard_coded(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule5 -> p_example2_local_variable:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_lower_1000),
                          TestRule5.p_example2_local_variable(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule5 -> p_example3_nested_local_variable:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_lower_1000),
                          TestRule5.p_example3_nested_local_variable(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule5 -> p_example4_direct_method_call:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_lower_1000),
                          TestRule5.p_example4_direct_method_call(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule5 -> p_example5_nested_method_call:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_lower_1000),
                          TestRule5.p_example5_nested_method_call(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule5 -> p_example6_direct_g_variable_access:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_lower_1000),
                          TestRule5.p_example6_direct_g_variable_access(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule5 -> p_example7_indirect_g_variable_access:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_lower_1000),
                          TestRule5.p_example7_indirect_g_variable_access(g_password, g_plaintext)) == g_plaintext)
    print("cryptography -> rule5 -> p_example8_warning_parameter_not_resolvable:",
          decrypt_aes_ecb(get_pbk(g_salt, g_iterations_lower_1000),
                          TestRule5.p_example8_warning_parameter_not_resolvable(g_password, g_iterations_lower_1000,
                                                                                g_plaintext)) == g_plaintext)
    print("cryptography -> rule5 -> n_example1_random_salt:",
          TestRule5.n_example1_iterations_eq_1000(g_password, g_plaintext))
