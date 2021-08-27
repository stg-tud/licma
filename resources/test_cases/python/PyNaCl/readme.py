from nacl.utils import random
from nacl.secret import SecretBox
"""
No example code for rule 1 because it is not possible to select the encryption mode, e.g. p_example1_encrypt.
No example code for rule 2 because it is not possible to set a value for iv
No example code for rule 5 because if opslimit is set to 1000 or greater the algorithm needs to much time.
No example code for rule 6 because the random function has no seed parameter, e.g. p_example2_random
"""

def p_example1_encrypt():
    """
    https://pynacl.readthedocs.io/en/stable/secret/
    """
    key = random(SecretBox.KEY_SIZE)
    plaintext = b"abcdefghijklmnop"
    secret_box = SecretBox(key)
    cipher_text = secret_box.encrypt(plaintext)
    return cipher_text


def p_example2_random():
    """
    https://pynacl.readthedocs.io/en/stable/secret/
    """
    return random(SecretBox.KEY_SIZE)
