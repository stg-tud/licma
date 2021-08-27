#!/bin/bash

echo Run test_pyrules_pycrypto_oop.py
python3 -m unittest licma/tests/test_pyrules_pycrypto_oop.py

echo Run test_pyrules_m2crypto_oop.py
python3 -m unittest licma/tests/test_pyrules_m2crypto_oop.py

echo Run test_pyrules_pynacl_oop.py
python3 -m unittest licma/tests/test_pyrules_pynacl_oop.py

echo Run test_pyrules_ucryptolib_oop.py
python3 -m unittest licma/tests/test_pyrules_ucryptolib_oop.py

echo Run test_pyrules_cryptography_oop.py
python3 -m unittest licma/tests/test_pyrules_cryptography_oop.py
