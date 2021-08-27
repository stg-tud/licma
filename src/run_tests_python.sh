#!/bin/bash

echo Run test_pyrules_pycrypto.py
python3 -m unittest licma/tests/test_pyrules_pycrypto.py

echo Run test_pyrules_m2crypto.py
python3 -m unittest licma/tests/test_pyrules_m2crypto.py

echo Run test_pyrules_pynacl.py
python3 -m unittest licma/tests/test_pyrules_pynacl.py

echo Run test_pyrules_ucryptolib.py
python3 -m unittest licma/tests/test_pyrules_ucryptolib.py

echo Run test_pyrules_cryptography.py
python3 -m unittest licma/tests/test_pyrules_cryptography.py
