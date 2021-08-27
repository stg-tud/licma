import unittest

from licma.babel_fish.babel_fish import BabelFish
from licma.rules.python.pyrules_m2crypto.pyrule1_m2crypto import PyRule1M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule2_m2crypto import PyRule2M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule3_m2crypto import PyRule3M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule4_m2crypto import PyRule4M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule5_m2crypto import PyRule5M2Crypto
from licma.tests.test_utilities import UnitTestBase


class PyRuleM2CryptoTestOOP(UnitTestBase):
    babel_fish = BabelFish()

    def test_pyrule1_m2crypto_oop(self):
        self.execute_test(PyRule1M2Crypto(),
                          "../resources/test_cases/python/M2Crypto/TestRule1c.py",
                          "../resources/test_cases/python/M2Crypto/TestRule1cExpectedMisuses.csv")

    def test_pyrule2_m2crypto_oop(self):
        self.execute_test(PyRule2M2Crypto(),
                          "../resources/test_cases/python/M2Crypto/TestRule2c.py",
                          "../resources/test_cases/python/M2Crypto/TestRule2cExpectedMisuses.csv")

    def test_pyrule3_m2crypto_oop(self):
        self.execute_test(PyRule3M2Crypto(),
                          "../resources/test_cases/python/M2Crypto/TestRule3c.py",
                          "../resources/test_cases/python/M2Crypto/TestRule3cExpectedMisuses.csv")

    def test_pyrule4_m2crypto_oop(self):
        self.execute_test(PyRule4M2Crypto(),
                          "../resources/test_cases/python/M2Crypto/TestRule4c.py",
                          "../resources/test_cases/python/M2Crypto/TestRule4cExpectedMisuses.csv")

    def test_pyrule5_m2crypto_oop(self):
        self.execute_test(PyRule5M2Crypto(),
                          "../resources/test_cases/python/M2Crypto/TestRule5c.py",
                          "../resources/test_cases/python/M2Crypto/TestRule5cExpectedMisuses.csv")


if __name__ == '__main__':
    unittest.main()
