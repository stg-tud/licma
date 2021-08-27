import unittest

from licma.babel_fish.babel_fish import BabelFish
from licma.tests.test_utilities import UnitTestBase
from licma.rules.python.pyrules_m2crypto.pyrule1_m2crypto import PyRule1M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule2_m2crypto import PyRule2M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule3_m2crypto import PyRule3M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule4_m2crypto import PyRule4M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule5_m2crypto import PyRule5M2Crypto


class PyRuleM2CryptoTest(UnitTestBase):
    babel_fish = BabelFish()

    def test_pyrule1_m2crypto(self):
        self.execute_test(PyRule1M2Crypto(),
                          "../resources/test_cases/python/M2Crypto/TestRule1.py",
                          "../resources/test_cases/python/M2Crypto/TestRule1ExpectedMisuses.csv")

    def test_pyrule2_m2crypto(self):
        self.execute_test(PyRule2M2Crypto(),
                          "../resources/test_cases/python/M2Crypto/TestRule2.py",
                          "../resources/test_cases/python/M2Crypto/TestRule2ExpectedMisuses.csv")

    def test_pyrule3_m2crypto(self):
        self.execute_test(PyRule3M2Crypto(),
                          "../resources/test_cases/python/M2Crypto/TestRule3.py",
                          "../resources/test_cases/python/M2Crypto/TestRule3ExpectedMisuses.csv")

    def test_pyrule4_m2crypto(self):
        self.execute_test(PyRule4M2Crypto(),
                          "../resources/test_cases/python/M2Crypto/TestRule4.py",
                          "../resources/test_cases/python/M2Crypto/TestRule4ExpectedMisuses.csv")

    def test_pyrule5_m2crypto(self):
        self.execute_test(PyRule5M2Crypto(),
                          "../resources/test_cases/python/M2Crypto/TestRule5.py",
                          "../resources/test_cases/python/M2Crypto/TestRule5ExpectedMisuses.csv")


if __name__ == '__main__':
    unittest.main()
