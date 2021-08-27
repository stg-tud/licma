import unittest

from licma.babel_fish.babel_fish import BabelFish
from licma.rules.python.pyrules_cryptography.pyrule1_cryptography import PyRule1Cryptography
from licma.rules.python.pyrules_cryptography.pyrule2_cryptography import PyRule2Cryptography
from licma.rules.python.pyrules_cryptography.pyrule3_cryptography import PyRule3Cryptography
from licma.rules.python.pyrules_cryptography.pyrule4_cryptography import PyRule4Cryptography
from licma.rules.python.pyrules_cryptography.pyrule5_cryptography import PyRule5Cryptography
from licma.tests.test_utilities import UnitTestBase


class PyRuleCryptographyTestOOP(UnitTestBase):
    babel_fish = BabelFish()

    def test_pyrule1_cryptography_oop(self):
        self.execute_test(PyRule1Cryptography(),
                          "../resources/test_cases/python/cryptography/TestRule1c.py",
                          "../resources/test_cases/python/cryptography/TestRule1cExpectedMisuses.csv")

    def test_pyrule2_cryptography_oop(self):
        self.execute_test(PyRule2Cryptography(),
                          "../resources/test_cases/python/cryptography/TestRule2c.py",
                          "../resources/test_cases/python/cryptography/TestRule2cExpectedMisuses.csv")

    def test_pyrule3_cryptography_oop(self):
        self.execute_test(PyRule3Cryptography(),
                          "../resources/test_cases/python/cryptography/TestRule3c.py",
                          "../resources/test_cases/python/cryptography/TestRule3cExpectedMisuses.csv")

    def test_pyrule4_cryptography_oop(self):
        self.execute_test(PyRule4Cryptography(),
                          "../resources/test_cases/python/cryptography/TestRule4c.py",
                          "../resources/test_cases/python/cryptography/TestRule4cExpectedMisuses.csv")

    def test_pyrule5_cryptography_oop(self):
        self.execute_test(PyRule5Cryptography(),
                          "../resources/test_cases/python/cryptography/TestRule5c.py",
                          "../resources/test_cases/python/cryptography/TestRule5cExpectedMisuses.csv")


if __name__ == '__main__':
    unittest.main()
