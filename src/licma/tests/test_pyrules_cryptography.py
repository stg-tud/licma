import unittest

from licma.babel_fish.babel_fish import BabelFish
from licma.rules.python.pyrules_cryptography.pyrule1_cryptography import PyRule1Cryptography
from licma.rules.python.pyrules_cryptography.pyrule2_cryptography import PyRule2Cryptography
from licma.rules.python.pyrules_cryptography.pyrule3_cryptography import PyRule3Cryptography
from licma.rules.python.pyrules_cryptography.pyrule4_cryptography import PyRule4Cryptography
from licma.rules.python.pyrules_cryptography.pyrule5_cryptography import PyRule5Cryptography
from licma.tests.test_utilities import UnitTestBase


class PyRuleCryptographyTest(UnitTestBase):
    babel_fish = BabelFish()

    def test_pyrule1_cryptography(self):
        self.execute_test(PyRule1Cryptography(),
                          "../resources/test_cases/python/cryptography/TestRule1.py",
                          "../resources/test_cases/python/cryptography/TestRule1ExpectedMisuses.csv")

    def test_pyrule2_cryptography(self):
        self.execute_test(PyRule2Cryptography(),
                          "../resources/test_cases/python/cryptography/TestRule2.py",
                          "../resources/test_cases/python/cryptography/TestRule2ExpectedMisuses.csv")

    def test_pyrule3_cryptography(self):
        self.execute_test(PyRule3Cryptography(),
                          "../resources/test_cases/python/cryptography/TestRule3.py",
                          "../resources/test_cases/python/cryptography/TestRule3ExpectedMisuses.csv")

    def test_pyrule4_cryptography(self):
        self.execute_test(PyRule4Cryptography(),
                          "../resources/test_cases/python/cryptography/TestRule4.py",
                          "../resources/test_cases/python/cryptography/TestRule4ExpectedMisuses.csv")

    def test_pyrule5_cryptography(self):
        self.execute_test(PyRule5Cryptography(),
                          "../resources/test_cases/python/cryptography/TestRule5.py",
                          "../resources/test_cases/python/cryptography/TestRule5ExpectedMisuses.csv")


if __name__ == '__main__':
    unittest.main()
