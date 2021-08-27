import unittest

from licma.babel_fish.babel_fish import BabelFish
from licma.rules.python.pyrules_pycrypto.pyrule1_pycrypto import PyRule1PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule2_pycrypto import PyRule2PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule3_pycrypto import PyRule3PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule4_pycrypto import PyRule4PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule5_pycrypto import PyRule5PyCrypto
from licma.tests.test_utilities import UnitTestBase


class PyRulePyCryptoTestOOP(UnitTestBase):
    babel_fish = BabelFish()

    def test_pyrule1_pycrypto_oop(self):
        self.execute_test(PyRule1PyCrypto(),
                          "../resources/test_cases/python/PyCrypto/TestRule1c.py",
                          "../resources/test_cases/python/PyCrypto/TestRule1cExpectedMisuses.csv")

    def test_pyrule2_pycrypto_oop(self):
        self.execute_test(PyRule2PyCrypto(),
                          "../resources/test_cases/python/PyCrypto/TestRule2c.py",
                          "../resources/test_cases/python/PyCrypto/TestRule2cExpectedMisuses.csv")

    def test_pyrule3_pycrypto_oop(self):
        self.execute_test(PyRule3PyCrypto(),
                          "../resources/test_cases/python/PyCrypto/TestRule3c.py",
                          "../resources/test_cases/python/PyCrypto/TestRule3cExpectedMisuses.csv")

    def test_pyrule4_pycrypto_oop(self):
        self.execute_test(PyRule4PyCrypto(),
                          "../resources/test_cases/python/PyCrypto/TestRule4c.py",
                          "../resources/test_cases/python/PyCrypto/TestRule4cExpectedMisuses.csv")

    def test_pyrule5_pycrypto_oop(self):
        self.execute_test(PyRule5PyCrypto(),
                          "../resources/test_cases/python/PyCrypto/TestRule5c.py",
                          "../resources/test_cases/python/PyCrypto/TestRule5cExpectedMisuses.csv")


if __name__ == '__main__':
    unittest.main()
