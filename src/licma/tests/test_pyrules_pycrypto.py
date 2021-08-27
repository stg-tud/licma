import unittest

from licma.babel_fish.babel_fish import BabelFish
from licma.tests.test_utilities import UnitTestBase
from licma.rules.python.pyrules_pycrypto.pyrule1_pycrypto import PyRule1PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule2_pycrypto import PyRule2PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule3_pycrypto import PyRule3PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule4_pycrypto import PyRule4PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule5_pycrypto import PyRule5PyCrypto


class PyRulePyCryptoTest(UnitTestBase):
    babel_fish = BabelFish()

    def test_pyrule1_pycrypto(self):
        self.execute_test(PyRule1PyCrypto(),
                          "../resources/test_cases/python/PyCrypto/TestRule1.py",
                          "../resources/test_cases/python/PyCrypto/TestRule1ExpectedMisuses.csv")

    def test_pyrule2_pycrypto(self):
        self.execute_test(PyRule2PyCrypto(),
                          "../resources/test_cases/python/PyCrypto/TestRule2.py",
                          "../resources/test_cases/python/PyCrypto/TestRule2ExpectedMisuses.csv")

    def test_pyrule3_pycrypto(self):
        self.execute_test(PyRule3PyCrypto(),
                          "../resources/test_cases/python/PyCrypto/TestRule3.py",
                          "../resources/test_cases/python/PyCrypto/TestRule3ExpectedMisuses.csv")

    def test_pyrule4_pycrypto(self):
        self.execute_test(PyRule4PyCrypto(),
                          "../resources/test_cases/python/PyCrypto/TestRule4.py",
                          "../resources/test_cases/python/PyCrypto/TestRule4ExpectedMisuses.csv")

    def test_pyrule5_pycrypto(self):
        self.execute_test(PyRule5PyCrypto(),
                          "../resources/test_cases/python/PyCrypto/TestRule5.py",
                          "../resources/test_cases/python/PyCrypto/TestRule5ExpectedMisuses.csv")


if __name__ == '__main__':
    unittest.main()
