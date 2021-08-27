import unittest

from licma.babel_fish.babel_fish import BabelFish
from licma.rules.python.pyrules_ucryptolib.pyrule1_ucryptolib import PyRule1ucryptolib
from licma.rules.python.pyrules_ucryptolib.pyrule2_ucryptolib import PyRule2ucryptolib
from licma.rules.python.pyrules_ucryptolib.pyrule3_ucryptolib import PyRule3ucryptolib
from licma.tests.test_utilities import UnitTestBase


class PyRuleUcryptolibTestOOP(UnitTestBase):
    babel_fish = BabelFish()

    def test_pyrule1_ucryptolib_oop(self):
        self.execute_test(PyRule1ucryptolib(),
                          "../resources/test_cases/python/ucryptolib/TestRule1c.py",
                          "../resources/test_cases/python/ucryptolib/TestRule1cExpectedMisuses.csv")

    def test_pyrule2_ucryptolib_oop(self):
        self.execute_test(PyRule2ucryptolib(),
                          "../resources/test_cases/python/ucryptolib/TestRule2c.py",
                          "../resources/test_cases/python/ucryptolib/TestRule2cExpectedMisuses.csv")

    def test_pyrule3_ucryptolib_oop(self):
        self.execute_test(PyRule3ucryptolib(),
                          "../resources/test_cases/python/ucryptolib/TestRule3c.py",
                          "../resources/test_cases/python/ucryptolib/TestRule3cExpectedMisuses.csv")


if __name__ == '__main__':
    unittest.main()
