import unittest

from licma.babel_fish.babel_fish import BabelFish
from licma.rules.python.pyrules_pynacl.pyrule3_pynacl import PyRule3PyNaCl
from licma.rules.python.pyrules_pynacl.pyrule4_pynacl import PyRule4PyNaCl
from licma.tests.test_utilities import UnitTestBase


class PyRulePyNaClTestOOP(UnitTestBase):
    babel_fish = BabelFish()

    def test_pyrule3_pynacl_oop(self):
        self.execute_test(PyRule3PyNaCl(),
                          "../resources/test_cases/python/PyNaCl/TestRule3c.py",
                          "../resources/test_cases/python/PyNaCl/TestRule3cExpectedMisuses.csv")

    def test_pyrule4_pynacl_oop(self):
        self.execute_test(PyRule4PyNaCl(),
                          "../resources/test_cases/python/PyNaCl/TestRule4c.py",
                          "../resources/test_cases/python/PyNaCl/TestRule4cExpectedMisuses.csv")


if __name__ == '__main__':
    unittest.main()
