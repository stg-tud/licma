import unittest

from licma.babel_fish.babel_fish import BabelFish
from licma.tests.test_utilities import UnitTestBase
from licma.rules.java.jrule1 import JRule1
from licma.rules.java.jrule2 import JRule2
from licma.rules.java.jrule3 import JRule3
from licma.rules.java.jrule4 import JRule4
from licma.rules.java.jrule5 import JRule5
from licma.rules.java.jrule6 import JRule6


class JRuleTest(UnitTestBase):
    babel_fish = BabelFish()

    def test_jrule1(self):
        self.execute_test(JRule1(),
                          "../resources/test_cases/java/TestRule1.java",
                          "../resources/test_cases/java/TestRule1ExpectedMisuses.csv")

    def test_jrule2(self):
        self.execute_test(JRule2(),
                          "../resources/test_cases/java/TestRule2.java",
                          "../resources/test_cases/java/TestRule2ExpectedMisuses.csv")

    def test_jrule3(self):
        self.execute_test(JRule3(),
                          "../resources/test_cases/java/TestRule3.java",
                          "../resources/test_cases/java/TestRule3ExpectedMisuses.csv")

    def test_jrule4(self):
        self.execute_test(JRule4(),
                          "../resources/test_cases/java/TestRule4.java",
                          "../resources/test_cases/java/TestRule4ExpectedMisuses.csv")

    def test_jrule5(self):
        self.execute_test(JRule5(),
                          "../resources/test_cases/java/TestRule5.java",
                          "../resources/test_cases/java/TestRule5ExpectedMisuses.csv")

    def test_jrule6(self):
        self.execute_test(JRule6(),
                          "../resources/test_cases/java/TestRule6.java",
                          "../resources/test_cases/java/TestRule6ExpectedMisuses.csv")


if __name__ == '__main__':
    unittest.main()
