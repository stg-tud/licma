import csv
import os
import unittest

from licma.babel_fish.babel_fish import BabelFish
from licma.query.misuse import Misuse
from licma.query.qtypes import get_type
from run_licma import Licma


class UnitTestBase(unittest.TestCase):
    babel_fish = BabelFish()

    def execute_test(self, rule, test_file, expected_misuses):
        rule_under_test = rule

        expected_misuses = self.get_expected_misuses(expected_misuses)
        actual_misuses = rule_under_test.apply_rule(self.babel_fish.parse(test_file))
        self.assertEqual(self.expected_misuses_to_string_list(expected_misuses),
                         self.actual_misuses_to_string_list(actual_misuses))

    def get_expected_misuses(self, expected_misuses_path):
        if not os.path.isfile(expected_misuses_path):
            raise Exception("No file: " + expected_misuses_path)

        expected_misuses = []
        with open(expected_misuses_path, 'r') as file:
            next(file)
            for misuse in csv.reader(file, delimiter=';'):
                expected_misuses.append(
                    Misuse(misuse[0], misuse[1], misuse[3], misuse[4], misuse[5], get_type(misuse[6].split(".")[1]),
                           misuse[7]))

        return expected_misuses

    def actual_misuses_to_string_list(self, actual_misuses):
        licma = Licma()  # needed to use licma's sort function
        return [misuse[0].to_string() for misuse in licma.sort_misuses(actual_misuses)]

    def expected_misuses_to_string_list(self, expected_misuses):
        return [misuse.to_string() for misuse in expected_misuses]
