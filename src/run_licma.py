import argparse as ap
import logging
import re
from licma.progress_log.log import create_logger_file
from licma.progress_log.log import create_logger_cli
from licma.progress_log.log import logger
from licma.rules.java.jrule1 import JRule1
from licma.rules.java.jrule2 import JRule2
from licma.rules.java.jrule3 import JRule3
from licma.rules.java.jrule4 import JRule4
from licma.rules.java.jrule5 import JRule5
from licma.rules.java.jrule6 import JRule6
from licma.rules.python.pyrules_pycrypto.pyrule1_pycrypto import PyRule1PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule2_pycrypto import PyRule2PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule3_pycrypto import PyRule3PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule4_pycrypto import PyRule4PyCrypto
from licma.rules.python.pyrules_pycrypto.pyrule5_pycrypto import PyRule5PyCrypto

from licma.rules.python.pyrules_cryptography.pyrule1_cryptography import PyRule1Cryptography
from licma.rules.python.pyrules_cryptography.pyrule2_cryptography import PyRule2Cryptography
from licma.rules.python.pyrules_cryptography.pyrule3_cryptography import PyRule3Cryptography
from licma.rules.python.pyrules_cryptography.pyrule4_cryptography import PyRule4Cryptography
from licma.rules.python.pyrules_cryptography.pyrule5_cryptography import PyRule5Cryptography

from licma.rules.python.pyrules_m2crypto.pyrule1_m2crypto import PyRule1M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule2_m2crypto import PyRule2M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule3_m2crypto import PyRule3M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule4_m2crypto import PyRule4M2Crypto
from licma.rules.python.pyrules_m2crypto.pyrule5_m2crypto import PyRule5M2Crypto

from licma.rules.python.pyrules_pynacl.pyrule3_pynacl import PyRule3PyNaCl
from licma.rules.python.pyrules_pynacl.pyrule4_pynacl import PyRule4PyNaCl

from licma.rules.python.pyrules_ucryptolib.pyrule1_ucryptolib import PyRule1ucryptolib
from licma.rules.python.pyrules_ucryptolib.pyrule2_ucryptolib import PyRule2ucryptolib
from licma.rules.python.pyrules_ucryptolib.pyrule3_ucryptolib import PyRule3ucryptolib

import glob
from licma.babel_fish.babel_fish import BabelFish
import os
import datetime
import csv
import operator


class Licma:
    """
    LICMA(Language Independent Crypto-Misuse Analysis)
    """

    def __init__(self):
        self.babel_fish = BabelFish()

    def create_result_file(self, output):
        with open(output, mode="a+") as output_file:
            csv_writer = csv.writer(output_file, delimiter=';')
            csv_writer.writerow(
                ["File", "Rule", "Hit-Type", "Misuse", "Misuse-Line", "Parameter-Value", "Parameter-Type",
                 "Parameter-Line"])

    def save_results(self, misuses, output):
        with open(output, mode="a+") as output_file:
            csv_writer = csv.writer(output_file, delimiter=';')
            # misuses_sorted = [(misuses[key], misuses[key].file, misuses[key].misuse_line, misuses[key].parameter_line) for key in misuses.keys()]
            # misuses_sorted.sort(key=operator.itemgetter(1, 2, 3))
            for misuse in self.sort_misuses(misuses):
                logger.debug("Store: " + misuse[0].to_string())
                csv_writer.writerow(misuse[0].get_list())

    def add_dict(self, dict1, dict2):
        if len(dict1.keys()) > 0:
            for key in dict1.keys():
                dict2[key] = dict1[key]
        return dict2

    def run(self, input, output, language, number, lib):
        files = []
        logger.debug("Language: " + language)
        if os.path.isdir(input):
            files = glob.glob(os.path.join(input, "**/*." + language), recursive=True)
        elif os.path.isfile(input) and os.path.splitext(input)[1] == "." + language:
            files = [input]
        elif os.path.isfile(input):
            with open(input) as input_file:
                for line in input_file.readlines():
                    if not line.startswith("#"):
                        file_path = line.strip("\n")
                        if os.path.isfile(file_path):
                            files.append(file_path)
        else:
            logger.error("No valid input directory or file.")
            return

        if not os.path.exists(output):
            os.makedirs(output)

        if not os.path.isdir(output):
            logger.error("No valid output directory")
            return

        output_file = os.path.join(output, "licma-result-" + str(datetime.datetime.now()) + ".csv")
        self.create_result_file(output_file)
        self.apply_rules(files, output_file, language, number, lib)

    def apply_rules(self, files, output, language, number=None, lib="*"):

        misuses = {}
        j_rules = [JRule1(), JRule2(), JRule3(), JRule4(), JRule5(), JRule6()]

        py_rules_pycrypto = [PyRule1PyCrypto(), PyRule2PyCrypto(), PyRule3PyCrypto(), PyRule4PyCrypto(), PyRule5PyCrypto()]
        py_rules_m2crypto = [PyRule1M2Crypto(), PyRule2M2Crypto(), PyRule3M2Crypto(), PyRule4M2Crypto(), PyRule5M2Crypto()]
        py_rules_pynacl = [PyRule3PyNaCl(), PyRule4PyNaCl()]
        py_rules_ucryptolib = [PyRule1ucryptolib(), PyRule2ucryptolib(), PyRule3ucryptolib()]
        py_rules_cryptography = [PyRule1Cryptography(), PyRule2Cryptography(), PyRule3Cryptography(), PyRule4Cryptography(), PyRule5Cryptography()]
        py_rules_all = py_rules_pycrypto + py_rules_m2crypto + py_rules_pynacl + py_rules_ucryptolib + py_rules_cryptography

        if language.lower() == "java":
            rules = j_rules
        elif language.lower() == "py":
            if lib == "*":
                rules = py_rules_all
            elif lib == "pycrypto":
                rules = py_rules_pycrypto
            elif lib == "m2crypto":
                rules = py_rules_m2crypto
            elif lib == "pynacl":
                rules = py_rules_pynacl
            elif lib == "ucryptolib":
                rules = py_rules_ucryptolib
            elif lib == "cryptography":
                rules = py_rules_cryptography
            else:
                rules = py_rules_all
        else:
            logger.error("Valid languages are: java, cpp. But got: " + str(language))
            return

        if not number is None:
            rules = list(filter(lambda rule: re.match("[^0-9]*" + str(number) + "[^0-9]*", rule.get_rule_name()), rules))

        for source_file in files:
            logger.info("processing: " + source_file)
            syntax_tree = self.babel_fish.parse(source_file)

            if not syntax_tree is None:
                for rule in rules:
                    logger.debug("Apply " + rule.get_rule_name() + " to " + source_file)
                    self.save_results(rule.apply_rule(syntax_tree), output)

    def sort_misuses(self, misuses):
        misuses_sorted = [(misuses[key], misuses[key].file, misuses[key].misuse_line, misuses[key].parameter_line) for
                          key in misuses.keys()]
        misuses_sorted.sort(key=operator.itemgetter(1, 2, 3))
        return misuses_sorted


if __name__ == '__main__':
    parser = ap.ArgumentParser(description='LICMA(Language Independent Crypto-Misuse Analysis)')

    parser.add_argument('--lo', help='output log file(defalut: ../log', default='../log')
    parser.add_argument('--ll', help='log level: CRITICAL = 50 ERROR = 40 WARNING = 30 INFO = 20 DEBUG = '
                                     '10\nNOTSET = 0', default=logging.INFO, type=int)
    parser.add_argument('--lc', help='print logging on cli', action='store_true')
    parser.add_argument('--la', help='source file type', default='java')
    parser.add_argument('--lib', help='library', choices=['pycrypto', 'm2crypto', 'pynacl', 'ucryptolib', 'cryptography', '*'], default='*')
    parser.add_argument('--num', help='number of rule', default=None, type=int)
    parser.add_argument("-i", help="input directory or file", required=True)
    parser.add_argument("-o", help="output directory", default='../output')

    args = parser.parse_args()

    # create a logger that store the output to a file
    create_logger_file(args.lo, args.ll)

    # create a logger that displays the output on the cli
    # only if parameter --lc is set
    if args.lc:
        create_logger_cli(args.ll)

    logger.info("input: " + args.i)
    logger.info("output: " + args.o)
    logger.info("output log: " + args.lo)
    logger.info("log level: " + str(args.ll))
    logger.info("source file type: " + args.la)
    logger.info("rule: " + str(args.num))
    logger.info("library: " + args.lib)

    logger.info("Analysis started")

    licma = Licma()
    licma.run(args.i, args.o, args.la, args.num, args.lib)

    logger.info("Analysis finished")
