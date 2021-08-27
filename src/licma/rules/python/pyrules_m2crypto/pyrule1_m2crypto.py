from abc import ABC

from licma.query.pyquery import PyQuery
from licma.query.qtypes import ParamType


class PyRule1M2Crypto(PyQuery, ABC):
    def rule(self, syntax_tree):
        dfc1 = self.dfc(syntax_tree, "Cipher", parameter_index=1, paramType=[ParamType.String])
        dfc2 = self.dfc(syntax_tree, "Cipher", parameter_keyword="alg", paramType=[ParamType.String])
        return self.o(self.o(self.is_unknowen(dfc1), self.is_contained(dfc1, "ecb")),
                      self.o(self.is_unknowen(dfc2), self.is_contained(dfc2, "ecb")))

    def get_rule_name(self):
        return "PyQuery: Rule 1 | M2Crypto"
