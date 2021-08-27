from abc import ABC

from licma.query.pyquery import PyQuery
from licma.query.qtypes import ParamType


class PyRule1Cryptography(PyQuery, ABC):
    def rule(self, syntax_tree):
        dfc1 = self.dfc(syntax_tree, "Cipher", parameter_index=2, paramType=[ParamType.Attribute])
        dfc2 = self.dfc(syntax_tree, "Cipher", parameter_keyword="mode", paramType=[ParamType.Attribute])
        return self.o(self.o(self.is_unknowen(dfc1), self.is_contained(dfc1, "ECB")),
                      self.o(self.is_unknowen(dfc2), self.is_contained(dfc2, "ECB")))

    def get_rule_name(self):
        return "PyQuery: Rule 1 | cryptography"
