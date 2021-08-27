from abc import ABC

from licma.query.pyquery import PyQuery
from licma.query.qtypes import ParamType


class PyRule5M2Crypto(PyQuery, ABC):
    def rule(self, syntax_tree):
        dfc1 = self.dfc(syntax_tree, "pbkdf2", parameter_index=3, paramType=[ParamType.Num])
        dfc2 = self.dfc(syntax_tree, "pbkdf2", parameter_keyword="iter", paramType=[ParamType.Num])
        return self.o(self.o(self.is_unknowen(dfc1), self.is_smaller(dfc1, 1000)),
                      self.o(self.is_unknowen(dfc2), self.is_smaller(dfc2, 1000)))

    def get_rule_name(self):
        return "PyQuery: Rule 5 | M2Crypto"
