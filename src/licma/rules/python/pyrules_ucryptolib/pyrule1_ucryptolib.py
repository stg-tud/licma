from abc import ABC

from licma.query.pyquery import PyQuery
from licma.query.qtypes import ParamType


class PyRule1ucryptolib(PyQuery, ABC):
    def rule(self, syntax_tree):
        dfc1 = self.dfc(syntax_tree, "aes", parameter_index=2, paramType=[ParamType.Name, ParamType.Num])
        dfc2 = self.dfc(syntax_tree, "aes", parameter_keyword="mode", paramType=[ParamType.Name, ParamType.Num])
        return self.o(self.o(self.o(self.is_unknowen(dfc1), self.is_contained(dfc1, "ECB")), self.is_eq(dfc1, 1)),
                      self.o(self.o(self.is_unknowen(dfc2), self.is_contained(dfc2, "ECB")), self.is_eq(dfc2, 1)))

    def get_rule_name(self):
        return "PyQuery: Rule 1 | ucryptolib"
