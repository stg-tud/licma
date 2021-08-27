from abc import ABC

from licma.query.pyquery import PyQuery
from licma.query.qtypes import ParamType


class PyRule4PyNaCl(PyQuery, ABC):
    def rule(self, syntax_tree):
        dfc1 = self.dfc(syntax_tree, "kdf", parameter_index=3, paramType=[ParamType.Byte])
        dfc2 = self.dfc(syntax_tree, "kdf", parameter_keyword="salt", paramType=[ParamType.Byte])
        return self.o(self.o(self.is_unknowen(dfc1), self.is_const(dfc1)),
                      self.o(self.is_unknowen(dfc2), self.is_const(dfc2)))

    def get_rule_name(self):
        return "PyQuery: Rule 4 | PyNaCl"
