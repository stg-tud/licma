from abc import ABC

from licma.query.pyquery import PyQuery
from licma.query.qtypes import ParamType


class PyRule3Cryptography(PyQuery, ABC):
    def rule(self, syntax_tree):
        dfc1 = self.dfc(syntax_tree, "Cipher", parameter_index=1, paramType=[ParamType.Byte])
        dfc2 = self.dfc(syntax_tree, "Cipher", parameter_keyword="algorithm", paramType=[ParamType.Byte])
        dfc3 = self.dfc(syntax_tree, "Fernet", parameter_index=1, paramType=[ParamType.Byte])
        dfc4 = self.dfc(syntax_tree, "Fernet", parameter_keyword="key", paramType=[ParamType.Byte])
        return self.o(self.o(self.o(self.is_unknowen(dfc1), self.is_const(dfc1)),
                             self.o(self.is_unknowen(dfc2), self.is_const(dfc2))),
                      self.o(self.o(self.is_unknowen(dfc3), self.is_const(dfc3)),
                             self.o(self.is_unknowen(dfc4), self.is_const(dfc4))))

    def get_rule_name(self):
        return "PyQuery: Rule 3 | cryptography"
