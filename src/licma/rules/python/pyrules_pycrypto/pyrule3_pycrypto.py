from abc import ABC

from licma.query.pyquery import PyQuery
from licma.query.qtypes import ParamType


class PyRule3PyCrypto(PyQuery, ABC):
    def rule(self, syntax_tree):
        cmf1 = self.cmf(syntax_tree, "AES", "new", parameter_index=1, paramType=[ParamType.Byte])
        cmf2 = self.cmf(syntax_tree, "AES", "new", parameter_keyword="key", paramType=[ParamType.Byte])
        return self.o(self.o(self.is_const(cmf1), self.is_unknowen(cmf1)),
                      self.o(self.is_const(cmf2), self.is_unknowen(cmf2)))

    def get_rule_name(self):
        return "PyQuery: Rule 3 | PyCrypto"
