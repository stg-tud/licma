from abc import ABC

from licma.query.pyquery import PyQuery
from licma.query.qtypes import ParamType


class PyRule1PyCrypto(PyQuery, ABC):
    def rule(self, syntax_tree):
        cmf1 = self.cmf(syntax_tree, "AES", "new", parameter_index=2, paramType=[ParamType.Attribute, ParamType.Num])
        cmf2 = self.cmf(syntax_tree, "AES", "new", parameter_keyword="mode", paramType=[ParamType.Attribute, ParamType.Num])
        return self.o(self.o(self.o(self.is_unknowen(cmf1), self.is_contained(cmf1, "ECB")), self.is_eq(cmf1, 1)),
                      self.o(self.o(self.is_unknowen(cmf2), self.is_contained(cmf2, "ECB")), self.is_eq(cmf2, 1)))

    def get_rule_name(self):
        return "PyQuery: Rule 1 | PyCrypto"
