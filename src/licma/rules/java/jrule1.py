from abc import ABC
from licma.query.jquery import JQuery


class JRule1(JQuery, ABC):
    def rule(self, syntax_tree):
        csm = self.csm(syntax_tree, "Cipher", "getInstance", parameter_index=1)
        return self.o(self.o(self.is_eq(csm, "AES"), self.is_contained(csm, "ECB")),
                      self.is_unknowen(csm))

    def get_rule_name(self):
        return "Rule 1"

