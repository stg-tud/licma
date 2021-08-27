from abc import ABC
from licma.query.jquery import JQuery


class JRule2(JQuery, ABC):
    def rule(self, syntax_tree):
        ci = self.ci(syntax_tree, "IvParameterSpec", parameter_index=1)
        return self.o(self.is_const(ci), self.is_unknowen(ci))

    def get_rule_name(self):
        return "Rule 2"
