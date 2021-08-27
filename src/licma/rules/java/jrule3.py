from abc import ABC
from licma.query.jquery import JQuery


class JRule3(JQuery, ABC):
    def rule(self, syntax_tree):
        ci = self.ci(syntax_tree, "SecretKeySpec", parameter_index=1)
        return self.o(self.is_const(ci), self.is_unknowen(ci))

    def get_rule_name(self):
        return "Rule 3"
