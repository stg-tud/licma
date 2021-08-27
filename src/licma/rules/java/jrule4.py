from abc import ABC
from licma.query.jquery import JQuery


class JRule4(JQuery, ABC):
    def rule(self, syntax_tree):
        ci_parameter_spec = self.ci(syntax_tree, "PBEParameterSpec", parameter_index=1)
        ci_key_spec = self.ci(syntax_tree, "PBEKeySpec", parameter_index=2)

        return self.o(self.o(self.is_const(ci_parameter_spec), self.is_unknowen(ci_parameter_spec)),
                      self.o(self.is_const(ci_key_spec), self.is_unknowen(ci_key_spec)))

    def get_rule_name(self):
        return "JRule 4"
