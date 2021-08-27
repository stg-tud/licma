from licma.query.qtypes import Types
from abc import ABC, abstractmethod
from licma.query.misuse import Misuse
from functools import reduce
from licma.query.value_parameter import ValueParameter


class Query(ABC):

    def vp_exists(self, vp_list, vp_exp):
        for vp in vp_list:
            if vp.to_string() == vp_exp.to_string():
                return True
        return False

    def o(self, vp_list1, vp_list2):
        """or"""
        new_list = vp_list1
        for vp in vp_list2:
            if not self.vp_exists(new_list, vp):
                new_list.append(vp)
        return new_list

    def a(self, vp_list1, vp_list2):
        """and"""
        new_list = []
        for vp in vp_list1:
            if self.vp_exists(vp_list2, vp):
                new_list.append(vp)
        return new_list

    def n(self, vp_list1, vp_list2):
        """not"""
        new_list = []
        for vp in vp_list1:
            if not self.vp_exists(vp_list2, vp):
                new_list.append(vp)
        return new_list

    def is_unknowen(self, parameter_values):
        parameter_values_filtered = []
        for parameter_value in parameter_values:
            if parameter_value.type == Types.Unknown:
                parameter_values_filtered.append(parameter_value)
        return parameter_values_filtered

    def is_contained(self, parameter_values, value):
        parameter_values_filtered = []
        for parameter_value in parameter_values:
            if parameter_value.type == Types.StringLiteral and value in parameter_value.value:
                parameter_values_filtered.append(parameter_value)
        return parameter_values_filtered

    def is_eq(self, parameter_values, value):
        parameter_values_filtered = []
        for parameter_value in parameter_values:
            if parameter_value.type == Types.StringLiteral or parameter_value.type == Types.NumberLiteral:
                if str(parameter_value.value) == str(value):
                    parameter_values_filtered.append(parameter_value)
        return parameter_values_filtered

    def is_smaller(self, parameter_values, threshold):
        parameter_values_filtered = []
        for parameter_value in parameter_values:
            if parameter_value.type == Types.NumberLiteral and int(parameter_value.value) < threshold:
                parameter_values_filtered.append(parameter_value)
        return parameter_values_filtered

    def is_const(self, parameter_values):
        parameter_values_filtered = []
        for parameter_value in parameter_values:
            if parameter_value.type == Types.NumberLiteral or parameter_value.type == Types.StringLiteral:
                parameter_values_filtered.append(parameter_value)
        return parameter_values_filtered

    def apply_rule(self, syntax_tree):
        misuses = {}
        hits = self.rule(syntax_tree)
        for hit in hits:
            misuses[hit.to_string()] = Misuse(syntax_tree.file,
                                              self.get_rule_name(),
                                              hit.misuse,
                                              hit.misuse_line,
                                              hit.value,
                                              hit.type,
                                              hit.line)

        return misuses

    def array_assignment(self, syntax_tree, query, separator=""):
        array_values = list(syntax_tree.tree.filter(query))
        if len(array_values) > 0:
            return set([ValueParameter(Types.StringLiteral,
                                       reduce(lambda v1, v2: v1 + v2 if v1 == "" else v1 + separator + v2,
                                              [(v.token).replace("'", "") for v in array_values], ""),
                                      syntax_tree.file, array_values[0].start_position.line)])
        return set()

    def value_assignment(self, syntax_tree, query):
        parameter_values = set()

        for value in syntax_tree.tree.filter(query):
            parameter_values.add(ValueParameter(Types.StringLiteral,
                                                value.get()["@token"],
                                                syntax_tree.file,
                                                value.get()["@pos"]["start"]["line"]))

        return parameter_values

    def int_assignment(self, syntax_tree, query):
        parameter_values = set()

        for value in syntax_tree.tree.filter(query):
            parameter_values.add(ValueParameter(Types.NumberLiteral,
                                                value.get()["@token"],
                                                syntax_tree.file,
                                                value.get()["@pos"]["start"]["line"]))

        return parameter_values

    def iterator_get_next(self, syntax_tree, query):
        try:
            value = next(syntax_tree.tree.filter(query))
            return value
        except StopIteration:
            return None

    @abstractmethod
    def get_rule_name(self):
        pass

    @abstractmethod
    def rule(self, syntax_tree):
        pass
