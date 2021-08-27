import os
from enum import Enum
from abc import ABC
from itertools import chain
from licma.query.qtypes import Types
from licma.query.query import Query
from licma.query.value_parameter import ValueParameter
from licma.query.qtypes import get_type
from licma.progress_log.log import logger
from licma.query.qtypes import ParamType

class PyQuery(Query, ABC):

    def __init__(self):
        self.start_module_body = "/Module/body"
        self.start_oop_body = "/Module/body//body/ClassDef.body"
        self.start_module_func = "/Module/body/FunctionDef"
        self.start_oop_func = "/Module/body//body/ClassDef.body//FunctionDef"
        self.mode = "module"

    def substitute_f(self, syntax_tree, name, mode, paramType=None):
        """
        Fields
        """
        query_f_module = "/Assign/targets/Name[@token='" + name + "']/parent::targets/parent::Assign/value"
        query_f_oop = "/body_stmts/FunctionDef[@token='__init__']/body/FunctionDef.body/body_stmts/Assign/targets/QualifiedIdentifier/identifiers/Attribute[@token='" + name + "']/parent::identifiers/parent::QualifiedIdentifier/parent::targets/parent::Assign/value"


        query_module = self.start_module_body + query_f_module
        query_oop = self.start_oop_body + query_f_oop

        if mode == Mode.Module:
            query = query_module
        else:
            query = query_oop

        types = [(ParamType.String, query + "/Str", Types.StringLiteral),
                 (ParamType.Name, query + "/Name", Types.StringLiteral),
                 (ParamType.Attribute, query + "//Attribute", Types.StringLiteral),
                 (ParamType.Byte, query + "/Bytes", Types.StringLiteral),
                 (ParamType.Byte, query + "/Call/func/Name[@token='bytes']/parent::func/parent::Call/args/*[1]", Types.StringLiteral),
                 (ParamType.Byte, query + "/Call/args/Bytes", Types.StringLiteral),  # lib cryptography, direct and indirect field access
                 (ParamType.Byte, query + "/Call/args/Call/func/Name[@token='bytes']/parent::func/parent::Call/args/*[1]", Types.StringLiteral),  # lib cryptography, direct and indirect field access
                 (ParamType.Num, query + "/Num", Types.NumberLiteral)]

#        query_f_attribute = query_f + "//Attribute"
#        query_f_num = query_f + "/Num"
#        query_f_name = query_f + "/Name"
#        query_f_str = query_f + "/Str"
#        query_f_bytes1 = query_f + "/Bytes"
#        query_f_bytes2 = query_f + "/Call/func/Name[@token='bytes']/parent::func/parent::Call/args/*[1]"

        # check if there is any corresponding field
        try:
            next(syntax_tree.tree.filter(query))
        except StopIteration:
            return set()

        for type in types:
            if type[0] in paramType:
                value = self.iterator_get_next(syntax_tree, type[1])
                if not value is None:
                    return set([ValueParameter(type[2], value.token, syntax_tree.file, value.start_position.line)])

        # determine field value

#        if paramType == ParamType.String:
#            # string assignment
#            value = self.iterator_get_next(syntax_tree, query_f_str)
#            if not value is None:
#                return set([ValueParameter(Types.StringLiteral, value.token, syntax_tree.file, value.start_position.line)])

#        if paramType == ParamType.Name:
#            # name assignment
#            value = self.iterator_get_next(syntax_tree, query_f_name)
#            if not value is None:
#                return set([ValueParameter(Types.StringLiteral, value.token, syntax_tree.file, value.start_position.line)])

#        # attribute assignment
#        value = self.iterator_get_next(syntax_tree, query_f_attribute)
#        if not value is None:
#            return set([ValueParameter(Types.StringLiteral, value.token, syntax_tree.file, value.start_position.line)])

#        # int assignment
#        value = self.iterator_get_next(syntax_tree, query_f_num)
#        if not value is None:
#            return set([ValueParameter(Types.NumberLiteral, value.token, syntax_tree.file, value.start_position.line)])

#        # byte array initialization = {'a', 'b', 'c', ... }
#        array_values = self.array_assignment(syntax_tree, query_f_bytes1)
#        if len(array_values) > 0:
#            return array_values

#        # byte array initialization = "a string".getBytes()
#        value = self.iterator_get_next(syntax_tree, query_f_bytes2)
#        if not value is None:
#            return set([ValueParameter(Types.StringLiteral, value.token, syntax_tree.file, value.start_position.line)])
        return set()

    def caller_arguments(self, syntax_tree, caller, called, parameter_index, mode):
        arguments = set()

        query_caller_arguments_module = "[@token='" + caller + "']" \
                "//func/Name[@role='Callee' and @token = '" + called + "']" \
                "/parent::func/parent::Call/args/*[" + str(parameter_index) + "]"
        query_caller_arguments_oop = "[@token='" + caller + "']" \
                "//func/QualifiedIdentifier/identifiers/Attribute[@token='" + called + "']" \
                "/parent::identifiers/parent::QualifiedIdentifier/parent::func/parent::Call/args/*[" + str(parameter_index - 1) + "]"
        query_module = self.start_module_func + query_caller_arguments_module
        query_oop = self.start_oop_func + query_caller_arguments_oop

        if mode == Mode.Module:
            query = query_module
        else:
            query = query_oop

        for argument in syntax_tree.tree.filter(query):
            arguments.add(ValueParameter(get_type(argument.internal_type),
                                                  argument.token,
                                                  syntax_tree.file,
                                                  argument.start_position.line))
        return arguments

    def caller_of(self, syntax_tree, function, mode):
        callers = set()

        query_caller_of_module = "//func/Name[@role='Callee' and @token='" + function + "']/ancestor::FunctionDef"
        query_caller_of_oop = "//func/QualifiedIdentifier/identifiers/Attribute[@token='" + function + "']/ancestor::FunctionDef"
        query_module = self.start_module_body + query_caller_of_module
        query_oop = self.start_oop_body + query_caller_of_oop

        if mode == Mode.Module:
            query = query_module
        else:
            query = query_oop

        for caller in syntax_tree.tree.filter(query):
            callers.add(caller.get()["@token"])

        return callers

    def function_parameter(self, syntax_tree, function_name, mode):
        parameters = []
        query_function_parameter = "[@token='" + function_name + "']/args/arguments/args/arg"
        query_module = self.start_module_func + query_function_parameter
        query_oop = self.start_oop_func + query_function_parameter

        if mode == Mode.Module:
            query = query_module
        else:
            query = query_oop

        parameters = parameters + list(syntax_tree.tree.filter(query))
        return parameters

    def function_parameter_index(self, syntax_tree, function_name, parameter_name, mode):
        n = 1
        for parameter in self.function_parameter(syntax_tree, function_name, mode):
            if parameter_name == parameter.token:
                return n
            else:
                n = n + 1

        return -1

    def substitute_p(self, syntax_tree, method, parameter_e, mode, paramType=None):
        value_parameter = set()
        parameter_index = self.function_parameter_index(syntax_tree, method, parameter_e, mode)
        if parameter_index == -1:
            return value_parameter
        for parameter_a in self.function_parameter(syntax_tree, method, mode):
            if parameter_e == parameter_a.get()["@token"]:
                callers = self.caller_of(syntax_tree, method, mode)
                if len(callers) == 0:
                    value_parameter.add(ValueParameter(Types.Unknown, "UNKNOWN", syntax_tree.file, parameter_a.start_position.line))
                else:
                    for caller in callers:
                        arguments = self.caller_arguments(syntax_tree, caller, method, parameter_index, mode)
                        for argument in arguments:
                            if argument.type == Types.StringLiteral or argument.type == Types.NumberLiteral:
                                value_parameter.add(argument)
                            elif argument.type == Types.SimpleName:
                                value_parameter = value_parameter.union(self.substitute_v(syntax_tree, caller, argument.value, mode, paramType=paramType))
                            elif argument.type == Types.Method:
                                logger.debug("not implemented yet!")
        return value_parameter

    def substitute_v(self, syntax_tree, function, variable, mode, parameter_keyword=None, paramType=None):
        """
        substitute variable
        :return:
        """
        parameter_values = set()

        query_substitute_v = "[@token='" + function + "']/body/FunctionDef.body" \
                       "//Assign/targets/Name[@token='" + variable + "']/parent::targets/parent::Assign/value"
        query_module = self.start_module_func + query_substitute_v
        query_oop = self.start_oop_func + query_substitute_v

        if mode == Mode.Module:
            query_assign = query_module
        else:
            query_assign = query_oop

        types = [(ParamType.String, query_assign + "/Str|" + query_assign + "/QualifiedIdentifier//Str"),
                 (ParamType.Name, query_assign + "/Name|" + query_assign + "/QualifiedIdentifier//Name"),
                 (ParamType.Attribute, query_assign + "/Attribute|" + query_assign + "/QualifiedIdentifier//Attribute|" + query_assign + "//func/QualifiedIdentifier/identifiers//Attribute[count(" + query_assign + "//args/*)=0]"),
                 (ParamType.Byte, query_assign + "//Bytes"),
                 (ParamType.Byte, query_assign + "//Call/func/Name[@token='bytes']/parent::func/parent::Call/args/*[1]//Str"),
                 (ParamType.Num, query_assign + "/Num|" + query_assign + "/QualifiedIdentifier//Num")]

        # check for nested variables
        if mode == Mode.Module:
            query_nested_variables = query_assign + "/Name"
        else:
            query_nested_variables = query_assign + "/Name|" + query_assign + "//Attribute"

        for nested_variable in [hit.token for hit in syntax_tree.tree.filter(query_nested_variables)]:
            parameter_values = parameter_values.union(self.substitute_v(syntax_tree, function, nested_variable, mode, paramType=paramType))

        # If a nested variable was found, stop here and return to substitute it.
        if len(parameter_values) > 0: return parameter_values

        for type in types:
            if type[0] in paramType:
                if ParamType.Num == type[0]:
                    parameter_values = parameter_values.union(self.int_assignment(syntax_tree, type[1]))
                elif ParamType.Byte == type[0]:
                    parameter_values = parameter_values.union(self.array_assignment(syntax_tree, type[1]))
                else:
                    parameter_values = parameter_values.union(self.value_assignment(syntax_tree, type[1]))
#        if paramType == ParamType.String:
            # String
#            query_string = query_assign + "/Str|" + query_assign + "/QualifiedIdentifier//Str"
#            parameter_values = parameter_values.union(self.value_assignment(syntax_tree, query_string))

#        if paramType == ParamType.Name:
            # Name
#            query_name = query_assign + "/Name|" + query_assign + "/QualifiedIdentifier//Name"
#            parameter_values = parameter_values.union(self.value_assignment(syntax_tree, query_name))

#        # Attribute value for variable can be found
#        query_attribute = query_assign + "/Attribute|" + query_assign + "/QualifiedIdentifier//Attribute|" + query_assign + "//func/QualifiedIdentifier/identifiers//Attribute[count(" + query_assign + "//args/*)=0]"

#        parameter_values = parameter_values.union(self.value_assignment(syntax_tree, query_attribute))
#        ###if len(parameter_values) > 0: return parameter_values

#        # Num value for variable can be found
#        query_num = query_assign + "/Num|" + query_assign + "/QualifiedIdentifier//Num"

#        parameter_values = parameter_values.union(self.int_assignment(syntax_tree, query_num))
#        ###if len(parameter_values) > 0: return parameter_values

#        # Byte value 1 for variable can be found
#        query_byte1 = query_assign + "//Bytes"
#        parameter_values = parameter_values.union(self.array_assignment(syntax_tree, query_byte1))

#        # Byte value 2 for variable can be found
#        query_byte2 = query_assign + "//Call/func/Name[@token='bytes']/parent::func/parent::Call/args/*[1]//Str"
#        parameter_values = parameter_values.union(self.array_assignment(syntax_tree, query_byte2))



        # check for function parameters
        parameter_values = parameter_values.union(self.substitute_p(syntax_tree, function, variable, mode, paramType=paramType))
        # If a function parameter was found, stop here and return to substitute it.
        if len(parameter_values) > 0: return parameter_values

        # check for field value
        parameter_values = parameter_values.union((self.substitute_f(syntax_tree, variable, mode, paramType=paramType)))
        return parameter_values


    def function_of_instantiation(self, syntax_tree, instantiation, parameter_name, mode):
        function_names = []
        query = instantiation + "[@token='" + parameter_name + "']/ancestor::FunctionDef/@token"
        functions = syntax_tree.tree.filter(query)
        file_name = os.path.basename(syntax_tree.file)

        if file_name.endswith(".py"):
            module_name = os.path.basename(syntax_tree.file).replace(".py", "")
            for function in functions:
                function_name = function.token

                # identify class name for python oop
                class_name = ""
                if mode == Mode.OOP:
                    query_class_name = instantiation + "[@token='" + parameter_name + "']/ancestor::FunctionDef[@token='" + function_name + "']/ancestor::ClassDef/@token"
                    class_name = list(syntax_tree.tree.filter(query_class_name))[0].token

                    function_names.append((module_name + "." + class_name, function_name))
                else:
                    function_names.append((module_name, function_name))

        return function_names

    def query_parameter_value(self, syntax_tree, base_query, parameter_receiver, mode, parameter_keyword=None, paramType=None):
        value_parameters = set()

        try:
            types = [(ParamType.String, "/self::Str", " -> hard coded string", Types.StringLiteral),
                     (ParamType.Name, "//Name", " -> hard coded name", Types.StringLiteral),
                     (ParamType.Attribute, "//Attribute", " -> hard coded attribute", Types.StringLiteral),
                     (ParamType.Num, "//Num", " -> hard coded int", Types.NumberLiteral),
                     (ParamType.Byte, "//Bytes", " -> hard coded bytes", Types.StringLiteral),
                     (ParamType.Byte, "//Call/func/Name[@token='bytes']/parent::func/parent::Call/args/*[1]//Str", " -> hard coded bytes", Types.StringLiteral)]

            for type in types:
                if type[0] in paramType:
                    query = base_query + type[1]
                    for string in syntax_tree.tree.filter(query):
                        value_parameters.add(
                            ValueParameter(type[3], string.token, syntax_tree.file, string.start_position.line,
                                           parameter_receiver + type[2], string.start_position.line))

            # parameter is variable
            if parameter_keyword is None:
                query_v = base_query + "//Name[@role='Identifier' and @role='Receiver' or @role='Argument']"
            else:
                query_v = base_query + "/Name"

            variables = syntax_tree.tree.filter(query_v + "/@token")

            if mode == Mode.OOP:
                if parameter_keyword is None:
                    query_v_oop = base_query + "/identifiers/Name[@token='self']/parent::identifiers/Attribute"
                else:
                    #"/Attribute"
                    query_v_oop = base_query + "/QualifiedIdentifier/identifiers/Name[@token='self']/parent::identifiers/Attribute"
                    query_v_oop_direct_field_access = base_query[:base_query.find(
                        "args")] + "keywords/keyword[@token='" + parameter_keyword + "']/value/QualifiedIdentifier/identifiers/Name[@token='self']/parent::identifiers/Attribute"

                # hard coded direct field access
                # x.y(self.field)
                query_v_oop_param_field = base_query + "//Call/args/QualifiedIdentifier/identifiers/Name[@token='self']/parent::identifiers/Attribute"
                variables = chain(variables, syntax_tree.tree.filter(query_v_oop_param_field))

                variables = chain(variables, syntax_tree.tree.filter(query_v_oop))

            for variable in variables:
                variable_name = variable.token
                functions = self.function_of_instantiation(syntax_tree, query_v, variable_name, mode)
                if mode == Mode.OOP and not parameter_keyword is None:
                    functions = chain(functions, syntax_tree.tree.filter(query_v_oop_direct_field_access))

                if mode == Mode.OOP:
                    # hard coded direct field access
                    # x.y(self.field)
                    functions = chain(functions, self.function_of_instantiation(syntax_tree, query_v_oop_param_field, variable_name, mode))

                    functions = chain(functions, self.function_of_instantiation(syntax_tree, query_v_oop, variable_name, mode))

                for function in functions:
                    value_parameters_substituted = self.substitute_v(syntax_tree, function[1], variable_name, mode, paramType=paramType)

                    # determine line number of analysed function call
                    query_line = query_v + "[ancestor::FunctionDef[@token = '" + function[1] + "']]"
                    lines = syntax_tree.tree.filter(query_line)

                    if mode == Mode.OOP:
                        query_line_oop = query_v_oop + "[ancestor::FunctionDef[@token = '" + function[1] + "']]"
                        lines = chain(lines, syntax_tree.tree.filter(query_line_oop))

                        # hard coded direct field access
                        # x.y(self.field)
                        query_line_oop_param_field = query_v_oop_param_field + "[ancestor::FunctionDef[@token = '" + function[1] + "']]"
                        lines = chain(lines, syntax_tree.tree.filter(query_line_oop_param_field))

                    try:
                        misuse_line = next(lines).start_position.line
                    except StopIteration:
                        logger.error(str(function))

                    for value_parameter in value_parameters_substituted:
                        value_parameter.init_misuse_position(function[0] + "." + function[1] + "." + parameter_receiver, misuse_line)
                    value_parameters = value_parameters.union(value_parameters_substituted)

        except RecursionError as recursion_error:
            logger.error(str(recursion_error) + " | rule: " + str(self.get_rule_name()) + " | file: " + str(syntax_tree.file))

        return value_parameters

    def dfc(self, syntax_tree, function_name, parameter_index=None, parameter_keyword=None, paramType=None):
        """
        direct function call(dfc)
        """
        value_parameters = set()

        queries = [(self.start_module_func, Mode.Module), (self.start_oop_func, Mode.OOP)]

        for query in queries:
            if not parameter_index is None:
                base_query = query[0] + "/body//Assign/value//func/Name[@token='" +\
                             function_name + "']/ancestor::func/ancestor::value//args/*[" + str(parameter_index) + "]"
            elif not parameter_keyword is None:
                base_query = query[0] + "/body//Assign/value//func/Name[@token='" + function_name + "']/ancestor::func" \
                             "/ancestor::value//keywords/keyword[@token='" + str(parameter_keyword) + "']/value"
            else:
                return value_parameters

            value_parameters = value_parameters.union(self.query_parameter_value(syntax_tree,
                                                                                 base_query,
                                                                                 function_name,
                                                                                 query[1],
                                                                                 parameter_keyword=parameter_keyword,
                                                                                 paramType=paramType))

        #base_query = "//Module/body[FunctionDef/body|FunctionDef.body]//Assign/value//func//identifiers" \
        #             "/Attribute[@token='" + function_name + "']" \
        #             "/ancestor::value//args/*[" + str(parameter_index) + "]"

        #base_query_oo = "//Module/body//body/ClassDef.body//FunctionDef/body//Assign/value//func//identifiers" \
        #                "/Attribute[@token='" + function_name + "']/ancestor::value//args/*[2]"

        #return self.query_parameter_value(syntax_tree, base_query, function_name).union(
        #       self.query_parameter_value(syntax_tree, base_query_oo, function_name))
        return value_parameters

    def cmf(self, syntax_tree, module_name, function_name, parameter_index=None, parameter_keyword=None, paramType=None):
        """
        call module's function(cmf)
        :return:
        """
        value_parameters = set()

        queries = [(self.start_module_func, Mode.Module), (self.start_oop_func, Mode.OOP)]

        for query in queries:
            if not parameter_index is None:
                base_query = query[0] + "/body//Assign/value//func//identifiers" \
                             "/Name[@token='" + module_name + "']/ancestor::identifiers" \
                             "/Attribute[@token='" + function_name + "']" \
                             "/ancestor::value//args/*[" + str(parameter_index) + "]"
            elif not parameter_keyword is None:
                base_query = query[0] + "/body//Assign/value//func//identifiers" \
                             "/Name[@token='" + module_name + "']/ancestor::identifiers" \
                             "/Attribute[@token='" + function_name + "']" \
                             "/ancestor::value//keywords/keyword[@token='" + str(parameter_keyword) + "']/value"
            else:
                return value_parameters

            value_parameters = value_parameters.union(self.query_parameter_value(syntax_tree,
                                                                                 base_query,
                                                                                 module_name + "." + function_name,
                                                                                 mode=query[1],
                                                                                 parameter_keyword=parameter_keyword,
                                                                                 paramType=paramType))

        return value_parameters


class Mode(Enum):
    Module = 0
    OOP = 1
