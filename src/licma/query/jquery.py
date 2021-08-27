from abc import ABC

from licma.query.query import Query
from licma.query.qtypes import get_type
from licma.query.qtypes import Types
from licma.query.value_parameter import ValueParameter
from licma.progress_log.log import logger


class JQuery(Query, ABC):
    def method_of_instantiation(self, syntax_tree, instantiation, parameter_name):
        method_names = []
        query = instantiation + "[@token='" + parameter_name + "']/ancestor::MethodDeclaration/name/SimpleName/@token"
        methods = syntax_tree.tree.filter(query)

        for method in methods:
            method_name = method.token
            #method_names.append(method.get()["@token"])
            query_class_name = "/CompilationUnit/types//MethodDeclaration/name/SimpleName[@token='" + method_name + "']" \
                               "/ancestor::name/ancestor::MethodDeclaration/ancestor::TypeDeclaration/name/SimpleName/@token"

            class_name = list(syntax_tree.tree.filter(query_class_name))[0].token
            method_names.append((class_name, method_name))

        return method_names

    def method_of_invocation(self):
        pass

    def caller_arguments(self, syntax_tree, caller, called, parameter_index):
        query = "/CompilationUnit/types//MethodDeclaration/name/SimpleName[@token='" + caller + "']" \
                "/parent::name/parent::MethodDeclaration//MethodInvocation/name" \
                "/SimpleName[@token='" + called + "']/parent::name/parent::MethodInvocation/arguments/*["+ str(parameter_index) + "]//@token"

        arguments = set()
        for argument in syntax_tree.tree.filter(query):
            arguments.add(ValueParameter(get_type(argument.internal_type),
                                                  argument.token,
                                                  syntax_tree.file,
                                                  argument.start_position.line))
        return arguments

    def caller_of(self, syntax_tree, method):
        query = "/CompilationUnit/types//MethodInvocation//*[@role='Call' and @role='Callee' " \
                "and @token='" + method + "']/ancestor::MethodDeclaration/name/SimpleName/@token"

        callers = set()
        for caller in syntax_tree.tree.filter(query):
            callers.add(caller.get()["@token"])

        return callers

    def method_parameter(self, syntax_tree, method):
        query = "/CompilationUnit/types//SimpleName[@token='" + method + "']" \
                "/parent::name/parent::MethodDeclaration/parameters//name/SimpleName" \
                "[@role='Identifier' and @role='Argument']/@token"
        return list(syntax_tree.tree.filter(query))

    def method_parameter_index(self, syntax_tree, method_name, parameter_name):
        n = 1
        for parameter in self.method_parameter(syntax_tree, method_name):
            if parameter_name == parameter.token:
                return n
            else:
                n = n + 1

        return -1

    def substitute_p(self, syntax_tree, method, parameter_e):
        value_parameter = set()
        parameter_index = self.method_parameter_index(syntax_tree, method, parameter_e)
        if parameter_index == -1:
            return value_parameter
        for parameter_a in self.method_parameter(syntax_tree, method):
            if parameter_e == parameter_a.get()["@token"]:
                callers = self.caller_of(syntax_tree, method)
                if len(callers) == 0:
                    value_parameter.add(ValueParameter(Types.Unknown, "UNKNOWN", syntax_tree.file, parameter_a.start_position.line))
                else:
                    for caller in callers:
                        arguments = self.caller_arguments(syntax_tree, caller, method, parameter_index)
                        for argument in arguments:
                            if argument.type == Types.StringLiteral or argument.type == Types.NumberLiteral:
                                value_parameter.add(argument)
                            elif argument.type == Types.SimpleName:
                                value_parameter = value_parameter.union(self.substitute_v(syntax_tree, caller, argument.value))
                            elif argument.type == Types.Method:
                                logger.debug("not implemented yet!")
        return value_parameter

    def substitute_v(self, syntax_tree, method, variable):
        """
        substitute variable
        :return:
        """
        parameter_values = set()
        # string value for variable can be found
        query = "/CompilationUnit/types//SimpleName[@token='" + method + "']" \
                "/ancestor::MethodDeclaration//VariableDeclarationFragment/name/SimpleName[@token='" + variable + "']" \
                "/parent::name/parent::VariableDeclarationFragment/initializer/StringLiteral/@token"

        parameter_values = parameter_values.union(self.value_assignment(syntax_tree, query))
        #if len(parameter_values) > 0: return parameter_values

        # int value for variable can be found
        query = "/CompilationUnit/types//SimpleName[@token='" + method + "']" \
                "/ancestor::MethodDeclaration//VariableDeclarationFragment/name/SimpleName[@token='" + variable + "']" \
                "/parent::name/parent::VariableDeclarationFragment/initializer/NumberLiteral/@token"

        parameter_values = parameter_values.union(self.int_assignment(syntax_tree, query))
        #if len(parameter_values) > 0: return parameter_values

        # value assignment for byte array with = {'a', 'b', 'c', ... }
        query = "/CompilationUnit/types//SimpleName[@token='" + method + "']" \
                "/ancestor::MethodDeclaration//VariableDeclarationFragment/name/SimpleName[@token='" + variable + "']" \
                "/parent::name/parent::VariableDeclarationFragment/initializer/ArrayInitializer/expressions/" \
                "CharacterLiteral"

        parameter_values = parameter_values.union(self.array_assignment(syntax_tree, query))
        #if len(parameter_values) > 0: return parameter_values

        # value assignment for byte array with = {(byte) 0x00, (byte) 0x01, (byte) 0x02, ... }
        query = "/CompilationUnit/types//SimpleName[@token='" + method + "']" \
                "/ancestor::MethodDeclaration//VariableDeclarationFragment/name/SimpleName[@token='" + variable + "']" \
                "/parent::name/parent::VariableDeclarationFragment/initializer/ArrayInitializer/" \
                "expressions//NumberLiteral"

        parameter_values = parameter_values.union(self.array_assignment(syntax_tree, query, ", "))
        #if len(parameter_values) > 0: return parameter_values

        # value assignment for byte array with {getBytes()}
        query = "/CompilationUnit/types//SimpleName[@token='" + method + "']" \
                "/ancestor::MethodDeclaration//VariableDeclarationFragment/name/SimpleName[@token='" + variable + "']" \
                "/parent::name/parent::VariableDeclarationFragment/initializer//expression/StringLiteral/@token"

        parameter_values = parameter_values.union(self.value_assignment(syntax_tree, query))
        #if len(parameter_values) > 0: return parameter_values

        # number value for variable can be found
        query = "/CompilationUnit/types//SimpleName[@token='" + method + "']" \
                "/ancestor::MethodDeclaration//VariableDeclarationFragment/name/SimpleName[@token='" + variable + "']" \
                "/parent::name/parent::VariableDeclarationFragment/initializer/NumberLiteral/@token"

        parameter_values = parameter_values.union(self.value_assignment(syntax_tree, query))
        #if len(parameter_values) > 0: return parameter_values

        # check for nested variables
        query = "/CompilationUnit/types//bodyDeclarations/MethodDeclaration/name/" \
                "SimpleName[@token='" + method + "']/ancestor::MethodDeclaration/body//statements/" \
                "VariableDeclarationStatement/fragments//name/SimpleName[@token='" + variable + "']" \
                "/ancestor::VariableDeclarationStatement/fragments//initializer/SimpleName"
        for nested_variable in [hit.token for hit in syntax_tree.tree.filter(query)]:
            parameter_values = parameter_values.union(self.substitute_v(syntax_tree, method, nested_variable))

        # check for method parameters
        parameter_values = parameter_values.union(self.substitute_p(syntax_tree, method, variable))
        if len(parameter_values) > 0: return parameter_values

        # check for field value
        parameter_values = parameter_values.union((self.substitute_f(syntax_tree, variable)))
        return parameter_values

    def substitute_f(self, syntax_tree, name):
        query_f = "/CompilationUnit/types//bodyDeclarations//FieldDeclaration/fragments//name/SimpleName[@token='" + name + "']"
        query_f_string = query_f + "/ancestor::FieldDeclaration/type//name/" \
                             "SimpleName[@token='String']" \
                             "/ancestor::FieldDeclaration/fragments//initializer/StringLiteral"
        query_f_int = query_f + "/ancestor::FieldDeclaration/type/PrimitiveType[@token='int']" \
                                "/ancestor::FieldDeclaration/fragments//initializer/NumberLiteral"
        query_f_char_array1 = query_f + "/ancestor::FieldDeclaration/type/ArrayType/elementType/" \
                                       "PrimitiveType[@token='byte']/ancestor::FieldDeclaration/" \
                                       "fragments//initializer/ArrayInitializer/expressions/CharacterLiteral"
        query_f_char_array2 = query_f + "/ancestor::FieldDeclaration/type/ArrayType/elementType/" \
                                        "PrimitiveType[@token='byte']/ancestor::FieldDeclaration/" \
                                        "fragments//initializer//StringLiteral"
        query_f_char_array3 = query_f + "/ancestor::FieldDeclaration/type/ArrayType/elementType/" \
                                        "PrimitiveType[@token='byte']/ancestor::FieldDeclaration/" \
                                        "fragments//initializer//NumberLiteral"

        # check if there is any corresponding field
        try:
            next(syntax_tree.tree.filter(query_f))
        except StopIteration:
            return set()

        # determine field value

        # string assignment
        value = self.iterator_get_next(syntax_tree, query_f_string)
        if not value is None:
            return set([ValueParameter(Types.StringLiteral, value.token, syntax_tree.file, value.start_position.line)])

        # int assignment
        value = self.iterator_get_next(syntax_tree, query_f_int)
        if not value is None:
            return set([ValueParameter(Types.NumberLiteral, value.token, syntax_tree.file, value.start_position.line)])

        # byte array initialization = {'a', 'b', 'c', ... }
        array_values = self.array_assignment(syntax_tree, query_f_char_array1)
        if len(array_values) > 0:
            return array_values

        # byte array initialization = "a string".getBytes()
        value = self.iterator_get_next(syntax_tree, query_f_char_array2)
        if not value is None:
            return set([ValueParameter(Types.StringLiteral, value.token, syntax_tree.file, value.start_position.line)])

        # byte array initialization = {(byte) 0x00, (byte) 0x01, (byte) 0x02, ... }
        array_values = self.array_assignment(syntax_tree, query_f_char_array3, ", ")
        if len(array_values) > 0:
            return array_values

        return set()

    def substitute_m(self):
        """substitute method"""

    def cm(self, syntax_tree, class_type, method_name, parameter_index):
        """
        call method
        :return:
        """
        value_parameters = set()
        base_query = "/CompilationUnit/types//VariableDeclarationStatement/type//name/SimpleName[@token='" + class_type + "']/ancestor::VariableDeclarationStatement/fragments/VariableDeclarationFragment/name/SimpleName/@token"
        objects = syntax_tree.tree.filter(base_query)
        for object in objects:
            value_parameters = value_parameters.union(self.csm(syntax_tree, object.token, method_name, parameter_index))

        return value_parameters

    def csm(self, syntax_tree, class_type, method_name, parameter_index):
        """
        call static method
        :return:
        """
        value_parameters = set()

        base_query = "/CompilationUnit/types//MethodInvocation//" \
                     "*[@role='Call' and @role='Callee' and @token='" + method_name + "']/" \
                     "ancestor::MethodInvocation/expression/SimpleName[@token='" + class_type + "']/" \
                     "ancestor::MethodInvocation/arguments/*[" + str(parameter_index) + "]"

        # StringLiteral
        #query_s = base_query + "//StringLiteral/@token"
        #for string in syntax_tree.filter(query_s):
        #    value_parameters.add(ValueParameter(Types.StringLiteral, string.token, "File", string.start_position.line, class_type + "." + method_name + "(...) -> hard coded string"))
        return self.query_parameter_value(syntax_tree, base_query, class_type + "." + method_name)

        #return value_parameters

    def ci(self, syntax_tree, type_name, parameter_index, operator=None, value=None):
        """
        create instance

        :param syntax_tree:
        :param type_name:
        :param parameter_index:
        :param operator:
        :param value:
        :return:
        """

        value_parameters = set()

        base_query = "/CompilationUnit/types//ClassInstanceCreation/type//name" \
                     "/SimpleName[@token='" + type_name + "']/ancestor::ClassInstanceCreation/arguments/*["\
                     + str(parameter_index) + "]"

        return self.query_parameter_value(syntax_tree, base_query, type_name)

    def query_parameter_value(self, syntax_tree, base_query, parameter_receiver):
        value_parameters = set()

        # new Byte[] { '.', '.', ... }
        query_array_char = base_query + "//ArrayInitializer/expressions/CharacterLiteral"
        for value_parameter in self.array_assignment(syntax_tree, query_array_char):
            value_parameter.init_misuse_position(parameter_receiver + " -> hard coded array", value_parameter.line)
            value_parameters.add(value_parameter)

        # new Byte[] {(byte) 0x01, (byte) 0x02, ... )
        query_array_int = base_query + "//ArrayInitializer/expressions//NumberLiteral"
        int_arrays = self.array_assignment(syntax_tree, query_array_int, ",")
        for value_parameter in int_arrays:
            value_parameter.init_misuse_position(parameter_receiver + " -> hard coded array", value_parameter.line)
            value_parameters.add(value_parameter)

        if int_arrays is None or len(int_arrays) < 1:
            # NumberLiteral
            query_n = base_query + "//NumberLiteral/@token"
            for string in syntax_tree.tree.filter(query_n):
                value_parameters.add(
                    ValueParameter(Types.NumberLiteral, string.token, syntax_tree.file, string.start_position.line,
                                   parameter_receiver + " -> hard coded int", string.start_position.line))

        # StringLiteral
        query_s = base_query + "//StringLiteral/@token"
        for string in syntax_tree.tree.filter(query_s):
            value_parameters.add(ValueParameter(Types.StringLiteral, string.token, syntax_tree.file, string.start_position.line, parameter_receiver + " -> hard coded string", string.start_position.line))

        # parameter is variable
        query_v = base_query + "//SimpleName[@role='Identifier' and @role='Receiver' or @role='Argument']"

        for variable in syntax_tree.tree.filter(query_v + "/@token"):
            variable_name = variable.token
            methods = self.method_of_instantiation(syntax_tree, query_v, variable_name)

            for method in methods:
                value_parameters_substituted = self.substitute_v(syntax_tree, method[1], variable_name)

                # determine line number of analysed method call
                query_line = query_v + "[ancestor::MethodDeclaration/name/SimpleName[@token = '" + method[1] + "']]"
                misuse_line = next(syntax_tree.tree.filter(query_line)).start_position.line

                for value_parameter in value_parameters_substituted:
                    value_parameter.init_misuse_position(method[0] + "." + method[1] + "." + parameter_receiver, misuse_line)
                value_parameters = value_parameters.union(value_parameters_substituted)

        return value_parameters

        # TODO: possible improvements
        # parameter is variable with method call e.g. string.getBytes()
        # query_vm = base_query + "//MethodInvocation/expression/SimpleName/@token"

        # parameter is method return value
        # query_m = base_query + "//MethodInvocation[@expression]/name/SimpleName/@token"

        # ClassInstanceCreation
        # query_c = "//ClassInstanceCreateion"
