from licma.query.qtypes import type_to_string, Types


class ValueParameter:
    def __init__(self, parameter_type, parameter_value, file, value_line, misuse="", misuse_line=-1):
        self.type = parameter_type
        if self.type == Types.StringLiteral:
            self.value = parameter_value.strip("\"")
        else:
            self.value = parameter_value
        self.file = file
        self.line = value_line
        self.misuse = misuse
        self.misuse_line = misuse_line

    def init_misuse_position(self, start_point, misuse_line):
        if self.misuse == "":
            self.misuse = start_point
        if self.misuse_line == -1:
            self.misuse_line = misuse_line

    def to_string(self):
        return " ".join([self.misuse, type_to_string(self.type), str(self.value), self.file, str(self.line)])

