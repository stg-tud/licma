from licma.query.qtypes import type_to_string
from licma.query.qtypes import Types


class Misuse:
    def __init__(self, file, rule,  misuse, misuse_line, parameter_value, parameter_type, parameter_line):
        self.file = file
        self.rule = rule
        if parameter_type == Types.Unknown:
            self.hit_type = "warning"
        else:
            self.hit_type = "critical"
        self.misuse = misuse
        self.misuse_line = misuse_line
        self.parameter_value = parameter_value
        self.parameter_type = parameter_type
        self.parameter_line = parameter_line

    def to_string(self):
        return self.file + " | " + \
               self.rule + " | " + \
               self.hit_type + " | " + \
               self.misuse + " | " + \
               str(self.misuse_line) + " | " + \
               str(self.parameter_value) + " | " + \
               type_to_string(self.parameter_type) + " | " + \
               str(self.parameter_line)

    #def equal(self, misuse):
    #    return self.file == misuse.file and self.rule == misuse.rule and self.message == misuse.message

    def get_sort_element(self):
        return " ".join([self.file, str(self.misuse_line), str(self.parameter_line)])

    def get_list(self):
        return [self.file,
                self.rule,
                self.hit_type,
                self.misuse,
                self.misuse_line,
                self.parameter_value,
                self.parameter_type,
                self.parameter_line]
