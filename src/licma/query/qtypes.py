from enum import Enum

class ParamType(Enum):
    String = 0
    Byte = 1
    Name = 2
    Attribute = 3
    Num = 4

class Types(Enum):
    UnknownType = -1
    Unknown = 0
    StringLiteral = 1
    NumberLiteral = 2
    SimpleName = 3
    Method = 4


def type_to_string(type):
    if type == Types.StringLiteral:
        return "StringLiteral"
    elif type == Types.NumberLiteral:
        return "NumberLiteral"
    elif type == Types.Method:
        return "Method"
    elif type == Types.SimpleName:
        return "SimpleName"
    elif type == Types.Unknown:
        return "Unknown"
    else:
        return "type is unknown"

def get_type(type):
    if type == "SimpleName" or type == "Name":
        return Types.SimpleName
    elif type == "StringLiteral":
        return Types.StringLiteral
    elif type == "NumberLiteral":
        return Types.NumberLiteral
    elif type == "Method":
        return Types.Method
    elif type == "Unknown":
        return Types.Unknown
    else:
        return Types.UnknownType
        raise Exception(type + " is not a type")
