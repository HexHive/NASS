from typing import List
import ghidra.app.util.cparser.C
import ghidra.app.util.cparser.C.CParser
import ghidra.program.model.data
import ghidra.util.task
import java.io
import java.lang
import java.util


class CParser(object, ghidra.app.util.cparser.C.CParserConstants):
    ALIGNAS: int = 46
    ALIGNOF: int = 47
    ASM: int = 53
    ASMBLOCK: int = 1
    ASMBLOCKB: int = 89
    ASMBLOCKP: int = 90
    ASM_SEMI: int = 91
    ATTRIBUTE: int = 50
    AUTO: int = 70
    BOOL: int = 67
    BREAK: int = 35
    CASE: int = 59
    CDECL: int = 38
    CHAR: int = 72
    CHARACTER_LITERAL: int = 16
    CONST: int = 37
    CONTINUE: int = 18
    DECIMAL_LITERAL: int = 11
    DECLSPEC: int = 39
    DEFAULT: int = 0
    DFLT: int = 23
    DIGIT: int = 86
    DO: int = 79
    DOUBLE: int = 24
    ELSE: int = 58
    ENUM: int = 69
    EOF: int = 0
    EXPONENT: int = 15
    EXTENSION: int = 51
    EXTERN: int = 28
    FAR: int = 75
    FASTCALL: int = 44
    FLOAT: int = 56
    FLOATING_POINT_LITERAL: int = 14
    FOR: int = 76
    GOTO: int = 73
    HEX_LITERAL: int = 12
    IDENTIFIER: int = 84
    IF: int = 78
    INLINE: int = 54
    INT: int = 77
    INT16: int = 62
    INT32: int = 63
    INT64: int = 64
    INT8: int = 61
    INTEGER_LITERAL: int = 10
    INTERFACE: int = 81
    LETTER: int = 85
    LINE: int = 82
    LINEALT: int = 83
    LINEBLOCK: int = 2
    LINENUMBER_LITERAL: int = 97
    LONG: int = 60
    NEAR: int = 74
    NORETURN: int = 45
    OBJC: int = 4
    OBJC2: int = 5
    OBJC2_END: int = 142
    OBJC2_IGNORE: int = 141
    OBJC_DIGIT: int = 129
    OBJC_IDENTIFIER: int = 127
    OBJC_IGNORE: int = 126
    OBJC_LETTER: int = 128
    OBJC_SEMI: int = 130
    OCTAL_LITERAL: int = 13
    PACKED: int = 49
    PATH_LITERAL: int = 96
    PCLOSE: int = 110
    PCOLON: int = 114
    PCOMMA: int = 115
    PDECIMAL_LITERAL: int = 117
    PDIGIT: int = 108
    PHEX_LITERAL: int = 118
    PIDENTIFIER: int = 106
    PINTEGER_LITERAL: int = 116
    PLETTER: int = 107
    PMINUS: int = 111
    POCTAL_LITERAL: int = 119
    POPEN: int = 109
    PPLUS: int = 112
    PRAGMA: int = 40
    PRAGMALINE: int = 3
    PRAGMA_FUNC: int = 41
    PROTOCOL: int = 80
    PSTAR: int = 113
    PSTRING_LITERAL: int = 120
    PTR32: int = 66
    PTR64: int = 65
    QUOTE_C: int = 29
    READABLETO: int = 42
    REGISTER: int = 20
    RESTRICT: int = 52
    RETURN: int = 27
    SHORT: int = 57
    SIGNED: int = 33
    SIZEOF: int = 25
    STATIC: int = 31
    STATICASSERT: int = 55
    STDCALL: int = 43
    STRING_LITERAL: int = 17
    STRUCT: int = 30
    SWITCH: int = 26
    THREADLOCAL: int = 32
    TYPEDEF: int = 22
    UNALIGNED: int = 48
    UNION: int = 36
    UNSIGNED: int = 21
    VOID: int = 71
    VOLATILE: int = 19
    W64: int = 68
    WHILE: int = 34
    jj_nt: ghidra.app.util.cparser.C.Token
    token: ghidra.app.util.cparser.C.Token
    tokenImage: List[unicode] = array(java.lang.String, [u'<EOF>', u'"\\ufeff"', u'" "', u'"\\f"', u'"\\t"', u'"\\n"', u'"\\r"', u'"\\\\"', u'<token of kind 8>', u'<token of kind 9>', u'<INTEGER_LITERAL>', u'<DECIMAL_LITERAL>', u'<HEX_LITERAL>', u'<OCTAL_LITERAL>', u'<FLOATING_POINT_LITERAL>', u'<EXPONENT>', u'<CHARACTER_LITERAL>', u'<STRING_LITERAL>', u'"continue"', u'<VOLATILE>', u'"register"', u'"unsigned"', u'"typedef"', u'"default"', u'"double"', u'"sizeof"', u'"switch"', u'"return"', u'"extern"', u'"\\"C\\""', u'"struct"', u'"static"', u'"_Thread_local"', u'<SIGNED>', u'"while"', u'"break"', u'"union"', u'<CONST>', u'<CDECL>', u'"__declspec"', u'<PRAGMA>', u'<PRAGMA_FUNC>', u'"__readableTo"', u'<STDCALL>', u'<FASTCALL>', u'"_Noreturn"', u'"_Alignas"', u'"_Alignof"', u'"__unaligned"', u'"__packed"', u'<ATTRIBUTE>', u'<EXTENSION>', u'<RESTRICT>', u'<ASM>', u'<INLINE>', u'<STATICASSERT>', u'"float"', u'"short"', u'"else"', u'"case"', u'"long"', u'"__int8"', u'"__int16"', u'"__int32"', u'"__int64"', u'"__ptr64"', u'"__ptr32"', u'"_Bool"', u'"__w64"', u'"enum"', u'"auto"', u'"void"', u'"char"', u'"goto"', u'"__near"', u'"__far"', u'"for"', u'"int"', u'"if"', u'"do"', u'"@protocol"', u'"@interface"', u'"#line"', u'<LINEALT>', u'<IDENTIFIER>', u'<LETTER>', u'<DIGIT>', u'" "', u'"\\t"', u'<ASMBLOCKB>', u'<ASMBLOCKP>', u'<ASM_SEMI>', u'" "', u'"\\f"', u'"\\t"', u'":"', u'<PATH_LITERAL>', u'<LINENUMBER_LITERAL>', u'" "', u'"\\f"', u'"\\t"', u'"\\n"', u'"\\r"', u'";"', u'<token of kind 104>', u'<token of kind 105>', u'<PIDENTIFIER>', u'<PLETTER>', u'<PDIGIT>', u'"("', u'")"', u'"-"', u'"+"', u'"*"', u'":"', u'","', u'<PINTEGER_LITERAL>', u'<PDECIMAL_LITERAL>', u'<PHEX_LITERAL>', u'<POCTAL_LITERAL>', u'<PSTRING_LITERAL>', u'" "', u'"\\f"', u'"\\t"', u'"\\n"', u'"\\r"', u'<OBJC_IGNORE>', u'<OBJC_IDENTIFIER>', u'<OBJC_LETTER>', u'<OBJC_DIGIT>', u'<OBJC_SEMI>', u'" "', u'"\\f"', u'"\\t"', u'"\\n"', u'"\\r"', u'"@private"', u'"@protected"', u'"@property"', u'"@optional"', u'"@required"', u'<OBJC2_IGNORE>', u'"@end"', u'"{"', u'"}"', u'";"', u'"("', u'")"', u'"["', u'"]"', u'","', u'":"', u'"="', u'"#"', u'"*"', u'"&"', u'"..."', u'"."', u'"+"', u'"-"', u'"*="', u'"/="', u'"%="', u'"+="', u'"-="', u'"<<="', u'">>="', u'"&="', u'"^="', u'"|="', u'"?"', u'"||"', u'"&&"', u'"|"', u'"^"', u'"=="', u'"!="', u'"<"', u'">"', u'"<="', u'">="', u'"<<"', u'">>"', u'"/"', u'"%"', u'"++"', u'"--"', u'"~"', u'"!"', u'"->"'])
    token_source: ghidra.app.util.cparser.C.CParserTokenManager



    @overload
    def __init__(self): ...

    @overload
    def __init__(self, tm: ghidra.app.util.cparser.C.CParserTokenManager):
        """
        Constructor with generated Token Manager.
        """
        ...

    @overload
    def __init__(self, dtmgr: ghidra.program.model.data.DataTypeManager): ...

    @overload
    def __init__(self, stream: java.io.InputStream):
        """
        Constructor with InputStream.
        """
        ...

    @overload
    def __init__(self, stream: java.io.Reader):
        """
        Constructor.
        """
        ...

    @overload
    def __init__(self, stream: java.io.InputStream, encoding: unicode):
        """
        Constructor with InputStream and supplied encoding
        """
        ...

    @overload
    def __init__(self, dtmgr: ghidra.program.model.data.DataTypeManager, storeDataType: bool, subDTMgrs: List[ghidra.program.model.data.DataTypeManager]): ...



    def ANDExpression(self) -> object: ...

    def AbstractDeclarator(self, dt: ghidra.app.util.cparser.C.Declaration) -> ghidra.app.util.cparser.C.Declaration: ...

    def AdditiveExpression(self) -> object: ...

    def AlignmentSpecifier(self) -> None: ...

    def ArgumentExpressionList(self) -> None: ...

    def AsmLine(self) -> None: ...

    def AsmStatement(self) -> None: ...

    def AssignmentExpression(self) -> object: ...

    def AssignmentOperator(self) -> None: ...

    def AttributeList(self, dec: ghidra.app.util.cparser.C.Declaration) -> None: ...

    def AttributeSpec(self, dec: ghidra.app.util.cparser.C.Declaration) -> None: ...

    def AttributeSpecList(self, dec: ghidra.app.util.cparser.C.Declaration) -> None: ...

    def AttributeToken(self, dec: ghidra.app.util.cparser.C.Declaration) -> None: ...

    def BuiltInDeclarationSpecifier(self, dec: ghidra.app.util.cparser.C.Declaration) -> ghidra.app.util.cparser.C.Declaration: ...

    def BuiltInTypeSpecifier(self, dec: ghidra.app.util.cparser.C.Declaration) -> ghidra.app.util.cparser.C.Declaration: ...

    def CastExpression(self) -> object: ...

    def CompoundStatement(self) -> None: ...

    def ConditionalExpression(self) -> object: ...

    def Constant(self) -> object: ...

    def ConstantExpression(self) -> object: ...

    def DeclConstant(self) -> None: ...

    def DeclSpec(self, dec: ghidra.app.util.cparser.C.Declaration) -> None: ...

    def DeclSpecifier(self, dec: ghidra.app.util.cparser.C.Declaration) -> None: ...

    def Declaration(self) -> ghidra.app.util.cparser.C.Declaration: ...

    def DeclarationList(self) -> None: ...

    def DeclarationSpecifiers(self, specDT: ghidra.app.util.cparser.C.Declaration) -> ghidra.app.util.cparser.C.Declaration: ...

    def Declarator(self, dt: ghidra.app.util.cparser.C.Declaration, container: ghidra.program.model.data.DataType) -> ghidra.app.util.cparser.C.Declaration: ...

    def Designation(self) -> None: ...

    def Designator(self) -> None: ...

    def DesignatorList(self) -> None: ...

    def DirectAbstractDeclarator(self, dt: ghidra.app.util.cparser.C.Declaration) -> ghidra.app.util.cparser.C.Declaration: ...

    def DirectDeclarator(self, dt: ghidra.app.util.cparser.C.Declaration, container: ghidra.program.model.data.DataType) -> ghidra.app.util.cparser.C.Declaration: ...

    def EnumSpecifier(self) -> ghidra.program.model.data.DataType: ...

    def Enumerator(self, __a0: java.util.ArrayList, __a1: int) -> int: ...

    def EnumeratorList(self) -> List[ghidra.app.util.cparser.C.CParser.EnumMember]: ...

    def EqualityExpression(self) -> object: ...

    def ExclusiveORExpression(self) -> object: ...

    def Expression(self) -> object: ...

    def ExpressionStatement(self) -> None: ...

    def ExternalDeclaration(self) -> None: ...

    def FunctionDefinition(self) -> None: ...

    def IdentifierList(self, funcDT: ghidra.program.model.data.FunctionDefinitionDataType, retDT: ghidra.program.model.data.DataType) -> None: ...

    def InclusiveORExpression(self) -> object: ...

    def InitDeclarator(self, dt: ghidra.app.util.cparser.C.Declaration) -> None: ...

    def InitDeclaratorList(self, dt: ghidra.app.util.cparser.C.Declaration) -> None: ...

    def Initializer(self) -> None: ...

    def InitializerList(self) -> None: ...

    def IterationStatement(self) -> None: ...

    def JumpStatement(self) -> None: ...

    def LabeledStatement(self) -> None: ...

    def LineDef(self) -> None: ...

    def LogicalANDExpression(self) -> object: ...

    def LogicalORExpression(self) -> object: ...

    def MultiLineString(self) -> ghidra.app.util.cparser.C.Token: ...

    def MultiplicativeExpression(self) -> object: ...

    def ObjcDef(self) -> ghidra.program.model.data.DataType: ...

    def ParameterDeclaration(self, __a0: java.util.ArrayList) -> None: ...

    def ParameterList(self) -> List[ghidra.app.util.cparser.C.Declaration]: ...

    def ParameterTypeList(self, funcDT: ghidra.program.model.data.FunctionDefinitionDataType, retDT: ghidra.program.model.data.DataType) -> ghidra.app.util.cparser.C.Declaration: ...

    def Pointer(self, dec: ghidra.app.util.cparser.C.Declaration) -> ghidra.app.util.cparser.C.Declaration: ...

    def PostfixExpression(self) -> object: ...

    def PragmaConstant(self) -> ghidra.app.util.cparser.C.Token: ...

    def PragmaSpec(self) -> None: ...

    def PragmaSpecifier(self) -> None: ...

    def PrimaryExpression(self) -> object: ...

    @overload
    def ReInit(self, tm: ghidra.app.util.cparser.C.CParserTokenManager) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, stream: java.io.InputStream) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, stream: java.io.Reader) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, stream: java.io.InputStream, encoding: unicode) -> None:
        """
        Reinitialise.
        """
        ...

    def RelationalExpression(self) -> object: ...

    def SelectionStatement(self) -> None: ...

    def ShiftExpression(self) -> object: ...

    def SpecifierQualifierList(self) -> ghidra.app.util.cparser.C.Declaration: ...

    def Statement(self) -> None: ...

    def StatementList(self) -> None: ...

    def StaticAssert(self) -> None: ...

    def StorageClassSpecifier(self, specDT: ghidra.app.util.cparser.C.Declaration) -> ghidra.app.util.cparser.C.Declaration: ...

    def StructDeclaration(self, comp: ghidra.program.model.data.Composite, compositeHandler: ghidra.app.util.cparser.C.CompositeHandler) -> None: ...

    def StructDeclarationList(self, comp: ghidra.program.model.data.Composite) -> None: ...

    def StructDeclarator(self, dt: ghidra.app.util.cparser.C.Declaration, comp: ghidra.program.model.data.Composite, compositeHandler: ghidra.app.util.cparser.C.CompositeHandler) -> None: ...

    def StructDeclaratorList(self, dt: ghidra.app.util.cparser.C.Declaration, comp: ghidra.program.model.data.Composite, compositeHandler: ghidra.app.util.cparser.C.CompositeHandler) -> None: ...

    def StructOrUnion(self) -> ghidra.program.model.data.Composite: ...

    def StructOrUnionSpecifier(self) -> ghidra.program.model.data.DataType: ...

    def SubIdent(self, dec: ghidra.app.util.cparser.C.Declaration) -> None: ...

    def TranslationUnit(self) -> None: ...

    def TypeName(self) -> ghidra.app.util.cparser.C.Declaration: ...

    def TypeQualifier(self, dec: ghidra.app.util.cparser.C.Declaration) -> ghidra.app.util.cparser.C.Declaration: ...

    def TypeQualifierList(self, dec: ghidra.app.util.cparser.C.Declaration) -> ghidra.app.util.cparser.C.Declaration: ...

    def TypeSpecifier(self, dec: ghidra.app.util.cparser.C.Declaration) -> ghidra.app.util.cparser.C.Declaration: ...

    def TypedefName(self) -> ghidra.program.model.data.DataType: ...

    def UnaryExpression(self) -> object: ...

    def UnaryOperator(self) -> None: ...

    def didParseSucceed(self) -> bool: ...

    def disable_tracing(self) -> None:
        """
        Disable tracing.
        """
        ...

    def enable_tracing(self) -> None:
        """
        Enable tracing.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def generateParseException(self) -> ghidra.app.util.cparser.C.ParseException:
        """
        Generate ParseException.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getComposites(self) -> java.util.Map:
        """
        Get composite definitions
        @return Composite (structure/union) definitions
        """
        ...

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Get the data type manager
        @return 
        """
        ...

    def getDeclarations(self) -> java.util.Map:
        """
        Get Global variable declarations
        @return 
        """
        ...

    def getEnums(self) -> java.util.Map:
        """
        Get Defined Enumerations
        @return Defined enumeration names
        """
        ...

    def getFunctions(self) -> java.util.Map:
        """
        Get Function signatures
        @return Function signatures
        """
        ...

    def getLastDataType(self) -> ghidra.program.model.data.DataType:
        """
        @return the last data type parsed
        """
        ...

    def getNextToken(self) -> ghidra.app.util.cparser.C.Token:
        """
        Get the next Token.
        """
        ...

    def getParseMessages(self) -> unicode: ...

    def getToken(self, index: int) -> ghidra.app.util.cparser.C.Token:
        """
        Get the specific Token.
        """
        ...

    def getTypes(self) -> java.util.Map:
        """
        Get Type definitions
        @return Type definitions
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def main(args: List[unicode]) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def parse(self, str: unicode) -> ghidra.program.model.data.DataType: ...

    @overload
    def parse(self, fis: java.io.InputStream) -> None: ...

    def setMonitor(self, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def setParseFileName(self, fName: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def composites(self) -> java.util.Map: ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    @property
    def declarations(self) -> java.util.Map: ...

    @property
    def enums(self) -> java.util.Map: ...

    @property
    def functions(self) -> java.util.Map: ...

    @property
    def lastDataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def monitor(self) -> None: ...  # No getter available.

    @monitor.setter
    def monitor(self, value: ghidra.util.task.TaskMonitor) -> None: ...

    @property
    def nextToken(self) -> ghidra.app.util.cparser.C.Token: ...

    @property
    def parseFileName(self) -> None: ...  # No getter available.

    @parseFileName.setter
    def parseFileName(self, value: unicode) -> None: ...

    @property
    def parseMessages(self) -> unicode: ...

    @property
    def types(self) -> java.util.Map: ...