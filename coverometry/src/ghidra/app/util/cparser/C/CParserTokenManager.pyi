import ghidra.app.util.cparser.C
import java.io
import java.lang


class CParserTokenManager(object, ghidra.app.util.cparser.C.CParserConstants):
    """
    Token Manager.
    """

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
    debugStream: java.io.PrintStream
    jjnewLexState: List[int] = array('i', [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4, 4, 2, 2, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, 0, -1, -1, -1, -1, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5, 5, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1])
    jjstrLiteralImages: List[unicode] = array(java.lang.String, [u'', None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, u'continue', None, u'register', u'unsigned', u'typedef', u'default', u'double', u'sizeof', u'switch', u'return', u'extern', u'"C"', u'struct', u'static', u'_Thread_local', None, u'while', u'break', u'union', None, None, u'__declspec', None, None, u'__readableTo', None, None, u'_Noreturn', u'_Alignas', u'_Alignof', u'__unaligned', u'__packed', None, None, None, None, None, None, u'float', u'short', u'else', u'case', u'long', u'__int8', u'__int16', u'__int32', u'__int64', u'__ptr64', u'__ptr32', u'_Bool', u'__w64', u'enum', u'auto', u'void', u'char', u'goto', u'__near', u'__far', u'for', u'int', u'if', u'do', u'@protocol', u'@interface', u'#line', None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, u'(', u')', u'-', u'+', u'*', u':', u',', None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, u'@end', u'{', u'}', u';', u'(', u')', u'[', u']', u',', u':', u'=', u'#', u'*', u'&', u'...', u'.', u'+', u'-', u'*=', u'/=', u'%=', u'+=', u'-=', u'<<=', u'>>=', u'&=', u'^=', u'|=', u'?', u'||', u'&&', u'|', u'^', u'==', u'!=', u'<', u'>', u'<=', u'>=', u'<<', u'>>', u'/', u'%', u'++', u'--', u'~', u'!', u'->'])
    lexStateNames: List[unicode] = array(java.lang.String, [u'DEFAULT', u'ASMBLOCK', u'LINEBLOCK', u'PRAGMALINE', u'OBJC', u'OBJC2'])
    tokenImage: List[unicode] = array(java.lang.String, [u'<EOF>', u'"\\ufeff"', u'" "', u'"\\f"', u'"\\t"', u'"\\n"', u'"\\r"', u'"\\\\"', u'<token of kind 8>', u'<token of kind 9>', u'<INTEGER_LITERAL>', u'<DECIMAL_LITERAL>', u'<HEX_LITERAL>', u'<OCTAL_LITERAL>', u'<FLOATING_POINT_LITERAL>', u'<EXPONENT>', u'<CHARACTER_LITERAL>', u'<STRING_LITERAL>', u'"continue"', u'<VOLATILE>', u'"register"', u'"unsigned"', u'"typedef"', u'"default"', u'"double"', u'"sizeof"', u'"switch"', u'"return"', u'"extern"', u'"\\"C\\""', u'"struct"', u'"static"', u'"_Thread_local"', u'<SIGNED>', u'"while"', u'"break"', u'"union"', u'<CONST>', u'<CDECL>', u'"__declspec"', u'<PRAGMA>', u'<PRAGMA_FUNC>', u'"__readableTo"', u'<STDCALL>', u'<FASTCALL>', u'"_Noreturn"', u'"_Alignas"', u'"_Alignof"', u'"__unaligned"', u'"__packed"', u'<ATTRIBUTE>', u'<EXTENSION>', u'<RESTRICT>', u'<ASM>', u'<INLINE>', u'<STATICASSERT>', u'"float"', u'"short"', u'"else"', u'"case"', u'"long"', u'"__int8"', u'"__int16"', u'"__int32"', u'"__int64"', u'"__ptr64"', u'"__ptr32"', u'"_Bool"', u'"__w64"', u'"enum"', u'"auto"', u'"void"', u'"char"', u'"goto"', u'"__near"', u'"__far"', u'"for"', u'"int"', u'"if"', u'"do"', u'"@protocol"', u'"@interface"', u'"#line"', u'<LINEALT>', u'<IDENTIFIER>', u'<LETTER>', u'<DIGIT>', u'" "', u'"\\t"', u'<ASMBLOCKB>', u'<ASMBLOCKP>', u'<ASM_SEMI>', u'" "', u'"\\f"', u'"\\t"', u'":"', u'<PATH_LITERAL>', u'<LINENUMBER_LITERAL>', u'" "', u'"\\f"', u'"\\t"', u'"\\n"', u'"\\r"', u'";"', u'<token of kind 104>', u'<token of kind 105>', u'<PIDENTIFIER>', u'<PLETTER>', u'<PDIGIT>', u'"("', u'")"', u'"-"', u'"+"', u'"*"', u'":"', u'","', u'<PINTEGER_LITERAL>', u'<PDECIMAL_LITERAL>', u'<PHEX_LITERAL>', u'<POCTAL_LITERAL>', u'<PSTRING_LITERAL>', u'" "', u'"\\f"', u'"\\t"', u'"\\n"', u'"\\r"', u'<OBJC_IGNORE>', u'<OBJC_IDENTIFIER>', u'<OBJC_LETTER>', u'<OBJC_DIGIT>', u'<OBJC_SEMI>', u'" "', u'"\\f"', u'"\\t"', u'"\\n"', u'"\\r"', u'"@private"', u'"@protected"', u'"@property"', u'"@optional"', u'"@required"', u'<OBJC2_IGNORE>', u'"@end"', u'"{"', u'"}"', u'";"', u'"("', u'")"', u'"["', u'"]"', u'","', u'":"', u'"="', u'"#"', u'"*"', u'"&"', u'"..."', u'"."', u'"+"', u'"-"', u'"*="', u'"/="', u'"%="', u'"+="', u'"-="', u'"<<="', u'">>="', u'"&="', u'"^="', u'"|="', u'"?"', u'"||"', u'"&&"', u'"|"', u'"^"', u'"=="', u'"!="', u'"<"', u'">"', u'"<="', u'">="', u'"<<"', u'">>"', u'"/"', u'"%"', u'"++"', u'"--"', u'"~"', u'"!"', u'"->"'])



    @overload
    def __init__(self, stream: ghidra.app.util.cparser.C.SimpleCharStream):
        """
        Constructor.
        """
        ...

    @overload
    def __init__(self, stream: ghidra.app.util.cparser.C.SimpleCharStream, lexState: int):
        """
        Constructor.
        """
        ...



    @overload
    def ReInit(self, stream: ghidra.app.util.cparser.C.SimpleCharStream) -> None:
        """
        Reinitialise parser.
        """
        ...

    @overload
    def ReInit(self, stream: ghidra.app.util.cparser.C.SimpleCharStream, lexState: int) -> None:
        """
        Reinitialise parser.
        """
        ...

    def SwitchTo(self, lexState: int) -> None:
        """
        Switch to specified lex state.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getNextToken(self) -> ghidra.app.util.cparser.C.Token:
        """
        Get the next Token.
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setDebugStream(self, ds: java.io.PrintStream) -> None:
        """
        Set debug output.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def nextToken(self) -> ghidra.app.util.cparser.C.Token: ...