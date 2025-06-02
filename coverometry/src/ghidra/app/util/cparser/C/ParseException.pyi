from typing import List
import java.io
import java.lang


class ParseException(java.lang.Exception):
    """
    This exception is thrown when parse errors are encountered.
     You can explicitly create objects of this exception type by
     calling the method generateParseException in the generated
     parser.

     You can modify this class to customize your error reporting
     mechanisms so long as you retain the public fields.
    """

    currentToken: ghidra.app.util.cparser.C.Token
    expectedTokenSequences: List[int]
    tokenImage: List[unicode]



    @overload
    def __init__(self):
        """
        The following constructors are for use by you for whatever
         purpose you can think of.  Constructing the exception in this
         manner makes the exception behave in the normal way - i.e., as
         documented in the class "Throwable".  The fields "errorToken",
         "expectedTokenSequences", and "tokenImage" do not contain
         relevant information.  The JavaCC generated code does not use
         these constructors.
        """
        ...

    @overload
    def __init__(self, message: unicode):
        """
        Constructor with message.
        """
        ...

    @overload
    def __init__(self, currentTokenVal: ghidra.app.util.cparser.C.Token, expectedTokenSequencesVal: List[int], tokenImageVal: List[unicode]):
        """
        This constructor is used by the method "generateParseException"
         in the generated parser.  Calling this constructor generates
         a new object of this type with the fields "currentToken",
         "expectedTokenSequences", and "tokenImage" set.
        """
        ...



    def addSuppressed(self, __a0: java.lang.Throwable) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def fillInStackTrace(self) -> java.lang.Throwable: ...

    def getCause(self) -> java.lang.Throwable: ...

    def getClass(self) -> java.lang.Class: ...

    def getLocalizedMessage(self) -> unicode: ...

    def getMessage(self) -> unicode: ...

    def getStackTrace(self) -> List[java.lang.StackTraceElement]: ...

    def getSuppressed(self) -> List[java.lang.Throwable]: ...

    def hashCode(self) -> int: ...

    def initCause(self, __a0: java.lang.Throwable) -> java.lang.Throwable: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def printStackTrace(self) -> None: ...

    @overload
    def printStackTrace(self, __a0: java.io.PrintStream) -> None: ...

    @overload
    def printStackTrace(self, __a0: java.io.PrintWriter) -> None: ...

    def setStackTrace(self, __a0: List[java.lang.StackTraceElement]) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

